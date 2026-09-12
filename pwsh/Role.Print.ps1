# Role provider: Print Server.
#
# Dot-sourced by Configure-ServerRoles.ps1 - not runnable on its own. Everything
# here lands in that script's scope, so $script: variables and functions are shared
# with every other part. Use $scriptRootPath, never $PSScriptRoot: inside this file
# $PSScriptRoot is the pwsh folder, not the folder the run was started from.

# ===========================[ Print Server ]===========================
# Four things stacked, each one the prerequisite of the next: a driver, a port, a queue,
# and a policy that puts the queue in front of somebody. The design describes them in that
# order because the server builds them in that order - a queue naming a driver that is not
# installed fails with "the specified driver does not exist", which reads as a broken
# design rather than a missing step.
#
# **A printer object is a device; a queue is what a user connects to.** The same physical
# printer is normally published several times over with different defaults - Backoffice as
# A4 mono and Backoffice as A4 colour - and those are two Windows printers on one port with
# one driver. So the design carries a printer *object* holding the port, the driver and the
# location once, and one or more *variations* under it, each of which becomes a queue with
# its own share, its own group and its own paper and colour defaults. The object itself may
# or may not be a queue (`createBase`): a device that only exists as variations is the
# normal case, and forcing a base queue nobody uses would publish a third printer.
#
# **This role spans two machines, the same split the File Server uses.** On the print
# server the access groups are a prerequisite and are never created; on a domain controller
# the same config creates them, brings their members in, and writes the deployment GPOs.
# Test-StudioDomainController is the branch. See Directory.ps1.

$script:printGpoPrefix = "U - USR - Printer"

# The Group Policy Preferences Printers client-side extension. The **first** GUID of the
# second pair is the one that matters: it is what a client reads to decide that this GPO
# has printer preferences to process, and without it Printers.xml sits in SYSVOL and
# nothing ever opens it. The second GUID of each pair is the administrative *tool*
# extension - it tells GPMC which editor node owns the settings, and a wrong one costs a
# rendering, not a deployment. Worth knowing which is which before "correcting" either.
$script:printPreferenceExtension = "[{00000000-0000-0000-0000-000000000000}{1612B55C-243C-48DD-A449-FFC097B19776}][{BC75B1ED-5833-4858-9BB8-CBF0B166DF9D}{1612B55C-243C-48DD-A449-FFC097B19776}]"

# RAW over 9100 is what every network printer sold in the last twenty years speaks, and
# what the Standard TCP/IP port monitor defaults to. LPR exists and is not offered: it is
# slower, it has no status channel, and a design that needs it is a design with a print
# appliance in it that wants deciding rather than defaulting.
$script:printDefaultPortNumber = 9100

# ---------------------------[ Module ]---------------------------
# PrintManagement ships with the Print-Services role, so it is loaded on demand rather
# than required up front - a domain controller running only the directory half of this
# role has no print role and needs none of it.
function Import-PrintModule {
    if (Get-Command -Name "Add-Printer" -ErrorAction SilentlyContinue) { return $true }
    try {
        Import-Module -Name "PrintManagement" -ErrorAction Stop
        return $true
    }
    catch {
        Write-Log "The PrintManagement module could not be loaded: $($_.Exception.Message)" -Tag "Error"
        Write-Log "    Install-WindowsFeature -Name Print-Services" -Tag "Error"
        return $false
    }
}

# ---------------------------[ Reading the design ]---------------------------
# Always fully qualified - see Resolve-StudioServerFqdn for why a single label is a per
# client failure rather than a shorter spelling. An empty design falls back to this
# machine's own name, which is only ever right on the print server itself; the domain
# controller run would otherwise put its *own* name in every client's printer path.
function Get-PrintServerName {
    param([Parameter(Mandatory)][object]$PrintServer)

    $root = Get-ConfigValue -InputObject $PrintServer -Name "root"
    $name = Get-ConfigText -InputObject $root -Name "computerName"
    if ([string]::IsNullOrWhiteSpace($name)) { $name = [string]$env:COMPUTERNAME }
    return (Resolve-StudioServerFqdn -Name $name -Label "print server")
}

# Lower case and a dash - "ip-10.0.0.50". The console names its own ports "IP_<address>"
# and accepts any name at all, so this is a house style rather than a constraint. What it
# does have to be is *stable*: the name is the only thing that tells a port this run makes
# from one already on the server, so changing it mints a second port beside the first
# rather than renaming anything.
$script:printPortPrefix = "ip-"

function Get-PrintPortName {
    param([Parameter(Mandatory)][object]$Port)

    $name = Get-ConfigText -InputObject $Port -Name "name"
    if (-not [string]::IsNullOrWhiteSpace($name)) { return $name }

    $address = Get-ConfigText -InputObject $Port -Name "address"
    if ([string]::IsNullOrWhiteSpace($address)) { return "" }
    return ($script:printPortPrefix + $address)
}

function Get-PrintDriverDefinition {
    param([Parameter(Mandatory)][object]$PrintServer)

    $drivers = @()
    foreach ($entry in @(Get-ConfigArray -InputObject $PrintServer -Name "drivers")) {
        $name = Get-ConfigText -InputObject $entry -Name "name"
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $drivers += [pscustomobject]@{
            Name    = $name
            InfPath = Get-ConfigText -InputObject $entry -Name "infPath"
        }
    }
    return ,$drivers
}

function Get-PrintPortDefinition {
    param([Parameter(Mandatory)][object]$PrintServer)

    $ports = @()
    foreach ($entry in @(Get-ConfigArray -InputObject $PrintServer -Name "ports")) {
        $address = Get-ConfigText -InputObject $entry -Name "address"
        if ([string]::IsNullOrWhiteSpace($address)) { continue }
        $number = [int](Get-ConfigValue -InputObject $entry -Name "portNumber" -Default $script:printDefaultPortNumber)
        if ($number -le 0) { $number = $script:printDefaultPortNumber }
        $ports += [pscustomobject]@{
            Name        = Get-PrintPortName -Port $entry
            Address     = $address
            PortNumber  = $number
            Description = Get-ConfigText -InputObject $entry -Name "description"
        }
    }
    return ,$ports
}

# One flat list of everything that becomes a Windows printer, base queues and variations
# alike, each carrying the port and driver it inherited from its object. Every consumer -
# the apply path, the GPO writer, the prerequisite check - reads this rather than walking
# the nested shape again and disagreeing about it.
function Get-PrintQueue {
    param([Parameter(Mandatory)][object]$PrintServer)

    $queues = @()
    foreach ($printer in @(Get-ConfigArray -InputObject $PrintServer -Name "printers")) {
        $printerName = Get-ConfigText -InputObject $printer -Name "name"
        if ([string]::IsNullOrWhiteSpace($printerName)) { continue }

        $port     = Get-ConfigText -InputObject $printer -Name "port"
        $driver   = Get-ConfigText -InputObject $printer -Name "driver"
        $location = Get-ConfigText -InputObject $printer -Name "location"
        $comment  = Get-ConfigText -InputObject $printer -Name "comment"
        # One group for the whole device. Every variation of a printer is the same printer -
        # whoever may print on it may print on it whichever queue they pick - so the group
        # belongs to the object rather than to each way it happens to be published. A config
        # written while it sat on the queue is still read, below, so an older file applies.
        $group    = Get-ConfigText -InputObject $printer -Name "group"
        # Who may print, as opposed to who gets it pushed. Absent means the key predates
        # the setting, and the safe reading of that is "change nothing" - see
        # Set-PrintQueuePermission.
        $rights   = Get-ConfigText -InputObject $printer -Name "permissions" -Default "default"
        $publish  = [bool](Get-ConfigValue -InputObject $printer -Name "publishInDirectory" -Default $false)

        $entries = @()
        if ([bool](Get-ConfigValue -InputObject $printer -Name "createBase" -Default $false)) {
            $entries += [pscustomobject]@{ Value = (Get-ConfigValue -InputObject $printer -Name "baseQueue"); Name = $printerName }
        }
        foreach ($variation in @(Get-ConfigArray -InputObject $printer -Name "variations")) {
            $name = Get-ConfigText -InputObject $variation -Name "name"
            if ([string]::IsNullOrWhiteSpace($name)) {
                $label = Get-ConfigText -InputObject $variation -Name "label"
                if ([string]::IsNullOrWhiteSpace($label)) { continue }
                $name = "{0} - {1}" -f $printerName, $label
            }
            $entries += [pscustomobject]@{ Value = $variation; Name = $name }
        }

        foreach ($entry in $entries) {
            $share = Get-ConfigText -InputObject $entry.Value -Name "shareName" -Default $entry.Name
            $queues += [pscustomobject]@{
                Printer   = $printerName
                Name      = $entry.Name
                ShareName = $share
                Group     = $(if ([string]::IsNullOrWhiteSpace($group)) { Get-ConfigText -InputObject $entry.Value -Name "group" } else { $group })
                Rights    = $rights
                Port      = $port
                Driver    = $driver
                Location  = $location
                Comment   = $comment
                Published = $publish
            }
        }
    }
    return ,$queues
}

# ---------------------------[ Drivers ]---------------------------
# Add-PrinterDriver installs a driver that is already in the machine's driver store - it
# does not read an INF. So a vendor driver has to be staged first, and pnputil is what
# stages it: without that step the call fails with "the specified driver does not exist",
# naming neither the file nor the reason. An in-box driver needs no INF and the design
# leaves the path empty for it.
function Install-PrintDriver {
    param([Parameter(Mandatory)][object]$Driver)

    $existing = $null
    try { $existing = Get-PrinterDriver -Name $Driver.Name -ErrorAction SilentlyContinue }
    catch { $existing = $null }
    if ($null -ne $existing) {
        Write-Log "The driver '$($Driver.Name)' is already installed" -Tag "Debug"
        return $true
    }

    if (-not [string]::IsNullOrWhiteSpace($Driver.InfPath)) {
        if (-not (Test-Path -LiteralPath $Driver.InfPath)) {
            Write-Log "The driver '$($Driver.Name)' names '$($Driver.InfPath)', which is not on this server" -Tag "Error"
            return $false
        }
        try {
            Write-Log "pnputil.exe /add-driver `"$($Driver.InfPath)`" /install" -Tag "Run"
            $output = & pnputil.exe /add-driver $Driver.InfPath /install 2>&1
            foreach ($line in (($output | Out-String) -split "`r?`n")) {
                if ($line.Trim()) { Write-Log "    $($line.Trim())" -Tag "Debug" }
            }
        }
        catch {
            Write-Log "Could not stage '$($Driver.InfPath)': $($_.Exception.Message)" -Tag "Error"
            return $false
        }
    }

    try {
        Add-PrinterDriver -Name $Driver.Name -ErrorAction Stop
        Write-Log "Installed the driver '$($Driver.Name)'" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "Could not install the driver '$($Driver.Name)': $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Error"
        if ([string]::IsNullOrWhiteSpace($Driver.InfPath)) {
            Write-Log "    The name must match the driver store exactly and is not in it - stage the vendor INF and name it in the design" -Tag "Error"
        }
        else {
            Write-Log "    The INF was staged and the name matches nothing it provides - check Get-PrinterDriver -ComputerName . | Select Name" -Tag "Error"
        }
        return $false
    }
}

# ---------------------------[ Ports ]---------------------------
# A port that exists is left as it is rather than repointed. The address behind a port name
# is the one thing a queue cannot see, so silently moving it would send every job on that
# port to a different device with nothing on screen to say so.
function Set-PrintPortEntry {
    param([Parameter(Mandatory)][object]$Port)

    $existing = $null
    try { $existing = Get-PrinterPort -Name $Port.Name -ErrorAction SilentlyContinue }
    catch { $existing = $null }

    if ($null -ne $existing) {
        $currentAddress = [string]$existing.PrinterHostAddress
        if ((-not [string]::IsNullOrWhiteSpace($currentAddress)) -and
            (-not $currentAddress.Equals($Port.Address, [System.StringComparison]::OrdinalIgnoreCase))) {
            Write-Log "The port '$($Port.Name)' already points at $currentAddress, not $($Port.Address) - left as it is" -Tag "Warn"
            Write-Log "Repointing a port moves every queue on it to another device, so that is a decision rather than a step" -Tag "Warn"
            return $true
        }
        Write-Log "The port '$($Port.Name)' already exists" -Tag "Debug"
        return $true
    }

    try {
        Add-PrinterPort -Name $Port.Name -PrinterHostAddress $Port.Address -PortNumber $Port.PortNumber -ErrorAction Stop
        Write-Log "Created the port '$($Port.Name)' -> $($Port.Address):$($Port.PortNumber)" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "Could not create the port '$($Port.Name)': $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Error"
        return $false
    }
}

# ---------------------------[ Queues ]---------------------------
# **How a queue prints is not this script's business.** Paper size, colour, duplex and the
# rest are printing defaults: per driver, per model, and no two drivers name them the same
# way - so a run that wrote them would be overwriting whoever set them properly in the
# console, every time it re-ran. What is written here is the part that is the same on every
# printer and that nothing else will do: the queue exists, it is on the right port with the
# right driver, and it is shared under the name the policy hands out.

function Set-PrintQueueObject {
    param([Parameter(Mandatory)][object]$Queue)

    $existing = $null
    try { $existing = Get-Printer -Name $Queue.Name -ErrorAction SilentlyContinue }
    catch { $existing = $null }

    if ($null -eq $existing) {
        try {
            Add-Printer -Name $Queue.Name -DriverName $Queue.Driver -PortName $Queue.Port `
                -Shared -ShareName $Queue.ShareName -ErrorAction Stop
            Write-Log "Created the printer '$($Queue.Name)', shared as '$($Queue.ShareName)'" -Tag "Ok"
        }
        catch {
            Write-Log "Could not create the printer '$($Queue.Name)': $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Error"
            return $false
        }
    }
    else {
        Write-Log "The printer '$($Queue.Name)' already exists - its settings are re-applied" -Tag "Debug"
    }

    # Re-applied for a new queue and an existing one alike: the settings are the part that
    # changes between runs, which is the same rule the file server's ACLs follow.
    $arguments = @{ Name = $Queue.Name; Shared = $true; ShareName = $Queue.ShareName; ErrorAction = "Stop" }
    if (-not [string]::IsNullOrWhiteSpace($Queue.Location)) { $arguments["Location"] = $Queue.Location }
    if (-not [string]::IsNullOrWhiteSpace($Queue.Comment))  { $arguments["Comment"]  = $Queue.Comment }
    $arguments["Published"] = [bool]$Queue.Published

    try {
        Set-Printer @arguments
    }
    catch {
        Write-Log "Could not apply the settings on '$($Queue.Name)': $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Error"
        return $false
    }

    return $true
}

# ---------------------------[ Queue permissions ]---------------------------
# The group on a printer decided one thing until now: who the deployment policy pushes the
# connection to. It decided nothing about who may print - the default printer descriptor
# gives **Everyone** the Print right, so anybody who types \\<server>\<share> prints, group
# or no group. This is the other half, and it is what makes the group mean something.
#
# Microsoft's own printing best practice (troubleshoot-printing-and-best-practices) says to
# put a group in front of the Print permission and take Everyone off it. It says to do that
# with a *local* group holding global groups - 2003-era A-G-DL-P, and the wrong shape here:
# a machine-local group's SID is machine-local, so a print server rebuilt from this design
# would carry printer ACEs naming a group that no longer exists, and the directory leg of
# this role runs on a domain controller, which has no local groups at all. The design
# already mints `Printer - <name>` as a domain global group and already resolves its SID
# for the policy's item-level targeting. One group, one meaning: in the group = it is
# deployed to you = you may print. Three facts that cannot drift apart.
#
# **The descriptor is edited, never authored.** A hand-written printer SDDL is how the
# ACEs nobody thinks about get dropped: `ALL APPLICATION PACKAGES` (without it no
# AppContainer app prints - Edge, Store apps, several PDF readers - while Notepad is fine),
# `CREATOR OWNER` (without it nobody can cancel their own job), SYSTEM, the administrator
# groups. So the live descriptor is read, the printer-level Everyone entry is taken out of
# it, the wanted one is put in, and everything else is left exactly as it was found.
$script:printEveryoneSid = "S-1-1-0"
# ADS_RIGHT_DS_SELF (0x8, PRINTER_ACCESS_USE) + READ_CONTROL (0x20000) - `SWRC` in SDDL,
# which is the mask the default descriptor gives Everyone. The same right, a different
# trustee: this step narrows who holds it and changes nothing about what it is.
$script:printAccessUseMask = 0x20008

# Everyone's PRINTER-level entry only. The inherit-only ones carry document rights and are
# a different question - taking those away is how users lose the ability to cancel their
# own jobs.
function Set-PrintSddlPrintRight {
    param(
        [Parameter(Mandatory)][string]$Sddl,
        [Parameter(Mandatory)][string]$Sid
    )

    $descriptor = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
    $everyone = New-Object System.Security.Principal.SecurityIdentifier($script:printEveryoneSid)
    $wanted = New-Object System.Security.Principal.SecurityIdentifier($Sid)

    $held = $false
    for ($index = $descriptor.DiscretionaryAcl.Count - 1; $index -ge 0; $index--) {
        $ace = $descriptor.DiscretionaryAcl[$index]
        if ($ace.AceFlags -ne [System.Security.AccessControl.AceFlags]::None) { continue }
        if ($ace.SecurityIdentifier -eq $everyone) {
            $null = $descriptor.DiscretionaryAcl.RemoveAce($index)
            continue
        }
        if (($ace.SecurityIdentifier -eq $wanted) -and ([int]$ace.AccessMask -band $script:printAccessUseMask)) { $held = $true }
    }

    if (-not $held) {
        $ace = New-Object System.Security.AccessControl.CommonAce(
            [System.Security.AccessControl.AceFlags]::None,
            [System.Security.AccessControl.AceQualifier]::AccessAllowed,
            $script:printAccessUseMask, $wanted, $false, $null)
        $descriptor.DiscretionaryAcl.InsertAce($descriptor.DiscretionaryAcl.Count, $ace)
    }

    return [string]$descriptor.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
}

# Who can print, read back off the descriptor and written out by name. Without it the only
# way to answer "why was this user refused" is to open the Security tab on a client, and
# the tab is misleading on its own: EVERYONE STAYS IN THAT LIST after this runs. The
# printer-level Everyone ACE is the one taken away; the inherit-only ones carry document
# rights and are deliberately kept, so the name is still there with Print unticked. A log
# line naming the trustees that hold the print right is the honest version of that.
function Write-PrintQueueAccess {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Sddl
    )

    try {
        $descriptor = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
    }
    catch {
        Write-Log "    Could not read back who may print on '$Name': $($_.Exception.Message)" -Tag "Debug"
        return
    }

    # The whole descriptor at Debug. Everything below this is an interpretation of it, and
    # when the interpretation and the behaviour disagree - a group that is in the user's
    # token, shows Print in the GUI, and is still refused - the only way forward is the
    # string itself. Cheap to log, and impossible to reconstruct afterwards.
    Write-Log "    $Name SDDL: $Sddl" -Tag "Debug"

    $holders = @()
    foreach ($ace in $descriptor.DiscretionaryAcl) {
        # Reported per ACE rather than only the ones that pass, because "the group is in
        # there but with an inheritance flag" and "the group is not in there" look
        # identical in the Security tab and are different problems.
        if ($ace.AceFlags -ne [System.Security.AccessControl.AceFlags]::None) {
            if ([int]$ace.AccessMask -band $script:printAccessUseMask) {
                Write-Log ("    {0} carries the print right on '{1}' but only as {2} - inherited by documents, NOT by the printer" -f
                    $ace.SecurityIdentifier, $Name, $ace.AceFlags) -Tag "Debug"
            }
            continue
        }
        if (-not ([int]$ace.AccessMask -band $script:printAccessUseMask)) { continue }
        $who = [string]$ace.SecurityIdentifier
        try { $who = ($ace.SecurityIdentifier.Translate([System.Security.Principal.NTAccount])).Value }
        catch {
            # A SID from a domain this server cannot reach, or a deleted principal. The
            # raw SID is still the answer to "who may print" - it just needs looking up
            # somewhere else - so it stands rather than dropping the entry.
            Write-Log "    '$who' did not resolve to a name: $($_.Exception.Message)" -Tag "Debug"
        }
        $holders += $who
    }
    if ($holders.Count -eq 0) {
        Write-Log "    Nothing holds the print right on '$Name' - every connection is refused" -Tag "Warn"
        return
    }
    Write-Log ("    May print on '{0}': {1}" -f $Name, (($holders | Select-Object -Unique) -join ", ")) -Tag "Info"
}

# Never fatal, and never a lock-down onto a name that could not be checked: a group whose
# SID does not resolve leaves the queue exactly as it is and prints the line to run once it
# does. Same contract Sync-PrintGpo already uses for the same group.
function Set-PrintQueuePermission {
    param([Parameter(Mandatory)][object]$Queue)

    $mode = [string]$Queue.Rights
    if ([string]::IsNullOrWhiteSpace($mode) -or ($mode -eq "default")) { return $true }

    $sid = ""
    $label = ""
    switch ($mode) {
        "authenticated" {
            # The article's own alternative: everybody with an account in the domain, which
            # is every printing user and no anonymous or guest session.
            $sid = "S-1-5-11"
            $label = "Authenticated Users"
        }
        "group" {
            if ([string]::IsNullOrWhiteSpace([string]$Queue.Group)) {
                Write-Log "'$($Queue.Name)' is set to print-by-group and names no group - its permissions are left alone" -Tag "Warn"
                return $true
            }
            $label = [string]$Queue.Group
            $sid = Get-StudioGroupSid -Name $label
            if ([string]::IsNullOrWhiteSpace($sid)) {
                Write-Log "'$label' does not resolve from here - '$($Queue.Name)' keeps the permissions it has" -Tag "Warn"
                Write-Log "    Run this config on a domain controller first, then re-run here" -Tag "Warn"
                return $true
            }
        }
        default {
            Write-Log "'$($Queue.Name)' names an unknown permission mode '$mode' - its permissions are left alone" -Tag "Warn"
            return $true
        }
    }

    $current = ""
    try { $current = [string](Get-Printer -Name $Queue.Name -Full -ErrorAction Stop).PermissionSDDL }
    catch { $current = "" }
    if ([string]::IsNullOrWhiteSpace($current)) {
        Write-Log "The security descriptor of '$($Queue.Name)' could not be read - its permissions are left alone" -Tag "Warn"
        return $true
    }

    $updated = ""
    try { $updated = Set-PrintSddlPrintRight -Sddl $current -Sid $sid }
    catch {
        Write-Log "The descriptor of '$($Queue.Name)' could not be rewritten: $($_.Exception.Message)" -Tag "Warn"
        return $true
    }

    if ($updated -eq $current) {
        Write-Log "'$($Queue.Name)': Print is already '$label' and Everyone is already off it" -Tag "Debug"
        Write-PrintQueueAccess -Name $Queue.Name -Sddl $current
        return $true
    }

    try {
        Set-Printer -Name $Queue.Name -PermissionSDDL $updated -ErrorAction Stop
        Write-Log "'$($Queue.Name)': Print granted to '$label', removed from Everyone" -Tag "Ok"
        Write-PrintQueueAccess -Name $Queue.Name -Sddl $updated
        # Said once per queue on purpose. A user outside the group is refused at CONNECT
        # time, not at print time, because installing the driver needs the Print right -
        # and "Access is denied" while adding a printer reads as a broken share. The
        # deployment GPO reports that as event 4098 with 0x80070005, which is a DIFFERENT
        # failure from the point-and-print one (0x80070bcb) that belongs to the client
        # hardening toolbox - the codes are how you tell them apart.
        # Only for `group`. These describe what narrowing to a group of PEOPLE costs, and
        # `authenticated` already includes the machine accounts - warning about the driver
        # fetch there is telling somebody to do the thing they have just done. The first
        # version of this fired in both modes and said exactly that on a clean run.
        if ($mode -eq "group") {
            Write-Log "    Anybody not in it is refused when they connect, which is where the driver install happens" -Tag "Debug"
            Write-Log "    A refused user shows as event 4098 '0x80070005' on their machine - group membership, not point and print" -Tag "Debug"
            # The one this catches out. Connecting fetches the driver, and that fetch
            # arrives as the CLIENT'S COMPUTER ACCOUNT, which is in no group of people -
            # so a user who is in the group and has it in their token is still refused on
            # a machine that has never had the driver. Field-proven 2026-09-05. Nothing
            # here can fix it: a printer ACL cannot say "machines may fetch, users may
            # print", because both are the same PRINTER_ACCESS_USE right.
            Write-Log "    A client with no driver yet fetches it as its COMPUTER account - not in this group, so its first connect is refused" -Tag "Warn"
            Write-Log "    Stage the driver on the clients, or use permissions 'authenticated', which covers the machines too" -Tag "Warn"
        }
        return $true
    }
    catch {
        Write-Log "The permissions on '$($Queue.Name)' could not be set: $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Warn"
        Write-Log ("    Set-Printer -Name '{0}' -PermissionSDDL '{1}'" -f $Queue.Name, $updated) -Tag "Info"
        return $true
    }
}

# ---------------------------[ Deployment policy ]---------------------------
# One GPO per printer object, every variation of it inside. Two preference items per
# variation, exactly like the drive maps: an Update targeted at the variation's group, and
# a Delete for the same connection targeted at *not* being in it, so losing the group takes
# the printer away at the next refresh rather than leaving it behind forever.
function New-PrintGpoXml {
    param([Parameter(Mandatory)][object[]]$Entry)

    $stamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $lines = @(
        '<?xml version="1.0" encoding="utf-8"?>',
        '<Printers clsid="{1F577D12-3D1B-471e-A1B7-060317597B9C}">'
    )

    foreach ($item in $Entry) {
        $path          = [System.Security.SecurityElement]::Escape($item.Path)
        $escapedGroup  = [System.Security.SecurityElement]::Escape($item.GroupName)
        $location      = [System.Security.SecurityElement]::Escape([string]$item.Location)
        $updateUid     = Get-StudioStableGuid -Seed ("printer-update-" + $item.Path)
        $deleteUid     = Get-StudioStableGuid -Seed ("printer-delete-" + $item.Path)

        # default="0" on every item, deliberately. Which printer a person's jobs go to
        # unasked is theirs, not a deployment's, and a design that sets it takes the choice
        # away from everyone the policy reaches at once.
        $lines += ('  <SharedPrinter clsid="{9A5E9697-9095-436d-A0EE-4D128FDFBCE5}" name="' + $path + '" status="' + $path + '" image="2" changed="' + $stamp + '" uid="' + $updateUid + '" bypassErrors="1">')
        $lines += ('    <Properties action="U" comment="" path="' + $path + '" location="' + $location + '" default="0" skipLocal="0" deleteAll="0" persistent="0" deleteMap="0" port=""/>')
        $lines += '    <Filters>'
        $lines += ('      <FilterGroup bool="AND" not="0" name="' + $escapedGroup + '" sid="' + $item.GroupSid + '" userContext="1" primaryGroup="0" localGroup="0"/>')
        $lines += '    </Filters>'
        $lines += '  </SharedPrinter>'

        $lines += ('  <SharedPrinter clsid="{9A5E9697-9095-436d-A0EE-4D128FDFBCE5}" name="' + $path + '" status="' + $path + '" image="3" changed="' + $stamp + '" uid="' + $deleteUid + '" bypassErrors="1">')
        $lines += ('    <Properties action="D" comment="" path="' + $path + '" location="" default="0" skipLocal="0" deleteAll="0" persistent="0" deleteMap="0" port=""/>')
        $lines += '    <Filters>'
        $lines += ('      <FilterGroup bool="AND" not="1" name="' + $escapedGroup + '" sid="' + $item.GroupSid + '" userContext="1" primaryGroup="0" localGroup="0"/>')
        $lines += '    </Filters>'
        $lines += '  </SharedPrinter>'
    }

    $lines += '</Printers>'
    return ($lines -join "`r`n")
}

function Get-PrintGpoName {
    param([Parameter(Mandatory)][string]$PrinterName)

    return ("{0} - {1}" -f $script:printGpoPrefix, $PrinterName)
}

function Sync-PrintGpo {
    param([Parameter(Mandatory)][object]$PrintServer)

    $queues = Get-PrintQueue -PrintServer $PrintServer
    if ($queues.Count -eq 0) { return $true }

    if (-not (Get-Command -Name "New-GPO" -ErrorAction SilentlyContinue)) {
        Write-Log "The GroupPolicy module is not available - the printer GPOs were not created" -Tag "Error"
        Write-Log "    Install-WindowsFeature -Name GPMC" -Tag "Error"
        return $false
    }

    $serverName = Get-PrintServerName -PrintServer $PrintServer
    $netbios    = [string]$env:USERDOMAIN
    $allCreated = $true

    # One list for every printer object this design writes, not one per printer. Same
    # reasoning as the drive maps: each connection inside these policies already filters
    # on its own group, so who gets which printer is membership - the link only decides
    # who processes the object at all, and that is the users' OU for all of them.
    $groupPolicy = Get-ConfigValue -InputObject $PrintServer -Name "groupPolicy"
    $linkTo = @(Get-StudioGpoLinkTarget -InputObject $groupPolicy -Name "linkTo")

    # Grouped by printer object, in the order the design lists them, so the GPO a person
    # opens holds every variation of the one printer they were asked about.
    $printerNames = @()
    foreach ($queue in $queues) {
        if ($printerNames -notcontains $queue.Printer) { $printerNames += $queue.Printer }
    }

    foreach ($printerName in $printerNames) {
        $gpoName = Get-PrintGpoName -PrinterName $printerName
        $entries = @()

        foreach ($queue in ($queues | Where-Object { $_.Printer -eq $printerName })) {
            if ([string]::IsNullOrWhiteSpace($queue.Group)) {
                Write-Log "'$printerName' names no group - its queues are shared on the server and deployed to nobody" -Tag "Warn"
                continue
            }
            $groupSid = Get-StudioGroupSid -Name $queue.Group
            if ([string]::IsNullOrWhiteSpace($groupSid)) {
                Write-Log "'$($queue.Name)' targets the group '$($queue.Group)', which does not exist - group sync failed above?" -Tag "Error"
                $allCreated = $false
                continue
            }
            $entries += [pscustomobject]@{
                Path      = "\\{0}\{1}" -f $serverName, $queue.ShareName
                GroupName = "{0}\{1}" -f $netbios, $queue.Group
                GroupSid  = $groupSid
                Location  = $queue.Location
            }
        }

        if ($entries.Count -eq 0) {
            Write-Log "'$gpoName' would hold no connection - nothing written" -Tag "Info"
            continue
        }

        try {
            $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($null -eq $gpo) {
                $gpo = New-GPO -Name $gpoName -ErrorAction Stop
                Write-Log "Created '$gpoName'" -Tag "Ok"
            }
            else {
                Write-Log "'$gpoName' already exists - its printer entries are re-applied" -Tag "Info"
            }
            # User preferences only; the computer half stays off so nothing ever processes
            # an empty side.
            if ($gpo.GpoStatus -ne "ComputerSettingsDisabled") { $gpo.GpoStatus = "ComputerSettingsDisabled" }

            $policyFolder = Set-StudioGpoUserExtension -Gpo $gpo -Extension $script:printPreferenceExtension
            $xml = New-PrintGpoXml -Entry $entries
            Write-StudioGpoPreferenceFile -PolicyFolder $policyFolder -Folder "Printers" -FileName "Printers.xml" -Content $xml

            Write-Log "'$gpoName': $($entries.Count) connection(s), each added inside its group and removed outside it" -Tag "Ok"

            if (-not (Set-StudioGpoLink -Name $gpoName -TargetDn $linkTo `
                        -UnlinkedNote "link it to the users' OU when ready")) {
                $allCreated = $false
            }
        }
        catch {
            Write-Log "Could not build '$gpoName': $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Error"
            $allCreated = $false
        }
    }

    return $allCreated
}

# Point and Print / PrintNightmare client policy is deliberately NOT here. What a client
# may install - RestrictDriverInstallationToAdministrators, trusted server lists, package
# point-and-print - is client hardening, and another toolbox (CIS hardening) owns that
# whole layer. This role builds the server and the deployment; worth knowing when a
# non-admin's connection fails at the driver step, the answer lives in that toolbox.

# ---------------------------[ Prerequisites ]---------------------------
function Test-PrintPrerequisite {
    param([object]$Config)

    $printServer = Get-ConfigValue -InputObject $Config -Name "printServer"
    if ($null -eq $printServer) { return $true }

    $groups = Get-StudioGroupDefinition -Entries (Get-ConfigArray -InputObject $printServer -Name "groups")

    # On a domain controller this role is the directory half and nothing else: the groups
    # are what it creates, so demanding they exist first would refuse the run that makes
    # them. Same split the File Server uses.
    if (Test-StudioDomainController) {
        $passed = $true
        if (-not (Get-Command -Name "New-GPO" -ErrorAction SilentlyContinue)) {
            Write-Log "Domain controller: this role writes the groups and printer GPOs, and the GroupPolicy module is missing" -Tag "Error"
            Write-Log "    Install-WindowsFeature -Name GPMC" -Tag "Error"
            $passed = $false
        }
        # The fallback in Get-PrintServerName is this machine's own name, which on a domain
        # controller is the wrong machine entirely - every deployed printer path would name
        # the DC. Nothing else can supply it, so it is a refusal rather than a warning.
        $root = Get-ConfigValue -InputObject $printServer -Name "root"
        if ([string]::IsNullOrWhiteSpace((Get-ConfigText -InputObject $root -Name "computerName"))) {
            Write-Log "printServer.root.computerName is empty and this run writes the deployment policies - nothing to put in the printer paths" -Tag "Error"
            Write-Log "Set it to the print server's fully qualified name, for example print-01.ad.lab.invalid" -Tag "Error"
            $passed = $false
        }
        return $passed
    }

    $passed = $true

    if (-not (Import-PrintModule)) { $passed = $false }

    foreach ($group in $groups) {
        $found = $null
        try { $found = Find-AdcsGroup -Name $group.Name } catch { $found = $null }
        if ($null -eq $found) {
            Write-Log "Printer group '$($group.Name)' does not exist - run this config on a domain controller first, or create it by hand" -Tag "Error"
            # DomainLocal, not Global. This group's whole job is to hold a permission on a
            # resource in this domain, which is what domain local scope is for - AGDLP,
            # with the people in a global group nested inside it. The run resolves the
            # name to a SID and never looks at the scope, so either works; the printed
            # line should be the one that is right rather than the one that is shortest.
            Write-Log "    New-ADGroup -Name '$($group.Name)' -GroupScope DomainLocal -GroupCategory Security" -Tag "Error"
            Write-Log "    Nesting a global group inside it is the normal shape - the token carries both, so targeting and the ACL both see it" -Tag "Info"
            $passed = $false
        }
    }

    # Every queue has to name a port and a driver the design also describes, or the apply
    # path fails one queue at a time with an error naming neither the design nor the gap.
    $portNames   = @(Get-PrintPortDefinition -PrintServer $printServer | ForEach-Object { $_.Name })
    $driverNames = @(Get-PrintDriverDefinition -PrintServer $printServer | ForEach-Object { $_.Name })

    foreach ($queue in (Get-PrintQueue -PrintServer $printServer)) {
        if ([string]::IsNullOrWhiteSpace($queue.Port) -or ($portNames -notcontains $queue.Port)) {
            Write-Log "'$($queue.Name)' names the port '$($queue.Port)', which is not in the design's port list" -Tag "Error"
            $passed = $false
        }
        if ([string]::IsNullOrWhiteSpace($queue.Driver) -or ($driverNames -notcontains $queue.Driver)) {
            Write-Log "'$($queue.Name)' names the driver '$($queue.Driver)', which is not in the design's driver list" -Tag "Error"
            $passed = $false
        }
    }

    return $passed
}

# ---------------------------[ Entry point ]---------------------------
function Invoke-PrintConfiguration {
    param([object]$Config)

    $printServer = Get-ConfigValue -InputObject $Config -Name "printServer"
    if ($null -eq $printServer) {
        return (New-RoleResult -Status "Failed" -Message "config.json has no printServer section")
    }

    $groups = Get-StudioGroupDefinition -Entries (Get-ConfigArray -InputObject $printServer -Name "groups")

    # The directory half. Same config, different machine, different job - the groups the
    # print server refuses to start without, and the policies that hand the queues out.
    if (Test-StudioDomainController) {
        Write-Log "Domain controller: creating the printer groups and bringing their members in" -Tag "Run"
        $allSynced = $true
        foreach ($group in $groups) {
            if (-not (Sync-StudioAccessGroup -Name $group.Name -Description "Printer access group" -MemberUpn $group.Members)) {
                $allSynced = $false
            }
        }
        # After the groups: every preference item filters on a group SID, so a group that
        # failed above fails its GPO here with the reason already on screen.
        if (-not (Sync-PrintGpo -PrintServer $printServer)) { $allSynced = $false }
        if (-not $allSynced) {
            return (New-RoleResult -Status "ManualStepRequired" -Message "Not every group, member or printer GPO could be written - fix the names above and re-run")
        }
        return (New-RoleResult -Status "Completed" -Message "Printer groups and deployment GPOs ready - run the same config on the print server for the queues themselves")
    }

    if (-not (Import-PrintModule)) {
        return (New-RoleResult -Status "Failed" -Message "The PrintManagement module is not available on this server")
    }

    $failures = @()

    foreach ($driver in (Get-PrintDriverDefinition -PrintServer $printServer)) {
        if (-not (Install-PrintDriver -Driver $driver)) { $failures += ("driver " + $driver.Name) }
    }

    foreach ($port in (Get-PrintPortDefinition -PrintServer $printServer)) {
        if (-not (Set-PrintPortEntry -Port $port)) { $failures += ("port " + $port.Name) }
    }

    $queues = Get-PrintQueue -PrintServer $printServer
    if ($queues.Count -eq 0) {
        Write-Log "No printer is designed - the drivers and ports are in place" -Tag "Info"
    }

    foreach ($queue in $queues) {
        # A queue whose driver or port failed above would fail here as well, with an error
        # about the driver rather than about the step that did not happen.
        if ($failures -contains ("driver " + $queue.Driver)) {
            Write-Log "'$($queue.Name)' is skipped - its driver did not install" -Tag "Error"
            $failures += $queue.Name
            continue
        }
        if ($failures -contains ("port " + $queue.Port)) {
            Write-Log "'$($queue.Name)' is skipped - its port was not created" -Tag "Error"
            $failures += $queue.Name
            continue
        }
        if (-not (Set-PrintQueueObject -Queue $queue)) {
            $failures += $queue.Name
            continue
        }
        # After the queue exists and never before it: the descriptor being edited is the
        # one the queue was created with.
        $null = Set-PrintQueuePermission -Queue $queue
    }

    Write-Log "The deployment policies are the domain controller's half of this role - run the same config there" -Tag "Info"

    if ($failures.Count -gt 0) {
        return (New-RoleResult -Status "ManualStepRequired" -Message ("These did not complete: " + (($failures | Select-Object -Unique) -join ", ") + "."))
    }
    return (New-RoleResult -Status "Completed" -Message ("{0} printer(s) shared on {1}." -f $queues.Count, (Get-PrintServerName -PrintServer $printServer)))
}
