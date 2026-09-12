#Requires -Version 5.1
# ---------------------------[ Hyper-V ]---------------------------
# The second role allowed to install itself, and for a better reason than the first.
# Exchange is the exception because setup.exe owns its own prerequisite list; Hyper-V is
# the exception because **a host cannot be configured before it is a hypervisor**. Every
# interesting thing here - the virtual switch, the SET team inside it, Set-VMHost - needs
# the Virtual Machine Management Service answering, which needs the role, which needs a
# restart. "Print the Install-WindowsFeature line and stop" would mean the operator does
# step one by hand and this script only ever sees step three.
#
# Mechanically the exception is one field: Feature = '' in $script:roleRegistry, the same
# way Exchange opts out of the engine's missing-feature refusal.
#
# The shape of a run:
#
#   Apply        install Hyper-V and, on Server Core, the App Compatibility feature;
#                power plan; SMB1. Returns RebootRequired.
#   (reboot)     performed by the engine through Get-HypervAutoRestartDelay
#   PostReboot   the hypervisor is live: data volume, folders, Set-VMHost, Defender
#                exclusions. Nothing here asks a human anything - the resume leg runs
#                -NoGui and a prompt there is a scheduled task that never returns.
#
# The interactive part belongs *before* the install, not after it: every question is
# about hardware and none of it needs Hyper-V present, so the answers are collected once
# and replayed unattended on the other side of the restart.

# ---------------------------[ Config ]---------------------------
function Get-HypervSection {
    param([Parameter(Mandatory)][object]$Config)
    return (Get-ConfigValue -InputObject $Config -Name "hyperV")
}

# One config describes a whole design and the same file is carried to every server in
# it, so a machine name - when the design states one - decides whether this role is for
# this machine. Empty means "wherever this lands", which is right for a design with one
# host in it.
function Test-HypervAppliesHere {
    param([Parameter(Mandatory)][object]$Config)

    $hyperv = Get-HypervSection -Config $Config
    if ($null -eq $hyperv) { return $false }

    # The two-node S2D mode names its machines itself - nodes, builder, witness host -
    # and answers this question in its own file. Nothing below is for that mode.
    if (Test-HypervS2dMode -Hyperv $hyperv) { return (Test-HypervS2dAppliesHere -Config $Config) }

    $computerName = [string](Get-ConfigText -InputObject $hyperv -Name "computerName" -Default "")
    if ([string]::IsNullOrWhiteSpace($computerName)) { return $true }
    if ($computerName.Equals($env:COMPUTERNAME, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }

    Write-Log "Design names '$computerName' as the Hyper-V host, this is $env:COMPUTERNAME - skipping" -Tag "Info"
    return $false
}

# ---------------------------[ State ]---------------------------
function Test-HypervFeatureInstalled {
    try {
        $feature = Get-WindowsFeature -Name "Hyper-V" -ErrorAction Stop
        return ($feature.InstallState -eq "Installed")
    }
    catch {
        return $false
    }
}

# Whether the stack actually answers, which is a different question from whether the
# feature is installed - between the two sits the restart.
#
# Deliberately not Win32_ComputerSystem.HypervisorPresent: that is true inside every
# guest virtual machine as well, so it would report a hypervisor on a server that is
# merely running on one. Asking Get-VMHost is asking the service.
function Test-HypervServiceReady {
    if (-not (Get-Command -Name "Get-VMHost" -ErrorAction SilentlyContinue)) { return $false }
    try {
        $null = Get-VMHost -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Test-HypervRebootPending {
    # The witness host of the two-node S2D mode never installs Hyper-V, so "the service
    # is not answering" is its permanent state rather than a restart it owes. Without
    # this branch the engine would park its post-reboot step behind a restart that never
    # comes. $config is the entry script's - reachable through the scope chain, the same
    # way $script:noGui is.
    $hyperv = $null
    if ($null -ne $config) { $hyperv = Get-HypervSection -Config $config }
    if (($null -ne $hyperv) -and (Test-HypervS2dMode -Hyperv $hyperv)) {
        $s2d = Get-HypervS2dSection -Hyperv $hyperv
        if ((Get-HypervS2dPersona -S2d $s2d) -eq "witness") { return $false }
    }
    return (-not (Test-HypervServiceReady))
}

# Server Core reports itself here. The App Compatibility feature is only meaningful on
# Core, and on Desktop Experience the switch is a logged no-op rather than an error.
# The probe itself moved to Directory.ps1 when Remote Desktop grew a second caller -
# RD Web Access is one of the role services that does not run on Server Core. This name
# stays because the call sites below read better with it.
function Test-HypervServerCore {
    return (Test-StudioServerCore)
}

# ---------------------------[ Prerequisites ]---------------------------
# Reported, never refused. The processor flags below are read from the platform and a
# guest virtual machine reports them differently from the metal it runs on, so refusing
# on them would block a nested lab that works. Install-WindowsFeature gives the honest
# answer a moment later, and it names the reason.
function Test-HypervVirtualizationSupport {
    $processors = @()
    try { $processors = @(Get-CimInstance -ClassName "Win32_Processor" -ErrorAction Stop) }
    catch {
        Write-Log "Processor not readable - virtualization support unchecked: $($_.Exception.Message)" -Tag "Warn"
        return
    }
    foreach ($processor in $processors) {
        if (-not $processor.VirtualizationFirmwareEnabled) {
            Write-Log "Virtualization is not enabled in firmware - Hyper-V will not start until it is" -Tag "Warn"
        }
        if (-not $processor.SecondLevelAddressTranslationExtensions) {
            Write-Log "Processor reports no SLAT, which Hyper-V requires" -Tag "Warn"
        }
    }
}

# Microsoft is explicit that the root partition belongs to Hyper-V alone: "Running
# additional server roles on a server running Hyper-V can adversely affect the
# performance of the virtualization server". The engine already knows what else this
# design puts here, so the warning costs nothing and arrives before the build.
function Test-HypervDedicatedHost {
    param([Parameter(Mandatory)][object]$Config)

    $others = @()
    foreach ($role in @(Get-ConfigArray -InputObject $Config -Name "roles")) {
        $id = [string](Get-ConfigText -InputObject $role -Name "id" -Default "")
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        if ($id -eq "Hyper-V") { continue }
        $others += $id
    }
    if ($others.Count -eq 0) { return }

    Write-Log "This design also puts $($others -join ', ') on this server" -Tag "Warn"
    Write-Log "    Microsoft asks for a root partition dedicated to Hyper-V - anything else competes with the guests for CPU, memory and IO" -Tag "Warn"
}

function Test-HypervPrerequisite {
    param([object]$Config)

    $hyperv = Get-HypervSection -Config $Config
    if ($null -eq $hyperv) {
        Write-Log "config.json has no hyperV section" -Tag "Error"
        return $false
    }

    Test-HypervVirtualizationSupport
    Test-HypervDedicatedHost -Config $Config

    if (Test-HypervS2dMode -Hyperv $hyperv) {
        $s2d = Get-HypervS2dSection -Hyperv $hyperv
        $names = @(Get-HypervS2dNodeName -S2d $s2d)
        Write-Log ("This design is a two-node S2D cluster: '{0}' across {1}" -f
            (Get-HypervS2dClusterName -S2d $s2d), ($names -join " + ")) -Tag "Info"
        return $true
    }

    if (Test-HypervClusterWanted -Hyperv $hyperv) {
        $null = Test-HypervClusterPrerequisite -Cluster (Get-HypervClusterSection -Hyperv $hyperv)
    }

    if (Test-HypervFeatureInstalled) {
        Write-Log "Hyper-V role installed" -Tag "Info"
    }
    else {
        Write-Log "Hyper-V role missing - this run installs it" -Tag "Info"
    }
    return $true
}

# ---------------------------[ Install ]---------------------------
function Install-HypervRole {
    Write-Log "Installing the Hyper-V role with its management tools" -Tag "Run"
    $result = $null
    try {
        $result = Install-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -ErrorAction Stop
    }
    catch {
        Write-Log "Hyper-V role not installed: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
    if (($null -ne $result) -and (-not $result.Success)) {
        Write-Log "Install-WindowsFeature failed: exit $($result.ExitCode)" -Tag "Error"
        return $false
    }
    Write-Log "Hyper-V role installed - the hypervisor runs after a restart" -Tag "Ok"
    return $true
}

# ---------------------------[ Reaching the outside ]---------------------------
# Whether this server can fetch a Feature on Demand from Microsoft. Probed against the
# hosts the download actually uses rather than against google.com, and for a reason: a
# server can perfectly well resolve google and still have no route to Windows Update,
# and a locked-down one can be blocked from google while WSUS or a proxy delivers the
# package fine.
#
# **The answer never blocks anything.** It decides which line the menu shows and which
# option sits under the cursor, and that is all it is allowed to do - a restricted
# network that answers nothing here is exactly the network where the online install
# still works through a proxy nobody told this script about.
$script:hypervConnectivityHost = @("dl.delivery.mp.microsoft.com", "www.msftconnecttest.com")

function Test-HypervTcpPort {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [int]$Port = 443,
        [int]$TimeoutMilliseconds = 3000,
        # Which address the connection leaves from. Empty is the normal case - the stack
        # picks, which is right for a check about whether something out there answers.
        # Given, it BINDS: the socket can only use that address, so a check about whether
        # a particular network carries traffic cannot be answered by another one that
        # happens to reach the same destination. The storage-path check needs that
        # distinction - see Test-HypervS2dStoragePathReady.
        [string]$SourceAddress = ""
    )

    return [bool](Get-HypervTcpProbe -ComputerName $ComputerName -Port $Port `
        -TimeoutMilliseconds $TimeoutMilliseconds -SourceAddress $SourceAddress).Open
}

# The same connection, with the REASON kept. A boolean throws away the difference between
# four answers that mean four different things, and three of them are not "it did not
# answer":
#
#   ConnectionRefused    a refusal is a REPLY. The subnet carries traffic; nothing is
#                        listening on that port at the other end. Reporting this as "does
#                        not answer" sends somebody to look at cabling for a service that
#                        is simply not running.
#   AddressNotAvailable  the bind failed - the source address is not on this machine, so
#                        nothing was ever sent and the destination is not implicated.
#   NetworkUnreachable   no route from that source. Also not about the destination.
#   timed out            packets left and nothing came back. The only one of the four that
#                        is evidence about the far end being silent.
#
# `Retryable` follows from that: only a timeout can heal on its own, so the other three
# stop a retry loop instead of spending a minute re-proving a fact that cannot change.
function Get-HypervTcpProbe {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [int]$Port = 443,
        [int]$TimeoutMilliseconds = 3000,
        [string]$SourceAddress = ""
    )

    $result = [pscustomobject]@{ Open = $false; Error = ""; Detail = ""; Retryable = $true }

    $client = $null
    try {
        if ([string]::IsNullOrWhiteSpace($SourceAddress)) {
            $client = New-Object System.Net.Sockets.TcpClient
        }
        else {
            $local  = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($SourceAddress)), 0
            $client = New-Object System.Net.Sockets.TcpClient $local
        }
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)) {
            $result.Error = "TimedOut"
            $result.Detail = "packets left and nothing came back"
            return $result
        }
        $client.EndConnect($async)
        $result.Open = $true
        return $result
    }
    catch {
        # The SocketException is normally wrapped - twice, when the constructor is the
        # thing that threw - so the chain is walked rather than the top read.
        $socket = $null
        $exception = $_.Exception
        while ($null -ne $exception) {
            if ($exception -is [System.Net.Sockets.SocketException]) { $socket = $exception; break }
            $exception = $exception.InnerException
        }

        if ($null -eq $socket) {
            $result.Error = "Failed"
            $result.Detail = [string]$_.Exception.Message
            return $result
        }

        $result.Error = [string]$socket.SocketErrorCode
        switch ([string]$socket.SocketErrorCode) {
            "ConnectionRefused" {
                $result.Detail = "refused - which is a reply, so the path works and nothing is listening there"
                $result.Retryable = $false
            }
            "AddressNotAvailable" {
                $result.Detail = "the source address is not on this machine, so nothing was sent"
                $result.Retryable = $false
            }
            "NetworkUnreachable" {
                $result.Detail = "no route to it from that source address"
                $result.Retryable = $false
            }
            "HostUnreachable" {
                $result.Detail = "the network answered that the host is unreachable"
                $result.Retryable = $false
            }
            "ConnectionReset" {
                $result.Detail = "the connection was reset, so something is there and it hung up"
                $result.Retryable = $false
            }
            default {
                $result.Detail = [string]$socket.Message
            }
        }
        return $result
    }
    finally { if ($null -ne $client) { $client.Close() } }
}

function Test-HypervInternetAccess {
    $result = [pscustomobject]@{
        Dns       = $false
        Reachable = $false
        Ping      = $false
        Detail    = ""
    }

    foreach ($name in $script:hypervConnectivityHost) {
        if (-not $result.Dns) {
            try {
                $addresses = @([System.Net.Dns]::GetHostAddresses($name))
                if ($addresses.Count -gt 0) {
                    $result.Dns = $true
                    $result.Detail = "$name resolves to $($addresses[0].IPAddressToString)"
                }
            }
            # A probe that fails is the answer, not an error: nothing here is allowed to
            # interrupt a run, and the caller reports what did and did not respond.
            catch { }
        }
        if (-not $result.Reachable) {
            if (Test-HypervTcpPort -ComputerName $name -Port 443) {
                $result.Reachable = $true
                if ([string]::IsNullOrWhiteSpace($result.Detail)) { $result.Detail = "$name answers on 443" }
            }
        }
        # ICMP last and only as colour on the answer: plenty of networks that deliver
        # packages perfectly well drop every ping that crosses them.
        if (-not $result.Ping) {
            try { $result.Ping = [bool](Test-Connection -ComputerName $name -Count 1 -Quiet -ErrorAction SilentlyContinue) }
            catch { $result.Ping = $false }
        }
        if ($result.Dns -and $result.Reachable) { break }
    }

    if ($result.Reachable) {
        Write-Log ("Windows Update reachable - {0}" -f $result.Detail) -Tag "Ok"
    }
    elseif ($result.Dns) {
        Write-Log ("DNS answers for Microsoft's download hosts, nothing on 443 - {0}" -f $result.Detail) -Tag "Warn"
        Write-Log "    Not a refusal: a proxy or WSUS can still deliver the package" -Tag "Info"
    }
    else {
        Write-Log "Neither DNS nor 443 to Microsoft's download hosts answered from here" -Tag "Warn"
        Write-Log "    Still not a refusal - a restricted network can answer a probe with nothing and deliver a package fine" -Tag "Info"
    }
    return $result
}

# ---------------------------[ App Compatibility ]---------------------------
# Core only. It is a Feature on Demand rather than a Windows feature, so an offline
# server needs a source - and the picker and mount tracking for that already exist in
# Media.ps1, pointed at the Languages and Optional Features ISO instead of an Exchange
# one. Microsoft's documented offline line is the one this builds:
#
#   Add-WindowsCapability -Online -Name ServerCore.AppCompatibility~~~~0.0.1.0 `
#       -Source <drive>:\LanguagesAndOptionalFeatures\ -LimitAccess
#
# The folder is that one on Server 2022 and later and the root of the ISO before that,
# so both are probed rather than assumed. -LimitAccess is what keeps a source-based
# install from quietly falling back to Windows Update, which is the whole point of
# naming a source on a server that cannot reach it.
$script:hypervAppCompatName = "ServerCore.AppCompatibility~~~~0.0.1.0"

function Get-HypervAppCompatSourcePath {
    param([Parameter(Mandatory)][string]$DriveRoot)

    $root = $DriveRoot.TrimEnd("\")
    $candidates = @((Join-Path -Path "$root\" -ChildPath "LanguagesAndOptionalFeatures"), "$root\")
    foreach ($candidate in $candidates) {
        if (-not (Test-Path -LiteralPath $candidate)) { continue }
        $cabs = @(Get-ChildItem -LiteralPath $candidate -File -Filter "*.cab" -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($cabs.Count -gt 0) { return $candidate }
    }
    Write-Log "No .cab on that ISO - it may not be the Languages and Optional Features media" -Tag "Warn"
    return ""
}

# Whether this machine has anything to ask about at all: Core only, wanted by the design,
# and not already installed. Asked before the interview screen is drawn so a host with
# nothing to decide never sees the question.
# Whether the App Compatibility package is on this box - asked so the Server Core note
# can say what is genuinely reachable from this console and what is not.
function Test-HypervAppCompatInstalled {
    if (-not (Get-Command -Name "Get-WindowsCapability" -ErrorAction SilentlyContinue)) { return $false }
    try {
        $capability = Get-WindowsCapability -Online -Name $script:hypervAppCompatName -ErrorAction Stop
        return (($null -ne $capability) -and ($capability.State -eq "Installed"))
    }
    catch {
        return $false
    }
}

function Test-HypervAppCompatWanted {
    param([Parameter(Mandatory)][object]$Hyperv)

    if (-not [bool](Get-ConfigValue -InputObject $Hyperv -Name "serverCoreAppCompat" -Default $true)) { return $false }
    if (-not (Test-HypervServerCore)) { return $false }
    if (-not (Get-Command -Name "Get-WindowsCapability" -ErrorAction SilentlyContinue)) { return $false }

    try {
        $capability = Get-WindowsCapability -Online -Name $script:hypervAppCompatName -ErrorAction Stop
        if (($null -ne $capability) -and ($capability.State -eq "Installed")) { return $false }
    }
    catch {
        # Unreadable is not "already installed" - the question is still worth asking.
        return $true
    }
    return $true
}

# Which source this run uses. The config decides when it has an opinion; otherwise the
# console is asked, with the connectivity probe deciding only which line reads
# 'available' and which option the cursor starts on.
#
# A plan already carries the answer: this is asked during the interview, with every other
# question, so that nothing stops the build halfway through to ask a human something.
function Get-HypervAppCompatChoice {
    param(
        [Parameter(Mandatory)][object]$Hyperv,
        [object]$Plan = $null
    )

    if (($null -ne $Plan) -and ($null -ne $Plan.appCompat)) {
        $mode = [string]$Plan.appCompat.mode
        if (-not [string]::IsNullOrWhiteSpace($mode)) {
            return [pscustomobject]@{ Mode = $mode; IsoPath = [string]$Plan.appCompat.isoPath }
        }
    }

    $source = [string](Get-ConfigText -InputObject $Hyperv -Name "appCompatSource" -Default "ask")
    $isoPath = [string](Get-ConfigText -InputObject $Hyperv -Name "appCompatIsoPath" -Default "")

    if ($source -eq "online") { return [pscustomobject]@{ Mode = "online"; IsoPath = "" } }
    if ($source -eq "iso") {
        $resolved = Resolve-StudioIsoPath -ConfiguredPath $isoPath `
            -Title "Select the Languages and Optional Features ISO" `
            -NoInteraction:(-not (Test-HypervInterviewWanted))
        if ([string]::IsNullOrWhiteSpace($resolved)) {
            Write-Log "ISO source asked for and none found - falling back to Windows Update" -Tag "Warn"
            return [pscustomobject]@{ Mode = "online"; IsoPath = "" }
        }
        return [pscustomobject]@{ Mode = "iso"; IsoPath = $resolved }
    }

    # "ask". Without a console there is nobody to ask, so a configured ISO wins and
    # Windows Update is the fallback - the same order an unattended run would want.
    $online = Test-HypervInternetAccess
    if (-not (Test-HypervInterviewWanted)) {
        if (-not [string]::IsNullOrWhiteSpace($isoPath)) {
            $resolved = Resolve-StudioIsoPath -ConfiguredPath $isoPath -Title "Languages and Optional Features ISO" -NoInteraction
            if (-not [string]::IsNullOrWhiteSpace($resolved)) { return [pscustomobject]@{ Mode = "iso"; IsoPath = $resolved } }
        }
        return [pscustomobject]@{ Mode = "online"; IsoPath = "" }
    }

    $onlineLabel = "Windows Update - it is reachable from here"
    if (-not $online.Reachable) {
        $onlineLabel = "Windows Update - nothing answered the probe, but try it anyway (a proxy or WSUS may still deliver it)"
    }
    $items = @(
        [pscustomobject]@{ Id = "online"; Label = $onlineLabel }
        [pscustomobject]@{ Id = "iso";    Label = "An ISO - the Languages and Optional Features media, picked from isos\" }
        [pscustomobject]@{ Id = "skip";   Label = "Neither - leave the App Compatibility feature out" }
    )
    # The probe only reorders the list. Both are always on it, because a probe that
    # answered nothing is evidence about the probe, not about Windows Update.
    if (-not $online.Reachable) { $items = @($items[1], $items[0], $items[2]) }

    $picked = Read-HypervChoice -Title "App Compatibility" -Heading "Where does the App Compatibility feature come from?" `
        -Hint "Server Core only. It is a Feature on Demand, so offline it needs the Languages and Optional Features ISO for this Windows version." `
        -Items $items
    if (($null -eq $picked) -or ($picked -eq "skip")) { return [pscustomobject]@{ Mode = "skip"; IsoPath = "" } }
    if ($picked -eq "online") { return [pscustomobject]@{ Mode = "online"; IsoPath = "" } }

    $resolved = Resolve-StudioIsoPath -ConfiguredPath $isoPath -Title "Select the Languages and Optional Features ISO"
    if ([string]::IsNullOrWhiteSpace($resolved)) {
        Write-Log "No ISO picked - using Windows Update" -Tag "Warn"
        return [pscustomobject]@{ Mode = "online"; IsoPath = "" }
    }
    return [pscustomobject]@{ Mode = "iso"; IsoPath = $resolved }
}

function Install-HypervAppCompatibility {
    param(
        [Parameter(Mandatory)][object]$Hyperv,
        [object]$Plan = $null
    )

    if (-not (Test-HypervServerCore)) {
        Write-Log "Not Server Core - App Compatibility does not apply" -Tag "Info"
        return $true
    }
    if (-not (Get-Command -Name "Get-WindowsCapability" -ErrorAction SilentlyContinue)) {
        Write-Log "Get-WindowsCapability unavailable - App Compatibility not installed" -Tag "Warn"
        return $true
    }

    $name = $script:hypervAppCompatName
    $capability = $null
    try { $capability = Get-WindowsCapability -Online -Name $name -ErrorAction Stop }
    catch {
        Write-Log "App Compatibility feature not queryable: $($_.Exception.Message)" -Tag "Warn"
        return $true
    }

    if (($null -ne $capability) -and ($capability.State -eq "Installed")) {
        Write-Log "Server Core App Compatibility already installed" -Tag "Info"
        return $true
    }

    $choice = Get-HypervAppCompatChoice -Hyperv $Hyperv -Plan $Plan
    if ($choice.Mode -eq "skip") {
        Write-Log "App Compatibility left out - later: Add-WindowsCapability -Online -Name $name" -Tag "Info"
        return $true
    }

    $parameters = @{ Online = $true; Name = $name; ErrorAction = "Stop" }
    $mounted = ""
    if ($choice.Mode -eq "iso") {
        try { $mounted = Mount-StudioIso -IsoFilePath $choice.IsoPath }
        catch {
            Write-Log "'$($choice.IsoPath)' not mounted: $($_.Exception.Message)" -Tag "Warn"
            Write-Log "    Falling back to Windows Update" -Tag "Info"
            $mounted = ""
        }
        if (-not [string]::IsNullOrWhiteSpace($mounted)) {
            $sourcePath = Get-HypervAppCompatSourcePath -DriveRoot $mounted
            if ([string]::IsNullOrWhiteSpace($sourcePath)) {
                Write-Log "That ISO carries no package folder this run recognises - falling back to Windows Update" -Tag "Warn"
            }
            else {
                $parameters["Source"] = $sourcePath
                # Without this, a source that does not carry the package falls back to
                # Windows Update and the failure arrives as a download timeout instead of
                # an answer about the media.
                $parameters["LimitAccess"] = $true
                Write-Log "Installing it from '$sourcePath'" -Tag "Run"
            }
        }
    }
    if (-not $parameters.ContainsKey("Source")) {
        Write-Log "Installing Server Core App Compatibility from Windows Update - takes several minutes" -Tag "Run"
    }

    try {
        $null = Add-WindowsCapability @parameters
        Write-Log "App Compatibility installed" -Tag "Ok"
    }
    catch {
        Write-Log "App Compatibility not installed: $($_.Exception.Message)" -Tag "Warn"
        Write-Log "    Offline, it needs a source: Add-WindowsCapability -Online -Name $name -Source <ISO>\LanguagesAndOptionalFeatures\ -LimitAccess" -Tag "Info"
        Write-Log "    The ISO is the Languages and Optional Features media for THIS version - a 2022 one does not serve a 2025 host" -Tag "Info"
    }
    finally {
        # Released here rather than at the end of the run: the capability is installed or
        # it is not, and either way this ISO has nothing more to give.
        if (-not [string]::IsNullOrWhiteSpace($mounted)) { $null = Dismount-StudioIsoPath -IsoFilePath $choice.IsoPath }
    }
    return $true
}

# ---------------------------[ Management tools ]---------------------------
# 'The Hyper-V role management tools are not installed', on a server that just installed
# the Hyper-V role. Not a bug in the install: Microsoft's own words are that on Server
# Core, -IncludeManagementTools installs **only the Hyper-V module for PowerShell**,
# because the graphical tool is meant to run on another machine.
#
# The App Compatibility feature does ship virtmgmt.msc, so once it is in, the snap-in has
# somewhere to run - it just needs the feature that registers it. This tries, after the
# restart and after the App Compatibility install, and says plainly what happened either
# way. It is never fatal: a Core host is managed from Windows Admin Center or from a
# workstation, and both work whatever this returns.
function Install-HypervManagementTool {
    $wanted = @("RSAT-Hyper-V-Tools", "Hyper-V-PowerShell")
    foreach ($name in $wanted) {
        $feature = $null
        try { $feature = Get-WindowsFeature -Name $name -ErrorAction Stop }
        catch { $feature = $null }

        if ($null -eq $feature) {
            Write-Log "'$name' is not a feature this Windows offers" -Tag "Debug"
            continue
        }
        if ($feature.InstallState -eq "Installed") {
            Write-Log "'$($feature.DisplayName)' is installed" -Tag "Debug"
            continue
        }
        if ($feature.InstallState -eq "Removed") {
            Write-Log "'$($feature.DisplayName)' was removed from this image and needs a source to come back" -Tag "Info"
            continue
        }

        try {
            $result = Install-WindowsFeature -Name $name -ErrorAction Stop
            if (($null -ne $result) -and $result.Success) {
                Write-Log "'$($feature.DisplayName)' is installed" -Tag "Ok"
            }
            else {
            Write-Log "'$($feature.DisplayName)' not installed" -Tag "Info"
            }
        }
        catch {
            Write-Log "'$($feature.DisplayName)' not installed: $($_.Exception.Message)" -Tag "Info"
        }
    }

    if (Test-HypervServerCore) {
        Write-Log "Server Core - no Hyper-V Manager, PowerShell module only" -Tag "Info"
        Write-Log "    Manage from Windows Admin Center, or Hyper-V Manager on a workstation" -Tag "Info"
        # The App Compatibility package's exact contents, because the gap inside it is the
        # one that surprises people: Microsoft's own component table lists cluadmin.msc
        # (2019) and virtmgmt.msc (2022) and does NOT list vmconnect.exe - the Virtual
        # Machine Connection tool is simply not in the package, and there is no supported
        # way to add it to Core (the GUI management tools feature is Desktop-only). So
        # both consoles open and manage everything, and the moment either one's 'Connect'
        # is clicked it answers 'The Virtual Machine Connection tool is not installed',
        # which reads like a broken install and is the package working as shipped.
        if (Test-HypervAppCompatInstalled) {
            Write-Log "    A guest console from here: Enter-PSSession -VMName <name>" -Tag "Debug"
            Write-Log "    App Compatibility brings the two consoles but not vmconnect.exe - 'Connect' says the tool is not installed, as shipped" -Tag "Debug"
            Write-Log "    vmconnect from a workstation works too - against a workgroup host it needs CredSSP delegation there" -Tag "Debug"
        }
    }
    return $true
}

# DNS registration off, on every adapter that still has it on - the workgroup cluster
# answer to an event that reads like a fault and is not one. The cluster's network name
# resource registers through the node adapters' own 'register this connection's
# addresses' setting, and on a workgroup cluster the attempt can never succeed: the
# secure dynamic update needs a computer account, which is the one identity a workgroup
# machine does not have. So every resource restart and periodic refresh logs 'failed
# registration ... No credentials are available in the security package' forever, about
# a name that works fine off its static record.
#
# Applied rather than reported (the user's call, 2026-08-18): on a workgroup design the
# records are static by construction, the node's own registration is the same doomed
# attempt as the cluster's, and the event this silences misleads everyone who reads it.
# The storage links already had registration off by design; this extends the same answer
# to the rest of the adapters. Reverting is one line and the log prints it.
#
# Never fatal - a node that keeps the event keeps a cosmetic event. The builder reaches
# the peer over Invoke-Command, and on a workgroup cluster that session is exactly the
# kind of call the peer is entitled to refuse - so a refusal prints the one-liner to run
# at the peer's own console instead of failing anything.
function Disable-HypervWorkgroupDnsRegistration {
    param([string]$ComputerName = "")

    $where = "this node"
    if (-not [string]::IsNullOrWhiteSpace($ComputerName)) { $where = "'$ComputerName'" }

    # This does NOT stop event 1196 on an ATC-managed cluster, and the attempt to make it
    # is worth recording so nobody spends the afternoon again (bench, 2026-08-23):
    #
    #   - Switching RegisterThisConnectionsAddress off is the documented fix and is
    #     field-confirmed to end 1196 on a workgroup cluster. It does not survive here:
    #     Network ATC owns `vManagement` and restores it - on remediation AND at boot.
    #   - ATC exposes no override for it. Add-NetIntent takes adapter property, RSS, QoS,
    #     switch, storage, site, proxy and cluster overrides, and none touches DNS
    #     registration. Windows Admin Center shows such a control; PowerShell has none.
    #   - The machine-wide HKLM\...\Tcpip\Parameters\DisableDynamicUpdate key does not
    #     help either: the per-interface setting takes precedence, so an interface that
    #     says "register" registers whatever the machine-wide default is. Tried, restarted,
    #     1196 came back, reverted.
    #
    # So on a workgroup cluster the event is genuinely expected. The static record is what
    # the name resource comes online from, and that is what this design verifies instead.
    # This pass is still run: it holds on every adapter ATC does not own, and it is right
    # before ATC exists on a manual-lane build.
    $apply = {
        $changed = @()
        foreach ($client in @(Get-DnsClient -ErrorAction Stop | Where-Object { $_.RegisterThisConnectionsAddress })) {
            try {
                Set-DnsClient -InterfaceAlias $client.InterfaceAlias -RegisterThisConnectionsAddress $false -ErrorAction Stop
                $changed += [string]$client.InterfaceAlias
            }
            catch { }
        }
        return $changed
    }

    $changed = @()
    try {
        if ([string]::IsNullOrWhiteSpace($ComputerName)) {
            $changed = @(& $apply)
        }
        else {
            $changed = @(Invoke-Command -ComputerName $ComputerName -ScriptBlock $apply -ErrorAction Stop)
        }
    }
    catch {
        Write-Log "DNS registration not switched off on ${where}: $($_.Exception.Message)" -Tag "Warn"
        if (-not [string]::IsNullOrWhiteSpace($ComputerName)) {
            Write-Log "    That node is not reachable from here. Sign in on '$ComputerName' and run:" -Tag "Warn"
            Write-Log "        Get-DnsClient | Where-Object { `$_.RegisterThisConnectionsAddress } | Set-DnsClient -RegisterThisConnectionsAddress `$false" -Tag "Info"
        }
        else {
            Write-Log "    By hand: Get-DnsClient | Where-Object { `$_.RegisterThisConnectionsAddress } | Set-DnsClient -RegisterThisConnectionsAddress `$false" -Tag "Info"
        }
        return $false
    }

    if ($changed.Count -eq 0) {
        Write-Log "DNS registration is already off on every adapter of $where" -Tag "Debug"
        return $true
    }
    Write-Log ("DNS registration off on {0}: {1}" -f $where, ($changed -join ", ")) -Tag "Ok"
    Write-Log "    Network ATC restores it on the vNICs it owns, so the cluster keeps logging event 1196" -Tag "Debug"
    Write-Log "    Revert with: Set-DnsClient -InterfaceAlias '<adapter>' -RegisterThisConnectionsAddress `$true" -Tag "Debug"
    return $true
}

# ---------------------------[ Domain join ]---------------------------
# Off by default, and that is the right default for a hypervisor: plenty of them are
# deliberately workgroup machines, and a host that joins a domain whose controllers are
# virtual machines *on that host* has a dependency loop waiting for the next power cut.
#
# When it is on it happens **before** anything else in the apply leg, for one reason: the
# join owes a restart, Hyper-V owes a restart, and one restart is cheaper than two. It
# also has to be done before the cluster is created - a cluster name object lives in the
# directory this join reaches.
function Get-HypervDomainJoinSection {
    param([Parameter(Mandatory)][object]$Hyperv)
    return (Get-ConfigValue -InputObject $Hyperv -Name "domainJoin")
}

function Test-HypervDomainJoinWanted {
    param([object]$Hyperv)

    if ($null -eq $Hyperv) { return $false }
    $join = Get-HypervDomainJoinSection -Hyperv $Hyperv
    if ($null -eq $join) { return $false }
    return [bool](Get-ConfigValue -InputObject $join -Name "enabled" -Default $false)
}

# Already in the domain the design names, whatever else it may be joined to.
function Test-HypervInDomain {
    param([Parameter(Mandatory)][string]$Domain)

    try {
        $system = Get-CimInstance -ClassName "Win32_ComputerSystem" -ErrorAction Stop
        if (-not $system.PartOfDomain) { return $false }
        $current = [string]$system.Domain
        return $current.Equals($Domain, [System.StringComparison]::OrdinalIgnoreCase)
    }
    catch {
        return $false
    }
}

# Returns $true when this run joined the domain - which is the caller's signal that the
# machine owes a restart it did not owe a moment ago.
function Invoke-HypervDomainJoin {
    param([Parameter(Mandatory)][object]$Hyperv)

    $join = Get-HypervDomainJoinSection -Hyperv $Hyperv
    if ($null -eq $join) { return $false }

    $domain = [string](Get-ConfigText -InputObject $join -Name "domain" -Default "")
    $user = [string](Get-ConfigText -InputObject $join -Name "joinUser" -Default "")
    $password = [string](Get-ConfigText -InputObject $join -Name "joinPassword" -Default "")
    $ouPath = [string](Get-ConfigText -InputObject $join -Name "ouPath" -Default "")

    if ([string]::IsNullOrWhiteSpace($domain)) {
        Write-Log "Domain join is on and the design names no domain" -Tag "Error"
        return $false
    }
    if (Test-HypervInDomain -Domain $domain) {
        Write-Log "Already in '$domain'" -Tag "Info"
        return $false
    }
    if ([string]::IsNullOrWhiteSpace($user) -or [string]::IsNullOrWhiteSpace($password)) {
        Write-Log "Domain join needs an account that may join computers to '$domain'" -Tag "Error"
        return $false
    }

    $parameters = @{
        DomainName  = $domain
        Force       = $true
        ErrorAction = "Stop"
    }
    if (-not [string]::IsNullOrWhiteSpace($ouPath)) {
        # Named, the computer object is created where the design says. Left blank it lands
        # in the domain's default computer container, which on a tiered directory is
        # usually the wrong side of a boundary somebody drew on purpose.
        $parameters["OUPath"] = $ouPath.Trim()
    }
    $secure = ConvertTo-SecureString -String $password -AsPlainText -Force
    $parameters["Credential"] = New-Object System.Management.Automation.PSCredential($user, $secure)

    Write-Log "Joining '$domain' as '$user'" -Tag "Run"
    if (-not [string]::IsNullOrWhiteSpace($ouPath)) { Write-Log "    Computer object goes to '$ouPath'" -Tag "Info" }
    try {
        $null = Add-Computer @parameters
        Write-Log "Joined '$domain' - true of every session after the restart" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "Domain join failed: $($_.Exception.Message)" -Tag "Error"
        Write-Log "    Needs DNS pointed at a controller for '$domain' and an account allowed to create the computer object" -Tag "Info"
        if (-not [string]::IsNullOrWhiteSpace($ouPath)) {
            Write-Log "    And rights on '$ouPath' - a wrong OU fails the join, it does not fall back" -Tag "Info"
        }
        return $false
    }
}

# ---------------------------[ Host settings ]---------------------------
# High Performance, and the studio says out loud that this is a trade rather than a
# best practice: Microsoft's documented default is Balanced, and High Performance is
# what you choose when "deterministic, low-latency response for all tenant workloads"
# matters more than the power bill. The GUID is the same on every Windows.
function Set-HypervPowerPlan {
    $highPerformance = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    try {
        $null = & powercfg.exe "/setactive" $highPerformance 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Power plan: High Performance" -Tag "Ok"
            Write-Log "    Firmware wins over this - a host in a vendor power-saver profile ignores what Windows asks for" -Tag "Debug"
            return $true
        }
        Write-Log "Power plan not set - powercfg exited $LASTEXITCODE" -Tag "Warn"
    }
    catch {
        Write-Log "Power plan not set: $($_.Exception.Message)" -Tag "Warn"
    }
    return $false
}

function Remove-HypervSmb1 {
    try {
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction Stop
        if ($smb1.State -ne "Enabled") {
            Write-Log "SMB1 is not enabled here" -Tag "Debug"
            return $true
        }
        $null = Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction Stop
        Write-Log "SMB1 removed - takes effect at the next restart" -Tag "Ok"
    }
    catch {
        Write-Log "SMB1 not checked or removed: $($_.Exception.Message)" -Tag "Warn"
    }
    return $true
}

# The page file is deliberately **not** touched here, and that is worth stating rather
# than leaving as an absence: the documented answer for a Hyper-V management OS is
# System Managed. The Exchange role in this same repo sets a fixed page file at RAM plus
# 10 MB, which is the correct answer to a different question. The two must not be
# harmonised - see also the ReFS allocation unit, where the same trap is set.
function Write-HypervPageFileNote {
    Write-Log "Page file: System Managed, the documented setting for a Hyper-V management OS" -Tag "Debug"
}

# ---------------------------[ Storage ]---------------------------
# The data volume, and it happens on **every** host rather than only the ones with a
# storage pool: a hardware RAID controller presents its array as one uninitialised disk,
# which is exactly the state Initialize-StudioDataVolume claims and formats. Pool or no
# pool, the volume ends up at the same specification.
#
# The numbers are stated here and nowhere else. Storage.ps1 carries no defaults on
# purpose, because Exchange's 64K allocation unit and this role's are answers to
# different questions - Microsoft's ReFS guidance is 4K for most deployments and 64K for
# large sequential IO, and a virtual machine's IO through a VHDX is not large sequential.
$script:hypervVolumeLabel = "Hyper-V"

function Initialize-HypervDataVolume {
    param(
        [Parameter(Mandatory)][object]$Hyperv,
        [object]$Plan = $null
    )

    $storage = Get-ConfigValue -InputObject $Hyperv -Name "storage"
    if ($null -eq $storage) {
        Write-Log "No storage section - no data volume prepared" -Tag "Info"
        return ""
    }
    if (-not [bool](Get-ConfigValue -InputObject $storage -Name "prepareDataVolume" -Default $true)) {
        Write-Log "Data volume preparation off" -Tag "Info"
        return ""
    }

    $driveLetter = ([string](Get-ConfigText -InputObject $storage -Name "driveLetter" -Default "D:")).Trim().TrimEnd(":", "\")
    $diskNumber = -1
    $partitionSizeBytes = 0
    $answer = $null
    if (($null -ne $Plan) -and ($null -ne $Plan.storage)) { $answer = $Plan.storage }
    if ($null -ne $answer) {
        if (-not [string]::IsNullOrWhiteSpace([string]$answer.driveLetter)) { $driveLetter = ([string]$answer.driveLetter).TrimEnd(":", "\") }
        try { $diskNumber = [int]$answer.diskNumber } catch { $diskNumber = -1 }
        try { $partitionSizeBytes = [long]$answer.partitionSizeBytes } catch { $partitionSizeBytes = 0 }
    }
    if ([string]::IsNullOrWhiteSpace($driveLetter)) { return "" }

    # The pool first, when the interview planned one - its virtual disk is what the
    # volume is then built on, and it arrives as an uninitialised disk like any other.
    if (($null -ne $answer) -and ($null -ne $answer.pool)) {
        $wanted = @([string[]]$answer.pool.disks)
        $available = @(Get-StudioPoolCandidateDisk | Where-Object { $wanted -contains [string]$_.DeviceId })
        if ($available.Count -lt 2) {
            # Two different situations, and only one of them is a problem. The pool this
            # run already built is the usual reason its disks are no longer poolable -
            # they are in it - and reporting that as a failure is how a second pass at the
            # same machine reads like something went wrong.
            $built = $null
            try { $built = Get-StoragePool -FriendlyName ([string]$answer.pool.name) -ErrorAction Stop } catch { $built = $null }
            if ($null -ne $built) {
                Write-Log "Pool '$($answer.pool.name)' is already built" -Tag "Info"
            }
            else {
                Write-Log "The interview's pool disks are no longer free and no pool by that name exists - none built" -Tag "Warn"
            }
        }
        else {
            $redundancy = 0
            try { $redundancy = [int]$answer.pool.redundancy } catch { $redundancy = 0 }
            $created = New-StudioStoragePool -Name ([string]$answer.pool.name) -PhysicalDisk $available `
                -Resiliency ([string]$answer.pool.resiliency) -NumberOfDataCopies ([int]$answer.pool.copies) `
                -PhysicalDiskRedundancy $redundancy
            # A pool's virtual disk is taken whole - it was built for exactly this.
            if ($created -ge 0) { $diskNumber = $created; $partitionSizeBytes = 0 }
        }
    }

    $fileSystem = [string](Get-ConfigText -InputObject $storage -Name "fileSystem" -Default "ReFS")
    $allocationUnitSize = [int](Get-ConfigValue -InputObject $storage -Name "allocationUnitSize" -Default 4096)
    $label = [string](Get-ConfigText -InputObject $storage -Name "label" -Default $script:hypervVolumeLabel)

    $result = Initialize-StudioDataVolume -DriveLetter $driveLetter `
        -FileSystem $fileSystem `
        -AllocationUnitSize $allocationUnitSize `
        -Label $label `
        -IntegrityStreams $false `
        -AllowPrepare `
        -DiskNumber $diskNumber `
        -PartitionSizeBytes $partitionSizeBytes

    if (-not $result.Ready) {
        Write-Log $result.Message -Tag "Error"
        return ""
    }
    if (-not $result.ToSpec) { Write-Log $result.Message -Tag "Warn" }
    return $driveLetter
}

# Two folders at the root of the data drive, named by the design. Hyper-V's own defaults
# put virtual machines under %ProgramData% on the system drive, which is how a host ends
# up unable to boot because somebody's checkpoint filled C:.
# The two folders, made once and reported. Split out because a clustered host wants them
# on every volume while only one of them can be the host's default.
function New-HypervGuestFolder {
    param([Parameter(Mandatory)][string[]]$Path)

    foreach ($item in $Path) {
        if (Test-Path -LiteralPath $item) { continue }
        try {
            $null = New-Item -ItemType Directory -Path $item -Force -ErrorAction Stop
            Write-Log "Created '$item'" -Tag "Debug"
        }
        catch {
            Write-Log "'$item' not created: $($_.Exception.Message)" -Tag "Error"
            return @()
        }
    }
    return @($Path)
}

function Set-HypervHostPath {
    param(
        [Parameter(Mandatory)][object]$Hyperv,
        [string]$DriveLetter = "",
        # Where the two folders go when it is not a drive root - a Cluster Shared Volume
        # is reached through C:\ClusterStorage\<name> and has no letter of its own.
        [string]$BasePath = "",
        # Make the folders and stop. A clustered host gets the same pair on **every**
        # Cluster Shared Volume, so that moving a virtual machine from one to the other is
        # a copy rather than a redesign - but Set-VMHost takes one path, so only the call
        # for the first volume goes on to set it.
        [switch]$FoldersOnly
    )

    $storage = Get-ConfigValue -InputObject $Hyperv -Name "storage"
    $vmFolder  = [string](Get-ConfigText -InputObject $storage -Name "vmFolderName" -Default "vms")
    $vhdFolder = [string](Get-ConfigText -InputObject $storage -Name "vhdFolderName" -Default "vhd")

    $root = $BasePath
    if ([string]::IsNullOrWhiteSpace($root)) {
        if ([string]::IsNullOrWhiteSpace($DriveLetter)) {
            Write-Log "No drive letter and no path for the host folders" -Tag "Error"
            return @()
        }
        $root = "$($DriveLetter):\"
    }

    $vmPath  = Join-Path -Path $root -ChildPath $vmFolder
    $vhdPath = Join-Path -Path $root -ChildPath $vhdFolder
    if ($FoldersOnly) { return (New-HypervGuestFolder -Path @($vmPath, $vhdPath)) }

    if ((New-HypervGuestFolder -Path @($vmPath, $vhdPath)).Count -eq 0) { return @() }

    try {
        Set-VMHost -VirtualMachinePath $vmPath -VirtualHardDiskPath $vhdPath -ErrorAction Stop
        Write-Log "Host paths: virtual machines '$vmPath', disks '$vhdPath'" -Tag "Ok"
    }
    catch {
        Write-Log "Host paths not set: $($_.Exception.Message)" -Tag "Error"
        return @()
    }
    return @($vmPath, $vhdPath)
}

# Defender configures Hyper-V's exclusions automatically when the role installs - but
# **for the default paths only**, and only for real-time protection. Moving virtual
# machines to a data drive therefore moves them out from under the folder exclusions,
# and a scheduled scan was never covered in the first place. A custom exclusion is
# honoured by every scan type, so exactly the two paths this run set are added and
# nothing else.
function Set-HypervDefenderExclusion {
    param([Parameter(Mandatory)][string[]]$Path)

    if ($Path.Count -eq 0) { return $true }
    if (-not (Get-Command -Name "Add-MpPreference" -ErrorAction SilentlyContinue)) {
        Write-Log "Defender cmdlets unavailable - no exclusions added" -Tag "Info"
        return $true
    }

    $existing = @()
    try { $existing = @((Get-MpPreference -ErrorAction Stop).ExclusionPath) }
    catch { $existing = @() }

    # One line for the set rather than one per folder. Four paths produced four
    # identical sentences that differed only in their tail, which is a list wearing a
    # sentence's clothes.
    $added = @()
    foreach ($item in $Path) {
        if ($existing -contains $item) {
            Write-Log "'$item' is already excluded" -Tag "Debug"
            continue
        }
        try {
            Add-MpPreference -ExclusionPath $item -ErrorAction Stop
            $added += $item
        }
        catch {
            Write-Log "Defender exclusion for '$item' not added: $($_.Exception.Message)" -Tag "Warn"
        }
    }
    if ($added.Count -gt 0) {
        Write-Log ("Defender exclusions: {0}" -f ($added -join ", ")) -Tag "Ok"
        Write-Log "    The automatic Hyper-V exclusions cover the default paths only" -Tag "Debug"
    }
    return $true
}

function Set-HypervEnhancedSessionMode {
    param([Parameter(Mandatory)][object]$Hyperv)

    if (-not [bool](Get-ConfigValue -InputObject $Hyperv -Name "enhancedSessionMode" -Default $true)) { return $true }
    try {
        Set-VMHost -EnableEnhancedSessionMode $true -ErrorAction Stop
        Write-Log "Enhanced session mode on" -Tag "Ok"
    }
    catch {
        Write-Log "Enhanced session mode not set: $($_.Exception.Message)" -Tag "Warn"
    }
    return $true
}

# ---------------------------[ The plan file ]---------------------------
# The run's own memory across the restart, and the reason the interactive half can sit
# *before* the install rather than after it.
#
# Everything a human has to answer here is about hardware - which adapters, which disks,
# which drive letter - and none of it needs Hyper-V to be present to answer. So the
# questions are asked once, on the way in, and written down. The leg on the other side of
# the reboot is the resume task's, runs -NoGui, and reads the file: a prompt there would
# be a scheduled task waiting forever for a keypress nobody is at the console to give.
#
# It is never imported anywhere. The studio has no idea this file exists and is not
# supposed to - a design describes intent, and this is a description of one machine's
# hardware, which is the studio's business only if somebody wants a config that is wrong
# on the next server.
function Get-HypervPlanPath {
    return (Join-Path -Path $scriptRootPath -ChildPath "hyperv-plan.json")
}

function Read-HypervPlan {
    $path = Get-HypervPlanPath
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try {
        return (Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json)
    }
    catch {
        Write-Log "'$path' unreadable - no interview answers this run: $($_.Exception.Message)" -Tag "Warn"
        return $null
    }
}

function Write-HypervPlan {
    param([Parameter(Mandatory)][object]$Plan)

    $path = Get-HypervPlanPath
    try {
        $Plan | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8 -ErrorAction Stop
        Write-Log "Answers written to '$path' - the run after the restart asks nothing" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "Plan not written to '$path': $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

function Remove-HypervPlan {
    $path = Get-HypervPlanPath
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        Write-Log "Plan file removed" -Tag "Debug"
    }
}

# ---------------------------[ Adapters ]---------------------------
# Physical adapters only. A vEthernet is the management operating system's end of a
# switch that already exists, and offering one as a team member is offering to build a
# switch on top of itself.
function Get-HypervPhysicalAdapter {
    try {
        return @(Get-NetAdapter -Physical -ErrorAction Stop | Sort-Object -Property Name)
    }
    catch {
        Write-Log "Network adapters unreadable: $($_.Exception.Message)" -Tag "Warn"
        return @()
    }
}

# A link speed in bits per second as the number written on the port. Get-NetAdapter's own
# LinkSpeed string is what the link **negotiated**, which is the number that matters, but
# it comes back as "25 Gbps" on one adapter and "25000 Mbps" on the next - one unit here
# is what makes a 25G port and a 10G port tell themselves apart in a list.
function Format-HypervLinkSpeed {
    param([long]$BitsPerSecond)

    if ($BitsPerSecond -le 0) { return "" }
    if ($BitsPerSecond -ge 1000000000) { return ("{0:N0} Gbps" -f ($BitsPerSecond / 1000000000)) }
    if ($BitsPerSecond -ge 1000000) { return ("{0:N0} Mbps" -f ($BitsPerSecond / 1000000)) }
    return ("{0:N0} bps" -f $BitsPerSecond)
}

# Everything needed to tell one network port from the one below it. On a host with four
# onboard 1G ports and a two-port 25G card, "Ethernet 5, Up, 00-15-5D-..." names none of
# them: the card is the thing being chosen, and the card is in the interface description,
# the driver and the PCIe slot it negotiated.
#
# Every read here is optional and separately guarded. A synthetic adapter in a virtual
# machine has no PCIe link and no RDMA, and the line is simply shorter for it rather than
# a row of blanks - and none of this may cost the interview a failure, because it is
# decoration on a question that has to be askable regardless.
function Get-HypervAdapterDetail {
    param([Parameter(Mandatory)][object]$Adapter)

    $name = [string]$Adapter.Name

    # What the card is.
    $identity = @()
    $description = [string]$Adapter.InterfaceDescription
    if (-not [string]::IsNullOrWhiteSpace($description)) { $identity += $description.Trim() }

    # Only when it is worth saying. Every wired port on a server answers '802.3', and a
    # column of it on every row says nothing about any of them.
    $media = [string]$Adapter.PhysicalMediaType
    if ([string]::IsNullOrWhiteSpace($media) -or ($media -eq "Unspecified")) { $media = [string]$Adapter.MediaType }
    if ((-not [string]::IsNullOrWhiteSpace($media)) -and ($media -ne "Unspecified") -and ($media -ne "802.3")) {
        $identity += $media
    }

    $mac = [string]$Adapter.MacAddress
    if (-not [string]::IsNullOrWhiteSpace($mac)) { $identity += ("MAC " + $mac) }

    $mtu = 0
    try { $mtu = [int]$Adapter.MtuSize } catch { $mtu = 0 }
    if ($mtu -gt 0) { $identity += ("MTU " + $mtu) }
    if ($null -ne $Adapter.FullDuplex) {
        if ([bool]$Adapter.FullDuplex) { $identity += "full duplex" } else { $identity += "HALF DUPLEX" }
    }

    # What is driving it, and how it is attached. A 25G card in a x4 slot is a 25G card
    # that will never do 25G, and that is visible here and nowhere else in this run.
    $hardware = @()
    $driver = [string]$Adapter.DriverProvider
    $version = [string]$Adapter.DriverVersion
    $driverText = ""
    if (-not [string]::IsNullOrWhiteSpace($driver)) { $driverText = $driver.Trim() }
    if (-not [string]::IsNullOrWhiteSpace($version)) { $driverText = ($driverText + " " + $version).Trim() }
    if (-not [string]::IsNullOrWhiteSpace($driverText)) { $hardware += ("driver " + $driverText) }

    if (Get-Command -Name "Get-NetAdapterHardwareInfo" -ErrorAction SilentlyContinue) {
        try {
            $info = Get-NetAdapterHardwareInfo -Name $name -ErrorAction Stop
            $slot = ""
            if ($null -ne $info.SlotNumber) { $slot = "slot " + [string]$info.SlotNumber }
            $bus = ("PCI {0}:{1}.{2}" -f $info.BusNumber, $info.DeviceNumber, $info.FunctionNumber)
            $link = ""
            $width = [string]$info.PcieLinkWidth
            $speed = [string]$info.PcieLinkSpeed
            if ((-not [string]::IsNullOrWhiteSpace($width)) -or (-not [string]::IsNullOrWhiteSpace($speed))) {
                $link = ("PCIe {0} x{1}" -f $speed, $width).Trim()
            }
            foreach ($value in @($slot, $bus, $link)) {
                if (-not [string]::IsNullOrWhiteSpace($value)) { $hardware += $value }
            }
        }
        catch {
            # A synthetic or teamed adapter has no PCI address. Nothing is added.
        }
    }

    if (Get-Command -Name "Get-NetAdapterRdma" -ErrorAction SilentlyContinue) {
        try {
            $rdma = Get-NetAdapterRdma -Name $name -ErrorAction Stop
            if ([bool]$rdma.Enabled) { $hardware += "RDMA on" }
        }
        catch {
            # No RDMA on this adapter, which is the ordinary answer.
        }
    }

    # The address it carries today. That is how an operator recognises the port their
    # session came in on, and how they spot the one that is already the storage network.
    if (Get-Command -Name "Get-NetIPAddress" -ErrorAction SilentlyContinue) {
        try {
            $addresses = @(Get-NetIPAddress -InterfaceAlias $name -AddressFamily IPv4 -ErrorAction Stop |
                Where-Object { [string]$_.IPAddress -notlike "169.254.*" })
            foreach ($address in $addresses) {
                $hardware += ("{0}/{1}" -f $address.IPAddress, $address.PrefixLength)
            }
        }
        catch {
            # No address, or no IP stack answer. The port is still a port.
        }
    }

    $lines = @()
    if ($identity.Count -gt 0) { $lines += ($identity -join "   ") }
    if ($hardware.Count -gt 0) { $lines += ($hardware -join "   ") }
    return @($lines)
}

# The IPv4 configuration of an adapter, captured before anything touches it.
#
# This is the single most valuable thing the interview does. Building a switch that the
# management operating system shares tears the physical adapter down and rebuilds it as
# 'vEthernet (<switch>)', and **a static address does not follow** - the new adapter
# comes up on DHCP. Captured here, re-applied on the other side by the same run, that is
# a five second outage rather than a server nobody can reach.
function Get-HypervAdapterAddress {
    param([Parameter(Mandatory)][string]$Name)

    $address = [pscustomobject]@{
        adapter      = $Name
        dhcp         = $true
        ipAddress    = ""
        prefixLength = 0
        gateway      = ""
        dns          = @()
    }

    try {
        $configuration = Get-NetIPConfiguration -InterfaceAlias $Name -ErrorAction Stop
        $ipv4 = @($configuration.IPv4Address)
        if ($ipv4.Count -gt 0) {
            $address.ipAddress = [string]$ipv4[0].IPAddress
            $address.prefixLength = [int]$ipv4[0].PrefixLength
        }
        if ($null -ne $configuration.IPv4DefaultGateway) {
            $address.gateway = [string]@($configuration.IPv4DefaultGateway)[0].NextHop
        }
        if ($null -ne $configuration.DNSServer) {
            $address.dns = @($configuration.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ })
        }

        $interface = Get-NetIPInterface -InterfaceAlias $Name -AddressFamily IPv4 -ErrorAction Stop
        $address.dhcp = ($interface.Dhcp -eq "Enabled")
    }
    catch {
        Write-Log "Address of '$Name' unreadable: $($_.Exception.Message)" -Tag "Warn"
    }
    return $address
}

# Put the captured address back on the management vNIC the switch just created. Skipped
# for an adapter that was on DHCP, because DHCP is what the new one comes up on anyway.
function Restore-HypervManagementAddress {
    param(
        [Parameter(Mandatory)][object]$Address,
        [Parameter(Mandatory)][string]$SwitchName
    )

    if ([bool]$Address.dhcp) {
        Write-Log "'$($Address.adapter)' was on DHCP - the new management adapter stays on DHCP" -Tag "Info"
        return $true
    }
    if ([string]::IsNullOrWhiteSpace([string]$Address.ipAddress)) {
        Write-Log "No address captured for '$($Address.adapter)' - nothing re-applied" -Tag "Warn"
        return $false
    }

    $alias = "vEthernet ($SwitchName)"
    Write-Log "Restoring $($Address.ipAddress)/$($Address.prefixLength) on '$alias'" -Tag "Run"

    try {
        $null = Set-NetIPInterface -InterfaceAlias $alias -Dhcp Disabled -ErrorAction Stop
        # Removed first: the vNIC may already carry a DHCP lease, and New-NetIPAddress
        # against an interface that has one fails rather than replacing it.
        Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        Get-NetRoute -InterfaceAlias $alias -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

        $parameters = @{
            InterfaceAlias = $alias
            IPAddress      = [string]$Address.ipAddress
            PrefixLength   = [int]$Address.prefixLength
            ErrorAction    = "Stop"
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$Address.gateway)) { $parameters["DefaultGateway"] = [string]$Address.gateway }
        $null = New-NetIPAddress @parameters

        $dns = @($Address.dns | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        if ($dns.Count -gt 0) {
            $null = Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses $dns -ErrorAction Stop
        }
        Write-Log "'$alias' carries the physical adapter's address" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "Address not re-applied to '$alias': $($_.Exception.Message)" -Tag "Error"
        Write-Log "    New-NetIPAddress -InterfaceAlias '$alias' -IPAddress $($Address.ipAddress) -PrefixLength $($Address.prefixLength) -DefaultGateway $($Address.gateway)" -Tag "Error"
        return $false
    }
}

# ---------------------------[ Switches ]---------------------------
# On Server 2025 there is no separate team object to build. SET - Switch Embedded
# Teaming - *is* the virtual switch: one switch across several adapters with embedded
# teaming turned on. The old two-step arrangement was LBFO, and LBFO underneath a
# Hyper-V switch is blocked outright on 2025.
function Test-HypervLbfoTeam {
    if (-not (Get-Command -Name "Get-NetLbfoTeam" -ErrorAction SilentlyContinue)) { return $false }
    $teams = @()
    try { $teams = @(Get-NetLbfoTeam -ErrorAction Stop) } catch { $teams = @() }
    if ($teams.Count -eq 0) { return $false }

    foreach ($team in $teams) {
        Write-Log "LBFO team '$($team.Name)' present - LBFO under a Hyper-V switch is not supported on Server 2025" -Tag "Warn"
    }
    Write-Log "    Remove it and let the switch team: Remove-NetLbfoTeam -Name <name>" -Tag "Warn"
    return $true
}

# ---------------------------[ Adapter names ]---------------------------
# 'Ethernet', 'Ethernet 2', 'Ethernet 5' is what Windows leaves behind, and on a host
# whose adapters all sit under virtual switches those names say nothing about what the
# adapter is for. They are renamed before the switch is built, and **the name says which
# switch the adapter is under**:
#
#   nic-vms-01, nic-vms-02        the members of 'vswitch-vms'
#   nic-mgmt-01, nic-mgmt-02      the members of 'vswitch-mgmt'
#
# The label is the switch's own name with the word 'switch' taken out of it, so the two
# halves of the host's networking carry the same word and looking at an adapter answers
# the only question worth asking about it. **Numbered from one within each switch**, not
# across the host: the label already separates the families, so a global counter would
# only make the second switch start at 03 for no reason anybody reading it could see.
#
# There is no 'set' in the name any more. It used to mark a switch with two or more
# members, but every switch this run builds is created with embedded teaming on whatever
# its member count - a one-adapter switch is a team waiting for its second adapter - so
# the marker distinguished nothing, and two adapters sharing a label are visibly the team.
$script:hypervAdapterNameIndex = @{}

# The words that only ever say 'this is a switch'. Dropped from either end of the name,
# because both 'vswitch-vms' and 'vms-switch' get written by people who mean the same
# thing, and neither 'vswitch' nor 'switch' belongs in an adapter's name.
$script:hypervSwitchWord = @("vswitch", "vmswitch", "extswitch", "switch", "vsw", "sw")

# The prefix from the design, without whatever 'set' suffix somebody typed onto it. The
# run no longer adds one, but the designs that asked for 'nic-set' are still out there and
# must not produce 'nic-set-vms-01'.
function Get-HypervAdapterNamePrefix {
    param([string]$Prefix = "")

    $value = ([string]$Prefix).Trim()
    # Trailing separators first, then the suffix, then whatever separator that left
    # behind - 'nic-set', 'nic-set-' and 'nic_set' all have to come out as 'nic'.
    $value = $value.TrimEnd("-", "_", " ")
    $value = $value -replace "(?i)[-_ ]*set$", ""
    $value = $value.TrimEnd("-", "_", " ")
    if ([string]::IsNullOrWhiteSpace($value)) { $value = "nic" }
    return $value
}

# What the switch's name contributes to its members' names. Everything an adapter name
# cannot carry is turned into a separator first, so a switch called 'vSwitch VM/Guest'
# is read as 'vswitch-vm-guest' before a word of it is looked at.
#
# A switch named nothing but the switch word has no label to give and says so with an
# empty string - its members fall back to nic-01, nic-02. That is the only case that
# falls back: a one-word name like 'Datacenter' is a perfectly good label and is used.
function Get-HypervAdapterSwitchLabel {
    param([string]$SwitchName = "")

    $value = ([string]$SwitchName).Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($value)) { return "" }
    $value = $value -replace "[^a-z0-9]+", "-"
    $value = $value.Trim("-")
    if ([string]::IsNullOrWhiteSpace($value)) { return "" }

    $parts = @($value -split "-" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    while (($parts.Count -gt 1) -and ($script:hypervSwitchWord -contains $parts[0])) {
        $parts = @($parts | Select-Object -Skip 1)
    }
    while (($parts.Count -gt 1) -and ($script:hypervSwitchWord -contains $parts[$parts.Count - 1])) {
        $parts = @($parts | Select-Object -First ($parts.Count - 1))
    }
    if ($parts.Count -eq 0) { return "" }
    if (($parts.Count -eq 1) -and ($script:hypervSwitchWord -contains $parts[0])) { return "" }
    # A label of nothing but digits is the switch namer's own fallback - 'vswitch-02' is
    # what Get-HypervSwitchNameSuggestion reaches for once vms, mgmt and storage are
    # taken. It says no more than the number the adapter is about to get anyway, and
    # 'nic-02-01' reads as a pair of numbers rather than a name.
    if (($parts -join "") -match "^\d+$") { return "" }

    # Capped, because the label is a word for a human to recognise the adapter by and
    # 'nic-storage-replication-live-migration-01' is not that.
    $label = ($parts -join "-")
    if ($label.Length -gt 12) { $label = $label.Substring(0, 12).TrimEnd("-") }
    return $label
}

# Whether a name is free, ignoring the adapter that holds it if that adapter is the one
# being renamed - which is what makes a second run a no-op instead of a collision.
function Test-HypervAdapterNameFree {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$ExceptMac = ""
    )

    $holders = @()
    try { $holders = @(Get-NetAdapter -Name $Name -ErrorAction Stop) } catch { return $true }
    foreach ($holder in $holders) {
        if ([string]::IsNullOrWhiteSpace($ExceptMac)) { return $false }
        if (-not ([string]$holder.MacAddress).Equals($ExceptMac, [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
    }
    return $true
}

# The plan's members, found on this server. By MAC first and by name only as a fallback:
# the run renames adapters, so a plan that could only match names would stop finding its
# own members the moment it had done its job once.
function Resolve-HypervPlannedAdapter {
    param([Parameter(Mandatory)][object[]]$Member)

    $physical = @(Get-HypervPhysicalAdapter)
    $resolved = @()
    foreach ($item in $Member) {
        $name = ""
        $mac = ""
        if ($item -is [string]) { $name = [string]$item }
        else {
            $name = [string]$item.name
            $mac = [string]$item.mac
        }

        $match = $null
        if (-not [string]::IsNullOrWhiteSpace($mac)) {
            $match = @($physical | Where-Object { ([string]$_.MacAddress).Equals($mac, [System.StringComparison]::OrdinalIgnoreCase) })[0]
        }
        if (($null -eq $match) -and (-not [string]::IsNullOrWhiteSpace($name))) {
            $match = @($physical | Where-Object { [string]$_.Name -eq $name })[0]
        }
        if ($null -eq $match) {
            # Loud rather than terse: this is the one failure that silently produces a
            # host with no external switch and adapters still called 'Ethernet 5', so it
            # prints what it looked for and what it found instead.
            Write-Log "Adapter '$name' (MAC '$mac') from the interview is not on this server" -Tag "Warn"
            Write-Log "    Physical adapters here:" -Tag "Info"
            if ($physical.Count -eq 0) {
                Write-Log "        none - Get-NetAdapter -Physical returned nothing" -Tag "Warn"
            }
            foreach ($adapter in $physical) {
                Write-Log ("        {0}   MAC {1}   {2}" -f $adapter.Name, $adapter.MacAddress, $adapter.InterfaceDescription) -Tag "Info"
            }
            continue
        }
        $resolved += $match
    }
    return @($resolved)
}

function Rename-HypervTeamMember {
    param(
        [Parameter(Mandatory)][object[]]$Adapter,
        [Parameter(Mandatory)][string]$Prefix,
        # The switch these adapters are about to sit under. Its label is what puts the
        # 'vms' in nic-vms-01, and a switch that has no label to give gets nic-01.
        [string]$SwitchName = ""
    )

    $base = Get-HypervAdapterNamePrefix -Prefix $Prefix
    $label = Get-HypervAdapterSwitchLabel -SwitchName $SwitchName
    $family = $base
    if (-not [string]::IsNullOrWhiteSpace($label)) { $family = "{0}-{1}" -f $base, $label }

    # One counter per family, kept for the length of the run. Two switches that reduce to
    # the same label - 'vswitch-vms' and 'sw-vms' both say 'vms' - carry on through one
    # sequence instead of both starting at 01 and fighting over the name.
    if ($null -eq $script:hypervAdapterNameIndex) { $script:hypervAdapterNameIndex = @{} }
    if (-not $script:hypervAdapterNameIndex.ContainsKey($family)) { $script:hypervAdapterNameIndex[$family] = 0 }

    $names = @()
    foreach ($item in $Adapter) {
        $mac = [string]$item.MacAddress
        $current = [string]$item.Name

        $target = ""
        while ($true) {
            if ($script:hypervAdapterNameIndex[$family] -ge 99) { break }
            $script:hypervAdapterNameIndex[$family]++
            $number = $script:hypervAdapterNameIndex[$family]
            $candidate = "{0}-{1:00}" -f $family, $number
            if (Test-HypervAdapterNameFree -Name $candidate -ExceptMac $mac) {
                $target = $candidate
                break
            }
            Write-Log "'$candidate' is another adapter here and not a member of this switch - that number is skipped" -Tag "Warn"
        }

        if ([string]::IsNullOrWhiteSpace($target)) {
            Write-Log "No free name left for '$current' - it keeps the one it has" -Tag "Warn"
            $names += $current
            continue
        }
        if ($current -eq $target) {
            Write-Log "'$current' is already named for its place in the team" -Tag "Debug"
            $names += $target
            continue
        }
        try {
            Rename-NetAdapter -Name $current -NewName $target -ErrorAction Stop
            Write-Log "'$current' -> '$target'" -Tag "Ok"
            $names += $target
        }
        catch {
            Write-Log "'$current' not renamed to '$target': $($_.Exception.Message)" -Tag "Warn"
            $names += $current
        }
    }
    return @($names)
}

function New-HypervVirtualSwitch {
    param(
        [Parameter(Mandatory)][object]$Definition,
        [switch]$RenameMembers,
        [string]$NamePrefix = "nic"
    )

    $name = [string]$Definition.name
    if ([string]::IsNullOrWhiteSpace($name)) { return $false }

    $existing = $null
    try { $existing = Get-VMSwitch -Name $name -ErrorAction Stop } catch { $existing = $null }
    if ($null -ne $existing) {
        # Adopted, never rebuilt. Embedded teaming, SR-IOV and the minimum bandwidth
        # mode are decided when a switch is created and cannot be changed afterwards -
        # so "make it match" would mean deleting a switch, which takes every virtual
        # machine on it off the network and, when the management operating system shares
        # it, this session with them.
        Write-Log "Switch '$name' already exists - left as it is" -Tag "Info"
        return $true
    }

    $switchType = [string]$Definition.type
    if ([string]::IsNullOrWhiteSpace($switchType)) { $switchType = "External" }

    $adapters = @()
    $parameters = @{ Name = $name; ErrorAction = "Stop" }
    if ($switchType -eq "External") {
        $planned = @($Definition.adapters | Where-Object { $null -ne $_ })
        if ($planned.Count -eq 0) {
            Write-Log "Switch '$name' is external and names no adapter - skipped" -Tag "Error"
            return $false
        }
        $members = @(Resolve-HypervPlannedAdapter -Member $planned)
        if ($members.Count -eq 0) {
            Write-Log "No adapter planned for '$name' was found here - skipped" -Tag "Error"
            return $false
        }

        # Renamed before the switch is built, never after: once a switch owns them the
        # names are what the team members are referred to by, and renaming them then
        # means touching a switch that virtual machines are already on.
        $adapters = @($members | ForEach-Object { [string]$_.Name })
        if ($RenameMembers) {
            $adapters = @(Rename-HypervTeamMember -Adapter $members -Prefix $NamePrefix -SwitchName $name)
        }
        $parameters["NetAdapterName"] = $adapters
        $parameters["AllowManagementOS"] = [bool]$Definition.managementOs
        # On even for a single adapter, and that is deliberate: embedded teaming cannot
        # be turned on later. A switch built without it has to be deleted and rebuilt to
        # gain a second adapter; built with it, the second adapter is one
        # Add-VMSwitchTeamMember away.
        $parameters["EnableEmbeddedTeaming"] = $true
    }
    else {
        $parameters["SwitchType"] = $switchType
    }

    Write-Log ("Creating the {0} switch '{1}'{2}" -f $switchType.ToLowerInvariant(), $name,
        $(if ($adapters.Count -gt 0) { " over " + ($adapters -join ", ") } else { "" })) -Tag "Run"
    try {
        $null = New-VMSwitch @parameters
        Write-Log "Switch '$name' created" -Tag "Ok"
    }
    catch {
        Write-Log "Switch '$name' not created: $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    if ($switchType -eq "External") {
        # Dynamic when the plan carries nothing, because that is what Set-VMSwitchTeam
        # itself defaults to. It used to be HyperVPort here, which quietly imposed the
        # 10 Gbps answer on a design that never said anything.
        $algorithm = [string]$Definition.loadBalancing
        if ([string]::IsNullOrWhiteSpace($algorithm)) { $algorithm = "Dynamic" }
        try {
            $null = Set-VMSwitchTeam -Name $name -LoadBalancingAlgorithm $algorithm -ErrorAction Stop
            Write-Log "'$name': load balancing $algorithm" -Tag "Ok"
        }
        catch {
            Write-Log "Load balancing not set on '$name': $($_.Exception.Message)" -Tag "Warn"
        }
    }

    $vlanId = 0
    try { $vlanId = [int]$Definition.vlanId } catch { $vlanId = 0 }
    if (($vlanId -gt 0) -and [bool]$Definition.managementOs) {
        try {
            $null = Set-VMNetworkAdapterVlan -ManagementOS -VMNetworkAdapterName $name -Access -VlanId $vlanId -ErrorAction Stop
            Write-Log "'$name': management adapter tagged VLAN $vlanId" -Tag "Ok"
        }
        catch {
            Write-Log "VLAN $vlanId not set on '$name': $($_.Exception.Message)" -Tag "Warn"
        }
    }

    if (($null -ne $Definition.management) -and [bool]$Definition.managementOs) {
        $null = Restore-HypervManagementAddress -Address $Definition.management -SwitchName $name
    }
    return $true
}

# ---------------------------[ Restart ]---------------------------
# The role that finishes needing a restart it cannot perform itself, exactly like
# Exchange - and on a machine with nothing running on it yet, which is the whole reason
# this is allowed to be automatic. The engine refuses to act on the answer unless the
# resume task is registered, so a restart never leaves a server that has forgotten it
# was mid-run.
function Get-HypervAutoRestartDelay {
    param([object]$Config)

    $hyperv = Get-HypervSection -Config $Config
    if ($null -eq $hyperv) { return 0 }
    if (-not [bool](Get-ConfigValue -InputObject $hyperv -Name "autoRestart" -Default $true)) { return 0 }
    return [int](Get-ConfigValue -InputObject $hyperv -Name "autoRestartDelaySeconds" -Default 15)
}

# ---------------------------[ The interview ]---------------------------
# The console half, and the only place a human is ever asked anything. Gated exactly the
# way the Arc and connector roles gate theirs: never under -NoGui, never in the resume
# leg, never without a real interactive session. Headless the run does the declarative
# half and says what it skipped.
function Test-HypervInterviewWanted {
    if ($script:noGui) { return $false }
    if ($script:isResume) { return $false }
    if (-not [Environment]::UserInteractive) { return $false }
    return (Test-MenuHostSupported)
}

# Every question carries its recommended answer already selected, so Enter walks the
# whole thing and produces the layout this repo would have argued for anyway.
function Read-HypervChoice {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Heading,
        [string]$Hint = "",
        [Parameter(Mandatory)][object[]]$Items,
        # Drawn above the menu on every redraw - what is already planned, so the answer
        # is chosen against the list rather than against memory.
        [scriptblock]$PreItems
    )
    return (Show-Menu -Title "Hyper-V host setup" -Heading $Heading -HeadingHint $Hint -Subtitle $Title `
            -Items $Items -PreItems $PreItems)
}

# The same question when the answer is a set: which adapters, which disks. Space ticks.
function Read-HypervMultiChoice {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Heading,
        [string]$Hint = "",
        [Parameter(Mandatory)][object[]]$Items,
        [scriptblock]$PreItems
    )
    return (Show-MultiSelectMenu -Title "Hyper-V host setup" -Heading $Heading -HeadingHint $Hint -Subtitle $Title `
            -Items $Items -PreItems $PreItems)
}

function Read-HypervText {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [string]$Default = "",
        # A typed prompt cannot be escaped the way a menu can, so the word is the way
        # back. Returns an empty string, which every caller already treats as "leave
        # this step alone".
        [switch]$AllowBack
    )

    $suffix = ""
    if (-not [string]::IsNullOrWhiteSpace($Default)) { $suffix = " [$Default]" }
    if ($AllowBack) { $suffix = $suffix + " (or 'back')" }
    $answer = Read-Host ("  " + $Prompt + $suffix)
    if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
    $answer = $answer.Trim()
    if ($AllowBack -and $answer.Equals("back", [System.StringComparison]::OrdinalIgnoreCase)) { return "" }
    return $answer
}

function Get-HypervStorageAnswer {
    param([Parameter(Mandatory)][object]$Hyperv)

    $storage = Get-ConfigValue -InputObject $Hyperv -Name "storage"

    # 'prepareDataVolume' is the stand-alone host's D: - a clustered host has no such
    # volume and its Cluster Shared Volumes are not that question answered again. So the
    # toggle being off skips the data volume and **never** the cluster disk question: a
    # cluster whose disks were never asked for has nothing to build on.
    $clusterMode = Test-HypervClusterWanted -Hyperv $Hyperv
    $prepareWanted = ($null -ne $storage) -and
        [bool](Get-ConfigValue -InputObject $storage -Name "prepareDataVolume" -Default $true)
    if ((-not $prepareWanted) -and (-not $clusterMode)) { return $null }
    # A cluster with no storage section at all still gets asked. Every read below takes a
    # default, and Get-ConfigText will not accept $null.
    if ($null -eq $storage) { $storage = [pscustomobject]@{} }

    $answer = [pscustomobject]@{
        driveLetter        = ([string](Get-ConfigText -InputObject $storage -Name "driveLetter" -Default "D:")).Trim().TrimEnd(":", "\")
        diskNumber         = -1
        partitionSizeBytes = 0
        pool               = $null
        # Clustered hosts only. On the Storage Spaces Direct path these are the disks that
        # go into the one pool every volume is carved from; on the shared-disk path they
        # are one whole disk per Cluster Shared Volume, in order.
        clusterDisks       = @()
        # The same disks by identity rather than by number, because a disk number is only
        # true until the next restart and the pool is built on the far side of one.
        clusterDiskIds     = @()
        # The subset of those disks the operator confirmed may be wiped, by number. A disk
        # that already carries partitions is only ever cleared because this list says so.
        clusterDiskWipe    = @()
        # What the cluster's storage actually is - 's2d', 'sharedDisks' or 'plain'. Decided
        # at the console against this machine's hardware, so it beats the design's answer:
        # only the console saw whether Storage Spaces Direct was possible here at all.
        clusterStorageMode = ""
        # How many copies of everything the cluster volumes carry. Asked at the console
        # rather than taken from the design alone, because how many are *possible* depends
        # on how many disks were just ticked - which the design cannot know.
        clusterCopies      = 0
    }

    $poolWanted = $false
    $pool = Get-ConfigValue -InputObject $storage -Name "pool"
    if ($null -ne $pool) { $poolWanted = [bool](Get-ConfigValue -InputObject $pool -Name "enabled" -Default $false) }

    # A clustered host is asked a different storage question entirely - see below. Its
    # volumes are whole disks, so the pool screen never appears for it.
    if ($clusterMode) {
        $chosen = Get-HypervClusterDiskAnswer -Hyperv $Hyperv
        $answer.clusterDisks = @($chosen.Numbers)
        $answer.clusterDiskIds = @($chosen.Ids)
        $answer.clusterDiskWipe = @($chosen.Wipe)
        $answer.clusterStorageMode = [string]$chosen.Mode
        $answer.clusterCopies = [int]$chosen.Copies
        return $answer
    }

    # The pool step only exists when the design asked for one. A host with a RAID
    # controller behind it never sees this screen - its array arrives as one
    # uninitialised disk and takes the same path a pooled virtual disk does.
    if ($poolWanted) {
        $candidates = @(Get-StudioPoolCandidateDisk)
        if ($candidates.Count -lt 2) {
            Write-Log "A pool was asked for and $($candidates.Count) disk(s) are poolable - fewer than two cannot be redundant, so none is built" -Tag "Warn"
        }
        else {
            # Every candidate starts ticked: a pool built from all of the free disks is
            # the answer this repo would argue for, so Enter walks straight past it.
            $items = @()
            foreach ($candidate in $candidates) {
                $items += [pscustomobject]@{
                    Id       = [string]$candidate.DeviceId
                    Selected = $true
                    Label    = ("{0}   {1}   {2}   {3}" -f $candidate.FriendlyName,
                        (Format-StudioCapacity -Bytes ([long]$candidate.Size)), $candidate.BusType, $candidate.MediaType)
                    Detail   = @(Get-StudioDiskDetail -Physical $candidate)
                }
            }

            $picked = Read-HypervMultiChoice -Title "Storage pool" -Heading "Which disks go into the pool?" `
                -Hint "Everything listed is a disk Windows says is free. Check the serials against the sticker. Nothing ticked means no pool." -Items $items
            if ($null -eq $picked) {
                $chosen = @()
            }
            else {
                $chosen = @($candidates | Where-Object { @($picked) -contains [string]$_.DeviceId })
            }

            if ($chosen.Count -ge 2) {
                # Every layout these disks can be built into, with the capacity and the
                # column count each one would end up with - and the one this workload
                # wants first, which is where the cursor already is. Nothing is hidden:
                # parity and simple are on the list with what they cost written on them.
                $rawBytes = 0
                foreach ($item in $chosen) { $rawBytes += [long]$item.Size }
                $layouts = @(Get-StudioPoolLayout -DiskCount $chosen.Count -RawBytes $rawBytes)

                $layoutItems = @()
                foreach ($layout in $layouts) {
                    $marker = ""
                    if ($layout.Recommended) { $marker = "   <- recommended" }
                    $layoutItems += [pscustomobject]@{ Id = $layout.Id; Label = ($layout.Label + $marker) }
                }
                $layoutId = Read-HypervChoice -Title "Storage pool" -Heading "How is the space laid out?" `
                    -Hint "Top of the list is what a host full of running virtual machines wants: mirrored, striped across as many columns as the disks allow." -Items $layoutItems
                if ($null -eq $layoutId) { $layoutId = $layouts[0].Id }
                $layout = @($layouts | Where-Object { $_.Id -eq $layoutId })[0]

                if (-not $layout.Recommended) {
                    Write-Log ("'{0}' was chosen over the recommended layout - {1}" -f $layout.Id, $layout.Label) -Tag "Warn"
                }

                $suggested = [string](Get-ConfigText -InputObject $pool -Name "name" -Default "")
                if ([string]::IsNullOrWhiteSpace($suggested)) { $suggested = Get-StudioPoolNameSuggestion -Base "pool" }
                $poolName = Read-HypervText -Prompt "Pool name" -Default $suggested
                $answer.pool = [pscustomobject]@{
                    name       = $poolName
                    resiliency = $layout.Resiliency
                    copies     = $layout.Copies
                    redundancy = $layout.Redundancy
                    disks      = @($chosen | ForEach-Object { [string]$_.DeviceId })
                }
            }
            elseif ($chosen.Count -eq 1) {
                Write-Log "One disk is not a redundant pool - none built" -Tag "Warn"
            }
        }
    }

    # No pool, or a pool that was declined: the volume comes from one disk. Two kinds
    # qualify and the second is the one most servers actually have - a RAID 1 pair
    # arrives as one array with a 64 GB system partition on it and the rest unallocated,
    # which is not an uninitialised disk and never used to be offered here at all.
    if ($null -eq $answer.pool) {
        $candidates = @(Get-HypervDataDiskCandidate)

        if ($candidates.Count -eq 0) {
            Write-Log "No free disk or unallocated space here to build the data volume from" -Tag "Warn"
        }
        else {
            $chosenDisk = $null
            if ($candidates.Count -eq 1) {
                $chosenDisk = $candidates[0]
                Write-Log ("{0} is the only candidate and becomes the data volume" -f $chosenDisk.Label) -Tag "Info"
            }
            else {
                $items = @()
                foreach ($candidate in $candidates) {
                    $items += [pscustomobject]@{ Id = [string]$candidate.Id; Label = [string]$candidate.Label }
                }
                $picked = Read-HypervChoice -Title "Data volume" -Heading "Where does the data volume come from?" `
                    -Hint "An uninitialised disk is initialised and formatted whole. Unallocated space becomes a new partition and touches nothing already on the disk." -Items $items
                if ($null -ne $picked) { $chosenDisk = @($candidates | Where-Object { $_.Id -eq $picked })[0] }
            }

            if ($null -ne $chosenDisk) {
                $answer.diskNumber = [int]$chosenDisk.Number
                if ($chosenDisk.FreeSpace) {
                    $maximumGb = [math]::Floor($chosenDisk.FreeBytes / 1GB)
                    $sizeAnswer = Read-HypervText -Prompt ("How much of the {0} GB unallocated space, in GB" -f $maximumGb) -Default "max"
                    if ($sizeAnswer -match "^\d+$") {
                        $wanted = [long]$sizeAnswer * 1GB
                        if ($wanted -ge $chosenDisk.FreeBytes) { $answer.partitionSizeBytes = 0 }
                        else { $answer.partitionSizeBytes = $wanted }
                    }
                }
            }
        }
    }

    $answer.driveLetter = (Read-HypervText -Prompt "Drive letter for the data volume" -Default $answer.driveLetter).TrimEnd(":", "\")
    Write-Log ("{0}: this volume's letter - anything else holding it moves" -f $answer.driveLetter) -Tag "Info"
    return $answer
}

# What a given number of copies actually leaves you with, in the words the menu shows:
# the volumes it can carve, how big each is, and what is held back for repairs. Silent -
# it is drawn inside a menu label, so it explains itself in one line or not at all.
function Get-HypervClusterSizeLine {
    param(
        [long]$RawBytes = 0,
        [long]$LargestDiskBytes = 0,
        [int]$DiskCount = 0,
        [Parameter(Mandatory)][int]$Copies,
        [int]$VolumeCount = 2
    )

    if ($RawBytes -le 0) { return "" }
    $plan = Get-HypervClusterVolumePlan -FreeBytes $RawBytes -LargestDiskBytes $LargestDiskBytes `
        -DiskCount $DiskCount -Copies $Copies -Count $VolumeCount
    if ($plan.PerVolume -le 0) { return "too small to divide" }

    $line = "{0} x {1} GB" -f $VolumeCount, [math]::Round($plan.PerVolume / 1GB)
    if ($plan.Reserve -gt 0) {
        $line = $line + (" ({0} GB usable, {1} GB kept for repairs)" -f [math]::Round($plan.Usable / 1GB), [math]::Round($plan.Reserve / 1GB))
    }
    else {
        $line = $line + (" ({0} GB usable, no repair capacity)" -f [math]::Round($plan.Usable / 1GB))
    }
    return $line
}

# How many copies the cluster volumes carry, offered against the disks that were actually
# ticked. Four copies needs four disks to put them on - the fault domain on one node is the
# physical disk - so a menu built from the design alone would offer answers this pool
# cannot honour.
function Get-HypervClusterCopiesAnswer {
    param(
        [Parameter(Mandatory)][object]$Cluster,
        [Parameter(Mandatory)][int]$DiskCount,
        # What the ticked disks add up to, so each row can say what it would leave behind.
        # The numbers come from the same function that sizes the volumes for real.
        [long]$RawBytes = 0,
        [long]$LargestDiskBytes = 0,
        [int]$VolumeCount = 2
    )

    $wanted = [int](Get-ConfigValue -InputObject $Cluster -Name "mirrorCopies" -Default 2)
    if ($wanted -lt 1) { $wanted = 1 }
    if ($wanted -gt 4) { $wanted = 4 }

    $items = @()
    foreach ($copies in @(2, 3, 4, 1)) {
        if (($copies -gt 1) -and ($DiskCount -lt $copies)) { continue }
        $name = switch ($copies) {
            2 { "Two-way mirror   survives one disk" }
            3 { "Three-way mirror survives two disks" }
            4 { "Four-way mirror  survives three disks" }
            1 { "Simple           NO RESILIENCY, one disk failure loses everything" }
        }
        $items += [pscustomobject]@{
            Id    = [string]$copies
            Label = ("{0}   {1}" -f $name, (Get-HypervClusterSizeLine -RawBytes $RawBytes -LargestDiskBytes $LargestDiskBytes `
                    -DiskCount $DiskCount -Copies $copies -VolumeCount $VolumeCount))
        }
    }

    # The design's answer first, so Enter takes it - unless these disks cannot carry it,
    # in which case the best they can is at the top and the log says why.
    $preferred = $wanted
    if ($DiskCount -lt $preferred) {
        $preferred = [math]::Max(1, [math]::Min(4, $DiskCount))
        Write-Log ("Design asks for {0} copies and {1} disk(s) were ticked - {2} is the most they carry" -f $wanted, $DiskCount, $preferred) -Tag "Warn"
    }
    $ordered = @($items | Where-Object { $_.Id -eq [string]$preferred })
    $ordered += @($items | Where-Object { $_.Id -ne [string]$preferred })

    $heading = "How resilient, across {0} disk(s)?" -f $DiskCount
    $hint = "Every copy needs a disk of its own to sit on - one node has nothing but its disks to spread them across."
    if ($RawBytes -gt 0) {
        $hint = ("The pool holds {0} GB raw. " -f [math]::Round($RawBytes / 1GB)) + $hint
    }
    $picked = Read-HypervChoice -Title "Cluster storage" -Heading $heading -Hint $hint -Items $ordered
    if ($null -eq $picked) { $picked = [string]$preferred }

    $copies = 2
    try { $copies = [int]$picked } catch { $copies = 2 }
    if ($copies -eq 1) {
        Write-Log "Simple chosen - the cluster volumes have no resiliency at all" -Tag "Warn"
    }
    else {
        Write-Log ("Cluster volumes: {0} copies of everything" -f $copies) -Tag "Info"
    }
    return $copies
}

# Which disks the cluster gets, and the question is a different one on each path.
#
#   Storage Spaces Direct   **All of them go into one pool**, and every Cluster Shared
#                           Volume is carved out of that pool - the disks stop being
#                           individually meaningful and become capacity the cluster owns.
#                           Two is the floor, because a mirror needs somewhere to put the
#                           second copy.
#   Shared disks            One whole disk per volume, in the order they are ticked - a
#                           SAN LUN or an iSCSI target is a disk and stays one.
function Get-HypervClusterDiskAnswer {
    param([Parameter(Mandatory)][object]$Hyperv)

    $cluster = Get-HypervClusterSection -Hyperv $Hyperv
    $labels = @(Get-HypervCsvLabel -Cluster $cluster)

    # Where the volumes come from. The design's answer, carried into the plan so the leg on
    # the far side of the restart builds what this leg prepared.
    $mode = Get-HypervClusterStorageMode -Cluster $cluster
    $empty = [pscustomobject]@{ Numbers = @(); Ids = @(); Wipe = @(); Copies = 0; Mode = $mode }
    $pooled = ($mode -eq "s2d")

    # Every disk on the machine, classified rather than filtered - see
    # Get-HypervClusterDiskCandidate. A disk this run will not touch is named with the
    # reason, because "it was not in the list" is the one answer an operator cannot act on.
    $all = @(Get-HypervClusterDiskCandidate)
    $candidates = @($all | Where-Object { $_.Usable })
    foreach ($item in @($all | Where-Object { -not $_.Usable })) {
        Write-Log ("Disk {0} not offered: {1}" -f $item.Number, $item.Reason) -Tag "Info"
    }

    if ($candidates.Count -eq 0) {
        Write-Log "No disk here the cluster can use - it takes whole disks, never a slice" -Tag "Error"
        Write-Log "    Unallocated space beside a partition can still be a stand-alone volume: switch the cluster off and this run builds D: instead" -Tag "Info"
        Write-Log "    A cluster here needs a whole second disk, or shared storage from outside" -Tag "Info"
        return $empty
    }
    if ((-not $pooled) -and ($candidates.Count -lt $labels.Count)) {
        Write-Log ("Design asks for {0} Cluster Shared Volume(s), {1} free disk(s) here" -f $labels.Count, $candidates.Count) -Tag "Warn"
    }

    # Empty disks first: they are the answer, and a disk that would have to be wiped
    # should never be the one the cursor lands on.
    $candidates = @(@($candidates | Where-Object { -not $_.NeedsWipe }) + @($candidates | Where-Object { $_.NeedsWipe }))

    $items = @()
    $offered = 0
    foreach ($candidate in $candidates) {
        # Pooled: every empty disk ticked, because the usual answer is all of them. Shared
        # disks: as many as there are volumes. A disk carrying data is **never** ticked by
        # this run - it is on the list to be chosen deliberately or not at all.
        $selected = $false
        if (-not $candidate.NeedsWipe) {
            $selected = $true
            if (-not $pooled) { $selected = ($offered -lt $labels.Count) }
            $offered++
        }
        $items += [pscustomobject]@{
            Id       = [string]$candidate.Number
            Selected = $selected
            Label    = [string]$candidate.Label
            Detail   = @($candidate.Detail)
        }
    }

    if ($pooled) {
        $heading = "Which disks go into the Storage Spaces Direct pool?"
        $hint = ("Every ticked disk goes into one pool, and {0} are carved out of it. An empty disk is left untouched until the cluster exists - S2D claims it itself." -f ($labels -join " and "))
    }
    else {
        $heading = ("Which disks become {0}?" -f ($labels -join " and "))
        $hint = "One whole disk each, in the order they are ticked. Each is initialised, formatted and handed to the cluster."
    }
    if (@($candidates | Where-Object { $_.NeedsWipe }).Count -gt 0) {
        $hint = $hint + " A disk marked ERASES is not empty and is confirmed separately."
    }

    $picked = @(Read-HypervMultiChoice -Title "Cluster storage" -Heading $heading -Hint $hint -Items $items)
    $chosen = @()
    foreach ($id in $picked) {
        if ([string]::IsNullOrWhiteSpace([string]$id)) { continue }
        try { $chosen += [int]$id } catch { }
    }

    if ($chosen.Count -eq 0) {
        Write-Log "No disk ticked - the cluster has no storage to build on" -Tag "Warn"
        return $empty
    }

    # Anything ticked that is not empty is destroyed before it can be used, and that is
    # asked for in words rather than with a keystroke. Declining drops those disks and
    # keeps the rest of the answer.
    $wipe = @()
    $dirty = @($candidates | Where-Object { $_.NeedsWipe -and (@($chosen) -contains [int]$_.Number) })
    if ($dirty.Count -gt 0) {
        Write-Log ("{0} ticked disk(s) are not empty and would be erased:" -f $dirty.Count) -Tag "Warn"
        foreach ($item in $dirty) {
            Write-Log ("    disk {0}   {1} GB   {2}" -f $item.Number, [math]::Round($item.SizeBytes / 1GB), $item.State) -Tag "Warn"
        }
        Write-Log "    Every partition, volume and file on them is destroyed - no undo, nothing backed up" -Tag "Warn"
        $answered = Read-HypervText -Prompt "Type ERASE to confirm, or press Enter to leave them alone" -Default ""
        if ([string]$answered -ceq "ERASE") {
            $wipe = @($dirty | ForEach-Object { [int]$_.Number })
            Write-Log ("Erase confirmed at the console: disk(s) {0}" -f ($wipe -join ", ")) -Tag "Warn"
        }
        else {
            $dropped = @($dirty | ForEach-Object { [int]$_.Number })
            $chosen = @($chosen | Where-Object { $dropped -notcontains [int]$_ })
            Write-Log ("Disk(s) {0} keep their contents and are not used" -f ($dropped -join ", ")) -Tag "Info"
            if ($chosen.Count -eq 0) {
                Write-Log "Nothing left to build the cluster storage on" -Tag "Warn"
                return $empty
            }
        }
    }

    if ((-not $pooled) -and ($chosen.Count -gt $labels.Count)) {
        Write-Log ("{0} disk(s) ticked for {1} volume(s) - the first {1} are used" -f $chosen.Count, $labels.Count) -Tag "Warn"
        $chosen = @($chosen | Select-Object -First $labels.Count)
    }
    if ($pooled -and ($chosen.Count -lt 2)) {
        Write-Log "One disk cannot be mirrored - every volume in this pool would survive nothing" -Tag "Warn"
    }

    # Identity as well as number. The pool is built after a restart, and a disk number is
    # only true until then.
    $ids = @()
    foreach ($number in $chosen) {
        try {
            $disk = Get-Disk -Number $number -ErrorAction Stop
            foreach ($value in @([string]$disk.UniqueId, [string]$disk.SerialNumber)) {
                if (-not [string]::IsNullOrWhiteSpace($value)) { $ids += $value.Trim() }
            }
        }
        catch { }
    }

    if ($pooled) {
        Write-Log ("Pool: {0} disk(s) in, {1} out" -f $chosen.Count, ($labels -join " and ")) -Tag "Info"
    }
    else {
        for ($index = 0; $index -lt $chosen.Count; $index++) {
            Write-Log ("    {0} from disk {1}" -f $labels[$index], $chosen[$index]) -Tag "Info"
        }
    }
    # How resilient, asked here because only now is it known how many disks there are to
    # spread copies across. The design's answer is the one selected; anything the ticked
    # disks cannot carry is simply not on the menu.
    $copies = 0
    if ($pooled) {
        $raw = 0
        $largest = 0
        foreach ($number in $chosen) {
            $candidate = @($candidates | Where-Object { [int]$_.Number -eq [int]$number })[0]
            if ($null -eq $candidate) { continue }
            $raw += [long]$candidate.FreeBytes
            if ([long]$candidate.FreeBytes -gt $largest) { $largest = [long]$candidate.FreeBytes }
        }
        if ($raw -gt 0) {
            Write-Log ("    {0} disk(s), {1} GB raw" -f $chosen.Count, [math]::Round($raw / 1GB)) -Tag "Info"
        }
        $copies = Get-HypervClusterCopiesAnswer -Cluster $cluster -DiskCount $chosen.Count -RawBytes $raw `
            -LargestDiskBytes $largest -VolumeCount $labels.Count
    }

    # The wipe list is narrowed to what is actually being used: a disk trimmed off by the
    # volume count above is not erased for a volume it never becomes.
    $wipe = @($wipe | Where-Object { @($chosen) -contains [int]$_ })
    return [pscustomobject]@{ Numbers = @($chosen); Ids = @($ids); Wipe = @($wipe); Copies = $copies; Mode = $mode }
}

# Every disk on the machine, classified rather than filtered, because a cluster claims a
# whole disk and the only question is what state that disk is in.
#
#   Usable, empty        Uninitialised (PartitionStyle RAW), or initialised with no
#                        partitions on it. Storage Spaces Direct pools either as it finds
#                        them - "make sure your drives are empty" means no partitions,
#                        not no partition table.
#   Usable, needs wiping Carries partitions. Offered, never ticked by default, and only
#                        cleared after the console confirms it in words.
#   Not usable           The boot or system disk, or a disk another cluster already owns.
#                        Named with the reason: a disk that is silently absent from the
#                        list is a disk nobody can act on.
#
# Unallocated space beside an existing partition is deliberately not a candidate. A pool
# claims disks, not slices, and so does a cluster - that answer belongs to the stand-alone
# data volume in Get-HypervDataDiskCandidate.
function Get-HypervClusterDiskCandidate {
    $disks = @()
    try { $disks = @(Get-Disk -ErrorAction Stop | Sort-Object -Property Number) }
    catch {
        Write-Log "Disks unreadable: $($_.Exception.Message)" -Tag "Warn"
        return @()
    }

    $candidates = @()
    foreach ($disk in $disks) {
        $number = [int]$disk.Number
        $size = 0
        try { $size = [long]$disk.Size } catch { $size = 0 }
        $bus = [string]$disk.BusType
        if ([string]::IsNullOrWhiteSpace($bus)) { $bus = "unknown bus" }

        $usable = $true
        $reason = ""
        if ($disk.IsBoot -or $disk.IsSystem) {
            $usable = $false
            $reason = "it carries the boot or system volume"
        }
        elseif ($disk.IsClustered) {
            $usable = $false
            $reason = "a cluster already owns it"
        }

        # How many partitions, counted rather than inferred from the partition style: an
        # initialised disk with nothing on it is as poolable as an uninitialised one.
        $partitions = -1
        if ([string]$disk.PartitionStyle -eq "RAW") { $partitions = 0 }
        else {
            try { $partitions = @(Get-Partition -DiskNumber $number -ErrorAction Stop).Count }
            catch {
                # An offline or unreadable disk answers nothing. NumberOfPartitions comes
                # off the disk object itself and is the second-best answer.
                try { $partitions = [int]$disk.NumberOfPartitions } catch { $partitions = -1 }
            }
        }

        if ([string]$disk.PartitionStyle -eq "RAW") { $state = "uninitialised, taken whole" }
        elseif ($partitions -eq 0) { $state = ("initialised {0}, no partitions, taken whole" -f $disk.PartitionStyle) }
        elseif ($partitions -gt 0) { $state = ("{0} partition(s) on it - ERASES EVERYTHING" -f $partitions) }
        else { $state = "state unreadable - ERASES EVERYTHING" }

        $needsWipe = ($usable -and ($partitions -ne 0))
        $offline = ""
        if ($disk.IsOffline) { $offline = "   offline" }

        $candidates += [pscustomobject]@{
            Number    = $number
            Usable    = $usable
            NeedsWipe = $needsWipe
            Reason    = $reason
            State     = $state
            SizeBytes = $size
            # The whole disk is what the cluster gets, so its size is its free space. The
            # name matches what the resiliency question reads off a candidate.
            FreeBytes = $size
            Label     = ("disk {0}   {1}   {2}{3}   {4}" -f $number,
                (Format-StudioCapacity -Bytes $size), $bus, $offline, $state)
            Detail    = @(Get-StudioDiskDetail -Disk $disk)
        }
    }
    return $candidates
}

# The two kinds of disk a data volume can come from, in one list because the question
# asked at the console is one question: where does it come from?
function Get-HypervDataDiskCandidate {
    $disks = @()
    try { $disks = @(Get-Disk -ErrorAction Stop | Sort-Object -Property Number) }
    catch {
        Write-Log "Disks unreadable: $($_.Exception.Message)" -Tag "Warn"
        return @()
    }

    $candidates = @()
    foreach ($disk in $disks) {
        if ($disk.IsClustered) { continue }

        if ($disk.PartitionStyle -eq "RAW") {
            # The whole disk, initialised and formatted. Never the boot or system disk:
            # this path writes a partition table.
            if ($disk.IsBoot -or $disk.IsSystem) { continue }
            $candidates += [pscustomobject]@{
                Id        = "raw:$($disk.Number)"
                Number    = [int]$disk.Number
                FreeSpace = $false
                FreeBytes = [long]$disk.Size
                Label     = ("disk {0}   {1}   {2}   uninitialised, taken whole" -f $disk.Number,
                    (Format-StudioCapacity -Bytes ([long]$disk.Size)), $disk.BusType)
                Detail    = @(Get-StudioDiskDetail -Disk $disk)
            }
            continue
        }

        # Unallocated space on a disk that already carries partitions - including the one
        # Windows booted from, because a partition built in free space initialises
        # nothing and moves nothing.
        $free = 0
        try { $free = [long]$disk.LargestFreeExtent } catch { $free = 0 }
        if ($free -lt $script:storageFreeSpaceMinimumBytes) { continue }

        $marker = ""
        if ($disk.IsBoot -or $disk.IsSystem) { $marker = "   <- the system disk" }
        $partitionCount = 0
        try { $partitionCount = [int]$disk.NumberOfPartitions } catch { $partitionCount = 0 }
        $candidates += [pscustomobject]@{
            Id        = "free:$($disk.Number)"
            Number    = [int]$disk.Number
            FreeSpace = $true
            FreeBytes = $free
            Label     = ("disk {0}   {1} unallocated of {2}   {3}   new partition{4}" -f $disk.Number,
                (Format-StudioCapacity -Bytes $free), (Format-StudioCapacity -Bytes ([long]$disk.Size)),
                $disk.BusType, $marker)
            Detail    = @(@(("{0}, {1} partition(s) already on it" -f $disk.PartitionStyle, $partitionCount)) +
                @(Get-StudioDiskDetail -Disk $disk))
        }
    }
    return $candidates
}

# The switches this host already carries. Empty before the role is installed - there is
# no Get-VMSwitch yet - and that is the normal first run rather than a failure. On a
# re-run it matters twice: they are shown so nobody plans a switch that already exists,
# and the adapters they own are off the table, because an adapter belongs to one switch.
function Get-HypervExistingSwitch {
    if (-not (Get-Command -Name "Get-VMSwitch" -ErrorAction SilentlyContinue)) { return @() }

    $switches = @()
    try { $switches = @(Get-VMSwitch -ErrorAction Stop) } catch { return @() }
    if ($switches.Count -eq 0) { return @() }

    # Adapters are matched by interface description rather than by name: that is what a
    # switch records, and it survives the renaming this role does.
    $physical = @(Get-HypervPhysicalAdapter)
    $result = @()
    foreach ($item in $switches) {
        $descriptions = @()
        if (-not [string]::IsNullOrWhiteSpace([string]$item.NetAdapterInterfaceDescription)) {
            $descriptions += [string]$item.NetAdapterInterfaceDescription
        }
        try {
            $team = Get-VMSwitchTeam -Name $item.Name -ErrorAction Stop
            if ($null -ne $team) { $descriptions += @([string[]]$team.NetAdapterInterfaceDescription) }
        }
        catch {
            # Not a team, or no teaming cmdlets here. The single description above is
            # then the whole answer.
        }
        $descriptions = @($descriptions | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)

        $names = @()
        foreach ($description in $descriptions) {
            $match = @($physical | Where-Object { [string]$_.InterfaceDescription -eq $description })
            foreach ($adapter in $match) { $names += [string]$adapter.Name }
        }

        $result += [pscustomobject]@{
            Name         = [string]$item.Name
            Type         = [string]$item.SwitchType
            AdapterNames = @($names)
            Descriptions = @($descriptions)
        }
    }
    return @($result)
}

# What a planned switch reads as on one line.
function Get-HypervSwitchLine {
    param([Parameter(Mandatory)][object]$Definition)

    $detail = @()
    $adapters = @($Definition.adapters | ForEach-Object { [string]$_.name })
    if ($adapters.Count -gt 0) { $detail += ($adapters -join " + ") }
    if ([bool]$Definition.managementOs) { $detail += "the host shares it" }
    if ([int]$Definition.vlanId -gt 0) { $detail += "VLAN $([int]$Definition.vlanId)" }
    if (($null -ne $Definition.management) -and (-not [bool]$Definition.management.dhcp)) {
        $detail += "keeps $([string]$Definition.management.ipAddress)"
    }
    return ("{0,-20} {1,-9} {2}" -f [string]$Definition.name, [string]$Definition.type, ($detail -join ", "))
}

# The panel above the menu: everything planned so far and everything already here. It is
# redrawn on every keypress, so what is on the screen is always the current answer.
function Write-HypervSwitchPanel {
    param(
        [object[]]$Planned = @(),
        [object[]]$Existing = @()
    )

    Write-Host "  Planned in this run" -ForegroundColor White
    if ($Planned.Count -eq 0) {
        Write-Host "    nothing yet" -ForegroundColor DarkGray
    }
    else {
        foreach ($definition in $Planned) {
            Write-Host ("    " + (Get-HypervSwitchLine -Definition $definition)) -ForegroundColor Cyan
        }
    }
    Write-Host ""

    if ($Existing.Count -gt 0) {
        Write-Host "  Already on this host" -ForegroundColor White
        foreach ($item in $Existing) {
            $detail = "adopted, left exactly as it is"
            if ($item.AdapterNames.Count -gt 0) { $detail = ($item.AdapterNames -join " + ") + " - adopted, left exactly as it is" }
            Write-Host ("    {0,-20} {1,-9} {2}" -f $item.Name, $item.Type, $detail) -ForegroundColor DarkGray
        }
        Write-Host ""
    }
}

# The next name to offer. These three are the ones a host usually wants and they are
# offered in that order; whatever is planned or already here is skipped, so pressing
# Enter three times produces three differently named switches rather than a collision.
$script:hypervSwitchNameSuggestion = @("vswitch-vms", "vswitch-mgmt", "vswitch-storage")

function Get-HypervSwitchNameSuggestion {
    param(
        [object[]]$Planned = @(),
        [object[]]$Existing = @()
    )

    $taken = @()
    $taken += @($Planned | ForEach-Object { [string]$_.name })
    $taken += @($Existing | ForEach-Object { [string]$_.Name })

    foreach ($candidate in $script:hypervSwitchNameSuggestion) {
        if ($taken -notcontains $candidate) { return $candidate }
    }
    for ($number = 2; $number -lt 99; $number++) {
        $candidate = "vswitch-{0:00}" -f $number
        if ($taken -notcontains $candidate) { return $candidate }
    }
    return "vswitch"
}

# Which load balancing algorithm a team of these adapters should carry.
#
# Microsoft states one rule and only one: "SET supports only switch-independent configuration
# by using either Dynamic or Hyper-V Port load-balancing algorithms. For best performance,
# **Hyper-V Port is recommended for use on all NICs that operate at or above 10 Gbps**." Below
# that speed they say nothing, so below that this returns what the product itself defaults to
# - Set-VMSwitchTeam documents "The default value is Dynamic" - rather than inventing a
# recommendation nobody published.
#
# Hyper-V Port pins each virtual adapter to one physical port by MAC address, round robin,
# which is what lets the hardware offloads work; the cost is that no single virtual machine
# goes faster than one member. On 10 Gbps and up that trade is worth it, which is exactly what
# Microsoft's threshold is saying.
#
# The slowest member decides. A team is only as fast as the port a given flow lands on, and
# SET wants members of the same speed anyway.
function Get-HypervTeamLoadBalancing {
    param([object[]]$Adapter = @())

    $slowest = 0
    foreach ($item in @($Adapter)) {
        $speed = 0
        try { $speed = [long]$item.ReceiveLinkSpeed } catch { $speed = 0 }
        if ($speed -le 0) { continue }
        if (($slowest -eq 0) -or ($speed -lt $slowest)) { $slowest = $speed }
    }

    if ($slowest -ge 10000000000) { return "HyperVPort" }
    return "Dynamic"
}

function Get-HypervSwitchAnswer {
    param([Parameter(Mandatory)][object]$Hyperv)

    if (-not [bool](Get-ConfigValue -InputObject $Hyperv -Name "configureSwitches" -Default $true)) { return @() }

    $adapters = @(Get-HypervPhysicalAdapter)
    if ($adapters.Count -eq 0) {
        Write-Log "No physical network adapter found - no switch built" -Tag "Warn"
        return @()
    }
    $null = Test-HypervLbfoTeam

    # Which adapter is carrying this session. Marked rather than forbidden - sharing a
    # switch with the management operating system is the normal design - but it is the
    # one that costs connectivity if the address does not come back, so it is named.
    $sessionAdapter = ""
    try {
        $route = @(Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop | Sort-Object -Property RouteMetric)[0]
        if ($null -ne $route) { $sessionAdapter = [string]$route.InterfaceAlias }
    }
    catch { $sessionAdapter = "" }

    $switches = @()
    $used = @()

    # Adapters an existing switch already owns are spoken for before this interview
    # starts. Offering one would be offering to take it off a switch that virtual
    # machines are on, which is not a thing this run does.
    $existing = @(Get-HypervExistingSwitch)
    foreach ($item in $existing) {
        foreach ($adapterName in $item.AdapterNames) {
            if ($used -notcontains $adapterName) { $used += $adapterName }
            Write-Log "'$adapterName' already belongs to the switch '$($item.Name)', so it is not offered" -Tag "Debug"
        }
    }

    # Deliberately NOT .GetNewClosure(), and Confirm-RunPlan in ConsoleUi.ps1 carries the
    # same note for the same reason: a closure binds the scriptblock to a fresh dynamic
    # module, and on Windows PowerShell 5.1 a module scope cannot see functions defined at
    # script scope - Write-HypervSwitchPanel comes back as CommandNotFoundException. A
    # plain scriptblock keeps this script's session state, so what it needs travels in
    # script scope instead. It is read at draw time, so reassigning these each pass is
    # what keeps the panel current.
    $script:hypervPanelExisting = $existing
    $script:hypervPanelPlanned = @()
    $panel = { Write-HypervSwitchPanel -Planned $script:hypervPanelPlanned -Existing $script:hypervPanelExisting }

    while ($true) {
        $script:hypervPanelPlanned = $switches

        $items = @()
        if ($switches.Count -eq 0) {
            $items += [pscustomobject]@{ Id = "add"; Label = "Build a virtual switch" }
        }
        else {
            $items += [pscustomobject]@{ Id = "add"; Label = "Build another virtual switch" }
            $items += [pscustomobject]@{ Id = "remove"; Label = "Remove one of the planned switches" }
        }
        $items += [pscustomobject]@{ Id = "done"; Label = "Done - $($switches.Count) switch(es) planned" }

        $choice = Read-HypervChoice -Title "Virtual switches" -Heading "Networking" `
            -Hint "A SET team is the switch on Server 2025 - there is no separate team object. Nothing here is built until the restart is over." `
            -Items $items -PreItems $panel
        if (($null -eq $choice) -or ($choice -eq "done")) { break }

        # Undo, and it costs nothing: none of this exists yet. The adapters the removed
        # switch had claimed go back on the table with it.
        if ($choice -eq "remove") {
            $removeItems = @()
            foreach ($definition in $switches) {
                $removeItems += [pscustomobject]@{ Id = [string]$definition.name; Label = (Get-HypervSwitchLine -Definition $definition) }
            }
            $removeItems += [pscustomobject]@{ Id = "__back"; Label = "Back - change nothing" }

            $victim = Read-HypervChoice -Title "Virtual switches" -Heading "Which planned switch goes?" `
                -Hint "Only what this interview planned. A switch already on the host is never removed by this run." `
                -Items $removeItems -PreItems $panel
            if (($null -eq $victim) -or ($victim -eq "__back")) { continue }

            $dropped = @($switches | Where-Object { [string]$_.name -eq $victim })
            foreach ($definition in $dropped) {
                foreach ($member in @($definition.adapters)) {
                    $used = @($used | Where-Object { $_ -ne [string]$member.name })
                }
            }
            $switches = @($switches | Where-Object { [string]$_.name -ne $victim })
            Write-Log "'$victim' off the plan - its adapters are free again" -Tag "Info"
            continue
        }

        $suggested = Get-HypervSwitchNameSuggestion -Planned $switches -Existing $existing
        $name = Read-HypervText -Prompt "Switch name" -Default $suggested -AllowBack
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        if (@($switches | Where-Object { [string]$_.name -eq $name }).Count -gt 0) {
            Write-Log "'$name' is already planned in this run - pick another name" -Tag "Warn"
            continue
        }
        if (@($existing | Where-Object { [string]$_.Name -eq $name }).Count -gt 0) {
            Write-Log "'$name' exists on this host and is adopted rather than rebuilt - planning it again does nothing" -Tag "Warn"
            continue
        }

        $typeId = Read-HypervChoice -Title "Switch '$name'" -Heading "What kind of switch?" `
            -Hint "Esc goes back to the list and plans nothing - what is already planned stays." -PreItems $panel -Items @(
            [pscustomobject]@{ Id = "External"; Label = "External - reaches the physical network" }
            [pscustomobject]@{ Id = "Internal"; Label = "Internal - host and virtual machines only" }
            [pscustomobject]@{ Id = "Private";  Label = "Private - virtual machines only" }
        )
        if ($null -eq $typeId) { continue }

        $definition = [pscustomobject]@{
            name          = $name
            type          = $typeId
            adapters      = @()
            managementOs  = $false
            loadBalancing = "HyperVPort"
            vlanId        = 0
            management    = $null
        }

        if ($typeId -eq "External") {
            $free = @($adapters | Where-Object { $used -notcontains $_.Name })
            if ($free.Count -eq 0) {
                Write-Log "Every physical adapter is spoken for - by a switch in this plan or one this host already carries" -Tag "Warn"
                Write-Log "    Remove a planned switch to get its adapters back" -Tag "Info"
                continue
            }

            # One tick list rather than one question per adapter: the answer here is a
            # set, and a set is easier to check when the whole of it is on the screen.
            $items = @()
            foreach ($adapter in $free) {
                $marker = ""
                if ($adapter.Name -eq $sessionAdapter) { $marker = "   <- THIS SESSION" }
                # The negotiated speed off the adapter itself where it is readable, so a
                # 25G port that came up at 10G says 10 rather than what it is capable of.
                $negotiated = 0
                try { $negotiated = [long]$adapter.ReceiveLinkSpeed } catch { $negotiated = 0 }
                if ($negotiated -gt 0) { $speed = Format-HypervLinkSpeed -BitsPerSecond $negotiated }
                elseif ([string]$adapter.Status -eq "Up") { $speed = [string]$adapter.LinkSpeed }
                else { $speed = "no link" }
                if ([string]::IsNullOrWhiteSpace($speed)) { $speed = "speed unknown" }

                $items += [pscustomobject]@{
                    Id     = [string]$adapter.Name
                    Label  = ("{0}   {1}   {2}{3}" -f $adapter.Name, $speed, $adapter.Status, $marker)
                    Detail = @(Get-HypervAdapterDetail -Adapter $adapter)
                }
            }

            $picked = @(Read-HypervMultiChoice -Title "Switch '$name'" -Heading "Which adapters go into this switch?" `
                -Hint "SET wants members of the same speed, is switch-independent only, and takes up to eight. Esc goes back to the list." `
                -Items $items -PreItems $panel)
            $chosen = @($free | Where-Object { $picked -contains [string]$_.Name })

            if ($chosen.Count -eq 0) {
                Write-Log "No adapter ticked - '$name' is not planned. Back to the list, nothing lost" -Tag "Warn"
                continue
            }
            if ($chosen.Count -gt 8) {
                Write-Log "SET takes eight members - the first eight of the $($chosen.Count) ticked are used" -Tag "Warn"
                $chosen = @($chosen | Select-Object -First 8)
            }

            $chosenName = @($chosen | ForEach-Object { [string]$_.Name })
            # Both the name and the MAC, because the name is about to change: the run
            # renames team members before it builds the switch, and a plan that only
            # knew names could not find them afterwards.
            $definition.adapters = @($chosen | ForEach-Object {
                    [pscustomobject]@{ name = [string]$_.Name; mac = [string]$_.MacAddress }
                })
            $used += $chosenName

            # What the team should carry, decided from the link speed before anybody is asked.
            $suggested = Get-HypervTeamLoadBalancing -Adapter $chosen

            if ($chosen.Count -lt 2) {
                # **Not asked, because with one member there is nothing to balance.** Every
                # flow leaves by the only port there is, whichever algorithm is set. The value
                # is still written, and written correctly, because it goes live the moment a
                # second adapter is added and nobody comes back to revisit it then.
                $definition.loadBalancing = $suggested
                Write-Log ("'{0}' has one adapter - load balancing {1}" -f $name, $suggested) -Tag "Info"
            }
            else {
                $items = @(
                    [pscustomobject]@{ Id = "HyperVPort"; Label = "Hyper-V Port - each virtual adapter keeps one physical port"
                        Detail = @("Microsoft recommends this on every NIC at or above 10 Gbps",
                            "hardware offloads such as VMQ work; no single virtual machine goes faster than one member") }
                    [pscustomobject]@{ Id = "Dynamic"; Label = "Dynamic - flows are spread across the team"
                        Detail = @("what Set-VMSwitchTeam defaults to",
                            "one virtual machine can use more than one member's bandwidth") }
                )
                # The recommended one first, so Enter takes it.
                if ($suggested -eq "Dynamic") { $items = @($items[1], $items[0]) }

                $balancing = Read-HypervChoice -Title "Switch '$name'" -Heading "Load balancing across the team" `
                    -Hint ("{0} is the answer for these adapters. SET is switch-independent only - the ports on the physical switch must not be a LACP port-channel." -f $suggested) `
                    -Items $items
                if ($null -ne $balancing) { $definition.loadBalancing = $balancing }
                else { $definition.loadBalancing = $suggested }
            }

            $shared = Read-HypervChoice -Title "Switch '$name'" -Heading "Does the host share this switch?" `
                -Hint "Sharing it takes the physical adapter down and rebuilds it as a virtual one. The address is captured now and put back afterwards." -Items @(
                [pscustomobject]@{ Id = "yes"; Label = "Yes - the host reaches the network through it" }
                [pscustomobject]@{ Id = "no";  Label = "No - virtual machines only" }
            )
            $definition.managementOs = ($shared -eq "yes")

            if ($definition.managementOs) {
                $vlan = Read-HypervText -Prompt "VLAN for the host's own adapter (blank for untagged)" -Default ""
                if ($vlan -match "^\d+$") { $definition.vlanId = [int]$vlan }

                # The capture, and it happens here rather than at build time because by
                # build time the adapter this reads has already been torn down.
                $captureFrom = $chosenName[0]
                if ($chosenName -contains $sessionAdapter) { $captureFrom = $sessionAdapter }
                $definition.management = Get-HypervAdapterAddress -Name $captureFrom
                if (-not [bool]$definition.management.dhcp) {
                    Write-Log "Captured $($definition.management.ipAddress)/$($definition.management.prefixLength) from '$captureFrom' - returns on 'vEthernet ($name)'" -Tag "Ok"
                }
                if ($chosenName -contains $sessionAdapter) {
                    Write-Log "'$sessionAdapter' carries this session - have console or out-of-band access before the restart" -Tag "Warn"
                }
            }
        }

        $switches += $definition
        # Built up outside the string rather than inside a subexpression: a double quote
        # within $() inside a double-quoted string ends the string on 5.1.
        $planned = "$name ($typeId"
        if ($definition.adapters.Count -gt 0) {
            $planned = $planned + ", " + (@($definition.adapters | ForEach-Object { [string]$_.name }) -join " + ")
        }
        $planned = $planned + ")"
        Write-Log "Planned: $planned" -Tag "Info"
    }

    return $switches
}

# ---------------------------[ The summary ]---------------------------
# Everything the interview collected, on one screen, before a single thing is built. The
# questions all happen first and the build happens after - a run that stops halfway
# through to ask something is a run nobody can walk away from.
function Write-HypervPlanSummary {
    param(
        [Parameter(Mandatory)][object]$Hyperv,
        [Parameter(Mandatory)][object]$Plan
    )

    $clustered = Test-HypervClusterWanted -Hyperv $Hyperv
    $storage = $Plan.storage

    Write-Host "  Storage" -ForegroundColor White
    if ($null -eq $storage) {
        Write-Host "    nothing is prepared - virtual machines land where Hyper-V's defaults put them" -ForegroundColor DarkGray
    }
    else {
        if ((-not $clustered) -and ($null -ne $storage.pool)) {
            $copies = [int]$storage.pool.copies
            $layout = if ([string]$storage.pool.resiliency -eq "Mirror") { "$copies-way mirror" } else { [string]$storage.pool.resiliency }
            Write-Host ("    pool           {0}   {1}   {2} disk(s)" -f $storage.pool.name, $layout, @($storage.pool.disks).Count) -ForegroundColor Cyan
        }
        if ($clustered) {
            $cluster = Get-HypervClusterSection -Hyperv $Hyperv
            $count = [int](Get-ConfigValue -InputObject $cluster -Name "csvCount" -Default 2)
            if ($count -lt 1) { $count = 1 }
            $prefix = [string](Get-ConfigText -InputObject $cluster -Name "csvNamePrefix" -Default "csv")
            $names = @()
            for ($index = 1; $index -le $count; $index++) { $names += ("{0}-{1:00}" -f $prefix, $index) }
            $disks = @($storage.clusterDisks)
            $unit = Get-ConfigValue -InputObject $cluster -Name "allocationUnitSize" -Default 65536

            if (Test-HypervClusterS2dMode -Cluster $cluster -Plan $Plan) {
                # One pool out of every chosen disk, and the volumes carved from it.
                $poolName = [string](Get-ConfigText -InputObject $cluster -Name "poolName" -Default "")
                # Named by the run at build time, so the screen says what it will pick
                # rather than a name that was never the default.
                if ([string]::IsNullOrWhiteSpace($poolName)) { $poolName = Get-StudioPoolNameSuggestion -Base "pool" -Kind "s2d" }

                $copies = 0
                try { $copies = [int]$storage.clusterCopies } catch { $copies = 0 }
                if ($copies -lt 1) { $copies = [int](Get-ConfigValue -InputObject $cluster -Name "mirrorCopies" -Default 2) }
                $shape = if ($copies -le 1) { "no resiliency" } else { "{0} copies across disks" -f $copies }

                if ($disks.Count -gt 0) {
                    Write-Host ("    pool           {0}   {1} disk(s), Storage Spaces Direct, {2}" -f $poolName, $disks.Count, $shape) -ForegroundColor Cyan
                    Write-Host ("                   disks {0} - left empty until the cluster claims them" -f ($disks -join ", ")) -ForegroundColor DarkGray
                    if ($copies -le 1) {
                        Write-Host "                   nothing protects these volumes - one disk failure loses every virtual machine" -ForegroundColor Yellow
                    }
                }
                else {
                    Write-Host "    pool           no disk chosen - the cluster will have nothing to build on" -ForegroundColor DarkGray
                }
                Write-Host ("    volumes        {0}   ReFS {1}, carved out of that one pool" -f ($names -join ", "), $unit) -ForegroundColor Cyan
            }
            else {
                Write-Host ("    volumes        {0}   {1} {2}, no drive letter" -f ($names -join ", "),
                    (Get-ConfigText -InputObject $cluster -Name "fileSystem" -Default "NTFS"), $unit) -ForegroundColor Cyan
                if ($disks.Count -gt 0) {
                    for ($index = 0; $index -lt $disks.Count; $index++) {
                        $name = if ($index -lt $names.Count) { $names[$index] } else { "(spare)" }
                        Write-Host ("    {0,-14} disk {1}, taken whole" -f $name, $disks[$index]) -ForegroundColor Cyan
                    }
                }
                else {
                    Write-Host "    disks          none chosen - the cluster will have nothing to hand out" -ForegroundColor DarkGray
                }
            }
            # The one destructive thing this run can do, on the screen that asks whether
            # to do it. It is never here unless the disk interview was answered with the
            # word.
            $wipe = @()
            try { $wipe = @($storage.clusterDiskWipe | Where-Object { $null -ne $_ }) } catch { $wipe = @() }
            if ($wipe.Count -gt 0) {
                Write-Host ("    erases         disk {0} - every partition and file on {1} is destroyed" -f
                    ($wipe -join ", "), $(if ($wipe.Count -eq 1) { "it" } else { "them" })) -ForegroundColor Yellow
            }
            Write-Host ("    cluster        {0}, one node" -f (Get-HypervClusterName -Cluster $cluster)) -ForegroundColor Cyan
        }
        else {
            $section = Get-ConfigValue -InputObject $Hyperv -Name "storage"
            $size = "the whole disk"
            $bytes = 0
            try { $bytes = [long]$storage.partitionSizeBytes } catch { $bytes = 0 }
            if ($bytes -gt 0) { $size = "{0} GB of it" -f [math]::Round($bytes / 1GB) }
            $disk = if ([int]$storage.diskNumber -ge 0) { "disk $([int]$storage.diskNumber), $size" } else { "the single free disk" }
            Write-Host ("    volume         {0}:   {1} {2}   from {3}" -f $storage.driveLetter,
                (Get-ConfigText -InputObject $section -Name "fileSystem" -Default "ReFS"),
                (Get-ConfigValue -InputObject $section -Name "allocationUnitSize" -Default 4096), $disk) -ForegroundColor Cyan
        }
    }
    Write-Host ""

    Write-Host "  Networking" -ForegroundColor White
    $switches = @($Plan.switches)
    if ($switches.Count -eq 0) {
        Write-Host "    no switch is built" -ForegroundColor DarkGray
    }
    else {
        foreach ($definition in $switches) {
            Write-Host ("    " + (Get-HypervSwitchLine -Definition $definition)) -ForegroundColor Cyan
        }
    }
    Write-Host ""

    if ($null -ne $Plan.appCompat) {
        Write-Host "  App Compatibility" -ForegroundColor White
        $mode = [string]$Plan.appCompat.mode
        $where = switch ($mode) {
            "online" { "from Windows Update" }
            "iso"    { "from '" + [string]$Plan.appCompat.isoPath + "'" }
            default  { "left out" }
        }
        Write-Host ("    {0}" -f $where) -ForegroundColor Cyan
        Write-Host ""
    }

    if (Test-HypervDomainJoinWanted -Hyperv $Hyperv) {
        $join = Get-HypervDomainJoinSection -Hyperv $Hyperv
        Write-Host "  Domain join" -ForegroundColor White
        Write-Host ("    {0}   as {1}" -f (Get-ConfigText -InputObject $join -Name "domain" -Default "?"),
            (Get-ConfigText -InputObject $join -Name "joinUser" -Default "?")) -ForegroundColor Cyan
        Write-Host ""
    }
}

# ---------------------------[ The interview ]---------------------------
# Every question first, the build afterwards. The order is deliberate: storage, then the
# switches, then the App Compatibility source - and then one screen showing all of it with
# the build behind a keypress.
function Invoke-HypervInterview {
    param([Parameter(Mandatory)][object]$Hyperv)

    while ($true) {
        Write-Log "Asking what the config cannot answer - disks, adapters, addresses" -Tag "Run"

        $plan = [pscustomobject]@{
            createdUtc   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            computerName = [string]$env:COMPUTERNAME
            storage      = (Get-HypervStorageAnswer -Hyperv $Hyperv)
            switches     = @(Get-HypervSwitchAnswer -Hyperv $Hyperv)
            appCompat    = $null
        }

        # Asked here rather than where it is used, which is the whole point of this
        # change: the install used to stop in the middle of the build to ask for an ISO.
        if (Test-HypervAppCompatWanted -Hyperv $Hyperv) {
            $choice = Get-HypervAppCompatChoice -Hyperv $Hyperv
            $plan.appCompat = [pscustomobject]@{ mode = [string]$choice.Mode; isoPath = [string]$choice.IsoPath }
        }

        $script:hypervSummaryHyperv = $Hyperv
        $script:hypervSummaryPlan = $plan
        # Not .GetNewClosure() - see the note above the switch panel. A closure cannot
        # see Write-HypervPlanSummary from a module scope on 5.1.
        $summary = { Write-HypervPlanSummary -Hyperv $script:hypervSummaryHyperv -Plan $script:hypervSummaryPlan }

        $decision = Show-Menu -Title "Hyper-V host setup" -Subtitle "Review" -Heading "This is what the run will build" `
            -HeadingHint "Nothing above has happened yet. Everything after this point runs without asking." `
            -PreItems $summary -Items @(
            [pscustomobject]@{ Id = "start"; Label = "Start the build" }
            [pscustomobject]@{ Id = "again"; Label = "Answer the questions again" }
            [pscustomobject]@{ Id = "cancel"; Label = "Cancel - change nothing on this server" }
        )

        if ($decision -eq "again") { continue }
        if (($null -eq $decision) -or ($decision -eq "cancel")) {
            Write-Log "Cancelled at the review screen - nothing built, no answers written" -Tag "Warn"
            return $null
        }

        $null = Write-HypervPlan -Plan $plan
        return $plan
    }
}

# ---------------------------[ Entry points ]---------------------------
function Invoke-HypervConfiguration {
    param([object]$Config)

    $hyperv = Get-HypervSection -Config $Config
    if ($null -eq $hyperv) {
        return (New-RoleResult -Status "Failed" -Message "config.json has no hyperV section.")
    }

    # The two-node S2D mode is a different build entirely and lives in its own file -
    # this dispatch is the whole of what the single-host path knows about it.
    if (Test-HypervS2dMode -Hyperv $hyperv) {
        return (Invoke-HypervS2dConfiguration -Config $Config)
    }

    # The interview comes first, before a single thing is installed. Every answer it
    # collects is about hardware, none of it needs Hyper-V present, and the leg on the
    # far side of the restart cannot ask for any of it - so this is the only moment.
    $plan = Read-HypervPlan
    if ($null -eq $plan) {
        if (Test-HypervInterviewWanted) {
            $plan = Invoke-HypervInterview -Hyperv $hyperv
            if ($null -eq $plan) {
                # Cancelled at the review screen. Nothing has been built yet - that is
                # the whole point of asking everything before building anything.
                return (New-RoleResult -Status "ManualStepRequired" -Message "The Hyper-V review screen was cancelled - nothing was changed. Run the script again to answer the questions afresh.")
            }
        }
        else {
            Write-Log "No console session and no plan file - this run does the declarative parts only" -Tag "Warn"
            Write-Log "    Run this at the console to shape the storage and the switches" -Tag "Info"
        }
    }
    else {
        Write-Log "Using the answers from '$(Get-HypervPlanPath)'" -Tag "Info"
    }

    # The domain join first, and before the feature install rather than after it: the
    # join owes a restart and so does Hyper-V, and one restart is cheaper than two.
    $domainJoined = $false
    if (Test-HypervDomainJoinWanted -Hyperv $hyperv) {
        $domainJoined = Invoke-HypervDomainJoin -Hyperv $hyperv
    }

    # The storage happens on this side of the restart, because none of it needs a
    # hypervisor: a pool is Storage Spaces and a volume is a volume. Only Set-VMHost and
    # the switches have to wait for the service, and those are the post-reboot leg.
    #
    # A clustered host takes the other road entirely. Its virtual machines live on Cluster
    # Shared Volumes under C:\ClusterStorage, so there is no lettered data volume to build
    # - the pool is cut into the CSV volumes instead, and they are formatted without a
    # letter because a CSV already has a name.
    $driveLetter = ""
    if (Test-HypervClusterWanted -Hyperv $hyperv) {
        $null = Invoke-HypervClusterPreparation -Hyperv $hyperv -Plan $plan
    }
    else {
        $driveLetter = Initialize-HypervDataVolume -Hyperv $hyperv -Plan $plan
    }

    if (-not (Test-HypervFeatureInstalled)) {
        if (-not [bool](Get-ConfigValue -InputObject $hyperv -Name "installRole" -Default $true)) {
            return (New-RoleResult -Status "ManualStepRequired" -Message "The Hyper-V role is not installed and this design does not install it: Install-WindowsFeature -Name Hyper-V -IncludeManagementTools")
        }
        if (-not (Install-HypervRole)) {
            return (New-RoleResult -Status "Failed" -Message "The Hyper-V role could not be installed - the lines above say why.")
        }
        # In the same pass as the role, on purpose: this needs a restart too, and two
        # restarts for one visit is a worse host build than one.
        if ([bool](Get-ConfigValue -InputObject $hyperv -Name "serverCoreAppCompat" -Default $true)) {
            $null = Install-HypervAppCompatibility -Hyperv $hyperv -Plan $plan
        }
    }
    else {
        Write-Log "Hyper-V role already installed" -Tag "Info"
        if ([bool](Get-ConfigValue -InputObject $hyperv -Name "serverCoreAppCompat" -Default $true)) {
            $null = Install-HypervAppCompatibility -Hyperv $hyperv -Plan $plan
        }
    }

    # These three need no hypervisor, so they happen on this side of the restart and are
    # in force the moment the machine comes back.
    if ([bool](Get-ConfigValue -InputObject $hyperv -Name "highPerformancePowerPlan" -Default $true)) {
        $null = Set-HypervPowerPlan
    }
    if ([bool](Get-ConfigValue -InputObject $hyperv -Name "disableSmb1" -Default $true)) {
        $null = Remove-HypervSmb1
    }
    Write-HypervPageFileNote

    if ((Test-HypervRebootPending) -or $domainJoined) {
        $message = "Hyper-V is installed - restart this server, and the run after the restart builds the switches and points the host at its storage."
        if (-not [string]::IsNullOrWhiteSpace($driveLetter)) {
            $message = "Hyper-V is installed and ${driveLetter}: is ready - restart this server, and the run after the restart builds the switches and points the host at its storage."
        }
        if ($domainJoined) {
            # Said out loud because the machine that comes back is a different one as far
            # as the directory is concerned, and every session on it will be too.
            $message = "The domain join is done and " + $message.Substring(0, 1).ToLowerInvariant() + $message.Substring(1)
        }
        return (New-RoleResult -Status "RebootRequired" -Message $message)
    }

    Write-Log "The hypervisor is already running - nothing to restart for" -Tag "Info"
    return (New-RoleResult -Status "Completed" -Message "Hyper-V is installed and running.")
}

function Invoke-HypervPostReboot {
    param([object]$Config)

    $hyperv = Get-HypervSection -Config $Config
    if ($null -eq $hyperv) {
        return (New-RoleResult -Status "Failed" -Message "config.json has no hyperV section.")
    }

    # Same dispatch as the apply leg: the two-node mode has its own post-reboot story.
    if (Test-HypervS2dMode -Hyperv $hyperv) {
        return (Invoke-HypervS2dPostReboot -Config $Config)
    }

    if (-not (Test-HypervServiceReady)) {
        return (New-RoleResult -Status "RebootRequired" -Message "The Hyper-V management service is not answering yet - this server still owes a restart.")
    }

    # Tried here rather than beside the role install: on Server Core the snap-in needs the
    # App Compatibility feature, which only exists on this side of the restart.
    $null = Install-HypervManagementTool

    # Nothing here asks anything. Every answer was given before the restart and is read
    # back off disk, which is what lets this leg run as the resume task with -NoGui.
    $plan = Read-HypervPlan
    $switchFailure = 0
    if (($null -ne $plan) -and ($null -ne $plan.switches)) {
        $renameMembers = [bool](Get-ConfigValue -InputObject $hyperv -Name "renameTeamMembers" -Default $true)
        $namePrefix = Get-HypervAdapterNamePrefix -Prefix ([string](Get-ConfigText -InputObject $hyperv -Name "adapterNamePrefix" -Default "nic"))
        # Cleared for the run, not for each switch: the counters are per family and a
        # family is normally one switch, so each switch's members start at 01 - but two
        # switches whose names reduce to the same label share one sequence.
        $script:hypervAdapterNameIndex = @{}

        foreach ($definition in @($plan.switches)) {
            if (-not (New-HypervVirtualSwitch -Definition $definition -RenameMembers:$renameMembers -NamePrefix $namePrefix)) {
                $switchFailure++
            }
        }
    }

    # The cluster is the whole storage story on a clustered host: it creates itself, takes
    # the volumes the apply leg prepared, and hands back the first Cluster Shared Volume
    # for the virtual machines to land on. Nothing here asks anything either.
    $paths = @()
    $clusterFellBack = $false
    if (Test-HypervClusterWanted -Hyperv $hyperv) {
        $csvPaths = @(Invoke-HypervClusterConfiguration -Hyperv $hyperv -Plan $plan)
        $csvPath = ""
        if ($csvPaths.Count -gt 0) { $csvPath = [string]$csvPaths[0] }
        if ([string]::IsNullOrWhiteSpace($csvPath)) {
            # No shared volume. The volumes themselves are fine, so the host is finished
            # as a stand-alone one rather than left half-built - and the rest of the run,
            # Windows Admin Center included, still gets to happen.
            $cluster = Get-HypervClusterSection -Hyperv $hyperv
            $labels = @(Get-HypervCsvLabel -Cluster $cluster)
            if ($labels.Count -gt 0) {
                $csvPath = Set-HypervClusterVolumeFallback -Hyperv $hyperv -Label $labels[0]
            }
            if ([string]::IsNullOrWhiteSpace($csvPath)) {
                return (New-RoleResult -Status "ManualStepRequired" -Message "Hyper-V is running but the cluster has no shared volume and the prepared volumes could not be used either - the lines above say why.")
            }
            $clusterFellBack = $true
            $csvPaths = @($csvPath)
        }

        # The same pair of folders on every volume, so a virtual machine moving from
        # csv-01 to csv-02 is a copy rather than a redesign. Only the first is handed to
        # Set-VMHost, which takes one path.
        foreach ($extra in @($csvPaths | Select-Object -Skip 1)) {
            $paths += @(Set-HypervHostPath -Hyperv $hyperv -BasePath $extra -FoldersOnly)
        }
        $paths += @(Set-HypervHostPath -Hyperv $hyperv -BasePath $csvPath)
        if ($paths.Count -eq 0) {
            return (New-RoleResult -Status "ManualStepRequired" -Message "The volume is ready but the host paths could not be set - the lines above say why.")
        }
    }
    else {
        # The volume again, and deliberately: the apply leg builds it, but a run that found
        # Hyper-V already installed never went through that branch, and this function is
        # also where a re-run lands.
        $driveLetter = Initialize-HypervDataVolume -Hyperv $hyperv -Plan $plan
        if ([string]::IsNullOrWhiteSpace($driveLetter)) {
            $null = Set-HypervEnhancedSessionMode -Hyperv $hyperv
            Remove-HypervPlan
            return (New-RoleResult -Status "Completed" -Message "Hyper-V is running. No data volume was prepared, so virtual machines land where Hyper-V's defaults put them.")
        }

        $paths = @(Set-HypervHostPath -Hyperv $hyperv -DriveLetter $driveLetter)
        if ($paths.Count -eq 0) {
            return (New-RoleResult -Status "ManualStepRequired" -Message "The data volume is ready but the host paths could not be set - the lines above say why.")
        }
    }

    if ([bool](Get-ConfigValue -InputObject $hyperv -Name "defenderExclusions" -Default $true)) {
        $null = Set-HypervDefenderExclusion -Path $paths
    }
    $null = Set-HypervEnhancedSessionMode -Hyperv $hyperv

    if ($switchFailure -gt 0) {
        # The plan stays on disk: a switch that failed is a switch worth retrying with
        # the same answers rather than re-interviewing somebody about.
        return (New-RoleResult -Status "ManualStepRequired" -Message ("Hyper-V is ready but {0} switch(es) could not be built - the lines above say why, and the answers are still in '{1}' for the next run." -f $switchFailure, (Get-HypervPlanPath)))
    }

    Remove-HypervPlan
    if ($clusterFellBack) {
        return (New-RoleResult -Status "Completed" -Message ("Hyper-V is ready and virtual machines land in '{0}', but the cluster has no shared volume - its disks cannot hold the reservations a cluster disk needs. The lines above say what storage would." -f $paths[0]))
    }
    return (New-RoleResult -Status "Completed" -Message ("Hyper-V is ready - virtual machines land in '{0}'." -f $paths[0]))
}
