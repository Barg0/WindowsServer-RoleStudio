# Role provider: DNS Server.
#
# Dot-sourced by Configure-ServerRoles.ps1 - not runnable on its own. Everything
# here lands in that script's scope, so $script: variables and functions are shared
# with every other part. Use $scriptRootPath, never $PSScriptRoot: inside this file
# $PSScriptRoot is the pwsh folder, not the folder the run was started from.

# ===========================[ DNS Server ]===========================

# ---------------------------[ DNS Configuration ]---------------------------
# Called by the engine before anything is applied, and before -CheckOnly exits.
# Whether this role is for this machine, asked before the plan is built.
#
# The distinction it draws is between the two ways `DNS` gets into `roles`. Somebody
# ticking the DNS Server role means it: the design configures a DNS server, and a machine
# without the feature should be told to install it - the old behaviour, unchanged.
#
# The studio also *adds* the role for a design that only carries an Exchange namespace,
# because the namespace's records are written by this provider and that happens on the
# domain controller. That copy is a passenger: it rides to every machine in the design,
# and on the Exchange server there is no DNS feature and nothing for it to do.
# `dnsServer.forExchangeNamespaceOnly` is what tells the two apart, and it exists for
# exactly this - the 2026-08-09 build demanded Install-WindowsFeature DNS on a mail
# server because the passenger looked like the driver.
function Test-DnsAppliesHere {
    param([object]$Config)

    $dnsServer = Get-ConfigValue -InputObject $Config -Name "dnsServer"
    if ($null -eq $dnsServer) { return $false }

    if (-not [bool](Get-ConfigValue -InputObject $dnsServer -Name "forExchangeNamespaceOnly" -Default $false)) {
        return $true
    }

    # The **service**, not the module. `Get-DnsServerZone` arrives with RSAT-DNS-Server,
    # which is management tooling - a member server that has it would answer yes and then
    # try to create zones on a machine that serves none. The DNS service existing is the
    # question actually being asked: is this a DNS server.
    $dnsService = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
    if ($null -ne $dnsService) { return $true }

    Write-Log "No DNS Server service here, and the only DNS work in this design is the Exchange namespace" -Tag "Debug"
    return $false
}

function Test-DnsPrerequisite {
    param([object]$Config)

    $passed = $true

    if (-not (Get-Command -Name "Set-DnsServerForwarder" -ErrorAction SilentlyContinue)) {
        Write-Log "The DnsServer PowerShell module is unavailable" -Tag "Error"
        Write-Log "Add the management tools, then run this script again:" -Tag "Error"
        Write-Log "    Install-WindowsFeature -Name RSAT-DNS-Server" -Tag "Error"
        $passed = $false
    }

    # Cheap to check here, expensive to discover halfway through a run.
    $dns = Get-ConfigValue -InputObject $Config -Name "dnsServer"
    foreach ($reverseZone in (Get-DnsReverseZoneEntry -Dns $dns)) {
        $networkId = [string](Get-ConfigValue -InputObject $reverseZone -Name "networkId" -Default "")
        if ([string]::IsNullOrWhiteSpace($networkId)) {
            Write-Log "A dnsServer.reverseLookupZones entry has an empty networkId" -Tag "Error"
            $passed = $false
            continue
        }
        if ($networkId.Split(".").Count -ne 4) {
            Write-Log "Reverse lookup zone network '$networkId' is not an IPv4 address" -Tag "Error"
            $passed = $false
        }
    }

    return $passed
}

# reverseLookupZones is the current shape; reverseLookupZone (single object) is still read.
function Get-DnsReverseZoneEntry {
    param([object]$Dns)

    $reverseZones = Get-ConfigArray -InputObject $Dns -Name "reverseLookupZones"
    if ($reverseZones.Count -eq 0) {
        $legacyZone = Get-ConfigValue -InputObject $Dns -Name "reverseLookupZone"
        if ($null -ne $legacyZone) { return @($legacyZone) }
    }
    return @($reverseZones)
}

function Set-DnsForwarder {
    param([string[]]$Address)

    if ($Address.Count -eq 0) { return }

    Write-Log "Setting DNS forwarders to $($Address -join ', ')" -Tag "Run"
    try {
        Set-DnsServerForwarder -IPAddress $Address -ErrorAction Stop
    }
    catch {
        throw "Set-DnsServerForwarder failed: $($_.Exception.Message)"
    }
    Write-Log "DNS forwarders applied" -Tag "Ok"
}

# 10.10.0.0/24 becomes 0.10.10.in-addr.arpa - one reversed octet per /8 of prefix.
function Get-ReverseZoneName {
    param(
        [Parameter(Mandatory)][string]$NetworkId,
        [Parameter(Mandatory)][int]$PrefixLength
    )

    $octets = $NetworkId.Split(".")
    if ($octets.Count -ne 4) {
        throw "Reverse lookup zone network '$NetworkId' is not an IPv4 address."
    }

    $significantOctetCount = [int]($PrefixLength / 8)
    $reversed = @()
    for ($index = $significantOctetCount - 1; $index -ge 0; $index--) {
        $reversed += $octets[$index]
    }
    return (($reversed -join ".") + ".in-addr.arpa")
}

function Add-ReverseLookupZone {
    param(
        [Parameter(Mandatory)][string]$NetworkId,
        [Parameter(Mandatory)][int]$PrefixLength
    )

    $networkWithPrefix = "$NetworkId/$PrefixLength"
    $zoneName = Get-ReverseZoneName -NetworkId $NetworkId -PrefixLength $PrefixLength

    $existingZone = Get-DnsServerZone -Name $zoneName -ErrorAction SilentlyContinue
    if ($null -ne $existingZone) {
        Write-Log "Reverse lookup zone '$zoneName' already exists - leaving it alone" -Tag "Info"
        return
    }

    Write-Log "Creating the AD-integrated reverse lookup zone '$zoneName' for $networkWithPrefix" -Tag "Run"
    try {
        Add-DnsServerPrimaryZone -NetworkId $networkWithPrefix -ReplicationScope "Forest" -DynamicUpdate "Secure" -ErrorAction Stop
    }
    catch {
        throw "Add-DnsServerPrimaryZone failed: $($_.Exception.Message)"
    }
    Write-Log "Reverse lookup zone created" -Tag "Ok"
}

function Enable-DnsScavenging {
    param([Parameter(Mandatory)][int]$IntervalDays)

    $interval = New-TimeSpan -Days $IntervalDays
    Write-Log "Enabling DNS scavenging with a $IntervalDays day interval" -Tag "Run"
    try {
        Set-DnsServerScavenging -ScavengingState $true -ScavengingInterval $interval `
            -RefreshInterval $interval -NoRefreshInterval $interval -ApplyOnAllZones -ErrorAction Stop
    }
    catch {
        throw "Set-DnsServerScavenging failed: $($_.Exception.Message)"
    }
    Write-Log "DNS scavenging enabled" -Tag "Ok"
}

# ---------------------------[ Exchange namespace ]---------------------------
# The three names Exchange answers on, written where the zone lives rather than on the
# Exchange server - which is a member server that would need RSAT and delegated rights
# to write DNS remotely. Same split, and the same reasoning, as the PKI's publication
# alias in Set-AdcsPublicationAlias.
#
# A record that already exists is left exactly as it is. An A record for the client
# name may well be a load balancer's, and repointing it would move every client's mail
# to whatever this design happens to name.
# Where the A records point, and the two ways this run can possibly know it - the run
# happens on a domain controller that has never met the Exchange server, so the answer
# has to arrive in the config. namespace.ipAddress states it and wins outright;
# otherwise namespace.serverComputerName names the machine and this resolves it against
# the domain this directory serves. install.computerName and a bare exchange.computerName
# are read as older spellings of the second.
#
# Resolved against $env:USERDNSDOMAIN rather than the namespace's own zone: the machine
# registers itself in the domain it joined, which is exactly the zone that is *not* the
# mail namespace whenever the two differ - and that difference is the case this whole
# function exists for.
function Resolve-DnsExchangeAddress {
    param(
        [Parameter(Mandatory)][object]$Config,
        [Parameter(Mandatory)][object]$Namespace
    )

    $configured = Get-ConfigText -InputObject $Namespace -Name "ipAddress"
    if (-not [string]::IsNullOrWhiteSpace($configured)) {
        Write-Log "The design states the Exchange server's address directly: $($configured.Trim())" -Tag "Debug"
        return $configured.Trim()
    }

    $exchange = Get-ConfigValue -InputObject $Config -Name "exchange"
    $serverName = Get-ConfigText -InputObject $Namespace -Name "serverComputerName"
    if ([string]::IsNullOrWhiteSpace($serverName)) {
        $install = Get-ConfigValue -InputObject $exchange -Name "install"
        if ($null -ne $install) { $serverName = Get-ConfigText -InputObject $install -Name "computerName" }
    }
    if ([string]::IsNullOrWhiteSpace($serverName)) { $serverName = Get-ConfigText -InputObject $exchange -Name "computerName" }

    if ([string]::IsNullOrWhiteSpace($serverName)) {
        Write-Log "The design names neither the Exchange server nor an address, so there is nothing to point the records at" -Tag "Warn"
        Write-Log "    Fill in the Exchange computer name or the address on the studio's namespace card and export again" -Tag "Warn"
        return ""
    }

    $candidates = @($serverName)
    $joinedDomain = [string]$env:USERDNSDOMAIN
    if (-not [string]::IsNullOrWhiteSpace($joinedDomain)) { $candidates += ("{0}.{1}" -f $serverName, $joinedDomain.ToLowerInvariant()) }

    foreach ($candidate in $candidates) {
        try {
            $resolved = @([System.Net.Dns]::GetHostAddresses($candidate) |
                Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork })
            if ($resolved.Count -gt 0) {
                Write-Log "'$candidate' resolves to $($resolved[0].IPAddressToString) - that is what the records will point at" -Tag "Debug"
                return $resolved[0].IPAddressToString
            }
        }
        catch {
            Write-Log "'$candidate' does not resolve from here" -Tag "Debug"
        }
    }

    Write-Log "'$serverName' does not resolve from this domain controller - it may not have registered yet" -Tag "Warn"
    Write-Log "    The address field on the studio's namespace card skips the lookup entirely" -Tag "Info"
    return ""
}

# One zone, forest-replicated and accepting secure updates - the same shape every zone
# an AD-integrated directory makes for itself. Shared rather than Exchange's own since
# the Remote Desktop namespace grew the same need: a design whose names live in a zone
# this directory does not serve.
function Add-StudioDnsZone {
    param([Parameter(Mandatory)][string]$ZoneName)

    try {
        $null = Add-DnsServerPrimaryZone -Name $ZoneName -ReplicationScope "Forest" -DynamicUpdate "Secure" -ErrorAction Stop
        Write-Log "Created the forward lookup zone '$ZoneName'" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "The zone '$ZoneName' could not be created: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

# Split DNS the narrow way: a zone whose name *is* the fully qualified name, holding one
# A record at its own apex. Internally only that one name is answered here; the rest of
# the parent domain still comes from wherever it always did.
#
# The aliases become A records rather than CNAMEs, and that is forced rather than
# chosen: a CNAME cannot sit at a zone apex beside the SOA and NS records. It costs the
# one-record-to-change property the CNAMEs had, which matters less than it sounds when
# the whole set is rewritten by this run anyway.
function Set-DnsExchangePinpointZone {
    param(
        [Parameter(Mandatory)][object]$Config,
        [Parameter(Mandatory)][object]$Namespace,
        [Parameter(Mandatory)][string]$HostName
    )

    $address = Resolve-DnsExchangeAddress -Config $Config -Namespace $Namespace
    if ([string]::IsNullOrWhiteSpace($address)) {
        Write-Log "Pinpoint zones need the Exchange server's address and none could be worked out - fill it in on the namespace card" -Tag "Error"
        return $false
    }

    $names = @($HostName)
    $exchange = Get-ConfigValue -InputObject $Config -Name "exchange"
    $autodiscover = Get-ConfigText -InputObject $Namespace -Name "autodiscoverName"
    if (-not [string]::IsNullOrWhiteSpace($autodiscover)) { $names += $autodiscover }
    $hardening = Get-ConfigValue -InputObject $exchange -Name "hardening"
    if ([bool](Get-ConfigValue -InputObject $hardening -Name "downloadDomains" -Default $true)) {
        $download = Get-ConfigText -InputObject $Namespace -Name "downloadName"
        if (-not [string]::IsNullOrWhiteSpace($download)) { $names += $download }
    }

    Write-Log "The zone above this namespace is not served here - one zone per name, so nothing else in that domain is shadowed" -Tag "Debug"

    $allDone = $true
    foreach ($name in ($names | Select-Object -Unique)) {
        $zone = Get-DnsServerZone -Name $name -ErrorAction SilentlyContinue
        if ($null -eq $zone) {
            if (-not (Add-StudioDnsZone -ZoneName $name)) { $allDone = $false; continue }
        }
        else {
            Write-Log "The zone '$name' already exists" -Tag "Debug"
        }

        # The apex record carries no name of its own - "@" in a zone file, an empty
        # -Name here. An existing one is left alone for the same reason the parent-zone
        # path leaves records alone: it may be a load balancer's.
        $existing = @(Get-DnsServerResourceRecord -ZoneName $name -RRType "A" -ErrorAction SilentlyContinue |
            Where-Object { [string]$_.HostName -eq "@" })
        if ($existing.Count -gt 0) {
            Write-Log "'$name' already answers with $([string]$existing[0].RecordData.IPv4Address) - left alone" -Tag "Info"
            continue
        }
        try {
            Add-DnsServerResourceRecordA -ZoneName $name -Name "@" -IPv4Address $address -ErrorAction Stop
            Write-Log "Created '$name' -> $address" -Tag "Ok"
        }
        catch {
            Write-Log "The record for '$name' could not be created: $($_.Exception.Message)" -Tag "Error"
            $allDone = $false
        }
    }

    Write-Log "Only these names are answered internally - everything else in that domain resolves from public DNS" -Tag "Debug"
    return $allDone
}

function Set-DnsExchangeRecord {
    param([object]$Config)

    $exchange = Get-ConfigValue -InputObject $Config -Name "exchange"
    if ($null -eq $exchange) { return $true }

    $namespace = Get-ConfigValue -InputObject $exchange -Name "namespace"
    if (($null -eq $namespace) -or (-not [bool](Get-ConfigValue -InputObject $namespace -Name "manageDns" -Default $true))) {
        return $true
    }

    $hostName = Get-ConfigText -InputObject $namespace -Name "hostName"
    if ([string]::IsNullOrWhiteSpace($hostName)) { return $true }

    $label = $hostName.Split(".")[0]
    if ($label.Length + 1 -ge $hostName.Length) {
        Write-Log "The Exchange namespace names the zone itself ('$hostName') - no record to create" -Tag "Info"
        return $true
    }
    $zoneName = $hostName.Substring($label.Length + 1)

    if (-not (Get-Command -Name "Get-DnsServerZone" -ErrorAction SilentlyContinue)) {
        Write-Log "The DnsServer module is not available here, so the Exchange records have to be created wherever '$zoneName' is served" -Tag "Warn"
        return $true
    }
    # The zone the namespace lives in is very often not a zone this directory has: the
    # AD domain is ad.lab.invalid and the mail namespace is example.com, which belongs
    # to a registrar. Internally those names still have to resolve, and that is what
    # split DNS is - the same name answered differently inside and out.
    #
    # namespace.zoneMode decides what to do about it when the zone is missing:
    #
    #   pinpoint  one zone *per name*, each holding a single record at its own apex.
    #             exchange.example.com becomes a zone called exchange.example.com. Only
    #             the names this design needs are answered internally and everything
    #             else in example.com still comes from public DNS. The default, and the
    #             narrow answer.
    #   full      one zone for the parent domain. Simple, and the consequence is not:
    #             this directory becomes authoritative for **the whole domain**
    #             internally, so every other name in it - the website, anything a
    #             partner hosts - stops resolving until it is recreated here by hand.
    #   none      report and change nothing, which is what this did before.
    $zoneMode = Get-ConfigText -InputObject $namespace -Name "zoneMode" -Default "pinpoint"
    $parentZone = Get-DnsServerZone -Name $zoneName -ErrorAction SilentlyContinue
    if ($null -eq $parentZone) {
        if ($zoneMode -eq "none") {
            Write-Log "'$zoneName' is not hosted here and the design creates no zones - make the Exchange records where that zone lives" -Tag "Warn"
            return $true
        }
        if ($zoneMode -eq "full") {
            if (-not (Add-StudioDnsZone -ZoneName $zoneName)) { return $false }
            Write-Log "    This directory is now authoritative for all of '$zoneName' internally - every other name in it must exist here too" -Tag "Warn"
        }
        else {
            return (Set-DnsExchangePinpointZone -Config $Config -Namespace $namespace -HostName $hostName)
        }
    }

    # The client name is an A record, not an alias: it is what the certificate is
    # issued for and what SMTP presents, and a CNAME target for those is asking for
    # trouble with Kerberos and with some SMTP peers.
    #
    # Which address, and how this run can possibly know. It happens on the domain
    # controller, which has never met the Exchange server and cannot ask it anything -
    # so the answer has to travel in the config, and there are two ways to put it there.
    # namespace.ipAddress is the direct one and wins outright. Otherwise
    # namespace.serverComputerName names the machine and this resolves
    # <name>.<zone> to whatever that machine registered for itself, which is the common
    # case and needs no address typed anywhere. install.computerName and a bare
    # exchange.computerName are read as older spellings of the same thing.
    #
    # Neither present means neither can be guessed: an earlier build shipped with no
    # field for this at all, the lookup below always ran on an empty name, and every
    # deployment got the manual line instead of a record. The studio now makes that a
    # validation error rather than a surprise on the domain controller.
    $address = Resolve-DnsExchangeAddress -Config $Config -Namespace $namespace

    $allDone = $true
    $existingHost = @(Get-DnsServerResourceRecord -ZoneName $zoneName -Name $label -ErrorAction SilentlyContinue)
    if ($existingHost.Count -gt 0) {
        Write-Log "'$hostName' already exists - left alone; make sure it reaches the Exchange server" -Tag "Info"
    }
    elseif ([string]::IsNullOrWhiteSpace($address)) {
        Write-Log "'$hostName' does not exist and the Exchange server's address could not be resolved - create it by hand:" -Tag "Warn"
        Write-Log "    Add-DnsServerResourceRecordA -ZoneName $zoneName -Name $label -IPv4Address <the Exchange server>" -Tag "Warn"
        $allDone = $false
    }
    else {
        try {
            Add-DnsServerResourceRecordA -ZoneName $zoneName -Name $label -IPv4Address $address -ErrorAction Stop
            Write-Log "Created '$hostName' -> $address" -Tag "Ok"
        }
        catch {
            Write-Log "Add-DnsServerResourceRecordA failed for '$hostName': $($_.Exception.Message)" -Tag "Error"
            $allDone = $false
        }
    }

    # Autodiscover and the attachment name are aliases of the client name, so a change
    # of address is one record rather than three.
    $aliases = @()
    $autodiscover = Get-ConfigText -InputObject $namespace -Name "autodiscoverName"
    if (-not [string]::IsNullOrWhiteSpace($autodiscover)) { $aliases += $autodiscover }
    $hardening = Get-ConfigValue -InputObject $exchange -Name "hardening"
    if ([bool](Get-ConfigValue -InputObject $hardening -Name "downloadDomains" -Default $true)) {
        $download = Get-ConfigText -InputObject $namespace -Name "downloadName"
        if (-not [string]::IsNullOrWhiteSpace($download)) { $aliases += $download }
    }

    foreach ($alias in $aliases) {
        $aliasLabel = $alias.Split(".")[0]
        if ($aliasLabel.Length + 1 -ge $alias.Length) { continue }
        $aliasZone = $alias.Substring($aliasLabel.Length + 1)
        if ($null -eq (Get-DnsServerZone -Name $aliasZone -ErrorAction SilentlyContinue)) {
            Write-Log "This server does not host '$aliasZone', so '$alias' has to be created there:" -Tag "Warn"
            Write-Log "    Add-DnsServerResourceRecordCName -ZoneName $aliasZone -Name $aliasLabel -HostNameAlias $hostName" -Tag "Warn"
            continue
        }
        $existingAlias = @(Get-DnsServerResourceRecord -ZoneName $aliasZone -Name $aliasLabel -ErrorAction SilentlyContinue)
        if ($existingAlias.Count -gt 0) {
            Write-Log "'$alias' already exists - left alone" -Tag "Info"
            continue
        }
        try {
            Add-DnsServerResourceRecordCName -ZoneName $aliasZone -Name $aliasLabel -HostNameAlias $hostName -ErrorAction Stop
            Write-Log "Created '$alias' -> $hostName" -Tag "Ok"
        }
        catch {
            Write-Log "Add-DnsServerResourceRecordCName failed for '$alias': $($_.Exception.Message)" -Tag "Error"
            $allDone = $false
        }
    }

    Write-Log "The MX, SPF and PTR records live in the public zone and are not this design's to write - the Exchange run prints them" -Tag "Info"
    return $allDone
}

# ---------------------------[ Entry Point ]---------------------------
function Invoke-DnsConfiguration {
    param([object]$Config)

    $dns = Get-ConfigValue -InputObject $Config -Name "dnsServer"
    $appliedSomething = $false

    # Before the zones below, so a design that only carries an Exchange namespace still
    # reports what it did rather than "the section is empty".
    if ($null -ne (Get-ConfigValue -InputObject $Config -Name "exchange")) {
        if (Set-DnsExchangeRecord -Config $Config) { $appliedSomething = $true }
    }

    $forwarders = Get-ConfigArray -InputObject $dns -Name "forwarders"
    if ($forwarders.Count -gt 0) {
        Set-DnsForwarder -Address ([string[]]$forwarders)
        $appliedSomething = $true
    }

    foreach ($reverseZone in (Get-DnsReverseZoneEntry -Dns $dns)) {
        $networkId    = [string](Get-ConfigValue -InputObject $reverseZone -Name "networkId" -Default "")
        $prefixLength = [int](Get-ConfigValue -InputObject $reverseZone -Name "prefixLength" -Default 24)
        if ([string]::IsNullOrWhiteSpace($networkId)) {
            throw "A dnsServer.reverseLookupZones entry has an empty networkId."
        }
        Add-ReverseLookupZone -NetworkId $networkId -PrefixLength $prefixLength
        $appliedSomething = $true
    }

    $scavenging = Get-ConfigValue -InputObject $dns -Name "scavenging"
    if (($null -ne $scavenging) -and [bool](Get-ConfigValue -InputObject $scavenging -Name "enabled" -Default $false)) {
        $intervalDays = [int](Get-ConfigValue -InputObject $scavenging -Name "intervalDays" -Default 7)
        Enable-DnsScavenging -IntervalDays $intervalDays
        $appliedSomething = $true
    }

    if (-not $appliedSomething) {
        return (New-RoleResult -Status "Completed" -Message "The dnsServer section is empty - nothing to apply")
    }

    return (New-RoleResult -Status "Completed" -Message "DNS configuration completed")
}

# ---------------------------[ Split DNS, shared ]---------------------------
# One name, made to resolve here. The parent zone is the easy case; the whole reason
# this exists is the other one - an AD domain of ad.lab.invalid and a name published
# under example.com, which belongs to a registrar and still has to answer inside.
#
# Written for Remote Desktop and moved here the day the SCEP tier needed the same
# thing, which is the rule Add-StudioDnsZone already follows: a second caller is what
# turns a role's function into a shared one. Both callers hand it {Name, Target,
# Purpose} and a zone mode, and neither of them decides how a zone gets made.
#
# A records, never CNAMEs. A CNAME cannot live at a zone apex beside the SOA and NS a
# pinpoint zone must carry, and the pinpoint zone is the narrow answer this exists for.
function Set-StudioNamespaceRecord {
    param(
        [Parameter(Mandatory)][object]$Record,
        [Parameter(Mandatory)][string]$Address,
        [Parameter(Mandatory)][string]$ZoneMode
    )

    $hostName = $Record.Name
    $label    = $hostName.Split(".")[0]
    if ($label.Length + 1 -ge $hostName.Length) {
        Write-Log "'$hostName' is a zone name rather than a name inside one - nothing to create for it here" -Tag "Info"
        return $true
    }
    $zoneName = $hostName.Substring($label.Length + 1)

    $parentZone = Get-DnsServerZone -Name $zoneName -ErrorAction SilentlyContinue
    if ($null -eq $parentZone) {
        if ($ZoneMode -eq "none") {
            Write-Log "'$zoneName' is not hosted here and the design creates no zones - create '$hostName' where that zone lives:" -Tag "Warn"
            Write-Log "    Add-DnsServerResourceRecordA -ZoneName $zoneName -Name $label -IPv4Address $Address" -Tag "Warn"
            return $false
        }
        if ($ZoneMode -eq "full") {
            if (-not (Add-StudioDnsZone -ZoneName $zoneName)) { return $false }
            Write-Log "    This directory is now authoritative for all of '$zoneName' internally - every other name in it must exist here too" -Tag "Warn"
        }
        else {
            # Split DNS the narrow way: a zone whose name *is* the fully qualified name,
            # holding one A record at its own apex. Only this name is answered here and
            # the rest of the parent domain still comes from wherever it always did.
            if ($null -eq (Get-DnsServerZone -Name $hostName -ErrorAction SilentlyContinue)) {
                if (-not (Add-StudioDnsZone -ZoneName $hostName)) { return $false }
            }
            $existingApex = @(Get-DnsServerResourceRecord -ZoneName $hostName -RRType "A" -ErrorAction SilentlyContinue |
                Where-Object { [string]$_.HostName -eq "@" })
            if ($existingApex.Count -gt 0) {
                Write-Log "'$hostName' already answers with $([string]$existingApex[0].RecordData.IPv4Address) - left alone" -Tag "Info"
                return $true
            }
            try {
                Add-DnsServerResourceRecordA -ZoneName $hostName -Name "@" -IPv4Address $Address -ErrorAction Stop
                Write-Log "Created '$hostName' -> $Address ($($Record.Purpose))" -Tag "Ok"
                return $true
            }
            catch {
                Write-Log "The record for '$hostName' could not be created: $($_.Exception.Message)" -Tag "Error"
                return $false
            }
        }
    }

    # An A record that already exists may well be a load balancer's, or a name somebody
    # pointed somewhere deliberately. Repointing it would move every client's session to
    # whatever this design happens to name, which is never this script's decision.
    $existing = @(Get-DnsServerResourceRecord -ZoneName $zoneName -Name $label -ErrorAction SilentlyContinue)
    if ($existing.Count -gt 0) {
        Write-Log "'$hostName' already exists - left alone; make sure it reaches $Address" -Tag "Info"
        return $true
    }
    try {
        Add-DnsServerResourceRecordA -ZoneName $zoneName -Name $label -IPv4Address $Address -ErrorAction Stop
        Write-Log "Created '$hostName' -> $Address ($($Record.Purpose))" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "Add-DnsServerResourceRecordA failed for '$hostName': $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

# Where a record points, and the one way this run can know it. Every target here is a
# domain member that registered its own name when it joined, so this resolves what the
# design already states rather than asking for an address twice.
function Resolve-StudioNamespaceAddress {
    param([Parameter(Mandatory)][string]$Fqdn)

    try {
        $resolved = @([System.Net.Dns]::GetHostAddresses($Fqdn) |
            Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork })
        if ($resolved.Count -gt 0) { return $resolved[0].IPAddressToString }
    }
    catch {
        Write-Log "'$Fqdn' does not resolve from here" -Tag "Debug"
    }
    return ""
}

