# Role provider: Remote Desktop Services - quick session deployment.
#
# Dot-sourced by Configure-ServerRoles.ps1 - not runnable on its own. Everything
# here lands in that script's scope, so $script: variables and functions are shared
# with every other part. Use $scriptRootPath, never $PSScriptRoot: inside this file
# $PSScriptRoot is the pwsh folder, not the folder the run was started from.

# ===========================[ Remote Desktop Services ]===========================
# Server Manager's Quick Start, as cmdlets - and its Standard deployment, which is the
# same design spread over several machines: connection broker, web access, licensing and
# a farm of session hosts, one session collection on top of them.
#
# ONE CODE PATH, TWO MODES. The contract carries the same shape either way: a quick
# session is the farm whose every part is this machine. So nothing below asks which mode
# it is in - it asks which parts of the topology name *this* machine, and does those.
#
# The binaries are not this script's job. The sibling HyperV-Scripts studio installs
# RDS-RD-Server, RDS-Connection-Broker, RDS-Web-Access and RSAT-RDS-Tools while the VM
# is built; this is the domain-joined, post-boot half it hands over. New-RDSessionDeployment
# would install the role services itself - it is the wizard - but the prerequisite check
# fails first when any of them is missing, so it never finds anything to install and the
# rule that this script configures rather than installs still holds.
#
# State-driven, like the CA provider: every run looks at what already exists and does
# the next possible thing, so re-running is safe and a half-built deployment finishes
# rather than starting over.

$script:rdsRoleServices = @("RDS-RD-Server", "RDS-Connection-Broker", "RDS-Web-Access")

# What each part of a deployment needs on its own machine. A quick session holds every
# part, so it is checked for all of them; a farm's session host is checked for one.
# RSAT-RDS-Tools is on every one of them, not only the broker: it carries the
# RemoteDesktop module, and a member joins the farm by calling Add-RDServer on itself.
# Listing it for the broker alone contradicted the module check a few lines later, which
# refuses any machine that cannot load it.
$script:rdsPartFeature = @{
    "broker"      = @("RDS-Connection-Broker", "RSAT-RDS-Tools")
    "webAccess"   = @("RDS-Web-Access", "RSAT-RDS-Tools")
    "licensing"   = @("RDS-Licensing", "RSAT-RDS-Tools")
    "sessionHost" = @("RDS-RD-Server", "RSAT-RDS-Tools")
}

# ---------------------------[ Module and machine ]---------------------------
function Import-RdsModule {
    if (Get-Command -Name "Get-RDServer" -ErrorAction SilentlyContinue) { return $true }
    try {
        Import-Module -Name "RemoteDesktop" -ErrorAction Stop
        return $true
    }
    catch {
        Write-Log "The RemoteDesktop module could not be loaded: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

# A machine in a farm is named however its owner names machines. A name with a dot is
# taken as written; a bare label is completed with this machine's own DNS domain, which
# is the only domain a run can speak for. Every deployment cmdlet refuses a short name
# with an error that names neither the parameter nor the reason, so this is where that
# stops being possible.
# This machine's DNS domain, asked of the machine rather than of the session.
#
# USERDNSDOMAIN is a *user* variable and SYSTEM does not have one - so every scheduled
# task this project registers ran with it empty, and a design that names its broker
# 'rds-cb-01' had that name handed to Get-RDServer as typed. Every deployment cmdlet
# refuses a short name, so the nightly certificate task reported "no deployment on this
# server" on the connection broker itself, night after night, while the same config run
# by an administrator worked perfectly. Field-hit 2026-08-16.
#
# Three sources, in the order they can be trusted: the session's own variable when there
# is one, then Win32_ComputerSystem (the machine's AD domain, which is what SYSTEM can
# still see), then the primary DNS suffix from the TCP/IP parameters - which is the
# right answer on a disjoint namespace and the only one left on a machine whose WMI is
# not answering.
$script:rdsDnsDomain = $null

function Get-RdsDnsDomain {
    if ($null -ne $script:rdsDnsDomain) { return $script:rdsDnsDomain }

    $domain = [string]$env:USERDNSDOMAIN
    if ([string]::IsNullOrWhiteSpace($domain)) {
        try {
            $computer = Get-CimInstance -ClassName "Win32_ComputerSystem" -ErrorAction Stop
            if ($computer.PartOfDomain) { $domain = [string]$computer.Domain }
        }
        catch {
            Write-Log "Could not read this machine's domain from Win32_ComputerSystem: $($_.Exception.Message)" -Tag "Debug"
        }
    }
    if ([string]::IsNullOrWhiteSpace($domain)) {
        foreach ($name in @("Domain", "NV Domain")) {
            try {
                $value = [string](Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name $name -ErrorAction Stop).$name
                if (-not [string]::IsNullOrWhiteSpace($value)) { $domain = $value; break }
            }
            # Empty on purpose: two value names are tried and a machine with a primary
            # DNS suffix has one of them. "The value does not exist" is the normal answer
            # to the other, not something to report.
            catch { }
        }
    }

    $script:rdsDnsDomain = ([string]$domain).Trim().TrimStart(".").ToLowerInvariant()
    return $script:rdsDnsDomain
}

function Resolve-RdsFqdn {
    param([string]$Name)

    $value = ([string]$Name).Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($value)) { return "" }
    if ($value.Contains(".")) { return $value }

    $domain = Get-RdsDnsDomain
    if ([string]::IsNullOrWhiteSpace($domain)) { return $value }
    return ("{0}.{1}" -f $value, $domain).ToLowerInvariant()
}

# This machine's own full name, which is what every "is that me?" question compares to.
function Get-RdsLocalFqdn {
    $domain = Get-RdsDnsDomain
    if ([string]::IsNullOrWhiteSpace($domain)) { return ([string]$env:COMPUTERNAME).ToLowerInvariant() }
    return ("{0}.{1}" -f $env:COMPUTERNAME, $domain).ToLowerInvariant()
}

# Every full name this machine answers to. Two, because they can differ: the AD domain
# (USERDNSDOMAIN) and the primary DNS suffix are the same on most networks and are not on
# a disjoint namespace, where the machine's real name is the one a design would type.
function Get-RdsLocalName {
    $names = @((Get-RdsLocalFqdn))
    try {
        $resolved = ([string]([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName)).ToLowerInvariant()
        if (-not [string]::IsNullOrWhiteSpace($resolved)) { $names += $resolved }
    }
    catch {
        Write-Log "Could not resolve this machine's own DNS name: $($_.Exception.Message)" -Tag "Debug"
    }
    return @($names | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
}

# Is the design naming THIS machine? Full names only, and that is the whole point: the
# host label on its own is not an identity. A forest with rds-01 in two domains - or a
# lab rebuilt into a second one - had every machine sharing a label claim to be the one
# the design meant, which is a session host in the wrong domain joining a farm it was
# never designed into. The label alone is accepted only when this machine has no domain
# to be sure with, and it says so out loud when it does.
function Test-RdsThisMachine {
    param([string]$Fqdn)

    $value = ([string]$Fqdn).Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($value)) { return $false }

    $known = @(Get-RdsLocalName)
    if ($known -contains $value) { return $true }

    if (-not [string]::IsNullOrWhiteSpace([string]$env:USERDNSDOMAIN)) { return $false }

    # No domain known at all - a machine that is not joined yet, which is where a design
    # naming bare labels is all anybody can go on.
    if ($value.Split(".")[0] -eq ([string]$env:COMPUTERNAME).ToLowerInvariant()) {
        Write-Log "Matching '$value' on its host name alone - this machine has no DNS domain to compare with" -Tag "Warn"
        return $true
    }
    return $false
}

# The design's machines, resolved once. Everything below reads this rather than the
# config, so "what is this farm" is answered in one place and the same way for a quick
# session - where every part is the same machine.
function Get-RdsTopology {
    param([Parameter(Mandatory)][object]$RemoteDesktop)

    $deployment = Get-ConfigValue -InputObject $RemoteDesktop -Name "deployment"
    $broker = Resolve-RdsFqdn -Name (Get-ConfigText -InputObject $deployment -Name "connectionBroker")
    if ([string]::IsNullOrWhiteSpace($broker)) {
        $broker = Resolve-RdsFqdn -Name (Get-ConfigText -InputObject $deployment -Name "fqdn")
    }
    if ([string]::IsNullOrWhiteSpace($broker)) { $broker = Get-RdsLocalFqdn }

    $webAccess = Get-ConfigValue -InputObject $deployment -Name "webAccess"
    $webName = ""
    if ($null -ne $webAccess) { $webName = Resolve-RdsFqdn -Name (Get-ConfigText -InputObject $webAccess -Name "name") }
    if ([string]::IsNullOrWhiteSpace($webName)) { $webName = $broker }

    $hosts = @()
    foreach ($entry in @(Get-ConfigArray -InputObject $deployment -Name "sessionHosts")) {
        # A bare string is the older shape and still reads.
        $name = ""
        $drain = "Yes"
        if ($entry -is [string]) { $name = [string]$entry }
        else {
            $name = Get-ConfigText -InputObject $entry -Name "name"
            $drain = Get-ConfigText -InputObject $entry -Name "newConnectionAllowed" -Default "Yes"
        }
        $name = Resolve-RdsFqdn -Name $name
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        if (@("Yes", "No", "NotUntilReboot") -notcontains $drain) { $drain = "Yes" }
        $hosts += [PSCustomObject]@{ Fqdn = $name; NewConnectionAllowed = $drain }
    }
    # A design with no host list at all is a quick session written before the farm
    # existed: the one server is every part of it.
    if ($hosts.Count -eq 0) { $hosts = @([PSCustomObject]@{ Fqdn = $broker; NewConnectionAllowed = "Yes" }) }

    # A section that is not there at all is a config written before it existed, not an
    # error: Get-ConfigArray takes an object and this one may legitimately be absent.
    $licensing = Get-ConfigValue -InputObject $RemoteDesktop -Name "licensing"
    $licenseServers = @()
    if ($null -ne $licensing) {
        $licenseServers = @(Get-ConfigArray -InputObject $licensing -Name "servers" |
            ForEach-Object { Resolve-RdsFqdn -Name ([string]$_) } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }

    return [PSCustomObject]@{
        Mode           = Get-ConfigText -InputObject $RemoteDesktop -Name "mode" -Default "singleHost"
        Broker         = $broker
        WebAccess      = $webName
        WebSeparate    = ($webName -ne $broker)
        SessionHosts   = $hosts
        LicenseServers = $licenseServers
        CollectionName = Get-ConfigText -InputObject $deployment -Name "collectionName" -Default "Remote Desktop Services"
    }
}

# Which parts of the deployment this machine is. Several, on a quick session; usually one
# in a farm; none is a design that does not mention the machine reading it.
function Get-RdsFarmPart {
    param([Parameter(Mandatory)][object]$Topology)

    $parts = @()
    if (Test-RdsThisMachine -Fqdn $Topology.Broker) { $parts += "broker" }
    if (Test-RdsThisMachine -Fqdn $Topology.WebAccess) { $parts += "webAccess" }
    foreach ($server in $Topology.LicenseServers) {
        if (Test-RdsThisMachine -Fqdn $server) { $parts += "licensing"; break }
    }
    foreach ($sessionHost in $Topology.SessionHosts) {
        if (Test-RdsThisMachine -Fqdn $sessionHost.Fqdn) { $parts += "sessionHost"; break }
    }
    return $parts
}

# Every deployment cmdlet takes the server by its full name and refuses a short one,
# with an error that names neither the parameter nor the reason.
function Get-RdsServerFqdn {
    param([Parameter(Mandatory)][object]$RemoteDesktop)

    $deployment = Get-ConfigValue -InputObject $RemoteDesktop -Name "deployment"
    $fqdn = Get-ConfigText -InputObject $deployment -Name "connectionBroker"
    if ([string]::IsNullOrWhiteSpace($fqdn)) { $fqdn = Get-ConfigText -InputObject $deployment -Name "fqdn" }
    # Resolved rather than returned as typed: a farm names machines the way its owner
    # names machines, and the cmdlets take nothing but a full name.
    if (-not [string]::IsNullOrWhiteSpace($fqdn)) { return (Resolve-RdsFqdn -Name $fqdn) }

    # Nothing in the design: fall back to what the machine calls itself, which is right
    # far more often than it is wrong.
    $domain = [string]$env:USERDNSDOMAIN
    if ([string]::IsNullOrWhiteSpace($domain)) { return "" }
    return (Get-RdsLocalFqdn)
}

function Test-RdsDomainMember {
    try {
        $computer = Get-CimInstance -ClassName "Win32_ComputerSystem" -ErrorAction Stop
        return [bool]$computer.PartOfDomain
    }
    catch {
        Write-Log "Could not determine whether this machine is domain joined: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

# ---------------------------[ Deployment state ]---------------------------
# Why the last query came back empty. Kept beside the function rather than returned,
# because every caller of Get-RdsDeploymentServer wants the list and only two of them
# care why it is short.
$script:rdsDeploymentQueryError = ""

function Get-RdsDeploymentServer {
    param([Parameter(Mandatory)][string]$Fqdn)

    $script:rdsDeploymentQueryError = ""
    try {
        return @(Get-RDServer -ConnectionBroker $Fqdn -ErrorAction Stop)
    }
    catch {
        # No deployment yet is the normal case on a fresh server, not a failure. What is
        # NOT normal, and read identically until 2026-08-16, is a broker that has a
        # deployment and could not answer - see Write-RdsDeploymentDiagnosis.
        $script:rdsDeploymentQueryError = [string]$_.Exception.Message
        Write-Log "No Remote Desktop deployment answers on '$Fqdn' yet: $($script:rdsDeploymentQueryError)" -Tag "Debug"
        return @()
    }
}

# Get-RDServer throwing and there being no deployment are the same empty array, and the
# difference matters most on the machine where the answer decides whether a certificate
# gets renewed tonight. The usual cause of the first is timing: after a broker restart
# rdms is not up yet, the RDS WMI namespace does not answer, and a run in that window
# reports "no deployment on this server" about the connection broker itself. Field-hit
# 2026-08-16 - the same lag the portal watchdog's five-minute startup delay exists for.
function Write-RdsDeploymentDiagnosis {
    param([Parameter(Mandatory)][string]$Fqdn)

    if (-not [string]::IsNullOrWhiteSpace($script:rdsDeploymentQueryError)) {
        Write-Log "    Get-RDServer said: $($script:rdsDeploymentQueryError)" -Tag "Info"
    }
    # First, because it is the one cause that looks like every other cause: a name with
    # no dot in it is refused by every deployment cmdlet, and the refusal names neither
    # the parameter nor the reason.
    if (-not $Fqdn.Contains(".")) {
        Write-Log "    '$Fqdn' is not a fully qualified name - the deployment cmdlets refuse a short one" -Tag "Warn"
        Write-Log "    This machine's DNS domain reads '$(Get-RdsDnsDomain)' - type the broker's full name in the design if it cannot be completed here" -Tag "Warn"
    }
    # Only about this machine. The services on somebody else's broker are not something
    # this run can read without asking for rights it does not have.
    if (-not (Test-RdsThisMachine -Fqdn $Fqdn)) { return }

    foreach ($service in @(Get-RdsBrokerService)) {
        Write-Log "    $($service.Label) ($($service.Name)): $(Get-RdsServiceState -Name $service.Name)" -Tag "Info"
    }


    # The one cause worth naming outright, because a hardened build walks into it and the
    # symptom is this exact silence. RDMS and the Connection Broker authenticate to the
    # Windows Internal Database, and WID speaks TLS 1.0 - so a baseline that turns TLS 1.0
    # off stops RDMS from starting at all ("started and then stopped"), and every RD
    # cmdlet on the box fails from then on. Microsoft KB 4036954. Only said when RDMS is
    # actually down, so it does not become noise on a healthy broker.
    if ((Get-RdsServiceState -Name "rdms") -ne "Running") {
        Write-Log "    Get-RDServer asks the Remote Desktop Management service, and it is not running - that is the failure, not this query" -Tag "Warn"
        Write-Log "    One classic cause on a hardened build: RDMS talks to the Windows Internal Database over TLS 1.0, so a baseline disabling TLS 1.0 stops it starting" -Tag "Warn"
        Write-Log "        HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server and \Client" -Tag "Warn"
        Write-Log "        Get-WinEvent -LogName 'Microsoft-Windows-Remote-Desktop-Management-Service/Admin' -MaxEvents 15" -Tag "Warn"
    }
}

# The three services a deployment query depends on, and the one that holds its data.
function Get-RdsBrokerService {
    return @(
        [PSCustomObject]@{ Name = "rdms";                     Label = "Remote Desktop Management" },
        [PSCustomObject]@{ Name = "tssdis";                   Label = "Remote Desktop Connection Broker" },
        [PSCustomObject]@{ Name = "tscpubrpc";                Label = "Remote Desktop Configuration" },
        [PSCustomObject]@{ Name = "MSSQL`$MICROSOFT##WID";    Label = "Windows Internal Database" }
    )
}

function Get-RdsServiceState {
    param([Parameter(Mandatory)][string]$Name)

    try { return [string](Get-Service -Name $Name -ErrorAction Stop).Status }
    catch { return "not installed" }
}

function Test-RdsDeployment {
    param([Parameter(Mandatory)][string]$Fqdn)
    return ((Get-RdsDeploymentServer -Fqdn $Fqdn).Count -gt 0)
}

function Get-RdsCollection {
    param(
        [Parameter(Mandatory)][string]$Fqdn,
        [Parameter(Mandatory)][string]$CollectionName
    )

    try {
        return (Get-RDSessionCollection -CollectionName $CollectionName -ConnectionBroker $Fqdn -ErrorAction Stop)
    }
    catch {
        return $null
    }
}

# ---------------------------[ Deployment and collection ]---------------------------
# Whether a role service is installed on ANOTHER machine. This is the check that keeps
# the project's rule intact in a farm: New-RDSessionDeployment and Add-RDServer install
# role services on the servers they are handed - remotely, and with a restart - which is
# the wizard doing exactly what this script never does. So a server that is not ready is
# left out of the call and named, rather than being quietly built.
function Test-RdsRemoteRoleService {
    param(
        [Parameter(Mandatory)][string]$Fqdn,
        [Parameter(Mandatory)][string]$Feature
    )

    if (Test-RdsThisMachine -Fqdn $Fqdn) {
        try {
            $state = Get-WindowsFeature -Name $Feature -ErrorAction Stop
            return (($null -ne $state) -and $state.Installed)
        }
        catch { return $false }
    }

    try {
        $state = Get-WindowsFeature -Name $Feature -ComputerName $Fqdn -ErrorAction Stop
        return (($null -ne $state) -and $state.Installed)
    }
    catch {
        Write-Log "Could not ask '$Fqdn' whether $Feature is installed: $($_.Exception.Message)" -Tag "Warn"
        Write-Log "    The account driving this run needs administrative rights and WinRM on every server in the farm" -Tag "Info"
        return $false
    }
}

# The session hosts this run may hand to a deployment cmdlet: ready, and reachable. One
# that is not is reported with its own line to run and skipped - a farm is built in
# whatever order the machines come up, and the host itself joins when its turn comes.
function Get-RdsReadySessionHost {
    param([Parameter(Mandatory)][object]$Topology)

    $ready = @()
    foreach ($sessionHost in $Topology.SessionHosts) {
        if (Test-RdsRemoteRoleService -Fqdn $sessionHost.Fqdn -Feature "RDS-RD-Server") {
            $ready += $sessionHost.Fqdn
            continue
        }
        Write-Log "'$($sessionHost.Fqdn)' does not have RDS-RD-Server yet - left out of the deployment" -Tag "Warn"
        Write-Log "    Install-WindowsFeature -Name RDS-RD-Server -IncludeManagementTools   (on that server)" -Tag "Info"
        Write-Log "    Then run this same config there - it adds itself to the farm" -Tag "Info"
    }
    return $ready
}

function New-RdsDeployment {
    param(
        [Parameter(Mandatory)][string]$Fqdn,
        [Parameter(Mandatory)][object]$Topology
    )

    $hosts = @(Get-RdsReadySessionHost -Topology $Topology)
    if ($hosts.Count -eq 0) {
        # The cmdlet demands at least one, and the broker is not a session host in a farm.
        throw "No session host in this design is ready - install RDS-RD-Server on one and re-run."
    }
    if (-not (Test-RdsRemoteRoleService -Fqdn $Topology.WebAccess -Feature "RDS-Web-Access")) {
        throw "'$($Topology.WebAccess)' does not have RDS-Web-Access installed. It is not a Server Core role service, and the run does not install it."
    }

    Write-Log ("Creating the session deployment - broker '{0}', web access '{1}', session host(s) {2}" -f `
        $Fqdn, $Topology.WebAccess, ($hosts -join ", ")) -Tag "Run"
    New-RDSessionDeployment -ConnectionBroker $Fqdn -WebAccessServer $Topology.WebAccess -SessionHost $hosts -ErrorAction Stop | Out-Null
    Write-Log "Session deployment created" -Tag "Ok"
}

# Everything the design names that is not in the deployment yet. Run on the broker, every
# run, so a farm that grew a machine picks it up without anybody remembering a wizard.
# Additive only: taking a host out of a farm is never this script's decision.
function Sync-RdsFarmMember {
    param(
        [Parameter(Mandatory)][string]$Fqdn,
        [Parameter(Mandatory)][object]$Topology,
        [Parameter(Mandatory)][string]$CollectionName
    )

    $allAdded = $true
    $servers = @(Get-RdsDeploymentServer -Fqdn $Fqdn)

    $wanted = @()
    $wanted += [PSCustomObject]@{ Fqdn = $Topology.WebAccess; Role = "RDS-WEB-ACCESS"; Feature = "RDS-Web-Access" }
    foreach ($sessionHost in $Topology.SessionHosts) {
        $wanted += [PSCustomObject]@{ Fqdn = $sessionHost.Fqdn; Role = "RDS-RD-SERVER"; Feature = "RDS-RD-Server" }
    }

    foreach ($member in $wanted) {
        $existing = @($servers | Where-Object { [string]$_.Server -eq $member.Fqdn -and @($_.Roles) -contains $member.Role })
        if ($existing.Count -gt 0) { continue }

        if (-not (Test-RdsRemoteRoleService -Fqdn $member.Fqdn -Feature $member.Feature)) {
            Write-Log "'$($member.Fqdn)' is in the design but does not have $($member.Feature) - not added" -Tag "Warn"
            Write-Log "    Install-WindowsFeature -Name $($member.Feature) -IncludeManagementTools   (on that server)" -Tag "Info"
            $allAdded = $false
            continue
        }

        Write-Log "Adding '$($member.Fqdn)' to the deployment as $($member.Role)" -Tag "Run"
        try {
            Add-RDServer -Server $member.Fqdn -Role $member.Role -ConnectionBroker $Fqdn -ErrorAction Stop | Out-Null
            Write-Log "'$($member.Fqdn)' added" -Tag "Ok"
        }
        catch {
            Write-Log "Could not add '$($member.Fqdn)': $($_.Exception.Message)" -Tag "Error"
            $allAdded = $false
        }
    }

    # The collection is the other half: a server can be in the deployment and in no
    # collection, which is a session host nobody ever lands on.
    $inCollection = @()
    try {
        $inCollection = @(Get-RDSessionHost -CollectionName $CollectionName -ConnectionBroker $Fqdn -ErrorAction Stop |
            ForEach-Object { ([string]$_.SessionHost).ToLowerInvariant() })
    }
    catch {
        Write-Log "Could not read the session hosts of '$CollectionName': $($_.Exception.Message)" -Tag "Debug"
    }

    foreach ($sessionHost in $Topology.SessionHosts) {
        if ($inCollection -contains $sessionHost.Fqdn) { continue }
        if (-not (Test-RdsRemoteRoleService -Fqdn $sessionHost.Fqdn -Feature "RDS-RD-Server")) { continue }
        Write-Log "Adding '$($sessionHost.Fqdn)' to the collection '$CollectionName'" -Tag "Run"
        try {
            Add-RDSessionHost -CollectionName $CollectionName -SessionHost $sessionHost.Fqdn -ConnectionBroker $Fqdn -ErrorAction Stop | Out-Null
            Write-Log "'$($sessionHost.Fqdn)' is serving the collection" -Tag "Ok"
        }
        catch {
            Write-Log "Could not add '$($sessionHost.Fqdn)' to the collection: $($_.Exception.Message)" -Tag "Error"
            $allAdded = $false
        }
    }
    return $allAdded
}

# The member's half. A machine that is not the broker adds ITSELF, which is what makes
# the eleventh session host one run on the eleventh session host rather than an edit to
# whatever built the first ten.
function Join-RdsFarm {
    param(
        [Parameter(Mandatory)][object]$Topology,
        [Parameter(Mandatory)][string[]]$Part
    )

    $broker = $Topology.Broker
    if (-not (Test-RdsDeployment -Fqdn $broker)) {
        Write-Log "There is no deployment on '$broker' yet - this machine joins it afterwards" -Tag "Info"
        return $false
    }

    $me = Get-RdsLocalFqdn
    $roles = @()
    if ($Part -contains "webAccess")   { $roles += "RDS-WEB-ACCESS" }
    if ($Part -contains "licensing")   { $roles += "RDS-LICENSING" }
    if ($Part -contains "sessionHost") { $roles += "RDS-RD-SERVER" }

    $servers = @(Get-RdsDeploymentServer -Fqdn $broker)
    $joined = $true
    foreach ($role in $roles) {
        $existing = @($servers | Where-Object { [string]$_.Server -eq $me -and @($_.Roles) -contains $role })
        if ($existing.Count -gt 0) {
            Write-Log "This machine is already in the deployment as $role" -Tag "Info"
            continue
        }
        Write-Log "Joining the deployment on '$broker' as $role" -Tag "Run"
        try {
            Add-RDServer -Server $me -Role $role -ConnectionBroker $broker -ErrorAction Stop | Out-Null
            Write-Log "Joined as $role" -Tag "Ok"
        }
        catch {
            Write-Log "Could not join as $role : $($_.Exception.Message)" -Tag "Error"
            Write-Log "    The account running this needs administrative rights on '$broker'" -Tag "Info"
            $joined = $false
        }
    }

    if ($Part -contains "sessionHost") {
        $inCollection = @()
        try {
            $inCollection = @(Get-RDSessionHost -CollectionName $Topology.CollectionName -ConnectionBroker $broker -ErrorAction Stop |
                ForEach-Object { ([string]$_.SessionHost).ToLowerInvariant() })
        }
        catch {
            Write-Log "Could not read the collection's session hosts: $($_.Exception.Message)" -Tag "Debug"
        }
        if ($inCollection -notcontains $me) {
            Write-Log "Adding this machine to the collection '$($Topology.CollectionName)'" -Tag "Run"
            try {
                Add-RDSessionHost -CollectionName $Topology.CollectionName -SessionHost $me -ConnectionBroker $broker -ErrorAction Stop | Out-Null
                Write-Log "This machine is serving the collection now" -Tag "Ok"
            }
            catch {
                Write-Log "Could not add this machine to the collection: $($_.Exception.Message)" -Tag "Error"
                $joined = $false
            }
        }
    }
    return $joined
}

# Draining, which is the only load-balancing control the module still supports: relative
# weights left the usable surface, and this is what is left. Re-applied every run, so a
# host parked at NotUntilReboot stays parked until the design says otherwise.
function Set-RdsSessionHostDrain {
    param(
        [Parameter(Mandatory)][string]$Fqdn,
        [Parameter(Mandatory)][object]$Topology
    )

    $allSet = $true
    foreach ($sessionHost in $Topology.SessionHosts) {
        $current = $null
        try {
            $current = Get-RDSessionHost -CollectionName $Topology.CollectionName -ConnectionBroker $Fqdn -ErrorAction Stop |
                Where-Object { ([string]$_.SessionHost).ToLowerInvariant() -eq $sessionHost.Fqdn }
        }
        catch {
            Write-Log "Could not read '$($sessionHost.Fqdn)' in the collection: $($_.Exception.Message)" -Tag "Debug"
        }
        if ($null -eq $current) { continue }
        if ([string]$current.NewConnectionAllowed -eq $sessionHost.NewConnectionAllowed) { continue }

        Write-Log "'$($sessionHost.Fqdn)': new connections -> $($sessionHost.NewConnectionAllowed)" -Tag "Run"
        try {
            Set-RDSessionHost -SessionHost $sessionHost.Fqdn -NewConnectionAllowed $sessionHost.NewConnectionAllowed `
                -ConnectionBroker $Fqdn -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Log "Could not set new connections on '$($sessionHost.Fqdn)': $($_.Exception.Message)" -Tag "Error"
            $allSet = $false
        }
    }
    return $allSet
}

function New-RdsCollection {
    param(
        [Parameter(Mandatory)][string]$Fqdn,
        [Parameter(Mandatory)][object]$Deployment,
        [Parameter(Mandatory)][object]$Topology
    )

    $collectionName = Get-ConfigText -InputObject $Deployment -Name "collectionName" -Default "Remote Desktop Services"
    $description    = Get-ConfigText -InputObject $Deployment -Name "collectionDescription"

    Write-Log "Creating the session collection '$collectionName'" -Tag "Run"
    # Every ready session host at once: a collection created with one and grown later is
    # the same collection, but the first user can land anywhere from the start.
    $hosts = @(Get-RdsReadySessionHost -Topology $Topology)
    if ($hosts.Count -eq 0) { throw "No session host is ready to carry the collection." }
    $parameters = @{
        CollectionName   = $collectionName
        SessionHost      = $hosts
        ConnectionBroker = $Fqdn
        ErrorAction      = "Stop"
    }
    if (-not [string]::IsNullOrWhiteSpace($description)) { $parameters["CollectionDescription"] = $description }

    New-RDSessionCollection @parameters | Out-Null
    Write-Log "Session collection created" -Tag "Ok"
}

# Applied to a new collection and an existing one alike: these are the settings that
# change between runs, and a collection nobody re-configures drifts from its design.
function Set-RdsCollectionConfiguration {
    param(
        [Parameter(Mandatory)][string]$Fqdn,
        [Parameter(Mandatory)][string]$CollectionName,
        [Parameter(Mandatory)][object]$RemoteDesktop
    )

    $session = Get-ConfigValue -InputObject $RemoteDesktop -Name "session"
    if ($null -eq $session) { return }

    $parameters = @{
        CollectionName   = $CollectionName
        ConnectionBroker = $Fqdn
        ErrorAction      = "Stop"
    }

    $access = Get-ConfigValue -InputObject $RemoteDesktop -Name "access"
    # userGroups carries {name, members} objects (or bare strings from an older
    # config); the collection wants the names, the members are the DC run's job.
    $groups = @((Get-StudioGroupDefinition -Entries (Get-ConfigArray -InputObject $access -Name "userGroups")) |
        ForEach-Object { $_.Name })

    # The groups are a prerequisite, never created here - Test-RdsPrerequisite refused
    # the run before this point if one of them is missing. The account driving a
    # deployment holds RDS rights, not necessarily the right to write groups into AD,
    # and a collection naming a group that does not exist refuses to configure with an
    # error naming neither the group nor the cause.
    if ($groups.Count -gt 0) {
        $parameters["UserGroup"] = $groups
        Write-Log ("Access is granted to: {0} - fill the group(s) by hand" -f ($groups -join ", ")) -Tag "Info"
    }

    $parameters["IdleSessionLimitMin"]           = [int](Get-ConfigValue -InputObject $session -Name "idleLimitMin" -Default 0)
    $parameters["DisconnectedSessionLimitMin"]   = [int](Get-ConfigValue -InputObject $session -Name "disconnectedLimitMin" -Default 0)
    $parameters["ActiveSessionLimitMin"]         = [int](Get-ConfigValue -InputObject $session -Name "activeLimitMin" -Default 0)
    $parameters["BrokenConnectionAction"]        = Get-ConfigText -InputObject $session -Name "brokenConnectionAction" -Default "Disconnect"
    $parameters["AutomaticReconnectionEnabled"]  = [bool](Get-ConfigValue -InputObject $session -Name "automaticReconnection" -Default $true)
    $parameters["TemporaryFoldersDeletedOnExit"] = [bool](Get-ConfigValue -InputObject $session -Name "temporaryFoldersDeletedOnExit" -Default $true)
    $parameters["ClientPrinterRedirected"]       = [bool](Get-ConfigValue -InputObject $session -Name "clientPrinterRedirected" -Default $false)
    $parameters["ClientPrinterAsDefault"]        = [bool](Get-ConfigValue -InputObject $session -Name "clientPrinterAsDefault" -Default $false)
    $parameters["RDEasyPrintDriverEnabled"]      = [bool](Get-ConfigValue -InputObject $session -Name "easyPrint" -Default $false)
    $parameters["MaxRedirectedMonitors"]         = [int](Get-ConfigValue -InputObject $session -Name "maxRedirectedMonitors" -Default 16)
    $parameters["SecurityLayer"]                 = Get-ConfigText -InputObject $session -Name "securityLayer" -Default "SSL"
    $parameters["EncryptionLevel"]               = Get-ConfigText -InputObject $session -Name "encryptionLevel" -Default "High"
    $parameters["AuthenticateUsingNLA"]          = [bool](Get-ConfigValue -InputObject $session -Name "authenticateUsingNla" -Default $true)

    # One flag list rather than a switch per device class - "None" is what an empty
    # list means to the cmdlet, and leaving the parameter out would keep whatever the
    # collection already had.
    $redirection = @(Get-ConfigArray -InputObject $session -Name "redirection" |
        ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($redirection.Count -eq 0) { $parameters["ClientDeviceRedirectionOptions"] = "None" }
    else { $parameters["ClientDeviceRedirectionOptions"] = ($redirection -join ",") }

    Write-Log "Applying the collection configuration" -Tag "Run"
    Set-RDSessionCollectionConfiguration @parameters | Out-Null
    Write-Log "Collection configuration applied" -Tag "Ok"
}

# ---------------------------[ FSLogix ]---------------------------
# User profile disks are gone from this design; FSLogix is the successor and the one
# Microsoft still invests in - per-user concurrency, an Office container, cloud cache -
# and an RDS CAL is an eligible license, so on a session host it costs nothing extra.
# The two must never be combined: both claim the profile at sign-in and FSLogix loses,
# which is why this provider no longer touches -EnableUserProfileDisk at all.
#
# The agent is a vendor installer, not a Windows feature - the same exception the WAC
# and Arc providers already are. aka.ms/fslogix_download serves a zip holding the
# setup for three architectures; x64\Release\FSLogixAppsSetup.exe is the one a session
# host wants.

function Test-RdsFslogixInstalled {
    return ($null -ne (Get-Service -Name "frxsvc" -ErrorAction SilentlyContinue))
}

function Install-RdsFslogixAgent {
    param([Parameter(Mandatory)][object]$Fslogix)

    if (Test-RdsFslogixInstalled) {
        Write-Log "The FSLogix agent is already installed" -Tag "Info"
        return $true
    }

    $url = Get-ConfigText -InputObject $Fslogix -Name "downloadUrl" -Default "https://aka.ms/fslogix_download"

    # The same folder the other agent downloads use - $env:TEMP is per account and a
    # resumed run may be SYSTEM.
    $downloadDirectory = Join-Path -Path $scriptRootPath -ChildPath "downloads"
    if (-not (Test-Path -LiteralPath $downloadDirectory)) {
        $null = New-Item -ItemType Directory -Path $downloadDirectory -Force
    }
    $archivePath = Join-Path -Path $downloadDirectory -ChildPath "FSLogix.zip"
    $extractPath = Join-Path -Path $downloadDirectory -ChildPath "FSLogix"

    try {
        Invoke-WacDownload -Url $url -Destination $archivePath

        # Anything under a megabyte is an error page, and Expand-Archive fails on it
        # later with a message that names neither the download nor the cause.
        if ((Get-Item -LiteralPath $archivePath).Length -lt 1MB) {
            throw "The download from '$url' is too small to be the FSLogix package - it is probably an error page."
        }

        if (Test-Path -LiteralPath $extractPath) {
            Remove-Item -LiteralPath $extractPath -Recurse -Force -ErrorAction SilentlyContinue
        }
        Expand-Archive -LiteralPath $archivePath -DestinationPath $extractPath -Force

        $setup = @(Get-ChildItem -Path $extractPath -Filter "FSLogixAppsSetup.exe" -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match "x64" })
        if ($setup.Count -eq 0) {
            throw "No x64 FSLogixAppsSetup.exe inside the package from '$url'."
        }

        Write-Log "Installing the FSLogix agent" -Tag "Run"
        $process = Start-Process -FilePath $setup[0].FullName -ArgumentList "/install /quiet /norestart" -Wait -PassThru
        # 3010 is success plus a pending reboot - the driver loads without one on a
        # fresh install, and the session host reboots with the deployment anyway.
        if (($process.ExitCode -ne 0) -and ($process.ExitCode -ne 3010)) {
            throw "FSLogixAppsSetup.exe exited with code $($process.ExitCode)."
        }
    }
    catch {
        Write-Log "The FSLogix agent could not be installed: $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    # The installer returns as the service registration settles, same habit as the
    # WAC bootstrapper - poll rather than fail a run that worked.
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        if (Test-RdsFslogixInstalled) {
            Write-Log "FSLogix agent installed" -Tag "Ok"
            return $true
        }
        Start-Sleep -Seconds 2
    }
    Write-Log "FSLogixAppsSetup reported success but the frxsvc service never appeared" -Tag "Error"
    return $false
}

function Set-RdsFslogixProfile {
    param([Parameter(Mandatory)][object]$RemoteDesktop)

    $fslogix = Get-ConfigValue -InputObject $RemoteDesktop -Name "fslogix"
    if ($null -eq $fslogix) { return $true }

    if (-not [bool](Get-ConfigValue -InputObject $fslogix -Name "enabled" -Default $false)) {
        if (Test-RdsFslogixInstalled) {
            Write-Log "FSLogix is installed and off in this design - its configuration belongs to Group Policy" -Tag "Info"
        }
        else {
            Write-Log "FSLogix is off - profiles stay on the session host" -Tag "Info"
        }
        return $true
    }

    if (-not (Install-RdsFslogixAgent -Fslogix $fslogix)) {
        return $false
    }

    # Deliberately nothing else. Where the containers live, how big they grow and how
    # the agent behaves are HKLM\SOFTWARE\Policies\FSLogix settings, and policy is
    # where they are managed - one place for every session host, refreshed on its own,
    # never fighting a local write this script left behind. This run's whole job is
    # that the agent those policies configure is actually on the machine.
    Write-Log "Profile locations, size and behaviour come from Group Policy" -Tag "Info"
    Write-Log "Until that policy applies here, FSLogix stays idle and profiles stay local" -Tag "Info"
    return $true
}

# ---------------------------[ Licensing ]---------------------------
# RD Licensing on this same server. The role service is added to the deployment here;
# the feature itself is checked in the prerequisite hook, and activation and CALs are
# not automatable at all - both go through Microsoft's clearing house.
function Add-RdsLicenseServerRole {
    param(
        [Parameter(Mandatory)][string]$Fqdn,
        [Parameter(Mandatory)][object]$RemoteDesktop
    )

    $licensing = Get-ConfigValue -InputObject $RemoteDesktop -Name "licensing"
    if (-not [bool](Get-ConfigValue -InputObject $licensing -Name "installOnThisServer" -Default $false)) { return $true }

    $existing = @(Get-RdsDeploymentServer -Fqdn $Fqdn | Where-Object { @($_.Roles) -contains "RDS-LICENSING" })
    if ($existing.Count -gt 0) {
        Write-Log "The deployment already has a license server role service" -Tag "Info"
    }
    else {
        Write-Log "Adding the RD Licensing role service on '$Fqdn'" -Tag "Run"
        try {
            Add-RDServer -Server $Fqdn -Role "RDS-LICENSING" -ConnectionBroker $Fqdn -ErrorAction Stop | Out-Null
            Write-Log "RD Licensing role service added" -Tag "Ok"
        }
        catch {
            Write-Log "Could not add the RD Licensing role service: $($_.Exception.Message)" -Tag "Error"
            return $false
        }
    }

    # Said on every run, not only the first: a license server that was never activated
    # issues nothing, and the deployment falls back to the grace period without a word.
    Write-Log "Activate the license server and install its CALs by hand - both go through Microsoft's clearing house" -Tag "Info"
    Write-Log "    licmgr.exe   (RD Licensing Manager, from RDS-Licensing-UI)" -Tag "Info"
    if (-not (Test-RdsLicenseServerActivated)) {
        Write-Log "This license server is not activated yet - until it is, it hands out nothing" -Tag "Info"
    }
    return $true
}

# Reported, never changed. Win32_TSLicenseServer lives on the licensing server itself,
# so an unreadable class here means the role service is not on this machine.
function Test-RdsLicenseServerActivated {
    try {
        $server = Get-CimInstance -Namespace "root/CIMV2" -ClassName "Win32_TSLicenseServer" -ErrorAction Stop
        if ($null -eq $server) { return $false }
        $status = Invoke-CimMethod -InputObject $server -MethodName "GetActivationStatus" -ErrorAction Stop
        # 0 is activated; anything else is not yet, or not activated any more.
        return ([int]$status.ActivationStatus -eq 0)
    }
    catch {
        Write-Log "Could not read the license server's activation status: $($_.Exception.Message)" -Tag "Debug"
        return $false
    }
}

function Set-RdsLicensing {
    param(
        [Parameter(Mandatory)][string]$Fqdn,
        [Parameter(Mandatory)][object]$RemoteDesktop
    )

    $licensing = Get-ConfigValue -InputObject $RemoteDesktop -Name "licensing"
    $mode      = Get-ConfigText -InputObject $licensing -Name "mode" -Default "NotConfigured"

    if ($mode -eq "NotConfigured") {
        # Not an omission to fix quietly: the deployment runs on its own 120 day grace
        # period and refuses every connection on day 121, with no warning before it.
        Write-Log "No licensing mode is set - the deployment runs on its 120 day grace period" -Tag "Info"
        return
    }

    # Resolved, not read raw: a farm names its licence server the way it names every
    # machine - often a bare label - and Set-RDLicenseConfiguration is a deployment
    # cmdlet like the rest, which is to say it takes full names. Get-RdsTopology already
    # resolves this list; this is the same rule at the one call site that bypasses it.
    $servers = @(Get-ConfigArray -InputObject $licensing -Name "servers" |
        ForEach-Object { Resolve-RdsFqdn -Name ([string]$_) } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($servers.Count -eq 0) {
        throw "licensing.mode is '$mode' but no license server is named."
    }

    Write-Log "Setting licensing to $mode against $($servers -join ', ')" -Tag "Run"
    Set-RDLicenseConfiguration -Mode $mode -LicenseServer $servers -ConnectionBroker $Fqdn -Force -ErrorAction Stop | Out-Null

    if ($mode -eq "PerUser") {
        Set-RdsLicenseServerGroup -Server $servers
    }

    # The half no script reaches: activation talks to Microsoft's clearinghouse through
    # a wizard, and the CALs come from a purchase. Without both, the grace period keeps
    # counting whatever the mode says - and it expires with no warning first.
    Write-Log "Two steps stay manual, in Remote Desktop Licensing Manager (licmgr.exe) on the license server:" -Tag "Info"
    Write-Log "    1. Activate the license server - the wizard talks to Microsoft's clearinghouse" -Tag "Info"
    Write-Log "    2. Install the purchased CALs onto it" -Tag "Info"
    Write-Log "Until both are done the deployment runs on its 120 day grace period and refuses every connection on day 121" -Tag "Info"
    Write-Log "Licensing configured" -Tag "Ok"
}

# Per User CALs are only *tracked* while the license server's computer account is in
# the domain's 'Terminal Server License Servers' group - and nothing reports the
# omission until an audit does. The group is builtin and well known, the member is a
# computer account this run already knows by name, and the account running this is a
# domain administrator: the same ADSI writes the enrollment groups use reach it, so
# 'nothing on this server can add it' stopped being true when those landed.
function Set-RdsLicenseServerGroup {
    param([Parameter(Mandatory)][string[]]$Server)

    $groupEntry = $null
    try {
        $groupDn = "CN=Terminal Server License Servers,CN=Builtin," + (Get-AdcsDefaultNamingContext)
        $groupEntry = Get-AdcsDirectoryEntry -DistinguishedName $groupDn
    }
    catch {
        Write-Log "Could not open 'Terminal Server License Servers': $($_.Exception.Message)" -Tag "Warn"
        Write-Log "Add the license server(s) by hand: Add-ADGroupMember -Identity 'Terminal Server License Servers' -Members <server>$" -Tag "Info"
        return
    }

    $members = @($groupEntry.Properties["member"] | ForEach-Object { [string]$_ })

    foreach ($serverName in $Server) {
        # The config carries FQDNs; the account is the host name plus the trailing $.
        $hostName = $serverName.Split(".")[0]

        $account = $null
        try {
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.Filter = "(&(objectCategory=computer)(sAMAccountName=$hostName$))"
            $null = $searcher.PropertiesToLoad.Add("distinguishedName")
            $account = $searcher.FindOne()
        }
        catch {
            Write-Log "Could not search for the computer account of '$hostName': $($_.Exception.Message)" -Tag "Warn"
        }
        if ($null -eq $account) {
            Write-Log "No computer account '$hostName$' in this domain - add the license server to 'Terminal Server License Servers' by hand" -Tag "Warn"
            continue
        }

        $accountDn = [string]$account.Properties["distinguishedname"][0]
        if ($members -contains $accountDn) {
            Write-Log "'$hostName' is already in 'Terminal Server License Servers'" -Tag "Info"
            continue
        }

        # One commit per member, same rule as the role groups: the directory refuses a
        # whole write over one bad value, and a shared failure names neither.
        try {
            $null = $groupEntry.Properties["member"].Add($accountDn)
            $groupEntry.CommitChanges()
            Write-Log "Added '$hostName' to 'Terminal Server License Servers'" -Tag "Ok"
        }
        catch {
            Write-Log "Could not add '$hostName' to 'Terminal Server License Servers': $($_.Exception.Message)" -Tag "Warn"
            try { $groupEntry.RefreshCache(@("member")) } catch { Write-Log "Could not re-read the membership" -Tag "Debug" }
        }
    }
}

# ---------------------------[ Workspace name ]---------------------------
# "Work Resources" is Microsoft's default and it is the most visible string this whole
# role produces: the heading on the RD Web page, the name of the connection in Control
# Panel > RemoteApp and Desktop Connections, the feed's name in the Remote Desktop and
# Windows apps, and the Start menu folder subscribed applications land in. One name, per
# DEPLOYMENT rather than per collection, held by the broker and pushed to every RD Web
# Access server from there.
#
# Two dead ends, so nobody re-treads them: RDWAStrings.xml cannot change this string, and
# the WorkspaceName / WorkspaceID keys in RD Web's web.config are 2008 R2 leftovers that
# only apply to a feed with no Connection Broker. Microsoft moved it onto the broker in
# 2012, and Set-RDWorkspace is the whole of the supported surface.
#
# Empty means untouched, the same rule the published name follows: a name nobody typed is
# not this design's to invent. The studio warns about that on Review rather than the run
# guessing at one.
function Set-RdsWorkspaceName {
    param(
        [Parameter(Mandatory)][string]$Fqdn,
        [Parameter(Mandatory)][object]$RemoteDesktop
    )

    $deployment = Get-ConfigValue -InputObject $RemoteDesktop -Name "deployment"
    $wanted = Get-ConfigText -InputObject $deployment -Name "workspaceName"
    if ([string]::IsNullOrWhiteSpace($wanted)) {
        Write-Log "No workspace name in the design - the deployment keeps what it publishes today" -Tag "Info"
        return $true
    }

    if ($null -eq (Get-Command -Name "Set-RDWorkspace" -ErrorAction SilentlyContinue)) {
        Write-Log "Set-RDWorkspace is not available on this machine - the workspace name was not written" -Tag "Warn"
        return $false
    }

    # Read before writing, like every other reconcile here: this runs on every pass and a
    # name that already matches is not worth a write, a log line or a failure.
    $current = ""
    try {
        $workspace = Get-RDWorkspace -ConnectionBroker $Fqdn -ErrorAction Stop
        if ($null -ne $workspace) { $current = [string]$workspace.Name }
    }
    catch {
        Write-Log "Could not read the current workspace name: $($_.Exception.Message)" -Tag "Debug"
    }

    if ($current -eq $wanted) {
        Write-Log "The workspace is already called '$wanted'" -Tag "Info"
        return $true
    }

    try {
        Set-RDWorkspace -Name $wanted -ConnectionBroker $Fqdn -ErrorAction Stop
    }
    catch {
        Write-Log "The workspace name could not be set to '$wanted': $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    if ([string]::IsNullOrWhiteSpace($current)) {
        Write-Log "Workspace name set to '$wanted'" -Tag "Ok"
    }
    else {
        Write-Log "Workspace name set to '$wanted' (was '$current')" -Tag "Ok"
    }
    # Said out loud because it is the one part of this that is not instant: a client that
    # already subscribed keeps the old name until its feed refreshes.
    Write-Log "    The RD Web heading changes at once; a client that already subscribed picks it up at its next feed refresh" -Tag "Debug"
    return $true
}

# ---------------------------[ Published name ]---------------------------
function Set-RdsPublishedName {
    param(
        [Parameter(Mandatory)][string]$Fqdn,
        [Parameter(Mandatory)][object]$RemoteDesktop
    )

    $publishedName = Get-ConfigValue -InputObject $RemoteDesktop -Name "publishedName"
    if ($null -eq $publishedName) { return $true }
    if (-not [bool](Get-ConfigValue -InputObject $publishedName -Name "manage" -Default $false)) {
        Write-Log "The published name is left as the deployment set it" -Tag "Info"
        return $true
    }

    $wanted = Get-ConfigText -InputObject $publishedName -Name "clientAccessName"
    if ([string]::IsNullOrWhiteSpace($wanted)) {
        Write-Log "publishedName.manage is on but clientAccessName is empty - leaving the name alone" -Tag "Info"
        return $true
    }

    # A single-broker deployment already publishes the broker's own name: that is what
    # New-RDSessionDeployment set and what every .rdp file carries. Writing it again
    # changes nothing and can only fail, so this is the common case and it exits here.
    # The setting exists for the other one - a name that is not this server's, an alias
    # or a load-balanced pair, which is what the certificate then has to carry.
    if ($wanted -eq $Fqdn) {
        Write-Log "The deployment publishes its own name '$Fqdn' already - nothing to change" -Tag "Info"
        return $true
    }

    # Get/Set-RDPublishedName never shipped in the RemoteDesktop module - they are the
    # names of a community script that predates 2016, and calling them here failed the
    # whole role with 'not recognized'. The module cmdlet is Set-RDClientAccessName;
    # what both actually move is one string on the broker, DeploymentRedirectorServer
    # in root/CIMV2/rdms, which is the fallback for a build without the cmdlet.
    $current = ""
    try {
        # The WMI property first: the cmdlets only serve a high-availability broker,
        # and on a single one they refuse rather than answer.
        #
        # Win32_RDMSDeploymentSettings declares no properties, so it has no instances -
        # Get-CimInstance comes back empty rather than failing, and the -InputObject
        # that followed then bound $null and took the whole step down with an error
        # naming a parameter instead of the cause. Both methods are static, so they are
        # called on the class. The argument is 'Key', not 'PropertyName' (MS-DTYP:
        # GetStringProperty(Key, out Value) / SetStringProperty(Key, Value)).
        $reply = Invoke-CimMethod -Namespace "root/CIMV2/rdms" -ClassName "Win32_RDMSDeploymentSettings" `
            -MethodName "GetStringProperty" -Arguments @{ Key = "DeploymentRedirectorServer" } -ErrorAction Stop
        $current = [string]$reply.Value
    }
    catch {
        Write-Log "Could not read the current published name: $($_.Exception.Message)" -Tag "Debug"
    }

    if ($current -eq $wanted) {
        Write-Log "The deployment already publishes '$wanted'" -Tag "Info"
        return $true
    }

    Write-Log "Publishing '$wanted' (was '$current')" -Tag "Run"
    try {
        $cmdletFailure = $null
        if (Get-Command -Name "Set-RDClientAccessName" -ErrorAction SilentlyContinue) {
            # The cmdlet only serves a broker configured for high availability - on a
            # single broker it refuses with exactly that message. The WMI property is
            # what the deployment actually stores either way, so the refusal is a
            # routing decision, not a failure.
            try {
                Set-RDClientAccessName -ConnectionBroker $Fqdn -ClientAccessName $wanted -ErrorAction Stop | Out-Null
            }
            catch {
                if ($_.Exception.Message -notmatch "high availability") { throw }
                $cmdletFailure = $_.Exception.Message
                Write-Log "Set-RDClientAccessName serves only a high-availability broker - writing the deployment setting directly" -Tag "Debug"
            }
        }
        else {
            $cmdletFailure = "the cmdlet is not on this build"
        }

        if ($null -ne $cmdletFailure) {
            $reply = Invoke-CimMethod -Namespace "root/CIMV2/rdms" -ClassName "Win32_RDMSDeploymentSettings" `
                -MethodName "SetStringProperty" -Arguments @{ Key = "DeploymentRedirectorServer"; Value = $wanted } -ErrorAction Stop
            # The method reports failure in its return value rather than by throwing.
            if ($null -ne $reply -and $null -ne $reply.ReturnValue -and [int]$reply.ReturnValue -ne 0) {
                throw "SetStringProperty returned $($reply.ReturnValue)"
            }
        }
    }
    catch {
        # Not worth failing the role: the deployment works under the broker's own name,
        # the certificate just does not match what the .rdp files say until this lands.
        Write-Log "Could not set the published name: $($_.Exception.Message)" -Tag "Error"
        Write-Log "Set it by hand on the broker: Set-RDClientAccessName -ConnectionBroker $Fqdn -ClientAccessName $wanted" -Tag "Info"
        return $false
    }
    Write-Log "Published name set - every .rdp file this deployment hands out carries it" -Tag "Ok"
    return $true
}

# ---------------------------[ Deployment certificate ]---------------------------
# What clients see: the web page, and the signature on the .rdp file. Set-RDCertificate
# takes either a thumbprint or a PFX depending on the build, so which one is used is
# read off the cmdlet rather than assumed.
# A PFX for a certificate that is already in this machine's store, so the deployment can
# hand it to a server that is not this machine. Set-RDCertificate -Thumbprint requires
# the certificate to be present in LocalMachine\My on EVERY server holding that role -
# with RD Web Access on its own box that is a machine the broker never wrote to, and the
# bind reports success while the portal serves something else entirely.
function Export-RdsCertificatePfx {
    param(
        [Parameter(Mandatory)][string]$Thumbprint,
        [Parameter(Mandatory)][System.Security.SecureString]$Password
    )

    $certificate = Get-Item -Path ("Cert:\LocalMachine\My\" + $Thumbprint) -ErrorAction Stop

    # Queried, never assumed - a service account with no TEMP would take Join-Path down
    # with it, and this is the step that carries a private key.
    $base = [string]$env:TEMP
    if ([string]::IsNullOrWhiteSpace($base)) {
        $base = [string]$env:SystemDrive
        if ([string]::IsNullOrWhiteSpace($base)) { $base = "C:" }
        $base = Join-Path -Path $base -ChildPath "Windows\Temp"
    }
    $folder = Join-Path -Path $base -ChildPath "studio-rds"
    if (-not (Test-Path -LiteralPath $folder)) { $null = New-Item -Path $folder -ItemType Directory -Force }
    $path = Join-Path -Path $folder -ChildPath ($Thumbprint + ".pfx")

    $null = Export-PfxCertificate -Cert $certificate -FilePath $path -Password $Password -Force -ErrorAction Stop
    return $path
}

function Set-RdsDeploymentCertificate {
    param(
        [Parameter(Mandatory)][string]$Fqdn,
        [Parameter(Mandatory)][object]$Certificate,
        [Parameter(Mandatory)][string]$Thumbprint,
        # The role's servers are not this machine, so the certificate has to travel as a
        # file rather than as a thumbprint nobody there can resolve.
        [switch]$Distribute
    )

    $roles = @(Get-ConfigArray -InputObject $Certificate -Name "roles" |
        ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($roles.Count -eq 0) {
        Write-Log "No deployment role is set to use the certificate - nothing to bind" -Tag "Info"
        return $true
    }

    $command = Get-Command -Name "Set-RDCertificate" -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        Write-Log "Set-RDCertificate is unavailable - the RemoteDesktop module is not the one that ships with the deployment" -Tag "Error"
        return $false
    }
    if (-not $command.Parameters.ContainsKey("Thumbprint")) {
        Write-Log "This build of Set-RDCertificate takes a PFX rather than a thumbprint - bind the certificate by hand:" -Tag "Error"
        foreach ($role in $roles) {
            Write-Log "    Set-RDCertificate -Role $role -ImportPath <pfx> -Password <secure> -ConnectionBroker $Fqdn -Force" -Tag "Error"
        }
        return $false
    }

    # Which roles still need this certificate, asked before anything is exported: a run
    # that changes nothing must not write a PFX to disk to find that out.
    $pending = @()
    foreach ($role in $roles) {
        $current = $null
        try {
            $current = Get-RDCertificate -Role $role -ConnectionBroker $Fqdn -ErrorAction Stop
        }
        catch {
            Write-Log "Could not read the current $role certificate: $($_.Exception.Message)" -Tag "Debug"
        }

        if (($null -ne $current) -and ([string]$current.Thumbprint -eq $Thumbprint.ToUpperInvariant())) {
            Write-Log "$role already serves $Thumbprint" -Tag "Info"
            continue
        }
        $pending += $role
    }
    if ($pending.Count -eq 0) { return $true }

    $pfxPath = ""
    $pfxPassword = $null
    $temporary = $false
    if ($Distribute) {
        # A PFX the design already staged is used as it is - it is the same certificate,
        # and re-exporting one only asks the key to be exportable for nothing.
        $source = Get-ConfigText -InputObject $Certificate -Name "source" -Default "leave"
        $stagedPath = Get-ConfigText -InputObject $Certificate -Name "pfxPath"
        $stagedPlain = Get-ConfigText -InputObject $Certificate -Name "pfxPassword"
        if (($source -eq "pfx") -and (-not [string]::IsNullOrWhiteSpace($stagedPath)) -and (Test-Path -LiteralPath $stagedPath)) {
            $pfxPath = $stagedPath
            $pfxPassword = New-Object System.Security.SecureString
            if (-not [string]::IsNullOrWhiteSpace($stagedPlain)) {
                $pfxPassword = ConvertTo-SecureString -String $stagedPlain -AsPlainText -Force
            }
        }
        else {
            # The same generator the ACME path uses for its own staging PFX.
            $plain = New-StudioPfxPassword
            $pfxPassword = ConvertTo-SecureString -String $plain -AsPlainText -Force
            try {
                $pfxPath = Export-RdsCertificatePfx -Thumbprint $Thumbprint -Password $pfxPassword
                $temporary = $true
            }
            catch {
                Write-Log "The certificate could not be exported for distribution: $($_.Exception.Message)" -Tag "Error"
                Write-Log "    Its private key is not exportable. From an internal CA that is the template's" -Tag "Error"
                Write-Log "    'Allow private key to be exported'; for a certificate placed by hand, re-import it as exportable." -Tag "Error"
                foreach ($role in $pending) {
                    Write-Log "    Set-RDCertificate -Role $role -ImportPath <pfx> -Password <secure> -ConnectionBroker $Fqdn -Force" -Tag "Error"
                }
                return $false
            }
        }
    }

    $allBound = $true
    try {
        foreach ($role in $pending) {
            Write-Log "Binding $Thumbprint to $role" -Tag "Run"
            try {
                if ($Distribute) {
                    # The cmdlet copies it to every server holding the role. That is the
                    # whole reason this path exists.
                    Set-RDCertificate -Role $role -ImportPath $pfxPath -Password $pfxPassword `
                        -ConnectionBroker $Fqdn -Force -ErrorAction Stop | Out-Null
                }
                else {
                    Set-RDCertificate -Role $role -Thumbprint $Thumbprint -ConnectionBroker $Fqdn -Force -ErrorAction Stop | Out-Null
                }
                Write-Log "$role bound" -Tag "Ok"
            }
            catch {
                Write-Log "Could not bind $role : $($_.Exception.Message)" -Tag "Error"
                $allBound = $false
            }
        }
    }
    finally {
        # The key does not stay on disk a moment longer than the bind needs it.
        if ($temporary -and (Test-Path -LiteralPath $pfxPath)) {
            try { Remove-Item -LiteralPath $pfxPath -Force -ErrorAction Stop }
            catch { Write-Log "Could not remove the temporary PFX '$pfxPath'" -Tag "Warn" }
        }
    }
    return $allBound
}

# Both certificate blocks a design can carry, resolved and bound. One in a quick session
# and with the portal on the broker; two once RD Web Access has its own machine, because
# a certificate cannot be in two stores at once.
function Set-RdsCertificateSet {
    param(
        [Parameter(Mandatory)][string]$Fqdn,
        [Parameter(Mandatory)][object]$RemoteDesktop,
        [Parameter(Mandatory)][object]$Topology
    )

    $failures = @()
    $blocks = @()
    $blocks += [PSCustomObject]@{
        Label       = "deployment"
        Certificate = Get-ConfigValue -InputObject $RemoteDesktop -Name "certificate"
        Distribute  = $false
    }
    $webCertificate = Get-ConfigValue -InputObject $RemoteDesktop -Name "webAccessCertificate"
    if ($null -ne $webCertificate) {
        $blocks += [PSCustomObject]@{
            Label       = "web access"
            Certificate = $webCertificate
            Distribute  = $true
        }
    }
    elseif ($Topology.WebSeparate) {
        # The studio refuses to export this, so it means a hand-written config.
        Write-Log "RD Web Access runs on '$($Topology.WebAccess)' but the design carries no certificate for it" -Tag "Warn"
        Write-Log "    The portal will serve whatever certificate is on that machine already - usually a self-signed one" -Tag "Warn"
    }

    foreach ($block in $blocks) {
        if ($null -eq $block.Certificate) { continue }
        $thumbprint = ""
        try {
            $thumbprint = Resolve-StudioCertificate -Certificate $block.Certificate
        }
        catch {
            Write-Log "The $($block.Label) certificate could not be obtained: $($_.Exception.Message)" -Tag "Error"
            $failures += "the $($block.Label) certificate was not obtained"
            continue
        }
        if ([string]::IsNullOrWhiteSpace($thumbprint)) { continue }

        if (-not (Set-RdsDeploymentCertificate -Fqdn $Fqdn -Certificate $block.Certificate `
                -Thumbprint $thumbprint -Distribute:$block.Distribute)) {
            $failures += "the $($block.Label) certificate is in the store but not bound to every role"
        }
    }
    return $failures
}

# ---------------------------[ The portal's own binding ]---------------------------
# Set-RDCertificate tells the DEPLOYMENT which certificate RD Web Access should serve. It
# does not reliably move the IIS HTTPS binding underneath it, which is why "I renewed it
# and the web page still shows the old certificate" is the most common RDS certificate
# call there is. The deployment is right and the binding is stale, and every field guide
# ends with the same manual step: rebind Default Web Site on 443.
#
# So the machine that HOLDS RD Web Access rebinds it - and only that machine can, because
# an IIS binding is local. On a quick session that is the machine running this; in a farm
# with its own portal it is that server's own run and its own nightly task, working from
# the certificate the deployment already distributed into its store.
function Get-RdsWebAccessThumbprint {
    param([Parameter(Mandatory)][string]$Fqdn)

    try {
        $current = Get-RDCertificate -Role "RDWebAccess" -ConnectionBroker $Fqdn -ErrorAction Stop
        if ($null -ne $current) { return ([string]$current.Thumbprint).Replace(" ", "").ToUpperInvariant() }
    }
    catch {
        Write-Log "Could not read the certificate the deployment publishes for RD Web Access: $($_.Exception.Message)" -Tag "Debug"
    }
    return ""
}

function Set-RdsWebBinding {
    param(
        [Parameter(Mandatory)][string]$Thumbprint,
        [string]$SiteName = "Default Web Site",
        [int]$Port = 443
    )

    $wanted = $Thumbprint.Replace(" ", "").ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($wanted)) { return $true }

    if ($null -eq (Get-Item -Path ("Cert:\LocalMachine\My\" + $wanted) -ErrorAction SilentlyContinue)) {
        Write-Log "The deployment publishes $wanted for RD Web Access, and it is not in this machine's store" -Tag "Warn"
        Write-Log "    The broker distributes it when it binds the certificate - run the config there first" -Tag "Info"
        return $false
    }

    if (-not (Get-Command -Name "Get-WebBinding" -ErrorAction SilentlyContinue)) {
        try { Import-Module -Name "WebAdministration" -ErrorAction Stop }
        catch {
            Write-Log "The WebAdministration module is not available, so the RD Web binding cannot be checked" -Tag "Warn"
            Write-Log "    Bind $wanted to '$SiteName' on port $Port in IIS Manager" -Tag "Info"
            return $false
        }
    }

    $binding = $null
    try {
        $binding = Get-WebBinding -Name $SiteName -Port $Port -Protocol "https" -ErrorAction Stop
    }
    catch {
        Write-Log "Could not read the '$SiteName' HTTPS binding: $($_.Exception.Message)" -Tag "Warn"
    }
    if ($null -eq $binding) {
        Write-Log "'$SiteName' has no HTTPS binding on port $Port - RD Web Access is reached over one, so this is worth a look" -Tag "Warn"
        return $false
    }

    $current = ([string]$binding.certificateHash).Replace(" ", "").ToUpperInvariant()
    if ($current -eq $wanted) {
        Write-Log "The RD Web binding already serves $wanted" -Tag "Info"
        return $true
    }

    Write-Log "Rebinding '$SiteName' on port $Port to $wanted (was $(if ($current) { $current } else { 'nothing' }))" -Tag "Run"
    try {
        $binding.AddSslCertificate($wanted, "My")
        Write-Log "The RD Web page serves the deployment's certificate now" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "The RD Web binding could not be moved: $($_.Exception.Message)" -Tag "Error"
        Write-Log "    Bind $wanted to '$SiteName' on port $Port in IIS Manager" -Tag "Error"
        return $false
    }
}

# Which block of the design covers RD Web Access, and what it says to do about it. A
# design that leaves the certificate alone leaves the BINDING alone too - otherwise a run
# would take a portal somebody bound by hand and point it at whatever the deployment
# happens to publish, which on a fresh deployment is its own self-signed certificate.
# Downgrading a working page is not a repair.
function Get-RdsWebAccessCertificateSource {
    param(
        [Parameter(Mandatory)][object]$RemoteDesktop,
        [Parameter(Mandatory)][object]$Topology
    )

    if ($Topology.WebSeparate) {
        $web = Get-ConfigValue -InputObject $RemoteDesktop -Name "webAccessCertificate"
        if ($null -eq $web) { return "leave" }
        return (Get-ConfigText -InputObject $web -Name "source" -Default "leave")
    }

    $certificate = Get-ConfigValue -InputObject $RemoteDesktop -Name "certificate"
    if ($null -eq $certificate) { return "leave" }
    $roles = @(Get-ConfigArray -InputObject $certificate -Name "roles" | ForEach-Object { [string]$_ })
    # A deployment certificate that is not bound to RDWebAccess says nothing about the
    # portal, whatever its source is.
    if (($roles.Count -gt 0) -and ($roles -notcontains "RDWebAccess")) { return "leave" }
    return (Get-ConfigText -InputObject $certificate -Name "source" -Default "leave")
}

# The whole step, for whichever machine holds the portal: what does the deployment say,
# and does IIS agree with it.
function Sync-RdsWebBinding {
    param(
        [Parameter(Mandatory)][string]$Fqdn,
        [Parameter(Mandatory)][object]$Topology,
        [Parameter(Mandatory)][string[]]$Part,
        [Parameter(Mandatory)][object]$RemoteDesktop
    )

    if ($Part -notcontains "webAccess") {
        if ($Topology.WebSeparate) {
            Write-Log "RD Web Access runs on '$($Topology.WebAccess)' - refreshed by that machine's own run" -Tag "Info"
        }
        return $true
    }

    $source = Get-RdsWebAccessCertificateSource -RemoteDesktop $RemoteDesktop -Topology $Topology
    if ($source -eq "leave") {
        Write-Log "The RD Web certificate is left alone in this design, so its IIS binding is too" -Tag "Info"
        return $true
    }

    $thumbprint = Get-RdsWebAccessThumbprint -Fqdn $Fqdn
    if ([string]::IsNullOrWhiteSpace($thumbprint)) {
        Write-Log "The deployment publishes no certificate for RD Web Access - nothing to bind" -Tag "Info"
        return $true
    }
    return (Set-RdsWebBinding -Thumbprint $thumbprint)
}

# The RDP listener's own certificate is deliberately not handled here any more. It is
# Group Policy's job: the AD CS design creates the 'Certificate - Remote Desktop
# Authentication' policy objects, which point every session host at the template
# (Remote Desktop Session Host > Security > Server authentication certificate template)
# and let autoenrollment keep the certificate renewed. A per-host enrollment writing
# Win32_TSGeneralSetting.SSLCertificateSHA1Hash - which is what used to live here -
# produces the same listener state once, and then fights the policy for it forever.

# ---------------------------[ RemoteApp ]---------------------------
function Set-RdsRemoteApp {
    param(
        [Parameter(Mandatory)][string]$Fqdn,
        [Parameter(Mandatory)][string]$CollectionName,
        [Parameter(Mandatory)][object]$RemoteDesktop,
        # On a quick session this machine IS the session host, so a missing executable is
        # checkable before the broker tries to read an icon out of it. On a farm the
        # broker publishes for hosts it is not, and checking ITS OWN disk would refuse
        # every legitimate application - a Server Core broker holds none of them.
        [switch]$PathOnAnotherMachine
    )

    $remoteApps = Get-ConfigValue -InputObject $RemoteDesktop -Name "remoteApps"
    if ($null -eq $remoteApps) { return @() }
    if (-not [bool](Get-ConfigValue -InputObject $remoteApps -Name "enabled" -Default $false)) {
        Write-Log "No application is published - the collection offers a full desktop" -Tag "Info"
        return @()
    }

    $items = @(Get-ConfigArray -InputObject $remoteApps -Name "items")
    if ($items.Count -eq 0) {
        Write-Log "remoteApps.enabled is true but the list is empty - the collection keeps its desktop" -Tag "Info"
        return @()
    }
    $failed = @()

    $existing = @()
    try {
        $existing = @(Get-RDRemoteApp -CollectionName $CollectionName -ConnectionBroker $Fqdn -ErrorAction Stop)
    }
    catch {
        Write-Log "Could not list the published applications: $($_.Exception.Message)" -Tag "Debug"
    }

    foreach ($item in $items) {
        $displayName = Get-ConfigText -InputObject $item -Name "displayName"
        $filePath    = Get-ConfigText -InputObject $item -Name "filePath"
        $alias       = Get-ConfigText -InputObject $item -Name "alias"
        if ([string]::IsNullOrWhiteSpace($displayName) -or [string]::IsNullOrWhiteSpace($filePath)) { continue }
        if ([string]::IsNullOrWhiteSpace($alias)) { $alias = ($displayName -replace "[^A-Za-z0-9]", "") }

        # This machine is the session host, so the path is checkable before the broker
        # tries to read an icon out of it. WordPad is the reason this exists: removed
        # from Windows entirely in Server 2024+, and publishing it failed the whole
        # role over a missing icon on an executable that is not coming back. In a farm
        # the path lives on the session hosts and this disk says nothing about it - the
        # per-application catch below is what reports a genuinely missing one there.
        if ((-not $PathOnAnotherMachine) -and (-not (Test-Path -LiteralPath $filePath))) {
            Write-Log "'$displayName' is not at '$filePath' on this session host - not published" -Tag "Error"
            $failed += $displayName
            continue
        }

        $parameters = @{
            CollectionName   = $CollectionName
            ConnectionBroker = $Fqdn
            Alias            = $alias
            DisplayName      = $displayName
            FilePath         = $filePath
            ShowInWebAccess  = [bool](Get-ConfigValue -InputObject $item -Name "showInWebAccess" -Default $true)
            ErrorAction      = "Stop"
        }

        $commandLine = Get-ConfigText -InputObject $item -Name "commandLineSetting" -Default "DoNotAllow"
        $parameters["CommandLineSetting"] = $commandLine
        if ($commandLine -eq "Require") {
            $parameters["RequiredCommandLine"] = Get-ConfigText -InputObject $item -Name "requiredCommandLine"
        }

        # The alias is the key, so an application that is already there is updated
        # rather than published twice under two names.
        $isPublished = @($existing | Where-Object { [string]$_.Alias -eq $alias }).Count -gt 0
        try {
            if ($isPublished) {
                Write-Log "Updating the published application '$displayName'" -Tag "Run"
                Set-RDRemoteApp @parameters | Out-Null
            }
            else {
                Write-Log "Publishing '$displayName'" -Tag "Run"
                New-RDRemoteApp @parameters | Out-Null
            }
        }
        catch {
            # One application that will not publish is that application's problem, not
            # the deployment's - everything else in the list still belongs on the feed.
            Write-Log "Could not publish '$displayName': $($_.Exception.Message)" -Tag "Error"
            $failed += $displayName
        }
    }

    if ($failed.Count -eq 0) {
        Write-Log "Published applications applied - the collection no longer offers a full desktop" -Tag "Ok"
    }
    else {
        Write-Log "$($failed.Count) of $($items.Count) application(s) were not published: $($failed -join ', ')" -Tag "Error"
    }
    return $failed
}

# ---------------------------[ The desktop on the portal ]---------------------------
# The watchdog's task name. Fixed rather than composed the way the certificate task's
# is: that one is named after whichever certificates the server happens to hold, and
# this one always does exactly the same job, so there is nothing for the name to vary
# on - and a fixed name is what lets the next run find the task the last one wrote.
$script:rdsPortalTaskName = "Remote Desktop Portal - Desktop publication"

# Puts the full desktop back on the portal beside the published applications. There is
# no supported way to publish both from one collection since Server 2012 - the feed
# hides the desktop the moment the first application is published - and the way every
# field guide puts it back is the collection's ShowInPortal registry value on the
# broker. Windows resets that value to 0 on a broker restart and on any change to the
# collection or its applications, so this runs on every configuration run rather than
# once: a re-run is how the design is re-asserted, here like everywhere else.
#
# It returns a result object rather than a boolean because two callers ask different
# questions of it. A configuration run wants "did this work"; the hourly watchdog wants
# "did you have to change anything", which is the whole basis of whether a mail goes
# out. One implementation answers both - the task is not a second copy of this logic.
function Set-RdsDesktopInPortal {
    param(
        [Parameter(Mandatory)][string]$CollectionName,
        [Parameter(Mandatory)][object]$RemoteDesktop
    )

    # Managed says the design asks for this value at all; Changed says this call wrote
    # it. Both are false on every path that decides there is nothing to assert, which is
    # what keeps "nothing to do" from ever looking like a repair.
    $result = [pscustomobject]@{
        Ok      = $true
        Managed = $false
        Changed = $false
        Alias   = ""
        Reason  = ""
    }

    $remoteApps = Get-ConfigValue -InputObject $RemoteDesktop -Name "remoteApps"
    if (-not [bool](Get-ConfigValue -InputObject $remoteApps -Name "enabled" -Default $false)) {
        $result.Reason = "this collection publishes a full desktop, so it is on the feed already"
        return $result
    }
    if (-not [bool](Get-ConfigValue -InputObject $remoteApps -Name "showDesktopInPortal" -Default $false)) {
        # Off means unmanaged, not "hide it": hidden is what Windows itself reverts to,
        # and a value somebody set by hand is not this design's to clear.
        $result.Reason = "the design does not ask for the desktop on the portal"
        return $result
    }
    if (@(Get-ConfigArray -InputObject $remoteApps -Name "items").Count -eq 0) {
        # With nothing published the desktop is on the feed anyway - the value would
        # assert something that is already true for a different reason.
        $result.Reason = "nothing is published, so the desktop is on the feed anyway"
        return $result
    }

    $result.Managed = $true

    # The key under CentralPublishedResources is the collection's *alias* - truncated
    # and underscored ("Remote Desktop Services" becomes "Remote_Desktop_S") - so it is
    # read from the deployment rather than derived from the name.
    $alias = ""
    try {
        $collection = @(Get-CimInstance -Namespace "root/CIMV2/rdms" -ClassName "Win32_RDSHCollection" -ErrorAction Stop |
            Where-Object { [string]$_.Name -eq $CollectionName })
        if ($collection.Count -gt 0) { $alias = [string]$collection[0].Alias }
    }
    catch {
        Write-Log "The collection alias could not be read from the deployment: $($_.Exception.Message)" -Tag "Debug"
    }
    if ([string]::IsNullOrWhiteSpace($alias)) {
        Write-Log "No collection named '$CollectionName' answered with an alias - the desktop cannot be put on the portal" -Tag "Error"
        $result.Ok     = $false
        $result.Reason = "no collection named '$CollectionName' answered with an alias"
        return $result
    }
    $result.Alias = $alias

    $key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\CentralPublishedResources\PublishedFarms\$alias\RemoteDesktops\$alias"
    if (-not (Test-Path -LiteralPath $key)) {
        Write-Log "The collection '$alias' has no published-desktop key yet - it appears when the applications publish" -Tag "Error"
        $result.Ok     = $false
        $result.Reason = "the collection '$alias' has no published-desktop key yet"
        return $result
    }

    $current = 0
    try { $current = [int](Get-ItemProperty -LiteralPath $key -ErrorAction Stop).ShowInPortal } catch { $current = 0 }
    if ($current -eq 1) {
        Write-Log "The full desktop is already on the portal beside the published applications" -Tag "Info"
        $result.Reason = "the value was already set"
        return $result
    }

    try {
        Set-ItemProperty -LiteralPath $key -Name "ShowInPortal" -Value 1 -Type DWord -ErrorAction Stop
    }
    catch {
        Write-Log "ShowInPortal could not be written on '$alias': $($_.Exception.Message)" -Tag "Error"
        $result.Ok     = $false
        $result.Reason = "ShowInPortal could not be written on '$alias': $($_.Exception.Message)"
        return $result
    }
    Write-Log "The full desktop is back on the portal (ShowInPortal)" -Tag "Ok"
    Write-Log "    Windows clears this on a broker restart or a collection change - a re-run puts it back" -Tag "Debug"
    $result.Changed = $true
    $result.Reason  = "the value had been cleared and was written back"
    return $result
}

# ---------------------------[ The portal watchdog ]---------------------------
# Every run re-asserts ShowInPortal, and between runs Windows takes it away again: a
# broker restart, a RemoteApp change, any collection settings change. On a deployment
# that is configured once and then left alone that means the desktop quietly leaves the
# feed and stays gone until somebody re-runs the studio's script. The watchdog is that
# re-run, on a schedule, over this one value.
function Get-RdsPortalWatchdog {
    param([object]$RemoteDesktop)

    $remoteApps = Get-ConfigValue -InputObject $RemoteDesktop -Name "remoteApps"
    if ($null -eq $remoteApps) { return $null }
    return (Get-ConfigValue -InputObject $remoteApps -Name "portalWatchdog")
}

# Asked of the design, never of the machine. A watchdog over a value this design does
# not write would spend every hour repairing a decision somebody else made by hand -
# which is the same rule that makes showDesktopInPortal itself opt-in.
function Test-RdsPortalWatchdogWanted {
    param([object]$RemoteDesktop)

    $watchdog = Get-RdsPortalWatchdog -RemoteDesktop $RemoteDesktop
    if ($null -eq $watchdog) { return $false }
    if (-not [bool](Get-ConfigValue -InputObject $watchdog -Name "enabled" -Default $false)) { return $false }

    $remoteApps = Get-ConfigValue -InputObject $RemoteDesktop -Name "remoteApps"
    if (-not [bool](Get-ConfigValue -InputObject $remoteApps -Name "enabled" -Default $false)) { return $false }
    return [bool](Get-ConfigValue -InputObject $remoteApps -Name "showDesktopInPortal" -Default $false)
}

function Unregister-RdsPortalTask {
    param([switch]$Quiet)

    if (-not (Get-Command -Name "Unregister-ScheduledTask" -ErrorAction SilentlyContinue)) { return }

    $existing = Get-ScheduledTask -TaskName $script:rdsPortalTaskName -ErrorAction SilentlyContinue
    if ($null -eq $existing) { return }

    try {
        Unregister-ScheduledTask -TaskName $script:rdsPortalTaskName -Confirm:$false -ErrorAction Stop
        if (-not $Quiet) {
            Write-Log "Removed '$($script:rdsPortalTaskName)'" -Tag "Ok"
        }
    }
    catch {
        Write-Log "Could not remove '$($script:rdsPortalTaskName)': $($_.Exception.Message)" -Tag "Info"
    }
}

function Register-RdsPortalTask {
    param(
        [Parameter(Mandatory)][object]$Config,
        [Parameter(Mandatory)][object]$RemoteDesktop,
        [string]$ConfigFilePath
    )

    if (-not (Test-RdsPortalWatchdogWanted -RemoteDesktop $RemoteDesktop)) {
        Unregister-RdsPortalTask
        return $true
    }

    if (-not (Get-Command -Name "Register-ScheduledTask" -ErrorAction SilentlyContinue)) {
        Write-Log "The ScheduledTasks module is unavailable - nothing will keep the desktop on the portal between runs" -Tag "Error"
        return $false
    }

    $watchdog = Get-RdsPortalWatchdog -RemoteDesktop $RemoteDesktop
    # A floor rather than a free number: the value only changes when Windows takes it
    # away, and a five-minute poll would be a scheduled task running 288 times a day to
    # catch an event that happens after a reboot.
    $interval = [int](Get-ConfigValue -InputObject $watchdog -Name "intervalMinutes" -Default 60)
    if ($interval -lt 15)   { $interval = 15 }
    if ($interval -gt 1440) { $interval = 1440 }

    # Shared with the certificate task on purpose: one staged copy of the script, one
    # folder to find when something has to be run by hand.
    $deployDirectory = Get-StudioDeployDirectory -RenewalTask (Get-CertificateTaskSection -Config $Config)

    try {
        # The task must not depend on wherever this run happened to be started from - a
        # share, a USB stick, a folder somebody tidies up next week.
        # Five parts, not twenty-seven: the preamble, this file and the mail report.
        # The action names them, so what is staged and what is loaded are one decision.
        $taskPart       = @(Get-StudioTaskPart -Task "RdsPortal" -Config $Config)
        $deployment     = Copy-StudioDeployment -DeployDirectory $deployDirectory -ConfigFilePath $ConfigFilePath -Part $taskPart
        $deployedScript = [string]$deployment.ScriptPath
        $deployedConfig = [string]$deployment.ConfigPath

        $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -ConfigPath "{1}" -Task RdsPortal -NoGui -Part "{2}"' -f `
            $deployedScript, $deployedConfig, ($taskPart -join ",")

        Unregister-RdsPortalTask -Quiet

        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arguments -WorkingDirectory $deployDirectory

        # Two triggers, and the startup one carries a delay for a reason that costs a
        # false alarm every reboot without it: at machine start tssdis is not up yet,
        # root/CIMV2/rdms does not answer, and the key the value lives under has not been
        # repopulated - so a watchdog that ran at T+0 would find nothing and report a
        # failure on every single boot. Five minutes, and the task itself retries.
        $startupTrigger = New-ScheduledTaskTrigger -AtStartup
        $startupTrigger.Delay = "PT5M"

        # -RepetitionDuration is deliberately not passed. A trigger whose XML carries no
        # Duration repeats indefinitely, which is what this wants; [TimeSpan]::MaxValue -
        # the value usually reached for - serialises to P10675199DT2H48M5.4775807S, which
        # some builds reject outright as an incorrectly formatted value.
        $repeatTrigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(5)) `
            -RepetitionInterval (New-TimeSpan -Minutes $interval)

        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        # IgnoreNew rather than the default: a run that is still retrying a key that has
        # not appeared yet must not be joined by the next hour's.
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 15)

        $null = Register-ScheduledTask -TaskName $script:rdsPortalTaskName -Action $action `
            -Trigger @($startupTrigger, $repeatTrigger) -Principal $principal -Settings $settings `
            -Description "Windows Server Role Studio - keeps the full desktop on the RD Web feed beside the published applications" `
            -ErrorAction Stop
    }
    catch {
        Write-Log "Could not register '$($script:rdsPortalTaskName)': $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    Write-Log "Registered '$($script:rdsPortalTaskName)' - every $interval minute(s) and 5 minutes after each start, as SYSTEM" -Tag "Ok"
    return $true
}

# What that task runs. Same function the configuration run calls, so a repair is not a
# second implementation of the same registry write - and the exit code is the task's,
# which is what makes a failure visible in Task Scheduler as well as in the mail.
function Invoke-RdsPortalTask {
    param([object]$Config)

    $rds = Get-ConfigValue -InputObject $Config -Name "remoteDesktop"
    if ($null -eq $rds) {
        Write-Log "This config has no remoteDesktop section - the portal watchdog has nothing to watch" -Tag "Info"
        return 0
    }
    if (-not (Test-RdsPortalWatchdogWanted -RemoteDesktop $rds)) {
        Write-Log "The design no longer keeps the desktop on the portal - this task can be removed" -Tag "Info"
        return 0
    }

    # The same config reaches every machine in the farm, and this value is the broker's
    # alone. A machine that stopped being the broker stops writing it rather than
    # writing it somewhere it means nothing.
    $topology = Get-RdsTopology -RemoteDesktop $rds
    $parts    = @(Get-RdsFarmPart -Topology $topology)
    if ($parts -notcontains "broker") {
        Write-Log "This machine is not the connection broker in this design - nothing here holds that value" -Tag "Info"
        return 0
    }

    $collectionName = $topology.CollectionName

    # Three attempts a minute apart, for the startup run: the delay on that trigger
    # covers the usual case and this covers the slow one, on a broker that took longer
    # than five minutes to bring the deployment up. An hourly run that genuinely cannot
    # read the key spends two extra minutes finding that out, which is cheap against
    # reporting a failure that would have cleared itself.
    $attempts = 0
    $result   = $null
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $attempts = $attempt
        $result   = Set-RdsDesktopInPortal -CollectionName $collectionName -RemoteDesktop $rds
        if ($result.Ok) { break }
        if ($attempt -lt 3) {
            Write-Log "Attempt $attempt did not get there - waiting a minute" -Tag "Info"
            Start-Sleep -Seconds 60
        }
    }

    $status = "Current"
    if (-not $result.Ok)     { $status = "Failed" }
    elseif ($result.Changed) { $status = "Repaired" }

    $report = New-RdsPortalReport -Status $status -CollectionName $collectionName -Alias ([string]$result.Alias) `
        -Attempts $attempts -Detail ([string]$result.Reason)
    $null = Send-RdsPortalReport -RemoteDesktop $rds -Report $report

    if ($status -eq "Failed") { return 1 }
    return 0
}

# ---------------------------[ FSLogix policy ]---------------------------
# The domain controller's half of FSLogix. The session host gets the agent; the agent
# does nothing at all until something tells it where containers live, and that something
# is one policy object covering every session host rather than a registry write on each.
#
# Three things about this are deliberate and each one has bitten somebody:
#
#   * The object is created **unlinked**, the same rule the PKI policy objects follow.
#     Where a policy belongs is a decision about an OU layout this design does not
#     describe, so creating one is safe and linking one is not.
#   * The values are re-applied on **every** run, unlike the PKI objects, which are left
#     alone once they exist. The difference is what the object is: those carry a fixed
#     setting nobody edits, this one carries the design - the container path, the size
#     cap, which of the recommendations are on - and re-running with a changed design is
#     precisely how it is meant to be edited.
#   * The values land under HKLM\SOFTWARE\FSLogix, **not** under \Policies. That is where
#     FSLogix's own ADMX writes them, so it is right - but it means they are not policy
#     values: they tattoo. Deleting or unlinking this object does not take them off a
#     machine that already applied it, and switching a setting off in the design stops
#     writing it rather than removing it.
function Set-RdsFsLogixGpo {
    param([Parameter(Mandatory)][object]$RemoteDesktop)

    $fslogix = Get-ConfigValue -InputObject $RemoteDesktop -Name "fslogix"
    if ($null -eq $fslogix) { return $true }
    if (-not [bool](Get-ConfigValue -InputObject $fslogix -Name "enabled" -Default $false)) { return $true }

    $policy = Get-ConfigValue -InputObject $fslogix -Name "groupPolicy"
    if ($null -eq $policy) {
        Write-Log "This config has no remoteDesktop.fslogix.groupPolicy section, so no FSLogix policy object is created" -Tag "Info"
        Write-Log "It was exported before that section existed - re-export the design to pick it up" -Tag "Info"
        return $true
    }
    if (-not [bool](Get-ConfigValue -InputObject $policy -Name "enabled" -Default $false)) {
        Write-Log "The FSLogix policy object is switched off in this design" -Tag "Info"
        return $true
    }

    $name = [string](Get-ConfigText -InputObject $policy -Name "name" -Default "")
    if ([string]::IsNullOrWhiteSpace($name)) {
        Write-Log "remoteDesktop.fslogix.groupPolicy.name is empty - no policy object was created" -Tag "Error"
        return $false
    }

    $values = @(Get-ConfigArray -InputObject $policy -Name "values")
    if ($values.Count -eq 0) {
        Write-Log "The FSLogix policy '$name' carries no registry values - nothing to write" -Tag "Error"
        return $false
    }

    if (-not (Get-Command -Name "New-GPO" -ErrorAction SilentlyContinue)) {
        Write-Log "The GroupPolicy module is not available, so the FSLogix policy was not created" -Tag "Error"
        Write-Log "    Install-WindowsFeature -Name GPMC" -Tag "Error"
        return $false
    }

    $existing = $null
    try { $existing = Get-GPO -Name $name -ErrorAction SilentlyContinue }
    catch { $existing = $null }

    if ($null -eq $existing) {
        Write-Log "Creating the group policy object '$name'" -Tag "Run"
        try {
            $null = New-GPO -Name $name -Comment "Created by Windows Server Role Studio for FSLogix profile containers. Computer settings only." -ErrorAction Stop
        }
        catch {
            Write-Log "Could not create '$name': $($_.Exception.Message)" -Tag "Error"
            return $false
        }
    }
    else {
        Write-Log "'$name' already exists - re-applying the settings this design describes" -Tag "Run"
    }

    $written = 0
    foreach ($value in $values) {
        $key       = [string](Get-ConfigText -InputObject $value -Name "key" -Default "")
        $valueName = [string](Get-ConfigText -InputObject $value -Name "valueName" -Default "")
        $type      = [string](Get-ConfigText -InputObject $value -Name "type" -Default "DWord")
        if ([string]::IsNullOrWhiteSpace($key) -or [string]::IsNullOrWhiteSpace($valueName)) { continue }

        # A DWord arrives from JSON as a number and a String as text; Set-GPRegistryValue
        # wants the matching .NET type, and a string handed to a DWord value fails with an
        # error naming the cmdlet rather than the setting.
        $data = Get-ConfigValue -InputObject $value -Name "data"
        if ($type -eq "DWord") { $data = [int]$data } else { $data = [string]$data }

        try {
            $null = Set-GPRegistryValue -Name $name -Key $key -ValueName $valueName -Type $type -Value $data -ErrorAction Stop
        }
        catch {
            Write-Log "Could not set '$valueName' in '$name': $($_.Exception.Message)" -Tag "Error"
            return $false
        }
        Write-Log "    $key\$valueName = $data" -Tag "Debug"
        $written++
    }

    # Every value here is a computer setting. Leaving the user half enabled costs a pass
    # on every user logon for settings the object does not contain.
    try {
        $gpo = Get-GPO -Name $name -ErrorAction Stop
        $gpo.GpoStatus = "UserSettingsDisabled"
    }
    catch {
        Write-Log "Could not disable the user half of '$name': $($_.Exception.Message)" -Tag "Warn"
    }

    Write-Log "'$name' carries $written FSLogix registry value(s)" -Tag "Ok"

    $filterName = [string](Get-ConfigText -InputObject $policy -Name "wmiFilter" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($filterName)) {
        $aliases = @(Get-ConfigArray -InputObject $policy -Name "wmiFilterAliases")
        Set-StudioGpoWmiFilter -Name $name -FilterName $filterName -Alias $aliases -DomainDn (Get-AdcsDefaultNamingContext)
    }

    # A computer policy, so it is linked where the session hosts are - not where their
    # users are. The WMI filter above narrows what it lands on inside that OU; the link
    # is what puts it in front of them at all.
    $linked = Set-StudioGpoLink -Name $name -TargetDn @(Get-StudioGpoLinkTarget -InputObject $policy -Name "linkTo") `
        -UnlinkedNote "it changes nothing until you link it where the session hosts are"

    Write-Log "    These live under HKLM\SOFTWARE\FSLogix, not a policy key - they stay on a machine that applied them" -Tag "Debug"
    Write-Log "Add fslogix.admx to the central store for GPMC to name them" -Tag "Debug"
    return $linked
}

# ---------------------------[ Reboot ]---------------------------
# The role services are installed before this ever runs, so the usual answer is no.
# Asked anyway, because a session host that owes a restart configures fine and then
# behaves oddly until it gets one.
function Test-RdsRebootPending {
    $keys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    )
    foreach ($key in $keys) {
        if (Test-Path -LiteralPath $key) {
            Write-Log "A restart is already pending on this server ($key)" -Tag "Info"
            return $true
        }
    }
    return $false
}

# ---------------------------[ The namespace, on the domain controller ]---------------------------
# The names clients actually type, written where the zone lives rather than on the
# broker - a member server that would need RSAT and delegated rights to write DNS
# remotely. Same split, and the same reasoning, as the Exchange namespace in
# Set-DnsExchangeRecord and the PKI's publication alias in Set-AdcsPublicationAlias.
#
# This lived nowhere for a while and the run printed the records instead, on the
# grounds that they "live in a zone this design does not own" - the rule the Exchange
# MX and SPF records follow. That rule fits a public-only record and does not fit
# these: the published name is what every domain-joined client resolves *internally*,
# and split DNS is precisely the answer to a name whose parent zone belongs to a
# registrar. Exchange had the machinery for that case since it shipped; Remote Desktop
# simply never had it.
#
# Two things differ from the Exchange path, and both are this design being simpler
# rather than a decision reversed. The names point at **different** machines - the
# portal at the web access server, the published name at the broker - so each record
# carries its own target instead of sharing one address. And every target is a fully
# qualified name the design already states, so nothing is typed twice: Exchange needs
# namespace.ipAddress because a domain controller has never met the Exchange server and
# the config is the only place that answer can come from, while these are machines that
# registered themselves in this very directory when they joined.
function Get-RdsNamespaceRecord {
    param(
        [Parameter(Mandatory)][object]$RemoteDesktop,
        [Parameter(Mandatory)][object]$Topology
    )

    $records = @()

    # The portal's name is the first name on whichever certificate serves RD Web Access,
    # which is the separate block when the portal moved out and the deployment
    # certificate when it did not - the same choice rdsWebFeedName() makes in the studio.
    $portalCertificate = Get-ConfigValue -InputObject $RemoteDesktop -Name "certificate"
    $portalTarget      = $Topology.Broker
    if ($Topology.WebSeparate) {
        $webCertificate = Get-ConfigValue -InputObject $RemoteDesktop -Name "webAccessCertificate"
        if ($null -ne $webCertificate) { $portalCertificate = $webCertificate }
        $portalTarget = $Topology.WebAccess
    }
    $portalName = ""
    $portalNames = @(Get-ConfigArray -InputObject $portalCertificate -Name "dnsNames" | ForEach-Object { [string]$_ })
    if ($portalNames.Count -gt 0) { $portalName = $portalNames[0].Trim().ToLowerInvariant() }
    if (-not [string]::IsNullOrWhiteSpace($portalName)) {
        $records += [PSCustomObject]@{
            Name    = $portalName
            Target  = $portalTarget
            Purpose = "the portal - https://$portalName/RDWeb and the feed URL"
        }
    }

    # The published name is the broker's, always: it is what the .rdp file connects to
    # and the broker is what answers. On a deployment whose portal runs on the broker
    # the two names are usually the same one, and one record is what that needs.
    $publishedBlock = Get-ConfigValue -InputObject $RemoteDesktop -Name "publishedName"
    if ([bool](Get-ConfigValue -InputObject $publishedBlock -Name "manage" -Default $false)) {
        $publishedName = Get-ConfigText -InputObject $publishedBlock -Name "clientAccessName"
        $publishedName = ([string]$publishedName).Trim().ToLowerInvariant()
        if ((-not [string]::IsNullOrWhiteSpace($publishedName)) -and ($publishedName -ne $portalName)) {
            $records += [PSCustomObject]@{
                Name    = $publishedName
                Target  = $Topology.Broker
                Purpose = "the published name - full address:s: in every .rdp file"
            }
        }
    }

    # A name that *is* its own target is the machine's own registration, which it made
    # for itself the day it joined. Creating a second record for it is at best a copy
    # that stops being true the moment the machine changes address.
    return @($records | Where-Object { $_.Name -ne ([string]$_.Target).Trim().ToLowerInvariant() })
}

# The domain controller's third job for this role, beside the access groups and the
# FSLogix policy. Off leaves the names to whoever owns the zone and prints them.
# The record writing itself lives in Role.Dns.ps1 - Set-StudioNamespaceRecord - because
# the SCEP tier needs the same split-DNS shape for its own external name.
function Set-RdsDnsRecord {
    param(
        [Parameter(Mandatory)][object]$RemoteDesktop,
        [Parameter(Mandatory)][object]$Topology
    )

    $dns = Get-ConfigValue -InputObject $RemoteDesktop -Name "dns"
    $records = @(Get-RdsNamespaceRecord -RemoteDesktop $RemoteDesktop -Topology $Topology)

    if (-not [bool](Get-ConfigValue -InputObject $dns -Name "manage" -Default $true)) {
        Write-Log "The design does not write its own DNS records - these have to exist wherever their zones are served:" -Tag "Info"
        foreach ($record in $records) {
            Write-Log "    $($record.Name)  ->  $($record.Target)   ($($record.Purpose))" -Tag "Info"
        }
        return $true
    }
    if ($records.Count -eq 0) {
        Write-Log "Every name this deployment answers on is a machine's own - nothing to create" -Tag "Debug"
        return $true
    }
    if (-not (Get-Command -Name "Get-DnsServerZone" -ErrorAction SilentlyContinue)) {
        Write-Log "The DnsServer module is not available here, so these records have to be created where their zones are served:" -Tag "Warn"
        foreach ($record in $records) {
            Write-Log "    $($record.Name)  ->  $($record.Target)   ($($record.Purpose))" -Tag "Warn"
        }
        return $true
    }

    $zoneMode = Get-ConfigText -InputObject $dns -Name "zoneMode" -Default "pinpoint"
    if (@("none", "pinpoint", "full") -notcontains $zoneMode) { $zoneMode = "pinpoint" }

    Write-Log "Writing the names this deployment answers on - A records" -Tag "Run"
    $allDone = $true
    foreach ($record in $records) {
        $address = Resolve-StudioNamespaceAddress -Fqdn $record.Target
        if ([string]::IsNullOrWhiteSpace($address)) {
            Write-Log "'$($record.Target)' does not resolve from this DC - it may not have registered yet, so '$($record.Name)' is not created" -Tag "Warn"
            Write-Log "    Run this again once that machine is on the network, or create the record by hand" -Tag "Warn"
            $allDone = $false
            continue
        }
        if (-not (Set-StudioNamespaceRecord -Record $record -Address $address -ZoneMode $zoneMode)) { $allDone = $false }
    }
    return $allDone
}

# ---------------------------[ Prerequisites ]---------------------------
function Test-RdsPrerequisite {
    param([object]$Config)

    $passed = $true
    $rds    = Get-ConfigValue -InputObject $Config -Name "remoteDesktop"
    if ($null -eq $rds) {
        Write-Log "config.json has no remoteDesktop section" -Tag "Error"
        return $false
    }

    # A domain controller runs the directory half only - no role service, module or
    # deployment name belongs on it, so none is checked there.
    if (Test-StudioDomainController) {
        Write-Log "This machine is a domain controller - only the access groups and their members are applied here" -Tag "Info"
        return $true
    }

    # Only the role services THIS machine's part of the deployment needs. A quick session
    # holds every part and is checked for all of them; a farm's session host is checked
    # for one, and a check demanding a broker on it would refuse a perfectly good server.
    # The engine checks none of them: the role registry carries no Feature, because the
    # same config also reaches a domain controller, where a generic feature check would
    # refuse the directory half before it ran.
    $topology = Get-RdsTopology -RemoteDesktop $rds
    $parts = @(Get-RdsFarmPart -Topology $topology)
    if ($parts.Count -eq 0) {
        Write-Log "This machine ('$(Get-RdsLocalFqdn)') is not named anywhere in this Remote Desktop design" -Tag "Error"
        Write-Log "    Broker: $($topology.Broker)" -Tag "Error"
        Write-Log "    Web access: $($topology.WebAccess)" -Tag "Error"
        Write-Log "    Session host(s): $(($topology.SessionHosts | ForEach-Object { $_.Fqdn }) -join ', ')" -Tag "Error"
        Write-Log "    A farm is a named set - add this machine to the design, or run a config that means it" -Tag "Error"
        return $false
    }
    Write-Log ("This machine is the deployment's: {0}" -f ($parts -join ", ")) -Tag "Info"

    $required = @()
    foreach ($part in $parts) { $required += $script:rdsPartFeature[$part] }
    $required = @($required | Select-Object -Unique)

    $missing = @()
    foreach ($feature in $required) {
        try {
            $state = Get-WindowsFeature -Name $feature -ErrorAction Stop
            if (($null -eq $state) -or (-not $state.Installed)) { $missing += $feature }
        }
        catch {
            Write-Log "Could not query the '$feature' feature: $($_.Exception.Message)" -Tag "Error"
            $passed = $false
        }
    }
    if ($missing.Count -gt 0) {
        Write-Log "The deployment needs role services this server does not have: $($missing -join ', ')" -Tag "Error"
        Write-Log "    Install-WindowsFeature -Name $($missing -join ',') -IncludeManagementTools" -Tag "Error"
        $passed = $false
    }

    if (-not (Import-RdsModule)) {
        Write-Log "    Install-WindowsFeature -Name RSAT-RDS-Tools" -Tag "Error"
        $passed = $false
    }

    # Neither RD Web Access nor RD Session Host is a Server Core role service - the
    # broker, licensing and virtualization host are. Said here rather than left to a
    # deployment cmdlet, whose failure names neither the machine nor the reason.
    if (Test-StudioServerCore) {
        if ($parts -contains "webAccess") {
            Write-Log "RD Web Access is designed to run on this machine, and this machine is Server Core" -Tag "Error"
            Write-Log "    RD Web Access does not run on Server Core. Put it on a Desktop Experience server," -Tag "Error"
            Write-Log "    or move it onto the broker and install the broker with Desktop Experience." -Tag "Error"
            $passed = $false
        }
        if ($parts -contains "sessionHost") {
            Write-Log "This machine is a session host in the design, and it is Server Core" -Tag "Error"
            Write-Log "    RD Session Host does not run on Server Core - a session host IS the desktop." -Tag "Error"
            $passed = $false
        }
    }

    # A Connection Broker cannot exist in a workgroup, and the failure otherwise arrives
    # halfway through New-RDSessionDeployment.
    if (-not (Test-RdsDomainMember)) {
        Write-Log "This server is not domain joined - a Remote Desktop deployment needs a domain" -Tag "Error"
        $passed = $false
    }
    else {
        # The access groups are a prerequisite, not something this run creates: the
        # account driving a deployment holds RDS rights, not necessarily the right to
        # write groups into AD, and a collection naming a group that does not exist
        # refuses to configure with an error naming neither the group nor the cause.
        # Whoever owns the directory creates it; the line to do so is printed.
        $access = Get-ConfigValue -InputObject $rds -Name "access"
        $userGroups = @((Get-StudioGroupDefinition -Entries (Get-ConfigArray -InputObject $access -Name "userGroups")) |
            ForEach-Object { $_.Name })
        foreach ($groupName in $userGroups) {
            if ($groupName.Contains("\")) {
                # Qualified names can live in another domain of the forest - resolve
                # through LSA rather than a search rooted in this domain.
                try {
                    $account = New-Object System.Security.Principal.NTAccount($groupName)
                    $null = $account.Translate([System.Security.Principal.SecurityIdentifier])
                }
                catch {
                    Write-Log "The access group '$groupName' does not resolve - the collection refuses a group that does not exist" -Tag "Error"
                    $passed = $false
                }
                continue
            }
            $found = $null
            try {
                $found = Find-AdcsGroup -Name $groupName
            }
            catch {
                Write-Log "Could not look up the access group '$groupName': $($_.Exception.Message)" -Tag "Error"
                $passed = $false
                continue
            }
            if ($null -eq $found) {
                Write-Log "The access group '$groupName' does not exist in the domain - create it first, membership stays yours" -Tag "Error"
                Write-Log "    New-ADGroup -Name '$groupName' -GroupScope Global -GroupCategory Security" -Tag "Error"
                $passed = $false
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($topology.Broker)) {
        Write-Log "The design names no connection broker and this machine has no DNS domain to build one from" -Tag "Error"
        $passed = $false
    }
    elseif ($topology.Broker.Split(".").Count -lt 2) {
        Write-Log "'$($topology.Broker)' is not a fully qualified name - every deployment cmdlet rejects a short one" -Tag "Error"
        $passed = $false
    }

    return $passed
}

# ---------------------------[ Entry Point ]---------------------------
function Invoke-RdsConfiguration {
    param([object]$Config)

    $rds = Get-ConfigValue -InputObject $Config -Name "remoteDesktop"
    if ($null -eq $rds) {
        return (New-RoleResult -Status "Failed" -Message "config.json has no remoteDesktop section.")
    }

    # The directory half, same split as the file server role: a domain controller
    # handed this config creates the access groups and their members - the things
    # only it may write - and never touches the deployment named for another machine.
    if (Test-StudioDomainController) {
        Write-Log "Domain controller: creating the Remote Desktop access groups and bringing their members in" -Tag "Run"
        $access = Get-ConfigValue -InputObject $rds -Name "access"
        $groups = Get-StudioGroupDefinition -Entries (Get-ConfigArray -InputObject $access -Name "userGroups")
        $allSynced = $true
        foreach ($group in $groups) {
            if ($group.Name.Contains("\")) {
                Write-Log "'$($group.Name)' is qualified - a group in another domain is not this DC's to create" -Tag "Info"
                continue
            }
            if (-not (Sync-StudioAccessGroup -Name $group.Name -Description "Users allowed to sign in to the Remote Desktop collection" -MemberUpn $group.Members)) {
                $allSynced = $false
            }
        }
        # After the groups: the FSLogix policy is the domain controller's other job here,
        # and it is independent of them - a group that failed above does not stop it.
        if (-not (Set-RdsFsLogixGpo -RemoteDesktop $rds)) { $allSynced = $false }

        # And the namespace. The topology is resolved here rather than passed down
        # because this branch runs before Get-RdsTopology is reached below - a domain
        # controller is not a part of the farm and never gets that far.
        if (-not (Set-RdsDnsRecord -RemoteDesktop $rds -Topology (Get-RdsTopology -RemoteDesktop $rds))) { $allSynced = $false }

        if (-not $allSynced) {
            return (New-RoleResult -Status "ManualStepRequired" -Message "Not every group, member, policy object or record could be written - fix the names above and re-run")
        }
        return (New-RoleResult -Status "Completed" -Message "Access groups, the FSLogix policy and the deployment's names are ready - run the same config on the broker for the deployment itself")
    }

    if (-not (Import-RdsModule)) {
        return (New-RoleResult -Status "Failed" -Message "The RemoteDesktop module is not available on this server.")
    }

    $topology = Get-RdsTopology -RemoteDesktop $rds
    $parts    = @(Get-RdsFarmPart -Topology $topology)
    $fqdn     = $topology.Broker
    if ([string]::IsNullOrWhiteSpace($fqdn)) {
        return (New-RoleResult -Status "Failed" -Message "The connection broker's fully qualified name could not be determined.")
    }
    if ($parts.Count -eq 0) {
        return (New-RoleResult -Status "Failed" -Message "This machine is not named anywhere in the Remote Desktop design - a farm is a named set.")
    }

    $deployment     = Get-ConfigValue -InputObject $rds -Name "deployment"
    $collectionName = $topology.CollectionName
    $manualSteps    = @()

    # A machine that is not the broker does its own half and stops. Every deployment
    # cmdlet below is the broker's - running them from a member would aim them at the
    # broker anyway, and then two machines would be writing the same collection.
    if ($parts -notcontains "broker") {
        Write-Log ("This machine is the deployment's {0}; the broker is '{1}'" -f ($parts -join " and "), $fqdn) -Tag "Info"
        $joined = Join-RdsFarm -Topology $topology -Part $parts

        if ($parts -contains "sessionHost") {
            if (-not (Set-RdsFslogixProfile -RemoteDesktop $rds)) {
                $manualSteps += "FSLogix could not be installed or configured"
            }
        }

        # The portal's binding is this machine's to make, and only this machine's: the
        # broker distributed the certificate into this store, and an IIS binding is local.
        if ($parts -contains "webAccess") {
            if (-not (Sync-RdsWebBinding -Fqdn $topology.Broker -Topology $topology -Part $parts -RemoteDesktop $rds)) {
                $manualSteps += "the RD Web page is not serving the deployment's certificate"
            }
            # And it has to keep following it: the broker renews and redistributes, but
            # nothing there can move an IIS binding on this machine.
            if (-not (Register-StudioCertificateTask -Config $Config -ConfigFilePath $script:configFilePath)) {
                $manualSteps += "the nightly task that keeps the RD Web binding in step could not be registered"
            }
        }

        # The portal watchdog belongs to the broker. This machine is not it - and if it
        # used to be, the task it left behind would keep writing a value that is now
        # another server's, so it goes rather than being left to run against nothing.
        Unregister-RdsPortalTask

        if (-not $joined) {
            return (New-RoleResult -Status "ManualStepRequired" -Message "This machine is not in the deployment on '$fqdn' yet - build the broker first, then run this again here.")
        }
        if ($manualSteps.Count -gt 0) {
            return (New-RoleResult -Status "ManualStepRequired" -Message ("Joined the farm, but " + ($manualSteps -join ", ") + "."))
        }
        return (New-RoleResult -Status "Completed" -Message ("This machine is the farm's " + ($parts -join " and ") + " on '$fqdn'."))
    }

    if (-not (Test-RdsDeployment -Fqdn $fqdn)) {
        New-RdsDeployment -Fqdn $fqdn -Topology $topology
    }
    else {
        Write-Log "A session deployment already exists on '$fqdn'" -Tag "Info"
    }

    if ($null -eq (Get-RdsCollection -Fqdn $fqdn -CollectionName $collectionName)) {
        New-RdsCollection -Fqdn $fqdn -Deployment $deployment -Topology $topology
    }
    else {
        Write-Log "The collection '$collectionName' already exists - its settings are re-applied" -Tag "Info"
    }

    # Every run, not only the first: a farm that grew a machine picks it up here, and
    # one that did not costs a read. Additive - a host is never taken out of a farm.
    if (-not (Sync-RdsFarmMember -Fqdn $fqdn -Topology $topology -CollectionName $collectionName)) {
        $manualSteps += "not every server in the design could be added to the deployment"
    }

    Set-RdsCollectionConfiguration -Fqdn $fqdn -CollectionName $collectionName -RemoteDesktop $rds

    if (-not (Set-RdsSessionHostDrain -Fqdn $fqdn -Topology $topology)) {
        $manualSteps += "the new-connection state of every session host could not be applied"
    }

    # After the collection, before the certificates: FSLogix is what makes the second
    # session host worth having, but a deployment without it still works - so a failed
    # agent install is a manual step, never a failed role. Only where sessions run: on a
    # broker that is not also a session host the agent would sit there doing nothing.
    if ($parts -contains "sessionHost") {
        if (-not (Set-RdsFslogixProfile -RemoteDesktop $rds)) {
            $manualSteps += "FSLogix could not be installed or configured"
        }
    }
    else {
        Write-Log "The FSLogix agent belongs on the session hosts" -Tag "Info"
    }

    # Before the licensing configuration: pointing the deployment at a license server
    # that is not part of it yet is what "the licensing mode is set but nothing answers"
    # looks like from the outside.
    if (-not (Add-RdsLicenseServerRole -Fqdn $fqdn -RemoteDesktop $rds)) {
        $manualSteps += "the RD Licensing role service could not be added"
    }
    # Caught rather than thrown: in a farm the licence server is its own machine and may
    # not have run this config yet, and "the collection is up but licensing is not
    # pointed at it" is a manual step. Failing the whole role would say the deployment
    # did not happen, which is not what went wrong.
    try {
        Set-RdsLicensing -Fqdn $fqdn -RemoteDesktop $rds
    }
    catch {
        Write-Log "The licensing configuration could not be applied: $($_.Exception.Message)" -Tag "Error"
        Write-Log "    A licence server has to be part of the deployment before it can be pointed at." -Tag "Error"
        Write-Log "    Run this same config on it, then re-run here." -Tag "Error"
        $manualSteps += "the licensing mode could not be applied"
    }

    # No private-key grant here, deliberately. That belongs to Windows Admin Center,
    # whose gateway cannot read its own key without it; the deployment certificate does
    # not need one. Set-RDCertificate configures the roles, the HTTPS binding is served
    # by HTTP.SYS with Schannel reading the key as SYSTEM rather than as the app pool,
    # and no RDS automation in the field grants anything on the key - not Microsoft's own
    # rds-update-certificate quickstart, not win-acme's ImportRDSFull.ps1, not
    # Posh-ACME.Deploy. The NETWORK SERVICE advice that gets quoted (KB3042780) is about
    # the RDP *listener* on a server outside an RDS deployment.
    #
    # The listener's own certificate is Group Policy's here, and the grant it needs lives
    # on the certificate template rather than on this server: msPKI-Key-Security-Descriptor,
    # which is the console's 'Authorize additional service accounts to access the private
    # key'. Without it an autoenrolled certificate leaves the listener unable to read its
    # key (Schannel 36870 / 1058).
    $manualSteps += @(Set-RdsCertificateSet -Fqdn $fqdn -RemoteDesktop $rds -Topology $topology)

    # The deployment now knows which certificate RD Web Access should serve; IIS on the
    # machine holding it may still be serving the last one.
    if (-not (Sync-RdsWebBinding -Fqdn $fqdn -Topology $topology -Part $parts -RemoteDesktop $rds)) {
        $manualSteps += "the RD Web page is not serving the deployment's certificate"
    }

    # After the certificate: the name in the .rdp file is checked against the signature,
    # so publishing a name the certificate does not carry would be the failure this
    # order avoids.
    if (-not (Set-RdsPublishedName -Fqdn $fqdn -RemoteDesktop $rds)) {
        $manualSteps += "the published name could not be set"
    }

    # Beside the published name, and for the same reason it sits here rather than with
    # the collection: both are deployment-wide strings the broker owns, and neither
    # depends on what is published in the collection.
    if (-not (Set-RdsWorkspaceName -Fqdn $fqdn -RemoteDesktop $rds)) {
        $manualSteps += "the workspace name could not be set"
    }

    $unpublished = @(Set-RdsRemoteApp -Fqdn $fqdn -CollectionName $collectionName -RemoteDesktop $rds `
        -PathOnAnotherMachine:($parts -notcontains "sessionHost"))
    if ($unpublished.Count -gt 0) {
        $manualSteps += ("these application(s) were not published: " + ($unpublished -join ", "))
    }

    # After the applications: publishing the first one is what takes the desktop off the
    # feed, so putting it back has to come second.
    if (-not (Set-RdsDesktopInPortal -CollectionName $collectionName -RemoteDesktop $rds).Ok) {
        $manualSteps += "the full desktop could not be put back on the portal"
    }

    # And it has to stay put between runs, which is the one thing a configuration run
    # cannot do: Windows clears that value on every broker restart and every collection
    # change. Registered here, on the broker, because the value is the broker's alone.
    if (-not (Register-RdsPortalTask -Config $Config -RemoteDesktop $rds -ConfigFilePath $script:configFilePath)) {
        $manualSteps += "the task that keeps the desktop on the portal could not be registered"
    }

    if (-not (Register-StudioCertificateTask -Config $Config -ConfigFilePath $script:configFilePath)) {
        $manualSteps += "the nightly certificate task could not be registered"
    }

    Write-Log "The web feed is https://$($topology.WebAccess)/RDWeb" -Tag "Info"
    Write-Log ("Session hosts: {0}" -f (($topology.SessionHosts | ForEach-Object { "$($_.Fqdn) [$($_.NewConnectionAllowed)]" }) -join ", ")) -Tag "Info"

    # Stated here, written on the domain controller. The broker is a member server: it
    # would need RSAT and delegated rights to write DNS remotely, and the run that
    # already happens on the directory needs neither.
    $records = @(Get-RdsNamespaceRecord -RemoteDesktop $rds -Topology $topology)
    if ($records.Count -gt 0) {
        $managesDns = [bool](Get-ConfigValue -InputObject (Get-ConfigValue -InputObject $rds -Name "dns") -Name "manage" -Default $true)
        if ($managesDns) {
            Write-Log "DNS records this deployment needs - written by the domain controller's own run:" -Tag "Info"
        }
        else {
            Write-Log "DNS records this deployment needs - A records, never CNAMEs, and none of them this run's to write:" -Tag "Info"
        }
        foreach ($record in $records) {
            Write-Log "    $($record.Name)  ->  $($record.Target)   ($($record.Purpose))" -Tag "Info"
        }
        if ($managesDns) {
            Write-Log "    Run the same config on a domain controller if you have not yet - nothing here can write them" -Tag "Info"
        }
    }

    if ($manualSteps.Count -gt 0) {
        return (New-RoleResult -Status "ManualStepRequired" -Message ("The collection is up, but " + ($manualSteps -join ", ") + "."))
    }
    $spread = "on $fqdn"
    if ($topology.SessionHosts.Count -gt 1) {
        $spread = "across $($topology.SessionHosts.Count) session hosts, brokered by $fqdn"
    }
    return (New-RoleResult -Status "Completed" -Message "The '$collectionName' collection is serving $spread.")
}

# What the nightly task runs for this role. Same code path as the configuration run
# from the certificate onward, so a renewal is not a second implementation.
function Invoke-RdsCertificateTask {
    param([object]$Config)

    $rds = Get-ConfigValue -InputObject $Config -Name "remoteDesktop"
    if ($null -eq $rds) { return 0 }

    $certificate = Get-ConfigValue -InputObject $rds -Name "certificate"
    $source      = Get-ConfigText -InputObject $certificate -Name "source" -Default "leave"
    $webCertificate = Get-ConfigValue -InputObject $rds -Name "webAccessCertificate"
    $webSource      = Get-ConfigText -InputObject $webCertificate -Name "source" -Default "leave"
    if ((@("internalCa", "acme") -notcontains $source) -and (@("internalCa", "acme") -notcontains $webSource)) {
        Write-Log "The Remote Desktop certificate comes from '$source' - no renewal schedule of its own" -Tag "Info"
        return 0
    }
    if (-not (Import-RdsModule)) {
        Write-Log "The RemoteDesktop module is not available - nothing to renew here" -Tag "Error"
        return 1
    }

    # Which machine is this, and therefore what is its half of a renewal? Invoke-CertificateTask
    # runs this whenever the config has a remoteDesktop section, and the same config reaches
    # every machine in the farm.
    $topology = Get-RdsTopology -RemoteDesktop $rds
    $parts = @(Get-RdsFarmPart -Topology $topology)

    if (-not (Test-RdsThisMachine -Fqdn $topology.Broker)) {
        # The portal's machine has one job tonight and it is not obtaining anything: the
        # broker renews and redistributes the certificate into this store, and only this
        # machine can move its own IIS binding onto it.
        if ($parts -contains "webAccess") {
            Write-Log "This machine serves RD Web Access - checking its binding" -Tag "Run"
            if (Sync-RdsWebBinding -Fqdn $topology.Broker -Topology $topology -Part $parts -RemoteDesktop $rds) { return 0 }
            return 1
        }
        # A session host that registered the task for some other role's certificate would
        # otherwise obtain the deployment certificate into ITS store and bind it from
        # there. The task is registered on the broker; this makes that a rule.
        Write-Log "The deployment certificate belongs to the broker ('$($topology.Broker)') - nothing to renew here" -Tag "Info"
        return 0
    }

    $fqdn = Get-RdsServerFqdn -RemoteDesktop $rds
    if ([string]::IsNullOrWhiteSpace($fqdn)) {
        Write-Log "The server's fully qualified name could not be determined" -Tag "Error"
        return 1
    }
    # Three attempts a minute apart, for the same reason the portal task retries: this
    # machine is the connection broker in the design, so "no deployment here" is not an
    # answer to accept the first time it is given. After a broker restart rdms takes a
    # while to come up and Get-RDServer throws until it does - which used to be reported
    # as nothing to renew, on the one machine whose certificate this task exists for.
    $deploymentFound = $false
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        if (Test-RdsDeployment -Fqdn $fqdn) { $deploymentFound = $true; break }
        # Waiting is only worth it for a service that is on its way up. RDMS stopped is
        # not a race, it is the answer - and three minutes spent re-asking a service that
        # is not running is three minutes of a log that says nothing.
        if ((Test-RdsThisMachine -Fqdn $fqdn) -and ((Get-RdsServiceState -Name "rdms") -ne "Running")) {
            Write-Log "The Remote Desktop Management service is not running - waiting will not change that" -Tag "Warn"
            break
        }
        if ($attempt -lt 3) {
            Write-Log "The deployment on '$fqdn' did not answer - waiting a minute in case the broker is still coming up" -Tag "Info"
            Start-Sleep -Seconds 60
        }
    }
    if (-not $deploymentFound) {
        Write-Log "No Remote Desktop deployment answered on '$fqdn' after three attempts - nothing was renewed" -Tag "Warn"
        Write-RdsDeploymentDiagnosis -Fqdn $fqdn
        Write-Log "    This machine is the connection broker in the design, so a deployment is expected here" -Tag "Warn"
        Write-Log "    Reported as a failure rather than nothing-to-do: a certificate expiring while the task says 'nothing to renew' is the silence this task exists to break" -Tag "Warn"
        return 1
    }

    $exitCode = 0

    # Both blocks, each with its own report: they are two certificates on two machines,
    # and one mail saying "renewed" about a pair where only one moved would be worse than
    # no mail at all. The deployment's first - it is the one the .rdp files are signed
    # with, and the one a failure has to be loudest about.
    $blocks = @()
    if (@("internalCa", "acme") -contains $source) {
        # Read the role the design actually binds rather than a fixed one: a deployment
        # certificate with RDWebAccess unticked is not on that role, and reading it would
        # compare against whatever else is there and report a renewal that never happened.
        $deploymentRoles = @(Get-ConfigArray -InputObject $certificate -Name "roles" |
            ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $readRole = "RDRedirector"
        if ($deploymentRoles.Count -gt 0) { $readRole = $deploymentRoles[0] }
        $blocks += [PSCustomObject]@{
            Certificate = $certificate; Source = $source; Label = "Remote Desktop"
            Role = $readRole; Distribute = $false
        }
    }
    if (@("internalCa", "acme") -contains $webSource) {
        $blocks += [PSCustomObject]@{
            Certificate = $webCertificate; Source = $webSource; Label = "Remote Desktop Web Access"
            Role = "RDWebAccess"; Distribute = $true
        }
    }

    foreach ($block in $blocks) {
        $names       = @(Get-ConfigArray -InputObject $block.Certificate -Name "dnsNames" | ForEach-Object { [string]$_ })
        $primaryName = ""
        if ($names.Count -gt 0) { $primaryName = $names[0] }
        $pluginName  = Get-ConfigText -InputObject (Get-ConfigValue -InputObject $block.Certificate -Name "acme") -Name "dnsPlugin"

        # Read before anything changes, so the report can say what was replaced.
        $previousThumbprint = ""
        $previousNotAfter   = ""
        try {
            $current = Get-RDCertificate -Role $block.Role -ConnectionBroker $fqdn -ErrorAction Stop
            if ($null -ne $current) {
                $previousThumbprint = [string]$current.Thumbprint
                if ($null -ne $current.ExpiresOn) { $previousNotAfter = ([datetime]$current.ExpiresOn).ToString("yyyy-MM-dd") }
            }
        }
        catch {
            Write-Log "Could not read the certificate $($block.Role) serves: $($_.Exception.Message)" -Tag "Debug"
        }

        $thumbprint = ""
        try {
            $thumbprint = Resolve-StudioCertificate -Certificate $block.Certificate
        }
        catch {
            Write-Log "The $($block.Label) certificate could not be obtained: $($_.Exception.Message)" -Tag "Error"
            $null = Send-CertificateReport -Config $Config -Report (New-WacCertificateReport `
                -Status "Failed" -RoleLabel $block.Label -PrimaryName $primaryName -Names $names -Source $block.Source `
                -PluginName $pluginName -Port 443 -PreviousThumbprint $previousThumbprint -PreviousNotAfter $previousNotAfter `
                -ErrorMessage $_.Exception.Message -ErrorStackTrace ([string]$_.ScriptStackTrace))
            $exitCode = 1
            continue
        }

        if ([string]::IsNullOrWhiteSpace($thumbprint)) {
            Write-Log "No certificate came back for $($block.Label) - it is left as it is" -Tag "Info"
            continue
        }

        $status = "Renewed"
        if ($previousThumbprint -eq $thumbprint.ToUpperInvariant()) {
            Write-Log "$($block.Label) already serves $thumbprint - nothing to do tonight" -Tag "Ok"
            $status = "Current"
        }

        # No key grant on renewal either - see the apply path for why it is Windows Admin
        # Center's and not this role's.
        $errorMessage = ""
        if (-not (Set-RdsDeploymentCertificate -Fqdn $fqdn -Certificate $block.Certificate `
                -Thumbprint $thumbprint -Distribute:$block.Distribute)) {
            $status = "Failed"
            $errorMessage = "The certificate is in the store but the deployment is not serving it on every role."
        }

        $notAfter = ""
        $issued = Get-Item -Path ("Cert:\LocalMachine\My\" + $thumbprint) -ErrorAction SilentlyContinue
        if ($null -ne $issued) { $notAfter = $issued.NotAfter.ToString("yyyy-MM-dd") }

        $null = Send-CertificateReport -Config $Config -Report (New-WacCertificateReport `
            -Status $status -RoleLabel $block.Label -PrimaryName $primaryName -Names $names -Source $block.Source `
            -PluginName $pluginName -Port 443 -Thumbprint $thumbprint -NotAfter $notAfter `
            -PreviousThumbprint $previousThumbprint -PreviousNotAfter $previousNotAfter -ErrorMessage $errorMessage)

        if ($status -eq "Failed") { $exitCode = 1 }
    }

    # A renewal that the deployment accepted and IIS did not is a web page still serving
    # last quarter's certificate, which is exactly the state this whole step exists for.
    if (-not (Sync-RdsWebBinding -Fqdn $fqdn -Topology $topology -Part $parts -RemoteDesktop $rds)) { $exitCode = 1 }

    return $exitCode
}
