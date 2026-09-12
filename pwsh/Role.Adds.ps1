# Role provider: Active Directory Domain Services.
#
# Dot-sourced by Configure-ServerRoles.ps1 - not runnable on its own. Everything
# here lands in that script's scope, so $script: variables and functions are shared
# with every other part. Use $scriptRootPath, never $PSScriptRoot: inside this file
# $PSScriptRoot is the pwsh folder, not the folder the run was started from.

# ===========================[ Active Directory Domain Services ]===========================

# ---------------------------[ Local accounts before promotion ]---------------------------
# Promoting the first DC of a new forest moves the local SAM into the directory:
# the built-in Administrator becomes the domain Administrator, and every other
# local account becomes a plain domain user - usually not what anyone wanted.
# https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/install-a-new-windows-server-2012-active-directory-forest--level-200-
$script:builtInAdministratorRid = 500
$script:wellKnownLocalRids = @(500, 501, 503, 504)

function Test-BuiltInAdministratorIdentity {
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $sid = [string]$identity.User.Value
    }
    catch {
        Write-Log "Could not read the current identity: $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    Write-Log "Running as $($identity.Name) ($sid)" -Tag "Info"
    return ($sid -match ("-" + $script:builtInAdministratorRid + "$"))
}

# Every enabled local account that is not one of the built-in, well-known ones.
function Get-MigratingLocalAccount {
    $accounts = @()

    if (Get-Command -Name "Get-LocalUser" -ErrorAction SilentlyContinue) {
        $localUsers = @(Get-LocalUser -ErrorAction SilentlyContinue)
        foreach ($user in $localUsers) {
            if (-not $user.Enabled) { continue }
            $sid = [string]$user.SID.Value
            $rid = [int]($sid.Split("-")[-1])
            if ($script:wellKnownLocalRids -contains $rid) { continue }
            $accounts += [pscustomobject]@{ Name = $user.Name; Sid = $sid }
        }
        return $accounts
    }

    $cimUsers = @(Get-CimInstance -ClassName "Win32_UserAccount" -Filter "LocalAccount = True" -ErrorAction SilentlyContinue)
    foreach ($user in $cimUsers) {
        if ($user.Disabled) { continue }
        $sid = [string]$user.SID
        $rid = [int]($sid.Split("-")[-1])
        if ($script:wellKnownLocalRids -contains $rid) { continue }
        $accounts += [pscustomobject]@{ Name = $user.Name; Sid = $sid }
    }
    return $accounts
}

# S-1-5-32-544 rather than the name, which is renamed often enough to matter.
function Get-LocalAdministratorName {
    $names = @()
    if (-not (Get-Command -Name "Get-LocalGroupMember" -ErrorAction SilentlyContinue)) { return $names }

    try {
        $members = @(Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop)
    }
    catch {
        Write-Log "Could not read the local Administrators group: $($_.Exception.Message)" -Tag "Info"
        return $names
    }

    foreach ($member in $members) {
        $names += ([string]$member.Name).Split("\")[-1]
    }
    return $names
}

function Test-LocalAccountReadiness {
    param(
        [object]$ActiveDirectory,
        [bool]$SkipCheck = $false
    )

    $mode = [string](Get-ConfigValue -InputObject $ActiveDirectory -Name "mode" -Default "newForest")
    $isNewForest = ($mode -eq "newForest")
    $problems = @()

    if (-not (Test-BuiltInAdministratorIdentity)) {
        $problems += "This session is not the built-in Administrator (RID $($script:builtInAdministratorRid))."
        Write-Log "The built-in Administrator is the account that becomes the domain Administrator - promote with it" -Tag "Error"
    }

    $localAccounts = @(Get-MigratingLocalAccount)
    if ($localAccounts.Count -eq 0) {
        Write-Log "No local account other than the built-in ones exists on this server" -Tag "Ok"
    }
    else {
        # On a replica the local SAM is discarded instead of migrated, so there it is
        # worth saying out loud but not worth refusing over.
        $accountTag = "Info"
        if ($isNewForest) { $accountTag = "Error" }

        $administrators = @(Get-LocalAdministratorName)
        foreach ($account in $localAccounts) {
            $suffix = ""
            if ($administrators -contains $account.Name) { $suffix = " - member of the local Administrators group" }
            Write-Log "Local account '$($account.Name)' ($($account.Sid))$suffix" -Tag $accountTag
        }

        if ($isNewForest) {
            $problems += "$($localAccounts.Count) other local account(s) would become domain accounts."
            Write-Log "Delete or disable these accounts before promoting, or set activeDirectory.options.skipLocalAccountCheck to keep them" -Tag "Error"
        }
        else {
            Write-Log "These local accounts stop working once this server becomes a domain controller" -Tag "Info"
        }
    }

    if ($problems.Count -eq 0) { return $true }

    foreach ($problem in $problems) { Write-Log $problem -Tag "Error" }

    if ($SkipCheck) {
        Write-Log "skipLocalAccountCheck is set - continuing anyway" -Tag "Info"
        return $true
    }
    return $false
}

# Called by the engine before anything is applied, and before -CheckOnly exits.
function Test-AddsPrerequisite {
    param([object]$Config)

    # A finished DC has no local SAM left to inspect, and nothing left to migrate.
    if (Test-DomainControllerRole) { return $true }

    $activeDirectory = Get-ConfigValue -InputObject $Config -Name "activeDirectory"
    $options         = Get-ConfigValue -InputObject $activeDirectory -Name "options"
    $skipCheck       = [bool](Get-ConfigValue -InputObject $options -Name "skipLocalAccountCheck" -Default $false)

    return (Test-LocalAccountReadiness -ActiveDirectory $activeDirectory -SkipCheck $skipCheck)
}

# ---------------------------[ Credentials ]---------------------------
function Read-SafeModePassword {
    param([object]$ActiveDirectory)

    $plainText = [string](Get-ConfigValue -InputObject $ActiveDirectory -Name "safeModePassword" -Default "")

    if (-not [string]::IsNullOrWhiteSpace($plainText)) {
        Write-Log "Using the DSRM password supplied in config.json" -Tag "Info"
        return (ConvertTo-SecureString -String $plainText -AsPlainText -Force)
    }

    Write-Log "DSRM password was not exported - prompting" -Tag "Info"
    $firstEntry  = Read-Host -Prompt "Directory Services Restore Mode password" -AsSecureString
    $secondEntry = Read-Host -Prompt "Confirm Directory Services Restore Mode password" -AsSecureString

    $firstPointer  = [IntPtr]::Zero
    $secondPointer = [IntPtr]::Zero
    try {
        $firstPointer  = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($firstEntry)
        $secondPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secondEntry)
        $firstPlain    = [Runtime.InteropServices.Marshal]::PtrToStringAuto($firstPointer)
        $secondPlain   = [Runtime.InteropServices.Marshal]::PtrToStringAuto($secondPointer)

        if ($firstPlain -ne $secondPlain) {
            throw "The two DSRM passwords do not match."
        }
        if ([string]::IsNullOrWhiteSpace($firstPlain)) {
            throw "The DSRM password must not be empty."
        }
    }
    finally {
        if ($firstPointer -ne [IntPtr]::Zero)  { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($firstPointer) }
        if ($secondPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secondPointer) }
    }
    return $firstEntry
}

function Read-DomainCredential {
    param([object]$JoinExisting)

    $userName  = [string](Get-ConfigValue -InputObject $JoinExisting -Name "credentialUser" -Default "")
    $plainText = [string](Get-ConfigValue -InputObject $JoinExisting -Name "credentialPassword" -Default "")

    if ([string]::IsNullOrWhiteSpace($userName)) {
        throw "joinExisting.credentialUser is missing from config.json."
    }

    if (-not [string]::IsNullOrWhiteSpace($plainText)) {
        Write-Log "Using the domain credential supplied in config.json for '$userName'" -Tag "Info"
        $securePassword = ConvertTo-SecureString -String $plainText -AsPlainText -Force
        return (New-Object System.Management.Automation.PSCredential($userName, $securePassword))
    }

    Write-Log "Domain password was not exported - prompting for '$userName'" -Tag "Info"
    return (Get-Credential -UserName $userName -Message "Credentials that may add this domain controller")
}

# ---------------------------[ Promotion ]---------------------------
function Add-SharedPromotionParameter {
    param(
        [Parameter(Mandatory)][hashtable]$Parameters,
        [object]$ActiveDirectory,
        [Parameter(Mandatory)][System.Security.SecureString]$SafeModePassword
    )

    $paths = Get-ConfigValue -InputObject $ActiveDirectory -Name "paths"
    if ($null -ne $paths) {
        $Parameters["DatabasePath"] = [string](Get-ConfigValue -InputObject $paths -Name "databasePath" -Default "C:\Windows\NTDS")
        $Parameters["LogPath"]      = [string](Get-ConfigValue -InputObject $paths -Name "logPath"      -Default "C:\Windows\NTDS")
        $Parameters["SysvolPath"]   = [string](Get-ConfigValue -InputObject $paths -Name "sysvolPath"   -Default "C:\Windows\SYSVOL")
    }

    $options = Get-ConfigValue -InputObject $ActiveDirectory -Name "options"
    if ([bool](Get-ConfigValue -InputObject $options -Name "skipPreChecks" -Default $false)) {
        $Parameters["SkipPreChecks"] = $true
    }
    if ([bool](Get-ConfigValue -InputObject $options -Name "skipAutoConfigureDns" -Default $false)) {
        $Parameters["SkipAutoConfigureDNS"] = $true
    }
    if ([bool](Get-ConfigValue -InputObject $options -Name "noRebootOnCompletion" -Default $false)) {
        $Parameters["NoRebootOnCompletion"] = $true
    }

    $Parameters["SafeModeAdministratorPassword"] = $SafeModePassword
    $Parameters["Force"]                         = $true
    $Parameters["ErrorAction"]                   = "Stop"
}

function Install-NewForest {
    param(
        [object]$ActiveDirectory,
        [Parameter(Mandatory)][System.Security.SecureString]$SafeModePassword
    )

    $forest = Get-ConfigValue -InputObject $ActiveDirectory -Name "newForest"
    if ($null -eq $forest) {
        throw "activeDirectory.mode is 'newForest' but the newForest section is missing."
    }

    $domainName = [string](Get-ConfigValue -InputObject $forest -Name "domainName" -Default "")
    if ([string]::IsNullOrWhiteSpace($domainName)) {
        throw "newForest.domainName is empty."
    }

    $promotionParameters = @{
        DomainName          = $domainName
        DomainNetbiosName   = [string](Get-ConfigValue -InputObject $forest -Name "domainNetbiosName" -Default "")
        ForestMode          = [string](Get-ConfigValue -InputObject $forest -Name "forestMode" -Default "WinThreshold")
        DomainMode          = [string](Get-ConfigValue -InputObject $forest -Name "domainMode" -Default "WinThreshold")
        InstallDns          = [bool](Get-ConfigValue -InputObject $forest -Name "installDns" -Default $true)
        CreateDnsDelegation = [bool](Get-ConfigValue -InputObject $forest -Name "createDnsDelegation" -Default $false)
    }
    Add-SharedPromotionParameter -Parameters $promotionParameters -ActiveDirectory $ActiveDirectory -SafeModePassword $SafeModePassword

    Write-Log "Creating a new forest '$domainName' (forest mode $($promotionParameters.ForestMode))" -Tag "Run"
    Install-ADDSForest @promotionParameters | Out-Null
}

function Install-ReplicaDomainController {
    param(
        [object]$JoinExisting,
        [object]$ActiveDirectory,
        [Parameter(Mandatory)][System.Security.SecureString]$SafeModePassword,
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$Credential
    )

    $domainName = [string](Get-ConfigValue -InputObject $JoinExisting -Name "domainName" -Default "")
    if ([string]::IsNullOrWhiteSpace($domainName)) {
        throw "joinExisting.domainName is empty."
    }

    $promotionParameters = @{
        DomainName          = $domainName
        Credential          = $Credential
        InstallDns          = [bool](Get-ConfigValue -InputObject $JoinExisting -Name "installDns" -Default $true)
        NoGlobalCatalog     = [bool](Get-ConfigValue -InputObject $JoinExisting -Name "noGlobalCatalog" -Default $false)
        CreateDnsDelegation = [bool](Get-ConfigValue -InputObject $JoinExisting -Name "createDnsDelegation" -Default $false)
    }

    $siteName = [string](Get-ConfigValue -InputObject $JoinExisting -Name "siteName" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($siteName)) {
        $promotionParameters["SiteName"] = $siteName
    }

    if ([bool](Get-ConfigValue -InputObject $JoinExisting -Name "isReadOnly" -Default $false)) {
        $promotionParameters["ReadOnlyReplica"] = $true

        $delegatedAccount = [string](Get-ConfigValue -InputObject $JoinExisting -Name "delegatedAdministratorAccount" -Default "")
        if (-not [string]::IsNullOrWhiteSpace($delegatedAccount)) {
            $promotionParameters["DelegatedAdministratorAccountName"] = $delegatedAccount
        }

        $allowedAccounts = Get-ConfigArray -InputObject $JoinExisting -Name "allowPasswordReplicationAccountName"
        if ($allowedAccounts.Count -gt 0) {
            $promotionParameters["AllowPasswordReplicationAccountName"] = $allowedAccounts
        }
        $deniedAccounts = Get-ConfigArray -InputObject $JoinExisting -Name "denyPasswordReplicationAccountName"
        if ($deniedAccounts.Count -gt 0) {
            $promotionParameters["DenyPasswordReplicationAccountName"] = $deniedAccounts
        }
    }

    $replicationSource = [string](Get-ConfigValue -InputObject $JoinExisting -Name "replicationSourceDc" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($replicationSource)) {
        $promotionParameters["ReplicationSourceDC"] = $replicationSource
    }

    $mediaPath    = [string](Get-ConfigValue -InputObject $JoinExisting -Name "installationMediaPath" -Default "")
    $criticalOnly = [bool](Get-ConfigValue -InputObject $JoinExisting -Name "criticalReplicationOnly" -Default $false)

    if ((-not [string]::IsNullOrWhiteSpace($mediaPath)) -and $criticalOnly) {
        throw "installationMediaPath and criticalReplicationOnly cannot be combined."
    }
    if (-not [string]::IsNullOrWhiteSpace($mediaPath)) {
        if (-not (Test-Path -LiteralPath $mediaPath)) {
            throw "joinExisting.installationMediaPath '$mediaPath' does not exist."
        }
        $promotionParameters["InstallationMediaPath"] = $mediaPath
    }
    if ($criticalOnly) {
        $promotionParameters["CriticalReplicationOnly"] = $true
    }

    Add-SharedPromotionParameter -Parameters $promotionParameters -ActiveDirectory $ActiveDirectory -SafeModePassword $SafeModePassword

    Write-Log "Adding a domain controller to the existing domain '$domainName'" -Tag "Run"
    Install-ADDSDomainController @promotionParameters | Out-Null
}

function Install-AdditionalDomain {
    param(
        [object]$JoinExisting,
        [object]$ActiveDirectory,
        [Parameter(Mandatory)][System.Security.SecureString]$SafeModePassword,
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$Credential
    )

    $parentDomainName = [string](Get-ConfigValue -InputObject $JoinExisting -Name "parentDomainName" -Default "")
    $newDomainName    = [string](Get-ConfigValue -InputObject $JoinExisting -Name "newDomainName" -Default "")
    $domainType       = [string](Get-ConfigValue -InputObject $JoinExisting -Name "domainType" -Default "ChildDomain")

    if ([string]::IsNullOrWhiteSpace($parentDomainName)) {
        throw "joinExisting.parentDomainName is empty."
    }
    if ([string]::IsNullOrWhiteSpace($newDomainName)) {
        throw "joinExisting.newDomainName is empty."
    }

    $promotionParameters = @{
        ParentDomainName     = $parentDomainName
        NewDomainName        = $newDomainName
        NewDomainNetbiosName = [string](Get-ConfigValue -InputObject $JoinExisting -Name "newDomainNetbiosName" -Default "")
        DomainType           = $domainType
        DomainMode           = [string](Get-ConfigValue -InputObject $JoinExisting -Name "domainMode" -Default "WinThreshold")
        Credential           = $Credential
        InstallDns           = [bool](Get-ConfigValue -InputObject $JoinExisting -Name "installDns" -Default $true)
        CreateDnsDelegation  = [bool](Get-ConfigValue -InputObject $JoinExisting -Name "createDnsDelegation" -Default $false)
    }

    $siteName = [string](Get-ConfigValue -InputObject $JoinExisting -Name "siteName" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($siteName)) {
        $promotionParameters["SiteName"] = $siteName
    }
    $replicationSource = [string](Get-ConfigValue -InputObject $JoinExisting -Name "replicationSourceDc" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($replicationSource)) {
        $promotionParameters["ReplicationSourceDC"] = $replicationSource
    }

    Add-SharedPromotionParameter -Parameters $promotionParameters -ActiveDirectory $ActiveDirectory -SafeModePassword $SafeModePassword

    Write-Log "Creating the $domainType '$newDomainName' below '$parentDomainName'" -Tag "Run"
    Install-ADDSDomain @promotionParameters | Out-Null
}

function Install-DomainController {
    param([object]$ActiveDirectory)

    try {
        Import-Module -Name "ADDSDeployment" -ErrorAction Stop
    }
    catch {
        throw "The ADDSDeployment module is unavailable even though the role reports as installed: $($_.Exception.Message)"
    }

    $safeModePassword = Read-SafeModePassword -ActiveDirectory $ActiveDirectory
    $mode = [string](Get-ConfigValue -InputObject $ActiveDirectory -Name "mode" -Default "newForest")

    if ($mode -eq "newForest") {
        Install-NewForest -ActiveDirectory $ActiveDirectory -SafeModePassword $safeModePassword
        return
    }

    $joinExisting = Get-ConfigValue -InputObject $ActiveDirectory -Name "joinExisting"
    if ($null -eq $joinExisting) {
        throw "activeDirectory.mode is 'joinExisting' but the joinExisting section is missing."
    }

    $credential = Read-DomainCredential -JoinExisting $joinExisting
    $operation  = [string](Get-ConfigValue -InputObject $joinExisting -Name "operation" -Default "addDomainController")

    if ($operation -eq "addDomainController") {
        Install-ReplicaDomainController -JoinExisting $joinExisting -ActiveDirectory $ActiveDirectory `
            -SafeModePassword $safeModePassword -Credential $credential
        return
    }

    Install-AdditionalDomain -JoinExisting $joinExisting -ActiveDirectory $ActiveDirectory `
        -SafeModePassword $safeModePassword -Credential $credential
}

# ---------------------------[ Unattended follow-up ]---------------------------
# The reboot boundary, the follow-up task and the hand-over to the next role all
# belong to the engine now. What is left here is the wait this role needs before
# its own post-reboot work can touch the directory.

# At startup the directory answers a few minutes later than the service claims.
function Wait-ForDirectoryService {
    param([int]$TimeoutSeconds = 600)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $null = Get-ADDomain -ErrorAction Stop
            Write-Log "The directory is answering" -Tag "Ok"
            return $true
        }
        catch {
            Write-Log "Waiting for the directory to answer" -Tag "Info"
            Start-Sleep -Seconds 15
        }
    }
    return $false
}

# Promotion pins ::1 as the IPv6 DNS server on every adapter. Reset the IPv6 side
# back to automatic without touching the IPv4 servers the DC needs.
function Set-Ipv6ClientAutomatic {
    if (-not (Get-Command -Name "Get-NetIPInterface" -ErrorAction SilentlyContinue)) {
        Write-Log "The NetTCPIP module is unavailable - skipping the IPv6 reset" -Tag "Info"
        return
    }

    $interfaces = @(Get-NetIPInterface -AddressFamily IPv6 -ErrorAction SilentlyContinue |
        Where-Object { ($_.ConnectionState -eq "Connected") -and ($_.InterfaceAlias -notlike "Loopback*") })

    if ($interfaces.Count -eq 0) {
        Write-Log "No connected IPv6 interfaces found - nothing to reset" -Tag "Info"
        return
    }

    foreach ($interface in $interfaces) {
        $alias = [string]$interface.InterfaceAlias
        Write-Log "Setting IPv6 on '$alias' back to automatic" -Tag "Run"

        try {
            Set-NetIPInterface -InterfaceIndex $interface.InterfaceIndex -AddressFamily IPv6 -Dhcp Enabled -ErrorAction Stop
        }
        catch {
            Write-Log "DHCPv6 on '$alias': $($_.Exception.Message)" -Tag "Info"
        }

        # Set-DnsClientServerAddress has no address family switch and would clear the
        # IPv4 servers as well, so the IPv6 DNS reset goes through netsh.
        $null = & netsh.exe interface ipv6 set dnsservers name="$alias" source=dhcp 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "netsh could not reset the IPv6 DNS servers on '$alias' (exit $LASTEXITCODE)" -Tag "Info"
        }
    }

    Write-Log "IPv6 client configuration is back on automatic" -Tag "Ok"
}

# ---------------------------[ Post-promotion: site, subnets, time ]---------------------------
# DomainRole 4 = backup DC, 5 = primary DC. Anything lower is not promoted yet.
function Test-DomainControllerRole {
    try {
        $computerSystem = Get-CimInstance -ClassName "Win32_ComputerSystem" -ErrorAction Stop
        return ([int]$computerSystem.DomainRole -ge 4)
    }
    catch {
        Write-Log "Could not read the domain role: $($_.Exception.Message)" -Tag "Info"
        return $false
    }
}

function Import-ActiveDirectoryModule {
    if (Get-Command -Name "Get-ADReplicationSite" -ErrorAction SilentlyContinue) { return }
    try {
        Import-Module -Name "ActiveDirectory" -ErrorAction Stop
    }
    catch {
        throw "The ActiveDirectory module is unavailable: $($_.Exception.Message)"
    }
}

function Rename-DefaultFirstSite {
    param([Parameter(Mandatory)][string]$SiteName)

    $existing = Get-ADReplicationSite -Filter "Name -eq '$SiteName'" -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        Write-Log "Site '$SiteName' already exists - leaving the site layout alone" -Tag "Info"
        return
    }

    $defaultSite = Get-ADReplicationSite -Filter "Name -eq 'Default-First-Site-Name'" -ErrorAction SilentlyContinue
    if ($null -eq $defaultSite) {
        Write-Log "Neither '$SiteName' nor 'Default-First-Site-Name' was found - rename the site manually" -Tag "Info"
        return
    }

    Write-Log "Renaming Default-First-Site-Name to '$SiteName'" -Tag "Run"
    try {
        Rename-ADObject -Identity $defaultSite.DistinguishedName -NewName $SiteName -ErrorAction Stop
    }
    catch {
        throw "Rename-ADObject failed: $($_.Exception.Message)"
    }
    Write-Log "Site renamed" -Tag "Ok"
}

function Add-ReplicationSubnet {
    param(
        [Parameter(Mandatory)][string]$Prefix,
        [Parameter(Mandatory)][string]$SiteName,
        [string]$Description = ""
    )

    $existing = Get-ADReplicationSubnet -Filter "Name -eq '$Prefix'" -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        Write-Log "Subnet '$Prefix' already exists - leaving it alone" -Tag "Info"
        return
    }

    $parameters = @{
        Name        = $Prefix
        Site        = $SiteName
        ErrorAction = "Stop"
    }
    if (-not [string]::IsNullOrWhiteSpace($Description)) { $parameters["Description"] = $Description }

    Write-Log "Creating replication subnet '$Prefix' in site '$SiteName'" -Tag "Run"
    try {
        $null = New-ADReplicationSubnet @parameters
    }
    catch {
        throw "New-ADReplicationSubnet failed for '$Prefix': $($_.Exception.Message)"
    }
    Write-Log "Subnet created" -Tag "Ok"
}

function Set-SiteConfiguration {
    param([object]$Site)

    $siteName = [string](Get-ConfigValue -InputObject $Site -Name "siteName" -Default "")
    if ([string]::IsNullOrWhiteSpace($siteName)) {
        throw "activeDirectory.site.siteName is empty."
    }

    if ([bool](Get-ConfigValue -InputObject $Site -Name "renameDefaultFirstSite" -Default $true)) {
        Rename-DefaultFirstSite -SiteName $siteName
    }
    else {
        Write-Log "Site rename is disabled - only subnets are applied" -Tag "Info"
    }

    $subnets = Get-ConfigArray -InputObject $Site -Name "subnets"
    if ($subnets.Count -eq 0) {
        Write-Log "No subnets defined for site '$siteName'" -Tag "Info"
        return
    }

    foreach ($subnet in $subnets) {
        $prefix = [string](Get-ConfigValue -InputObject $subnet -Name "prefix" -Default "")
        if ([string]::IsNullOrWhiteSpace($prefix)) {
            throw "An activeDirectory.site.subnets entry has an empty prefix."
        }
        $subnetSite = [string](Get-ConfigValue -InputObject $subnet -Name "site" -Default $siteName)
        if ([string]::IsNullOrWhiteSpace($subnetSite)) { $subnetSite = $siteName }
        $description = [string](Get-ConfigValue -InputObject $subnet -Name "description" -Default "")
        Add-ReplicationSubnet -Prefix $prefix -SiteName $subnetSite -Description $description
    }
}

# Only the forest root PDC emulator carries the authoritative time source.
# https://learn.microsoft.com/en-us/services-hub/unified/health/remediation-steps-ad/configure-the-root-pdc-with-an-authoritative-time-source-and-avoid-widespread-time-skew
function Set-AuthoritativeTimeSource {
    param([object]$Ntp)

    $servers = Get-ConfigArray -InputObject $Ntp -Name "servers"
    if ($servers.Count -eq 0) {
        throw "activeDirectory.ntp.servers is empty."
    }

    $domain = Get-ADDomain -ErrorAction Stop
    $pdcHost = [string]$domain.PDCEmulator
    $pdcName = $pdcHost.Split(".")[0]
    if (-not $pdcName.Equals([string]$env:COMPUTERNAME, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Log "This server is not the PDC emulator ($pdcHost) - skipping the time configuration" -Tag "Info"
        return
    }

    $peers = @()
    foreach ($server in $servers) {
        $peer = ([string]$server).Trim()
        if ([string]::IsNullOrWhiteSpace($peer)) { continue }
        if ($peer -notmatch ",0x") { $peer = "$peer,0x8" }
        $peers += $peer
    }
    $peerList = $peers -join " "

    Write-Log "Configuring Windows Time with peers: $peerList" -Tag "Run"
    $null = & w32tm.exe /config "/syncfromflags:manual" "/manualpeerlist:$peerList" "/reliable:yes" "/update" 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "w32tm /config failed with exit code $LASTEXITCODE."
    }

    try {
        Restart-Service -Name "W32Time" -Force -ErrorAction Stop
    }
    catch {
        Write-Log "W32Time restart: $($_.Exception.Message) - continuing with a resync" -Tag "Info"
    }

    # Right after the restart w32tm still reports the local clock until the first poll.
    $source = ""
    $synced = $false
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $null = & w32tm.exe /resync /rediscover 2>&1
        Start-Sleep -Seconds 3
        $source = (& w32tm.exe /query /source 2>&1 | Out-String).Trim()
        if ($source -and ($source -notmatch "Local CMOS Clock|Free-running System Clock")) {
            $synced = $true
            break
        }
        Write-Log "Time source is still '$source' (attempt $attempt of 3)" -Tag "Info"
    }

    if ($synced) {
        Write-Log "Time source is now '$source'" -Tag "Ok"
    }
    else {
        Write-Log "Peers are configured but no poll has succeeded yet (source '$source') - check outbound UDP 123" -Tag "Info"
    }
}

# ---------------------------[ Post-promotion: forest-wide settings ]---------------------------
# The Recycle Bin and the forest UPN suffixes are both writes against forest objects that
# live on the Domain Naming Master, so both need more than a directory that answers: on a
# freshly promoted DC the naming master is this same server, and it refuses either write
# until its initial replication has finished. The symptom is
# "The FSMO role ownership could not be verified because its directory partition has not
# replicated successfully with at least one replication partner", which reads as a broken
# forest rather than a machine that came back too fast.
#
# Neither is ever undone here. The Recycle Bin cannot be switched off at all, and a UPN
# suffix somebody already signs in with is not this script's to withdraw.
$script:addsForestFailure = @()

function Test-DirectoryRecycleBinEnabled {
    $feature = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -ErrorAction Stop
    if ($null -eq $feature) { return $false }
    return (@($feature.EnabledScopes).Count -gt 0)
}

function Wait-ForForestReadiness {
    param([int]$TimeoutSeconds = 300)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastProblem = "the forest did not answer"

    while ((Get-Date) -lt $deadline) {
        try {
            $forest = Get-ADForest -ErrorAction Stop
            $namingMaster = [string]$forest.DomainNamingMaster
            if ([string]::IsNullOrWhiteSpace($namingMaster)) {
                $lastProblem = "the forest has no Domain Naming Master registered"
            }
            else {
                $rootDse = Get-ADRootDSE -Server $namingMaster -ErrorAction Stop
                $isSynchronized = [string]$rootDse.isSynchronized
                if ($isSynchronized -match "(?i)true") {
                    Write-Log "Domain Naming Master $namingMaster is reachable and synchronized" -Tag "Ok"
                    return $true
                }
                $lastProblem = "$namingMaster reports isSynchronized=$isSynchronized"
            }
        }
        catch {
            $lastProblem = $_.Exception.Message
        }

        Write-Log "Waiting for the forest to settle - $lastProblem" -Tag "Info"
        Start-Sleep -Seconds 15
    }

    Write-Log "The forest is still not ready after $TimeoutSeconds seconds - $lastProblem" -Tag "Warn"
    return $false
}

function Enable-DirectoryRecycleBin {
    try {
        if (Test-DirectoryRecycleBinEnabled) {
            Write-Log "The Active Directory Recycle Bin is already enabled" -Tag "Info"
            return $true
        }
    }
    catch {
        Write-Log "Could not read the Recycle Bin optional feature: $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    if (-not (Wait-ForForestReadiness)) {
        Write-Log "Not enabling the Recycle Bin while the forest is unsettled - re-run once replication has finished" -Tag "Warn"
        return $false
    }

    $forest = Get-ADForest -ErrorAction Stop
    Write-Log "Enabling the Active Directory Recycle Bin for forest $($forest.Name) - this cannot be undone" -Tag "Run"
    try {
        Enable-ADOptionalFeature -Identity "Recycle Bin Feature" -Scope "ForestOrConfigurationSet" `
            -Target $forest.Name -Confirm:$false -ErrorAction Stop
    }
    catch {
        Write-Log "Enable-ADOptionalFeature failed: $($_.Exception.Message)" -Tag "Error"
        Write-Log "Re-run this script once replication has settled - the feature is enabled on the next pass" -Tag "Info"
        return $false
    }

    Write-Log "Recycle Bin enabled" -Tag "Ok"
    return $true
}

# One suffix at a time: Set-ADForest refuses the whole write for one bad value, which
# would take the good suffixes in the same call with it and name none of them.
function Add-ForestUpnSuffix {
    param(
        [Parameter(Mandatory)][string]$Suffix,
        [Parameter(Mandatory)][object]$Forest
    )

    $value = $Suffix.Trim().TrimStart("@")
    if ([string]::IsNullOrWhiteSpace($value)) { return $true }

    $forestDomains = @($Forest.Domains | ForEach-Object { [string]$_ })
    if ($forestDomains -contains $value) {
        Write-Log "UPN suffix '$value' is a domain in this forest - every account already has it" -Tag "Info"
        return $true
    }

    $existing = @($Forest.UPNSuffixes | ForEach-Object { [string]$_ })
    if ($existing -contains $value) {
        Write-Log "UPN suffix '$value' is already registered on the forest" -Tag "Info"
        return $true
    }

    Write-Log "Adding UPN suffix '$value' to forest $($Forest.Name)" -Tag "Run"
    try {
        Set-ADForest -Identity $Forest.Name -UPNSuffixes @{ Add = $value } -ErrorAction Stop
    }
    catch {
        Write-Log "Set-ADForest failed for '$value': $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    Write-Log "UPN suffix '$value' added - it can now be set on an account" -Tag "Ok"
    return $true
}

function Set-ForestConfiguration {
    param([object]$Forest)

    if ([bool](Get-ConfigValue -InputObject $Forest -Name "enableRecycleBin" -Default $false)) {
        if (-not (Enable-DirectoryRecycleBin)) {
            $script:addsForestFailure += "Recycle Bin"
        }
    }
    else {
        Write-Log "activeDirectory.forest.enableRecycleBin is off" -Tag "Info"
    }

    $suffixes = Get-ConfigArray -InputObject $Forest -Name "upnSuffixes"
    if ($suffixes.Count -eq 0) {
        Write-Log "No extra UPN suffixes in this design" -Tag "Info"
        return
    }

    # Read once: every Add is against the same forest object, and re-reading it per suffix
    # only invites a lookup landing on a DC that has not seen the previous write yet.
    $forestObject = $null
    try {
        $forestObject = Get-ADForest -ErrorAction Stop
    }
    catch {
        Write-Log "Could not read the forest: $($_.Exception.Message)" -Tag "Error"
        $script:addsForestFailure += "UPN suffixes"
        return
    }

    foreach ($suffix in $suffixes) {
        $value = [string]$suffix
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        if (-not (Add-ForestUpnSuffix -Suffix $value -Forest $forestObject)) {
            $script:addsForestFailure += "UPN suffix $($value.Trim().TrimStart('@'))"
        }
    }
}

# ---------------------------[ Entry Points ]---------------------------
# Everything behind this role - its own site and time settings, and every role
# ordered after it - waits until the promotion reboot has happened.
function Test-AddsRebootPending {
    return (-not (Test-DomainControllerRole))
}

function Invoke-AddsConfiguration {
    param([object]$Config)

    if (Test-DomainControllerRole) {
        return (New-RoleResult -Status "Completed" -Message "This server is already a domain controller - the promotion has nothing left to do")
    }

    $activeDirectory = Get-ConfigValue -InputObject $Config -Name "activeDirectory"

    Write-Log "Starting domain controller promotion - the server restarts when it finishes" -Tag "Info"
    Install-DomainController -ActiveDirectory $activeDirectory
    Write-Log "Promotion command completed" -Tag "Ok"

    # Install-ADDS* restarts the server itself, so this line is only reached when
    # noRebootOnCompletion left the restart to the operator.
    return (New-RoleResult -Status "RebootRequired" -Message "The promotion finished without restarting - noRebootOnCompletion is set")
}

function Invoke-AddsPostReboot {
    param([object]$Config)

    if (-not (Test-DomainControllerRole)) {
        return (New-RoleResult -Status "Failed" -Message "This server is not a domain controller - the promotion did not finish")
    }

    $activeDirectory = Get-ConfigValue -InputObject $Config -Name "activeDirectory"
    $site   = Get-ConfigValue -InputObject $activeDirectory -Name "site"
    $ntp    = Get-ConfigValue -InputObject $activeDirectory -Name "ntp"
    $forest = Get-ConfigValue -InputObject $activeDirectory -Name "forest"

    # Promotion is what pinned ::1 on the adapter, so undoing it belongs to this role
    # and runs whether or not there is a site to configure.
    $ipv6 = Get-ConfigValue -InputObject $activeDirectory -Name "ipv6"
    if (($null -ne $ipv6) -and [bool](Get-ConfigValue -InputObject $ipv6 -Name "setAutomatic" -Default $false)) {
        Set-Ipv6ClientAutomatic
    }

    # Joining an existing forest leaves none of these sections behind - the site layout,
    # the forest time source and the forest-wide settings are already settled there.
    if (($null -eq $site) -and ($null -eq $ntp) -and ($null -eq $forest)) {
        return (New-RoleResult -Status "Completed" -Message "No site, time or forest settings in this config - the directory needed nothing else")
    }

    Import-ActiveDirectoryModule
    if (-not (Wait-ForDirectoryService)) {
        return (New-RoleResult -Status "Failed" -Message "The directory did not answer in time - the follow-up task tries again at the next start")
    }

    $script:addsForestFailure = @()
    if ($null -ne $site)   { Set-SiteConfiguration -Site $site }
    if ($null -ne $ntp)    { Set-AuthoritativeTimeSource -Ntp $ntp }
    if ($null -ne $forest) { Set-ForestConfiguration -Forest $forest }

    # A forest setting that did not land is not a broken server, and every part of this
    # role is idempotent - so it is reported as work outstanding rather than as a failure,
    # and the next run of the same config finishes it.
    if ($script:addsForestFailure.Count -gt 0) {
        return (New-RoleResult -Status "ManualStepRequired" `
            -Message ("Post-promotion configuration applied, but these forest settings did not: " + ($script:addsForestFailure -join ", ") + " - re-run this script once replication has settled"))
    }

    return (New-RoleResult -Status "Completed" -Message "Post-promotion configuration completed")
}
