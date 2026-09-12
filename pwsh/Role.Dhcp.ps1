# Role provider: DHCP Server.
#
# Dot-sourced by Configure-ServerRoles.ps1 - not runnable on its own. Everything
# here lands in that script's scope, so $script: variables and functions are shared
# with every other part. Use $scriptRootPath, never $PSScriptRoot: inside this file
# $PSScriptRoot is the pwsh folder, not the folder the run was started from.

# ===========================[ DHCP Server ]===========================
# Two modes, one config, the same shape the AD DS role uses: **newDeployment** builds the
# first server in a domain - security groups, authorization, server options, scopes - and
# **addServer** puts a second server beside an existing one as its failover partner. The
# second is not a smaller version of the first: it deliberately does *not* create scopes,
# because a failover relationship replicates them from the partner, and a scope typed twice
# is two scopes that agree until somebody edits one.
#
# **Authorization is the step that has no error message worth reading.** An unauthorized
# DHCP server in a domain starts, logs one event, and answers nothing - clients simply do
# not get addresses, and the server looks healthy from every angle except a packet capture.
# Add-DhcpServerInDC is one line and it is the difference between a working server and a
# silent one, so it runs on both modes and its state is reported either way.
#
# **The post-install configuration flag is cosmetic and still worth setting.** Server
# Manager shows "Complete DHCP configuration" until ConfigurationState under the role's
# registry key says otherwise. Nothing breaks while it is unset; somebody re-runs the
# wizard because of it, and the wizard is where a second authorization attempt comes from.

$script:dhcpServiceName = "DHCPServer"

# Server Manager's roles key. 12 is DHCP; 2 means "configured", which is what the wizard
# writes when it finishes.
$script:dhcpRoleRegistryPath = "HKLM:\SOFTWARE\Microsoft\ServerManager\Roles\12"

# The option ids this design names directly. Everything else goes through the extra list,
# where an id and a value are all that can honestly be asked for.
$script:dhcpOptionRouter    = 3
$script:dhcpOptionDnsServer = 6
$script:dhcpOptionDnsDomain = 15
$script:dhcpOptionNtpServer = 42

# ---------------------------[ Module ]---------------------------
function Import-DhcpModule {
    if (Get-Command -Name "Get-DhcpServerv4Scope" -ErrorAction SilentlyContinue) { return $true }
    try {
        Import-Module -Name "DhcpServer" -ErrorAction Stop
        return $true
    }
    catch {
        Write-Log "The DhcpServer module could not be loaded: $($_.Exception.Message)" -Tag "Error"
        Write-Log "    Install-WindowsFeature -Name DHCP -IncludeManagementTools" -Tag "Error"
        return $false
    }
}

# ---------------------------[ Addresses ]---------------------------
# A prefix length is what the studio's shared subnet list carries, because that is how
# people write a network down; a subnet mask is what every DHCP cmdlet takes. One
# conversion, in one place, rather than a mask typed beside the prefix that says the same
# thing and can disagree with it.
function ConvertTo-DhcpSubnetMask {
    param([Parameter(Mandatory)][int]$PrefixLength)

    if (($PrefixLength -lt 0) -or ($PrefixLength -gt 32)) { return "" }

    $bits = 0
    if ($PrefixLength -gt 0) {
        $bits = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, (32 - $PrefixLength)))
    }
    $octets = @(
        [int](($bits -shr 24) -band 255),
        [int](($bits -shr 16) -band 255),
        [int](($bits -shr 8) -band 255),
        [int]($bits -band 255)
    )
    return ($octets -join ".")
}

function Get-DhcpScopeDefinition {
    param([Parameter(Mandatory)][object]$Dhcp)

    $scopes = @()
    foreach ($entry in @(Get-ConfigArray -InputObject $Dhcp -Name "scopes")) {
        $networkId = Get-ConfigText -InputObject $entry -Name "networkId"
        $start     = Get-ConfigText -InputObject $entry -Name "startRange"
        $end       = Get-ConfigText -InputObject $entry -Name "endRange"
        if ([string]::IsNullOrWhiteSpace($networkId) -or [string]::IsNullOrWhiteSpace($start) -or [string]::IsNullOrWhiteSpace($end)) {
            Write-Log "A scope entry is missing its network or its range - skipped" -Tag "Error"
            continue
        }

        $prefix = [int](Get-ConfigValue -InputObject $entry -Name "prefixLength" -Default 24)
        $mask   = Get-ConfigText -InputObject $entry -Name "subnetMask"
        if ([string]::IsNullOrWhiteSpace($mask)) { $mask = ConvertTo-DhcpSubnetMask -PrefixLength $prefix }

        $exclusions = @()
        foreach ($exclusion in @(Get-ConfigArray -InputObject $entry -Name "exclusions")) {
            $exclusionStart = Get-ConfigText -InputObject $exclusion -Name "startRange"
            $exclusionEnd   = Get-ConfigText -InputObject $exclusion -Name "endRange"
            if ([string]::IsNullOrWhiteSpace($exclusionStart) -or [string]::IsNullOrWhiteSpace($exclusionEnd)) { continue }
            $exclusions += [pscustomobject]@{ StartRange = $exclusionStart; EndRange = $exclusionEnd }
        }

        $reservations = @()
        foreach ($reservation in @(Get-ConfigArray -InputObject $entry -Name "reservations")) {
            $address  = Get-ConfigText -InputObject $reservation -Name "ipAddress"
            $clientId = Get-ConfigText -InputObject $reservation -Name "clientId"
            if ([string]::IsNullOrWhiteSpace($address) -or [string]::IsNullOrWhiteSpace($clientId)) { continue }
            $reservations += [pscustomobject]@{
                Name        = Get-ConfigText -InputObject $reservation -Name "name" -Default $address
                IPAddress   = $address
                ClientId    = $clientId
                Description = Get-ConfigText -InputObject $reservation -Name "description"
            }
        }

        $scopes += [pscustomobject]@{
            Name         = Get-ConfigText -InputObject $entry -Name "name" -Default $networkId
            ScopeId      = $networkId
            SubnetMask   = $mask
            PrefixLength = $prefix
            StartRange   = $start
            EndRange     = $end
            Description  = Get-ConfigText -InputObject $entry -Name "description"
            LeaseHours   = [int](Get-ConfigValue -InputObject $entry -Name "leaseDurationHours" -Default 8)
            State        = Get-ConfigText -InputObject $entry -Name "state" -Default "Active"
            Router       = Get-ConfigText -InputObject $entry -Name "router"
            DnsServers   = @(Get-ConfigArray -InputObject $entry -Name "dnsServers" | ForEach-Object { [string]$_ } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            DnsDomain    = Get-ConfigText -InputObject $entry -Name "dnsDomain"
            NtpServers   = @(Get-ConfigArray -InputObject $entry -Name "ntpServers" | ForEach-Object { [string]$_ } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            Extra        = @(Get-ConfigArray -InputObject $entry -Name "extraOptions")
            Exclusions   = $exclusions
            Reservations = $reservations
        }
    }
    return ,$scopes
}

# ---------------------------[ Post-install ]---------------------------
# The two local groups every DHCP server has and nothing else creates. Idempotent by
# design: the cmdlet is happy to be told twice, and the service has to be restarted for
# them to be read, which is why this runs before anything else does.
function Set-DhcpSecurityGroup {
    try {
        Write-Log "Add-DhcpServerSecurityGroup" -Tag "Run"
        Add-DhcpServerSecurityGroup -ErrorAction Stop
        Write-Log "DHCP Administrators and DHCP Users are in place" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "Could not create the DHCP security groups: $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Error"
        return $false
    }
}

function Set-DhcpConfigurationComplete {
    try {
        if (-not (Test-Path -Path $script:dhcpRoleRegistryPath)) {
            Write-Log "Server Manager has no DHCP role key on this machine - nothing to mark" -Tag "Debug"
            return
        }
        Set-ItemProperty -Path $script:dhcpRoleRegistryPath -Name "ConfigurationState" -Value 2 -ErrorAction Stop
        Write-Log "Server Manager no longer asks for the DHCP post-install wizard" -Tag "Debug"
    }
    catch {
        # Cosmetic, and never worth failing a working server over.
        Write-Log "Could not clear Server Manager's DHCP configuration flag: $($_.Exception.Message)" -Tag "Debug"
    }
}

function Restart-DhcpService {
    try {
        Write-Log "Restarting '$script:dhcpServiceName'" -Tag "Run"
        Restart-Service -Name $script:dhcpServiceName -Force -ErrorAction Stop
        Write-Log "'$script:dhcpServiceName' restarted" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "Could not restart '$script:dhcpServiceName': $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

# ---------------------------[ Audit log ]---------------------------
# The lease audit log is the only record of which device held which address at which time,
# and the question it answers - "who was 10.0.10.57 last Tuesday" - is always asked after
# the fact, by which time an unlogged answer is gone for good. On by default; the log
# rolls daily under %windir%\system32\dhcp and manages its own size.
function Set-DhcpAuditLogging {
    param([bool]$Enabled = $true)

    try {
        Set-DhcpServerAuditLog -Enable $Enabled -ErrorAction Stop
        if ($Enabled) { Write-Log "Lease audit logging is on" -Tag "Ok" }
        else { Write-Log "Lease audit logging is off - which device held which address is not being recorded" -Tag "Warn" }
        return $true
    }
    catch {
        Write-Log "Could not configure the audit log: $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Error"
        return $false
    }
}

# ---------------------------[ Authorization ]---------------------------
# The one step whose absence has no symptom other than clients getting no address. A
# server already in the list is left alone; the list is read by DNS name, because that is
# what it stores and an address comparison would re-add a server whose IP has changed.
function Confirm-DhcpAuthorization {
    param([Parameter(Mandatory)][string]$DnsName)

    $registered = @()
    try { $registered = @(Get-DhcpServerInDC -ErrorAction Stop) }
    catch {
        Write-Log "Could not read the authorized DHCP servers: $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Error"
        Write-Log "Authorizing needs Enterprise Admin rights - a server that is not in this list answers no client at all" -Tag "Error"
        return $false
    }

    foreach ($server in $registered) {
        if (([string]$server.DnsName).Equals($DnsName, [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Log "'$DnsName' is already authorized in the directory" -Tag "Info"
            return $true
        }
    }

    try {
        Write-Log "Add-DhcpServerInDC -DnsName $DnsName" -Tag "Run"
        Add-DhcpServerInDC -DnsName $DnsName -ErrorAction Stop
        Write-Log "'$DnsName' is authorized - it will answer clients" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "Could not authorize '$DnsName': $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Error"
        Write-Log "    Until it is authorized the service runs and answers nothing - which looks like a network fault, not a permission" -Tag "Error"
        Write-Log "    Add-DhcpServerInDC -DnsName $DnsName" -Tag "Error"
        return $false
    }
}

# ---------------------------[ Options ]---------------------------
# Router, DNS servers, DNS domain and NTP have named parameters; anything else is an id and
# a value. Both go through here so a scope option and a server option are written the same
# way and reported the same way.
function Set-DhcpOptionValue {
    param(
        [string]$Router = "",
        [string[]]$DnsServers = @(),
        [string]$DnsDomain = "",
        [string[]]$NtpServers = @(),
        [object[]]$Extra = @(),
        [string]$ScopeId = ""
    )

    $scope = "the server"
    $common = @{ ErrorAction = "Stop" }
    if (-not [string]::IsNullOrWhiteSpace($ScopeId)) {
        $common["ScopeId"] = $ScopeId
        $scope = "scope $ScopeId"
    }

    $named = @{}
    if (-not [string]::IsNullOrWhiteSpace($Router))    { $named["Router"] = $Router }
    if (@($DnsServers).Count -gt 0)                    { $named["DnsServer"] = $DnsServers }
    if (-not [string]::IsNullOrWhiteSpace($DnsDomain)) { $named["DnsDomain"] = $DnsDomain }

    $allSet = $true

    if ($named.Count -gt 0) {
        try {
            Set-DhcpServerv4OptionValue @common @named
            $described = @($named.Keys | ForEach-Object { $_ + "=" + (@($named[$_]) -join ",") }) -join " "
            Write-Log "$scope options: $described" -Tag "Ok"
        }
        catch {
            Write-Log "Could not set the options on $scope : $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Error"
            $allSet = $false
        }
    }

    # 042 has no named parameter, and neither does anything in the extra list - both are an
    # id and a value, so they take the same path.
    $byId = @()
    if (@($NtpServers).Count -gt 0) {
        $byId += [pscustomobject]@{ OptionId = $script:dhcpOptionNtpServer; Value = @($NtpServers) }
    }
    foreach ($entry in @($Extra)) {
        $optionId = [int](Get-ConfigValue -InputObject $entry -Name "optionId" -Default 0)
        if ($optionId -le 0) { continue }
        $values = @(Get-ConfigArray -InputObject $entry -Name "value" | ForEach-Object { [string]$_ } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($values.Count -eq 0) { continue }
        $byId += [pscustomobject]@{ OptionId = $optionId; Value = $values }
    }

    foreach ($option in $byId) {
        try {
            Set-DhcpServerv4OptionValue @common -OptionId $option.OptionId -Value $option.Value
            Write-Log "$scope option $($option.OptionId) = $(@($option.Value) -join ',')" -Tag "Ok"
        }
        catch {
            Write-Log "Could not set option $($option.OptionId) on $scope : $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Error"
            $allSet = $false
        }
    }

    return $allSet
}

# ---------------------------[ Scopes ]---------------------------
# A scope that exists keeps its identity and gets its settings re-applied - the range, the
# lease and the state are what change between runs. The **subnet mask is not** re-applied:
# it is part of what a scope *is*, and DHCP refuses to change it on a live scope, so a
# design that disagrees with the server is reported rather than forced.
function Set-DhcpScope {
    param([Parameter(Mandatory)][object]$Scope)

    $existing = $null
    try { $existing = Get-DhcpServerv4Scope -ScopeId $Scope.ScopeId -ErrorAction SilentlyContinue }
    catch { $existing = $null }

    $lease = New-TimeSpan -Hours $Scope.LeaseHours

    if ($null -eq $existing) {
        try {
            Add-DhcpServerv4Scope -Name $Scope.Name -StartRange $Scope.StartRange -EndRange $Scope.EndRange `
                -SubnetMask $Scope.SubnetMask -State $Scope.State -LeaseDuration $lease `
                -Description $Scope.Description -ErrorAction Stop
            Write-Log "Created the scope '$($Scope.Name)' $($Scope.StartRange) - $($Scope.EndRange) / $($Scope.SubnetMask)" -Tag "Ok"
        }
        catch {
            Write-Log "Could not create the scope '$($Scope.Name)': $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Error"
            return $false
        }
    }
    else {
        if (-not ([string]$existing.SubnetMask).Equals($Scope.SubnetMask, [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Log "The scope $($Scope.ScopeId) is /$($Scope.PrefixLength) in the design and $($existing.SubnetMask) on the server" -Tag "Warn"
            Write-Log "A live scope's mask cannot be changed - delete and rebuild it if the design is the right one" -Tag "Warn"
        }
        try {
            Set-DhcpServerv4Scope -ScopeId $Scope.ScopeId -Name $Scope.Name -StartRange $Scope.StartRange `
                -EndRange $Scope.EndRange -State $Scope.State -LeaseDuration $lease `
                -Description $Scope.Description -ErrorAction Stop
            Write-Log "The scope '$($Scope.Name)' already exists - its range, lease and state are re-applied" -Tag "Info"
        }
        catch {
            Write-Log "Could not update the scope '$($Scope.Name)': $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Error"
            return $false
        }
    }

    $allApplied = $true

    # Exclusions are additive and the cmdlet has no "set" verb, so an exclusion that is
    # already there is skipped rather than re-added - adding it twice is an error, not a
    # no-op, and it would fail the whole scope over something already correct.
    $current = @()
    try { $current = @(Get-DhcpServerv4ExclusionRange -ScopeId $Scope.ScopeId -ErrorAction SilentlyContinue) }
    catch { $current = @() }

    foreach ($exclusion in $Scope.Exclusions) {
        $present = $false
        foreach ($entry in $current) {
            if ((([string]$entry.StartRange) -eq $exclusion.StartRange) -and
                (([string]$entry.EndRange) -eq $exclusion.EndRange)) { $present = $true }
        }
        if ($present) {
            Write-Log "The exclusion $($exclusion.StartRange) - $($exclusion.EndRange) is already on $($Scope.ScopeId)" -Tag "Debug"
            continue
        }
        try {
            Add-DhcpServerv4ExclusionRange -ScopeId $Scope.ScopeId -StartRange $exclusion.StartRange `
                -EndRange $exclusion.EndRange -ErrorAction Stop
            Write-Log "Excluded $($exclusion.StartRange) - $($exclusion.EndRange) from $($Scope.ScopeId)" -Tag "Ok"
        }
        catch {
            Write-Log "Could not exclude $($exclusion.StartRange) - $($exclusion.EndRange): $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Error"
            $allApplied = $false
        }
    }

    foreach ($reservation in $Scope.Reservations) {
        $existingReservation = $null
        try {
            $existingReservation = Get-DhcpServerv4Reservation -ScopeId $Scope.ScopeId -IPAddress $reservation.IPAddress -ErrorAction SilentlyContinue
        }
        catch { $existingReservation = $null }

        try {
            if ($null -eq $existingReservation) {
                Add-DhcpServerv4Reservation -ScopeId $Scope.ScopeId -IPAddress $reservation.IPAddress `
                    -ClientId $reservation.ClientId -Name $reservation.Name -Description $reservation.Description -ErrorAction Stop
                Write-Log "Reserved $($reservation.IPAddress) for $($reservation.ClientId) ('$($reservation.Name)')" -Tag "Ok"
            }
            else {
                Set-DhcpServerv4Reservation -IPAddress $reservation.IPAddress -ClientId $reservation.ClientId `
                    -Name $reservation.Name -Description $reservation.Description -ErrorAction Stop
                Write-Log "The reservation for $($reservation.IPAddress) is re-applied" -Tag "Debug"
            }
        }
        catch {
            Write-Log "Could not reserve $($reservation.IPAddress): $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Error"
            $allApplied = $false
        }
    }

    if (-not (Set-DhcpOptionValue -Router $Scope.Router -DnsServers $Scope.DnsServers -DnsDomain $Scope.DnsDomain `
        -NtpServers $Scope.NtpServers -Extra $Scope.Extra -ScopeId $Scope.ScopeId)) {
        $allApplied = $false
    }

    return $allApplied
}

# ---------------------------[ The registration account ]---------------------------
# **A DHCP server has no identity of its own worth registering records with.** Left alone
# it writes them as the machine account, which makes every record that server's property -
# and the moment a second DHCP server tries to update one, it cannot. The fix is one plain
# domain user that both servers register as, set with Set-DhcpServerDnsCredential.
#
# The account needs **no privilege at all**. It is not a DnsAdmin, it is not in
# DnsUpdateProxy (which is a documented weakening, not a requirement), and it does not log
# on anywhere. Its whole job is to be a consistent owner for the records DHCP writes.
#
# Creating it is a directory write, so it follows the same split as every group in this
# toolbox: on a domain controller this run creates it, and anywhere else it is a
# prerequisite with the New-ADUser line printed.
function Get-DhcpServiceAccount {
    param([object]$Dhcp)

    $dns = Get-ConfigValue -InputObject $Dhcp -Name "dnsUpdate"
    if ($null -eq $dns) { return $null }
    $account = Get-ConfigValue -InputObject $dns -Name "serviceAccount"
    if ($null -eq $account) { return $null }

    # 'create' is what the key was called while the switch asked a narrower question.
    $enabled = Get-ConfigValue -InputObject $account -Name "enabled" -Default $null
    if ($null -eq $enabled) { $enabled = Get-ConfigValue -InputObject $account -Name "create" -Default $true }
    if (-not [bool]$enabled) { return $null }

    $sam = Get-ConfigText -InputObject $account -Name "samAccountName"
    if ([string]::IsNullOrWhiteSpace($sam)) { return $null }

    return [pscustomobject]@{
        SamAccountName     = $sam
        DisplayName        = Get-ConfigText -InputObject $account -Name "displayName" -Default ("Service - " + $sam)
        Password           = Get-ConfigText -InputObject $account -Name "password"
        OrganizationalUnit = Get-ConfigText -InputObject $account -Name "organizationalUnit"
    }
}

function Find-DhcpServiceAccount {
    param([Parameter(Mandatory)][string]$SamAccountName)

    $domainDn = Get-AdcsDefaultNamingContext
    $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDn")
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$(ConvertTo-AdcsLdapFilterValue -Value $SamAccountName)))"
    $null = $searcher.PropertiesToLoad.Add("distinguishedName")
    return $searcher.FindOne()
}

# Created, or adopted exactly as it is. **An existing account's password is never reset** -
# that is somebody's account and something else may already be using it, and a run that
# quietly changed it would break whatever that was while reporting success.
function New-DhcpServiceAccount {
    param(
        [Parameter(Mandatory)][object]$Account,
        # The SCEP tier creates its NDES account through this same function - the
        # rules (adopt-never-reset, password-required, disabled-until-password) are
        # the point, and only the description differs.
        [string]$Description = "DHCP dynamic DNS registration - no interactive logon",
        # "Account is sensitive and cannot be delegated" (ADS_UF_NOT_DELEGATED). Asked
        # for by the caller rather than applied to every account here, because the two
        # callers are not in the same position: the DHCP registration credential is
        # handed to every DHCP server in the domain and lives entirely inside it, while
        # the NDES one runs an application pool on a machine published to the internet
        # through a reverse proxy. That is precisely the account nobody should be able
        # to delegate, and NDES security guidance names this setting outright.
        [switch]$Sensitive
    )

    $existing = $null
    try { $existing = Find-DhcpServiceAccount -SamAccountName $Account.SamAccountName } catch { $existing = $null }
    if ($null -ne $existing) {
        Write-Log "The account '$($Account.SamAccountName)' already exists - left as it is, password included" -Tag "Info"
        # Reported, never corrected. An account somebody else made is theirs, and
        # flipping a userAccountControl bit on it is a change to an object this run did
        # not create - the same rule that stops it resetting the password. Saying so is
        # the useful half.
        if ($Sensitive) {
            $flags = 0
            try { $flags = [int]$existing.Properties["useraccountcontrol"][0] } catch { $flags = 0 }
            if (($flags -band 1048576) -eq 0) {
                Write-Log "'$($Account.SamAccountName)' is NOT marked 'sensitive and cannot be delegated' - this run did not create it, so it is reported, not changed" -Tag "Warn"
                Write-Log "    Set-ADUser '$($Account.SamAccountName)' -AccountNotDelegated `$true" -Tag "Warn"
            }
        }
        return $true
    }

    if ([string]::IsNullOrWhiteSpace($Account.Password)) {
        Write-Log "The account '$($Account.SamAccountName)' does not exist and the design carries no password for it" -Tag "Error"
        Write-Log "Export the design with secrets included, or create the account by hand" -Tag "Error"
        return $false
    }

    $container = $Account.OrganizationalUnit
    if ([string]::IsNullOrWhiteSpace($container)) {
        $container = "CN=Users," + (Get-AdcsDefaultNamingContext)
    }

    $domain = [string]$env:USERDNSDOMAIN
    try {
        $parent = Get-AdcsDirectoryEntry -DistinguishedName $container
        $user = $parent.Children.Add("CN=$(ConvertTo-AdcsRdnValue -Value $Account.DisplayName)", "user")
        $user.Properties["sAMAccountName"].Value = $Account.SamAccountName
        $user.Properties["displayName"].Value = $Account.DisplayName
        if (-not [string]::IsNullOrWhiteSpace($domain)) {
            $user.Properties["userPrincipalName"].Value = "{0}@{1}" -f $Account.SamAccountName, $domain
        }
        $user.Properties["description"].Value = $Description
        # Committed disabled, which is what the directory does with a user carrying no
        # password: the password cannot be set on an object that does not exist yet.
        $user.CommitChanges()

        $user.Invoke("SetPassword", $Account.Password)
        # 512 normal account + 65536 password never expires. A password this run generated
        # and nobody types has no business having an expiry that breaks DNS registration
        # ninety days later, in a way whose symptom is stale records rather than an error.
        # 512 normal account + 65536 password never expires, and 1048576 - "sensitive and
        # cannot be delegated" - when the caller asked for it.
        $uac = 512 -bor 65536
        if ($Sensitive) { $uac = $uac -bor 1048576 }
        $user.Properties["userAccountControl"].Value = $uac
        $user.CommitChanges()

        Write-Log "Created '$($Account.DisplayName)' ($($Account.SamAccountName)) in $container" -Tag "Ok"
        Write-Log "A standard user: no group membership, no privilege, no permission on any DNS zone" -Tag "Debug"
        if ($Sensitive) {
            Write-Log "Marked 'sensitive and cannot be delegated' - no service may impersonate it onward" -Tag "Ok"
        }
        Write-Log "Give every DHCP server in the domain this same credential, so each can update the records the others wrote" -Tag "Info"
        return $true
    }
    catch {
        Write-Log "Could not create '$($Account.SamAccountName)' in ${container}: $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Error"
        return $false
    }
}

function Set-DhcpRegistrationCredential {
    param([Parameter(Mandatory)][object]$Account)

    if ([string]::IsNullOrWhiteSpace($Account.Password)) {
        Write-Log "No password for '$($Account.SamAccountName)' in the design - the registration credential is not set" -Tag "Error"
        Write-Log "    Set-DhcpServerDnsCredential -Credential (Get-Credential)" -Tag "Error"
        return $false
    }

    $domain = [string]$env:USERDOMAIN
    $user = $Account.SamAccountName
    if (-not [string]::IsNullOrWhiteSpace($domain)) { $user = "{0}\{1}" -f $domain, $Account.SamAccountName }

    try {
        $secure = ConvertTo-SecureString -String $Account.Password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($user, $secure)
        # No -Force here: the cmdlet does not have one (it never prompts), and passing it
        # is a ParameterBindingException on a real server - which is exactly how this
        # line failed in the field while every parse and analyzer pass stayed green.
        Write-Log "Set-DhcpServerDnsCredential -Credential $user" -Tag "Run"
        Set-DhcpServerDnsCredential -Credential $credential -ErrorAction Stop
        Write-Log "DHCP registers DNS records as '$user'" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "Could not set the DNS registration credential: $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Error"
        Write-Log "Without it this server owns every record it writes and a second DHCP server cannot update them" -Tag "Error"
        return $false
    }
}

# ---------------------------[ DNS registration ]---------------------------
function Set-DhcpDnsSetting {
    param([object]$Dhcp)

    $dns = Get-ConfigValue -InputObject $Dhcp -Name "dnsUpdate"
    if ($null -eq $dns) { return $true }

    # Always, not Windows' own OnClientRequest: OnClientRequest leaves the A record to the
    # client, and anything without a computer account in AD - Entra-joined, Linux, phones -
    # cannot write into a secure-only zone at all, so it never resolves by name. Together
    # with UpdateDnsRRForOlderClients (some devices never send option 81 at all), DHCP
    # registers on every client's behalf and the service account owns the records.
    $arguments = @{ ErrorAction = "Stop" }
    $arguments["DynamicUpdates"] = Get-ConfigText -InputObject $dns -Name "dynamicUpdates" -Default "Always"
    $arguments["DeleteDnsRROnLeaseExpiry"] = [bool](Get-ConfigValue -InputObject $dns -Name "deleteDnsRROnLeaseExpiry" -Default $true)
    $arguments["UpdateDnsRRForOlderClients"] = [bool](Get-ConfigValue -InputObject $dns -Name "updateDnsRRForOlderClients" -Default $true)
    $arguments["NameProtection"] = [bool](Get-ConfigValue -InputObject $dns -Name "nameProtection" -Default $false)

    try {
        Set-DhcpServerv4DnsSetting @arguments
        Write-Log "DNS registration: $($arguments['DynamicUpdates']), name protection $($arguments['NameProtection'])" -Tag "Ok"
    }
    catch {
        Write-Log "Could not apply the DNS registration settings: $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Error"
        return $false
    }

    $account = Get-DhcpServiceAccount -Dhcp $Dhcp
    if ($null -eq $account) {
        Write-Log "No registration account in the design - DHCP writes DNS records as this machine account" -Tag "Warn"
        Write-Log "Every record is then owned by this server alone, so a second DHCP server cannot update them" -Tag "Warn"
        if (Test-StudioDomainController) {
            Write-Log "On a domain controller it registers with the DC's own credentials, which carry full rights over every zone" -Tag "Warn"
        }
        return $true
    }

    # The account is created by the domain controller half of this role - see
    # Invoke-DhcpConfiguration. Here it is a prerequisite, the same rule the file server and
    # printer groups follow.
    $found = $null
    try { $found = Find-DhcpServiceAccount -SamAccountName $account.SamAccountName } catch { $found = $null }
    if ($null -eq $found) {
        Write-Log "Registration account '$($account.SamAccountName)' missing - run this config on a domain controller first, or create it by hand" -Tag "Error"
        Write-Log "    New-ADUser -Name '$($account.DisplayName)' -SamAccountName '$($account.SamAccountName)' -Enabled `$true -PasswordNeverExpires `$true -AccountPassword (Read-Host -AsSecureString)" -Tag "Error"
        return $false
    }

    return (Set-DhcpRegistrationCredential -Account $account)
}

# ---------------------------[ Failover ]---------------------------
# The addServer mode's whole job. The scopes come from the partner rather than from this
# design on purpose: a failover relationship replicates them, and a scope described twice
# is two scopes that agree only until somebody edits one of them.
#
# THE CMDLET RUNS AGAINST THE PARTNER, NOT AGAINST THIS SERVER, and that is not a style
# choice - it is the only direction that works. Microsoft: "The ScopeId parameter value
# specified on the source DHCP server service, or local computer that runs the DHCP
# server service is identically setup on the partner DHCP server service." The acting
# server is the one that HOLDS the scopes; the partner is the one they are created on.
#
# This server is the new one and holds nothing. Run locally with -PartnerServer pointing
# at the existing server and the scope list read from it, and the cmdlet is being told to
# create those scopes ON THE EXISTING SERVER - which already has them:
#
#     Scope 10.1.0.0 already exists on the server dhcp-01.ad.migolf.io   (bench 2026-09-05)
#
# So -ComputerName is the partner and -PartnerServer is this machine. Two parameters
# invert with it, because both are documented relative to the LOCAL/-ComputerName server
# and that is now the other end:
#
#     -ServerRole            "the role of the local DHCP server service", so the design's
#                            "this server is Standby" has to be sent as Active - the role
#                            of the server the cmdlet is acting on.
#     -LoadBalancePercent    "served by the local ... service. The remaining requests
#                            would be served by the partner", so this server's share
#                            goes out as 100 minus itself.
#
# Getting either wrong builds a relationship that works and is backwards, which is the
# worst outcome available here: nothing fails, and the wrong server carries the load.
function Set-DhcpFailover {
    param(
        [Parameter(Mandatory)][object]$Dhcp,
        [Parameter(Mandatory)][string]$DnsName
    )

    $failover = Get-ConfigValue -InputObject $Dhcp -Name "failover"
    if ($null -eq $failover) {
        Write-Log "No failover block in the design - this server is authorized and has no relationship" -Tag "Info"
        return $true
    }

    $partner = Get-ConfigText -InputObject $failover -Name "partnerServer"
    if ([string]::IsNullOrWhiteSpace($partner)) {
        Write-Log "failover.partnerServer is empty - name the server this one partners with" -Tag "Error"
        return $false
    }

    $name = Get-ConfigText -InputObject $failover -Name "name" -Default ("{0}-{1}" -f ($DnsName -split "\.")[0], ($partner -split "\.")[0])

    # Asked of BOTH ends. The relationship lands on both once it is created, but a
    # half-finished earlier attempt can leave it on the partner alone - and then the
    # local check says "not there", the cmdlet says "already exists", and the run reports
    # a failure that is really a success from last time.
    $existing = $null
    try { $existing = Get-DhcpServerv4Failover -Name $name -ErrorAction SilentlyContinue }
    catch { $existing = $null }
    if ($null -eq $existing) {
        try { $existing = Get-DhcpServerv4Failover -ComputerName $partner -Name $name -ErrorAction SilentlyContinue }
        catch { $existing = $null }
        if ($null -ne $existing) {
            Write-Log "The failover relationship '$name' already exists on '$partner' - it was created by an earlier run" -Tag "Info"
        }
    }
    if ($null -ne $existing) {
        Write-Log "The failover relationship '$name' already exists with $($existing.PartnerServer)" -Tag "Info"
        return $true
    }

    # Whatever the partner is serving is what this relationship covers. Read from the
    # partner rather than from the design, for the reason in the header.
    $scopeIds = @(Get-ConfigArray -InputObject $failover -Name "scopes" | ForEach-Object { [string]$_ } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($scopeIds.Count -eq 0) {
        try {
            $scopeIds = @(Get-DhcpServerv4Scope -ComputerName $partner -ErrorAction Stop | ForEach-Object { [string]$_.ScopeId })
            Write-Log "$($scopeIds.Count) scope(s) read from $partner" -Tag "Info"
        }
        catch {
            Write-Log "Could not read the scopes on '$partner': $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Error"
            Write-Log "This run needs DHCP administrator rights on the partner - the relationship is created from here" -Tag "Error"
            return $false
        }
    }
    if ($scopeIds.Count -eq 0) {
        Write-Log "'$partner' serves no scope - there is nothing to fail over yet" -Tag "Error"
        return $false
    }

    # The partner is the server the cmdlet acts on, because it is the one holding the
    # scopes; this machine is what gets named as the partner. See the header.
    $arguments = @{
        ComputerName  = $partner
        Name          = $name
        PartnerServer = $DnsName
        ScopeId       = $scopeIds
        ErrorAction   = "Stop"
    }

    $secret = Get-ConfigText -InputObject $failover -Name "sharedSecret"
    if (-not [string]::IsNullOrWhiteSpace($secret)) { $arguments["SharedSecret"] = $secret }

    $lead = Get-ConfigText -InputObject $failover -Name "maxClientLeadTime"
    if (-not [string]::IsNullOrWhiteSpace($lead)) { $arguments["MaxClientLeadTime"] = [timespan]::Parse($lead) }

    # Both of these are documented against the LOCAL server, which is the partner now,
    # so both are inverted on the way out. The design always states THIS server's half.
    $mode = Get-ConfigText -InputObject $failover -Name "mode" -Default "LoadBalance"
    if ($mode -eq "HotStandby") {
        $thisRole = Get-ConfigText -InputObject $failover -Name "serverRole" -Default "Standby"
        $partnerRole = if ($thisRole -eq "Active") { "Standby" } else { "Active" }
        $arguments["ServerRole"] = $partnerRole
        Write-Log "This server is the $thisRole half, so '$partner' is sent as $partnerRole" -Tag "Debug"
        $arguments["ReservePercent"] = [int](Get-ConfigValue -InputObject $failover -Name "reservePercent" -Default 5)
        $switch = Get-ConfigText -InputObject $failover -Name "stateSwitchInterval"
        if (-not [string]::IsNullOrWhiteSpace($switch)) {
            $arguments["AutoStateTransition"] = $true
            $arguments["StateSwitchInterval"] = [timespan]::Parse($switch)
        }
    }
    else {
        $thisShare = [int](Get-ConfigValue -InputObject $failover -Name "loadBalancePercent" -Default 50)
        $arguments["LoadBalancePercent"] = 100 - $thisShare
        Write-Log "This server takes $thisShare%, so '$partner' is sent $(100 - $thisShare)%" -Tag "Debug"
    }

    try {
        # -Force is real on this cmdlet - it suppresses the confirmation a plain-text
        # shared secret raises - but it is probed rather than assumed, because assuming
        # one on Set-DhcpServerDnsCredential is exactly how a run failed in the field.
        if ((Get-Command -Name "Add-DhcpServerv4Failover").Parameters.ContainsKey("Force")) {
            $arguments["Force"] = $true
        }
        Write-Log "Add-DhcpServerv4Failover -ComputerName $partner -Name $name -PartnerServer $DnsName ($mode, $($scopeIds.Count) scope(s))" -Tag "Run"
        Add-DhcpServerv4Failover @arguments
        Write-Log "The failover relationship '$name' is up with $partner" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "Could not create the failover relationship '$name': $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Error"
        Write-Log "Both servers must be authorized, reachable by name, and their clocks within a minute of each other" -Tag "Error"
        Write-Log "    The relationship is built on '$partner' - this run needs DHCP administrator rights there, not only here" -Tag "Error"
        return $false
    }
}

# ---------------------------[ Prerequisites ]---------------------------
# Is there a DHCP server on this machine at all? The service is the honest question - the
# module ships with the management tools and answers yes on a workstation with RSAT.
function Test-DhcpInstalled {
    return ($null -ne (Get-Service -Name $script:dhcpServiceName -ErrorAction SilentlyContinue))
}

function Test-DhcpPrerequisite {
    param([object]$Config)

    $dhcp = Get-ConfigValue -InputObject $Config -Name "dhcp"
    if ($null -eq $dhcp) { return $true }

    # The directory half. A domain controller with no DHCP server on it is a perfectly good
    # machine to carry this config to - it is the one that can write the registration
    # account - and demanding the DHCP feature there would refuse the trip that exists to
    # prepare for the DHCP server's own run. Same split as the file server and printers.
    if ((Test-StudioDomainController) -and (-not (Test-DhcpInstalled))) {
        Write-Log "Domain controller with no DHCP server - this run does the directory half only" -Tag "Info"
        return $true
    }

    $passed = $true
    if (-not (Test-DhcpInstalled)) {
        Write-Log "The DHCP Server role is not installed on this machine" -Tag "Error"
        Write-Log "    Install-WindowsFeature -Name DHCP -IncludeManagementTools" -Tag "Error"
        $passed = $false
    }
    if (-not (Import-DhcpModule)) { $passed = $false }

    # Authorization is a directory write, so a workgroup machine cannot do it - and an
    # unauthorized server in a domain answers nothing at all. Both are worth saying before
    # anything is built rather than after.
    $domain = [string]$env:USERDNSDOMAIN
    if ([string]::IsNullOrWhiteSpace($domain)) {
        Write-Log "Not domain joined - a DHCP server outside a domain needs no authorization, and this run does not attempt it" -Tag "Warn"
    }

    $mode = Get-ConfigText -InputObject $dhcp -Name "mode" -Default "newDeployment"
    if ($mode -eq "addServer") {
        $failover = Get-ConfigValue -InputObject $dhcp -Name "failover"
        $partner  = Get-ConfigText -InputObject $failover -Name "partnerServer"
        if ([string]::IsNullOrWhiteSpace($partner)) {
            Write-Log "The design adds this server to an existing deployment but names no partner server" -Tag "Error"
            $passed = $false
        }
        elseif (@(Get-ConfigArray -InputObject $dhcp -Name "scopes").Count -gt 0) {
            Write-Log "Scopes listed on an 'add server' design are ignored - a failover relationship replicates the partner's" -Tag "Warn"
        }
    }
    else {
        foreach ($scope in (Get-DhcpScopeDefinition -Dhcp $dhcp)) {
            if ([string]::IsNullOrWhiteSpace($scope.SubnetMask)) {
                Write-Log "The scope '$($scope.Name)' has no usable subnet mask - prefixLength $($scope.PrefixLength) is out of range" -Tag "Error"
                $passed = $false
            }
        }
    }

    return $passed
}

# ---------------------------[ Entry point ]---------------------------
function Invoke-DhcpConfiguration {
    param([object]$Config)

    $dhcp = Get-ConfigValue -InputObject $Config -Name "dhcp"
    if ($null -eq $dhcp) {
        return (New-RoleResult -Status "Failed" -Message "config.json has no dhcp section")
    }

    # The directory half. Same config, different machine, different job: the DNS
    # registration account is a user object, and writing one is a domain controller's to do.
    # Carry the config there first, then to the DHCP server, which finds the account waiting
    # and only has to point at it. A domain controller that *is* the DHCP server falls
    # through and does both, in that order.
    if (-not (Test-DhcpInstalled)) {
        if (-not (Test-StudioDomainController)) {
            return (New-RoleResult -Status "Failed" -Message "The DHCP Server role is not installed on this machine")
        }

        $account = Get-DhcpServiceAccount -Dhcp $dhcp
        if ($null -eq $account) {
            return (New-RoleResult -Status "Completed" -Message "No registration account is designed - there is nothing for a domain controller to create")
        }

        Write-Log "Domain controller: creating the DNS registration account" -Tag "Run"
        if (-not (New-DhcpServiceAccount -Account $account)) {
            return (New-RoleResult -Status "ManualStepRequired" -Message "The DNS registration account could not be created - fix the error above and re-run")
        }
        return (New-RoleResult -Status "Completed" -Message ("'{0}' is ready - run the same config on the DHCP server for the scopes themselves" -f $account.SamAccountName))
    }

    if (-not (Import-DhcpModule)) {
        return (New-RoleResult -Status "Failed" -Message "The DhcpServer module is not available on this server")
    }

    # A domain controller that is also the DHCP server writes the account itself, first -
    # nothing else here can, and everything below it depends on the account existing.
    if (Test-StudioDomainController) {
        $account = Get-DhcpServiceAccount -Dhcp $dhcp
        if ($null -ne $account) {
            Write-Log "This DHCP server is a domain controller - creating the registration account here" -Tag "Run"
            $null = New-DhcpServiceAccount -Account $account
        }
    }

    $mode = Get-ConfigText -InputObject $dhcp -Name "mode" -Default "newDeployment"
    $dnsName = [string]$env:COMPUTERNAME
    $domain  = [string]$env:USERDNSDOMAIN
    if (-not [string]::IsNullOrWhiteSpace($domain)) { $dnsName = "{0}.{1}" -f $env:COMPUTERNAME, $domain }

    $failures = @()

    # Both modes: groups, flag and audit logging first, the restart later. Three of the
    # settings this run writes - the security groups, the audit log and the DNS
    # registration credential - are read by the service at startup, and the first
    # version restarted between them, so the console showed "Please restart the DHCP
    # server service for the new setting to take effect" immediately after a restart.
    # Everything that wants the restart is written first, then the service bounces once.
    if ([bool](Get-ConfigValue -InputObject $dhcp -Name "securityGroups" -Default $true)) {
        if (-not (Set-DhcpSecurityGroup)) { $failures += "security groups" }
    }
    Set-DhcpConfigurationComplete

    if (-not (Set-DhcpAuditLogging -Enabled ([bool](Get-ConfigValue -InputObject $dhcp -Name "auditLogging" -Default $true)))) {
        $failures += "audit logging"
    }

    if ([bool](Get-ConfigValue -InputObject $dhcp -Name "authorize" -Default $true)) {
        if ([string]::IsNullOrWhiteSpace($domain)) {
            Write-Log "Not domain joined - there is no directory to authorize in, and none is needed" -Tag "Info"
        }
        elseif (-not (Confirm-DhcpAuthorization -DnsName $dnsName)) {
            $failures += "authorization"
        }
    }
    else {
        Write-Log "authorize is false - this server is not registered in the directory and will answer no client until it is" -Tag "Warn"
    }

    $attempts = [int](Get-ConfigValue -InputObject $dhcp -Name "conflictDetectionAttempts" -Default 0)
    if ($attempts -gt 0) {
        try {
            Set-DhcpServerSetting -ConflictDetectionAttempts $attempts -ErrorAction Stop
            Write-Log "Conflict detection: $attempts ping(s) before an address is handed out" -Tag "Ok"
        }
        catch {
            Write-Log "Could not set conflict detection: $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Error"
            $failures += "conflict detection"
        }
    }

    if ($mode -eq "addServer") {
        # Everything the service reads at startup is in place - one bounce, then the
        # failover relationship is built against a service running on the new settings.
        if (-not (Restart-DhcpService)) { $failures += "service restart" }

        if (-not (Set-DhcpFailover -Dhcp $dhcp -DnsName $dnsName)) { $failures += "failover" }

        if ($failures.Count -gt 0) {
            return (New-RoleResult -Status "ManualStepRequired" -Message ("These did not complete: " + (($failures | Select-Object -Unique) -join ", ") + "."))
        }
        return (New-RoleResult -Status "Completed" -Message "This server is authorized and partnered with the existing deployment.")
    }

    if (-not (Set-DhcpDnsSetting -Dhcp $dhcp)) { $failures += "DNS registration" }

    # The one restart, now that the groups, the audit log and the credential are all
    # written - each is read at startup, and bouncing earlier meant the service came up
    # still ignorant of whichever setting landed after it.
    if (-not (Restart-DhcpService)) { $failures += "service restart" }

    $serverOptions = Get-ConfigValue -InputObject $dhcp -Name "serverOptions"
    if ($null -ne $serverOptions) {
        $applied = Set-DhcpOptionValue `
            -DnsServers @(Get-ConfigArray -InputObject $serverOptions -Name "dnsServers" | ForEach-Object { [string]$_ } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) `
            -DnsDomain (Get-ConfigText -InputObject $serverOptions -Name "dnsDomain") `
            -NtpServers @(Get-ConfigArray -InputObject $serverOptions -Name "ntpServers" | ForEach-Object { [string]$_ } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) `
            -Extra @(Get-ConfigArray -InputObject $serverOptions -Name "extra")
        if (-not $applied) { $failures += "server options" }
    }

    $scopes = Get-DhcpScopeDefinition -Dhcp $dhcp
    if ($scopes.Count -eq 0) {
        Write-Log "No scope is designed - the server is authorized and hands out nothing yet" -Tag "Info"
    }
    foreach ($scope in $scopes) {
        if (-not (Set-DhcpScope -Scope $scope)) { $failures += $scope.Name }
    }

    if ($failures.Count -gt 0) {
        return (New-RoleResult -Status "ManualStepRequired" -Message ("These did not complete: " + (($failures | Select-Object -Unique) -join ", ") + "."))
    }
    return (New-RoleResult -Status "Completed" -Message ("{0} scope(s) served by {1}." -f $scopes.Count, $dnsName))
}
