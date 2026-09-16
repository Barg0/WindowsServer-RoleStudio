# Role provider part: the SCEP / NDES tier of Active Directory Certificate Services.
#
# Dot-sourced by Configure-ServerRoles.ps1 - not runnable on its own. Everything
# here lands in that script's scope, so $script: variables and functions are shared
# with every other part. Use $scriptRootPath, never $PSScriptRoot: inside this file
# $PSScriptRoot is the pwsh folder, not the folder the run was started from.

# ===========================[ SCEP / NDES tier ]===========================
# The fourth machine of the certificateServices design: the box that runs the
# Network Device Enrollment Service and, later, the Certificate Connector for
# Microsoft Intune. Microsoft's own placement rules make it a machine of its own -
# the connector is not supported on the issuing CA, and NDES must not run on a
# domain controller - so it dispatches by computer name exactly like the other
# three tiers.
#
# The split of work follows the design's usual lines:
#   directory tier   creates svc.scep, the 'Certificate - SCEP' group, and puts the
#                    account in it (and, when asked, into the certificate managers
#                    role group for revocation)
#   issuing tier     builds and publishes the SCEP template like any other template
#   this tier        configures NDES itself: the MSCEP registry, the request size
#                    limits, IIS, the TLS binding, and proves the endpoint answers
#
# This tier INSTALLS what it needs, and is the second role in this project allowed
# to (Exchange is the first). The house rule - configure, never install - exists so
# that "which roles is this server for" stays a decision somebody made in Server
# Manager rather than one a config file made for them. That reasoning does not
# survive contact with this particular machine: NDES is not one feature, it is a
# role service plus IIS plus six of its role services plus three .NET features, in
# an order, and every one of them is a prerequisite of the NDES configuration step
# that follows in the same run. A design that lists them and then refuses to act on
# them is a checklist, and the person holding it types the same line this file
# already knows. Unlike Exchange there is no switch: a server carrying this tier is
# a server built for it.
#
# What stays manual, and none of it is a choice this script gets to make:
#   - Desktop Experience. The connector requires it and a Server Core installation
#     cannot be converted after the fact, so this is a refusal, not a fix.
#   - installing the Certificate Connector for Microsoft Intune. The download lives
#     behind the tenant (Tenant administration > Connectors and tokens) and the
#     configuration is an interactive Entra sign-in as an Intune Administrator.
#     There is no unattended path, and inventing one would mean holding tenant
#     credentials in a config file.
#   - publishing the NDES URL through a reverse proxy, with pre-authentication set
#     to passthrough and a ~40 KB URL allowed.
#   - MSCEP\EnforcePassword. The Intune policy module replaces the static SCEP
#     challenge with a signed blob, and the moment that value opens the endpoint
#     belongs to the connector install, not to this run. A bare NDES with
#     EnforcePassword=0 is an open enrollment endpoint - this script never
#     creates that state.

# Microsoft's own list, in installation order, each with the reason it is here -
# see the Certificate Connector prerequisites and 'Configure infrastructure to
# support SCEP'. Kept as objects rather than a bare name array because a feature
# that fails should be reported by what it was for, not by its feature id.
$script:adcsScepFeature = @(
    [pscustomobject]@{ Name = "Web-Server";              Why = "IIS itself - NDES is an ISAPI extension living inside it" }
    [pscustomobject]@{ Name = "Web-Filtering";           Why = "Request filtering, which is also where the 65534 URL limit is set" }
    [pscustomobject]@{ Name = "Web-Net-Ext45";           Why = ".NET Extensibility 4.7" }
    [pscustomobject]@{ Name = "Web-Asp-Net45";           Why = "ASP.NET 4.7" }
    [pscustomobject]@{ Name = "Web-Mgmt-Console";        Why = "The IIS management console" }
    [pscustomobject]@{ Name = "Web-Mgmt-Compat";         Why = "IIS 6 management compatibility" }
    [pscustomobject]@{ Name = "Web-Metabase";            Why = "IIS 6 metabase compatibility - NDES reads it" }
    [pscustomobject]@{ Name = "Web-WMI";                 Why = "IIS 6 WMI compatibility" }
    [pscustomobject]@{ Name = "NET-Framework-45-Core";   Why = ".NET Framework 4.7" }
    [pscustomobject]@{ Name = "NET-Framework-45-ASPNET"; Why = "ASP.NET 4.7 under the framework" }
    [pscustomobject]@{ Name = "NET-WCF-HTTP-Activation45"; Why = "WCF HTTP activation, which the connector service uses" }
    [pscustomobject]@{ Name = "RSAT-ADCS-Mgmt";          Why = "The Certification Authority console, for looking at what NDES enrolled" }
    # Last, because it is the one whose configuration step follows in this same run
    # and because installing it pulls IIS in anyway - listing IIS first means the
    # role services above are already decided when that happens.
    [pscustomobject]@{ Name = "ADCS-Device-Enrollment";  Why = "The Network Device Enrollment Service itself" }
)

# The .NET 3.5 half, separate because its payload is a separate problem. Microsoft
# lists it under NDES; the connector itself needs only 4.7.2, and whether a current
# Server release still genuinely requires it is not something a document settles -
# so these are installed, a failure is reported rather than fatal, and the NDES
# configuration step that follows is left to be the actual judge.
$script:adcsScepLegacyFeature = @(
    [pscustomobject]@{ Name = "NET-Framework-Core";  Why = ".NET Framework 3.5" }
    [pscustomobject]@{ Name = "NET-HTTP-Activation"; Why = "HTTP activation for 3.5" }
    [pscustomobject]@{ Name = "Web-Asp-Net";         Why = "ASP.NET 3.5" }
)

# Internet Explorer Enhanced Security Configuration, which the connector
# prerequisites say must be deactivated. Two Active Setup components: the first is
# the administrators' half, the second everybody else's.
$script:adcsScepEscComponent = @(
    [pscustomobject]@{ Guid = "{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"; Who = "administrators" }
    [pscustomobject]@{ Guid = "{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"; Who = "everybody else" }
)

# ---------------------------[ The certificates that stop SCEP ]---------------------------
# Four certificates expire in an NDES stack and only one of them is the HTTPS one this
# design renews. The other three are the reason SCEP deployments die quietly every couple
# of years: nothing renews them, nothing warns, and the first sign is Wi-Fi profiles
# failing to renew and devices falling out of compliance.
#
#   CEP Encryption            the registration authority certificate that encrypts the
#                             SCEP exchange with the device
#   Exchange Enrollment Agent the one NDES re-signs a device's request with
#   the policy module's       the client authentication certificate the Intune
#   certificate               connector's policy module binds to, named by
#                             MSCEP\Modules\NDESPolicy\NDESCertThumbprint
#
# The two registration authority certificates come from **version 1** templates, whose
# validity is a fixed two years that cannot be changed - and they do not auto-renew.
# Renewing them is not a right-click either: the Exchange Enrollment Agent (Offline
# request) template has Subject Type = User, so it cannot be renewed from the computer
# store at all. It is requested in the *user* store with an exportable key, exported to
# PFX, imported into the machine store, and the private key re-ACLed for the service
# account. That is a procedure for a person who meant to do it, which is exactly why
# this script **watches and never renews them**. What it can do is make sure nobody is
# surprised: read them, grade them, and put them in the mail the nightly task already
# sends.
$script:adcsScepWatchedCertificate = @(
    [pscustomobject]@{
        Label    = "NDES registration authority - CEP Encryption"
        Template = "CEPEncryption"
        Does     = "encrypts the SCEP exchange with the device"
    }
    [pscustomobject]@{
        Label    = "NDES registration authority - Exchange Enrollment Agent"
        Template = "EnrollmentAgentOffline"
        Does     = "re-signs the device's request on its behalf"
    }
)

# 60 / 30 / 14, which is what every field write-up on this settles on. Expired is its own
# state rather than a very small number, because the consequence is different in kind.
$script:adcsScepExpiryNotice   = 60
$script:adcsScepExpiryWarning  = 30
$script:adcsScepExpiryCritical = 14

function Get-AdcsScepExpiryGrade {
    param([int]$DaysLeft)

    if ($DaysLeft -lt 0) { return "Expired" }
    if ($DaysLeft -le $script:adcsScepExpiryCritical) { return "Critical" }
    if ($DaysLeft -le $script:adcsScepExpiryWarning) { return "Warning" }
    if ($DaysLeft -le $script:adcsScepExpiryNotice) { return "Notice" }
    return "Ok"
}

# The v1 template name lives in extension 1.3.6.1.4.1.311.20.2 as a plain string - the
# v2+ extension (1.3.6.1.4.1.311.21.7) carries an OID instead, which these two do not have because they
# are version 1. Matching on the template rather than on the subject is what makes this
# survive somebody having typed different registration authority details at NDES setup.
function Get-AdcsScepCertificateTemplateName {
    param([Parameter(Mandatory)][object]$Certificate)

    foreach ($extension in @($Certificate.Extensions)) {
        if ([string]$extension.Oid.Value -ne "1.3.6.1.4.1.311.20.2") { continue }
        try { return ([string]$extension.Format($false)).Trim() }
        catch { return "" }
    }
    return ""
}

function Get-AdcsScepCertificateHealth {
    $results = @()

    $store = @()
    try {
        $store = @(Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction Stop)
    }
    catch {
        Write-Log "The local machine certificate store could not be read: $($_.Exception.Message)" -Tag "Warn"
        return ,$results
    }

    foreach ($watched in $script:adcsScepWatchedCertificate) {
        # Newest first: a renewal leaves the old one in the store, and the one that
        # matters is the one NDES will still be using after the old one dies.
        $found = @($store | Where-Object {
            (Get-AdcsScepCertificateTemplateName -Certificate $_) -eq $watched.Template
        } | Sort-Object -Property NotAfter -Descending)

        if ($found.Count -eq 0) {
            $results += [pscustomobject]@{
                Label = $watched.Label; Detail = "not found in the machine store"
                Thumbprint = ""; NotAfter = ""; DaysLeft = 0; Grade = "Missing"
                Does = $watched.Does
            }
            continue
        }

        $certificate = $found[0]
        $daysLeft = [int][math]::Floor(($certificate.NotAfter - (Get-Date)).TotalDays)
        $results += [pscustomobject]@{
            Label = $watched.Label
            Detail = $watched.Does
            Thumbprint = [string]$certificate.Thumbprint
            NotAfter = $certificate.NotAfter.ToString("yyyy-MM-dd")
            DaysLeft = $daysLeft
            Grade = (Get-AdcsScepExpiryGrade -DaysLeft $daysLeft)
            Does = $watched.Does
        }
    }

    # The policy module's certificate, looked up by the thumbprint the connector install
    # writes into the registry. NOT by issuer: it is a **client authentication**
    # certificate whose common name is this server's own name, issued by this PKI rather
    # than by Intune, so there is nothing about its issuer to match on - an earlier
    # version of this guessed at "issued by something with Intune in the name" and would
    # never have found it. Microsoft's own Intune troubleshooting page names the value.
    #
    # When it expires the symptom is not an expiry message: the SCEP URL starts answering
    # the generic Network Device Enrollment Service page instead of 403, and the CAPI2 log
    # is where the validity error actually appears. Renewing it is not enough on its own -
    # the connector has to be reinstalled to bind to the new certificate.
    $policyThumbprint = ""
    try {
        $policyThumbprint = [string](Get-ItemProperty -Path ($script:adcsScepRegistryPath + "\Modules\NDESPolicy") `
            -Name "NDESCertThumbprint" -ErrorAction Stop).NDESCertThumbprint
    }
    catch { $policyThumbprint = "" }

    if (-not [string]::IsNullOrWhiteSpace($policyThumbprint)) {
        $normalised = ($policyThumbprint -replace "[^0-9A-Fa-f]", "").ToUpperInvariant()
        $policyCertificate = @($store | Where-Object { [string]$_.Thumbprint -eq $normalised })
        if ($policyCertificate.Count -eq 0) {
            $results += [pscustomobject]@{
                Label = "Intune connector policy module certificate"
                Detail = "the registry names $normalised and no such certificate is in the machine store"
                Thumbprint = $normalised; NotAfter = ""; DaysLeft = 0; Grade = "Missing"
                Does = "the certificate the policy module authenticates with"
            }
        }
        else {
            $daysLeft = [int][math]::Floor(($policyCertificate[0].NotAfter - (Get-Date)).TotalDays)
            $results += [pscustomobject]@{
                Label = "Intune connector policy module certificate"
                Detail = "client authentication for the policy module - renewing it also means reinstalling the connector"
                Thumbprint = [string]$policyCertificate[0].Thumbprint
                NotAfter = $policyCertificate[0].NotAfter.ToString("yyyy-MM-dd")
                DaysLeft = $daysLeft
                Grade = (Get-AdcsScepExpiryGrade -DaysLeft $daysLeft)
                Does = "the certificate the policy module authenticates with"
            }
        }
    }
    else {
        Write-Log "No NDESPolicy certificate thumbprint in the registry - the Intune connector is not installed on this server yet" -Tag "Debug"
    }

    return ,$results
}

# Said on every run of the tier, and in the nightly mail. The point is that nobody should
# ever learn about these from a helpdesk ticket.
function Write-AdcsScepCertificateHealth {
    param([object[]]$Health = @())

    if (@($Health).Count -eq 0) { return }

    Write-Log "The certificates NDES itself depends on:" -Tag "Info"
    foreach ($entry in @($Health)) {
        if ($entry.Grade -eq "Missing") {
            Write-Log "    $($entry.Label): not in the machine store" -Tag "Warn"
            continue
        }
        $line = "    {0}: expires {1} ({2} day(s))" -f $entry.Label, $entry.NotAfter, $entry.DaysLeft
        switch ($entry.Grade) {
            "Expired"  { Write-Log $line -Tag "Error" }
            "Critical" { Write-Log $line -Tag "Error" }
            "Warning"  { Write-Log $line -Tag "Warn" }
            "Notice"   { Write-Log $line -Tag "Warn" }
            default    { Write-Log $line -Tag "Ok" }
        }
    }

    $due = @($Health | Where-Object { @("Expired", "Critical", "Warning", "Notice") -contains $_.Grade })
    if ($due.Count -gt 0) {
        Write-Log "    These do not renew themselves and this script does not renew them - the enrollment agent one cannot be renewed from the computer store at all" -Tag "Warn"
        Write-Log "    Request it in the USER store with an exportable key, export to PFX, import into the machine store, then grant the service account read on the key" -Tag "Warn"
    }
}

$script:adcsScepRegistryPath = "HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP"
$script:adcsScepHttpParametersPath = "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"
$script:adcsScepMscepBinary = "$env:SystemRoot\system32\certsrv\mscep\mscep.dll"
# The application IIS itself registers HTTPS bindings under - reusing it keeps the
# netsh entry indistinguishable from one IIS Manager would have written.
$script:adcsScepIisAppId = "{4dc3e181-e14b-4a21-b022-59fc669b0914}"

function Get-AdcsScepSection {
    param([object]$CertificateServices)

    $scep = Get-ConfigValue -InputObject $CertificateServices -Name "scep"
    if ($null -eq $scep) { return $null }
    if (-not [bool](Get-ConfigValue -InputObject $scep -Name "enabled" -Default $false)) { return $null }
    return $scep
}

# ---------------------------[ The external name, indoors ]---------------------------
# The connector answers on a public name - scep.example.com - published to the internet
# through a reverse proxy, and the NDES box itself is ca-scep-01.ad.lab.invalid. A
# domain-joined client enrolling from inside has to reach that public name too, and
# almost no network lets a request leave for the proxy and come back to the machine
# beside it. So the name is made to answer indoors as well, pointing straight at the
# NDES server: the same split-DNS problem the Exchange namespace and the Remote Desktop
# published name each solve, solved the same way and by the same code.
#
# Written on the DOMAIN CONTROLLER run, like every other record this project creates -
# the NDES box is a member server and would need RSAT and delegated rights to write a
# zone remotely. It is written in the connector retrofit too: the CA in that mode
# belongs to somebody else, but this name is the connector's own, and a retrofit that
# publishes an endpoint nobody inside can resolve has retrofitted half a connector.
function Get-AdcsScepNamespaceRecord {
    param([Parameter(Mandatory)][object]$Scep)

    $externalUrl = Get-ConfigText -InputObject $Scep -Name "externalUrl"
    if ([string]::IsNullOrWhiteSpace($externalUrl)) { return @() }

    $hostName = ""
    try { $hostName = ([uri]$externalUrl).Host }
    catch { $hostName = "" }
    if ([string]::IsNullOrWhiteSpace($hostName)) {
        Write-Log "certificateServices.scep.externalUrl is not a URL, so there is no name to make resolve internally" -Tag "Warn"
        return @()
    }
    $hostName = $hostName.Trim().ToLowerInvariant()

    $target = Get-AdcsScepServerFqdn -Scep $Scep
    if ([string]::IsNullOrWhiteSpace($target)) { return @() }

    # A name that is already the machine's own is the machine's own registration, made
    # the day it joined. Same rule the Remote Desktop namespace follows.
    if ($hostName -eq $target) { return @() }

    return @([PSCustomObject]@{
        Name    = $hostName
        Target  = $target
        Purpose = "the SCEP endpoint, so a client inside reaches it without leaving the network"
    })
}

# The NDES server's full name, from the design rather than from this machine: this runs
# on the domain controller, where 'the SCEP server' is a name in a config file.
function Get-AdcsScepServerFqdn {
    param([Parameter(Mandatory)][object]$Scep)

    $computerName = Get-ConfigText -InputObject $Scep -Name "computerName"
    if ([string]::IsNullOrWhiteSpace($computerName)) {
        Write-Log "The SCEP tier names no server, so its external name has nothing to point at" -Tag "Warn"
        return ""
    }
    if ($computerName.Contains(".")) { return $computerName.Trim().ToLowerInvariant() }

    $domain = [string]$env:USERDNSDOMAIN
    if ([string]::IsNullOrWhiteSpace($domain)) {
        try {
            $computer = Get-CimInstance -ClassName "Win32_ComputerSystem" -ErrorAction Stop
            if ($computer.PartOfDomain) { $domain = [string]$computer.Domain }
        }
        catch { $domain = "" }
    }
    if ([string]::IsNullOrWhiteSpace($domain)) { return $computerName.Trim().ToLowerInvariant() }
    return ("{0}.{1}" -f $computerName.Trim(), $domain).ToLowerInvariant()
}

function Set-AdcsScepDnsRecord {
    param([Parameter(Mandatory)][object]$CertificateServices)

    $scep = Get-AdcsScepSection -CertificateServices $CertificateServices
    if ($null -eq $scep) { return $true }

    $records = @(Get-AdcsScepNamespaceRecord -Scep $scep)
    if ($records.Count -eq 0) { return $true }

    $dns = Get-ConfigValue -InputObject $scep -Name "dns"
    if (-not [bool](Get-ConfigValue -InputObject $dns -Name "manage" -Default $true)) {
        Write-Log "The design does not write the SCEP endpoint's internal record - it has to exist wherever that zone is served:" -Tag "Info"
        foreach ($record in $records) {
            Write-Log "    $($record.Name)  ->  $($record.Target)   ($($record.Purpose))" -Tag "Info"
        }
        return $true
    }

    if ($null -eq (Get-Command -Name "Get-DnsServerZone" -ErrorAction SilentlyContinue)) {
        Write-Log "The DnsServer module is not available here, so the SCEP endpoint's record has to be created where its zone is served:" -Tag "Warn"
        foreach ($record in $records) {
            Write-Log "    $($record.Name)  ->  $($record.Target)   ($($record.Purpose))" -Tag "Warn"
        }
        return $true
    }

    $zoneMode = Get-ConfigText -InputObject $dns -Name "zoneMode" -Default "pinpoint"
    if (@("none", "pinpoint", "full") -notcontains $zoneMode) { $zoneMode = "pinpoint" }

    $allDone = $true
    foreach ($record in $records) {
        $address = Resolve-StudioNamespaceAddress -Fqdn $record.Target
        if ([string]::IsNullOrWhiteSpace($address)) {
            Write-Log "'$($record.Target)' does not resolve from this DC - it may not have joined, so '$($record.Name)' is not created" -Tag "Warn"
            Write-Log "    Run this again once that server is on the network, or create the record by hand" -Tag "Warn"
            $allDone = $false
            continue
        }
        if (-not (Set-StudioNamespaceRecord -Record $record -Address $address -ZoneMode $zoneMode)) { $allDone = $false }
    }
    return $allDone
}

# The groups NDES enrolls its registration authority certificates through - one per
# template, the same rule every other template in this design follows, and groups rather
# than accounts, which is the rule every CA permission follows: an ACE naming one
# principal is invisible to anybody auditing group membership, outlives it, and has to be
# written again by hand the day a second one exists. Named in the design so they can be
# existing groups; the defaults name the certificate each one enrolls.
$script:adcsScepRaGroupDefault = @{
    "cepEncryption"   = "Certificate - CEP Encryption"
    "enrollmentAgent" = "Certificate - Exchange Enrollment Agent"
}

function Get-AdcsScepRaGroupName {
    param(
        [Parameter(Mandatory)][object]$CertificateServices,
        [Parameter(Mandatory)][string]$Key
    )

    $scep = Get-AdcsScepSection -CertificateServices $CertificateServices
    if ($null -eq $scep) { return "" }
    $groups = Get-ConfigValue -InputObject $scep -Name "raEnrollmentGroups"
    $name = [string](Get-ConfigText -InputObject $groups -Name $Key -Default "")
    if (-not [string]::IsNullOrWhiteSpace($name)) { return $name.Trim() }
    if ($script:adcsScepRaGroupDefault.ContainsKey($Key)) { return $script:adcsScepRaGroupDefault[$Key] }
    return ""
}

function Get-AdcsScepServiceAccount {
    # Same shape and same rules as the DHCP registration account: created on the
    # domain controller, a prerequisite everywhere else, an existing account's
    # password never reset.
    param([object]$Scep)

    $account = Get-ConfigValue -InputObject $Scep -Name "serviceAccount"
    if ($null -eq $account) { return $null }
    if (-not [bool](Get-ConfigValue -InputObject $account -Name "enabled" -Default $true)) { return $null }

    $sam = Get-ConfigText -InputObject $account -Name "samAccountName"
    if ([string]::IsNullOrWhiteSpace($sam)) { return $null }

    return [pscustomobject]@{
        SamAccountName     = $sam
        DisplayName        = Get-ConfigText -InputObject $account -Name "displayName" -Default ("Service - " + $sam)
        Password           = Get-ConfigText -InputObject $account -Name "password"
        OrganizationalUnit = Get-ConfigText -InputObject $account -Name "organizationalUnit"
    }
}

# ---------------------------[ The three template slots ]---------------------------
# One NDES server serves up to THREE certificate templates, and which one a request
# gets is decided by the *key usage* the Intune SCEP profile asks for - not by a name
# in the profile, because a SCEP profile against a Microsoft CA has no template name
# field at all. Microsoft's mapping, and the whole reason this tier has three slots:
#
#   template Purpose (Request Handling)  registry slot            SCEP profile key usage
#   Signature                            SignatureTemplate        Digital Signature
#   Encryption                           EncryptionTemplate       Key Encipherment
#   Signature and encryption             GeneralPurposeTemplate   both
#
# That ceiling is hard. A fourth template needs a second NDES server and a second
# connector instance. It is also why the Windows Hello for Business RDP sign-in
# certificate needs a slot of its own: that profile asks for Digital Signature, so it
# is served whatever SignatureTemplate names - and while all three slots carried one
# general-purpose template, that was silently the wrong certificate. It issued, and
# RDP sign-in did not work.
#
# Every slot may name the same template, which is the single-template deployment and
# still the studio's default.

# The legacy read: a design written before the slots existed carries one template
# flagged scepTemplate and nothing else. Returned as the fallback for all three slots
# so such a config applies exactly as it always did.
function Get-AdcsScepTemplateName {
    param([object]$CertificateServices)

    $issuing = Get-ConfigValue -InputObject $CertificateServices -Name "issuing"
    $templates = Get-ConfigValue -InputObject $issuing -Name "templates"
    foreach ($item in @(Get-ConfigArray -InputObject $templates -Name "items")) {
        if ([bool](Get-ConfigValue -InputObject $item -Name "scepTemplate" -Default $false)) {
            $name = Get-ConfigText -InputObject $item -Name "templateName"
            if (-not [string]::IsNullOrWhiteSpace($name)) { return $name }
        }
    }
    return ""
}

# What each slot should name. The studio resolves the three from the templates the
# design builds and writes them out by name, so this never has to know that a Windows
# Hello template and the Signature slot belong together - the same rule that keeps the
# WMI filter codes and the "C - DC -" prefixes out of the script.
function Get-AdcsScepSlotTemplate {
    param([Parameter(Mandatory)][object]$CertificateServices)

    $fallback = Get-AdcsScepTemplateName -CertificateServices $CertificateServices

    $scep = Get-ConfigValue -InputObject $CertificateServices -Name "scep"
    $templates = Get-ConfigValue -InputObject $scep -Name "templates"
    if ($null -eq $templates) {
        # Written before the slots existed. One template, three slots, exactly as before.
        return [ordered]@{
            SignatureTemplate      = $fallback
            EncryptionTemplate     = $fallback
            GeneralPurposeTemplate = $fallback
        }
    }

    return [ordered]@{
        SignatureTemplate      = [string](Get-ConfigText -InputObject $templates -Name "signature" -Default $fallback)
        EncryptionTemplate     = [string](Get-ConfigText -InputObject $templates -Name "encryption" -Default $fallback)
        GeneralPurposeTemplate = [string](Get-ConfigText -InputObject $templates -Name "generalPurpose" -Default $fallback)
    }
}

# The directory half, called from Invoke-AdcsDirectoryTier: the account, its place
# in the enrollment group, and - when asked - its place in the certificate managers
# role group so Intune-driven revocation works. That last one is the design's second
# stated exception to 'membership is never automated' (the first is the Remote
# Desktop group's seeding), because the account and the right exist for each other
# and were both asked for in the same design.
# A computer account into a security group, by sAMAccountName with the trailing dollar -
# the same searcher Set-RdsLicenseServerGroup uses, because a computer cannot go through
# Sync-StudioAccessGroup, whose members are people and groups resolved by UPN. The group
# is not created here: each caller owns its own group's existence. A computer that is not
# in the domain yet is a warning rather than a failure - the group is there either way,
# and the next directory run fills it.
function Add-AdcsScepComputerMember {
    param(
        [Parameter(Mandatory)][string]$GroupName,
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string]$Purpose
    )

    $accountName = ($ComputerName.Split(".")[0]).Trim() + "$"

    $entry = Find-AdcsGroup -Name $GroupName
    if ($null -eq $entry) {
        Write-Log "The group '$GroupName' could not be read - '$accountName' was not added to it" -Tag "Error"
        return $false
    }
    $group = $entry.GetDirectoryEntry()

    $accountDn = ""
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectCategory=computer)(sAMAccountName=$accountName))"
        $null = $searcher.PropertiesToLoad.Add("distinguishedName")
        $found = $searcher.FindOne()
        if ($null -ne $found) { $accountDn = [string]$found.Properties["distinguishedname"][0] }
    }
    catch {
        Write-Log "Could not search for the computer account '$accountName': $($_.Exception.Message)" -Tag "Warn"
    }
    if ([string]::IsNullOrWhiteSpace($accountDn)) {
        # Normal on a build where the NDES server has not been joined yet.
        Write-Log "No computer account '$accountName' in this domain yet - '$GroupName' stays without it" -Tag "Warn"
        Write-Log "    Join that server and run this again, or add it by hand: $Purpose" -Tag "Warn"
        return $true
    }

    $members = @()
    try { $members = @($group.Properties["member"] | ForEach-Object { [string]$_ }) } catch { $members = @() }
    if ($members -contains $accountDn) {
        Write-Log "'$accountName' is already in '$GroupName'" -Tag "Debug"
        return $true
    }

    try {
        $null = $group.Properties["member"].Add($accountDn)
        $group.CommitChanges()
    }
    catch {
        Write-Log "Could not add '$accountName' to '$GroupName': $($_.Exception.Message)" -Tag "Error"
        return $false
    }
    Write-Log "Added '$accountName' to '$GroupName' - $Purpose" -Tag "Ok"
    # A machine reads its own group membership from the ticket it got at boot, so a
    # membership added now is not in that machine's token until it restarts.
    Write-Log "    That server needs a RESTART before it can use this - a computer's group membership arrives in its ticket at boot" -Tag "Info"
    return $true
}

# Two groups, and only one of them gets a member written. The reason is the TEMPLATES'
# own subject types, not a convention this design picked:
#
#   CEPEncryption          Computer (CT_FLAG_MACHINE_TYPE) - the CA will not issue it to
#                          anything but a computer account, so the NDES MACHINE enrolls it
#                          and the machine is what has to be in the group.
#   EnrollmentAgentOffline User - enrolled by the USER running the configuration, which
#                          Domain and Enterprise Admins may already do. Who may act as an
#                          enrollment agent is a decision, never a default, so that group
#                          ships empty and the run says so.
#
# An earlier version of this comment called the machine "a fact of the design and not a
# decision", which was the right answer with the wrong reason behind it - and a reason
# that could not be checked. The subject type can.
function Sync-AdcsScepRaGroup {
    param(
        [Parameter(Mandatory)][object]$CertificateServices,
        [Parameter(Mandatory)][object]$Scep
    )

    $allDone = $true

    # The agent group: created so the issuing CA run has something to grant, left empty
    # on purpose.
    $agentGroup = Get-AdcsScepRaGroupName -CertificateServices $CertificateServices -Key "enrollmentAgent"
    if (-not [string]::IsNullOrWhiteSpace($agentGroup)) {
        $null = New-AdcsAccessGroup -Name $agentGroup `
            -Description "May enroll the Exchange Enrollment Agent (Offline request) certificate - the identity that configures NDES"
        Write-Log "'$agentGroup' exists and stays empty" -Tag "Info"
    }

    $cepGroup = Get-AdcsScepRaGroupName -CertificateServices $CertificateServices -Key "cepEncryption"
    if ([string]::IsNullOrWhiteSpace($cepGroup)) { return $allDone }

    $computerName = [string](Get-ConfigText -InputObject $Scep -Name "computerName" -Default "")
    if ([string]::IsNullOrWhiteSpace($computerName)) {
        Write-Log "The SCEP tier names no server, so there is no computer account to put into '$cepGroup'" -Tag "Warn"
        return $allDone
    }

    $null = New-AdcsAccessGroup -Name $cepGroup `
        -Description "May enroll the CEP Encryption certificate - the NDES server itself, which enrolls it as the machine"

    if (-not (Add-AdcsScepComputerMember -GroupName $cepGroup -ComputerName $computerName `
                -Purpose "the machine is what enrolls CEP Encryption")) {
        return $false
    }
    return $allDone
}

# The NDES server's own HTTPS certificate, when it comes from this design's issuing CA:
# the MACHINE enrolls it, so the machine is what needs Enroll on that template - and
# this design grants Enroll to a group and never to a principal, so what has to be
# written is a membership. Same rule and same restart caveat as the CEP Encryption
# group above; the difference is only where the group name comes from. The two
# registration authority groups are named on the SCEP blade because their templates are
# built-ins this design never publishes, while the server-authentication template is one
# it publishes itself and already carries the group that grants it - so the name is read
# off the template item, not out of a field of its own.
#
# Off is a real answer, which is why there is a switch: a forest whose server template
# is granted to a group somebody else maintains wants nothing written here.
$script:adcsScepBroadPrincipal = @(
    "domain users", "domain computers", "authenticated users", "everyone",
    "users", "domain guests", "guests", "anonymous logon"
)

function Sync-AdcsScepHttpsEnrollmentGroup {
    param(
        [Parameter(Mandatory)][object]$CertificateServices,
        [Parameter(Mandatory)][object]$Scep
    )

    $certificate = Get-ConfigValue -InputObject $Scep -Name "certificate"
    if ($null -eq $certificate) { return $true }
    if ([string](Get-ConfigText -InputObject $certificate -Name "source" -Default "") -ne "internalCa") { return $true }

    $internal = Get-ConfigValue -InputObject $certificate -Name "internalCa"
    if (-not [bool](Get-ConfigValue -InputObject $internal -Name "joinEnrollmentGroup" -Default $true)) {
        Write-Log "The NDES computer account is left out of the HTTPS template's enrollment group - certificate.internalCa.joinEnrollmentGroup is off" -Tag "Info"
        Write-Log "    That account has to hold Enroll on that template already, or the HTTPS binding gets no certificate" -Tag "Info"
        return $true
    }

    $computerName = [string](Get-ConfigText -InputObject $Scep -Name "computerName" -Default "")
    if ([string]::IsNullOrWhiteSpace($computerName)) {
        Write-Log "The SCEP tier names no server, so there is no computer account to put into the HTTPS template's group" -Tag "Warn"
        return $true
    }
    $accountName = "{0}$" -f ($computerName.Split(".")[0]).Trim()

    $templateName = [string](Get-ConfigText -InputObject $internal -Name "templateName" -Default "")
    if ([string]::IsNullOrWhiteSpace($templateName)) { $templateName = "WebServices" }

    # The template item this design publishes under that object name. A name that is not
    # in the design is a template somebody else owns - the group that grants it is theirs
    # too, and guessing at one would be this run writing into a design it cannot read.
    $issuing = Get-ConfigValue -InputObject $CertificateServices -Name "issuing"
    $templates = Get-ConfigValue -InputObject $issuing -Name "templates"
    $item = $null
    foreach ($candidate in @(Get-ConfigArray -InputObject $templates -Name "items")) {
        if ([string](Get-ConfigText -InputObject $candidate -Name "templateName" -Default "") -eq $templateName) {
            $item = $candidate
            break
        }
    }
    if ($null -eq $item) {
        Write-Log "'$templateName' is not a template this design publishes - nothing here knows which group grants Enroll on it" -Tag "Warn"
        Write-Log "    Put '$accountName' into that template's enrollment group by hand, or the NDES HTTPS certificate cannot be enrolled" -Tag "Warn"
        return $true
    }

    # A machine is in Domain Computers by its primary group and in Authenticated Users by
    # having logged on, so a template granted to one of those needs nothing written - and
    # an attempt to add the member would fail for a reason that has nothing to do with
    # this design.
    $groupNames = @()
    $broad = @()
    foreach ($principal in @(Get-ConfigArray -InputObject $item -Name "enrollPrincipals")) {
        # A { wellKnown } entry is a Windows principal, not a group anything can be put
        # into - see Resolve-AdcsEnrollmentPrincipal. Nothing to add a member to.
        if ($principal -isnot [string]) { continue }
        $name = ([string]$principal).Trim()
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        if ($script:adcsScepBroadPrincipal -contains $name.ToLowerInvariant()) {
            if ($broad -notcontains $name) { $broad += $name }
            continue
        }
        if ($groupNames -notcontains $name) { $groupNames += $name }
    }

    if ($groupNames.Count -eq 0) {
        if ($broad.Count -gt 0) {
            Write-Log "'$templateName' is granted to $($broad -join ', ') - '$accountName' is already covered, nothing to add" -Tag "Info"
        }
        else {
            Write-Log "'$templateName' has no enrollment group in this design, so '$accountName' cannot be given Enroll on it" -Tag "Warn"
            Write-Log "    Map a group to that template under Enrollment access, or the NDES HTTPS certificate cannot be enrolled" -Tag "Warn"
        }
        return $true
    }

    $allDone = $true
    foreach ($groupName in $groupNames) {
        if (-not (Add-AdcsScepComputerMember -GroupName $groupName -ComputerName $computerName `
                    -Purpose "the machine is what enrolls the NDES HTTPS certificate from '$templateName'")) {
            $allDone = $false
        }
    }
    return $allDone
}

function Set-AdcsScepDirectory {
    param([Parameter(Mandatory)][object]$CertificateServices)

    $scep = Get-AdcsScepSection -CertificateServices $CertificateServices
    if ($null -eq $scep) { return $true }

    $account = Get-AdcsScepServiceAccount -Scep $scep
    if ($null -eq $account) {
        Write-Log "The SCEP tier is on but carries no service account - NDES cannot run without one" -Tag "Error"
        return $false
    }

    # -Sensitive: this one runs an application pool on a server published to the
    # internet through a reverse proxy, which is the textbook account to put out of
    # reach of delegation.
    if (-not (New-DhcpServiceAccount -Account $account -Sensitive `
                -Description "Intune SCEP / NDES service account - no interactive logon")) {
        return $false
    }

    $allDone = $true
    $domain = ([string]$env:USERDNSDOMAIN).ToLowerInvariant()
    $memberUpn = "{0}@{1}" -f $account.SamAccountName, $domain

    # The enrollment group is the SCEP template's derived group - the contract
    # carries the merged principal, so this reads the same field the ACE writer does.
    $issuing = Get-ConfigValue -InputObject $CertificateServices -Name "issuing"
    $templates = Get-ConfigValue -InputObject $issuing -Name "templates"
    # EVERY SCEP template's enrollment group, not the first one's. This used to break
    # after the first match, which was correct while one template filled all three MSCEP
    # slots and silently wrong the moment a second one existed: each template derives its
    # own group, NDES enrols against all of them, and an account in only the first group
    # gets an access denied from the CA on the second - naming the template, not the
    # membership that is actually missing.
    $groupNames = @()
    foreach ($item in @(Get-ConfigArray -InputObject $templates -Name "items")) {
        if (-not [bool](Get-ConfigValue -InputObject $item -Name "scepTemplate" -Default $false)) { continue }
        foreach ($principal in @(Get-ConfigArray -InputObject $item -Name "enrollPrincipals")) {
            # Same rule as the HTTPS certificate's group above: a coded principal is a
            # Windows one, and the service account cannot be made a member of it.
            if ($principal -isnot [string]) { continue }
            $name = [string]$principal
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            if ($groupNames -notcontains $name) { $groupNames += $name }
        }
    }
    if ($groupNames.Count -eq 0) {
        Write-Log "No SCEP template is enabled in the design, so there is no enrollment group to put '$($account.SamAccountName)' into" -Tag "Warn"
    }
    else {
        foreach ($groupName in $groupNames) {
            if (-not (Sync-StudioAccessGroup -Name $groupName -Description "The NDES service account - the only principal that enrolls SCEP requests" -MemberUpn @($memberUpn))) {
                $allDone = $false
            }
        }
        Write-Log "'$($account.SamAccountName)' is in $($groupNames.Count) enrollment group(s): $($groupNames -join ', ')" -Tag "Info"
    }

    # The registration authority group: the machine, not the service account, is what
    # enrolls CEP Encryption at configuration time - so the machine is what goes in here,
    # and the issuing CA run grants this group Enroll on that template.
    if (-not (Sync-AdcsScepRaGroup -CertificateServices $CertificateServices -Scep $scep)) { $allDone = $false }

    # The third membership this tier writes, and the only one whose group the SCEP
    # section does not name: the machine into whatever group grants Enroll on the
    # template its own HTTPS certificate comes from.
    if (-not (Sync-AdcsScepHttpsEnrollmentGroup -CertificateServices $CertificateServices -Scep $scep)) { $allDone = $false }

    if ([bool](Get-ConfigValue -InputObject $scep -Name "grantRevocation" -Default $true)) {
        # Issue and Manage Certificates on the CA is what lets Intune revoke - and the
        # certificate managers role group is where that permission already lives, so
        # membership rather than an ACE of its own. TWO members, because the connector
        # picks its service identity at install time and both choices have to work:
        # installed as SYSTEM - the default, and a supported option Microsoft's own doc
        # answers with "provide the permissions to the NDES server" - it reaches the CA
        # as this tier's MACHINE account; installed as a domain account it reaches the
        # CA as that account. Granting only the service account bet on the second box
        # being ticked, and a connector installed with the default then failed every
        # revocation with nothing on this side saying why.
        $managerGroup = ""
        $roleGroups = Get-ConfigValue -InputObject $CertificateServices -Name "roleGroups"
        foreach ($entry in @(Get-ConfigArray -InputObject $roleGroups -Name "groups")) {
            if ([string](Get-ConfigValue -InputObject $entry -Name "role" -Default "") -eq "certificateManager") {
                $managerGroup = Get-ConfigText -InputObject $entry -Name "name"
                break
            }
        }
        if ([string]::IsNullOrWhiteSpace($managerGroup)) {
            Write-Log "grantRevocation is on and the design has no certificate managers group - Intune cannot revoke until one holds Issue and Manage Certificates" -Tag "Warn"
        }
        else {
            if (-not (Sync-StudioAccessGroup -Name $managerGroup -MemberUpn @($memberUpn))) {
                $allDone = $false
            }
            else {
                Write-Log "'$($account.SamAccountName)' added to '$managerGroup' so the connector can revoke (scep.grantRevocation)" -Tag "Info"
            }
            $scepComputer = [string](Get-ConfigText -InputObject $scep -Name "computerName" -Default "")
            if ([string]::IsNullOrWhiteSpace($scepComputer)) {
                Write-Log "The SCEP tier names no server - no computer account for '$managerGroup'. A connector running as SYSTEM revokes as that account" -Tag "Warn"
            }
            elseif (-not (Add-AdcsScepComputerMember -GroupName $managerGroup -ComputerName $scepComputer `
                        -Purpose "the connector installed as SYSTEM - its default - revokes as the machine")) {
                $allDone = $false
            }
        }
    }

    return $allDone
}

function Test-AdcsScepConfigured {
    return (Test-Path -LiteralPath $script:adcsScepRegistryPath)
}

# ---------------------------[ Prerequisites this tier installs ]---------------------------

# Desktop Experience or Server Core, asked of the installation itself rather than of
# a feature list. A Server Core box cannot be converted to Desktop Experience after
# setup - that path was removed after Server 2012 R2 - so this is a refusal with the
# only real answer attached, not something to try and fail at.
function Test-AdcsScepDesktopExperience {
    $installationType = ""
    try {
        $installationType = [string](Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" `
            -Name "InstallationType" -ErrorAction Stop).InstallationType
    }
    catch {
        # Unreadable is not the same as Core. Say so and let the run continue: the
        # connector install is where a genuinely headless server fails anyway.
        Write-Log "The installation type could not be read, so Desktop Experience is assumed: $($_.Exception.Message)" -Tag "Warn"
        return $true
    }
    Write-Log "Installation type: $installationType" -Tag "Debug"
    return ($installationType -ne "Server Core")
}

# Windows Server 2019 or later, and this is a warning rather than a refusal because the
# thing it breaks is not the install.
#
# The connector installs on 2012 R2 and later - Microsoft's own prerequisite - so refusing
# an older server here would be inventing a rule. What is version-bound is STRONG MAPPING:
# "Strong mapping in the Microsoft Intune Certificate Connector is only supported for
# Windows Server version 2019 or later." Since the KB5014754 rollout completed and Full
# Enforcement became mandatory in September 2025, a certificate without the SID mapping is
# refused by every domain controller. So on 2016 the connector still runs and still issues,
# and every certificate it issues for authenticating to the directory is dead on arrival -
# which is exactly the failure that gets blamed on the template.
$script:adcsScepStrongMappingBuild = 17763   # Windows Server 2019

function Test-AdcsScepStrongMappingSupported {
    $build = 0
    try {
        $build = [int](Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" `
            -Name "CurrentBuildNumber" -ErrorAction Stop).CurrentBuildNumber
    }
    catch {
        Write-Log "The build number could not be read, so strong mapping support is assumed: $($_.Exception.Message)" -Tag "Warn"
        return $true
    }
    Write-Log "Windows build: $build" -Tag "Debug"
    if ($build -ge $script:adcsScepStrongMappingBuild) { return $true }

    Write-Log "This server is older than Windows Server 2019, and the connector supports strong mapping only on 2019 or later" -Tag "Warn"
    Write-Log "    Certificates it issues carry no SID mapping, and domain controllers have refused those since September 2025" -Tag "Warn"
    Write-Log "    NDES still installs and still issues - what stops working is authenticating with what it issued" -Tag "Warn"
    return $false
}

# One feature, with the reason it is wanted in the message rather than only its id.
# Returns $null when the feature is already there, so the caller can tell "installed
# nothing" from "installed and now owes a restart".
function Install-AdcsScepFeature {
    param(
        [Parameter(Mandatory)][object]$Feature,
        [string]$Source = ""
    )

    $state = $null
    try { $state = Get-WindowsFeature -Name $Feature.Name -ErrorAction Stop }
    catch {
        Write-Log "Feature '$($Feature.Name)' is unknown on this operating system - skipping it" -Tag "Warn"
        return $null
    }
    if ($null -eq $state) {
        Write-Log "Feature '$($Feature.Name)' is unknown on this operating system - skipping it" -Tag "Warn"
        return $null
    }
    if ($state.Installed) {
        Write-Log "$($Feature.Name) is already installed - $($Feature.Why)" -Tag "Debug"
        return $null
    }

    Write-Log "Installing $($Feature.Name) - $($Feature.Why)" -Tag "Run"
    $arguments = @{ Name = $Feature.Name; IncludeManagementTools = $true; ErrorAction = "Stop" }
    # An empty -Source is not the same as no -Source: the cmdlet takes the empty
    # string literally and finds nothing there.
    if (-not [string]::IsNullOrWhiteSpace($Source)) { $arguments["Source"] = $Source }

    $result = Install-WindowsFeature @arguments
    if (-not $result.Success) {
        throw "Install-WindowsFeature reported failure for '$($Feature.Name)'"
    }
    Write-Log "$($Feature.Name) installed" -Tag "Ok"
    return $result
}

# What went wrong when a Features on Demand payload cannot be found, said in the terms
# the person fixing it needs. Features on Demand looks in three places in order: an
# explicit source path, the 'Specify settings for optional component installation and
# component repair' policy, then Windows Update - so a failure here is one of exactly
# three situations and the log should say which rather than printing a generic line.
function Write-AdcsScepPayloadDiagnosis {
    param([Parameter(Mandatory)][string]$FeatureName)

    Write-Log "The payload for '$FeatureName' is not on this server - it ships Removed and has to come from somewhere" -Tag "Error"

    $wsusServer = ""
    try {
        $wsusServer = [string](Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
            -Name "WUServer" -ErrorAction Stop).WUServer
    }
    catch { $wsusServer = "" }

    if (-not [string]::IsNullOrWhiteSpace($wsusServer)) {
        Write-Log "    This server takes updates from WSUS ($wsusServer), and WSUS does not carry Features on Demand payload" -Tag "Error"
        Write-Log "    Either tick 'Contact Windows Update directly to download repair content instead of WSUS' in the policy" -Tag "Error"
        Write-Log "    'Computer Configuration\Administrative Templates\System\Specify settings for optional component installation and component repair'" -Tag "Error"
    }
    else {
        Write-Log "    Either give this server Windows Update, which is where the payload comes from by default" -Tag "Error"
        Write-Log "    (that policy can forbid it - check it is not set to never download)" -Tag "Error"
    }
    Write-Log "    Or point the run at Windows Server installation media by setting certificateServices.scep.featureSource:" -Tag "Error"
    Write-Log "        Install-WindowsFeature -Name $FeatureName -Source <drive>:\sources\sxs" -Tag "Error"
}

# IE Enhanced Security Configuration off, which the connector prerequisites require.
# Never fatal: a server where this cannot be written is a server where the connector
# setup will say so itself, and failing the whole tier over a browser setting would
# be the wrong shape of refusal.
function Disable-AdcsScepEnhancedSecurity {
    foreach ($component in $script:adcsScepEscComponent) {
        $path = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\$($component.Guid)"
        if (-not (Test-Path -LiteralPath $path)) {
            Write-Log "Enhanced Security Configuration for $($component.Who) is not present on this server" -Tag "Debug"
            continue
        }
        $current = $null
        try { $current = [int](Get-ItemProperty -Path $path -Name "IsInstalled" -ErrorAction Stop).IsInstalled }
        catch { $current = $null }
        if ($current -eq 0) {
            Write-Log "Enhanced Security Configuration is already off for $($component.Who)" -Tag "Debug"
            continue
        }
        try {
            Set-ItemProperty -Path $path -Name "IsInstalled" -Value 0 -Type DWord -ErrorAction Stop
            Write-Log "Enhanced Security Configuration switched off for $($component.Who)" -Tag "Ok"
        }
        catch {
            Write-Log "Could not switch Enhanced Security Configuration off for $($component.Who): $($_.Exception.Message)" -Tag "Warn"
        }
    }
}

# Everything the NDES configuration step that follows needs to already be true.
# Returns a result the caller reads rather than a bare boolean: a run that installed
# IIS from nothing owes a restart before NDES is configured, and that is a different
# outcome from one that found everything in place.
# TLS 1.2, which the Certificate Connector prerequisites require outright. Setting
# ServicePointManager.SecurityProtocol - which several other roles here do - only affects
# the PowerShell process doing it, and the connector is a Windows service that will start
# long after this run ends. What decides its behaviour is the .NET Framework registry, in
# BOTH hives: a 64-bit machine runs 32-bit .NET code too, and half-configuring it is how a
# connector ends up negotiating TLS 1.0 on one code path and 1.2 on another.
#
#   SchUseStrongCrypto        stop offering SSL 3.0 and TLS 1.0
#   SystemDefaultTlsVersions  take the protocol from the OS rather than pinning one
function Set-AdcsScepStrongCrypto {
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
    )
    $changed = 0
    foreach ($path in $paths) {
        if (-not (Test-Path -LiteralPath $path)) {
            # The 32-bit hive is absent on a machine with no WOW64, which is not an error.
            Write-Log "'$path' is not present - nothing to set there" -Tag "Debug"
            continue
        }
        foreach ($name in @("SchUseStrongCrypto", "SystemDefaultTlsVersions")) {
            $current = $null
            try { $current = [int](Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name }
            catch { $current = $null }
            if ($current -eq 1) { continue }
            try {
                Set-ItemProperty -Path $path -Name $name -Value 1 -Type DWord -ErrorAction Stop
                $changed++
            }
            catch {
                Write-Log "Could not set $name in '$path': $($_.Exception.Message)" -Tag "Warn"
            }
        }
    }
    if ($changed -gt 0) {
        Write-Log "TLS 1.2 enforced for .NET Framework ($changed value(s) written)" -Tag "Ok"
    }
    else {
        Write-Log "TLS 1.2 is already enforced for .NET Framework" -Tag "Debug"
    }
}

function Install-AdcsScepPrerequisite {
    param([Parameter(Mandatory)][object]$Scep)

    $result = [pscustomobject]@{
        Ok            = $true
        RestartNeeded = $false
        Installed     = 0
        Failed        = @()
    }

    if (-not (Test-AdcsScepDesktopExperience)) {
        Write-Log "This is a Server Core installation. The Certificate Connector for Microsoft Intune requires Desktop Experience" -Tag "Error"
        Write-Log "    A Server Core installation cannot be converted - this tier needs a server installed with Desktop Experience" -Tag "Error"
        $result.Ok = $false
        return $result
    }

    if ($null -eq (Get-Command -Name "Install-WindowsFeature" -ErrorAction SilentlyContinue)) {
        Write-Log "Install-WindowsFeature is not available - this does not look like a Windows Server" -Tag "Error"
        $result.Ok = $false
        return $result
    }

    # Reported, not enforced: what an older server breaks is the certificates, not this run.
    $null = Test-AdcsScepStrongMappingSupported

    $source = [string](Get-ConfigText -InputObject $Scep -Name "featureSource")
    if (-not [string]::IsNullOrWhiteSpace($source)) {
        Write-Log "Feature payload comes from '$source' rather than Windows Update" -Tag "Info"
    }

    Write-Log "Installing the roles and features NDES needs - this tier builds its own server" -Tag "Run"
    foreach ($feature in $script:adcsScepFeature) {
        try {
            $installed = Install-AdcsScepFeature -Feature $feature -Source $source
            if ($null -ne $installed) {
                $result.Installed++
                if ($installed.RestartNeeded -ne "No") { $result.RestartNeeded = $true }
            }
        }
        catch {
            Write-Log "Could not install $($feature.Name) ($($feature.Why)): $($_.Exception.Message)" -Tag "Error"
            $result.Failed += $feature.Name
            $result.Ok = $false
        }
    }

    # The 3.5 half. A failure here is reported and the run carries on: Microsoft lists
    # these under NDES, the connector itself needs only 4.7.2, and the NDES
    # configuration step below is a better judge of whether they were needed than any
    # document is. If it succeeds without them, the log says so and nobody goes looking
    # for installation media that was never required.
    foreach ($feature in $script:adcsScepLegacyFeature) {
        try {
            $installed = Install-AdcsScepFeature -Feature $feature -Source $source
            if ($null -ne $installed) {
                $result.Installed++
                if ($installed.RestartNeeded -ne "No") { $result.RestartNeeded = $true }
            }
        }
        catch {
            Write-Log "$($feature.Name) ($($feature.Why)) could not be installed" -Tag "Warn"
            Write-AdcsScepPayloadDiagnosis -FeatureName $feature.Name
            Write-Log "    Carrying on - Microsoft lists .NET 3.5 under NDES, but the configuration step is what decides" -Tag "Warn"
        }
    }

    Disable-AdcsScepEnhancedSecurity
    Set-AdcsScepStrongCrypto

    if ($result.Installed -eq 0) {
        Write-Log "Every role and feature this tier needs was already installed" -Tag "Info"
    }
    else {
        Write-Log "$($result.Installed) role(s) and feature(s) installed" -Tag "Ok"
    }
    return $result
}

# ---------------------------[ Who may enroll what: the access preflight ]---------------------------
# `CMSCEPSetup::Install: Access is denied. 0x80070005` is the one failure this tier keeps
# coming back to, and it has been diagnosed by theory twice because the run never gathered
# the facts that would settle it. It arrives **after** nine roles and features have taken
# twenty-five minutes to install, names no identity, names no object, and leaves the MSCEP
# key behind so the next attempt needs an uninstall first.
#
# Three facts decide whether that call can succeed, and every one of them is readable in
# seconds before anything is installed:
#
#   1. Can the identity that enrolls each registration authority certificate actually
#      enroll it? **Who that identity is has never been bisected on the bench** - Microsoft's
#      own replacement procedure enrolls both as the installing USER, the machine-context
#      story is about renewal - so this asserts the honest thing rather than picking a
#      side: at least one of {this session's token, this machine's account} must hold
#      Enroll on each template, and the matrix is printed either way. The next failure
#      bisects itself.
#   2. Does this session hold Manage CA on the issuing CA? Probed rather than assumed, by
#      two calls whose difference is the answer: -CAInfo needs Read, -getreg needs
#      Manage CA. CAInfo answering while getreg is denied is that permission missing and
#      nothing else.
#   3. Is this session's token current? A membership granted after sign-in is not in it,
#      and `removeBuiltinAdmins` moves Manage CA into a group this design creates - so the
#      account can hold the right on paper and the session not carry it. The token is what
#      the CA checks, so the token is what is read here.
#
# Nothing here is a new requirement invented by this project: each check reads a
# permission the configuration is about to need. It refuses only what it can prove, and
# what it cannot prove it prints.

# The SIDs in THIS process's token - the user and every group the session actually
# carries. Deliberately not the account's directory memberships: those are what the
# account holds on paper, and the gap between the two is the whole reason this exists.
function Get-AdcsScepTokenSid {
    $sids = @()
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $sids += [string]$identity.User.Value
        foreach ($group in @($identity.Groups)) { $sids += [string]$group.Value }
    }
    catch {
        Write-Log "This session's token could not be read: $($_.Exception.Message)" -Tag "Warn"
    }
    return @($sids | Select-Object -Unique)
}

# The same list for a directory account - this machine's, or the service account the
# application pool runs as. Expanded by the directory rather than by walking memberOf:
# tokenGroups is what a domain controller computes for a Kerberos ticket, nesting
# included, which is the list an access check is actually made against.
function Get-AdcsScepAccountSid {
    param(
        [Parameter(Mandatory)][string]$SamAccountName,
        [ValidateSet("computer", "user")][string]$Kind = "user"
    )

    $sids = @()
    $accountName = $SamAccountName
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectCategory=$Kind)(sAMAccountName=$accountName))"
        $null = $searcher.PropertiesToLoad.Add("distinguishedName")
        $found = $searcher.FindOne()
        if ($null -eq $found) {
            Write-Log "No $Kind account '$accountName' in this domain - its rights cannot be read" -Tag "Warn"
            return @()
        }
        $entry = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://" + [string]$found.Properties["distinguishedname"][0]))
        $entry.RefreshCache(@("tokenGroups", "objectSid"))
        foreach ($value in @($entry.Properties["objectSid"])) {
            $sids += (New-Object System.Security.Principal.SecurityIdentifier($value, 0)).Value
        }
        foreach ($value in @($entry.Properties["tokenGroups"])) {
            $sids += (New-Object System.Security.Principal.SecurityIdentifier($value, 0)).Value
        }
    }
    catch {
        Write-Log "The group memberships of '$accountName' could not be read: $($_.Exception.Message)" -Tag "Warn"
        return @()
    }
    return @($sids | Select-Object -Unique)
}

# Whether a set of SIDs holds Enroll on a certificate template, read off the template
# object's own access control list. Enroll is an extended right, so an ACE granting it
# is one of three things: that right by its GUID, every extended right (the all-zero
# object type), or GenericAll. A Deny for any of the SIDs wins outright, which is how an
# ACL says no rather than by omission.
function Test-AdcsScepEnrollRight {
    param(
        [Parameter(Mandatory)][string]$TemplateName,
        [string[]]$Sid = @()
    )

    $result = [pscustomobject]@{ Known = $false; Allowed = $false; Denied = $false; Detail = "" }
    if (@($Sid).Count -eq 0) { return $result }

    try {
        $configurationDn = Get-AdcsConfigurationNamingContext
        $dn = "CN=$TemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configurationDn"
        if (-not (Test-StudioDirectoryObject -DistinguishedName $dn)) {
            $result.Detail = "the template is not in this forest"
            return $result
        }
        # -DaclOnly for the reason that function states: without the mask, ADSI fetches
        # the system access control list too, which needs SeSecurityPrivilege - and a read
        # that quietly fails on the privilege would read here as a permission nobody holds.
        $entry = Get-AdcsDirectoryEntry -DistinguishedName $dn -DaclOnly
        $security = $entry.ObjectSecurity
        $result.Known = $true

        $granting = @()
        foreach ($rule in @($security.Access)) {
            $ruleSid = ""
            try { $ruleSid = [string]$rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
            catch { $ruleSid = "" }
            if ([string]::IsNullOrWhiteSpace($ruleSid)) { continue }
            if (@($Sid) -notcontains $ruleSid) { continue }

            $rights = $rule.ActiveDirectoryRights
            $carriesEnroll = $false
            if (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) {
                $carriesEnroll = $true
            }
            elseif (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -eq [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) {
                $objectType = [string]$rule.ObjectType
                # All-zero means every extended right, which includes this one.
                if (($objectType -eq [string]$script:adcsEnrollRight) -or ($objectType -eq "00000000-0000-0000-0000-000000000000")) {
                    $carriesEnroll = $true
                }
            }
            if (-not $carriesEnroll) { continue }

            if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                $result.Denied = $true
                $result.Detail = "an explicit Deny"
                return $result
            }
            $result.Allowed = $true
            $name = $ruleSid
            try { $name = [string](New-Object System.Security.Principal.SecurityIdentifier($ruleSid)).Translate([System.Security.Principal.NTAccount]).Value }
            catch { $name = $ruleSid }
            if ($granting -notcontains $name) { $granting += $name }
        }
        if ($granting.Count -gt 0) { $result.Detail = "through " + ($granting -join ", ") }
    }
    catch {
        Write-Log "The permissions on '$TemplateName' could not be read: $($_.Exception.Message)" -Tag "Warn"
    }
    return $result
}

# A machine reads its own memberships from the ticket it got at boot. A group changed
# since then is a group this server does not know it is in yet, and the only cure is a
# restart - which is worth saying with the timestamps rather than as folklore.
function Test-AdcsScepGroupOlderThanBoot {
    param([Parameter(Mandatory)][string]$GroupName)

    try {
        $found = Find-AdcsGroup -Name $GroupName
        if ($null -eq $found) {
            Write-Log "    '$GroupName' is not in this domain, so nothing grants this machine Enroll on CEP Encryption through it" -Tag "Warn"
            return $true
        }
        # whenChanged off the object itself: Find-AdcsGroup loads the three attributes its
        # own callers need, and asking a search result for one it never fetched is how a
        # check like this quietly never fires.
        $entry = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://" + [string]$found.Properties["distinguishedname"][0]))
        $entry.RefreshCache(@("whenChanged"))
        $changed = [datetime]$entry.Properties["whenChanged"].Value
        $booted = [datetime](Get-CimInstance -ClassName "Win32_OperatingSystem" -ErrorAction Stop).LastBootUpTime
        # Logged either way. A check that only speaks when it fails is a check nobody can
        # tell ran at all - and this one silently answered "fine" through four bench runs
        # while the machine's ticket was the open question.
        Write-Log ("    '{0}' last changed {1}Z; this server booted {2} - its ticket {3} the membership" -f
            $GroupName, $changed.ToString("yyyy-MM-dd HH:mm"), $booted.ToString("yyyy-MM-dd HH:mm"),
            $(if ($changed -gt $booted.ToUniversalTime()) { "PREDATES" } else { "is newer than" })) -Tag "Info"
        if ($changed -gt $booted.ToUniversalTime()) {
            Write-Log ("'{0}' was changed at {1}Z and this server last booted at {2} - its ticket predates the membership" -f
                $GroupName, $changed.ToString("yyyy-MM-dd HH:mm"), $booted.ToString("yyyy-MM-dd HH:mm")) -Tag "Warn"
            Write-Log "    A computer's group memberships arrive in its ticket at boot - this server has to RESTART before it can use that grant" -Tag "Warn"
            return $false
        }
    }
    catch {
        # Unreadable is not evidence of anything - but silence about it is how a check
        # gets believed without ever having run.
        Write-Log "    '$GroupName' could not be read, so whether this machine's ticket carries it is unknown: $($_.Exception.Message)" -Tag "Warn"
        return $true
    }
    return $true
}

# The two probes whose difference is the answer. -CAInfo goes through ICertRequest and
# needs Read; -getreg goes through ICertAdmin's configuration entry and needs Manage CA.
# One answering while the other is denied names the missing permission exactly, which is
# the thing the raw 0x80070005 never does.
function Test-AdcsScepCaAdminAccess {
    param([Parameter(Mandatory)][string]$CaConfig)

    $result = [pscustomobject]@{ Reachable = $false; ManageCa = $false; Known = $false; Detail = ""; Security = "" }
    if (-not (Get-Command -Name "certutil.exe" -ErrorAction SilentlyContinue)) { return $result }

    $info = ""
    try { $info = (& certutil.exe -config $CaConfig -CAInfo 2>&1 | Out-String) } catch { $info = "" }
    $result.Reachable = ($LASTEXITCODE -eq 0)
    if (-not $result.Reachable) {
        $result.Detail = ($info -split "`r?`n" | Where-Object { $_ -match "(?i)error|denied" } | Select-Object -First 1)
        return $result
    }

    $registry = ""
    try { $registry = (& certutil.exe -config $CaConfig -getreg "CA\Security" 2>&1 | Out-String) } catch { $registry = "" }
    if ($LASTEXITCODE -eq 0) {
        $result.ManageCa = $true
        $result.Known = $true
        # The answer is the CA's whole security descriptor - kept, because it also
        # holds the one permission none of the template checks cover: Request
        # Certificates on the CA itself.
        $result.Security = $registry
        return $result
    }
    # Reaching here means the admin interface refused. Both the flags below can be the
    # reason rather than any permission, so they are read before the caller concludes
    # anything about ACLs - and they are read again by the fuller probe either way.
    if ($registry -match "(?i)0x80070005|access is denied") {
        $result.Known = $true
        $result.Detail = "the CA answers its identity but refuses to hand over its configuration"
    }
    else {
        $result.Detail = ($registry -split "`r?`n" | Where-Object { $_ -match "(?i)error" } | Select-Object -First 1)
    }
    return $result
}

# What `certutil -getreg CA\Security` actually prints, which is not what this file
# assumed for a day. There is no hex dump and no access mask - only a verb and a
# principal, one per line:
#
#     Security REG_BINARY =
#         Allow       NT AUTHORITY\Authenticated Users
#         Allow       AD\AD CS - Administrators
#         Allow       AD\AD CS - Certificate Managers
#
# The first version of this parsed a hex dump out of that answer and rebuilt a
# RawSecurityDescriptor from the bytes, so that a specific identity could be tested for
# CA_ACCESS_ENROLL. It was written from a guess about the output format and never saw
# one; on the bench it reported "the descriptor did not parse" on every run, which is
# the second time in two days a probe here was built without looking at what the command
# says. It failed safe, and that is the only reason it cost nothing.
#
# So this reads what is there and claims no more than that: WHO the CA names, never what
# they may do. Absence of Authenticated Users is the finding worth having - it holds
# Request Certificates on a default CA, its removal is exactly the hardening that stops
# NDES enrolling, and it is visible here.
function Get-AdcsScepCaSecurityPrincipal {
    param([Parameter(Mandatory)][string]$SecurityText)

    $principals = @()
    foreach ($line in @($SecurityText -split "`r?`n")) {
        # "    Allow       AD\AD CS - Administrators". Indented, a verb with no spaces,
        # then the principal - which does contain spaces, so it is everything left.
        if ($line -notmatch '^\s+(?<verb>\S+)\s+(?<who>\S.*?)\s*$') { continue }
        $who = [string]$Matches["who"]
        # The header line "Security REG_BINARY =" matches the shape and is not an ACE.
        if ($who -match '^=?$' -or $line -match '(?i)REG_BINARY') { continue }
        if ($principals -notcontains $who) { $principals += $who }
    }
    return @($principals)
}

# A well-known SID in the name this server would print for it. Resolved rather than
# spelled, because "NT AUTHORITY\Authenticated Users" is localised - a German server
# says "NT-AUTORITÄT\Authentifizierte Benutzer", and matching the English string there
# would report a hardened CA on a perfectly ordinary one.
function Get-AdcsScepWellKnownName {
    param([Parameter(Mandatory)][string]$Sid)

    try {
        return [string](New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
    }
    catch {
        return ""
    }
}

# Whether the service account can log on as the application pool at all, read from this
# machine's EFFECTIVE security policy. IIS grants IIS_IUSRS 'Log on as a batch job' when
# it installs and that grant is what the app pool logon rides on - but a group policy
# that defines the right REPLACES the local list (CIS baselines set it to Administrators
# alone), and a deny assignment beats every allow. Neither state shows in any
# certificate-side check, and what they produce is either the configuration cmdlet's
# anonymous denial or an app pool answering 503 while every service looks healthy.
# secedit exports the merged result - local database plus whatever group policy applied
# - which is the list the logon actually consults.
function Test-AdcsScepBatchLogonRight {
    param(
        [Parameter(Mandatory)][string]$SamAccountName,
        [string[]]$AccountSid = @()
    )

    $result = [pscustomobject]@{ Ok = $true; Reason = "" }
    $iisUsersSid = "S-1-5-32-568"
    $interesting = @(@($AccountSid) + $iisUsersSid | Select-Object -Unique)

    $exportPath = Join-Path -Path $env:TEMP -ChildPath ("scep-rights-{0}.inf" -f $PID)
    $rights = @{}
    try {
        $null = & secedit.exe /export /cfg $exportPath /areas USER_RIGHTS /quiet 2>&1
        if (($LASTEXITCODE -ne 0) -or -not (Test-Path -LiteralPath $exportPath)) {
            Write-Log "    Effective user rights not exported (secedit exit $LASTEXITCODE) - 'Log on as a batch job' stays unchecked" -Tag "Warn"
            return $result
        }
        foreach ($line in @(Get-Content -LiteralPath $exportPath)) {
            if ($line -notmatch '^\s*(?<right>Se[A-Za-z]+Right|Se[A-Za-z]+Privilege)\s*=\s*(?<value>.+)$') { continue }
            $holders = @()
            foreach ($token in @($Matches["value"] -split ",")) {
                $token = $token.Trim()
                if ([string]::IsNullOrWhiteSpace($token)) { continue }
                if ($token.StartsWith("*")) { $holders += $token.TrimStart("*"); continue }
                # A name rather than a SID - resolve it, and keep the name as its own
                # fallback so an unresolvable holder still compares against the account.
                try { $holders += (New-Object System.Security.Principal.NTAccount($token)).Translate([System.Security.Principal.SecurityIdentifier]).Value }
                catch { $holders += $token }
            }
            $rights[$Matches["right"]] = $holders
        }
    }
    finally {
        if (Test-Path -LiteralPath $exportPath) { Remove-Item -LiteralPath $exportPath -Force -ErrorAction SilentlyContinue }
    }

    if ($rights.ContainsKey("SeDenyBatchLogonRight")) {
        $denied = @($rights["SeDenyBatchLogonRight"] | Where-Object { $interesting -contains $_ })
        if ($denied.Count -gt 0) {
            Write-Log "    'Deny log on as a batch job' names the service account or IIS_IUSRS - the app pool cannot log '$SamAccountName' on, whatever else is granted" -Tag "Error"
            Write-Log "        A hardening baseline's assignment. Take the account and IIS_IUSRS out of the policy defining SeDenyBatchLogonRight" -Tag "Error"
            $result.Ok = $false
            $result.Reason = "'Deny log on as a batch job' names the service account"
            return $result
        }
    }

    if (-not $rights.ContainsKey("SeBatchLogonRight")) {
        Write-Log "    'Log on as a batch job' is not policy-defined here, so the grant IIS gave IIS_IUSRS at install stands" -Tag "Debug"
        return $result
    }

    $held = @($rights["SeBatchLogonRight"] | Where-Object { $interesting -contains $_ })
    if ($held.Count -gt 0) {
        Write-Log "    'Log on as a batch job' covers the application pool - the policy-defined list includes $(if ($held -contains $iisUsersSid) { 'IIS_IUSRS' } else { "'$SamAccountName'" })" -Tag "Ok"
        return $result
    }

    # The right IS defined and the list replaces the local one - IIS's own grant to
    # IIS_IUSRS included - so this is positive evidence, not an absence: the app pool
    # has no way to log the account on. CIS 'Log on as a batch job = Administrators'
    # produces exactly this on a server every other check calls healthy.
    Write-Log "    'Log on as a batch job' IS defined by policy on this server and covers neither IIS_IUSRS nor '$SamAccountName'" -Tag "Error"
    Write-Log "        A policy-defined right REPLACES the local list, so IIS's own grant to IIS_IUSRS goes with it - the app pool cannot log on and NDES answers 503" -Tag "Warn"
    Write-Log "        Add IIS_IUSRS to whichever policy owns 'Log on as a batch job' (CIS baselines set it to Administrators alone)" -Tag "Error"
    $result.Ok = $false
    $result.Reason = "policy strips 'Log on as a batch job' from the application pool"
    return $result
}

# `certutil -CAInfo role` answers **"Role Separation: <n>"** and nothing else. It was
# built here as a caller role bitmask on a research claim that it maps to GetMyRoles; it
# does not, and the cost of that was a run refused over a permission the session held -
# the probe read the 0 out of "Role Separation: 0" and reported it as "this caller holds
# nothing" about an account that had just read the CA's whole security descriptor.
# Bench-corrected 2026-08-17. There is no cheap remote way to ask a CA what the caller's
# rights are; the CA's own ACL and what the interfaces actually answer are the evidence,
# and both are already gathered above.
function Get-AdcsScepCaRoleSeparation {
    param([Parameter(Mandatory)][string]$CaConfig)

    $output = ""
    try { $output = (& certutil.exe -config $CaConfig -CAInfo "role" 2>&1 | Out-String) } catch { $output = "" }
    if ($LASTEXITCODE -ne 0) { return -1 }
    foreach ($line in @($output -split "`r?`n")) {
        if ($line -match "(?i)role\s+separation\s*:\s*(?<value>\d+)") { return [int]$Matches["value"] }
    }
    return -1
}

# Two switches that refuse work no permission can grant, both of them things a hardening
# baseline sets and neither of them visible in any access control list:
#
#   InterfaceFlags          IF_NOREMOTEICERTREQUEST (0x2) refuses every remote
#                           certificate REQUEST while leaving the admin interface alone -
#                           which is exactly the shape of an NDES configuration that can
#                           read the CA's registry and cannot enroll from it.
#                           IF_NOREMOTEICERTADMIN (0x10) is the mirror image.
#   RoleSeparationEnabled   an account holding two CA roles is denied ALL of them, with
#                           no audit event. This design hands one group four roles, so a
#                           CA with this on refuses the very account it was set up for.
function Get-AdcsScepCaRestriction {
    param([Parameter(Mandatory)][string]$CaConfig)

    $result = [pscustomobject]@{ InterfaceFlags = -1; RoleSeparation = -1 }
    foreach ($pair in @(
        @{ Name = "CA\InterfaceFlags"; Property = "InterfaceFlags" },
        @{ Name = "CA\RoleSeparationEnabled"; Property = "RoleSeparation" })) {

        $output = ""
        try { $output = (& certutil.exe -config $CaConfig -getreg $pair.Name 2>&1 | Out-String) } catch { $output = "" }
        if ($LASTEXITCODE -ne 0) { continue }
        foreach ($line in @($output -split "`r?`n")) {
            if ($line -notmatch "REG_DWORD") { continue }
            # certutil prints the value in HEX and repeats it in decimal in brackets:
            # "InterfaceFlags REG_DWORD = 40 (64)". Reading that leading 40 as decimal is
            # how a check for flag 0x2 answers about the wrong number entirely, so the
            # bracketed decimal wins where there is one and the bare token is read as hex
            # where there is not.
            if ($line -match "\((?<dec>\d+)\)") {
                $result.($pair.Property) = [int]$Matches["dec"]
                break
            }
            if ($line -match "=\s*(?:0x)?(?<hex>[0-9a-fA-F]+)") {
                $result.($pair.Property) = [Convert]::ToInt32($Matches["hex"], 16)
                break
            }
        }
    }
    return $result
}

# Everything above, in one screen, before a single feature is installed. Returns Ok when
# the configuration can be attempted; the caller stops when it cannot.
# Can THIS server build a trusted chain for the issuing CA's own certificate?
#
# Field failure, 2026-09-10, and it cost twenty-three minutes of feature installs plus an
# uninstall to recover from. The whole PKI had been built minutes earlier; this member
# server had booted before the root existed, so its Trusted Root store did not carry
# 'MiGolf Local Root CA' yet - a member server receives the enterprise root through group
# policy's Public Key Policies, not by being in the domain. `Install-AdcsNetworkDevice-
# EnrollmentService` validates the CA's certificate before it publishes its templates,
# the chain terminated in an untrusted root, and the installer reported:
#
#     Failed to add the following certificate templates ... EnrollmentAgentOffline,
#     CEPEncryption, IPSEC (Offline request). Element not found. 0x80070490
#
# which names the three templates and is about none of them. certocm.log carried the
# actual answer four lines earlier - CERT_E_UNTRUSTEDROOT, then ERROR_NOT_FOUND naming
# the CA. `gpupdate /force` fixed it.
#
# So this asks the question the installer asks, before nine features are installed:
# read the CA's certificate out of its own Enrollment Services object in the directory
# (which is reachable whatever this machine trusts) and try to chain it here. Trust and
# revocation are two passes on purpose - an unreachable CRL is a warning, an untrusted
# root is a refusal, and a single pass would have reported them as one verdict.
function Test-AdcsScepCaChainTrust {
    param([Parameter(Mandatory)][string]$CaCommonName)

    $result = [pscustomobject]@{
        Checked         = $false
        Trusted         = $true
        RevocationKnown = $true
        RootSubject     = ""
        Detail          = ""
    }

    $certificate = $null
    try {
        $enrollmentDn = "CN=$CaCommonName,CN=Enrollment Services,CN=Public Key Services,CN=Services," +
            (Get-AdcsConfigurationNamingContext)
        if (-not (Test-StudioDirectoryObject -DistinguishedName $enrollmentDn)) { return $result }

        $entry = Get-AdcsDirectoryEntry -DistinguishedName $enrollmentDn
        $values = $entry.Properties["cACertificate"]
        if (($null -eq $values) -or ($values.Count -eq 0)) { return $result }
        $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [byte[]]$values[0])
    }
    catch {
        # Not a refusal: a directory this run cannot read is a different problem, and the
        # checks around this one will say so in their own words.
        Write-Log "    The issuing CA's certificate could not be read from the directory, so its chain was not checked: $($_.Exception.Message)" -Tag "Debug"
        return $result
    }

    $result.Checked = $true

    # Pass one: trust alone. RevocationMode NoCheck, because a CRL this server cannot
    # fetch must not be reported as an untrusted root - they are different faults with
    # different fixes.
    try {
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $null = $chain.Build($certificate)
        if ($chain.ChainElements.Count -gt 0) {
            $result.RootSubject = [string]$chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Subject
        }
        foreach ($status in @($chain.ChainStatus)) {
            if (@("UntrustedRoot", "PartialChain") -contains [string]$status.Status) {
                $result.Trusted = $false
                $result.Detail = [string]$status.StatusInformation
            }
        }
    }
    catch {
        Write-Log "    The issuing CA's chain could not be built here: $($_.Exception.Message)" -Tag "Debug"
        return $result
    }

    # Pass two: revocation, and only when the chain is trusted - an untrusted chain has
    # nothing useful to say about its own CRLs.
    if ($result.Trusted) {
        try {
            $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
            $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
            $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
            $chain.ChainPolicy.UrlRetrievalTimeout = New-TimeSpan -Seconds 15
            $null = $chain.Build($certificate)
            foreach ($status in @($chain.ChainStatus)) {
                if (@("RevocationStatusUnknown", "OfflineRevocation") -contains [string]$status.Status) {
                    $result.RevocationKnown = $false
                }
            }
        }
        catch {
            $result.RevocationKnown = $false
        }
    }

    return $result
}

function Test-AdcsScepAccess {
    param([Parameter(Mandatory)][object]$CertificateServices)

    $result = [pscustomobject]@{ Ok = $true; Reason = "" }

    $shared = Get-ConfigValue -InputObject $CertificateServices -Name "shared"
    $issuing = Get-ConfigValue -InputObject $CertificateServices -Name "issuing"
    $forest = Get-ConfigText -InputObject $shared -Name "forestDomainName"
    $caComputer = Get-ConfigText -InputObject $issuing -Name "computerName"
    $caName = Get-ConfigText -InputObject $issuing -Name "caCommonName"
    if ([string]::IsNullOrWhiteSpace($caComputer) -or [string]::IsNullOrWhiteSpace($caName)) { return $result }
    $caConfig = "{0}.{1}\{2}" -f $caComputer.ToLowerInvariant(), $forest, $caName

    Write-Log "Checking that this session can configure NDES" -Tag "Run"

    $whoami = $env:USERNAME
    try { $whoami = [string][System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $whoami = $env:USERNAME }

    # The machine account cannot configure NDES, and this is the cheapest place to say
    # so. It is not a hypothetical: a feature install that asks for a restart hands the
    # rest of the plan to the resume task, which runs as SYSTEM - so the next attempt is
    # made by this server's own account, which holds neither Domain Admins nor Manage CA.
    # Refusing here costs nothing; the alternative is nine feature installs and an access
    # denied that names none of this.
    if ($whoami -match '(?i)^(NT AUTHORITY\\SYSTEM|.*\$)$') {
        Write-Log "    this session is '$whoami' - the machine account, which cannot configure NDES" -Tag "Error"
        Write-Log "        The configuration enrolls the RA certificates and writes to the CA, and Microsoft documents a domain account for it" -Tag "Error"
        Write-Log "        This is the resume task after a restart. Run the script at the console as the account that administers the issuing CA" -Tag "Error"
        $result.Ok = $false
        $result.Reason = "it is running as '$whoami', and the machine account cannot configure NDES"
        return $result
    }

    # Three identities, because which of them enrolls the registration authority
    # certificates has never been bisected on a bench and the documented answers
    # disagree: the installing user (Microsoft's own replacement procedure), the machine
    # (the renewal flow), and the service account (several field guides). Checking all
    # three costs three directory reads and settles the question the next time this
    # fails - and a template that none of them can enroll is a refusal under every one
    # of those readings.
    $scep = Get-AdcsScepSection -CertificateServices $CertificateServices
    $serviceAccount = Get-AdcsScepServiceAccount -Scep $scep
    $identities = @(
        [pscustomobject]@{ Label = "this session ($whoami)"; Short = "this session"; Sid = @(Get-AdcsScepTokenSid) }
        [pscustomobject]@{ Label = "this machine ($env:COMPUTERNAME$)"; Short = "this machine"
            Sid = @(Get-AdcsScepAccountSid -SamAccountName "$env:COMPUTERNAME$" -Kind "computer") }
    )
    $serviceSids = @()
    if ($null -ne $serviceAccount) {
        $serviceSids = @(Get-AdcsScepAccountSid -SamAccountName $serviceAccount.SamAccountName -Kind "user")
        $identities += [pscustomobject]@{ Label = "the service account ($($serviceAccount.SamAccountName))"
            Short = "the service account"
            Sid = $serviceSids }
    }
    Write-Log ("    running as '{0}', whose token carries {1} SID(s)" -f $whoami, @($identities[0].Sid).Count) -Tag "Info"

    # The application pool's logon right, before anything asks about certificates: a
    # hardening baseline that defines 'Log on as a batch job' replaces the local list
    # and takes IIS's own grant to IIS_IUSRS with it, and no certificate-side check
    # ever names that.
    if ($null -ne $serviceAccount) {
        $logon = Test-AdcsScepBatchLogonRight -SamAccountName $serviceAccount.SamAccountName -AccountSid $serviceSids
        if (-not $logon.Ok) {
            $result.Ok = $false
            $result.Reason = $logon.Reason
        }
    }

    $blocked = @()
    foreach ($template in $script:adcsScepRaTemplate) {
        $holders = @()
        $denied = $false
        $known = $false
        $detail = ""
        foreach ($identity in $identities) {
            $verdict = Test-AdcsScepEnrollRight -TemplateName $template.Name -Sid $identity.Sid
            if ($verdict.Known) { $known = $true }
            if ($verdict.Denied) { $denied = $true }
            if ($verdict.Allowed) {
                $holders += $identity.Short
                if ([string]::IsNullOrWhiteSpace($detail)) { $detail = $verdict.Detail }
            }
        }

        if ($holders.Count -gt 0) {
            Write-Log ("    {0}: enrollable by {1} {2}" -f $template.Display, ($holders -join " and "), $detail) -Tag "Ok"
            continue
        }
        if (-not $known) {
            Write-Log ("    {0}: permissions unreadable from here - unchecked rather than refused" -f $template.Display) -Tag "Warn"
            continue
        }
        if ($denied) {
            Write-Log ("    {0}: DENIED outright on the template's own permissions" -f $template.Display) -Tag "Error"
        }
        else {
            Write-Log ("    {0}: none of this session, this machine or the service account holds Enroll on it" -f $template.Display) -Tag "Error"
            Write-Log ("        it {0}, and it is enrolled while NDES configures - a template none of the three can enroll is the access denied with no name on it" -f $template.Does) -Tag "Error"
        }
        $blocked += $template
    }

    foreach ($template in $blocked) {
        $key = "enrollmentAgent"
        if ($template.Name -eq "CEPEncryption") { $key = "cepEncryption" }
        $groupName = Get-AdcsScepRaGroupName -CertificateServices $CertificateServices -Key $key
        if ([string]::IsNullOrWhiteSpace($groupName)) { continue }
        Write-Log ("    '{0}' is the group this design grants Enroll on {1}" -f $groupName, $template.Display) -Tag "Error"
        if ($template.Name -eq "CEPEncryption") {
            Write-Log ("        put this server's computer account in it - the directory run does that - and RESTART so its ticket carries it:" -f $groupName) -Tag "Error"
            Write-Log ("        Add-ADGroupMember -Identity '{0}' -Members '{1}$'" -f $groupName, $env:COMPUTERNAME) -Tag "Error"
        }
        else {
            Write-Log "        put the account running this in it, then SIGN OUT and back in - a session predating the membership does not carry it:" -Tag "Error"
            Write-Log ("        Add-ADGroupMember -Identity '{0}' -Members '{1}'" -f $groupName, $env:USERNAME) -Tag "Error"
        }
    }

    if ($blocked.Count -gt 0) {
        $result.Ok = $false
        $result.Reason = ("nothing here can enroll {0}" -f (($blocked | ForEach-Object { $_.Display }) -join " or "))
    }

    # The machine's ticket, when the machine is one of the identities that matters.
    $cepGroup = Get-AdcsScepRaGroupName -CertificateServices $CertificateServices -Key "cepEncryption"
    if (-not [string]::IsNullOrWhiteSpace($cepGroup)) { $null = Test-AdcsScepGroupOlderThanBoot -GroupName $cepGroup }

    # Manage CA, probed rather than assumed.
    # Before anything about permissions: can this server chain the CA's certificate at
    # all? A permission it holds is no use against a root it does not trust, and this is
    # the check that would have saved the 2026-09-10 bench run - see Test-AdcsScepCaChainTrust.
    $chain = Test-AdcsScepCaChainTrust -CaCommonName $caName
    if ($chain.Checked) {
        if (-not $chain.Trusted) {
            Write-Log "    this server does NOT trust the issuing CA's own certificate - its chain ends in a root that is not in this machine's Trusted Root store" -Tag "Error"
            if ($chain.RootSubject) {
                Write-Log ("        the root it ends in is {0}" -f $chain.RootSubject) -Tag "Error"
            }
            Write-Log "        A member server receives the enterprise root through group policy, not by being in the domain - a server that booted before the PKI existed has never seen it" -Tag "Error"
            Write-Log "        gpupdate /force        then    certutil -pulse" -Tag "Error"
            Write-Log "        Check it arrived:  Get-ChildItem Cert:\LocalMachine\Root | Where-Object { `$_.Subject -match 'CA' }" -Tag "Error"
            Write-Log "        If it never arrives the root is not published in the directory: on the domain controller,  certutil -dspublish -f <root>.crt RootCA" -Tag "Error"
            Write-Log "        This is what the NDES installer refuses on, and it refuses in the words of something else: it validates the CA certificate before publishing its own templates, and reports 'Failed to add the following certificate templates ... 0x80070490' when the chain does not build" -Tag "Error"
            $result.Ok = $false
            $result.Reason = "this server does not trust the issuing CA's certificate chain"
            return $result
        }
        Write-Log "    the issuing CA's certificate chains to a trusted root on this server" -Tag "Ok"
        if (-not $chain.RevocationKnown) {
            Write-Log "    the revocation status of that chain is unknown here - a CDP or a CRL this server cannot fetch" -Tag "Warn"
            Write-Log "        Not a refusal: NDES configured with an unreachable CRL, and enrollment later does not. certutil -verify -urlfetch is the same question by hand" -Tag "Warn"
        }
    }

    $ca = Test-AdcsScepCaAdminAccess -CaConfig $caConfig
    if (-not $ca.Reachable) {
        Write-Log "    '$caConfig' did not answer at all: $($ca.Detail)" -Tag "Warn"
        Write-Log "        certutil -config `"$caConfig`" -CAInfo     is the same question by hand" -Tag "Info"
    }
    elseif ($ca.ManageCa) {
        Write-Log "    '$caConfig' answers, and this session can read its configuration - Manage CA is held" -Tag "Ok"
    }
    elseif ($ca.Known) {
        Write-Log "    '$caConfig' answers this session, but REFUSES its configuration - this session does not hold Manage CA on it" -Tag "Error"
        Write-Log "        That is the documented cause of 'CMSCEPSetup::Install: Access is denied. 0x80070005'" -Tag "Error"

        # Read from the design rather than hedged about. A run that says "if this design
        # stripped the built-in admins" to somebody whose design did exactly that is
        # asking them to go and find out something it already knows.
        $roleGroups = Get-ConfigValue -InputObject $CertificateServices -Name "roleGroups"
        $adminGroup = ""
        foreach ($entry in @(Get-ConfigArray -InputObject $roleGroups -Name "groups")) {
            if ([string](Get-ConfigText -InputObject $entry -Name "role" -Default "") -eq "administrator") {
                $adminGroup = [string](Get-ConfigText -InputObject $entry -Name "name" -Default "")
                break
            }
        }
        if ([bool](Get-ConfigValue -InputObject $roleGroups -Name "removeBuiltinAdmins" -Default $false)) {
            Write-Log "        THIS DESIGN removed the built-in administrators from that CA (roleGroups.removeBuiltinAdmins), so Domain and Enterprise Admins hold nothing on it" -Tag "Error"
            if (-not [string]::IsNullOrWhiteSpace($adminGroup)) {
                Write-Log ("        Manage CA lives in '{0}' alone - and a session signed in before the membership does not carry it:" -f $adminGroup) -Tag "Error"
                Write-Log ("        Add-ADGroupMember -Identity '{0}' -Members '{1}'    then sign out and back in" -f $adminGroup, $env:USERNAME) -Tag "Error"
            }
        }
        elseif (-not [string]::IsNullOrWhiteSpace($adminGroup)) {
            Write-Log ("        The built-in administrators are still on that CA, so this is the account rather than the design - Manage CA lives in '{0}'" -f $adminGroup) -Tag "Error"
        }
        Write-Log "        Check what this session actually holds:  whoami /groups | findstr /i `"AD CS`"" -Tag "Error"
        $result.Ok = $false
        if ([string]::IsNullOrWhiteSpace($result.Reason)) { $result.Reason = "this session does not hold Manage CA on '$caConfig'" }
        else { $result.Reason = $result.Reason + ", and this session does not hold Manage CA on '$caConfig'" }
    }
    else {
        Write-Log "    '$caConfig' answers, and whether this session holds Manage CA could not be established: $($ca.Detail)" -Tag "Warn"
    }

    if ($ca.Reachable -and $ca.ManageCa -and -not [string]::IsNullOrWhiteSpace($ca.Security)) {
        # WHO the CA names, which is all `certutil -getreg CA\Security` reports - it
        # prints a verb and a principal per line and no access mask at all, so nothing
        # here can say whether a given identity holds Request Certificates. Reported as
        # the context it is rather than dressed up as a verdict.
        #
        # The one thing worth acting on is an absence: Authenticated Users holds Request
        # Certificates on a default CA, so a CA that no longer names it has been
        # tightened, and NDES enrolling from a member server is exactly what that breaks.
        # A warning, never a refusal - the group could have been replaced by a named one
        # that covers these identities perfectly well, and this output cannot tell.
        $principals = @(Get-AdcsScepCaSecurityPrincipal -SecurityText $ca.Security)
        if ($principals.Count -eq 0) {
            Write-Log "    the CA's security list could not be read from certutil's answer, so who it grants is unchecked" -Tag "Warn"
        }
        else {
            Write-Log ("    '{0}' names {1} principal(s) in its security: {2}" -f $caConfig, $principals.Count, ($principals -join ", ")) -Tag "Info"
            Write-Log "        certutil prints no access mask, so this says who the CA names and not what they may do" -Tag "Debug"
            # The raw block, because the parsed list above deliberately throws away
            # everything it cannot be sure of - and the one question a failed enrollment
            # actually turns on is whether anybody here holds REQUEST CERTIFICATES, which
            # is a different permission from the Manage CA proven above. Nothing here can
            # answer that from certutil's output, so the output itself goes in the log
            # rather than a guess about it.
            foreach ($line in @($ca.Security -split "`r?`n")) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                Write-Log ("        CA\Security: {0}" -f $line.Trim()) -Tag "Debug"
            }
            Write-Log "        Enrolling needs Request Certificates on the CA, which is NOT the Manage CA proven above - a design that" -Tag "Debug"
            Write-Log "        rewrote this descriptor can hold one without the other. On the CA:  certutil -getreg CA\Security" -Tag "Debug"

            $authenticated = Get-AdcsScepWellKnownName -Sid "S-1-5-11"
            $everyone = Get-AdcsScepWellKnownName -Sid "S-1-1-0"
            $broad = @($principals | Where-Object {
                (-not [string]::IsNullOrWhiteSpace($authenticated) -and ($_ -eq $authenticated)) -or
                (-not [string]::IsNullOrWhiteSpace($everyone) -and ($_ -eq $everyone))
            })
            if ($broad.Count -gt 0) {
                Write-Log ("        '{0}' is among them, which is where Request Certificates lives on a default CA" -f $broad[0]) -Tag "Debug"
            }
            else {
                Write-Log "    the CA does NOT name Authenticated Users, so Request Certificates was tightened on it" -Tag "Warn"
                Write-Log "        That permission is what lets NDES submit at all, and this design's identities have to sit inside one of the groups above" -Tag "Warn"
                Write-Log "        Not a refusal - one of those groups may cover them, and certutil's answer cannot say which" -Tag "Debug"
            }
        }
    }

    if ($ca.Reachable) {
        # What the CA says this caller is, which is a different question from what an
        # access control list grants a SID - and the only one that answers whether the
        # registration authority certificates can be enrolled at all.
        # The two switches on the CA that refuse work no permission can grant. Read and
        # decoded in full, and only the two that genuinely stop this are refusals - the
        # rest is printed because a reader chasing an access denied should see the CA's
        # posture rather than have to go and ask for it.
        $restriction = Get-AdcsScepCaRestriction -CaConfig $caConfig
        if ($restriction.InterfaceFlags -ge 0) {
            $flagNames = @{
                0x1 = "IF_LOCKICERTREQUEST"; 0x2 = "IF_NOREMOTEICERTREQUEST"
                0x8 = "IF_NOLOCALICERTREQUEST"; 0x10 = "IF_NOREMOTEICERTADMIN"
                0x20 = "IF_NOLOCALICERTADMIN"; 0x40 = "IF_NOREMOTEICERTADMINBACKUP"
                0x80 = "IF_NOLOCALICERTADMINBACKUP"; 0x100 = "IF_NOSNAPSHOTBACKUP"
                0x200 = "IF_ENFORCEENCRYPTICERTREQUEST"; 0x400 = "IF_ENFORCEENCRYPTICERTADMIN"
                0x800 = "IF_ENFORCEENCRYPTICERTADMINBACKUP"; 0x1000 = "IF_ENABLEADMINASAUDITOR"
            }
            $set = @()
            foreach ($bit in @($flagNames.Keys | Sort-Object)) {
                if (($restriction.InterfaceFlags -band $bit) -ne 0) { $set += $flagNames[$bit] }
            }
            Write-Log ("    '{0}' InterfaceFlags 0x{1:x}: {2}" -f $caConfig, $restriction.InterfaceFlags,
                $(if ($set.Count -gt 0) { ($set -join ", ") } else { "none set" })) -Tag "Info"
            # The two enforce-encryption flags are the modern default and are NOT a
            # fault - saying so keeps the next reader from turning off a mitigation
            # (ESC11) that was never the problem.
            if (($restriction.InterfaceFlags -band 0x600) -eq 0x600) {
                Write-Log "        The two ENFORCEENCRYPT flags are the current default and the ESC11 mitigation - leave them on" -Tag "Debug"
            }

            foreach ($pair in @(@{ Bit = 0x2; What = "certificate request" }, @{ Bit = 0x10; What = "administration" })) {
                if (($restriction.InterfaceFlags -band $pair.Bit) -eq 0) { continue }
                Write-Log ("    Including {0}, which refuses EVERY remote {1} call whatever the permissions say" -f $flagNames[$pair.Bit], $pair.What) -Tag "Error"
                Write-Log ("        On the CA:  certutil -setreg CA\InterfaceFlags -{0}   then restart certsvc" -f $flagNames[$pair.Bit]) -Tag "Error"
                $result.Ok = $false
                if ([string]::IsNullOrWhiteSpace($result.Reason)) { $result.Reason = ("the CA refuses remote {0} calls ({1})" -f $pair.What, $flagNames[$pair.Bit]) }
                else { $result.Reason = $result.Reason + (", and the CA refuses remote {0} calls" -f $pair.What) }
            }
        }

        # Role separation, asked two ways because the registry value is absent by default
        # and its absence means off rather than unknown.
        $separation = Get-AdcsScepCaRoleSeparation -CaConfig $caConfig
        if ($separation -lt 0) { $separation = $restriction.RoleSeparation }
        if ($separation -gt 0) {
            Write-Log ("    '{0}' has role separation ENABLED" -f $caConfig) -Tag "Warn"
            Write-Log "        With it on, an account holding two CA roles is denied ALL of them, and the denial writes no audit event" -Tag "Warn"
            Write-Log "        This design hands its role groups four separate roles, so an account in several is exactly that case" -Tag "Warn"
            Write-Log "        On the CA:  certutil -delreg CA\RoleSeparationEnabled   then restart certsvc" -Tag "Warn"
        }
        elseif ($separation -eq 0) {
            Write-Log "    role separation is off on that CA, so holding several role groups is not what is refusing anything" -Tag "Debug"
        }
        else {
            # -1 is "could not be read", and the first version of this said nothing at
            # all for that - so a CA whose role separation was unknown looked exactly
            # like one where it had been checked and found off. Silence is the one
            # answer a diagnostic must never give.
            Write-Log "    whether role separation is on could not be read from that CA - it is UNCHECKED, not off" -Tag "Warn"
            Write-Log "        With it on, an account holding two CA roles is denied all of them, and this design hands out four" -Tag "Warn"
            Write-Log "        On the CA:  certutil -getreg CA\RoleSeparationEnabled" -Tag "Warn"
        }
    }

    # The last thing the configuration does is write two virtual directories, and it is
    # where a run whose every permission is in order still fails. Checked here because
    # the IIS side is as much a prerequisite as the CA side, and because the error it
    # produces names nothing.
    $siteName = Get-ConfigText -InputObject $scep -Name "siteName" -Default "Default Web Site"
    if (-not (Test-AdcsScepIisPath -SiteName $siteName)) {
        $result.Ok = $false
        if ([string]::IsNullOrWhiteSpace($result.Reason)) { $result.Reason = "IIS cannot carry the NDES virtual directories" }
        else { $result.Reason = $result.Reason + ", and IIS cannot carry the NDES virtual directories" }
    }

    return $result
}

# Where NDES puts its two virtual directories, and why that is not a question about
# permissions at all. The configuration ends by writing
# `/LM/W3SVC/1/ROOT/CertSrv/mscep` and `.../mscep_admin` - an IIS 6 metabase path, and
# **site number 1 literally**, not "whichever site the design named". Three things have
# to be true for that write to land, and when one is not the whole configuration fails
# with `Failed to add the web virtual directory ... 0x80070003 ERROR_PATH_NOT_FOUND`,
# which names no site, no folder and no cause. Field-hit 2026-08-17, after the access
# checks above had all passed.
function Test-AdcsScepIisPath {
    param([Parameter(Mandatory)][string]$SiteName)

    $ok = $true
    $appCmd = Join-Path -Path $env:SystemRoot -ChildPath "system32\inetsrv\appcmd.exe"
    if (-not (Test-Path -LiteralPath $appCmd)) {
        Write-Log "    appcmd.exe is not on this server, so the IIS side was not checked" -Tag "Warn"
        return $true
    }

    $sites = ""
    try { $sites = (& $appCmd "list" "sites" 2>&1 | Out-String) } catch { $sites = "" }
    if ([string]::IsNullOrWhiteSpace($sites)) {
        Write-Log "    IIS listed no sites at all, so the NDES virtual directories have nowhere to go" -Tag "Error"
        return $false
    }

    # SITE "Default Web Site" (id:1,bindings:http/*:80:,state:Started)
    $siteOne = ""
    foreach ($line in @($sites -split "`r?`n")) {
        if ($line -match '^SITE\s+"(?<name>[^"]+)"\s+\(id:(?<id>\d+)') {
            if ([int]$Matches["id"] -eq 1) { $siteOne = $Matches["name"] }
        }
    }

    if ([string]::IsNullOrWhiteSpace($siteOne)) {
        Write-Log "    No IIS site carries id 1 here, and NDES writes its virtual directories to '/LM/W3SVC/1/ROOT/CertSrv' by number" -Tag "Error"
        Write-Log "        That is the whole of 'Failed to add the web virtual directory ... 0x80070003' - it is not a permission" -Tag "Error"
        Write-Log "        The sites here are:" -Tag "Error"
        foreach ($line in @($sites -split "`r?`n" | Where-Object { $_ -match '^SITE' })) {
            Write-Log ("            " + $line.Trim()) -Tag "Info"
        }
        Write-Log "        Give the site NDES should live in id 1, or recreate the Default Web Site:" -Tag "Error"
        Write-Log ("        {0} set site /site.name:`"{1}`" /id:1" -f $appCmd, $SiteName) -Tag "Error"
        return $false
    }
    Write-Log "    IIS site id 1 is '$siteOne' - where NDES writes its virtual directories" -Tag "Ok"
    if (-not $siteOne.Equals($SiteName, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Log "        The design names '$SiteName' for the HTTPS binding, which is a different site - NDES still lands in id 1" -Tag "Warn"
    }

    # A site can be listed and still have nothing under it. `/LM/W3SVC/1/ROOT` is the
    # site's **root application and its root virtual directory**, and a failed NDES
    # attempt is documented as corrupting applicationHost.config - after which
    # `appcmd list sites` answers happily while ROOT resolves to nothing and every child
    # vdir fails with exactly this error. So an empty answer here is the finding, not a
    # reason to skip: the first version of this check treated it as "nothing to say" and
    # passed the one server it was written for. Field-hit 2026-08-17.
    $rootApp = ""
    try { $rootApp = ((& $appCmd "list" "app" ("{0}/" -f $siteOne) 2>&1 | Out-String)).Trim() } catch { $rootApp = "" }
    $physicalPath = ""
    try { $physicalPath = ((& $appCmd "list" "vdir" ("{0}/" -f $siteOne) "/text:physicalPath" 2>&1 | Out-String)).Trim() }
    catch { $physicalPath = "" }

    # The path the two virtual directories hang off. It is not itself a virtual directory
    # on an NDES-only server - `/CertSrv` is a path segment the configuration creates as
    # it writes the first of the pair - but once something has removed one of them by
    # hand, the segment is gone and the next attempt cannot create a child under it. That
    # is why the reset below restores the whole IIS configuration rather than deleting
    # the two entries: this state looks identical to a healthy one from every angle
    # except the one that matters.
    $mscepVdir = ""
    try { $mscepVdir = ((& $appCmd "list" "vdir" ("{0}/CertSrv/mscep" -f $siteOne) 2>&1 | Out-String)).Trim() } catch { $mscepVdir = "" }
    $adminVdir = ""
    try { $adminVdir = ((& $appCmd "list" "vdir" ("{0}/CertSrv/mscep_admin" -f $siteOne) 2>&1 | Out-String)).Trim() } catch { $adminVdir = "" }
    if ((-not [string]::IsNullOrWhiteSpace($mscepVdir)) -xor (-not [string]::IsNullOrWhiteSpace($adminVdir))) {
        Write-Log "    Exactly one of the two NDES virtual directories exists - a half-removed pair, neither clean nor configured" -Tag "Warn"
        Write-Log "        The configuration will try to create the missing one under a path the survivor holds open - restore the IIS configuration instead" -Tag "Warn"
    }

    if ([string]::IsNullOrWhiteSpace($rootApp) -or [string]::IsNullOrWhiteSpace($physicalPath)) {
        Write-Log "    '$siteOne' is listed, but its ROOT application or root virtual directory is missing from the IIS configuration" -Tag "Error"
        Write-Log "        That is '/LM/W3SVC/1/ROOT' resolving to nothing - what 'Failed to add the web virtual directory' means here" -Tag "Error"
        Write-Log "        A failed NDES configuration is documented as leaving applicationHost.config like this - the site survives, its root does not" -Tag "Error"
        Write-Log "        Restore the file from the component store and rebuild the site, then run this again:" -Tag "Error"
        Write-Log "            Uninstall-AdcsNetworkDeviceEnrollmentService -Force" -Tag "Error"
        Write-Log "            `$config = Get-ChildItem C:\Windows\WinSxS -Recurse -Filter applicationHost.config -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1" -Tag "Error"
        Write-Log "            Copy-Item `$config.FullName 'C:\Windows\System32\inetsrv\config\applicationHost.config' -Force" -Tag "Error"
        Write-Log "            & `"`$env:SystemRoot\System32\inetsrv\appcmd.exe`" add site /name:'Default Web Site' /bindings:http/*:80: /physicalPath:'%SystemDrive%\inetpub\wwwroot'" -Tag "Error"
        $ok = $false
    }
    else {
        # "The system cannot find the path specified" is a filesystem error before it is
        # anything else, and a build that moved or never created inetpub produces it.
        $expanded = [System.Environment]::ExpandEnvironmentVariables($physicalPath)
        if (Test-Path -LiteralPath $expanded) {
            Write-Log "    '$siteOne' serves '$expanded', which is on disk" -Tag "Info"
        }
        else {
            Write-Log "    '$siteOne' points at '$expanded', and that folder is NOT on this server" -Tag "Error"
            Write-Log "        A virtual directory cannot be created under a root whose folder does not exist" -Tag "Error"
            Write-Log ("        New-Item -ItemType Directory -Path '{0}' -Force" -f $expanded) -Tag "Error"
            $ok = $false
        }
    }

    # What is under it already. NDES writes mscep and mscep_admin below CertSrv, so a
    # half-written CertSrv from an earlier attempt is worth seeing rather than guessing at.
    $vdirs = ""
    try { $vdirs = (& $appCmd "list" "vdir" 2>&1 | Out-String) } catch { $vdirs = "" }
    $existing = @($vdirs -split "`r?`n" | Where-Object { $_ -match "(?i)certsrv|mscep" })
    if ($existing.Count -gt 0) {
        Write-Log "    The certificate services virtual directories already on this server:" -Tag "Info"
        foreach ($line in $existing) { Write-Log ("        " + $line.Trim()) -Tag "Info" }
    }

    # The folder the two virtual directories point INTO. It arrives with the role
    # service, so its absence means the feature is installed and its payload is not.
    $mscepFolder = Join-Path -Path $env:SystemRoot -ChildPath "system32\certsrv\mscep"
    if (-not (Test-Path -LiteralPath $mscepFolder)) {
        Write-Log "    '$mscepFolder' is not on this server, and that is what the NDES virtual directories point into" -Tag "Error"
        Write-Log "        The role service is installed without its payload - reinstall ADCS-Device-Enrollment, with -Source if there is no Windows Update" -Tag "Error"
        $ok = $false
    }
    return $ok
}

# What a failed configuration leaves behind, and how to get back to a server this can be
# tried on again. Every one of these is something a failed attempt creates and a retry
# then trips over: the MSCEP key is what makes every later run say "already configured"
# and skip the step entirely, the two virtual directories come back as ERROR_ALREADY_EXISTS,
# and a half-enrolled registration authority certificate is worse than none because the
# health check counts it. Printed on failure rather than kept in somebody's notes.
function Write-AdcsScepResetChecklist {
    param([string]$SiteName = "Default Web Site")

    Write-Log "    To try again this server has to go back to before the attempt - a retry over the leftovers fails differently:" -Tag "Info"
    Write-Log "        Uninstall-AdcsNetworkDeviceEnrollmentService -Force" -Tag "Info"
    Write-Log "        Remove-Item 'HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP' -Recurse -Force -ErrorAction SilentlyContinue" -Tag "Info"
    # **Not `appcmd delete vdir`.** Deleting the two virtual directories by hand leaves
    # the CertSrv path node they hung off in a state the configuration cannot create a
    # child under, and the next attempt fails at 0x80070003 instead of getting as far as
    # it did. Restoring the file and rebuilding the site removes them as a side effect and
    # leaves IIS in the one state this configuration is known to get past. Bench-proven
    # both ways on 2026-08-17: surgical deletes broke it, the restore fixed it.
    Write-Log "        the two virtual directories go with the IIS configuration, which is restored rather than edited:" -Tag "Info"
    Write-Log "            `$config = Get-ChildItem C:\Windows\WinSxS -Recurse -Filter applicationHost.config -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1" -Tag "Info"
    Write-Log "            Copy-Item `$config.FullName 'C:\Windows\System32\inetsrv\config\applicationHost.config' -Force" -Tag "Info"
    Write-Log ("            & `"`$env:SystemRoot\System32\inetsrv\appcmd.exe`" add site /name:`"{0}`" /bindings:http/*:80: /physicalPath:`"%SystemDrive%\inetpub\wwwroot`"" -f $SiteName) -Tag "Info"
    Write-Log "            the HTTPS binding goes with it and this run puts it back on the next pass" -Tag "Debug"
    Write-Log "        Get-ChildItem Cert:\LocalMachine\My | Where-Object { `$_.Subject -match 'MSCEP' } | Remove-Item" -Tag "Info"
    Write-Log "            registration authority certificates only - read the list first, the HTTPS certificate lives in the same store" -Tag "Warn"
        Write-Log "        Restart once, so this machine's account picks up the group" -Tag "Info"
}

# What the configuration itself wrote down. `Install-AdcsNetworkDeviceEnrollmentService`
# logs every step to certocm.log and the failing call is named in it - which is the one
# place the reason for an access denied actually exists. Read on failure, because the
# alternative has been guessing at it across bench runs.
# The same file, read and not printed. The block that decides WHAT to say about a
# failure has to see it before the block that prints it does - the installer's own
# message names the wrong thing often enough that the log is the better witness.
function Get-AdcsScepSetupLogText {
    $path = Join-Path -Path $env:SystemRoot -ChildPath "certocm.log"
    if (-not (Test-Path -LiteralPath $path)) { return "" }
    try { return (@(Get-Content -LiteralPath $path -ErrorAction Stop -Tail 400) -join "`n") }
    catch { return "" }
}

function Write-AdcsScepSetupLog {
    $path = Join-Path -Path $env:SystemRoot -ChildPath "certocm.log"
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Log "    No certocm.log on this server - the configuration did not get far enough to write one" -Tag "Info"
        return
    }

    $lines = @()
    try { $lines = @(Get-Content -LiteralPath $path -ErrorAction Stop -Tail 400) }
    catch {
        Write-Log "    '$path' could not be read: $($_.Exception.Message)" -Tag "Warn"
        return
    }
    if ($lines.Count -eq 0) { return }

    # **Verbatim, in order.** The first version printed only the lines carrying an error
    # code, which reads as tidier and threw away the part that mattered: a failure with a
    # twenty-one second gap in front of it is a failure whose cause is in that gap, and
    # every line in it had been filtered out for not looking like an error. What a log is
    # for is the sequence.
    $interesting = @($lines | Select-Object -Last 45)

    Write-Log "    certocm.log, which is where the configuration wrote down what it was doing when it failed:" -Tag "Error"
    foreach ($line in $interesting) {
        $text = ([string]$line).TrimEnd()
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        Write-Log ("        " + $text) -Tag "Info"
    }
    Write-Log "    The whole file is '$path' - the lines above are its last 45" -Tag "Debug"
}

function Install-AdcsScepService {
    param(
        [Parameter(Mandatory)][object]$CertificateServices,
        [Parameter(Mandatory)][object]$Account
    )

    if ([string]::IsNullOrWhiteSpace($Account.Password)) {
        Write-Log "The design carries no password for '$($Account.SamAccountName)' - NDES cannot be configured unattended" -Tag "Error"
        Write-Log "Export the design with secrets included, or configure NDES by hand:" -Tag "Error"
        Write-Log "    Install-AdcsNetworkDeviceEnrollmentService -ServiceAccountName '$env:USERDOMAIN\$($Account.SamAccountName)' -ServiceAccountPassword (Read-Host -AsSecureString) -CAConfig '<CA server FQDN>\<CA name>'" -Tag "Error"
        return $false
    }

    $shared = Get-ConfigValue -InputObject $CertificateServices -Name "shared"
    $issuing = Get-ConfigValue -InputObject $CertificateServices -Name "issuing"
    $forest = Get-ConfigText -InputObject $shared -Name "forestDomainName"
    $caComputer = Get-ConfigText -InputObject $issuing -Name "computerName"
    $caName = Get-ConfigText -InputObject $issuing -Name "caCommonName"
    if ([string]::IsNullOrWhiteSpace($caComputer) -or [string]::IsNullOrWhiteSpace($caName)) {
        Write-Log "The design names no issuing CA - NDES has nothing to enroll against" -Tag "Error"
        return $false
    }
    $caConfig = "{0}.{1}\{2}" -f $caComputer.ToLowerInvariant(), $forest, $caName

    if ($null -eq (Get-Command -Name "Install-AdcsNetworkDeviceEnrollmentService" -ErrorAction SilentlyContinue)) {
        Write-Log "Install-AdcsNetworkDeviceEnrollmentService is not available - the NDES role service brings it" -Tag "Error"
        return $false
    }

    # A prerequisite of the cmdlet below, not a setting to reconcile after it. The
    # configuration checks the service account's local IIS_IUSRS membership before it
    # does anything and refuses with 0x80070529 ERROR_MEMBER_NOT_IN_GROUP - an error that
    # names the group but reads, in a run log, as one more access failure. It used to be
    # applied further down this role, after the configuration step, so the first run on a
    # clean server always failed here and only a later one - by which time somebody had
    # usually added the account by hand - got past it. Field-verified 2026-08-16.
    if (-not (Add-AdcsScepIisAccount -SamAccountName $Account.SamAccountName)) {
        Write-Log "NDES refuses to configure a service account that is not in the local IIS_IUSRS group" -Tag "Error"
        return $false
    }

    # TWO identities, and saying so is the point. This line used to read "Configuring
    # NDES against <ca> as AD\svc.scep", which is what the cmdlet's own parameter names
    # invite and is wrong in the way that matters: -ServiceAccountName is the identity
    # **NDES will use when it talks to the CA at runtime** (Microsoft's words for its
    # sibling -ApplicationPoolIdentity: "the identity that NDES uses when communicating
    # with the certification authority"), while the configuration happening right now
    # runs as whoever is at this console. There is a -Credential parameter for that
    # second identity and this run does not pass it, so the caller is it - and Microsoft
    # documents that account needing **Domain Admins** against an enterprise CA, which
    # is exactly the membership `roleGroups.removeBuiltinAdmins` takes off the CA.
    # Somebody reading a failure needs both names, so both are printed.
    $configuringAs = $env:USERNAME
    try { $configuringAs = [string][System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $configuringAs = $env:USERNAME }

    # SYSTEM cannot do this, and finding that out at the far end of an access denied is a
    # wasted cycle. It happens by a route nobody plans: a feature install that asked for a
    # restart hands the rest of the plan to the resume task, which runs as SYSTEM - so the
    # configuration would be attempted by this machine's own account, which is neither a
    # domain admin nor a CA administrator anywhere.
    if ($configuringAs -match '(?i)^(NT AUTHORITY\\SYSTEM|.*\$)$') {
        Write-Log "This session is '$configuringAs' - NDES cannot be configured by the machine account" -Tag "Error"
        Write-Log "    That is the resume task, running as SYSTEM. The configuration needs a domain account - it enrolls the RA certificates and writes to the CA" -Tag "Error"
        Write-Log "    Run this script again at the console, signed in as the account that administers the issuing CA - everything installed so far stays done" -Tag "Error"
        return $false
    }

    Write-Log "Configuring NDES against '$caConfig'" -Tag "Run"
    Write-Log "    this configuration runs as '$configuringAs' - it is the identity the CA checks now, and it needs Manage CA there" -Tag "Debug"
    Write-Log "    '$env:USERDOMAIN\$($Account.SamAccountName)' is what NDES will talk to the CA as afterwards - the application pool identity, not this" -Tag "Debug"
    try {
        $secure = ConvertTo-SecureString -String $Account.Password -AsPlainText -Force
        $parameters = @{
            ServiceAccountName     = ("{0}\{1}" -f $env:USERDOMAIN, $Account.SamAccountName)
            ServiceAccountPassword = $secure
            CAConfig               = $caConfig
            Force                  = $true
            ErrorAction            = "Stop"
        }
        # The subject of the two registration authority certificates, and the only thing
        # about them anybody ever sees. Left unset the installer names them
        # '<HOSTNAME>-MSCEP-RA', which is what turns up in the machine store looking like
        # nobody chose it. Only the fields the design actually filled in are passed:
        # handing the cmdlet an empty -RACompany is not the same as not handing it one.
        #
        # WRITE-ONCE. These are read at enrollment, so a server that already holds its
        # RA certificates keeps the names it was given - changing them later means
        # Uninstall-AdcsNetworkDeviceEnrollmentService -Force and configuring again.
        $raSection = Get-ConfigValue -InputObject (Get-AdcsScepSection -CertificateServices $CertificateServices) -Name "registrationAuthority"
        $raNamed = @()
        foreach ($pair in @(
            @{ Key = "name";       Parameter = "RAName" },
            @{ Key = "company";    Parameter = "RACompany" },
            @{ Key = "department"; Parameter = "RADepartment" },
            @{ Key = "city";       Parameter = "RACity" },
            @{ Key = "state";      Parameter = "RAState" },
            @{ Key = "country";    Parameter = "RACountry" },
            @{ Key = "email";      Parameter = "RAEmail" })) {

            $value = ([string](Get-ConfigText -InputObject $raSection -Name $pair.Key -Default "")).Trim()
            if ([string]::IsNullOrWhiteSpace($value)) { continue }
            $parameters[$pair.Parameter] = $value
            $raNamed += ("{0}='{1}'" -f $pair.Parameter, $value)
        }
        if ($raNamed.Count -gt 0) {
            Write-Log ("    the registration authority certificates are named by the design: {0}" -f ($raNamed -join ", ")) -Tag "Info"
        }
        else {
            Write-Log ("    the design names no registration authority subject, so both certificates become '{0}-MSCEP-RA' - the installer's default, and it cannot be changed without configuring NDES again" -f $env:COMPUTERNAME.ToUpperInvariant()) -Tag "Debug"
        }

        $script:adcsScepInstallSeconds = 0
        $installClock = [System.Diagnostics.Stopwatch]::StartNew()
        $result = Install-AdcsNetworkDeviceEnrollmentService @parameters
        $installClock.Stop()
        $script:adcsScepInstallSeconds = [math]::Round($installClock.Elapsed.TotalSeconds, 1)
        $errorString = [string](Get-ConfigValue -InputObject $result -Name "ErrorString" -Default "")
        if (-not [string]::IsNullOrWhiteSpace($errorString) -and ($errorString -notmatch '(?i)success')) {
            Write-Log "NDES configuration reported: $errorString" -Tag "Warn"
        }
    }
    catch {
        if ($null -ne $installClock -and $installClock.IsRunning) { $installClock.Stop() }
        $script:adcsScepInstallSeconds = if ($null -ne $installClock) { [math]::Round($installClock.Elapsed.TotalSeconds, 1) } else { -1 }
        Write-Log "NDES configuration failed: $($_.Exception.Message)" -Tag "Error"
        # How LONG it took to be refused, because that alone separates the two halves of
        # the question the block below asks. A local access check is answered out of a
        # token in memory and returns in well under a second; a refusal that took twenty
        # seconds has been out on the network to ask somebody, and the only somebody here
        # is the CA. Field case (2026-09-05): the last local step logged at 20:29:52 and
        # the access denied arrived at 20:30:13 - twenty-one seconds, which is not a
        # permission check on this server.
        if ($script:adcsScepInstallSeconds -ge 5) {
            Write-Log ("    That refusal took {0}s. A permission check on THIS server answers in well under a second - this went to the CA and back" -f
                $script:adcsScepInstallSeconds) -Tag "Error"
        }
        elseif ($script:adcsScepInstallSeconds -ge 0) {
            Write-Log ("    That refusal took {0}s, which is fast enough to be a check on this server rather than a call to the CA" -f
                $script:adcsScepInstallSeconds) -Tag "Error"
        }
        if ($_.Exception.Message -match '(?i)0x80070490|ERROR_NOT_FOUND|certificate templates') {
            # TWO causes, one message. The installer says "failed to add the following
            # certificate templates" for both of them, and until 2026-09-10 this block
            # asserted the second - which sent a bench run to the CA to publish templates
            # that were already published, and that this tier's own preflight had said so
            # about four minutes earlier.
            #
            # certocm.log settles it: a chain that will not build carries
            # CERT_E_UNTRUSTEDROOT before the ERROR_NOT_FOUND, and the name in that
            # ERROR_NOT_FOUND is then the CA rather than a template.
            $setupLog = Get-AdcsScepSetupLogText
            if (($setupLog -match '(?i)CERT_E_UNTRUSTEDROOT|CERT_TRUST_IS_UNTRUSTED_ROOT|0x800b0109') -or
                ($_.Exception.Message -match '(?i)CERT_E_UNTRUSTEDROOT|0x800b0109')) {
                Write-Log "    That is NOT about the templates. certocm.log carries CERT_E_UNTRUSTEDROOT: this server cannot build a trusted chain for the CA's own certificate" -Tag "Error"
                Write-Log "        The installer validates that certificate before it publishes anything, and reports the failure in the words of the step it never reached" -Tag "Error"
                Write-Log "        The root reaches a member server through group policy, not through domain membership - a server that booted before the PKI existed has never seen it" -Tag "Error"
                Write-Log "        gpupdate /force        then    certutil -pulse" -Tag "Error"
                Write-Log "        Then unwind this attempt and run again - the steps are below" -Tag "Error"
            }
            elseif ($setupLog -match '(?i)CERT_TRUST_IS_OFFLINE_REVOCATION|CERT_TRUST_REVOCATION_STATUS_UNKNOWN|0x80092013') {
                Write-Log "    certocm.log reports the CA's chain as revocation-unknown - a CDP this server cannot reach" -Tag "Error"
                Write-Log "        certutil -verify -urlfetch on the CA's certificate names the URL that did not answer" -Tag "Error"
                Write-Log "        An offline root publishes its CRL by hand: it has to be in the directory and at every CDP URL its certificates carry" -Tag "Error"
            }
            else {
                Write-Log "    That is the installer trying to publish its three templates on the CA from this server and failing to resolve their names" -Tag "Error"
                Write-Log "    Publication is a CA decision made on the CA: run this same config on the issuing CA, which publishes CEPEncryption, EnrollmentAgentOffline and IPSECIntermediateOffline, then run this again" -Tag "Error"
            }
            Write-Log "    This failure leaves the MSCEP key behind, so after fixing it:  Uninstall-AdcsNetworkDeviceEnrollmentService -Force   then re-run" -Tag "Error"
        }
        if (($_.Exception.Message -match '(?i)0x80070005|ERROR_ACCESS_DENIED') -and ($_.Exception.Message -match '(?i)CMSCEPSetup')) {
            # This block used to open by asserting the installing user lacks Manage CA,
            # which is one documented cause and reads as the diagnosis. It sent two bench
            # sessions after a permission that was held: on 2026-08-17 the account carried
            # 'AD CS - Administrators', Domain Admins and Enterprise Admins in its token
            # and `certutil -getreg CA\Security` answered, and the configuration still
            # failed here. So this names the candidates and then goes and reads which of
            # them is true, rather than choosing one for the reader.
            Write-Log "    Access denied here is one of four things, and the checks below say which:" -Tag "Error"
            Write-Log "        the CEP Encryption certificate is enrolled by this server's MACHINE account, whose ticket carries the enrollment group only from the boot after it was added - a restart is what applies it" -Tag "Error"
            Write-Log "        the enrollment agent certificate is enrolled by the identity running this, which needs Enroll on EnrollmentAgentOffline" -Tag "Error"
            Write-Log "        this session may lack 'Manage CA' on the issuing CA - proven or disproven below, not assumed" -Tag "Error"
            Write-Log "        the CA may refuse the request outright, which is its own Request Certificates permission" -Tag "Error"

            # Whether the CA is refusing this at all is settled by looking at the CA
            # rather than by reading permissions here. Both registration authority
            # templates supply their subject **in the request** - which is what the
            # cmdlet's -RAName / -RACompany / -RACountry parameters are for - so a bare
            # `certreq -enroll` against them answers CERTSRV_E_BAD_REQUESTSUBJECT no
            # matter who runs it, and that says nothing about rights. What does say
            # something: whether a request reaches the CA at all.
            Write-Log "    The question worth answering first is whether this even reaches the CA. On the issuing CA:" -Tag "Error"
            Write-Log "        certutil -view -restrict `"RequestId>=1`" -out `"RequestId,Request.RequesterName,CertificateTemplate,Disposition,DispositionMessage`" | more" -Tag "Error"
            Write-Log "    A new row timed with this failure means the CA saw the request and answered - so this is not an access check, and the Disposition says what it is" -Tag "Error"
            Write-Log "    No new row means the refusal happened on THIS server, before anything was submitted" -Tag "Error"
            # The facts, rather than the theory: the same three checks the preflight ran,
            # re-run against a CA that has now refused something for real, and then the
            # configuration's own log - which names the call that was denied.
            $null = Test-AdcsScepAccess -CertificateServices $CertificateServices
        }
        # Whatever the code, the configuration wrote down what it was doing. This is the
        # only place that reason exists, and it was never read.
        Write-AdcsScepSetupLog

        $siteName = "Default Web Site"
        $scepSection = Get-AdcsScepSection -CertificateServices $CertificateServices
        if ($null -ne $scepSection) { $siteName = Get-ConfigText -InputObject $scepSection -Name "siteName" -Default "Default Web Site" }
        Write-AdcsScepResetChecklist -SiteName $siteName
        # Not a permission at all, and it used to be read as one because it arrives from
        # the same call. NDES writes '/LM/W3SVC/1/ROOT/CertSrv/mscep_admin' - site number
        # 1 by number, into %windir%\system32\certsrv\mscep - and any of those three
        # missing produces this, naming none of them.
        if ($_.Exception.Message -match '(?i)0x80070003|ERROR_PATH_NOT_FOUND|virtual directory') {
            Write-Log "    That is the virtual directory step, not an access check: NDES writes '/LM/W3SVC/1/ROOT/CertSrv/mscep_admin'" -Tag "Error"
            Write-Log "    Site number 1 literally, whatever it is called, into a folder that has to be on disk. What this server has:" -Tag "Error"
            $siteName = "Default Web Site"
            $scepSection = Get-AdcsScepSection -CertificateServices $CertificateServices
            if ($null -ne $scepSection) { $siteName = Get-ConfigText -InputObject $scepSection -Name "siteName" -Default "Default Web Site" }
            $null = Test-AdcsScepIisPath -SiteName $siteName
            Write-Log "    This failure leaves the MSCEP key and both virtual directories behind - the reset below is what a retry needs" -Tag "Error"
        }
        if ($_.Exception.Message -match '(?i)IIS_IUSRS|0x80070529|1321') {
            Write-Log "    The membership above was written this run - a domain account added to a local group is read by the cmdlet immediately, so this is a refusal on something else in the same check" -Tag "Error"
            Write-Log "    net localgroup IIS_IUSRS     lists what this server sees" -Tag "Error"
        }
        return $false
    }

    if (-not (Test-AdcsScepConfigured)) {
        Write-Log "Install-AdcsNetworkDeviceEnrollmentService ran but the MSCEP registry key did not appear" -Tag "Error"
        return $false
    }
    Write-Log "NDES is configured" -Tag "Ok"
    return $true
}

function Set-AdcsScepTemplateSlot {
    # NDES arrives pointing all three slots at IPSECIntermediateOffline, a template
    # this CA does not publish. See the mapping table above for what each one serves.
    param([Parameter(Mandatory)][object]$Slot)

    $changed = $false
    $written = @()
    foreach ($name in @($Slot.Keys)) {
        $wanted = [string]$Slot[$name]
        if ([string]::IsNullOrWhiteSpace($wanted)) {
            # A slot the design does not name is a slot left exactly as it is. Emptying
            # it would take a working profile down, and NDES reads a blank slot as a
            # request it cannot serve rather than as one to fall back on.
            Write-Log "MSCEP\$name is not named by this design - left as it is" -Tag "Info"
            continue
        }
        $current = ""
        try {
            $current = [string](Get-ItemProperty -Path $script:adcsScepRegistryPath -Name $name -ErrorAction Stop).$name
        }
        catch {
            $current = ""
        }
        if ($current -eq $wanted) {
            Write-Log "MSCEP\$name already names '$wanted'" -Tag "Debug"
            continue
        }
        Set-ItemProperty -Path $script:adcsScepRegistryPath -Name $name -Value $wanted -Type String
        Write-Log "MSCEP\$name = '$wanted' (was '$current')" -Tag "Ok"
        $written += $wanted
        $changed = $true
    }

    if ($changed) {
        Write-Log "The template NAME goes into the registry, never the display name" -Tag "Debug"
        $distinct = @($written | Select-Object -Unique)
        if ($distinct.Count -gt 1) {
            Write-Log "Three slots, $($distinct.Count) different templates" -Tag "Info"
        }
    }
    return $changed
}

# ---------------------------[ The registration authority templates ]---------------------------
# NDES holds two certificates of its own, and they are not the ones it issues. The
# configuration routine enrolls both while it runs: a CEP Encryption certificate, which
# encrypts the SCEP exchange with the requesting client, and an Exchange Enrollment
# Agent (Offline request) certificate, which is what lets NDES re-sign a request on
# behalf of a device that has no directory identity at all.
#
# Both come from v1 built-in templates, by name, so this does NOT create or duplicate
# anything - a duplicate would be a template NDES never looks at.
#
# Publishing them on the CA is the ISSUING CA RUN's job (Publish-AdcsNdesTemplate), not
# this tier's. The NDES installer tries to publish them itself, from here, and on a
# member server that fails as a batch with 0x80070490 ERROR_NOT_FOUND - the same
# template-cache trap the CA-side publisher exists to avoid, because the name is resolved
# against a cache on the machine doing the write and this machine is not the CA. So this
# tier checks and reports; the CA publishes. Field-verified 2026-08-16.
#
# A third template is checked alongside them and is not a registration authority one:
# IPSECIntermediateOffline, which the installer wants for its own default MSCEP slots.
# Blocked on, and that was tested rather than assumed - withdrawn from the design on
# 2026-08-16 and restored the same evening, because a clean build with only the two RA
# templates published failed 0x80070490 naming all three: the installer processes its
# template batch atomically and cannot publish the third from a member server. The
# failure also leaves the MSCEP key behind, so it costs an uninstall to recover from.
#
# What is worth checking here is that the two RA templates are published and that the two
# identities that enroll them can - the split is the part people get wrong, because it is
# not one account:
#
#   CEP Encryption                          the NDES server's COMPUTER account enrolls it
#   Exchange Enrollment Agent (Offline)     the USER running the configuration does
#
# On a default forest both are covered - the run is Enterprise Admin and the templates
# ship with rights that include it. It bites on a forest whose built-in template ACLs
# have been tightened, which is exactly the sort of forest this toolbox is pointed at,
# and the failure without this check is an NDES configuration that stops with an access
# error naming a template rather than an identity.
$script:adcsScepRaTemplate = @(
    [pscustomobject]@{
        Name = "CEPEncryption"
        Display = "CEP Encryption"
        Enrollee = "the NDES server's computer account"
        Does = "encrypts the SCEP exchange with the requesting device"
    }
    [pscustomobject]@{
        Name = "EnrollmentAgentOffline"
        Display = "Exchange Enrollment Agent (Offline request)"
        Enrollee = "the account running this configuration"
        Does = "re-signs a device's request, which is what an enrollment agent is for"
    }
)

# Not a registration authority template and nothing here enrolls from it - but the
# installer fails its whole batch without it (field-tested 2026-08-16), so it is
# checked with the other two and blocks the same way.
$script:adcsScepInstallerTemplate = [pscustomobject]@{
    Name = "IPSECIntermediateOffline"
    Display = "IPSEC (Offline request)"
    Enrollee = "nothing in this design"
    Does = "is what a fresh MSCEP points all three of its slots at, which is why the installer insists on publishing it"
}

# The two template NAMES are built-in and fixed, so there is nothing in the design to
# read for those - but which CA is supposed to publish them is a design fact, and
# without it this can only check that the objects exist somewhere in the forest.
function Test-AdcsScepRaTemplate {
    param([string]$CaCommonName = "")

    $domainDn = ""
    try { $domainDn = Get-AdcsConfigurationNamingContext }
    catch {
        Write-Log "The configuration naming context could not be read, so the registration authority templates were not checked: $($_.Exception.Message)" -Tag "Warn"
        return $true
    }
    if ([string]::IsNullOrWhiteSpace($domainDn)) { return $true }

    $templatesDn = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$domainDn"

    # Existing in the forest and being published on the CA are two different facts, and
    # the second is the one that matters. Withdrawing a template from a CA does not
    # delete the object, so a check that only asked "does it exist" passed happily in
    # exactly the situation that breaks NDES - an earlier version of this did.
    $published = @()
    $caName = ""
    if (-not [string]::IsNullOrWhiteSpace($CaCommonName)) {
        $caName = $CaCommonName
        try { $published = @(Get-AdcsPublishedTemplateForCa -CaCommonName $caName) }
        catch {
            Write-Log "Could not read what '$caName' publishes: $($_.Exception.Message)" -Tag "Warn"
            $published = @()
        }
    }

    $allThere = $true
    # All three, because the installer fails its batch as a whole - a run blocked on the
    # two RA templates alone reported "the templates are published" and then died on the
    # third (field-hit 2026-08-16, twice in one evening).
    foreach ($template in (@($script:adcsScepRaTemplate) + @($script:adcsScepInstallerTemplate))) {
        $dn = "CN=$($template.Name),$templatesDn"
        $exists = (Test-StudioDirectoryObject -DistinguishedName $dn)

        if (-not $exists) {
            Write-Log "The built-in template '$($template.Display)' ($($template.Name)) is not in this forest at all" -Tag "Error"
            Write-Log "    It $($template.Does)" -Tag "Error"
            Write-Log "    It is a built-in, so it is restored rather than created: certutil -dstemplate" -Tag "Error"
            $allThere = $false
            continue
        }

        if ($published.Count -eq 0) {
            # Nothing to compare against - either no CA was named or its object could not
            # be read. Existence is all this run can honestly claim.
            Write-Log "'$($template.Display)' is in the forest - $($template.Does)" -Tag "Debug"
            continue
        }

        if ($published -contains $template.Name) {
            Write-Log "'$($template.Display)' is published on '$caName' - $($template.Does)" -Tag "Debug"
            continue
        }

        # An error, and it names the run that fixes it. The installer's own attempt to
        # publish from here is exactly what fails - 0x80070490, on all three names at
        # once - so "it will sort itself out" is the one thing this is not.
        Write-Log "'$($template.Display)' ($($template.Name)) exists in the forest but '$caName' does NOT publish it" -Tag "Error"
        Write-Log "    It $($template.Does)" -Tag "Error"
        Write-Log "    Run this same config on '$caName' - the issuing CA run publishes all three of these" -Tag "Error"
        Write-Log "    Or by hand on that CA, which is per CA and reversible:" -Tag "Error"
        Write-Log "        certutil -SetCATemplates +$($template.Name)" -Tag "Error"
        $allThere = $false
    }

    if ($allThere) {
        Write-Log "The templates the NDES installer needs are published" -Tag "Info"
        foreach ($template in $script:adcsScepRaTemplate) {
            Write-Log "    $($template.Display): enrolled by $($template.Enrollee)" -Tag "Debug"
        }
    }
    return $allThere
}

function Set-AdcsScepHttpLimit {
    # A SCEP request arrives in the query string and runs to tens of kilobytes;
    # http.sys answers 414/400 to anything past its defaults long before IIS or NDES
    # sees it. 65534 is the value Microsoft's own guide sets. These two are read at
    # driver start, so a change here is what makes the run end in a reboot - and
    # iisreset is explicitly not enough.
    $changed = $false
    foreach ($name in @("MaxFieldLength", "MaxRequestBytes")) {
        $current = $null
        try {
            $current = [int](Get-ItemProperty -Path $script:adcsScepHttpParametersPath -Name $name -ErrorAction Stop).$name
        }
        catch {
            $current = $null
        }
        if ($current -eq 65534) { continue }
        Set-ItemProperty -Path $script:adcsScepHttpParametersPath -Name $name -Value 65534 -Type DWord
        Write-Log "HTTP\Parameters\$name = 65534 (was $(if ($null -eq $current) { 'unset' } else { $current }))" -Tag "Ok"
        $changed = $true
    }
    return $changed
}

function Set-AdcsScepRequestFiltering {
    # The IIS half of the same limit. Site-scoped, not server-scoped, so a shared
    # host's other sites keep their own settings.
    param([Parameter(Mandatory)][string]$SiteName)

    $appCmd = Join-Path -Path $env:SystemRoot -ChildPath "system32\inetsrv\appcmd.exe"
    if (-not (Test-Path -LiteralPath $appCmd)) {
        Write-Log "appcmd.exe was not found - IIS is not installed, and NDES cannot exist without it" -Tag "Error"
        return $false
    }

    try {
        $null = Invoke-AdcsUtility -FilePath $appCmd -ArgumentList @(
            "set", "config", $SiteName, "-section:system.webServer/security/requestFiltering",
            "/requestLimits.maxUrl:65534", "/requestLimits.maxQueryString:65534", "/commit:apphost")
        Write-Log "Request filtering on '$SiteName': maxUrl and maxQueryString raised to 65534" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "Could not raise the request filtering limits: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

function Add-AdcsScepIisAccount {
    # IIS_IUSRS membership is what lets the application pool identity run, and the
    # configuration cmdlet refuses to run at all without it - so this is called twice:
    # once from Install-AdcsScepService before the configuration, and once on the
    # reconcile pass below for a server that was configured by hand or by an earlier
    # version. Idempotent, and the second call says so at Debug. Local group, so ADSI's
    # WinNT provider rather than LDAP.
    param([Parameter(Mandatory)][string]$SamAccountName)

    try {
        $group = [ADSI]"WinNT://$env:COMPUTERNAME/IIS_IUSRS,group"
        $members = @($group.Invoke("Members")) | ForEach-Object {
            ([ADSI]$_).InvokeGet("Name")
        }
        if ($members -contains $SamAccountName) {
            Write-Log "'$SamAccountName' is already in IIS_IUSRS" -Tag "Debug"
            return $true
        }
        $group.Add("WinNT://$env:USERDOMAIN/$SamAccountName,user")
        Write-Log "Added '$SamAccountName' to the local IIS_IUSRS group" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "Could not add '$SamAccountName' to IIS_IUSRS: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

# "Impersonate a client after authentication" for IIS_IUSRS, which Microsoft's Intune
# NDES troubleshooting page names as the cause of an HTTP 500 from the SCEP URL. A fresh
# Windows Server grants it to IIS_IUSRS already - the reason it is worth asserting is
# that hardening baselines routinely strip that right back to Administrators and the
# service accounts, and a CIS-hardened NDES box then answers 500 to every device with
# nothing in the NDES logs to say why. Granting a right that is already there is a no-op.
function Grant-AdcsScepImpersonation {
    $account = "IIS_IUSRS"
    if (-not (Grant-AdcsUserRight -AccountName $account -Privilege "SeImpersonatePrivilege")) {
        Write-Log "Could not confirm 'Impersonate a client after authentication' for $account" -Tag "Warn"
        Write-Log "    Without it the SCEP URL answers HTTP 500 to every device, and the NDES log says nothing" -Tag "Warn"
        Write-Log "    secpol.msc > Local Policies > User Rights Assignment > Impersonate a client after authentication" -Tag "Warn"
        return $false
    }
    return $true
}

function Clear-AdcsScepSpn {
    # This function used to REGISTER an http/<fqdn> SPN on the service account, and that
    # was wrong per Microsoft's own NDES account doc: a single NDES server answering on
    # its actual hostname needs no SPN at all - "the computer account's default SPNs for
    # HOST/computerFQDN cover this case" - and the doc's one case for an account SPN (a
    # CNAME or load-balanced name) comes with "then disable IIS Kernel-mode
    # Authentication". This design does neither, so an SPN on the account is the worst
    # of both: clients fetch tickets encrypted for the service account's key while
    # kernel-mode authentication - the IIS default - decrypts with the machine's, and
    # Windows authentication to mscep_admin fails for as long as the SPN stands.
    # So the reconcile now runs the other way: an SPN this design's earlier versions put
    # on its own service account is removed; one held by anything else is reported and
    # never moved - it may be somebody's deliberate CNAME setup, which is theirs to own.
    # Asked of the directory rather than of setspn -q's output: that output prints the
    # holder's DN, built from the CN, so matching it against a sAMAccountName fails
    # exactly when the answer matters. Field-hit 2026-08-16.
    param([Parameter(Mandatory)][string]$SamAccountName)

    $fqdn = "{0}.{1}" -f $env:COMPUTERNAME.ToLowerInvariant(), ([string]$env:USERDNSDOMAIN).ToLowerInvariant()
    $spn = "http/$fqdn"

    $holder = ""
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter = "(servicePrincipalName=$spn)"
        $null = $searcher.PropertiesToLoad.Add("sAMAccountName")
        $found = $searcher.FindOne()
        if ($null -ne $found) { $holder = [string]$found.Properties["samaccountname"][0] }
    }
    catch {
        Write-Log "Could not ask the directory who holds '$spn': $($_.Exception.Message)" -Tag "Warn"
    }

    if ([string]::IsNullOrWhiteSpace($holder)) {
        Write-Log "No account holds '$spn' - correct: the machine's own HOST SPNs carry Kerberos to this hostname" -Tag "Debug"
        return
    }

    if ($holder.Equals($SamAccountName, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Log "SPN '$spn' is on '$SamAccountName' - it breaks Windows authentication to mscep_admin" -Tag "Info"
        Write-Log "    Kerberos tickets for it are cut for the account's key while IIS kernel-mode authentication - the default - decrypts with the machine's; Microsoft's doc wants no SPN here at all" -Tag "Debug"
        $null = Invoke-AdcsUtility -FilePath "setspn.exe" -ArgumentList @("-d", $spn, ("{0}\{1}" -f $env:USERDOMAIN, $SamAccountName)) -IgnoreExitCode
        Write-Log "SPN '$spn' removed from '$SamAccountName'" -Tag "Ok"
        return
    }

    # The machine account holding an explicit http SPN is redundant beside its HOST
    # ones but decrypts with the same key, so nothing is broken by it.
    if ($holder.Equals("$env:COMPUTERNAME$", [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Log "SPN '$spn' is on this machine's own account - redundant beside HOST/$fqdn, and harmless" -Tag "Debug"
        return
    }

    Write-Log "SPN '$spn' is registered to '$holder' - left alone, it is not this design's to move" -Tag "Warn"
    Write-Log "    With it there, Kerberos to this hostname targets that account's key and Windows authentication to mscep_admin fails unless kernel-mode authentication was deliberately reconfigured" -Tag "Warn"
    Write-Log "    If it is a leftover of an earlier build:  setspn -d $spn $holder" -Tag "Warn"
}

function Set-AdcsScepTlsBinding {
    # The server authentication certificate on :443. Behind a reverse proxy that
    # rewrites the external name (Entra application proxy, most firewalls) NDES only
    # ever answers the internal URL, so the internal name is what the certificate
    # must carry - the external name matters on the proxy, not here.
    param(
        [Parameter(Mandatory)][object]$Scep,
        [Parameter(Mandatory)][string]$SiteName
    )

    $certificate = Get-ConfigValue -InputObject $Scep -Name "certificate"
    if ($null -eq $certificate) {
        Write-Log "No certificate section - the HTTPS binding is left as it is" -Tag "Info"
        return $true
    }

    $thumbprint = Resolve-StudioCertificate -Certificate $certificate
    if ([string]::IsNullOrWhiteSpace($thumbprint)) {
        Write-Log "The certificate source resolves to nothing to bind - the HTTPS binding is left as it is" -Tag "Info"
        return $true
    }

    $appCmd = Join-Path -Path $env:SystemRoot -ChildPath "system32\inetsrv\appcmd.exe"
    try {
        $bindings = Invoke-AdcsUtility -FilePath $appCmd -ArgumentList @("list", "site", $SiteName, "/text:bindings") -IgnoreExitCode
        if ($bindings -notmatch [regex]::Escape("https/*:443:")) {
            $null = Invoke-AdcsUtility -FilePath $appCmd -ArgumentList @(
                "set", "site", "/site.name:$SiteName", "/+bindings.[protocol='https',bindingInformation='*:443:']")
            Write-Log "HTTPS binding added to '$SiteName'" -Tag "Ok"
        }
    }
    catch {
        Write-Log "Could not add the HTTPS binding: $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    # http.sys owns the certificate half of the binding. Replacing an existing entry
    # is the point - a renewal lands here too.
    $null = & netsh.exe http delete sslcert ipport=0.0.0.0:443 2>&1
    $output = & netsh.exe http add sslcert ipport=0.0.0.0:443 certhash=$thumbprint "appid=$($script:adcsScepIisAppId)" certstorename=MY 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        Write-Log "netsh could not bind the certificate: $($output.Trim())" -Tag "Error"
        return $false
    }
    Write-Log "Certificate $thumbprint bound to 0.0.0.0:443" -Tag "Ok"
    return $true
}

function Test-AdcsScepEndpoint {
    # The one check that decides, same philosophy as the CA's publication endpoint:
    # fetch the URL NDES actually answers on. Before the Intune connector installs
    # its policy module the page answers 200; after it, direct requests get 403 -
    # both mean NDES is alive. 503 is the app pool down, which is almost always a
    # permission missing from the service account.
    $url = "http://localhost/certsrv/mscep/mscep.dll"
    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        Write-Log "NDES answers at $url (HTTP $([int]$response.StatusCode))" -Tag "Ok"
        return $true
    }
    catch {
        $status = 0
        if ($null -ne $_.Exception.Response) {
            try { $status = [int]$_.Exception.Response.StatusCode } catch { $status = 0 }
        }
        if ($status -eq 403) {
            Write-Log "NDES answers at $url with 403 - the Intune policy module is guarding it" -Tag "Ok"
            return $true
        }
        if ($status -eq 503) {
            Write-Log "NDES answers 503 - the SCEP application pool is stopped. The usual cause is a permission missing from the service account; the application event log names it." -Tag "Error"
        }
        elseif ($status -eq 500) {
            # 500 has two causes here and they are not guesses - one is visible in the
            # certificate store and the other in a token that has not been refreshed.
            Write-Log "NDES answers 500 - it is running and cannot serve. Two causes, in this order:" -Tag "Error"

            $missing = @(Get-AdcsScepCertificateHealth | Where-Object { $_.Grade -eq "Missing" -and $_.Label -like "NDES registration authority*" })
            if ($missing.Count -gt 0) {
                # The configuration writes the MSCEP key and then enrolls; a run that got
                # the first half and not the second leaves a server that answers
                # "already configured" for ever and 500 to every request.
                Write-Log "    Its registration authority certificate(s) are not in the machine store: $(($missing | ForEach-Object { $_.Label }) -join ', ')" -Tag "Error"
                Write-Log "    NDES enrolls those while it configures, so a configuration that ran before the CA was trusted or the templates were published wrote the MSCEP key and enrolled nothing" -Tag "Error"
                Write-Log "    The key being there is what makes every later run say 'already configured' - the repair is to configure it again, not to run this again:" -Tag "Error"
                Write-Log "        Uninstall-AdcsNetworkDeviceEnrollmentService -Force     then re-run this config" -Tag "Error"
            }
            else {
                Write-Log "    'Impersonate a client after authentication' for IIS_IUSRS - Microsoft's own NDES troubleshooting names a missing SeImpersonatePrivilege as the cause of a 500" -Tag "Error"
                Write-Log "    This run asserts that right, and a right granted to a running machine is not in the application pool's token yet: iisreset, or the reboot this design ends in, and then ask again" -Tag "Error"
            }
        }
        else {
            Write-Log "NDES does not answer at ${url}: $($_.Exception.Message)" -Tag "Error"
        }
        return $false
    }
}

function Write-AdcsScepConnectorChecklist {
    param([object]$Scep)

    $externalUrl = Get-ConfigText -InputObject $Scep -Name "externalUrl"
    Write-Log "What stays manual from here:" -Tag "Info"
    Write-Log "    1. Download the Certificate Connector for Microsoft Intune (IntuneWinAppUtil-free, from the Intune admin center: Tenant administration > Connectors and tokens > Certificate connectors)" -Tag "Info"
    Write-Log "    2. Install it on THIS server, signed in as an Intune Administrator with a licence - the sign-in is interactive, there is no unattended path" -Tag "Info"
    Write-Log "    3. Tick SCEP in the connector's feature page; the installer places the policy module that guards the NDES URL" -Tag "Info"
    if (-not [string]::IsNullOrWhiteSpace($externalUrl)) {
        Write-Log "    4. Publish '$externalUrl' to this server through your reverse proxy or firewall - pre-authentication must be passthrough (SCEP cannot preauth) and the proxy must accept a ~40 KB URL" -Tag "Info"
    }
    Write-Log "    Then: Intune trusted certificate profile (the root), and a SCEP profile pointing at the external URL" -Tag "Info"
    Write-Log "EnforcePassword left as it is - the connector install owns that switch" -Tag "Info"
    Write-Log "Do not re-enable EDITF_ATTRIBUTESUBJECTALTNAME2 for SCEP - the SAN comes from the CSR, which the policy module validates; the flag would reopen ESC6 for everything" -Tag "Info"
}

# ---------------------------[ Nightly renewal ]---------------------------
# The fourth consumer of the shared certificate machinery. NDES serves HTTPS out of
# http.sys rather than out of a service that reads a store, so the renewal is a
# rebind: get the certificate, then hand it to netsh again. Same shape as the other
# three - read what is served before anything changes, so the report can say what was
# replaced, and only act when the two differ.
function Invoke-AdcsScepCertificateTask {
    param([object]$Config)

    $certificateServices = Get-ConfigValue -InputObject $Config -Name "certificateServices"
    $scep = Get-AdcsScepSection -CertificateServices $certificateServices
    if ($null -eq $scep) {
        Write-Log "The SCEP tier is not in this config - nothing to renew" -Tag "Info"
        return 0
    }

    $certificate = Get-ConfigValue -InputObject $scep -Name "certificate"
    $source = Get-ConfigText -InputObject $certificate -Name "source" -Default "leave"
    if (@("acme", "internalCa") -notcontains $source) {
        Write-Log "The NDES certificate source is '$source' - nothing renews on a schedule" -Tag "Info"
        return 0
    }
    if ($source -eq "acme") { Update-PoshAcmeModule }

    # Read before anything is renewed, and attached to whichever report this run ends up
    # sending - including the failure ones. A run that could not renew the HTTPS
    # certificate is exactly the run where somebody should also see that the enrollment
    # agent certificate has eleven days left.
    $watched = @(Get-AdcsScepCertificateHealth)
    Write-AdcsScepCertificateHealth -Health $watched

    $names = @(Get-ConfigArray -InputObject $certificate -Name "dnsNames" | ForEach-Object { [string]$_ })
    $primaryName = ""
    if ($names.Count -gt 0) { $primaryName = $names[0] }
    $pluginName = Get-ConfigText -InputObject (Get-ConfigValue -InputObject $certificate -Name "acme") -Name "dnsPlugin"

    # What http.sys serves on 443 today, read out of its own binding table rather than
    # from the store - the store holds every certificate this machine ever enrolled.
    $previousThumbprint = ""
    $previousNotAfter = ""
    try {
        $binding = & netsh.exe http show sslcert ipport=0.0.0.0:443 2>&1 | Out-String
        $match = [regex]::Match($binding, '(?i)certificate hash\s*:\s*([0-9a-f]+)')
        if ($match.Success) {
            $previousThumbprint = $match.Groups[1].Value.ToUpperInvariant()
            $current = Get-Item -LiteralPath ("Cert:\LocalMachine\My\" + $previousThumbprint) -ErrorAction SilentlyContinue
            if ($null -ne $current) { $previousNotAfter = $current.NotAfter.ToString("yyyy-MM-dd") }
        }
    }
    catch {
        Write-Log "The current HTTPS binding could not be read: $($_.Exception.Message)" -Tag "Warn"
    }

    $thumbprint = ""
    try {
        $thumbprint = Resolve-StudioCertificate -Certificate $certificate
    }
    catch {
        Write-Log "The certificate could not be obtained: $($_.Exception.Message)" -Tag "Error"
        $null = Send-CertificateReport -Config $Config -Report (New-WacCertificateReport `
            -Status "Failed" -RoleLabel "Intune Certificate Connector" -PrimaryName $primaryName -Names $names -Source $source -PluginName $pluginName `
            -PreviousThumbprint $previousThumbprint -PreviousNotAfter $previousNotAfter `
            -WatchedCertificates $watched `
            -ErrorMessage $_.Exception.Message -ErrorStackTrace ([string]$_.ScriptStackTrace))
        return 1
    }
    if ([string]::IsNullOrWhiteSpace($thumbprint)) {
        Write-Log "No certificate came back - the binding is left as it is" -Tag "Info"
        return 0
    }

    $status = "Renewed"
    if ($previousThumbprint -eq $thumbprint.ToUpperInvariant()) {
        Write-Log "NDES already serves $thumbprint - nothing to do today" -Tag "Ok"
        $status = "Current"
    }
    else {
        $siteName = Get-ConfigText -InputObject $scep -Name "siteName" -Default "Default Web Site"
        if (-not (Set-AdcsScepTlsBinding -Scep $scep -SiteName $siteName)) {
            $null = Send-CertificateReport -Config $Config -Report (New-WacCertificateReport `
                -Status "Failed" -RoleLabel "Intune Certificate Connector" -PrimaryName $primaryName -Names $names -Source $source -PluginName $pluginName `
                -Thumbprint $thumbprint -PreviousThumbprint $previousThumbprint -PreviousNotAfter $previousNotAfter `
                -WatchedCertificates $watched `
                -ErrorMessage "The renewed certificate could not be bound to 0.0.0.0:443")
            return 1
        }
    }

    $endpoints = @()
    $reachable = Test-AdcsScepEndpoint
    $endpoints += [pscustomobject]@{
        Url = "http://localhost/certsrv/mscep/mscep.dll"
        Ok = $reachable
        Detail = $(if ($reachable) { "answering" } else { "no answer" })
    }

    $renewed = Get-Item -LiteralPath ("Cert:\LocalMachine\My\" + $thumbprint) -ErrorAction SilentlyContinue
    $notAfter = ""
    if ($null -ne $renewed) { $notAfter = $renewed.NotAfter.ToString("yyyy-MM-dd") }

    $null = Send-CertificateReport -Config $Config -Report (New-WacCertificateReport `
        -Status $status -RoleLabel "Intune Certificate Connector" -PrimaryName $primaryName -Names $names -Source $source -PluginName $pluginName `
        -Thumbprint $thumbprint -NotAfter $notAfter -PreviousThumbprint $previousThumbprint -PreviousNotAfter $previousNotAfter `
        -Endpoints $endpoints -WatchedCertificates $watched)
    return $(if ($reachable) { 0 } else { 1 })
}

# The reboot planning hook for the whole AD CS role. Never 'pending': the CA tiers
# do not reboot at all, and the SCEP tier's reboot is signalled by its own
# RebootRequired result rather than detected from machine state - so the planner
# must not stop the other tiers' runs waiting for a restart nothing asked for.
function Test-AdcsRebootPending {
    return $false
}

# After the SCEP tier's reboot: the registry values are live now, so this is where
# the endpoint proof lands. Every other tier answers Completed without comment -
# none of them ends in a reboot.
# The engine's optional auto-restart hook, the same contract Exchange and Hyper-V
# implement: asked only when a step returns RebootRequired, 0 means "leave the restart
# to the person". Answered for the SCEP tier alone - it is the one AD CS machine whose
# run ends by needing a restart it cannot perform for itself (the MSCEP slots and the
# http.sys limits are read at start), on a server that is still being built. The other
# tiers never return RebootRequired, and a root CA mid-ceremony is the last machine an
# automatic restart belongs on, so anything but scep answers 0. 90 seconds is Exchange's
# number and Exchange's reasoning: long enough to read the line and type 'shutdown /a'.
function Get-AdcsAutoRestartDelay {
    param([object]$Config)

    $certificateServices = Get-ConfigValue -InputObject $Config -Name "certificateServices"
    if ($null -eq $certificateServices) { return 0 }
    if ((Resolve-AdcsTier -CertificateServices $certificateServices) -ne "scep") { return 0 }

    $scep = Get-AdcsScepSection -CertificateServices $certificateServices
    if ($null -eq $scep) { return 0 }
    if (-not [bool](Get-ConfigValue -InputObject $scep -Name "autoRestart" -Default $true)) { return 0 }
    return [int](Get-ConfigValue -InputObject $scep -Name "autoRestartDelaySeconds" -Default 15)
}

function Invoke-AdcsPostReboot {
    param([object]$Config)

    $certificateServices = Get-ConfigValue -InputObject $Config -Name "certificateServices"
    $tierName = Resolve-AdcsTier -CertificateServices $certificateServices
    if ($tierName -ne "scep") {
        return (New-RoleResult -Status "Completed")
    }

    $scep = Get-AdcsScepSection -CertificateServices $certificateServices
    if ($null -eq $scep) {
        return (New-RoleResult -Status "Completed")
    }

    if (-not (Test-AdcsScepEndpoint)) {
        return (New-RoleResult -Status "ManualStepRequired" -Message "The reboot happened but NDES does not answer - the log above says what came back.")
    }
    Write-AdcsScepCertificateHealth -Health (Get-AdcsScepCertificateHealth)
    Write-AdcsScepConnectorChecklist -Scep $scep
    return (New-RoleResult -Status "Completed" -Message "NDES is configured and answering - install the Certificate Connector for Microsoft Intune by hand to finish.")
}

function Invoke-AdcsScepTier {
    param([Parameter(Mandatory)][object]$CertificateServices)

    $scep = Get-AdcsScepSection -CertificateServices $CertificateServices
    if ($null -eq $scep) {
        return (New-RoleResult -Status "Completed" -Message "The SCEP tier is switched off in the design - nothing to do on this server.")
    }

    if (Test-AdcsDomainController) {
        # Microsoft's placement rule, and the same shape of refusal the RDS role uses.
        return (New-RoleResult -Status "Failed" -Message "NDES must not run on a domain controller - point the SCEP tier at a member server.")
    }

    # The account is created by the directory tier; here it is a prerequisite.
    $account = Get-AdcsScepServiceAccount -Scep $scep
    if ($null -eq $account) {
        return (New-RoleResult -Status "Failed" -Message "The SCEP tier has no service account in the design - NDES cannot run without one.")
    }
    $found = $null
    try { $found = Find-DhcpServiceAccount -SamAccountName $account.SamAccountName } catch { $found = $null }
    if ($null -eq $found) {
        Write-Log "The service account '$($account.SamAccountName)' does not exist - run this config on the domain controller first, or create it by hand:" -Tag "Error"
        Write-Log "    New-ADUser -Name '$($account.DisplayName)' -SamAccountName '$($account.SamAccountName)' -Enabled `$true -PasswordNeverExpires `$true -AccountPassword (Read-Host -AsSecureString)" -Tag "Error"
        return (New-RoleResult -Status "ManualStepRequired" -Message ("The service account '{0}' does not exist yet - the directory preparation run creates it." -f $account.SamAccountName))
    }

    # Before the twenty-five minutes, not after them. Every access this configuration
    # needs is readable now, and the failure it prevents - CMSCEPSetup's access denied -
    # arrives at the far end of nine feature installs, names nothing, and leaves the
    # MSCEP key behind so the retry needs an uninstall first. A server that is already
    # configured is not asked: its registration authority certificates were enrolled long
    # ago and this run reconciles settings around them.
    if (-not (Test-AdcsScepConfigured)) {
        $access = Test-AdcsScepAccess -CertificateServices $CertificateServices
        if (-not $access.Ok) {
            return (New-RoleResult -Status "ManualStepRequired" -Message ("NDES cannot be configured from this session: {0}. Nothing was installed - the lines above name what to grant and whether a sign-out or a restart is what makes it take." -f $access.Reason))
        }
    }

    # The roles and features, installed rather than reported - see the header. This is
    # the second role in the project allowed to install anything, and unlike Exchange
    # it has no switch: a server carrying this tier is a server built for it.
    $prerequisite = Install-AdcsScepPrerequisite -Scep $scep
    if (-not $prerequisite.Ok) {
        return (New-RoleResult -Status "ManualStepRequired" -Message ("The roles and features NDES needs could not all be installed: {0}. The log above says why." -f (($prerequisite.Failed -join ", "))))
    }
    if ($prerequisite.RestartNeeded) {
        # Before NDES is configured, not after. The configuration step enrolls the
        # registration authority certificates and writes into IIS, and doing that on a
        # server that is still half-way through installing IIS is how a run produces a
        # broken NDES that then has to be taken apart by hand.
        Write-Log "A role or feature asked for a restart - NDES is configured on the run after it" -Tag "Info"
        return (New-RoleResult -Status "RebootRequired" -Message "The roles and features NDES needs are installed - restart this server, then run this again to configure NDES.")
    }

    # mscep.dll is what the role service puts on disk, so it is the direct question -
    # the same reasoning every other feature check in the AD CS path uses. Reaching
    # here without it means Install-WindowsFeature claimed success and produced nothing.
    if (-not (Test-Path -LiteralPath $script:adcsScepMscepBinary)) {
        Write-Log "ADCS-Device-Enrollment installed but '$($script:adcsScepMscepBinary)' is not there" -Tag "Error"
        return (New-RoleResult -Status "ManualStepRequired" -Message "The NDES role service reports installed but its binary is missing - check the feature installation on this server.")
    }

    if (-not (Test-AdcsScepConfigured)) {
        # Checked here rather than earlier: the templates are only needed by the
        # configuration step, and a server that is already configured has enrolled its
        # registration authority certificates long ago.
        $issuingTier = Get-ConfigValue -InputObject $CertificateServices -Name "issuing"
        $caCommonName = [string](Get-ConfigText -InputObject $issuingTier -Name "caCommonName" -Default "")
        # Blocking, rather than a note before an attempt that cannot work: the installer
        # publishes the three itself and fails as a batch on 0x80070490 when it cannot,
        # and that error names three templates and no cause. Stopping here says which
        # run fixes it. A CA that could not be read at all does not block - the check
        # returns true and the attempt goes ahead, which is the older behaviour.
        if (-not (Test-AdcsScepRaTemplate -CaCommonName $caCommonName)) {
            return (New-RoleResult -Status "ManualStepRequired" -Message ("The templates the NDES installer needs are not published on '{0}' - run this same config on that CA first, then this one again." -f $caCommonName))
        }
        if (-not (Install-AdcsScepService -CertificateServices $CertificateServices -Account $account)) {
            return (New-RoleResult -Status "ManualStepRequired" -Message "NDES could not be configured - the log above says why.")
        }
    }
    else {
        Write-Log "NDES is already configured - settings are reconciled" -Tag "Info"
    }

    $failures = @()

    # "Configured" is one registry key, and the two certificates the configuration should
    # have enrolled are a different fact. A configuration that ran while the CA was not
    # trusted, or before its templates were published, writes the key and enrolls
    # nothing - and from then on every run reads the key, says "already configured" and
    # reconciles settings around an NDES that answers 500 to everything. Field-hit
    # 2026-08-16: the key was there, both registration authority certificates were not.
    $missingRa = @(Get-AdcsScepCertificateHealth |
        Where-Object { $_.Grade -eq "Missing" -and $_.Label -like "NDES registration authority*" })
    if ($missingRa.Count -gt 0) {
        Write-Log "NDES is configured but holds none of its registration authority certificates: $(($missingRa | ForEach-Object { $_.Label }) -join ', ')" -Tag "Error"
        Write-Log "    It enrolls those while it configures, so this server was configured before it could - an untrusted CA root or templates the CA did not publish" -Tag "Error"
        Write-Log "    Running this again does not repair it: the MSCEP key is what makes every run skip the configuration step" -Tag "Error"
        Write-Log "    Fix the cause first, then configure it again:" -Tag "Error"
        Write-Log "        certutil -store -enterprise Root      does this server trust the root?" -Tag "Error"
        Write-Log "        Uninstall-AdcsNetworkDeviceEnrollmentService -Force      then re-run this config" -Tag "Error"
        $failures += "the registration authority certificates"
    }

    $slots = Get-AdcsScepSlotTemplate -CertificateServices $CertificateServices
    $rebootNeeded = $false
    if (@($slots.Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -eq 0) {
        Write-Log "The design names no SCEP template at all - the MSCEP slots keep whatever they name now" -Tag "Warn"
    }
    else {
        if (Set-AdcsScepTemplateSlot -Slot $slots) { $rebootNeeded = $true }
    }
    if (Set-AdcsScepHttpLimit) { $rebootNeeded = $true }

    $siteName = Get-ConfigText -InputObject $scep -Name "siteName" -Default "Default Web Site"
    if (-not (Set-AdcsScepRequestFiltering -SiteName $siteName)) { $failures += "request filtering" }
    # The reconcile pass. The configuration step above writes this itself before it runs
    # - it has to, the cmdlet refuses without it - so on a run that configured NDES this
    # is a no-op at Debug. It earns its place on the other path: a server configured by
    # hand, or by a version of this that added the membership afterwards.
    if (-not (Add-AdcsScepIisAccount -SamAccountName $account.SamAccountName)) { $failures += "IIS_IUSRS membership" }
    $null = Grant-AdcsScepImpersonation
    Clear-AdcsScepSpn -SamAccountName $account.SamAccountName
    if (-not (Set-AdcsScepTlsBinding -Scep $scep -SiteName $siteName)) { $failures += "TLS binding" }

    # Only a certificate that expires on a schedule of its own earns the nightly task -
    # a thumbprint or a staged PFX is whatever put it there.
    $certificateSource = Get-ConfigText -InputObject (Get-ConfigValue -InputObject $scep -Name "certificate") -Name "source" -Default "leave"
    if (@("acme", "internalCa") -contains $certificateSource) {
        $null = Register-StudioCertificateTask -Config $script:currentConfig -ConfigFilePath $script:configFilePath
    }

    # EnforcePassword: reported, never written. See the header comment.
    $enforce = $null
    try { $enforce = [int](Get-ItemProperty -Path $script:adcsScepRegistryPath -Name "EnforcePassword" -ErrorAction Stop).EnforcePassword } catch { $enforce = $null }
    if ($null -ne $enforce) {
        Write-Log "MSCEP\EnforcePassword is $enforce - left exactly as it is" -Tag "Info"
    }

    if ($rebootNeeded) {
        Write-Log "The MSCEP template slots and the http.sys limits are read at start - iisreset is not enough" -Tag "Debug"
        Write-AdcsScepConnectorChecklist -Scep $scep
        # A restart does not repair a missing registration authority certificate or any
        # other collected failure - returning RebootRequired here buried them below the
        # restart message, and the run read as clean until the endpoint answered 500
        # after the reboot. Field-hit 2026-08-16.
        if ($failures.Count -gt 0) {
            return (New-RoleResult -Status "ManualStepRequired" -Message ("The registry changes want a restart, but these have to be fixed first - a reboot does not repair them: {0}. The log above says how." -f ($failures -join ", ")))
        }
        return (New-RoleResult -Status "RebootRequired" -Message "NDES is configured - restart this server to apply the registry changes, then run this again to verify the endpoint.")
    }

    # Not asked when the answer is already known: an NDES with no registration authority
    # certificate answers 500 to everything, and a second error saying so would send
    # somebody looking at IIS instead of at the four lines above.
    if ($missingRa.Count -gt 0) {
        Write-Log "The endpoint is not checked - NDES cannot serve a request without its registration authority certificates" -Tag "Info"
    }
    elseif (-not (Test-AdcsScepEndpoint)) { $failures += "the NDES endpoint" }

    Write-AdcsScepCertificateHealth -Health (Get-AdcsScepCertificateHealth)
    Write-AdcsScepConnectorChecklist -Scep $scep

    if ($failures.Count -gt 0) {
        return (New-RoleResult -Status "ManualStepRequired" -Message ("NDES is configured, but these did not go in: {0}. Fix the cause and run this again." -f ($failures -join ", ")))
    }
    return (New-RoleResult -Status "Completed" -Message "NDES is configured and answering - install the Certificate Connector for Microsoft Intune by hand to finish.")
}
