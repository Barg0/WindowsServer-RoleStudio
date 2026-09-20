# =====================================================================================
# Role.Adcs.Pkcs.ps1 - the PKCS mode of the Intune Certificate Connector tier.
#
# Dot-sourced by Configure-ServerRoles.ps1 into the same scope as every other part.
#
# This file exists because PKCS and SCEP share a machine and nothing else. SCEP is the
# Network Device Enrollment Service: a role service plus IIS plus six of its role
# services plus three .NET features, a service account, two registration authority
# certificates, three registry slots and an HTTPS endpoint published to the internet.
# PKCS is none of that. The connector asks the certification authority directly over
# RPC - CCertRequest::Submit - generates the key on this server, exports a PKCS#12 and
# hands it to Intune. So:
#
#   * this tier installs NO Windows feature. The house rule that a run never installs a
#     role has exactly three exceptions and NDES is one of them; the exception belongs
#     to NDES and does not travel with the tier.
#   * there is no reboot boundary, because nothing is installed.
#   * there is no service account. The connector is installed as SYSTEM - the
#     installer's default - and reaches the CA as this machine's COMPUTER ACCOUNT.
#     Microsoft's own "Denied by Policy Module" fix grants Read and Enroll on the
#     template to exactly that identity.
#   * there is no certificate of this tier's own, no SPN, no IIS site and no external
#     name. Nothing here answers a request from anywhere.
#
# What is left, and all this file does:
#
#   directory tier   creates one group and puts this machine's computer account in it
#   issuing tier     publishes the templates and grants that group its permissions -
#                    done by the ordinary template machinery, not by anything here
#   connector tier   checks the host's prerequisites, writes one registry value and
#                    reports what is still manual
#
# The connector install itself stays manual in both modes: the download lives behind
# the tenant and the configuration is an interactive Entra sign-in as an Intune
# Administrator. There is no unattended path and inventing one would mean holding
# tenant credentials in a config file.
# =====================================================================================

# The connector's own registry key. Created by the connector installer, never by this
# run - which is why a server without the connector reports the value as outstanding
# rather than having it written into a key nothing has defined the meaning of yet.
$script:adcsPkcsRegistryPath = "HKLM:\SOFTWARE\Microsoft\MicrosoftIntune\PFXCertificateConnector"

# KB5014754 strong mapping. Off by default and set by no installer: certificates issue
# perfectly well without it, and then a domain controller refuses to authenticate one.
$script:adcsPkcsSidValueName = "EnableSidSecurityExtension"

# The connector version that first writes the SID extension. Below this the registry
# value is read by nothing.
$script:adcsPkcsSidMinimumVersion = [version]"6.2406.0.1001"

# Strong mapping in the connector is supported on Windows Server 2019 and later only.
# A warning rather than a refusal: the connector installs on 2012 R2 and later and
# still issues certificates on an older build - what stops working is authenticating
# with what it issued, which is the failure that gets blamed on the template.
$script:adcsPkcsStrongMappingMinimumBuild = 17763

# Both connector services. The value above is read at service start, so writing it
# without the restart changes nothing until somebody reboots.
$script:adcsPkcsServiceNames = @(
    "PFXCertificateConnectorSvc",
    "PkcsCreateLegacyConnectorSvc"
)

# The issuing CA's common name, which is what both directory reads below are keyed on.
# This tier holds no CA of its own, so everything it wants to know about one is read out
# of the configuration naming context by name.
function Get-AdcsPkcsCaCommonName {
    param([Parameter(Mandatory)][object]$CertificateServices)

    $issuing = Get-ConfigValue -InputObject $CertificateServices -Name "issuing"
    return ([string](Get-ConfigText -InputObject $issuing -Name "caCommonName" -Default "")).Trim()
}

function Get-AdcsPkcsGroupName {
    param([Parameter(Mandatory)][object]$Connector)

    return ([string](Get-ConfigText -InputObject $Connector -Name "enrollmentGroup" -Default "")).Trim()
}

# The enrollment group each selected template grants Enroll to - what the connector
# group is nested into. The studio reads them off the same template grants the issuing
# run writes the ACEs from, so this list and those ACEs name the same strings.
function Get-AdcsPkcsTemplateGroup {
    param([Parameter(Mandatory)][object]$Connector)

    $names = @()
    foreach ($name in @(Get-ConfigArray -InputObject $Connector -Name "templateGroups")) {
        $text = ([string]$name).Trim()
        if (-not [string]::IsNullOrWhiteSpace($text) -and ($names -notcontains $text)) { $names += $text }
    }
    return $names
}

function Get-AdcsPkcsTemplateName {
    param([Parameter(Mandatory)][object]$Connector)

    $names = @()
    foreach ($name in @(Get-ConfigArray -InputObject $Connector -Name "templateNames")) {
        $text = ([string]$name).Trim()
        if (-not [string]::IsNullOrWhiteSpace($text) -and ($names -notcontains $text)) { $names += $text }
    }
    return $names
}

# The connector group goes INSIDE each template's own enrollment group rather than onto
# the template itself, so a PKCS template's ACL has the same shape as every other
# template this design writes and withdrawing one is a change to one group. What
# Microsoft's shared-queue rule actually needs survives that: every connector is still in
# one group, and that group is in all of them, so a second connector reaches every PKCS
# template the moment it joins - which is the property a per-connector group would break
# and a per-template group never did.
#
# Every run, and not only the run that creates the group. Set-AdcsAccessGroup adopts a
# group that already exists and leaves its membership alone, which is right for a
# membership somebody decided and exactly wrong for this one: the nesting is structural,
# not a decision, and a design whose second run silently skipped it would issue nothing
# and point at the template.
#
# Add-only, like every other membership write in this project. A group that is missing is
# an Error rather than a Warn: the template is published, its Enroll rule names a group,
# and nothing is inside it - a CA that refuses the connector and says nothing about why.
function Add-AdcsPkcsGroupNesting {
    param(
        [Parameter(Mandatory)][string]$ConnectorGroup,
        [string[]]$TemplateGroup = @()
    )

    $names = @($TemplateGroup | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($names.Count -eq 0) {
        Write-Log "No template enrollment group is named, so '$ConnectorGroup' is nested into nothing here" -Tag "Info"
        Write-Log "    Expected in the original retrofit, where the templates and their groups belong to whoever owns that CA" -Tag "Debug"
        return $true
    }

    $connectorEntry = Find-AdcsGroup -Name $ConnectorGroup
    if ($null -eq $connectorEntry) {
        Write-Log "The group '$ConnectorGroup' could not be read back - it was not nested into anything" -Tag "Error"
        return $false
    }
    $connectorDn = [string]$connectorEntry.Properties["distinguishedname"][0]

    $allDone = $true
    foreach ($name in $names) {
        $entry = Find-AdcsGroup -Name $name
        if ($null -eq $entry) {
            Write-Log "The enrollment group '$name' does not exist - '$ConnectorGroup' is not in it, so nothing can enroll that template" -Tag "Error"
            Write-Log "    The access-group pass on this run creates it; with group creation switched off it is yours to make, then re-run" -Tag "Info"
            $allDone = $false
            continue
        }

        $group = $entry.GetDirectoryEntry()
        $members = @()
        try { $members = @($group.Properties["member"] | ForEach-Object { [string]$_ }) } catch { $members = @() }
        if ($members -contains $connectorDn) {
            Write-Log "'$ConnectorGroup' is already in '$name'" -Tag "Debug"
            continue
        }

        try {
            $null = $group.Properties["member"].Add($connectorDn)
            $group.CommitChanges()
        }
        catch {
            Write-Log "Could not nest '$ConnectorGroup' into '$name': $($_.Exception.Message)" -Tag "Error"
            $allDone = $false
            continue
        }
        Write-Log "Nested '$ConnectorGroup' into '$name'" -Tag "Ok"
    }
    return $allDone
}

# ---------------------------[ The directory tier's half ]---------------------------
# One group holding the computer accounts, nested into each template's own enrollment
# group. There is no service account to create: the connector runs as SYSTEM and reaches
# the CA as the machine.
function Set-AdcsPkcsDirectory {
    param(
        [Parameter(Mandatory)][object]$CertificateServices,
        [Parameter(Mandatory)][object]$Connector
    )

    $groupName = Get-AdcsPkcsGroupName -Connector $Connector
    if ([string]::IsNullOrWhiteSpace($groupName)) {
        Write-Log "The PKCS tier names no enrollment group - nothing to create in the directory" -Tag "Error"
        return $false
    }

    $computerName = ([string](Get-ConfigText -InputObject $Connector -Name "computerName" -Default "")).Trim()
    if ([string]::IsNullOrWhiteSpace($computerName)) {
        Write-Log "The PKCS tier names no computer, so there is no account to put in '$groupName'" -Tag "Error"
        return $false
    }

    # Created empty first, then filled: Sync-StudioAccessGroup resolves members by UPN
    # and a computer has none, which is why the membership goes through the same
    # sAMAccountName searcher the CEP Encryption group uses.
    if (-not (Sync-StudioAccessGroup -Name $groupName `
                -Description "The Intune Certificate Connector - the only principal that enrolls PKCS requests")) {
        return $false
    }

    if (-not (Add-AdcsScepComputerMember -GroupName $groupName -ComputerName $computerName `
                -Purpose "the Intune Certificate Connector reaches the CA as this machine when it is installed as SYSTEM")) {
        return $false
    }

    # After the member, not before: a group nested somewhere before it holds anything is
    # a right granted to nobody, and the order costs nothing to get right.
    if (-not (Add-AdcsPkcsGroupNesting -ConnectorGroup $groupName `
                -TemplateGroup (Get-AdcsPkcsTemplateGroup -Connector $Connector))) {
        return $false
    }

    # Said here because this run cannot do it and the next one can: the group exists
    # now and holds nothing on any CA until the issuing run writes its ACEs.
    $caName = Get-AdcsPkcsCaCommonName -CertificateServices $CertificateServices
    if ([string]::IsNullOrWhiteSpace($caName)) {
        Write-Log "'$groupName' is created, filled and nested - no issuing CA is named, so its permissions are somebody else's to grant" -Tag "Warn"
    }
    else {
        Write-Log "'$groupName' is created, filled and nested - the run on '$caName' grants it Request Certificates and writes each template's Enroll rule" -Tag "Info"
    }
    return $true
}

# ---------------------------[ The connector host's half ]---------------------------

# Desktop Experience is checked by Test-AdcsScepDesktopExperience, which is shared
# rather than copied: the requirement is the connector's and not NDES's, the refusal it
# prints is already the right one, and two probes answering the same question is two
# things to keep in step. The same goes for Test-AdcsScepCaChainTrust and
# Disable-AdcsScepEnhancedSecurity below - the `Scep` in those names is where they were
# written, not who they are for.

# .NET 4.7.2 or later. The connector installer will attempt to put 4.7.2 in itself, so
# this reports rather than refuses - what it buys is that a failure later reads as the
# prerequisite it is instead of as an installer that died for no stated reason.
function Test-AdcsPkcsDotNetVersion {
    $release = 0
    try {
        $release = [int](Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" `
            -Name "Release" -ErrorAction Stop).Release
    }
    catch { $release = 0 }

    # 461808 is 4.7.2 on Windows Server 2019 and later; 461814 is the same release on
    # older builds. The lower of the two is the honest floor to compare against.
    if ($release -ge 461808) {
        Write-Log ".NET Framework release $release - 4.7.2 or later" -Tag "Debug"
        return $true
    }
    if ($release -eq 0) {
        Write-Log "Could not read the installed .NET Framework release - the connector needs 4.7.2 or later" -Tag "Warn"
    }
    else {
        Write-Log ".NET Framework release $release is below 4.7.2 - the connector installer will try to install it" -Tag "Warn"
    }
    return $true
}

# Strong mapping is a 2019-and-later feature of the connector. Reported, never blocking:
# everything else about this tier works on an older build.
function Test-AdcsPkcsStrongMappingSupported {
    $build = 0
    try { $build = [int](Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "CurrentBuildNumber" -ErrorAction Stop).CurrentBuildNumber }
    catch { $build = 0 }

    if ($build -le 0) {
        Write-Log "Could not read this server's build number - the strong mapping support check is skipped" -Tag "Warn"
        return $true
    }
    if ($build -lt $script:adcsPkcsStrongMappingMinimumBuild) {
        Write-Log "Build $build is older than Windows Server 2019 - the connector supports strong mapping on 2019 and later only" -Tag "Warn"
        Write-Log "Certificates from this connector will carry no SID, and a domain controller in full enforcement refuses them at authentication" -Tag "Warn"
        return $false
    }
    return $true
}

# Whether the connector is on this machine at all, and which version. Read from the
# service's own image rather than from an uninstall entry: the uninstall entry can
# survive a removal, the binary cannot.
function Get-AdcsPkcsConnectorVersion {
    $service = $null
    try { $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='PFXCertificateConnectorSvc'" -ErrorAction Stop }
    catch { $service = $null }
    if ($null -eq $service) { return $null }

    $imagePath = ([string]$service.PathName).Trim('"')
    if ([string]::IsNullOrWhiteSpace($imagePath) -or -not (Test-Path -LiteralPath $imagePath)) { return $null }

    try {
        $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($imagePath)
        return [version]$info.FileVersion
    }
    catch {
        Write-Log "Could not read the connector's version from '$imagePath': $($_.Exception.Message)" -Tag "Warn"
        return $null
    }
}

# The one thing this tier writes. It is deliberately NOT pre-seeded on a server where
# the connector has never been installed: the key is the installer's, the version gate
# cannot be checked without it, and a value written into a key nothing has created yet
# would be reported as done and then quietly lost if the installer rewrites the key.
function Set-AdcsPkcsSidExtension {
    param([Parameter(Mandatory)][bool]$Wanted)

    if (-not $Wanted) {
        Write-Log "The SID security extension is off in the design - '$script:adcsPkcsSidValueName' is left as it is" -Tag "Info"
        return "Skipped"
    }

    if (-not (Test-Path -LiteralPath $script:adcsPkcsRegistryPath)) {
        Write-Log "The Certificate Connector is not installed on this server yet, so '$script:adcsPkcsSidValueName' cannot be set" -Tag "Warn"
        Write-Log "Install the connector, then run this config again - the value is written then and nothing else changes" -Tag "Warn"
        return "Pending"
    }

    $version = Get-AdcsPkcsConnectorVersion
    if ($null -ne $version) {
        Write-Log "Certificate Connector version $version" -Tag "Info"
        if ($version -lt $script:adcsPkcsSidMinimumVersion) {
            Write-Log "Version $version is older than $script:adcsPkcsSidMinimumVersion, which is where the SID extension was added" -Tag "Error"
            Write-Log "Update the connector first - setting the value on this build writes a flag nothing reads" -Tag "Error"
            return "Failed"
        }
    }
    else {
        Write-Log "The connector's version could not be read - the value is set anyway and takes effect on $script:adcsPkcsSidMinimumVersion or later" -Tag "Warn"
    }

    $null = Test-AdcsPkcsStrongMappingSupported

    $current = $null
    try { $current = (Get-ItemProperty -Path $script:adcsPkcsRegistryPath -Name $script:adcsPkcsSidValueName -ErrorAction Stop).$script:adcsPkcsSidValueName }
    catch { $current = $null }

    if ($null -ne $current -and [int]$current -eq 1) {
        Write-Log "'$script:adcsPkcsSidValueName' is already 1 - no change and no restart" -Tag "Info"
        return "Completed"
    }

    try {
        $null = New-ItemProperty -Path $script:adcsPkcsRegistryPath -Name $script:adcsPkcsSidValueName `
            -PropertyType DWord -Value 1 -Force -ErrorAction Stop
        Write-Log "Set '$script:adcsPkcsSidValueName' to 1 - PKCS certificates now carry the SID security extension" -Tag "Success"
    }
    catch {
        Write-Log "Could not set '$script:adcsPkcsSidValueName': $($_.Exception.Message)" -Tag "Error"
        return "Failed"
    }

    # The value is read at service start. Restarting is the whole point of writing it.
    foreach ($serviceName in $script:adcsPkcsServiceNames) {
        $service = $null
        try { $service = Get-Service -Name $serviceName -ErrorAction Stop } catch { $service = $null }
        if ($null -eq $service) {
            Write-Log "No service '$serviceName' on this server - nothing to restart" -Tag "Debug"
            continue
        }
        try {
            Restart-Service -Name $serviceName -Force -ErrorAction Stop
            Write-Log "Restarted '$serviceName'" -Tag "Success"
        }
        catch {
            Write-Log "Could not restart '$serviceName': $($_.Exception.Message)" -Tag "Warn"
            Write-Log "The value is read at service start, so restart it by hand before expecting the SID extension" -Tag "Warn"
        }
    }
    return "Completed"
}

# Whether the CA issues or holds. `certutil -setreg policy\RequestDisposition` is a
# CA-wide switch that outranks every template: with it set to pend, every PKCS request
# lands in Pending Requests and the connector logs "The submission is pending" - the
# profile then waits for ever with nothing on this side saying why.
#
# Read remotely by name, because this tier runs on a member server and that value is in
# the CA's own registry. What it reports is deliberately narrow: Microsoft documents 1
# as issue-immediately, so 1 is reported as correct and ANYTHING ELSE is reported as the
# raw value with what it means left open. This probe has not been on a bench against a
# pending CA, and the rule this project learned twice - once from `certutil -CAInfo
# role` and once from `certutil -getreg CA\Security` - is that a probe must not claim
# more than the measurement supports. Never a refusal.
function Test-AdcsPkcsCaRequestDisposition {
    param([Parameter(Mandatory)][string]$CaCommonName)

    $output = ""
    try { $output = (& certutil.exe -config $CaCommonName -getreg "policy\RequestDisposition" 2>&1 | Out-String) }
    catch {
        Write-Log "Could not read the CA's request disposition: $($_.Exception.Message)" -Tag "Debug"
        return
    }

    $match = [regex]::Match($output, "RequestDisposition\s+REG_DWORD\s+=\s+([0-9a-fA-Fx]+)")
    if (-not $match.Success) {
        Write-Log "The CA's request disposition could not be read from certutil's output - it is not checked" -Tag "Debug"
        return
    }

    $raw = $match.Groups[1].Value
    $value = 0
    try { $value = [Convert]::ToInt32($raw, $(if ($raw -like "0x*") { 16 } else { 10 })) }
    catch { $value = -1 }

    if ($value -eq 1) {
        Write-Log "The CA issues requests immediately (policy\RequestDisposition = 1)" -Tag "Debug"
        return
    }

    Write-Log "The CA's policy\RequestDisposition is $raw, not 1 - Microsoft documents 1 as issue-immediately" -Tag "Warn"
    Write-Log "    a CA that holds requests pending answers every PKCS profile with 'The submission is pending' and issues nothing" -Tag "Warn"
    Write-Log "    check Certification Authority > Properties > Policy Module > Properties on '$CaCommonName' before blaming the template" -Tag "Warn"
}

# What the CA has to answer before any of this works, asked with the identity that will
# actually be asking: this machine. The template ACL check is the one that matters -
# Microsoft's documented failure here is "Denied by Policy Module", which says nothing
# about which template or which account.
function Test-AdcsPkcsEnrollment {
    param(
        [Parameter(Mandatory)][object]$CertificateServices,
        [Parameter(Mandatory)][object]$Connector
    )

    $templateNames = Get-AdcsPkcsTemplateName -Connector $Connector
    if ($templateNames.Count -eq 0) {
        Write-Log "The PKCS tier names no template - a profile has nothing to ask for" -Tag "Warn"
        return $true
    }

    $caName = Get-AdcsPkcsCaCommonName -CertificateServices $CertificateServices
    if ([string]::IsNullOrWhiteSpace($caName)) {
        Write-Log "The design names no issuing CA, so what it publishes cannot be checked from here" -Tag "Warn"
        return $true
    }

    # Read out of the CA's own enrollment services object rather than off this machine:
    # this server has no CA and still needs to know what the issuing one publishes.
    $published = @()
    try { $published = @(Get-AdcsPublishedTemplateForCa -CaCommonName $caName) }
    catch {
        Write-Log "Could not read what '$caName' publishes: $($_.Exception.Message)" -Tag "Warn"
        return $true
    }

    $allFound = $true
    foreach ($templateName in $templateNames) {
        $match = @($published | Where-Object { $_.Equals($templateName, [System.StringComparison]::OrdinalIgnoreCase) })
        if ($match.Count -gt 0) {
            Write-Log "'$templateName' is published on '$caName'" -Tag "Success"
        }
        else {
            Write-Log "'$templateName' is NOT published on '$caName' - a profile naming it fails with 'The requested certificate template is not supported by this CA'" -Tag "Warn"
            Write-Log "    the issuing CA run publishes it; run this config there first" -Tag "Warn"
            $allFound = $false
        }
    }
    return $allFound
}

# ---------------------------[ The tier ]---------------------------
function Invoke-AdcsPkcsTier {
    param(
        [Parameter(Mandatory)][object]$CertificateServices,
        [Parameter(Mandatory)][object]$Connector
    )

    Write-Log "Configuring this server as the Intune Certificate Connector host - PKCS mode" -Tag "Info"
    Write-Log "PKCS installs no Windows feature: the connector reaches the CA over RPC and runs no web server" -Tag "Info"

    if (Test-AdcsDomainController) {
        return (New-RoleResult -Status "Failed" -Message "The certificate connector must not run on a domain controller - point the tier at a member server.")
    }
    if (-not (Test-AdcsScepDesktopExperience)) {
        return (New-RoleResult -Status "Failed" -Message "The Certificate Connector requires Desktop Experience and this is a Server Core installation, which cannot be converted after setup.")
    }
    $null = Test-AdcsPkcsDotNetVersion

    # EVERY refusal before ANY change. This tier's only persistent change to the host
    # weakens it, and a run that weakened the server and then refused to do anything
    # else is the worst of both - field-hit 2026-09-19, where Enhanced Security
    # Configuration was switched off and the run then failed on the chain check four
    # seconds later, leaving a hardening feature off for a run that configured nothing.
    $caName = Get-AdcsPkcsCaCommonName -CertificateServices $CertificateServices
    if (-not [string]::IsNullOrWhiteSpace($caName)) {
        $chain = Test-AdcsScepCaChainTrust -CaCommonName $caName
        if ($chain.Checked -and -not $chain.Trusted) {
            Write-Log "This server does not trust the issuing CA's own certificate - its chain ends in a root this machine does not hold" -Tag "Error"
            Write-Log "    a member server receives the enterprise root through group policy, not by being in the domain - try gpupdate /force" -Tag "Error"
            Write-Log "    nothing has been changed on this server" -Tag "Info"
            return (New-RoleResult -Status "Failed" -Message "This server does not trust the issuing CA's certificate chain - the connector cannot talk to a CA it cannot validate.")
        }
    }

    # Enhanced Security Configuration off - a stated connector prerequisite, and the
    # thing that stops the configuration wizard's Entra sign-in working. Both components
    # and no switch, exactly as the SCEP path does it: a prerequisite is done.
    $null = Disable-AdcsScepEnhancedSecurity

    $groupName = Get-AdcsPkcsGroupName -Connector $Connector
    if (-not [string]::IsNullOrWhiteSpace($groupName)) {
        Write-Log "This machine enrolls through '$groupName' - the directory run puts its computer account in it" -Tag "Info"
    }

    $null = Test-AdcsPkcsEnrollment -CertificateServices $CertificateServices -Connector $Connector
    if (-not [string]::IsNullOrWhiteSpace($caName)) {
        Test-AdcsPkcsCaRequestDisposition -CaCommonName $caName
    }

    $sidWanted = [bool](Get-ConfigValue -InputObject $Connector -Name "sidExtension" -Default $true)
    $sidState = Set-AdcsPkcsSidExtension -Wanted $sidWanted

    if ($sidState -eq "Failed") {
        return (New-RoleResult -Status "Failed" -Message "The SID security extension could not be set on this connector - see the log.")
    }

    # The connector itself. Manual in both modes, and said plainly rather than left to
    # be discovered at the end of a run that reported success.
    $version = Get-AdcsPkcsConnectorVersion
    if ($null -eq $version) {
        Write-Log "The Certificate Connector for Microsoft Intune is not installed on this server" -Tag "Warn"
        Write-Log "    Intune admin center > Tenant administration > Connectors and tokens > Certificate connectors > Add" -Tag "Warn"
        Write-Log "    Run IntuneCertificateConnector.exe, tick PKCS, leave the service account on SYSTEM, sign in as an Intune Administrator" -Tag "Warn"
        return (New-RoleResult -Status "ManualStepRequired" `
            -Message "The CA side is ready. Install the Certificate Connector for Microsoft Intune on this server - it is an interactive Entra sign-in - and run this config again to set the SID extension.")
    }

    if ($sidState -eq "Pending") {
        return (New-RoleResult -Status "ManualStepRequired" `
            -Message "The connector is installed but its registry key was not readable - run this config again once the connector has been configured.")
    }

    return (New-RoleResult -Status "Completed" `
        -Message ("The Intune Certificate Connector host is configured for PKCS - connector {0}, {1} template(s)." -f $version, (Get-AdcsPkcsTemplateName -Connector $Connector).Count))
}
