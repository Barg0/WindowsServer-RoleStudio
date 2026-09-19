# Role provider: Active Directory Certificate Services.
#
# Dot-sourced by Configure-ServerRoles.ps1 - not runnable on its own. Everything
# here lands in that script's scope, so $script: variables and functions are shared
# with every other part. Use $scriptRootPath, never $PSScriptRoot: inside this file
# $PSScriptRoot is the pwsh folder, not the folder the run was started from.

# ===========================[ Active Directory Certificate Services ]===========================
# A two-tier PKI across two machines, driven by one config.json that travels with
# the transfer folder. Which half of it applies is decided by the computer name.
#
#   1. issuing  installs the subordinate CA and writes a request   -> ManualStepRequired
#   2. carry    transfer\ to the offline root
#   3. root     installs itself, signs the request, writes the chain
#   4. carry    transfer\ back
#   5. issuing  publishes the root, installs the chain, configures, publishes a CRL
#
# Nothing here is step-numbered: each run looks at what already exists and does the
# next thing that is possible, so the order the two machines are visited in does not
# matter, re-running is always safe, and the yearly root CRL ceremony is the same
# two commands as the initial build.

# certcli.h CSURL_* flags. Spelled out because a bare "79:" in a CDP string is the
# single most copy-pasted, least understood number in a Windows PKI.
$script:csurlServerPublish      = 1
$script:csurlAddToCertCdp       = 2
$script:csurlAddToFreshestCrl   = 4
$script:csurlAddToCrlCdp        = 8
$script:csurlAddToCertOcsp      = 32
$script:csurlServerPublishDelta = 64

$script:adcsCertEnrollPath = Join-Path -Path $env:SystemRoot -ChildPath "system32\CertSrv\CertEnroll"

# What the CRL and the CA certificate are called where they are served over HTTP.
# Not '%3' - that expands to the CA's common name, spaces and all, so a CA called
# 'MiGolf Local Issuing CA' produces a URL full of %20 that is then frozen into every
# certificate it issues. The published guidance is to keep these names simple; the
# name has to be deterministic rather than pretty, because the file the CA writes and
# the URL stamped into the certificate are built from it separately and a mismatch is
# a 404 nothing can correct afterwards.
function Get-AdcsPublicationName {
    param([Parameter(Mandatory)][string]$CommonName)

    return ($CommonName -replace '[^A-Za-z0-9-]', '-')
}

# The same rename applied to a file that arrived from somewhere else - the root's CRL
# and certificate cross the air gap under the names the root's CertEnroll gave them.
# Everything up to and including the common name goes: the CA certificate is written
# as '<hostname>_<CA name>.crt', and naming the server is what the dedicated DNS name
# exists to avoid.
function ConvertTo-AdcsWebFileName {
    param(
        [Parameter(Mandatory)][string]$FileName,
        [string[]]$CommonName = @()
    )

    foreach ($name in $CommonName) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $index = $FileName.IndexOf($name, [System.StringComparison]::OrdinalIgnoreCase)
        if ($index -lt 0) { continue }
        return (Get-AdcsPublicationName -CommonName $name) + $FileName.Substring($index + $name.Length)
    }
    return $FileName
}

# ---------------------------[ Tier and paths ]---------------------------
# Three machines, one config: each applies the tier whose computerName is its own.
# The directory tier is deliberately last - a machine named as both a CA and the
# directory tier is a mistake the studio calls out, and being a CA is the answer that
# does not silently skip building one.
# The connector tier was written as `scep` before it had a second mode and is written
# as `intuneConnector` now. Both are read, the new one first, so a config.json from an
# earlier build still runs unchanged - there is no migration step and nothing rewrites
# the old file. The TIER NAME stays "scep" throughout the engine: it is what the plan,
# the summary and every existing branch key off, and renaming it would be a rename of
# the run rather than of a config key.
function Get-AdcsTierSection {
    param([object]$CertificateServices, [Parameter(Mandatory)][string]$TierName)

    if ($TierName -eq "scep") {
        $connector = Get-ConfigValue -InputObject $CertificateServices -Name "intuneConnector"
        if ($null -ne $connector) { return $connector }
    }
    return (Get-ConfigValue -InputObject $CertificateServices -Name $TierName)
}

# scep or pkcs. Absent means a config written before the second mode existed, and every
# one of those is a SCEP design.
function Get-AdcsConnectorMode {
    param([object]$CertificateServices)

    $connector = Get-AdcsTierSection -CertificateServices $CertificateServices -TierName "scep"
    $mode = [string](Get-ConfigText -InputObject $connector -Name "connectorMode" -Default "scep")
    if ($mode.Equals("pkcs", [System.StringComparison]::OrdinalIgnoreCase)) { return "pkcs" }
    return "scep"
}

function Resolve-AdcsTier {
    param([object]$CertificateServices)

    foreach ($tierName in @("root", "issuing", "scep", "directory")) {
        $tier = Get-AdcsTierSection -CertificateServices $CertificateServices -TierName $tierName
        if ($null -eq $tier) { continue }
        $name = [string](Get-ConfigText -InputObject $tier -Name "computerName" -Default "")
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        if ($name.Equals([string]$env:COMPUTERNAME, [System.StringComparison]::OrdinalIgnoreCase)) { return $tierName }
    }
    return ""
}

# build (the default, and what every config written before the setting existed
# means) installs whatever is missing; adopt applies this design to a CA that
# already exists and refuses to install one - a config meant for an existing CA
# that lands on a bare server must not quietly build a second PKI.
# Three modes, and they are three different runs rather than three views of one.
#
#   build   install what is missing and configure all of it.
#   adopt   apply this design to a CA somebody else built, and refuse to install one -
#           a config meant for an existing CA that lands on a bare server must not
#           quietly build a second PKI. Re-keying lives here, because re-keying is
#           something you do to a CA you have taken over.
#   renew   the annual trip and nothing else. No registry pass, no hardening, no
#           templates, no endpoint: a renewal config is a one-job config, and a run
#           that also reapplied the design would be doing work nobody asked for on the
#           one visit where the CA is mid-ceremony.
#   connector  the Intune Certificate Connector retrofit. A CA is already running and
#           somebody wants NDES beside it - so this mode does the CA-side groundwork
#           that retrofit used to leave as homework, and nothing else at all. On the
#           domain controller: the SCEP service account, its enrollment group, and the
#           certificate managers group. On the issuing CA: publish the SCEP templates
#           with their enrollment rights, and give that managers group Issue and Manage
#           Certificates so Intune can revoke. On the NDES box: the usual SCEP tier.
#
#           What it deliberately does NOT do is every other thing adopt does. No
#           registry pass, no CRL periods, no issued validity, no hardening, no
#           publication URLs, no re-key, no web publishing. Adopt means "this design
#           now describes that CA"; connector means "that CA is none of my business,
#           I need three objects on it". Running adopt to get a SCEP template would
#           rewrite a CA somebody else is responsible for, which is why this is a mode
#           and not a flag on that one.
#
# Absent means build, which is what every config written before the setting existed
# means.
function Get-AdcsMode {
    param([object]$CertificateServices)

    $mode = [string](Get-ConfigValue -InputObject $CertificateServices -Name "mode" -Default "build")
    if (@("adopt", "renew", "connector") -contains $mode) { return $mode }
    return "build"
}

function Get-AdcsTransferPath {
    param([object]$CertificateServices)

    $shared = Get-ConfigValue -InputObject $CertificateServices -Name "shared"
    $folder = [string](Get-ConfigValue -InputObject $shared -Name "transferDirectory" -Default "transfer")

    if ([System.IO.Path]::IsPathRooted($folder)) { return $folder }
    return (Join-Path -Path $scriptRootPath -ChildPath $folder)
}

function Confirm-AdcsTransferPath {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        $null = New-Item -ItemType Directory -Path $Path -Force
        Write-Log "Created the transfer folder '$Path'" -Tag "Info"
    }
    return $Path
}

# The web folder is a CRL *publication target*, so it has to exist before the target
# is registered rather than before the folder is first browsed - certsvc writes into
# it on the next 'certutil -CRL', which happens well before the IIS virtual directory
# is set up. Missing, it fails the publish with 0x8007010b ERROR_DIRECTORY, which
# names neither the path nor which of the four publication targets it was.
# Returns the path, or an empty string when this design does not publish over HTTP.
function Confirm-AdcsWebPath {
    param([Parameter(Mandatory)][object]$CertificateServices)

    $issuing = Get-ConfigValue -InputObject $CertificateServices -Name "issuing"
    $web     = Get-ConfigValue -InputObject $issuing -Name "webPublishing"

    if (($null -eq $web) -or (-not [bool](Get-ConfigValue -InputObject $web -Name "enabled" -Default $false))) {
        return ""
    }

    $webPath = [string](Get-ConfigValue -InputObject $web -Name "physicalPath" -Default "")
    if ([string]::IsNullOrWhiteSpace($webPath)) { return "" }

    if (-not (Test-Path -LiteralPath $webPath)) {
        $null = New-Item -ItemType Directory -Path $webPath -Force
        Write-Log "Created '$webPath' for CRL publication" -Tag "Info"
    }
    return $webPath
}

# ---------------------------[ Transfer manifest ]---------------------------
# The air gap is the security control, so the crossing gets a checksum rather than
# an automated copy. Anything that arrives without a matching hash stops the run.
function New-AdcsTransferManifest {
    param([Parameter(Mandatory)][string]$Path)

    $entries = @()
    $files = @(Get-ChildItem -LiteralPath $Path -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne "manifest.json" })

    foreach ($file in $files) {
        $hash = Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop
        $entries += [pscustomobject]@{ name = $file.Name; sha256 = $hash.Hash }
    }

    $manifest = [pscustomobject]@{
        generatedUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        producedBy   = [string]$env:COMPUTERNAME
        files        = @($entries)
    }

    $manifestPath = Join-Path -Path $Path -ChildPath "manifest.json"
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    Write-Log "Wrote a manifest covering $($entries.Count) file(s) in the transfer folder" -Tag "Ok"
}

function Test-AdcsTransferManifest {
    param([Parameter(Mandatory)][string]$Path)

    $manifestPath = Join-Path -Path $Path -ChildPath "manifest.json"
    if (-not (Test-Path -LiteralPath $manifestPath)) {
        Write-Log "No manifest.json in the transfer folder - skipping the integrity check" -Tag "Info"
        return $true
    }

    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        Write-Log "manifest.json is not readable: $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    $producedBy = [string](Get-ConfigValue -InputObject $manifest -Name "producedBy" -Default "")
    if ($producedBy.Equals([string]$env:COMPUTERNAME, [System.StringComparison]::OrdinalIgnoreCase)) {
        # Our own manifest, still sitting where we wrote it. Nothing has crossed yet.
        return $true
    }

    $allMatch = $true
    foreach ($entry in (Get-ConfigArray -InputObject $manifest -Name "files")) {
        $name = [string](Get-ConfigValue -InputObject $entry -Name "name" -Default "")
        $expected = [string](Get-ConfigValue -InputObject $entry -Name "sha256" -Default "")
        $filePath = Join-Path -Path $Path -ChildPath $name

        if (-not (Test-Path -LiteralPath $filePath)) {
            Write-Log "'$name' is listed in the manifest but did not arrive" -Tag "Error"
            $allMatch = $false
            continue
        }

        $actual = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash
        if (-not $actual.Equals($expected, [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Log "'$name' does not match the manifest - the file changed in transit" -Tag "Error"
            $allMatch = $false
            continue
        }
        Write-Log "'$name' matches the manifest" -Tag "Debug"
    }

    if ($allMatch) {
        Write-Log "Every file from '$producedBy' matches the manifest" -Tag "Ok"
    }
    return $allMatch
}

# ---------------------------[ CA state ]---------------------------
function Get-AdcsActiveCaName {
    try {
        $configuration = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" -ErrorAction Stop
    }
    catch {
        return ""
    }
    return [string](Get-ConfigValue -InputObject $configuration -Name "Active" -Default "")
}

function Test-AdcsAuthorityInstalled {
    return (-not [string]::IsNullOrWhiteSpace((Get-AdcsActiveCaName)))
}

# A subordinate CA exists as a configuration long before it has a certificate. The
# CA cert hash is what tells the two states apart.
function Test-AdcsAuthorityCertified {
    $caName = Get-AdcsActiveCaName
    if ([string]::IsNullOrWhiteSpace($caName)) { return $false }

    try {
        $caKey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName" -ErrorAction Stop
    }
    catch {
        return $false
    }
    return (Test-ConfigProperty -InputObject $caKey -Name "CACertHash")
}

function Get-AdcsConfigString {
    $caName = Get-AdcsActiveCaName
    if ([string]::IsNullOrWhiteSpace($caName)) {
        throw "No certification authority is configured on this server."
    }
    return ("{0}\{1}" -f $env:COMPUTERNAME, $caName)
}

# ---------------------------[ Command helpers ]---------------------------
function Invoke-AdcsUtility {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [switch]$IgnoreExitCode
    )

    Write-Log "$FilePath $($ArgumentList -join ' ')" -Tag "Run"
    $output = & $FilePath @ArgumentList 2>&1
    $text = ($output | Out-String).Trim()

    if ($text) {
        foreach ($line in ($text -split "`r?`n")) {
            if ($line.Trim()) { Write-Log "    $($line.Trim())" -Tag "Debug" }
        }
    }

    if ((-not $IgnoreExitCode) -and ($LASTEXITCODE -ne 0)) {
        throw "$FilePath exited with code $LASTEXITCODE : $text"
    }
    return $text
}

function Set-AdcsRegistryValue {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )

    $null = Invoke-AdcsUtility -FilePath "certutil.exe" -ArgumentList @("-setreg", $Name, $Value)
}

# ---------------------------[ CAPolicy.inf ]---------------------------
# Built as a line list rather than a here-string: the file's first setting is
# Signature="$Windows NT$", which any double-quoted PowerShell string would eat.
function New-AdcsPolicyFile {
    param(
        [Parameter(Mandatory)][object]$Tier,
        [Parameter(Mandatory)][string]$TierName
    )

    $renewalPeriod = [string](Get-ConfigValue -InputObject $Tier -Name "validityPeriod" -Default "Years")
    $renewalUnits  = [int](Get-ConfigValue -InputObject $Tier -Name "validityUnits" -Default 5)
    $keyLength     = [int](Get-ConfigValue -InputObject $Tier -Name "keyLength" -Default 4096)
    $crl           = Get-ConfigValue -InputObject $Tier -Name "crl"

    # Same split as Set-AdcsAuthorityConfiguration: a year on the root, a week online.
    $crlPeriodDefault = "Weeks"
    $crlUnitsDefault  = 1
    if ($TierName -eq "root") {
        $crlPeriodDefault = "Years"
        $crlUnitsDefault  = 1
    }

    $lines = @(
        "[Version]",
        'Signature="$Windows NT$"',
        "",
        "[Certsrv_Server]",
        "RenewalKeyLength=$keyLength",
        "RenewalValidityPeriod=$renewalPeriod",
        "RenewalValidityPeriodUnits=$renewalUnits",
        "CRLPeriod=" + [string](Get-ConfigValue -InputObject $crl -Name "period" -Default $crlPeriodDefault),
        "CRLPeriodUnits=" + [int](Get-ConfigValue -InputObject $crl -Name "periodUnits" -Default $crlUnitsDefault),
        "CRLDeltaPeriod=" + [string](Get-ConfigValue -InputObject $crl -Name "deltaPeriod" -Default "Days"),
        "CRLDeltaPeriodUnits=" + [int](Get-ConfigValue -InputObject $crl -Name "deltaPeriodUnits" -Default 0),
        "AlternateSignatureAlgorithm=0",
        "LoadDefaultTemplates=0"
    )

    # Windows never revocation-checks a root, and the machine named in a CDP would be
    # switched off anyway. Empty sections drop both extensions from the root's cert.
    if ($TierName -eq "root") {
        $lines += @("", "[CRLDistributionPoint]", "", "[AuthorityInformationAccess]")
    }

    $policyPath = Join-Path -Path $env:SystemRoot -ChildPath "CAPolicy.inf"
    Write-Log "Writing $policyPath" -Tag "Run"
    Set-Content -LiteralPath $policyPath -Value $lines -Encoding ASCII
    Write-Log "CAPolicy.inf written for the $TierName tier" -Tag "Ok"
}

# ---------------------------[ Publication URLs ]---------------------------
function Set-AdcsPublicationUrl {
    param(
        [Parameter(Mandatory)][object]$CertificateServices,
        [Parameter(Mandatory)][string]$TierName
    )

    $shared     = Get-ConfigValue -InputObject $CertificateServices -Name "shared"
    $pkiBaseUrl = ([string](Get-ConfigValue -InputObject $shared -Name "pkiBaseUrl" -Default "")).TrimEnd("/")
    $tier       = Get-AdcsTierSection -CertificateServices $CertificateServices -TierName $TierName
    $crl        = Get-ConfigValue -InputObject $tier -Name "crl"
    $deltaUnits = [int](Get-ConfigValue -InputObject $crl -Name "deltaPeriodUnits" -Default 0)

    $localCrl = Join-Path -Path $script:adcsCertEnrollPath -ChildPath "%3%8%9.crl"
    $localCrt = Join-Path -Path $script:adcsCertEnrollPath -ChildPath "%1_%3%4.crt"
    $ldapCrl  = 'ldap:///CN=%7%8,CN=%2,CN=CDP,CN=Public Key Services,CN=Services,%6%10'
    $ldapCrt  = 'ldap:///CN=%7,CN=AIA,CN=Public Key Services,CN=Services,%6%11'

    # The local path publishes; LDAP and HTTP are what end up inside issued certs.
    $localCrlFlag = $script:csurlServerPublish
    if ($deltaUnits -gt 0) { $localCrlFlag = $localCrlFlag + $script:csurlServerPublishDelta }

    $ldapCrlFlag = $script:csurlAddToCertCdp + $script:csurlAddToCrlCdp
    $httpCrlFlag = $script:csurlAddToCertCdp
    if ($deltaUnits -gt 0) {
        $ldapCrlFlag = $script:csurlServerPublish + $script:csurlAddToCertCdp + $script:csurlAddToFreshestCrl +
            $script:csurlAddToCrlCdp + $script:csurlServerPublishDelta
        $httpCrlFlag = $script:csurlAddToCertCdp + $script:csurlAddToFreshestCrl
    }

    # The extension URLs go in first-tried order, and CryptoAPI walks them strictly in
    # order with a 15 second timeout on each. HTTP therefore comes before LDAP: a
    # client with no directory - a workgroup RDS host, a phone, anything not Windows -
    # would otherwise wait out that timeout on the LDAP entry before it ever reaches a
    # URL it can use. Microsoft's own current guidance drops the LDAP entry entirely;
    # it is kept here because it also *publishes* the CRL into the directory, which
    # costs nothing and is what domain controllers read.
    $crlUrls = @("$localCrlFlag`:$localCrl")
    $crtUrls = @("$($script:csurlServerPublish)`:$localCrt")

    $publicationName = Get-AdcsPublicationName -CommonName ([string](Get-ConfigValue -InputObject $tier -Name "caCommonName" -Default "ca"))

    # The web folder gets its own *publication* entry, not a copy made once during a
    # run. The CA regenerates its CRL on its own schedule - weekly here, daily for the
    # delta - straight into CertEnroll, and the HTTP URL frozen into every certificate
    # it has ever issued points at the web folder. Without this the file behind that
    # URL is stale within a week and every client that has no LDAP path fails
    # revocation checking, with no way to change the URL in the certificates already out.
    $web = Get-ConfigValue -InputObject $tier -Name "webPublishing"
    if (($TierName -eq "issuing") -and ($null -ne $web) -and
        [bool](Get-ConfigValue -InputObject $web -Name "enabled" -Default $false)) {
        $webPath = Confirm-AdcsWebPath -CertificateServices $CertificateServices
        if (-not [string]::IsNullOrWhiteSpace($webPath)) {
            $webCrl = Join-Path -Path $webPath -ChildPath "$publicationName%8%9.crl"
            $crlUrls += "$localCrlFlag`:$webCrl"

            # The CA certificate needs the same treatment for the same reason, on a
            # longer clock. Renewal writes a new file with %4 incremented, and the AIA
            # frozen into everything issued afterwards names it - so a web folder that
            # only ever received a copy made during some earlier run answers 404 for
            # the certificate clients need to build the chain.
            $webCrt = Join-Path -Path $webPath -ChildPath "$publicationName%4.crt"
            $crtUrls += "$($script:csurlServerPublish)`:$webCrt"

            Write-Log "The CA will publish its CRL and its own certificate into '$webPath' as well as CertEnroll" -Tag "Info"
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($pkiBaseUrl)) {
        $crlUrls += "$httpCrlFlag`:$pkiBaseUrl/$publicationName%8%9.crl"
        $crtUrls += "$($script:csurlAddToCertCdp)`:$pkiBaseUrl/$publicationName%4.crt"
    }
    else {
        Write-Log "No shared.pkiBaseUrl is set - issued certificates will carry LDAP paths only" -Tag "Info"
    }

    # Last, so a client that can reach the web endpoint never waits on the directory.
    $crlUrls += "$ldapCrlFlag`:$ldapCrl"
    $crtUrls += "$($script:csurlAddToCertCdp)`:$ldapCrt"

    Set-AdcsRegistryValue -Name "CA\CRLPublicationURLs"    -Value ($crlUrls -join '\n')
    Set-AdcsRegistryValue -Name "CA\CACertPublicationURLs" -Value ($crtUrls -join '\n')
    Write-Log "CDP and AIA publication URLs applied" -Tag "Ok"
}

function Set-AdcsAuthorityConfiguration {
    param(
        [Parameter(Mandatory)][object]$CertificateServices,
        [Parameter(Mandatory)][string]$TierName
    )

    $shared = Get-ConfigValue -InputObject $CertificateServices -Name "shared"
    $tier   = Get-AdcsTierSection -CertificateServices $CertificateServices -TierName $TierName
    $crl    = Get-ConfigValue -InputObject $tier -Name "crl"

    # An offline root has never seen the domain, so the %6 in an LDAP path has
    # nothing to expand to until DSConfigDN says what the forest is called.
    $dsConfigDn = [string](Get-ConfigValue -InputObject $shared -Name "dsConfigDN" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($dsConfigDn)) {
        Set-AdcsRegistryValue -Name "CA\DSConfigDN" -Value $dsConfigDn
    }

    # A missing crl block means one year on the root - the ceremony interval - and one
    # week on an online issuing CA, which republishes by itself.
    $crlPeriodDefault = "Weeks"
    $crlUnitsDefault  = 1
    if ($TierName -eq "root") {
        $crlPeriodDefault = "Years"
        $crlUnitsDefault  = 1
    }

    Set-AdcsRegistryValue -Name "CA\CRLPeriod"            -Value ([string](Get-ConfigValue -InputObject $crl -Name "period" -Default $crlPeriodDefault))
    Set-AdcsRegistryValue -Name "CA\CRLPeriodUnits"       -Value ([string][int](Get-ConfigValue -InputObject $crl -Name "periodUnits" -Default $crlUnitsDefault))
    Set-AdcsRegistryValue -Name "CA\CRLDeltaPeriod"       -Value ([string](Get-ConfigValue -InputObject $crl -Name "deltaPeriod" -Default "Days"))
    Set-AdcsRegistryValue -Name "CA\CRLDeltaPeriodUnits"  -Value ([string][int](Get-ConfigValue -InputObject $crl -Name "deltaPeriodUnits" -Default 0))
    Set-AdcsRegistryValue -Name "CA\CRLOverlapPeriod"     -Value ([string](Get-ConfigValue -InputObject $crl -Name "overlapPeriod" -Default "Hours"))
    Set-AdcsRegistryValue -Name "CA\CRLOverlapPeriodUnits" -Value ([string][int](Get-ConfigValue -InputObject $crl -Name "overlapPeriodUnits" -Default 12))

    # What this CA stamps on the certificates it issues, not its own lifetime. A
    # subordinate cannot outlive its parent, so Windows silently truncates anything
    # that does not fit inside what the CA has left.
    Set-AdcsRegistryValue -Name "CA\ValidityPeriod"      -Value ([string](Get-ConfigValue -InputObject $tier -Name "issuedValidityPeriod" -Default "Years"))
    Set-AdcsRegistryValue -Name "CA\ValidityPeriodUnits" -Value ([string][int](Get-ConfigValue -InputObject $tier -Name "issuedValidityUnits" -Default 1))

    Set-AdcsRegistryValue -Name "CA\AuditFilter" -Value ([string][int](Get-ConfigValue -InputObject $tier -Name "auditFilter" -Default 127))

    Set-AdcsHardening -Hardening (Get-ConfigValue -InputObject $shared -Name "hardening")
    $null = Test-AdcsSidExtension

    Set-AdcsPublicationUrl -CertificateServices $CertificateServices -TierName $TierName
}

# ---------------------------[ Hardening ]---------------------------
# The published ESC catalogue is mostly about certificate templates, but four of the
# mitigations live on the CA itself and cost nothing to apply at build time.
$script:adcsSidExtensionOid = "1.3.6.1.4.1.311.25.2"
# Object Access -> Certification Services. Addressed by GUID because the display
# name is localised, and a German or French server would not match the English one.
$script:adcsAuditSubcategoryGuid = "{0CCE9221-69AE-11D9-BED3-505054503030}"

# "Audit: Force audit policy subcategory settings to override audit policy category
# settings". Without it, any legacy category-level audit policy that arrives - from a
# GPO or from the local security policy - discards the subcategory setting below at
# the next refresh, and the CA quietly goes back to logging nothing.
$script:adcsLsaKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

function Enable-AdcsAuditSubcategoryOverride {
    try {
        $current = $null
        $existing = Get-ItemProperty -Path $script:adcsLsaKeyPath -Name "SCENoApplyLegacyAuditPolicy" -ErrorAction SilentlyContinue
        if ($null -ne $existing) { $current = $existing.SCENoApplyLegacyAuditPolicy }

        if ($current -eq 1) {
            Write-Log "Audit policy subcategories already override the legacy categories" -Tag "Info"
            return $true
        }

        Set-ItemProperty -Path $script:adcsLsaKeyPath -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord -ErrorAction Stop
        Write-Log "SCENoApplyLegacyAuditPolicy set" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "Could not set SCENoApplyLegacyAuditPolicy: $($_.Exception.Message)" -Tag "Error"
        Write-Log "Without it a legacy audit policy will silently undo the subcategory setting" -Tag "Error"
        return $false
    }
}

# certutil -setreg CA\AuditFilter on its own produces no audit events whatsoever.
# The subcategory has to be switched on as well, which is the step that gets missed
# and leaves an audited-looking CA writing nothing to the Security log.
function Enable-AdcsAuditPolicy {
    $null = Enable-AdcsAuditSubcategoryOverride

    $auditPol = Join-Path -Path $env:SystemRoot -ChildPath "system32\auditpol.exe"
    if (-not (Test-Path -LiteralPath $auditPol)) {
        Write-Log "auditpol.exe was not found - enable Object Access / Certification Services auditing by hand" -Tag "Error"
        return
    }

    $null = Invoke-AdcsUtility -FilePath $auditPol -ArgumentList @(
        "/set", "/subcategory:$($script:adcsAuditSubcategoryGuid)", "/success:enable", "/failure:enable")
    Write-Log "Certification Services auditing enabled for success and failure" -Tag "Ok"

    # The registry value above only settles a fight between local settings. A domain
    # audit policy still wins at the next refresh, and nothing on this server can stop
    # it - so say so rather than leaving a silent regression.
    Write-Log "    A domain audit policy can still override this - check with: auditpol /get /subcategory:$($script:adcsAuditSubcategoryGuid)" -Tag "Info"
}

function Set-AdcsHardening {
    param([Parameter(Mandatory)][object]$Hardening)

    # ESC6. With this flag set, any enrollee can put an arbitrary SAN - a domain
    # admin's UPN, for instance - into a request, whatever the template allows.
    if ([bool](Get-ConfigValue -InputObject $Hardening -Name "disableSanAttribute" -Default $true)) {
        Set-AdcsRegistryValue -Name "policy\EditFlags" -Value "-EDITF_ATTRIBUTESUBJECTALTNAME2"
        Write-Log "EDITF_ATTRIBUTESUBJECTALTNAME2 cleared - requesters cannot dictate their own SAN" -Tag "Ok"
    }
    else {
        Write-Log "EDITF_ATTRIBUTESUBJECTALTNAME2 left alone - while it is set, any enrollee can request a certificate for any identity" -Tag "Error"
    }

    # ESC11. Unencrypted ICertPassage RPC enrollment is relayable.
    if ([bool](Get-ConfigValue -InputObject $Hardening -Name "enforceEncryptedRequests" -Default $true)) {
        Set-AdcsRegistryValue -Name "CA\InterfaceFlags" -Value "+IF_ENFORCEENCRYPTICERTREQUEST"
        Write-Log "RPC enrollment requests must now be encrypted" -Tag "Ok"
    }

    # Genuinely recommended, genuinely able to lock an administrator out of their own
    # CA, so it stays opt-in rather than being switched on for everyone.
    if ([bool](Get-ConfigValue -InputObject $Hardening -Name "enableRoleSeparation" -Default $false)) {
        Set-AdcsRegistryValue -Name "CA\RoleSeparationEnabled" -Value "1"
        Write-Log "Role separation enabled" -Tag "Info"
    }

    if ([bool](Get-ConfigValue -InputObject $Hardening -Name "auditSubcategory" -Default $true)) {
        Enable-AdcsAuditPolicy
    }

    # ESC8, and the only mitigation in this function that removes something rather than
    # writing a registry value. Off by default for that reason: a CA this design did not
    # build may have people genuinely enrolling through certsrv, and taking it away is
    # not a change a config file should make unasked.
    if ([bool](Get-ConfigValue -InputObject $Hardening -Name "removeWebEnrollment" -Default $false)) {
        $null = Remove-AdcsWebEnrollment
    }
}

# The presence question on its own, with no opinion attached, because two callers want
# it for opposite reasons - one to report a finding, one to decide whether there is
# anything to remove - and only one of them should be logging about it.
#
# The /CertSrv application, not the feature. That is what the role service puts into
# IIS and what a relay attack actually targets, so it is the more direct question - and
# it comes from a file read rather than a component store walk.
function Get-AdcsWebEnrollmentPresent {
    $configPath = Join-Path -Path $env:SystemRoot -ChildPath "system32\inetsrv\config\applicationHost.config"
    if (-not (Test-Path -LiteralPath $configPath)) { return $false }
    try {
        $text = Get-Content -LiteralPath $configPath -Raw -ErrorAction Stop
        return [regex]::IsMatch($text, 'path="/[Cc]ert[Ss]rv"')
    }
    catch {
        return $false
    }
}

# Two steps, in this order and not the other. Uninstall-AdcsWebEnrollment unconfigures
# the role service, which is what takes the /CertSrv application back out of IIS;
# Uninstall-WindowsFeature then removes the payload so nothing puts it back. Removing
# the feature first leaves the IIS application behind, pointed at a role service that
# is no longer there - which is a worse state than either end of the operation.
function Remove-AdcsWebEnrollment {
    if (-not (Get-AdcsWebEnrollmentPresent)) {
        Write-Log "Web Enrollment is not installed here - nothing to remove" -Tag "Debug"
        return $true
    }

    Write-Log "Removing AD CS Web Enrollment - its certsrv endpoint is the ESC8 relay target" -Tag "Run"

    if (Get-Command -Name "Uninstall-AdcsWebEnrollment" -ErrorAction SilentlyContinue) {
        try {
            $null = Uninstall-AdcsWebEnrollment -Force -ErrorAction Stop
            Write-Log "The Web Enrollment role service is unconfigured" -Tag "Ok"
        }
        catch {
            Write-Log "Uninstall-AdcsWebEnrollment failed: $($_.Exception.Message)" -Tag "Error"
            Write-Log "    the feature is left in place - run it by hand and re-run this script" -Tag "Error"
            return $false
        }
    }
    else {
        Write-Log "Uninstall-AdcsWebEnrollment is not available on this server - removing the feature alone" -Tag "Info"
    }

    # Removing the payload, and why failing at it is not failing.
    #
    # The two steps answer different questions. Uninstall-AdcsWebEnrollment above takes
    # the /CertSrv application out of IIS, and **that application is the ESC8 relay
    # target** - once it is gone the thing this switch exists to remove is removed.
    # Uninstall-WindowsFeature then takes the bits off the disk, which is tidiness.
    #
    # It also fails on servers where the first step did not, because Server Manager asks
    # WS-Management for the role service status even for a local uninstall: "The
    # WS-Management service cannot process the request. The service is configured to not
    # accept any remote shell requests." A server hardened against remote shells - which
    # is a good thing to be - cannot remove the feature this way. Reporting that as a
    # failed mitigation would be wrong, so the endpoint is asked directly and the answer
    # to *that* decides.
    $featureRemoved = $false
    try {
        $result = Uninstall-WindowsFeature -Name "ADCS-Web-Enrollment" -ErrorAction Stop
        if ([bool]$result.Success) {
            $featureRemoved = $true
            Write-Log "Windows feature 'ADCS-Web-Enrollment' removed" -Tag "Ok"
            if ([string]$result.RestartNeeded -eq "Yes") {
                Write-Log "    A restart finishes the removal - the endpoint is gone, this is the component store catching up" -Tag "Debug"
            }
        }
        else {
            Write-Log "The Windows feature 'ADCS-Web-Enrollment' did not uninstall" -Tag "Warn"
        }
    }
    catch {
        Write-Log "Uninstall-WindowsFeature ADCS-Web-Enrollment failed: $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Warn"
    }

    if (-not $featureRemoved) {
        Write-Log "    The role service is unconfigured either way, so /CertSrv is gone" -Tag "Debug"
        Write-Log "    Server Manager asks WS-Management for role service status even locally, so this fails where remote shells are refused" -Tag "Debug"
        Write-Log "    Remove the payload later with: Uninstall-WindowsFeature -Name ADCS-Web-Enrollment" -Tag "Info"
    }

    # Asked again rather than assumed: the point of the switch is that /CertSrv stops
    # answering, and both cmdlets above can report success while IIS keeps the
    # application - a hand-made one, or a copy in another site.
    if (Get-AdcsWebEnrollmentPresent) {
        Write-Log "IIS still serves /CertSrv after the removal - something created it outside the role service, and it accepts NTLM" -Tag "Error"
        return $false
    }
    Write-Log "IIS no longer serves /CertSrv - the ESC8 relay target is gone" -Tag "Ok"
    return $true
}

# ESC16. Suppressing the SID extension breaks the strong certificate mapping that
# domain controllers have enforced since the KB5014754 rollout completed.
function Test-AdcsSidExtension {
    $output = Invoke-AdcsUtility -FilePath "certutil.exe" -ArgumentList @("-getreg", "policy\DisableExtensionList") -IgnoreExitCode

    if ($output -match [regex]::Escape($script:adcsSidExtensionOid)) {
        Write-Log "The SID security extension ($($script:adcsSidExtensionOid)) is in DisableExtensionList" -Tag "Error"
        Write-Log "Certificates issued here cannot map strongly to an account, and domain controllers refuse them" -Tag "Error"
        Write-Log "    certutil -setreg policy\DisableExtensionList -$($script:adcsSidExtensionOid)" -Tag "Error"
        return $false
    }
    Write-Log "The SID security extension is not suppressed - certificates will map strongly" -Tag "Ok"
    return $true
}

# ESC8. The static file endpoint this script builds is not the same thing as the
# Web Enrollment role service, which is the NTLM relay target. This reports and does
# not block: a server that genuinely enrolls through certsrv is a deployment decision,
# and refusing to configure the CA leaves it with no CDP and no templates either -
# strictly worse than a configured CA with a known finding logged against it.
function Test-AdcsWebEnrollmentAbsent {
    if (Get-AdcsWebEnrollmentPresent) {
        Write-Log "IIS serves /CertSrv here - AD CS Web Enrollment, it accepts NTLM, and it is the ESC8 relay target" -Tag "Warn"
        Write-Log "    Remove it unless something enrolls through it, or put it behind HTTPS with Extended Protection and no NTLM" -Tag "Warn"
        Write-Log "    The Hardening card does it; by hand: Uninstall-AdcsWebEnrollment then Uninstall-WindowsFeature -Name ADCS-Web-Enrollment" -Tag "Warn"
        return $false
    }
    return $true
}

# 'Running' is not 'ready'. The service control manager reports certsvc started as soon
# as it has a process; the CA then loads its configuration, opens its database and only
# then registers the RPC interface everything else here talks to. Anything that calls
# the CA inside that window fails with 0x800706ba RPC_S_SERVER_UNAVAILABLE - 'The RPC
# server is unavailable', an error that reads like a broken machine rather than like a
# race, and one that only shows up on the faster half of the fleet.
#
# 'certutil -ping' is the CA's own liveness call. It is run raw rather than through
# Invoke-AdcsUtility because that logs every attempt, and a poll loop has no business
# writing thirty lines into the log.
function Wait-AdcsAuthorityReady {
    param([int]$TimeoutSeconds = 60)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $attempt = 0
    while ((Get-Date) -lt $deadline) {
        $attempt++
        $null = & "certutil.exe" "-ping" 2>&1
        if ($LASTEXITCODE -eq 0) {
            if ($attempt -gt 1) { Write-Log "The certification authority answered after $attempt attempt(s)" -Tag "Debug" }
            return $true
        }
        Start-Sleep -Seconds 2
    }

    Write-Log "certutil -ping unanswered after $TimeoutSeconds s - carrying on, the next call reports what is wrong" -Tag "Warn"
    return $false
}

function Restart-AdcsService {
    Write-Log "Restarting the certification authority service" -Tag "Run"
    try {
        Restart-Service -Name "certsvc" -Force -ErrorAction Stop
    }
    catch {
        throw "Could not restart certsvc: $($_.Exception.Message)"
    }
    $null = Wait-AdcsAuthorityReady
    Write-Log "certsvc restarted" -Tag "Ok"
}

function Publish-AdcsCrl {
    # Also here, not only after the restart: this runs on paths that did not start the
    # service, and the CA is equally unreachable for a moment after a failover or a
    # manual start somebody did while the run was in its prompts.
    $null = Wait-AdcsAuthorityReady
    $null = Invoke-AdcsUtility -FilePath "certutil.exe" -ArgumentList @("-CRL")
    Write-Log "Certificate revocation list published" -Tag "Ok"
}

# ---------------------------[ Root tier ]---------------------------
function Install-AdcsRootAuthority {
    param([Parameter(Mandatory)][object]$Root)

    New-AdcsPolicyFile -Tier $Root -TierName "root"

    $parameters = @{
        CAType              = "StandaloneRootCA"
        CACommonName        = [string](Get-ConfigValue -InputObject $Root -Name "caCommonName" -Default "")
        CryptoProviderName  = [string](Get-ConfigValue -InputObject $Root -Name "cryptoProvider" -Default "RSA#Microsoft Software Key Storage Provider")
        KeyLength           = [int](Get-ConfigValue -InputObject $Root -Name "keyLength" -Default 4096)
        HashAlgorithmName   = [string](Get-ConfigValue -InputObject $Root -Name "hashAlgorithm" -Default "SHA256")
        ValidityPeriod      = [string](Get-ConfigValue -InputObject $Root -Name "validityPeriod" -Default "Years")
        ValidityPeriodUnits = [int](Get-ConfigValue -InputObject $Root -Name "validityUnits" -Default 5)
        DatabaseDirectory   = [string](Get-ConfigValue -InputObject $Root -Name "databasePath" -Default "C:\Windows\system32\CertLog")
        LogDirectory        = [string](Get-ConfigValue -InputObject $Root -Name "logPath" -Default "C:\Windows\system32\CertLog")
        Force               = $true
        ErrorAction         = "Stop"
    }

    $dnSuffix = [string](Get-ConfigValue -InputObject $Root -Name "caDistinguishedNameSuffix" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($dnSuffix)) {
        $parameters["CADistinguishedNameSuffix"] = $dnSuffix
    }

    Write-Log "Installing the standalone root CA '$($parameters.CACommonName)'" -Tag "Run"
    $null = Install-AdcsCertificationAuthority @parameters
    Write-Log "Root CA installed" -Tag "Ok"
}

function Export-AdcsRootMaterial {
    param(
        [Parameter(Mandatory)][string]$TransferPath,
        [object]$Root
    )

    # A '+' file in the root's CertEnroll is a fossil, not a publication. Installing the
    # CA starts certsvc, which publishes its first CRL with the install defaults - delta
    # CRLs on, one day - before this script's configuration lands. That single delta is
    # born then; the configuration disables deltas, and nothing ever refreshes or removes
    # the file. Exporting it wholesale carried it across the air gap and onto the web
    # endpoint every ceremony, where it sat looking like a served delta that no base CRL
    # references (a base published with deltas off carries no Freshest CRL extension).
    $deltaOff = $true
    if ($null -ne $Root) {
        $crl = Get-ConfigValue -InputObject $Root -Name "crl"
        if ($null -ne $crl) { $deltaOff = ([int](Get-ConfigValue -InputObject $crl -Name "deltaPeriodUnits" -Default 0) -eq 0) }
    }

    $exported = 0
    foreach ($pattern in @("*.crt", "*.crl")) {
        $files = @(Get-ChildItem -Path (Join-Path -Path $script:adcsCertEnrollPath -ChildPath $pattern) -File -ErrorAction SilentlyContinue)
        foreach ($file in $files) {
            if ($deltaOff -and ($file.Name -like "*+.crl")) {
                Write-Log "Skipped '$($file.Name)' - the design publishes no delta CRL" -Tag "Info"
                # An earlier export may already have carried it into the transfer folder;
                # take that copy back out so the issuing CA stops serving it too.
                $stale = Join-Path -Path $TransferPath -ChildPath $file.Name
                if (Test-Path -LiteralPath $stale) {
                    Remove-Item -LiteralPath $stale -Force -ErrorAction SilentlyContinue
                    Write-Log "Removed the stale '$($file.Name)' from the transfer folder" -Tag "Info"
                }
                continue
            }
            Copy-Item -LiteralPath $file.FullName -Destination $TransferPath -Force
            Write-Log "Exported '$($file.Name)'" -Tag "Info"
            $exported++
        }
    }

    if ($exported -eq 0) {
        throw "Nothing was found in $($script:adcsCertEnrollPath) to export."
    }
    return $exported
}

# The request id out of `certreq -submit`, WITHOUT reading the label.
#
# certreq writes its labels in the server's display language. An English server says
#
#     RequestId: 5
#     RequestId: "5"
#     Certificate request is pending: Taken Under Submission (0)
#
# and a German one says
#
#     Anforderungs-ID: 5
#     Anforderungs-ID: "5"
#     Ausstehende Zertifikatanforderung: Bei Uebermittlung (0)
#
# Matching "RequestId:" therefore failed on a German root CA and took the whole PKI
# build down at the first submit - field-hit 2026-09-19, the first time this project
# was run on a non-English forest. Same class of bug as matching "Authenticated Users"
# by name instead of by SID, and the same rule applies: read the SHAPE, not the word.
#
# The shape is stable across locales - a label, a colon, and the id alone on the line,
# printed twice, bare and then quoted. The pending line that follows never matches,
# because its value ends in "(0)" rather than in digits. The English label is still
# tried first so an English server takes a deterministic path and any surprise here
# shows up as the fallback being used rather than as a different answer.
# The NextUpdate out of `certutil -dump <crl>`, also without reading the label - a
# German server prints "Naechste Aktualisierung" where an English one prints
# "NextUpdate". The shape here is weaker than the request id's, because the value is a
# date rather than an integer, so this does both:
#
#   1. the English label when it is there, which is exact;
#   2. otherwise every "label: value" line parsed as a date IN THE SERVER'S OWN
#      CULTURE, taking the LATEST. A CRL dump carries ThisUpdate and NextUpdate and
#      NextUpdate is by definition the later of the two, so the maximum is the one
#      wanted whatever the two are called.
#
# TryParse with the current culture is what makes (2) work at all: "19.09.2026 20:04"
# is not a date to an invariant parser and is one to a German server.
function Get-AdcsCrlNextUpdateFromDump {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Dump)

    # Three cultures, because the two that matter can disagree: certutil prints in the
    # DISPLAY language (CurrentUICulture) while a date parses under the REGIONAL format
    # (CurrentCulture), and a German-language server set to English formats - or the
    # reverse - is an ordinary thing to find. Invariant last, for an ISO-ish value.
    $cultures = @(
        [System.Globalization.CultureInfo]::CurrentCulture,
        [System.Globalization.CultureInfo]::CurrentUICulture,
        [System.Globalization.CultureInfo]::InvariantCulture
    )
    $tryParse = {
        param([string]$Text)
        foreach ($culture in $cultures) {
            $value = [datetime]::MinValue
            if ([datetime]::TryParse($Text, $culture, [System.Globalization.DateTimeStyles]::None, [ref]$value)) {
                return $value
            }
        }
        return $null
    }

    $anchored = [regex]::Match($Dump, "NextUpdate:\s*(.+)")
    if ($anchored.Success) {
        $exact = & $tryParse $anchored.Groups[1].Value.Trim()
        if ($null -ne $exact) { return $exact }
    }

    $latest = $null
    foreach ($line in ($Dump -split "`r?`n")) {
        $pair = [regex]::Match($line, '^[^\r\n:]*:\s*(?<value>\S.*)$')
        if (-not $pair.Success) { continue }
        $parsed = & $tryParse $pair.Groups["value"].Value.Trim()
        if ($null -eq $parsed) { continue }
        if (($null -eq $latest) -or ($parsed -gt $latest)) { $latest = $parsed }
    }
    if ($null -ne $latest) {
        Write-Log "certutil did not print an English NextUpdate - the CRL's latest date was used instead" -Tag "Debug"
    }
    return $latest
}

function Get-AdcsSubmittedRequestId {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$SubmitOutput)

    $anchored = [regex]::Match($SubmitOutput, "RequestId:\s*`"?(\d+)`"?")
    if ($anchored.Success) { return $anchored.Groups[1].Value }

    $shaped = [regex]::Match($SubmitOutput, '(?m)^[^\r\n:]*:\s*"?(\d+)"?\s*$')
    if ($shaped.Success) {
        Write-Log "certreq did not print an English label - the request id was read by shape" -Tag "Debug"
        return $shaped.Groups[1].Value
    }
    return ""
}

# A standalone CA parks incoming requests as pending. Issuing one from the console
# is the step every guide has you click through; this is the same three calls.
function New-AdcsIssuedCertificate {
    param(
        [Parameter(Mandatory)][string]$RequestPath,
        [Parameter(Mandatory)][string]$TransferPath
    )

    $configString = Get-AdcsConfigString
    $submitOutput = Invoke-AdcsUtility -FilePath "certreq.exe" -ArgumentList @("-config", $configString, "-submit", $RequestPath) -IgnoreExitCode

    $requestId = Get-AdcsSubmittedRequestId -SubmitOutput $submitOutput
    if ([string]::IsNullOrWhiteSpace($requestId)) {
        throw "Could not read a request id out of the certreq output: $submitOutput"
    }
    Write-Log "The request was taken as RequestId $requestId" -Tag "Info"

    $null = Invoke-AdcsUtility -FilePath "certutil.exe" -ArgumentList @("-resubmit", $requestId) -IgnoreExitCode

    $certificateName = [System.IO.Path]::GetFileNameWithoutExtension($RequestPath) + ".cer"
    $certificatePath = Join-Path -Path $TransferPath -ChildPath $certificateName
    $null = Invoke-AdcsUtility -FilePath "certreq.exe" -ArgumentList @("-config", $configString, "-retrieve", $requestId, $certificatePath)

    if (-not (Test-Path -LiteralPath $certificatePath)) {
        throw "certreq -retrieve reported success but '$certificatePath' is not there."
    }
    Write-Log "Signed certificate written to '$certificateName'" -Tag "Ok"
    return $certificatePath
}

# Deliberately not automated: every line here writes the most valuable private key in
# the forest, or the state needed to rebuild around it, to somewhere of the operator's
# choosing. Where those files land and what protects them is the whole point of an
# offline root, so the script prints the ceremony rather than performing it.
function Write-AdcsRootBackupChecklist {
    Write-Log "Back this server up before it is powered off - all four parts, to removable media:" -Tag "Info"
    Write-Log "    certutil -backupkey  <drive>:\rootca      the CA certificate and its private key" -Tag "Info"
    Write-Log "    certutil -backupdb   <drive>:\rootca      the issued-certificate and request database" -Tag "Info"
    Write-Log "    reg export HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration <drive>:\rootca\certsvc.reg" -Tag "Info"
    Write-Log "    copy CAPolicy.inf from $env:SystemRoot and the published CRL from the transfer folder" -Tag "Info"
    Write-Log "    The key backup is password protected - store that password apart from the media" -Tag "Debug"
    Write-Log "    The media belongs in a safe. A key backup beside the server it came from protects nothing" -Tag "Debug"
}

function Invoke-AdcsRootTier {
    param(
        [Parameter(Mandatory)][object]$CertificateServices,
        [Parameter(Mandatory)][string]$TransferPath
    )

    $root = Get-ConfigValue -InputObject $CertificateServices -Name "root"

    $rootMode = Get-AdcsMode -CertificateServices $CertificateServices
    if (-not (Test-AdcsAuthorityInstalled)) {
        if (@("adopt", "renew") -contains $rootMode) {
            return (New-RoleResult -Status "ManualStepRequired" -Message ("The design is in {0} mode, but no certification authority is installed on this server - check the computer name, or switch the design to build mode if a new root is actually wanted." -f $rootMode))
        }
        Install-AdcsRootAuthority -Root $root
        Set-AdcsAuthorityConfiguration -CertificateServices $CertificateServices -TierName "root"
        Restart-AdcsService
        Publish-AdcsCrl
        Write-Log "There is no recovering this hierarchy without a backup of the key just created" -Tag "Info"
    }
    else {
        Write-Log "The root CA is already installed" -Tag "Info"

        # Adopt applies this design to the root as well, and the reason is the extension
        # that ends up in the *subordinate's* certificate.
        #
        # A CA stamps CDP and AIA from **its own** configuration onto everything it
        # signs. The issuing CA's certificate therefore carries what the root had
        # configured on the day it signed - not what the issuing CA has configured now,
        # and not what this design says. So an adoption that configured only the issuing
        # CA would set the design's publication URLs everywhere except the one
        # certificate every client walks the chain through, and the re-key ceremony
        # would faithfully reproduce the old URL on the new certificate.
        #
        # Renew mode deliberately does none of this: that run is the ceremony and
        # nothing else, and the root's settings are not its business.
        if ($rootMode -eq "adopt") {
            Write-Log "Adopting: applying this design's configuration to the existing root" -Tag "Run"
            Set-AdcsAuthorityConfiguration -CertificateServices $CertificateServices -TierName "root"
            Restart-AdcsService
            # The CRL is regenerated so it carries the periods just set, rather than
            # waiting out whatever the old ones were.
            Publish-AdcsCrl
            Write-Log "    What the root signs from now on carries these URLs - a subordinate signed earlier keeps the ones it was born with" -Tag "Debug"
        }
    }

    $requests = @(Get-ChildItem -Path (Join-Path -Path $TransferPath -ChildPath "*.req") -File -ErrorAction SilentlyContinue)

    if ($requests.Count -eq 0) {
        # No request waiting: refresh the CRL instead. This is the yearly ceremony -
        # power the root on, run this, carry the folder back. It is also what a folder
        # that lost the subordinate's request on the way here looks like, and the two
        # are indistinguishable from this side, so say which one this run assumed.
        Write-Log "No .req in '$TransferPath' - nothing was signed. Treating this as the CRL ceremony." -Tag "Warn"
        Write-Log "No subordinate request arrived - copy the .req in and run again" -Tag "Warn"
        Publish-AdcsCrl
        $null = Export-AdcsRootMaterial -TransferPath $TransferPath -Root $root
        New-AdcsTransferManifest -Path $TransferPath
        Write-Log (Get-AdcsCrlExpiryMessage) -Tag "Info"
        Write-AdcsRootBackupChecklist
        return (New-RoleResult -Status "Completed" -Message "No request was waiting - the CRL was refreshed and exported. Carry '$TransferPath' to the issuing CA.")
    }

    if ($requests.Count -gt 1) {
        return (New-RoleResult -Status "Failed" -Message "More than one .req is in '$TransferPath' - leave only the request you want signed.")
    }

    $null = New-AdcsIssuedCertificate -RequestPath $requests[0].FullName -TransferPath $TransferPath
    $null = Export-AdcsRootMaterial -TransferPath $TransferPath -Root $root
    Remove-Item -LiteralPath $requests[0].FullName -Force -ErrorAction SilentlyContinue
    New-AdcsTransferManifest -Path $TransferPath

    Write-Log (Get-AdcsCrlExpiryMessage) -Tag "Info"
    Write-AdcsRootBackupChecklist
    Write-Log "Power this server off again once the folder has been copied" -Tag "Info"
    return (New-RoleResult -Status "Completed" -Message "The subordinate request is signed. Carry '$TransferPath' back to the issuing CA and run the same command there.")
}

# ---------------------------[ Issuing tier ]---------------------------
function Install-AdcsIssuingAuthority {
    param(
        [Parameter(Mandatory)][object]$Issuing,
        [Parameter(Mandatory)][string]$TransferPath
    )

    New-AdcsPolicyFile -Tier $Issuing -TierName "issuing"

    $commonName = [string](Get-ConfigValue -InputObject $Issuing -Name "caCommonName" -Default "")
    $requestPath = Join-Path -Path $TransferPath -ChildPath ("{0}_{1}.req" -f $env:COMPUTERNAME, ($commonName -replace '[^A-Za-z0-9-]', '-'))

    $parameters = @{
        CAType               = "EnterpriseSubordinateCA"
        CACommonName         = $commonName
        CryptoProviderName   = [string](Get-ConfigValue -InputObject $Issuing -Name "cryptoProvider" -Default "RSA#Microsoft Software Key Storage Provider")
        KeyLength            = [int](Get-ConfigValue -InputObject $Issuing -Name "keyLength" -Default 4096)
        HashAlgorithmName    = [string](Get-ConfigValue -InputObject $Issuing -Name "hashAlgorithm" -Default "SHA256")
        DatabaseDirectory    = [string](Get-ConfigValue -InputObject $Issuing -Name "databasePath" -Default "C:\Windows\system32\CertLog")
        LogDirectory         = [string](Get-ConfigValue -InputObject $Issuing -Name "logPath" -Default "C:\Windows\system32\CertLog")
        OutputCertRequestFile = $requestPath
        Force                = $true
        ErrorAction          = "Continue"
    }

    $dnSuffix = [string](Get-ConfigValue -InputObject $Issuing -Name "caDistinguishedNameSuffix" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($dnSuffix)) {
        $parameters["CADistinguishedNameSuffix"] = $dnSuffix
    }

    Write-Log "Installing the enterprise subordinate CA '$commonName'" -Tag "Run"

    # A subordinate installed with no parent online always reports back as incomplete -
    # that is the point, the parent is an air gap away. The request file on disk is the
    # real success signal, so the reported error is logged rather than thrown on.
    $setupFailure = ""
    try {
        $setupResult = Install-AdcsCertificationAuthority @parameters
        $errorString = [string](Get-ConfigValue -InputObject $setupResult -Name "ErrorString" -Default "")
        if (-not [string]::IsNullOrWhiteSpace($errorString)) {
            Write-Log "Setup reported: $errorString" -Tag "Info"
            $setupFailure = $errorString
        }
    }
    catch {
        Write-Log "Setup reported: $($_.Exception.Message)" -Tag "Info"
        $setupFailure = $_.Exception.Message
    }

    if (-not (Test-Path -LiteralPath $requestPath)) {
        if ([string]::IsNullOrWhiteSpace($setupFailure)) {
            throw "The installation did not leave a request file at '$requestPath'."
        }
        throw "The subordinate CA could not be installed: $setupFailure"
    }
    Write-Log "Certificate request written to '$([System.IO.Path]::GetFileName($requestPath))'" -Tag "Ok"
    return $requestPath
}

function Publish-AdcsRootToDirectory {
    param(
        [Parameter(Mandatory)][object]$CertificateServices,
        [Parameter(Mandatory)][string]$TransferPath
    )

    $rootComputer = [string](Get-ConfigValue -InputObject (Get-ConfigValue -InputObject $CertificateServices -Name "root") -Name "computerName" -Default "")

    $certificates = @(Get-ChildItem -Path (Join-Path -Path $TransferPath -ChildPath "*.crt") -File -ErrorAction SilentlyContinue)
    foreach ($certificate in $certificates) {
        $null = Invoke-AdcsUtility -FilePath "certutil.exe" -ArgumentList @("-dspublish", "-f", $certificate.FullName, "RootCA")
        $null = Invoke-AdcsUtility -FilePath "certutil.exe" -ArgumentList @("-addstore", "-f", "Root", $certificate.FullName)
        Write-Log "Published '$($certificate.Name)' to the forest and the local root store" -Tag "Ok"
    }

    $revocationLists = @(Get-ChildItem -Path (Join-Path -Path $TransferPath -ChildPath "*.crl") -File -ErrorAction SilentlyContinue)
    foreach ($revocationList in $revocationLists) {
        $null = Invoke-AdcsUtility -FilePath "certutil.exe" -ArgumentList @("-dspublish", "-f", $revocationList.FullName, $rootComputer)
        Write-Log "Published '$($revocationList.Name)' to the forest" -Tag "Ok"
    }

    if ($certificates.Count -eq 0) {
        Write-Log "No root certificate was in the transfer folder - the chain may not validate" -Tag "Info"
    }
}

# The root material that came back across the air gap, put where a chain check can reach
# it - *before* anything installs a certificate the root signed.
#
# certutil -installcert verifies the chain of what it is about to install, and a
# revocation check that cannot reach a current root CRL does not fail quietly. It puts up
# a modal dialog - "Cannot verify certificate chain ... The revocation function was unable
# to check revocation because the revocation server was offline. 0x80092013" - and waits
# for somebody to click it. At a console that is an OK; in the resume leg of an unattended
# run it is a scheduled task that never returns.
#
# What makes it certain rather than unlucky: at that moment the fresh root CRL is sitting
# in the transfer folder, having just arrived, while the copy behind the CDP is whatever
# the last ceremony left there - on an adopted hierarchy, a year old and long past its
# NextUpdate. The first-build branch has always published the root before installing the
# chain for exactly this reason. The renewal and re-key paths did it afterwards, which is
# one certificate too late.
function Publish-AdcsIncomingRootMaterial {
    param(
        [Parameter(Mandatory)][object]$CertificateServices,
        [Parameter(Mandatory)][string]$TransferPath
    )

    $incoming = @(Get-ChildItem -Path (Join-Path -Path $TransferPath -ChildPath "*.crt") -File -ErrorAction SilentlyContinue) +
                @(Get-ChildItem -Path (Join-Path -Path $TransferPath -ChildPath "*.crl") -File -ErrorAction SilentlyContinue)
    if ($incoming.Count -eq 0) { return }

    # Verified here rather than taken on trust: this publishes files that crossed the air
    # gap into the forest and into the local root store. A folder that does not match its
    # manifest is left exactly as it is, and the caller's own check is what fails the run
    # over it - saying so twice is better than publishing first and refusing second.
    if (-not (Test-AdcsTransferManifest -Path $TransferPath)) {
        Write-Log "Transfer folder does not match its manifest - the incoming root material was not published" -Tag "Warn"
        return
    }

    Write-Log "Publishing the root material that came back, so the chain can be checked first" -Tag "Run"
    Publish-AdcsRootToDirectory -CertificateServices $CertificateServices -TransferPath $TransferPath

    $webPath = Confirm-AdcsWebPath -CertificateServices $CertificateServices
    if (-not [string]::IsNullOrWhiteSpace($webPath)) {
        Copy-AdcsWebContent -CertificateServices $CertificateServices -TransferPath $TransferPath -PhysicalPath $webPath
    }
}

# The site's own physical root, which nothing in this design serves from - the CRLs
# live in a virtual directory with a path of its own - and which IIS nonetheless has to
# be able to read, because configuration for every path inside the site is resolved
# from the site root down. A missing one answers *every* request to the virtual
# directory with 500.19, and fails appcmd with 'Cannot read configuration file' naming
# a web.config in the folder that is not there.
#
# It goes missing more easily than it sounds: anything that cleans %SystemDrive%\inetpub
# takes it, and nothing recreates it, because IIS only writes it at role install.
# Where a site serves its root from. appcmd reports it exactly as
# applicationHost.config stores it, which is normally %SystemDrive%\inetpub\wwwroot
# rather than an expanded path - so it is expanded here, or every comparison against a
# real folder fails for a reason nobody can see.
function Get-AdcsSiteRootPath {
    param(
        [Parameter(Mandatory)][string]$AppCmd,
        [Parameter(Mandatory)][string]$SiteName
    )

    $output = Invoke-AdcsUtility -FilePath $AppCmd -ArgumentList @(
        "list", "vdir", "`"$SiteName/`"", "/text:physicalPath") -IgnoreExitCode

    foreach ($line in (([string]$output) -split "`r?`n")) {
        $candidate = $line.Trim()
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            return [System.Environment]::ExpandEnvironmentVariables($candidate)
        }
    }
    return ""
}

function Confirm-AdcsSiteRoot {
    param(
        [Parameter(Mandatory)][string]$AppCmd,
        [Parameter(Mandatory)][string]$SiteName
    )

    $rootPath = Get-AdcsSiteRootPath -AppCmd $AppCmd -SiteName $SiteName

    if ([string]::IsNullOrWhiteSpace($rootPath)) {
        Write-Log "Could not read the physical path of '$SiteName' - carrying on" -Tag "Debug"
        return $false
    }
    if (Test-Path -LiteralPath $rootPath -PathType Container) {
        Write-Log "The '$SiteName' physical root is '$rootPath'" -Tag "Debug"
        return $false
    }

    try {
        $null = New-Item -ItemType Directory -Path $rootPath -Force -ErrorAction Stop
    }
    catch {
        Write-Log "'$SiteName' physical root '$rootPath' is missing and could not be created: $($_.Exception.Message)" -Tag "Warn"
        Write-Log "    Until it exists IIS answers every request under that site - the CRL folder included - with 500.19" -Tag "Warn"
        return $false
    }

    Write-Log "Created the missing physical root of '$SiteName' at '$rootPath'" -Tag "Ok"
    Write-Log "    IIS resolves configuration from the site root down, so nothing under this site can be served without it" -Tag "Debug"
    return $true
}

# A stopped site serves nothing, and nothing about a CRL that will not download says
# which of the two dozen possible reasons it is. Starting it is safe: the site either
# was meant to be running - it is the one this design publishes through - or it stops
# again the moment somebody stops it. A site that refuses to start is reported and the
# run carries on: the CA is already built and publishing by this point, and the reason
# is usually a port conflict this script has no business resolving.
function Confirm-AdcsSiteStarted {
    param(
        [Parameter(Mandatory)][string]$AppCmd,
        [Parameter(Mandatory)][string]$SiteName
    )

    $output = Invoke-AdcsUtility -FilePath $AppCmd -ArgumentList @(
        "list", "site", "`"$SiteName`"", "/text:state") -IgnoreExitCode

    $state = ""
    foreach ($line in (([string]$output) -split "`r?`n")) {
        $candidate = $line.Trim()
        if (-not [string]::IsNullOrWhiteSpace($candidate)) { $state = $candidate; break }
    }

    if ([string]::IsNullOrWhiteSpace($state)) {
        Write-Log "Could not read the state of '$SiteName'" -Tag "Debug"
        return $false
    }
    if ($state.Equals("Started", [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Log "'$SiteName' is started" -Tag "Debug"
        return $false
    }

    Write-Log "'$SiteName' is $state - nothing it publishes can be fetched while it is" -Tag "Warn"
    try {
        $null = Invoke-AdcsUtility -FilePath $AppCmd -ArgumentList @("start", "site", "`"$SiteName`"")
    }
    catch {
        Write-Log "Could not start '$SiteName': $($_.Exception.Message)" -Tag "Warn"
        Write-Log "    A site that will not start is usually another process on its port: netstat -ano | findstr :80" -Tag "Warn"
        return $false
    }
    Write-Log "Started '$SiteName'" -Tag "Ok"
    return $true
}

# Returns an empty string when the setting went in, the error text when it did not.
# A boolean would throw away the message, and the message is what names the file in
# the configuration chain that could not be parsed.
function Set-AdcsDoubleEscaping {
    param(
        [Parameter(Mandatory)][string]$AppCmd,
        [Parameter(Mandatory)][string]$ConfigPath
    )

    try {
        $null = Invoke-AdcsUtility -FilePath $AppCmd -ArgumentList @(
            "set", "config", "`"$ConfigPath`"", "/section:system.webServer/security/requestFiltering",
            "-allowDoubleEscaping:True")
        Write-Log "Double escaping enabled so delta CRL names resolve" -Tag "Ok"
        return ""
    }
    catch {
        return [string]$_.Exception.Message
    }
}

# IIS reads every web.config from the site root down, so one that cannot be parsed
# fails everything beneath it - this virtual directory, and every request to it with a
# 500.19 that names a file nobody was editing. The default site root is exactly where
# an unreadable one is most likely: it is created by whatever was installed before
# this, and nothing ever reads it back.
#
# This is the one file outside its own folders that the script will touch, and only in
# the case where it is already broken: an empty or malformed web.config is not
# somebody's configuration, it is a file that stops IIS serving the folder it sits in.
# It is copied aside first, under a name that says what it was, and replaced with the
# empty-but-valid document IIS would have accepted all along. A file that *parses* is
# left alone whatever it contains - then the failure is something else and the run says
# so rather than helpfully deleting a working configuration.
# The document IIS ships when it writes one of these itself. No BOM: IIS accepts one,
# but a stray BOM mid-file is one of the ways these break, and without it the file
# diffs cleanly against a stock one.
function Write-AdcsEmptyConfiguration {
    param([Parameter(Mandatory)][string]$Path)

    $lines = @(
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<configuration>',
        '</configuration>'
    )
    [System.IO.File]::WriteAllText($Path, ($lines -join [Environment]::NewLine), (New-Object System.Text.UTF8Encoding($false)))
}

function Repair-AdcsChainedConfiguration {
    param([Parameter(Mandatory)][string]$Message)

    # appcmd names the file it choked on. '\\?\' is the long-path prefix it prints.
    # The label is localised - "Dateiname:" on a German server - so the anchor is the
    # drive-letter path itself, which is not. Same rule as the request id above.
    $match = [regex]::Match($Message, "(?:Filename|Dateiname)?:?\s*(?:\\\\\?\\)?(?<path>[A-Za-z]:\\[^\r\n]+)")
    if (-not $match.Success) { return $false }

    $configPath = $match.Groups["path"].Value.Trim()

    # A file that is not there at all, and IIS still refusing to read it. That is not a
    # broken document - it is the *folder* underneath: this path is the site's physical
    # root, and when that directory is missing IIS cannot resolve configuration for any
    # path inside the site, this virtual directory included. It is the same failure a
    # browser gets as 500.19 with 0x80070003, and it names the web.config it expected to
    # find rather than the folder that is not there, which is why it reads as a file
    # problem. Both halves are stock IIS artefacts, so both are simply put back.
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        $folder = Split-Path -Path $configPath -Parent
        $repaired = $false

        if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
            try {
                $null = New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop
            }
            catch {
                Write-Log "IIS needs '$folder' and it does not exist: $($_.Exception.Message)" -Tag "Warn"
                return $false
            }
            Write-Log "Created '$folder'" -Tag "Ok"
            $repaired = $true
        }

        # Only after the folder is there. An absent web.config is normally fine, but a
        # stock empty one costs nothing and takes the file IIS named out of the picture.
        try {
            Write-AdcsEmptyConfiguration -Path $configPath
            Write-Log "Wrote a stock empty '$configPath'" -Tag "Ok"
            $repaired = $true
        }
        catch {
            Write-Log "Could not create '$configPath': $($_.Exception.Message)" -Tag "Warn"
        }

        if (-not $repaired) {
            Write-Log "IIS named '$configPath', which does not exist and could not be created - the failure is something else" -Tag "Warn"
        }
        return $repaired
    }

    try {
        $document = New-Object System.Xml.XmlDocument
        $document.Load($configPath)
        Write-Log "'$configPath' parses as XML, so it is not what IIS is refusing - leaving it alone" -Tag "Warn"
        return $false
    }
    catch {
        Write-Log "'$configPath' is not readable as XML: $($_.Exception.Message)" -Tag "Warn"
    }

    $backupPath = "$configPath.broken"
    $index = 0
    while (Test-Path -LiteralPath $backupPath) {
        $index++
        $backupPath = "$configPath.broken$index"
    }

    try {
        Copy-Item -LiteralPath $configPath -Destination $backupPath -Force -ErrorAction Stop
        Write-AdcsEmptyConfiguration -Path $configPath
    }
    catch {
        Write-Log "Could not replace '$configPath': $($_.Exception.Message)" -Tag "Warn"
        return $false
    }

    Write-Log "Kept the old one as '$backupPath' and wrote an empty valid document in its place" -Tag "Ok"
    Write-Log "    Whatever that file configured is gone with it - it was unparsable, so IIS was not applying it either" -Tag "Debug"
    return $true
}

# Renamed on the way in. The root's CRL and certificate arrive named after the root -
# spaces, machine name prefix and all - while the AIA and CDP the root stamped into the
# issuing CA's certificate name the simplified form. Copying them across unchanged is a
# chain that cannot be built from the URLs inside it.
function Copy-AdcsWebContent {
    param(
        [Parameter(Mandatory)][object]$CertificateServices,
        [Parameter(Mandatory)][string]$TransferPath,
        [Parameter(Mandatory)][string]$PhysicalPath
    )

    $commonNames = @(
        [string](Get-ConfigText -InputObject (Get-ConfigValue -InputObject $CertificateServices -Name "root") -Name "caCommonName" -Default ""),
        [string](Get-ConfigText -InputObject (Get-ConfigValue -InputObject $CertificateServices -Name "issuing") -Name "caCommonName" -Default "")
    )

    $copied = 0
    foreach ($pattern in @("*.crt", "*.crl")) {
        foreach ($source in @($TransferPath, $script:adcsCertEnrollPath)) {
            $files = @(Get-ChildItem -Path (Join-Path -Path $source -ChildPath $pattern) -File -ErrorAction SilentlyContinue)
            foreach ($file in $files) {
                $target = Join-Path -Path $PhysicalPath -ChildPath (ConvertTo-AdcsWebFileName -FileName $file.Name -CommonName $commonNames)
                Copy-Item -LiteralPath $file.FullName -Destination $target -Force
                $copied++
            }
        }
    }
    Write-Log "Copied $copied certificate and CRL file(s) into '$PhysicalPath'" -Tag "Ok"
}

function Set-AdcsWebPublishing {
    param(
        [Parameter(Mandatory)][object]$CertificateServices,
        [Parameter(Mandatory)][string]$TransferPath
    )

    $script:adcsWebFailure = ""

    $issuing = Get-ConfigValue -InputObject $CertificateServices -Name "issuing"
    $web     = Get-ConfigValue -InputObject $issuing -Name "webPublishing"

    if (-not [bool](Get-ConfigValue -InputObject $web -Name "enabled" -Default $false)) {
        Write-Log "Web publishing is switched off - CDP and AIA rely on LDAP only" -Tag "Info"
        return
    }

    $appCmd = Join-Path -Path $env:SystemRoot -ChildPath "system32\inetsrv\appcmd.exe"
    if (-not (Test-Path -LiteralPath $appCmd)) {
        Write-Log "appcmd.exe was not found - IIS is not installed on this server" -Tag "Error"
        Write-Log "    Install-WindowsFeature -Name Web-Server -IncludeManagementTools" -Tag "Error"
        $script:adcsWebFailure = "IIS is not installed, so the http:// CDP and AIA in every certificate this CA issues resolve to nothing"
        return
    }

    $shared        = Get-ConfigValue -InputObject $CertificateServices -Name "shared"
    $pkiBaseUrl    = ([string](Get-ConfigValue -InputObject $shared -Name "pkiBaseUrl" -Default "")).TrimEnd("/")
    $physicalPath  = [string](Get-ConfigValue -InputObject $web -Name "physicalPath" -Default "C:\inetpub\pki")
    $siteName      = [string](Get-ConfigValue -InputObject $web -Name "siteName" -Default "Default Web Site")

    # The path in the URL decides the layout, and it is read off the URL rather than
    # guessed from its last segment - which, for a URL with no path at all, is the host
    # name. http://pki.example/x.crl means the files are served at the site root and
    # there is no virtual directory to create; http://pki.example/pki/x.crl means one
    # called 'pki'. Either way the name in the certificate and the thing IIS serves come
    # from the same string, so they cannot disagree.
    $alias = ""
    if (-not [string]::IsNullOrWhiteSpace($pkiBaseUrl)) {
        try { $alias = ([uri]$pkiBaseUrl).AbsolutePath.Trim("/") }
        catch { $alias = "" }
    }

    if (-not (Test-Path -LiteralPath $physicalPath)) {
        $null = New-Item -ItemType Directory -Path $physicalPath -Force
        Write-Log "Created '$physicalPath'" -Tag "Info"
    }

    # No URL, nothing to serve. Worth an early exit of its own rather than falling into
    # the layout below: an empty publication URL produces an empty path, an empty path
    # means "the site root", and that would repoint the whole site for a design that
    # does not publish over HTTP at all.
    if ([string]::IsNullOrWhiteSpace($pkiBaseUrl)) {
        Write-Log "No shared.pkiBaseUrl - no HTTP endpoint to build" -Tag "Info"
        Copy-AdcsWebContent -CertificateServices $CertificateServices -TransferPath $TransferPath -PhysicalPath $physicalPath
        return
    }

    # What the IIS configuration calls the thing being configured: the site itself when
    # the CRLs sit at its root, the virtual directory otherwise. Decided before the site
    # root is checked, not after - the other order creates the root the site *had*, then
    # repoints the site away from the folder it just made.
    $configPath = "$siteName/$alias"

    if ([string]::IsNullOrWhiteSpace($alias)) {
        # No path in the URL, so the site's own root has to be the folder the CA
        # publishes into. There is no virtual directory at '/' - that *is* the site.
        $configPath = "$siteName/"
        $currentRoot = Get-AdcsSiteRootPath -AppCmd $appCmd -SiteName $siteName
        if ($currentRoot.Equals($physicalPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Log "'$siteName' already serves '$physicalPath' at its root" -Tag "Info"
        }
        else {
            # Worth saying out loud: this repoints the site, and anything else that was
            # being served from its old root stops being served.
            Write-Log "Pointing '$siteName' at '$physicalPath'" -Tag "Info"
            if (-not [string]::IsNullOrWhiteSpace($currentRoot)) {
                Write-Log "    Its root was '$currentRoot' - anything served from there is no longer reachable through this site" -Tag "Debug"
            }
            $null = Invoke-AdcsUtility -FilePath $appCmd -ArgumentList @(
                "set", "vdir", "`"$siteName/`"", "/physicalPath:`"$physicalPath`"")
        }
    }
    else {
        $existing = Invoke-AdcsUtility -FilePath $appCmd -ArgumentList @("list", "vdir", "/name:`"$siteName/$alias`"") -IgnoreExitCode
        if ($existing -notmatch [regex]::Escape($alias)) {
            $null = Invoke-AdcsUtility -FilePath $appCmd -ArgumentList @(
                "add", "vdir", "/app.name:`"$siteName/`"", "/path:/$alias", "/physicalPath:`"$physicalPath`"")
            Write-Log "Created the '/$alias' virtual directory" -Tag "Ok"
        }
        else {
            Write-Log "The '/$alias' virtual directory already exists" -Tag "Info"
        }
    }

    $null = Confirm-AdcsSiteRoot -AppCmd $appCmd -SiteName $siteName
    $null = Confirm-AdcsSiteStarted -AppCmd $appCmd -SiteName $siteName

    # Delta CRL file names contain a '+'. Without double escaping IIS answers 404 to
    # every delta CRL request, which is a genuinely miserable thing to debug.
    #
    # Scoped to whatever serves the CRLs, which is what $configPath holds: the virtual
    # directory when there is one, the site when the files sit at its root. appcmd
    # writes the setting into a web.config in the folder behind that node - and in both
    # layouts that folder is this design's own, which is the reason the site-level case
    # is acceptable here and was not before.
    #
    # Not a fatal step either: the CA is built and publishing by the time it runs, so an
    # IIS that will not take the setting is a delta CRL that 404s, not a reason to
    # abandon the run before the templates are written.
    $escapingError = Set-AdcsDoubleEscaping -AppCmd $appCmd -ConfigPath $configPath
    if (-not [string]::IsNullOrWhiteSpace($escapingError)) {
        # One retry, and only after something was actually repaired. A broken web.config
        # in the chain is not this script's file, but it fails every request under the
        # site as well as this call, so leaving it is not a neutral act either.
        if (Repair-AdcsChainedConfiguration -Message $escapingError) {
            $escapingError = Set-AdcsDoubleEscaping -AppCmd $appCmd -ConfigPath $configPath
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($escapingError)) {
        Write-Log "Could not enable double escaping on '$configPath': $escapingError" -Tag "Warn"
        Write-Log "    Delta CRL requests 404 until this is set - their file names contain a '+'. By hand:" -Tag "Warn"
        Write-Log "    $appCmd set config `"$configPath`" /section:system.webServer/security/requestFiltering -allowDoubleEscaping:True" -Tag "Warn"
    }

    $null = Invoke-AdcsUtility -FilePath $appCmd -ArgumentList @(
        "set", "config", "`"$configPath`"", "/section:system.webServer/directoryBrowse",
        "/enabled:true") -IgnoreExitCode

    Copy-AdcsWebContent -CertificateServices $CertificateServices -TransferPath $TransferPath -PhysicalPath $physicalPath

    Test-AdcsPublicationEndpoint -CertificateServices $CertificateServices -PhysicalPath $physicalPath
}

# Everything above this point is inference: the role service is installed, the virtual
# directory exists, the setting went in. None of it is the question. The question is
# whether the URL frozen into every certificate this CA issues returns a CRL, and the
# only honest way to answer it is to ask for one.
#
# So the run fetches what it just published, over HTTP, from the machine that publishes
# it. A 404 here is the failure that would otherwise surface months later as a client
# that cannot do revocation checking, and IIS returns detailed errors to a local
# request - which is where the sub-status comes from, and the sub-status is the whole
# diagnosis: .3 is the static file handler, .17 a handler precondition, .11 double
# escaping refusing the '+' in a delta CRL name.
#
# Never fatal. The CA is built and publishing by now, nothing has been issued from it,
# and a missing role service is a five second fix once somebody knows which one.
function Get-AdcsUnservedCrl {
    param(
        [Parameter(Mandatory)][object[]]$File,
        [Parameter(Mandatory)][string]$BaseUrl
    )

    $failed = @()
    foreach ($item in $File) {
        $url = "$BaseUrl/" + $item.Name.Replace(" ", "%20")
        $result = Get-AdcsHttpStatus -Url $url
        if ($result.Ok) {
            Write-Log "$url returns $($result.Status)" -Tag "Debug"
            continue
        }
        $failed += [pscustomobject]@{ Url = $url; Status = $result.Status; Advice = @($result.Advice) }
    }
    # No leading comma here. ',@()' is an array *containing* an empty array, so an
    # all-served run would come back with a count of one and a phantom failure whose
    # every property is the whole list joined together. Callers wrap in @() instead,
    # which is what turns a single failure back into a one-element array.
    return $failed
}

function Test-AdcsPublicationEndpoint {
    param(
        [Parameter(Mandatory)][object]$CertificateServices,
        [Parameter(Mandatory)][string]$PhysicalPath
    )

    $shared     = Get-ConfigValue -InputObject $CertificateServices -Name "shared"
    $pkiBaseUrl = ([string](Get-ConfigText -InputObject $shared -Name "pkiBaseUrl" -Default "")).TrimEnd("/")
    if ([string]::IsNullOrWhiteSpace($pkiBaseUrl)) { return }

    # The files themselves, not a name built from the template - a delta CRL is only
    # there when one is configured, and its '+' is exactly the case worth proving.
    $files = @(Get-ChildItem -Path (Join-Path -Path $PhysicalPath -ChildPath "*.crl") -File -ErrorAction SilentlyContinue |
        Sort-Object -Property Name)
    if ($files.Count -eq 0) { return }

    $failed = @(Get-AdcsUnservedCrl -File $files -BaseUrl $pkiBaseUrl)

    # A site started moments ago answers moments later, and the whole point of asking is
    # to be believed - a false negative here is a warning nobody can reproduce, sending
    # somebody after a role service that was never the problem.
    if ($failed.Count -gt 0) {
        Start-Sleep -Seconds 5
        $failed = @(Get-AdcsUnservedCrl -File $files -BaseUrl $pkiBaseUrl)
    }

    if ($failed.Count -eq 0) {
        Write-Log "Every published CRL is reachable at $pkiBaseUrl" -Tag "Ok"
        return
    }

    foreach ($failure in $failed) {
        Write-Log "$($failure.Url) does not answer: $($failure.Status)" -Tag "Warn"
        foreach ($line in $failure.Advice) { Write-Log "    $line" -Tag "Warn" }
    }
    $script:adcsWebFailure = "$($failed[0].Url) does not answer ($($failed[0].Status))"
    Write-Log "    That URL is in the CDP of everything this CA issues - fix it before anything enrolls" -Tag "Warn"
}

# The status line plus what it means, because an HTTP number on its own sends people
# to the wrong place. Sub-statuses come out of the response body: IIS writes a detailed
# error page for a request from the machine itself.
function Get-AdcsHttpStatus {
    param([Parameter(Mandatory)][string]$Url)

    $body = ""
    $status = ""
    try {
        $request = [System.Net.HttpWebRequest]::Create($Url)
        $request.Method = "GET"
        $request.Timeout = 15000
        $request.UseDefaultCredentials = $true
        $response = $request.GetResponse()
        $code = [int]$response.StatusCode
        $response.Close()
        return [pscustomobject]@{ Ok = ($code -ge 200 -and $code -lt 300); Status = "HTTP $code"; Advice = @() }
    }
    catch [System.Net.WebException] {
        $webResponse = $_.Exception.Response
        if ($null -eq $webResponse) {
            return [pscustomobject]@{ Ok = $false; Status = $_.Exception.Message; Advice = @(
                "Nothing answered at all - the site may be stopped, or the name may resolve to a different machine.") }
        }
        $status = "HTTP {0}" -f [int]$webResponse.StatusCode
        try {
            $reader = New-Object System.IO.StreamReader($webResponse.GetResponseStream())
            $body = $reader.ReadToEnd()
            $reader.Close()
        }
        catch { $body = "" }
        $webResponse.Close()
    }
    catch {
        return [pscustomobject]@{ Ok = $false; Status = $_.Exception.Message; Advice = @() }
    }

    $advice = @()
    $subStatus = [regex]::Match($body, "HTTP Error (\d{3}\.\d+)")
    if ($subStatus.Success) {
        $status = "HTTP " + $subStatus.Groups[1].Value
        switch ($subStatus.Groups[1].Value) {
            "404.3" {
                $advice += "That sub-status is the static file handler: IIS has no way to serve a file with this extension."
                $advice += "    Install-WindowsFeature -Name Web-Static-Content"
            }
            "404.11" {
                $advice += "That sub-status is double escaping, which is the '+' in a delta CRL name."
                $advice += "    appcmd set config `"<site>/<alias>`" /section:requestFiltering -allowDoubleEscaping:True"
            }
            "404.7" { $advice += "Request filtering is blocking this file name extension." }
            "404.8" { $advice += "Request filtering is blocking this path as a hidden segment." }
            "500.19" { $advice += "A web.config in the chain cannot be read - see the site's physical root." }
        }
    }
    return [pscustomobject]@{ Ok = $false; Status = $status; Advice = $advice }
}

# ---------------------------[ Certificate templates ]---------------------------
# There is no cmdlet that duplicates a certificate template - the console writes the
# object itself - so this does the same thing against the Configuration naming
# context. Every new template is a copy of a built-in one with the handful of
# attributes the deployment guide calls out changed on top, which keeps the EKUs,
# key usage and critical extensions exactly as Microsoft shipped them.

# Extended rights, from the schema.
$script:adcsEnrollRight     = [guid]"0e10c968-78fb-11d2-90d4-00c04f79dc55"
$script:adcsAutoEnrollRight = [guid]"a05b8cc2-17bc-4802-a710-e7c15ab866a2"

# msPKI-Certificate-Name-Flag / msPKI-Private-Key-Flag bits used below.
$script:ctFlagEnrolleeSuppliesSubject = 0x00000001
$script:ctFlagExportableKey           = 0x00000010

# CT_FLAG_STRONG_KEY_PROTECTION_REQUIRED (MS-CRTD 2.27). The client protects the private
# key beyond simply holding it - with the software Key Storage Provider that is the
# prompt on every use, and with a smart card or hardware module it is the PIN the
# provider already demands. It is the template half of "the key is not just a file".
$script:ctFlagStrongKeyProtection = 0x00000020

# CT_FLAG_EXPORTABLE_KEY in the *legacy* flags attribute, which is a different attribute
# from the one above carrying a bit of the same name and value. A schema 1 source states
# its export behaviour there, and that value is copied wholesale, so the design's answer
# is written to both or the object disagrees with itself.
$script:ctFlagLegacyExportableKey = 0x00000010

# msPKI-Enrollment-Flag. A request against a template carrying this bit is held as
# pending until a certificate manager approves it - the control that stops a subject
# supplied by the requester from being whatever the requester felt like typing.
$script:ctFlagPendAllRequests = 0x00000002

# CT_FLAG_USER_INTERACTION_REQUIRED. Written with the strong key protection bit above and
# never on its own: that bit says the key is protected, this one says a human consents at
# enrollment. The console's "prompt the user during enrollment and require user input
# when the private key is used" is the pair, and half of it is a different setting.
$script:ctFlagUserInteractionRequired = 0x00000100

# CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS. The CA adds a Basic Constraints
# extension with cA=FALSE to an end-entity certificate - the console's Extensions tab
# calls it "Basic Constraints / Enable this extension". App Control for Business asks for
# it on the certificate that signs a policy; nothing else here needs it.
$script:ctFlagIncludeBasicConstraints = 0x00008000

# The bit that makes a template autoenrollable at all. Granting the Autoenroll right
# and leaving this clear produces a template nothing ever enrolls for, silently - the
# permission is there, the client just never asks.
$script:ctFlagAutoEnrollment = 0x00000020

# CT_FLAG_PUBLISH_TO_DS. The CA writes every issued certificate into the requester's
# own directory object - the console's "Publish certificate in Active Directory". It
# exists for encryption certificates other people have to find; an authentication
# certificate published there is directory bloat and a list of everything this template
# ever issued, readable by anyone who can read the object. Microsoft's PKCS guide says
# to clear it explicitly, so the design states it rather than inheriting whichever
# answer the source template happened to carry.
$script:ctFlagPublishToDs = 0x00000008

# CT_FLAG_NO_SECURITY_EXTENSION suppresses the SID extension on everything issued from
# the template, which forces the weak UPN mapping KB5014754 exists to retire - ESC9. No
# template Microsoft ships carries it, so a copy arriving with it set means the source
# was edited; it is cleared with a warning rather than trusted across.
$script:ctFlagNoSecurityExtension = 0x00080000

# The domain's own DNS name in the subject alternative name. Inherited, never set here,
# and checked rather than written: it is what distinguishes 'Kerberos Authentication'
# from the two older domain controller templates, and the console offers no checkbox
# for it - a copy either carries it across or silently does not.
$script:ctFlagSubjectAltRequireDomainDns = 0x00400000

# Schema version 4 with both compatibility levels at Windows Server 2016 / Windows 10,
# which is what the console's Compatibility tab shows. The schema version alone does
# not say it: the console reads the version *and* two nibbles packed into
# msPKI-Private-Key-Flag, and a v4 template with those nibbles left at zero reports the
# lowest pairing the version allows. Copying a v1 or v2 source carries zeros across,
# which is how these ended up reading "Windows Server 2008 / Windows Vista" while
# saying schema 3 - the setting was never chosen, it was inherited from a template
# written before the concept existed.
#
# The values are enumerations, not bit flags, and they are masked out before being set
# so a source that carried its own does not merge with ours. MS-CRTD defines the masks
# (0x000F0000 for the CA, 0x0F000000 for the client): a CA whose own version is lower
# than the template's will not issue it, and a client below it will not enroll for it.
# The floor that buys is real - anything older than Windows 10 or Server 2016 ignores
# these templates entirely, autoenrollment included, and says nothing about why.
$script:adcsTemplateSchemaVersion = 4
$script:adcsTemplateVersionMask   = 0x0F0F0000   # both enumerations, CA and client
$script:adcsTemplateCaVersion     = 0x00060000   # TEMPLATE_SERVER_VER_THRESHOLD, Windows Server 2016
$script:adcsTemplateClientVersion = 0x06000000   # TEMPLATE_CLIENT_VER_THRESHOLD, Windows 10

# The algorithm settings are *not* attributes of their own - they live inside
# msPKI-RA-Application-Policies as name`type`value triples, which is what this string
# is. That format (MS-CRTD 2.23.2) is what a version 3 template uses, and what a
# version 4 template uses **unless** CT_FLAG_USE_LEGACY_PROVIDER is set - with that
# bit, the same attribute means a list of RA application policy OIDs instead. This
# design uses the Key Storage Provider and never sets it, so the triples stay correct
# at schema 4. Setting that flag without rewriting this string would turn the CNG
# settings into a malformed OID list.
$script:adcsCngPolicyFormat = 'msPKI-Asymmetric-Algorithm`PZPWSTR`RSA`msPKI-Hash-Algorithm`PZPWSTR`{0}`msPKI-Key-Usage`DWORD`16777215`msPKI-Symmetric-Algorithm`PZPWSTR`3DES`msPKI-Symmetric-Key-Length`DWORD`168`'

# Attributes worth carrying over from the template being copied. Identity and
# bookkeeping attributes are deliberately absent - those belong to the new object.
$script:adcsTemplateCopyAttributes = @(
    "flags",
    "revision",
    "pKIDefaultKeySpec",
    "pKIKeyUsage",
    "pKIMaxIssuingDepth",
    "pKICriticalExtensions",
    "pKIExtendedKeyUsage",
    "pKIDefaultCSPs",
    "pKIExpirationPeriod",
    "pKIOverlapPeriod",
    "msPKI-Certificate-Application-Policy",
    "msPKI-Certificate-Name-Flag",
    "msPKI-Enrollment-Flag",
    "msPKI-Minimal-Key-Size",
    "msPKI-Private-Key-Flag",
    "msPKI-RA-Application-Policies",
    "msPKI-RA-Policies",
    "msPKI-RA-Signature",
    "msPKI-Template-Minor-Revision",
    "msPKI-Template-Schema-Version"
)

# The common names Windows ships in CN=Certificate Templates. A design must not land on
# one of these: the object name is derived from the display name with the spaces taken
# out, so a template called "Code Signing" resolves to CN=CodeSigning - which already
# exists, is forest-wide, is schema version 1, and is the *built-in*. The existing-object
# branch below would then quietly grant enrollment on Microsoft's template and publish
# it, with none of the design's settings written, and the override branch would edit a
# forest-wide object this design never created. Hence the refusal, and hence the studio's
# entry being named "Code Sign".
$script:adcsBuiltInTemplateNames = @(
    "Administrator", "CA", "CAExchange", "CEPEncryption", "ClientAuth", "CodeSigning",
    "CrossCA", "CTLSigning", "DirectoryEmailReplication", "DomainController",
    "DomainControllerAuthentication", "EFS", "EFSRecovery", "EnrollmentAgent",
    "EnrollmentAgentOffline", "ExchangeUser", "ExchangeUserSignature",
    "IPSECIntermediateOffline", "IPSECIntermediateOnline", "KerberosAuthentication",
    "KeyRecoveryAgent", "Machine", "MachineEnrollmentAgent", "OCSPResponseSigning",
    "OfflineRouter", "RASAndIASServer", "Router", "SmartcardLogon", "SmartcardUser",
    "SubCA", "User", "UserSignature", "WebServer", "Workstation"
)

# groupType, as AD stores it. Security groups are the negative half of the range -
# 0x80000000 is the security bit, and the low bits are the scope.
$script:adcsGroupTypeGlobal      = -2147483646   # 0x80000002
$script:adcsGroupTypeDomainLocal = -2147483644   # 0x80000004
$script:adcsGroupTypeUniversal   = -2147483640   # 0x80000008

# name -> SID, filled in as groups are created or found. A group created seconds ago
# may not have reached the DC that an NTAccount translation happens to ask, so the
# SID read straight off the object is used in preference to a name lookup.
$script:adcsPrincipalSid = @{}

# Principals that could not be resolved when a template ACE was written. A template
# published with nobody able to enroll for it is a template that is quietly useless,
# so the run reports a manual step rather than a success.
$script:adcsGrantFailure = @()

# The publication endpoint, when it could not be built or does not answer. Same reason
# as the two below: without a channel back to the role result, a CA whose CDP resolves
# to nothing reports Completed, and the URL in that CDP is inside every certificate it
# is about to issue.
$script:adcsWebFailure = ""

# Templates that could not be written at all. Separate from the grant failures above
# because the cause is different and so is the fix, but they share the reason for
# existing: without a channel back to the role result, a run where every template
# failed still logs "templates applied" and exits 0.
$script:adcsTemplateFailure = @()

function Get-AdcsDefaultNamingContext {
    try {
        $rootDse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
        return [string]$rootDse.Properties["defaultNamingContext"].Value
    }
    catch {
        throw "Could not read the domain naming context: $($_.Exception.Message)"
    }
}

# LDAP filters treat these as syntax, so a group name carrying one has to arrive
# escaped or the search silently matches the wrong thing - or nothing.
function ConvertTo-AdcsLdapFilterValue {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    $escaped = $Value.Replace("\", "\5c").Replace("*", "\2a").Replace("(", "\28").Replace(")", "\29")
    return $escaped.Replace([string][char]0, "\00")
}

# A CN is not a string in a filter, it is a component of a distinguished name, and
# these characters end it early. Group names carry spaces and a hyphen by design
# ("Certificate - Web Services"), which are fine - the rest are escaped anyway so a
# hand-typed name can never build a DN that means something other than it reads.
function ConvertTo-AdcsRdnValue {
    param([Parameter(Mandatory)][string]$Value)

    $escaped = $Value.Replace("\", "\\")
    foreach ($character in @(",", "+", '"', "<", ">", ";", "=")) {
        $escaped = $escaped.Replace($character, "\$character")
    }
    if ($escaped.StartsWith(" ") -or $escaped.StartsWith("#")) { $escaped = "\" + $escaped }
    if ($escaped.EndsWith(" ")) { $escaped = $escaped.Substring(0, $escaped.Length - 1) + "\ " }
    return $escaped
}

function Find-AdcsGroup {
    param([Parameter(Mandatory)][string]$Name)

    $domainDn = Get-AdcsDefaultNamingContext
    $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDn")
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
    $searcher.Filter = "(&(objectCategory=group)(sAMAccountName=$(ConvertTo-AdcsLdapFilterValue -Value $Name)))"
    $null = $searcher.PropertiesToLoad.Add("objectSid")
    $null = $searcher.PropertiesToLoad.Add("distinguishedName")
    $null = $searcher.PropertiesToLoad.Add("groupType")
    return $searcher.FindOne()
}

# Created empty, on purpose. Which servers belong in a group is the decision the
# group exists to record, and no script is in a position to make it.
function New-AdcsAccessGroup {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Description = "",
        [string]$ContainerDn = "",
        [ValidateSet("Global", "DomainLocal", "Universal")][string]$Scope = "Global",
        # Applied only when this run is the one creating the group. An existing group's
        # membership is somebody's decision and is never touched.
        [string[]]$InitialMemberDn = @()
    )

    $Name = $Name.Trim()
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }

    $found = Find-AdcsGroup -Name $Name
    if ($null -ne $found) {
        try {
            $sidBytes = $found.Properties["objectsid"][0]
            $script:adcsPrincipalSid[$Name] = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
        }
        catch {
            # Not fatal - the ACE falls back to resolving the name, which works fine
            # for a group that has been around long enough to be found by a search.
            Write-Log "Could not read the SID of '$Name' from the search result - falling back to name resolution" -Tag "Debug"
        }
        Write-Log "Group '$Name' already exists - leaving it and its membership alone" -Tag "Info"
        return $true
    }

    $container = $ContainerDn
    if ([string]::IsNullOrWhiteSpace($container)) {
        $container = "CN=Users," + (Get-AdcsDefaultNamingContext)
    }

    # Applied only to a group this run creates. An existing one returned above with its
    # scope untouched: re-scoping a group that is already in ACLs and already has members
    # is a change somebody made a decision about, and AD refuses half of those conversions
    # anyway (a domain local group holding domain local members cannot become global).
    $groupType = $script:adcsGroupTypeGlobal
    if ($Scope -eq "Universal") { $groupType = $script:adcsGroupTypeUniversal }
    elseif ($Scope -eq "DomainLocal") { $groupType = $script:adcsGroupTypeDomainLocal }

    try {
        $parent = Get-AdcsDirectoryEntry -DistinguishedName $container
        $group = $parent.Children.Add("CN=$(ConvertTo-AdcsRdnValue -Value $Name)", "group")
        $group.Properties["sAMAccountName"].Value = $Name
        $group.Properties["groupType"].Value = $groupType
        if (-not [string]::IsNullOrWhiteSpace($Description)) {
            $group.Properties["description"].Value = $Description
        }
        $group.CommitChanges()
        $group.RefreshCache(@("objectSid"))
        $script:adcsPrincipalSid[$Name] = New-Object System.Security.Principal.SecurityIdentifier($group.Properties["objectSid"].Value, 0)
    }
    catch {
        Write-Log "Could not create the group '$Name' in ${container}: $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    # Members go in a *second* write, after the object exists. 'member' is a linked
    # attribute: the link needs a source object to hang off, and ADSI setting one in the
    # same operation that creates the group is refused with "The server is unwilling to
    # process the request" - an error that names neither the attribute nor the reason,
    # and which looked like the group creation itself failing.
    $seeded = @($InitialMemberDn | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($seeded.Count -eq 0) {
        Write-Log "Created $Scope group '$Name' in $container - empty, membership is yours" -Tag "Ok"
        return $true
    }

    # One member per commit. A group's scope decides what it may contain - a *global*
    # group cannot hold a *universal* one, which is exactly Domain Admins (global, legal
    # here) alongside Enterprise Admins (universal, not) - and the directory refuses the
    # whole write for one bad value. Adding them separately means the legal member
    # survives the illegal one, and the message can name which was which.
    $added = 0
    foreach ($memberDn in $seeded) {
        if (($Scope -eq "Global") -and ((Get-AdcsGroupScope -DistinguishedName $memberDn) -eq "Universal")) {
            Write-Log "'$memberDn' is universal and '$Name' is global - a global group cannot contain one, so it is left out" -Tag "Warn"
            Write-Log "Set certificateServices.roleGroups.scope to Universal if you want it in there" -Tag "Warn"
            continue
        }
        try {
            $null = $group.Properties["member"].Add($memberDn)
            $group.CommitChanges()
            $added++
        }
        catch {
            Write-Log "Could not add '$memberDn' to '$Name': $($_.Exception.Message)" -Tag "Warn"
            $group.RefreshCache(@("member"))
        }
    }

    Write-Log "Created $Scope group '$Name' in $container with $added initial member(s)" -Tag "Ok"
    return $true
}

# Which of the three scopes a group has, read off groupType rather than guessed from
# the name. The low bits are the scope and the top bit is what makes it a security
# group: 2 global, 4 domain local, 8 universal.
function Get-AdcsGroupScope {
    param([Parameter(Mandatory)][string]$DistinguishedName)

    try {
        $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DistinguishedName")
        $groupType = [int]$entry.Properties["groupType"].Value
        if (($groupType -band 0x00000008) -ne 0) { return "Universal" }
        if (($groupType -band 0x00000004) -ne 0) { return "DomainLocal" }
        if (($groupType -band 0x00000002) -ne 0) { return "Global" }
        return ""
    }
    catch {
        return ""
    }
}

# The domain's own SID, which is what every well-known account RID hangs off. Read from
# the naming context object rather than resolved from a name: 'Domain Admins' is
# 'Domaenen-Admins' on a German installation and 'Administrateurs du domaine' on a French
# one, and a name lookup is the classic way a script works everywhere it was tested and
# nowhere else.
function Get-AdcsDomainSid {
    param([Parameter(Mandatory)][string]$NamingContext)

    try {
        $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$NamingContext")
        return New-Object System.Security.Principal.SecurityIdentifier($entry.Properties["objectSid"].Value, 0)
    }
    catch {
        Write-Log "Could not read the domain SID of '$NamingContext': $($_.Exception.Message)" -Tag "Warn"
        return $null
    }
}

# Whatever object holds this SID, as a distinguished name. LDAP://<SID=...> binds
# straight to it, so nothing here depends on what it is called in this language.
function Get-AdcsDnBySid {
    param([Parameter(Mandatory)][object]$Sid)

    try {
        $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://<SID=$($Sid.Value)>")
        $dn = [string]$entry.Properties["distinguishedName"].Value
        if ([string]::IsNullOrWhiteSpace($dn)) { return "" }
        return $dn
    }
    catch {
        return ""
    }
}

# A well-known group as a distinguished name, found by SID. WellKnownSidType does the
# RID arithmetic - Domain Admins is the domain SID plus 512, Enterprise Admins the
# *forest root* domain's SID plus 519 - so nothing here is a name either.
function Get-AdcsWellKnownGroupDn {
    param(
        [Parameter(Mandatory)][System.Security.Principal.WellKnownSidType]$WellKnownType,
        [Parameter(Mandatory)][object]$DomainSid
    )

    if ($null -eq $DomainSid) { return "" }

    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($WellKnownType, $DomainSid)
        return Get-AdcsDnBySid -Sid $sid
    }
    catch {
        return ""
    }
}

# Where the enrollment groups go. An organizationalUnit that does not exist fails
# every single group creation with an ADSI error naming the container rather than the
# setting, so it is checked once, before anything is created, and it names the field.
# Empty means the domain's Users container, which always exists.
function Test-AdcsAccessContainer {
    param([Parameter(Mandatory)][object]$CertificateServices)

    $access = Get-ConfigValue -InputObject $CertificateServices -Name "access"
    if ($null -eq $access) { return $true }
    if (-not [bool](Get-ConfigValue -InputObject $access -Name "createGroups" -Default $false)) { return $true }

    $container = [string](Get-ConfigText -InputObject $access -Name "organizationalUnit" -Default "")
    if ([string]::IsNullOrWhiteSpace($container)) { return $true }

    if ((Test-StudioDirectoryObject -DistinguishedName $container)) {
        Write-Log "Enrollment groups will be created in $container" -Tag "Info"
        return $true
    }

    Write-Log "certificateServices.access.organizationalUnit names a container that does not exist: $container" -Tag "Error"
    Write-Log "Create it, or clear the field to use the domain's Users container:" -Tag "Error"
    Write-Log "    New-ADOrganizationalUnit -Name <name> -Path <parent DN>" -Tag "Error"
    return $false
}

# The five groups that say who runs this PKI, as opposed to who may enroll from it.
# Created on the domain controller, before either CA exists, and adopted rather than
# rebuilt when something else got there first - the sibling ActiveDirectory-Toolkit
# creates the same names, and two tools fighting over one group is worse than either
# tool not running.
#
# A group this run creates is seeded with Domain Admins. That looks like the opposite
# of least privilege and is the thing that makes least privilege reachable: these
# groups are about to be given the CA's administrative rights *instead of* the built-in
# ones, and a group with no members handed that job is a certification authority nobody
# can administer. Seeding means the switch-over is survivable on day one; taking it out
# again once real members exist is a membership change, which is somebody's decision
# and never this script's.
#
# An adopted group is left exactly as found, seeding included - if it already exists,
# whoever made it decided who belongs in it.
# Two of the five role groups cannot be granted anything by the certification
# authority: auditor and backup operator are Windows *user rights*, and rights live in
# the LSA policy database, not in the CA's security descriptor.
#
# LsaAddAccountRights is the surgical way in - it adds one privilege to one account and
# touches nothing else. secedit is the usual alternative and it is worse: export the
# whole policy, edit it, apply it back, and hope nothing else in that file moved.
#
# Compiled at call time rather than when this part is dot-sourced, so a -CheckOnly run
# on a machine with no advapi32.dll never tries.
function Initialize-AdcsLsaType {
    if (([System.Management.Automation.PSTypeName]"WsrsLsa").Type) { return }

    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class WsrsLsa
{
    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public int Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint LsaOpenPolicy(IntPtr systemName, ref LSA_OBJECT_ATTRIBUTES objectAttributes, int desiredAccess, out IntPtr policyHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint LsaAddAccountRights(IntPtr policyHandle, byte[] accountSid, LSA_UNICODE_STRING[] userRights, int countOfRights);

    [DllImport("advapi32.dll")]
    private static extern uint LsaClose(IntPtr policyHandle);

    [DllImport("advapi32.dll")]
    private static extern int LsaNtStatusToWinError(uint status);

    private const int POLICY_CREATE_ACCOUNT = 0x00000010;
    private const int POLICY_LOOKUP_NAMES = 0x00000800;

    public static int Grant(byte[] sid, string right)
    {
        LSA_OBJECT_ATTRIBUTES attributes = new LSA_OBJECT_ATTRIBUTES();
        attributes.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));

        IntPtr policy;
        uint status = LsaOpenPolicy(IntPtr.Zero, ref attributes, POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES, out policy);
        if (status != 0) { return LsaNtStatusToWinError(status); }

        try
        {
            LSA_UNICODE_STRING[] rights = new LSA_UNICODE_STRING[1];
            rights[0] = new LSA_UNICODE_STRING();
            rights[0].Buffer = Marshal.StringToHGlobalUni(right);
            rights[0].Length = (ushort)(right.Length * 2);
            rights[0].MaximumLength = (ushort)((right.Length + 1) * 2);
            try
            {
                status = LsaAddAccountRights(policy, sid, rights, 1);
                return LsaNtStatusToWinError(status);
            }
            finally
            {
                Marshal.FreeHGlobal(rights[0].Buffer);
            }
        }
        finally
        {
            LsaClose(policy);
        }
    }
}
"@
}

function Grant-AdcsUserRight {
    param(
        [Parameter(Mandatory)][string]$AccountName,
        [Parameter(Mandatory)][string]$Privilege
    )

    $sid = $null
    try {
        $sid = (New-Object System.Security.Principal.NTAccount($AccountName)).Translate([System.Security.Principal.SecurityIdentifier])
    }
    catch {
        Write-Log "'$AccountName' did not resolve for $Privilege - the group may not have replicated here yet" -Tag "Warn"
        return $false
    }

    $bytes = New-Object byte[] $sid.BinaryLength
    $sid.GetBinaryForm($bytes, 0)

    try {
        Initialize-AdcsLsaType
        $code = [WsrsLsa]::Grant($bytes, $Privilege)
    }
    catch {
        Write-Log "Could not grant $Privilege to '$AccountName': $($_.Exception.Message)" -Tag "Warn"
        return $false
    }

    if ($code -ne 0) {
        Write-Log "Granting $Privilege to '$AccountName' failed with Win32 error $code" -Tag "Warn"
        return $false
    }
    Write-Log "Granted $Privilege to '$AccountName'" -Tag "Ok"
    return $true
}

# Runs on the certification authority, not on the domain controller: the groups are
# created there, the rights are held here. Off unless the design asks for it, and worth
# being honest about even when it works - user rights assignment through Group Policy is
# *replace*, not merge, so the first GPO that defines one of these rights becomes the
# whole list for it and quietly drops what was set locally. A stopgap for a CA no policy
# has reached yet; the durable answer is that GPO.
function Set-AdcsRoleUserRight {
    param([Parameter(Mandatory)][object]$CertificateServices)

    $roleGroups = Get-ConfigValue -InputObject $CertificateServices -Name "roleGroups"
    if ($null -eq $roleGroups) { return }
    if (-not [bool](Get-ConfigValue -InputObject $roleGroups -Name "applyUserRights" -Default $false)) { return }


    # The two roles the CA itself cannot grant, and the privileges behind their
    # friendly names in the policy editor.
    $wanted = @{
        "auditor"        = @("SeSecurityPrivilege")
        "backupOperator" = @("SeBackupPrivilege", "SeRestorePrivilege")
    }

    $granted = 0
    foreach ($group in @(Get-ConfigArray -InputObject $roleGroups -Name "groups")) {
        $role = [string](Get-ConfigText -InputObject $group -Name "role" -Default "")
        $name = [string](Get-ConfigText -InputObject $group -Name "name" -Default "")
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        if (-not $wanted.ContainsKey($role)) { continue }

        foreach ($privilege in $wanted[$role]) {
            if (Grant-AdcsUserRight -AccountName $name -Privilege $privilege) { $granted++ }
        }
    }

    if ($granted -eq 0) { return }
    Write-Log "    These are *local* user rights. A group policy defining one of them replaces the whole list for that right, this grant included" -Tag "Warn"
    Write-Log "    Put the same groups into whichever policy owns those rights, or they vanish at the next refresh" -Tag "Warn"
}

# The CA's own permissions, from MS-CSRA. Officer is what the console calls "Issue and
# Manage Certificates" and Administrator "Manage CA"; Read is implied by any of Enroll,
# Officer or Administrator and is not set separately.
#
# Auditor and Operator are the halves people miss. The specification is explicit that
# the *role* is the CA permission plus a Windows privilege - an auditor needs this bit
# and SeSecurityPrivilege, an operator this bit and SeBackupPrivilege - so granting one
# without the other produces a group that looks configured and can do nothing.
$script:adcsAccessAdministrator = 0x00000001
$script:adcsAccessOfficer       = 0x00000002
$script:adcsAccessAuditor       = 0x00000004
$script:adcsAccessOperator      = 0x00000008
$script:adcsAccessRead          = 0x00000100

$script:adcsRoleAccessMask = @{
    "administrator"     = 0x00000001
    "certificateManager" = 0x00000002
    "auditor"           = 0x00000104
    "backupOperator"    = 0x00000108
    # CA_ACCESS_ENROLL - the console's "Request Certificates", which is what lets a
    # principal submit at all. It is normally unstated because a default CA grants it
    # to Authenticated Users and every computer account is one of those. It is stated
    # here because this design can take that default away itself: applyCaSecurity
    # rewrites the descriptor, and a CA tightened that far refuses the Intune
    # connector with an access denied that names nothing.
    "requester"         = 0x00000200
}

# BUILTIN\Administrators. The two domain ones are resolved per domain, by RID, the same
# way the seeding does - a name lookup would be wrong on a localised installation.
$script:adcsBuiltinAdministratorsSid = "S-1-5-32-544"

function Get-AdcsPrincipalSidValue {
    param([Parameter(Mandatory)][string]$Name)

    try {
        return (New-Object System.Security.Principal.NTAccount($Name)).Translate([System.Security.Principal.SecurityIdentifier])
    }
    catch {
        Write-Log "Could not resolve '$Name' to a SID - it may not have replicated to this server yet" -Tag "Warn"
        return $null
    }
}

# Every principal the design would strip from the CA's permissions: the two well-known
# domain groups plus the local Administrators group. Resolved by SID, never by name.
# How many principals a role group holds, or -1 when the group could not be found at
# all. The two are different answers and this run used to give them the same silent one:
# a group that could not be looked up counted as a group with nobody in it, which is the
# state the built-in administrators are deliberately kept for.
#
# The SID is tried first, because the two lookups in this file disagree. On 2026-08-10 an
# adoption run resolved 'AD CS - Administrators' through the LSA - the same translate
# every ACE in this file is built from, which succeeded - while an LDAP sAMAccountName
# search for that name in the same second found nothing, and the run refused the strip on
# a group that dsa.msc showed as populated. The groups were four minutes old, created by
# the directory tier on another machine; a run where they already existed had worked. So
# the tolerant path is the one to ask, and the search stays as the fallback.
function Get-AdcsGroupMemberCount {
    param([Parameter(Mandatory)][string]$Name)

    $sid = Get-AdcsPrincipalSidValue -Name $Name
    if ($null -ne $sid) {
        try {
            $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://<SID=$($sid.Value)>")
            if ($null -ne $entry.Name) {
                return @($entry.Properties["member"]).Count
            }
        }
        catch {
            Write-Log "Could not read the membership of '$Name' by SID: $($_.Exception.Message)" -Tag "Debug"
        }
    }

    $found = Find-AdcsGroup -Name $Name
    if ($null -eq $found) { return -1 }
    try {
        $entry = Get-AdcsDirectoryEntry -DistinguishedName ([string]$found.Properties["distinguishedname"][0])
        return @($entry.Properties["member"]).Count
    }
    catch {
        Write-Log "Could not read the membership of '$Name': $($_.Exception.Message)" -Tag "Warn"
        return -1
    }
}

function Get-AdcsBuiltinAdminSid {
    $sids = @($script:adcsBuiltinAdministratorsSid)

    $rootDse = $null
    try { $rootDse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE") } catch { $rootDse = $null }
    if ($null -eq $rootDse) { return $sids }

    $pairs = @(
        @{ Type = [System.Security.Principal.WellKnownSidType]::AccountDomainAdminsSid;     Context = (Get-AdcsDefaultNamingContext) },
        @{ Type = [System.Security.Principal.WellKnownSidType]::AccountEnterpriseAdminsSid; Context = [string]$rootDse.Properties["rootDomainNamingContext"].Value }
    )
    foreach ($pair in $pairs) {
        $domainSid = Get-AdcsDomainSid -NamingContext $pair.Context
        if ($null -eq $domainSid) { continue }
        try { $sids += (New-Object System.Security.Principal.SecurityIdentifier($pair.Type, $domainSid)).Value }
        catch {
            # Enterprise Admins does not exist outside the forest root, which is a fact
            # about this domain rather than a failure - there is simply nothing to strip.
            Write-Log "No well-known SID for $($pair.Type) in $($pair.Context) - nothing of that kind to remove" -Tag "Debug"
        }
    }
    return $sids
}

# The CA's access control list is a binary security descriptor in its own registry key,
# not an object in the directory - so it is read, edited and written back whole. The
# console does the same thing over RPC; this is the same descriptor.
function Set-AdcsCaSecurity {
    param([Parameter(Mandatory)][object]$CertificateServices)

    $roleGroups = Get-ConfigValue -InputObject $CertificateServices -Name "roleGroups"
    if ($null -eq $roleGroups) { return $true }
    if (-not [bool](Get-ConfigValue -InputObject $roleGroups -Name "applyCaSecurity" -Default $false)) {
        Write-Log "Role groups get no permissions on this CA - roleGroups.applyCaSecurity is off" -Tag "Info"
        return $true
    }

    $groups = @(Get-ConfigArray -InputObject $roleGroups -Name "groups")
    if ($groups.Count -eq 0) { return $true }

    $caName = Get-AdcsActiveCaName
    if ([string]::IsNullOrWhiteSpace($caName)) { return $true }
    $keyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName"

    $existing = $null
    try { $existing = (Get-ItemProperty -Path $keyPath -Name "Security" -ErrorAction Stop).Security }
    catch {
        Write-Log "Could not read the CA's security descriptor: $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    $descriptor = $null
    try { $descriptor = New-Object System.Security.AccessControl.RawSecurityDescriptor($existing, 0) }
    catch {
        Write-Log "The CA's security descriptor could not be parsed: $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    # Every role a group is given is OR-ed into one mask before anything is written.
    # A descriptor carries one ACE per principal and the ACE below replaces whatever
    # that principal had, so two entries naming the same group would otherwise mean the
    # last one read wins and the first right is silently dropped. One group holding two
    # rights is not hypothetical: the Intune connector group needs Request Certificates
    # to issue at all, and Issue and Manage Certificates as well once revocation is in
    # the design.
    $wanted = [ordered]@{}
    foreach ($group in $groups) {
        $role = [string](Get-ConfigText -InputObject $group -Name "role" -Default "")
        $name = [string](Get-ConfigText -InputObject $group -Name "name" -Default "")
        if (-not $script:adcsRoleAccessMask.ContainsKey($role)) { continue }
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        $sid = Get-AdcsPrincipalSidValue -Name $name
        if ($null -eq $sid) { continue }

        $sidText = [string]$sid
        if ($wanted.Contains($sidText)) {
            $wanted[$sidText].Mask   = $wanted[$sidText].Mask -bor $script:adcsRoleAccessMask[$role]
            $wanted[$sidText].Roles += $role
        }
        else {
            $wanted[$sidText] = [pscustomobject]@{
                Sid   = $sid
                Name  = $name
                Mask  = $script:adcsRoleAccessMask[$role]
                Roles = @($role)
            }
        }
    }

    $applied = @()
    foreach ($wantedAce in $wanted.Values) {
        # Replace rather than add: running this twice must not leave two ACEs for the
        # same group with different masks, which is how a permission nobody granted
        # survives a design change.
        for ($index = $descriptor.DiscretionaryAcl.Count - 1; $index -ge 0; $index--) {
            if ([string]$descriptor.DiscretionaryAcl[$index].SecurityIdentifier -eq [string]$wantedAce.Sid) {
                $descriptor.DiscretionaryAcl.RemoveAce($index)
            }
        }
        $descriptor.DiscretionaryAcl.InsertAce($descriptor.DiscretionaryAcl.Count,
            (New-Object System.Security.AccessControl.CommonAce(
                [System.Security.AccessControl.AceFlags]::None,
                [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                $wantedAce.Mask, $wantedAce.Sid, $false, $null)))
        $applied += ("{0} ({1})" -f $wantedAce.Name, ($wantedAce.Roles -join ", "))
    }

    if ($applied.Count -eq 0) {
        Write-Log "No role group resolved, so the CA's permissions are unchanged" -Tag "Warn"
        return $false
    }

    # Before taking the built-ins away, prove the replacement is real. An ACE counts
    # towards the guard below whether or not anybody is in the group, so a group adopted
    # from somewhere else and never filled would pass that check and leave a CA nobody
    # can administer. The studio says to fill them first; this is what makes it true.
    $removed = @()
    $stripWanted = [bool](Get-ConfigValue -InputObject $roleGroups -Name "removeBuiltinAdmins" -Default $false)
    $populated = 0

    if ($stripWanted) {
        foreach ($adminGroup in @(Get-ConfigArray -InputObject $roleGroups -Name "groups" |
            Where-Object { [string](Get-ConfigText -InputObject $_ -Name "role" -Default "") -eq "administrator" })) {

            $adminName = [string](Get-ConfigText -InputObject $adminGroup -Name "name" -Default "")
            if ([string]::IsNullOrWhiteSpace($adminName)) { continue }

            # Three outcomes, three messages. "Not found" and "found and empty" used to
            # arrive at the same place by different roads, and only one of them is a
            # statement about who administers this CA.
            $memberCount = Get-AdcsGroupMemberCount -Name $adminName
            if ($memberCount -lt 0) {
                Write-Log "'$adminName' could not be read from the directory - that is not the same as it being empty" -Tag "Warn"
                continue
            }
            if ($memberCount -gt 0) {
                $populated++
                Write-Log "'$adminName' holds $memberCount member(s)" -Tag "Info"
            }
            else {
                Write-Log "'$adminName' has no members" -Tag "Warn"
            }
        }

        if ($populated -eq 0) {
            Write-Log "Not removing the built-in administrators - no group that would hold Manage CA has a member" -Tag "Error"
            Write-Log "    Fill the administrators role group first, or this CA would answer to nobody" -Tag "Error"
            Write-Log "    The permissions above are applied either way - re-run once the group is filled" -Tag "Info"
        }
    }

    if ($stripWanted -and ($populated -gt 0)) {
        $builtin = @(Get-AdcsBuiltinAdminSid)
        for ($index = $descriptor.DiscretionaryAcl.Count - 1; $index -ge 0; $index--) {
            $aceSid = [string]$descriptor.DiscretionaryAcl[$index].SecurityIdentifier
            if ($builtin -contains $aceSid) {
                $removed += $aceSid
                $descriptor.DiscretionaryAcl.RemoveAce($index)
            }
        }
    }

    # The guard that matters. A descriptor with nothing holding Administrator is a CA
    # no one can configure, and the console cannot put it back - it needs that very
    # permission to write this descriptor.
    $administrators = 0
    foreach ($ace in $descriptor.DiscretionaryAcl) {
        if (($ace.AccessMask -band $script:adcsAccessAdministrator) -ne 0) { $administrators++ }
    }
    if ($administrators -eq 0) {
        Write-Log "Refusing a CA security descriptor that leaves nobody with Manage CA - that cannot be undone from the console" -Tag "Error"
        return $false
    }

    $bytes = New-Object byte[] $descriptor.BinaryLength
    $descriptor.GetBinaryForm($bytes, 0)
    try {
        Set-ItemProperty -Path $keyPath -Name "Security" -Value $bytes -ErrorAction Stop
    }
    catch {
        Write-Log "Could not write the CA's security descriptor: $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    foreach ($entry in $applied) { Write-Log "Granted $entry on the certification authority" -Tag "Ok" }
    foreach ($sid in ($removed | Select-Object -Unique)) { Write-Log "Removed $sid from the CA's permissions" -Tag "Ok" }
    Write-Log "$administrators principal(s) hold Manage CA after this change" -Tag "Info"

    Restart-AdcsService
    return $true
}

# Who may write certificate templates, which is a question about the forest rather than
# about this CA: the container lives in the Configuration NC and every CA issues from
# it. Inherited down to the templates themselves, so the group can edit what is already
# there and not only create new ones.
function Set-AdcsTemplateContainerAcl {
    param([Parameter(Mandatory)][object]$CertificateServices)

    $roleGroups = Get-ConfigValue -InputObject $CertificateServices -Name "roleGroups"
    if ($null -eq $roleGroups) { return $true }
    if (-not [bool](Get-ConfigValue -InputObject $roleGroups -Name "applyCaSecurity" -Default $false)) { return $true }

    $manager = @(Get-ConfigArray -InputObject $roleGroups -Name "groups" |
        Where-Object { [string](Get-ConfigText -InputObject $_ -Name "role" -Default "") -eq "templateManager" })
    if ($manager.Count -eq 0) { return $true }

    $name = [string](Get-ConfigText -InputObject $manager[0] -Name "name" -Default "")
    if ([string]::IsNullOrWhiteSpace($name)) { return $true }
    $sid = Get-AdcsPrincipalSidValue -Name $name
    if ($null -eq $sid) { return $false }

    # Two containers, because duplicating a template creates two objects. The template
    # goes under CN=Certificate Templates and its OID goes under CN=OID - New-AdcsTemplateOid
    # mints one per template, and the console does the same. A group holding only the first
    # can edit templates and cannot create one, which is the operation it exists for, and
    # the console reports that as a permissions error naming neither container.
    $configurationNamingContext = Get-AdcsConfigurationNamingContext
    $containers = @(
        "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configurationNamingContext",
        "CN=OID,CN=Public Key Services,CN=Services,$configurationNamingContext"
    )

    $allDone = $true
    foreach ($containerDn in $containers) {
        try {
            $entry = Get-AdcsDirectoryEntry -DistinguishedName $containerDn
            # Every right GenericAll decomposes into EXCEPT ExtendedRight, which is the
            # exact set Microsoft grants Domain Admins on its own templates: the SDDL on
            # CN=KerberosAuthentication reads CCDCLCSWRPWPDTLOSDRCWDWO and this is that
            # string. The omission is the whole point. On a template object the only two
            # extended rights that exist are Enroll and Autoenroll, so GenericAll here -
            # inherited by every template in the forest - quietly made the template
            # managers an autoenrolling principal on all of them. A member of the group
            # signing in to any machine then had its autoenrollment client submit for
            # every template flagged CT_FLAG_AUTO_ENROLLMENT, including the domain
            # controller one, and the CA denied each in turn: pages of Denied by Policy
            # Module against a design that grants them nothing. Bench-found on 2026-09-19.
            #
            # Still not the individual rights spelled out one by one for presentation's
            # sake. The certificate templates console has five checkboxes - Full Control,
            # Read, Write, Enroll, Autoenroll - and this set ticks Read and Write, which
            # is what the group does. A set like CreateChild/WriteProperty alone maps to
            # none of them and would leave the group looking as though it held nothing.
            $rights = [System.DirectoryServices.ActiveDirectoryRights]"CreateChild, DeleteChild, ListChildren, Self, ReadProperty, WriteProperty, DeleteTree, ListObject, Delete, ReadControl, WriteDacl, WriteOwner"
            $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $sid, $rights, [System.Security.AccessControl.AccessControlType]::Allow,
                [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)
            # Purge before granting, and not as tidiness: AddAccessRule MERGES, so on a
            # container that already carries this group's old GenericAll the new narrower
            # rule is added beside it and the extended rights survive untouched. A run
            # against an existing deployment would then report the fix and change nothing.
            # Only this group's explicit rules go; anything inherited from further up
            # belongs to a decision made above this container and cannot be removed here.
            $security = $entry.ObjectSecurity
            $security.PurgeAccessRules($sid)
            $security.AddAccessRule($rule)
            $entry.ObjectSecurity = $security
            $entry.CommitChanges()
        }
        catch {
            Write-Log "Could not grant '$name' write access to $($containerDn): $($_.Exception.Message)" -Tag "Error"
            $allDone = $false
            continue
        }
        Write-Log "Granted '$name' read and write on $containerDn, inherited by the objects in it" -Tag "Ok"
    }

    Write-Log "    Enterprise Admins keep their own access - this says who edits templates routinely, not who is prevented" -Tag "Debug"
    Write-Log "    Read and write here is inherited by every template, which is write access to what a certificate may assert" -Tag "Debug"
    Write-Log "    Enroll and autoenroll are deliberately not in it - managing a template is not enrolling for one" -Tag "Debug"
    return $allDone
}

function Set-AdcsRoleGroup {
    param([Parameter(Mandatory)][object]$CertificateServices)

    $roleGroups = Get-ConfigValue -InputObject $CertificateServices -Name "roleGroups"
    if ($null -eq $roleGroups) {
        Write-Log "This config has no certificateServices.roleGroups section, so no role groups are created" -Tag "Info"
        Write-Log "It was exported before that section existed - re-export the design to pick it up" -Tag "Debug"
        return $true
    }
    if (-not [bool](Get-ConfigValue -InputObject $roleGroups -Name "createGroups" -Default $false)) {
        Write-Log "Role group creation is switched off" -Tag "Info"
        return $true
    }

    $groups = @(Get-ConfigArray -InputObject $roleGroups -Name "groups")
    if ($groups.Count -eq 0) { return $true }

    $container = [string](Get-ConfigText -InputObject $roleGroups -Name "organizationalUnit" -Default "")
    $scope     = [string](Get-ConfigText -InputObject $roleGroups -Name "scope" -Default "Global")

    # Domain Admins and nothing else. Enterprise Admins was in here too and is not any
    # more, for two reasons that point the same way: it is a *universal* group, so a
    # global role group cannot contain it at all, and on a member server like the
    # issuing CA it is Domain Admins that lands in the local Administrators group -
    # Enterprise Admins does not. So it was the half of the safety net that did not
    # hold anything up. Resolved by SID, never by name: this group is Domanen-Admins
    # on a German installation.
    $seed = @()
    $domainAdminsDn = Get-AdcsWellKnownGroupDn -WellKnownType ([System.Security.Principal.WellKnownSidType]::AccountDomainAdminsSid) `
        -DomainSid (Get-AdcsDomainSid -NamingContext (Get-AdcsDefaultNamingContext))
    if ([string]::IsNullOrWhiteSpace($domainAdminsDn)) {
        Write-Log "Could not resolve Domain Admins by SID - the new role groups are created empty" -Tag "Warn"
    }
    else { $seed += $domainAdminsDn }

    Write-Log "Making sure the $($groups.Count) role group(s) this design names exist" -Tag "Run"
    $allDone = $true

    foreach ($group in $groups) {
        $name = [string](Get-ConfigText -InputObject $group -Name "name" -Default "")
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        $found = Find-AdcsGroup -Name $name
        if ($null -ne $found) {
            $dn = [string]$found.Properties["distinguishedname"][0]
            Write-Log "'$name' already exists at $dn - adopting it, membership untouched" -Tag "Info"

            # Found but unusable is worse than absent: everything downstream reads as
            # having worked. A distribution group cannot carry an access control entry.
            $groupType = 0
            try { $groupType = [int]$found.Properties["grouptype"][0] } catch { $groupType = 0 }
            if (($groupType -ne 0) -and (($groupType -band 0x80000000) -eq 0)) {
                Write-Log "'$name' is a distribution group and cannot hold rights on the CA - convert it to a security group" -Tag "Warn"
                $allDone = $false
            }
            continue
        }

        if (-not (New-AdcsAccessGroup -Name $name -Scope $scope -ContainerDn $container -InitialMemberDn $seed `
                -Description ([string](Get-ConfigText -InputObject $group -Name "description" -Default "")))) {
            $allDone = $false
        }
    }

    if ($seed.Count -gt 0) {
        Write-Log "Groups created just now hold Domain Admins" -Tag "Info"
        Write-Log "    Take it out once the real members are in - that is a membership change, which this script never makes" -Tag "Debug"
    }
    return $allDone
}

# Microsoft's own AD CS hardening guidance says to strip Domain Admins and Enterprise
# Admins from the templates during the build and replace them with a dedicated group -
# and names the reason this cannot be done template by template: "they are assigned
# rights to the container in AD where all of the templates reside". Only half of what
# the console shows is per-template. The schema's defaultSecurityDescriptor puts an
# explicit Domain Admins ACE on each object as it is created, which the per-template
# removal takes off; Enterprise Admins arrives by inheritance from the container, and an
# inherited ACE cannot be removed from the object that inherited it. So the container is
# where the second half has to happen, and the templates below it follow.
function Remove-AdcsTemplateContainerBuiltinAdmin {
    param([Parameter(Mandatory)][object]$CertificateServices)

    $roleGroups = Get-ConfigValue -InputObject $CertificateServices -Name "roleGroups"
    if ($null -eq $roleGroups) { return }
    if (-not [bool](Get-ConfigValue -InputObject $roleGroups -Name "removeBuiltinAdmins" -Default $false)) { return }
    if (-not [bool](Get-ConfigValue -InputObject $roleGroups -Name "applyCaSecurity" -Default $false)) { return }

    # Same guard as the CA descriptor, for the same reason: an ACE counts whether or not
    # anybody is behind it, so prove the replacement holds somebody before the built-ins
    # go. An empty template managers group means nobody edits templates routinely.
    $manager = @(Get-ConfigArray -InputObject $roleGroups -Name "groups" |
        Where-Object { [string](Get-ConfigText -InputObject $_ -Name "role" -Default "") -eq "templateManager" })
    if ($manager.Count -eq 0) { return }
    $managerName = [string](Get-ConfigText -InputObject $manager[0] -Name "name" -Default "")
    if ([string]::IsNullOrWhiteSpace($managerName)) { return }

    $memberCount = Get-AdcsGroupMemberCount -Name $managerName
    if ($memberCount -lt 0) {
        Write-Log "Not stripping the built-in administrators from the templates container - '$managerName' could not be read" -Tag "Error"
        Write-Log "    A lookup that did not answer, not an empty group - check the name, then run again" -Tag "Info"
        return
    }
    if ($memberCount -eq 0) {
        Write-Log "Not stripping the built-in administrators from the templates container - '$managerName' holds nobody" -Tag "Error"
        Write-Log "Fill it first, then re-run - the grant above is applied either way" -Tag "Info"
        return
    }

    # Membership is only half of what an access check reads - the other half is the
    # token, and a token is minted at sign-in. A group created this same visit is not
    # in it, however many members it holds, so the very account being seeded into the
    # replacement group is refused by it until the next sign-in. Said now, because the
    # symptom arrives later and elsewhere: template edits denied in a session that
    # looks like it holds every right.
    $managerSid = Get-AdcsPrincipalSidValue -Name $managerName
    if ($null -ne $managerSid) {
        $tokenCarries = $false
        try {
            foreach ($tokenGroup in @([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups)) {
                if ([string]$tokenGroup.Value -eq [string]$managerSid) { $tokenCarries = $true; break }
            }
        }
        catch {
            Write-Log "Could not read this session's token groups: $($_.Exception.Message)" -Tag "Debug"
        }
        if (-not $tokenCarries) {
            Write-Log "This session's token does not carry '$managerName' - it signed in before the group existed" -Tag "Warn"
            Write-Log "    The strip still runs, but template edits from this session are refused until you sign out and back in" -Tag "Warn"
        }
    }

    $builtin = @(Get-AdcsBuiltinAdminSid | Where-Object { $_ -ne $script:adcsBuiltinAdministratorsSid })
    if ($builtin.Count -eq 0) { return }

    $containerDn = "CN=Certificate Templates,CN=Public Key Services,CN=Services," + (Get-AdcsConfigurationNamingContext)
    $entry = $null
    try { $entry = Get-AdcsDirectoryEntry -DistinguishedName $containerDn -DaclOnly }
    catch {
        Write-Log "Could not open $($containerDn): $($_.Exception.Message)" -Tag "Warn"
        return
    }

    $wanted = @(Get-AdcsContainerBuiltinSid -Entry $entry -Builtin $builtin)
    if ($wanted.Count -eq 0) {
        Write-Log "No built-in administrator holds the certificate templates container - nothing to strip" -Tag "Info"
        return
    }

    # Breaking inheritance and taking the entries off are two writes, not one, and doing
    # them in a single commit is what hid the failure. Their rights come down from the
    # Configuration container, so until the protection flag is actually stored there is
    # nothing on this object to remove - and if that flag does not persist, the directory
    # recomputes inheritance from the parent and puts both back the moment the write
    # lands. Commit the protection, read it back, and only then purge.
    if (-not $entry.ObjectSecurity.AreAccessRulesProtected) {
        Write-Log "The built-in administrators reach this container by inheritance, so inheritance is broken on it" -Tag "Warn"
        Write-Log "    Existing inherited entries are copied down and keep working; later edits above $containerDn no longer reach the templates" -Tag "Warn"
        try {
            $security = $entry.ObjectSecurity
            # preserveInheritance copies every inherited entry down as an explicit one, so
            # only the two being stripped are actually lost.
            $security.SetAccessRuleProtection($true, $true)
            $entry.ObjectSecurity = $security
            $entry.CommitChanges()
            $entry.RefreshCache(@("nTSecurityDescriptor"))
        }
        catch {
            Write-Log "Could not break inheritance on $($containerDn): $($_.Exception.Message)" -Tag "Warn"
            Write-AdcsContainerStripFallback -ContainerDn $containerDn -Sid $wanted
            return
        }

        if (-not $entry.ObjectSecurity.AreAccessRulesProtected) {
            Write-Log "Inheritance is still enabled on $containerDn - the protection flag did not store" -Tag "Warn"
            Write-Log "Nothing removed - while it inherits from the container above, the directory puts both entries straight back" -Tag "Warn"
            Write-AdcsContainerStripFallback -ContainerDn $containerDn -Sid $wanted
            return
        }
        Write-Log "Inheritance is now broken on $containerDn" -Tag "Ok"
    }

    try {
        $security = $entry.ObjectSecurity
        foreach ($sid in $wanted) {
            $security.PurgeAccessRules((New-Object System.Security.Principal.SecurityIdentifier($sid)))
        }
        $entry.ObjectSecurity = $security
        $entry.CommitChanges()
        $entry.RefreshCache(@("nTSecurityDescriptor"))
    }
    catch {
        Write-Log "Could not strip the built-in administrators from $($containerDn): $($_.Exception.Message)" -Tag "Warn"
        Write-AdcsContainerStripFallback -ContainerDn $containerDn -Sid $wanted
        return
    }

    # Read it back rather than reporting the intent. This is the step whose failure is
    # invisible - the console keeps showing the groups and the log claims otherwise.
    $survivors = @(Get-AdcsContainerBuiltinSid -Entry $entry -Builtin $wanted)

    foreach ($sid in $wanted) {
        if ($survivors -contains $sid) {
            Write-Log "$sid still holds $containerDn - the removal did not take" -Tag "Warn"
            continue
        }
        Write-Log "Removed $sid from $containerDn" -Tag "Ok"
    }
    if ($survivors.Count -gt 0) {
        Write-AdcsContainerStripFallback -ContainerDn $containerDn -Sid $survivors
    }
    Write-Log "    Enterprise Admins own the Configuration NC and can take this back - it says who edits templates routinely" -Tag "Debug"
}

# Every ACL walk in this file wants the same thing off a rule and has to handle both
# forms: .Access hands back NTAccount identities by default, and a SID that no longer
# resolves to a name comes back as a SecurityIdentifier already.
function Get-AdcsAccessRuleSid {
    param([Parameter(Mandatory)][object]$Rule)

    $ruleSid = $Rule.IdentityReference
    if ($ruleSid -isnot [System.Security.Principal.SecurityIdentifier]) {
        try { $ruleSid = $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) }
        catch { return $null }
    }
    return [string]$ruleSid
}

# ---------------------------[ Principals nobody types ]---------------------------
# Every Windows principal the design names on its own: the built-in groups an enrollment
# group is seeded with, and the identity-bound principals a template is granted to. The
# contract carries a CODE for each and never a name, and this is why:
#
# Domain Computers is Domaenencomputer on a German installation. For a seed member a name
# lookup there does not fail - it finds nothing, and New-AdcsAccessGroup would go on to
# create an empty group by the English name and grant it the template. For a template
# grant it is worse, because it *does* fail: on a German domain 'Domain Controllers'
# threw out of NTAccount.Translate, so the Domain Controller Authentication template was
# created, flagged for autoenrollment and left holding no autoenroll ACE at all - a
# certificate no domain controller could ever enrol for, on a CA that reported the
# template written. Bench-proven, on a German forest, which is why this table exists.
#
# DomainRelative says which of the two SID forms the type is. 516 and 515 and 553 are
# RIDs on the account domain's own SID; Enterprise Domain Controllers is S-1-5-9, an
# absolute SID belonging to no domain. The flag is what stops the first kind being built
# with no domain SID: the SecurityIdentifier constructor documents domainSid as REQUIRED
# for exactly the Account* types (and throws when it is absent), and as IGNORED for
# every other type - so the flag also means "do not go and read the domain SID for a
# value that would be thrown away".
#
# Label is the English name, for the log line when the SID cannot be translated. It is
# never a lookup value. Mirrored by WELL_KNOWN_MEMBERS in the studio.
$script:adcsWellKnownPrincipal = @{
    "domainComputers"             = [pscustomobject]@{ Type = [System.Security.Principal.WellKnownSidType]::AccountComputersSid;        DomainRelative = $true;  Label = "Domain Computers" }
    "domainControllers"           = [pscustomobject]@{ Type = [System.Security.Principal.WellKnownSidType]::AccountControllersSid;      DomainRelative = $true;  Label = "Domain Controllers" }
    "enterpriseDomainControllers" = [pscustomobject]@{ Type = [System.Security.Principal.WellKnownSidType]::EnterpriseControllersSid;   DomainRelative = $false; Label = "Enterprise Domain Controllers" }
    "rasAndIasServers"            = [pscustomobject]@{ Type = [System.Security.Principal.WellKnownSidType]::AccountRasAndIasServersSid; DomainRelative = $true;  Label = "RAS and IAS Servers" }
    # .NET has no WellKnownSidType for this one, so it is the only entry built from a RID
    # rather than from the enumeration - and the RID sits on the FOREST ROOT domain's SID,
    # the same shape as Enterprise Admins, because that is where the group lives. In a
    # single-domain forest the two naming contexts are the same string and ForestRoot
    # costs nothing; in a child domain, reading the account domain would build the SID of
    # a group that does not exist and grant enrollment to nobody.
    "enterpriseReadOnlyDomainControllers" = [pscustomobject]@{ Type = $null; DomainRelative = $true; ForestRoot = $true; Rid = 498; Label = "Enterprise Read-only Domain Controllers" }
}

# One of them as a SID, or $null with a line saying which and why. A code this build does
# not know is a config from a newer studio: reported, never guessed at.
function Get-AdcsWellKnownPrincipalSid {
    param([Parameter(Mandatory)][string]$Code)

    $key = $Code.Trim()
    if (-not $script:adcsWellKnownPrincipal.ContainsKey($key)) {
        Write-Log "'$Code' is not a well-known principal this script knows - nothing was resolved for it" -Tag "Warn"
        return $null
    }

    $definition = $script:adcsWellKnownPrincipal[$key]
    $domainSid = $null
    if ($definition.DomainRelative) {
        # Get-AdcsDefaultNamingContext THROWS when no domain answers, and this function's
        # contract is "$null and a line saying why": an unresolvable principal is a
        # reported grant failure that ends the role in ManualStepRequired, never an
        # exception out of the middle of the template pass. The naming context is also
        # checked for empty, because Get-AdcsDomainSid takes it as a mandatory parameter
        # and an empty string fails the binding rather than the lookup.
        $namingContext = ""
        if ($definition.ForestRoot) {
            try {
                $rootDse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
                $namingContext = [string]$rootDse.Properties["rootDomainNamingContext"].Value
            }
            catch { $namingContext = "" }
        }
        else {
            try { $namingContext = [string](Get-AdcsDefaultNamingContext) }
            catch { $namingContext = "" }
        }
        if ([string]::IsNullOrWhiteSpace($namingContext)) {
            $where = "the account domain"
            if ($definition.ForestRoot) { $where = "the forest root domain" }
            Write-Log "No domain answered, so '$($definition.Label)' could not be resolved - it is a group in $where" -Tag "Warn"
            return $null
        }
        $domainSid = Get-AdcsDomainSid -NamingContext $namingContext
        if ($null -eq $domainSid) {
            Write-Log "The account domain's SID could not be read, so '$($definition.Label)' could not be resolved" -Tag "Warn"
            return $null
        }
    }

    try {
        # A RID is arithmetic on the domain SID this function just read, for the groups
        # the enumeration does not name. Everything else goes through WellKnownSidType.
        if ($null -ne $definition.Rid) {
            return (New-Object System.Security.Principal.SecurityIdentifier("$($domainSid.Value)-$($definition.Rid)"))
        }
        return (New-Object System.Security.Principal.SecurityIdentifier($definition.Type, $domainSid))
    }
    catch {
        Write-Log "Could not build the SID of '$($definition.Label)': $($_.Exception.Message)" -Tag "Warn"
        return $null
    }
}

# The name this machine prints for a SID - what the certificates console and the
# security tab show, so a log line matches what somebody is looking at. Empty when the
# SID does not resolve, which the callers treat as "use the English label".
function Get-AdcsSidAccountName {
    param([Parameter(Mandatory)][object]$Sid)

    try { return [string]$Sid.Translate([System.Security.Principal.NTAccount]).Value }
    catch { return "" }
}

# A seed member as a distinguished name, which is the form a group's `member` attribute
# takes.
function Get-AdcsSeedMemberDn {
    param([Parameter(Mandatory)][string]$Code)

    $sid = Get-AdcsWellKnownPrincipalSid -Code $Code
    if ($null -eq $sid) { return "" }
    return Get-AdcsDnBySid -Sid $sid
}

function Set-AdcsAccessGroup {
    param([object]$Access)

    if ($null -eq $Access) { return }
    if (-not [bool](Get-ConfigValue -InputObject $Access -Name "createGroups" -Default $false)) {
        Write-Log "Group creation is switched off - every mapped group has to exist already" -Tag "Info"
        return
    }

    $groups = Get-ConfigArray -InputObject $Access -Name "groups"
    if ($groups.Count -eq 0) { return }

    $container = [string](Get-ConfigValue -InputObject $Access -Name "organizationalUnit" -Default "")
    $scope     = [string](Get-ConfigValue -InputObject $Access -Name "scope" -Default "Global")

    Write-Log "Making sure the $($groups.Count) enrollment group(s) this design maps exist" -Tag "Run"
    $created = @()
    foreach ($group in $groups) {
        $name = [string](Get-ConfigValue -InputObject $group -Name "name" -Default "")
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        # Membership is not automated here as a rule - which servers belong in a group is
        # the decision the group exists to record. The exception the design may state is
        # a built-in group whose membership is not a decision at all: every machine that
        # answers Remote Desktop wants that certificate. Seeded only when this run is the
        # one creating the group, so an adopted group keeps what it has.
        $seed = @()
        $seedName = @()
        foreach ($member in (Get-ConfigArray -InputObject $group -Name "members")) {
            $code = [string](Get-ConfigValue -InputObject $member -Name "wellKnown" -Default "")
            if ([string]::IsNullOrWhiteSpace($code)) { continue }
            $memberDn = Get-AdcsSeedMemberDn -Code $code
            if ([string]::IsNullOrWhiteSpace($memberDn)) {
                Write-Log "Could not resolve the built-in group '$code' by SID - '$name' is created without it" -Tag "Warn"
                continue
            }
            $seed += $memberDn
            $seedName += [string](Get-ConfigValue -InputObject $member -Name "name" -Default $code)
        }

        $null = New-AdcsAccessGroup -Name $name -Scope $scope -ContainerDn $container -InitialMemberDn $seed `
            -Description ([string](Get-ConfigValue -InputObject $group -Name "description" -Default ""))

        if ($seed.Count -eq 0) { $created += $name }
        else { Write-Log "'$name' carries $($seedName -join ', ') when this run creates it" -Tag "Info" }
    }

    if ($created.Count -gt 0) {
        Write-Log "Fill these before anything can enroll:" -Tag "Info"
        foreach ($name in $created) {
            Write-Log "    Add-ADGroupMember -Identity '$name' -Members <server>`$" -Tag "Info"
        }
    }
}

function Get-AdcsConfigurationNamingContext {
    try {
        $rootDse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
        return [string]$rootDse.Properties["configurationNamingContext"].Value
    }
    catch {
        throw "Could not read the Configuration naming context: $($_.Exception.Message)"
    }
}

function Get-AdcsDirectoryEntry {
    param(
        [Parameter(Mandatory)][string]$DistinguishedName,
        # Read and write the discretionary access control list and nothing else. Without a
        # mask ADSI round-trips the owner, the group and the system access control list as
        # well, and the last of those needs SeSecurityPrivilege - which is how a descriptor
        # write comes back as a no-op rather than an error. Only the callers that edit a
        # descriptor ask for it; everything else reads attributes and does not care.
        [switch]$DaclOnly
    )

    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DistinguishedName")
    if ($null -eq $entry.Name) {
        throw "Directory object not found: $DistinguishedName"
    }
    if ($DaclOnly) {
        # psbase, not $entry.Options: PowerShell's ADSI adapter reads property names as
        # LDAP attributes, so the bare form goes looking for an attribute called
        # 'Options' on the AD object and fails with 'property cannot be found'.
        $entry.psbase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
        $entry.RefreshCache(@("nTSecurityDescriptor"))
    }
    return $entry
}

# The same walk both halves of the container strip need: which of these principals hold
# an entry on this object at all, inherited or not.
function Get-AdcsContainerBuiltinSid {
    param(
        [Parameter(Mandatory)][object]$Entry,
        [Parameter(Mandatory)][string[]]$Builtin
    )

    $found = @()
    foreach ($rule in @($Entry.ObjectSecurity.Access)) {
        $ruleSid = Get-AdcsAccessRuleSid -Rule $rule
        if ($null -eq $ruleSid) { continue }
        if ($Builtin -notcontains $ruleSid) { continue }
        if ($found -notcontains $ruleSid) { $found += $ruleSid }
    }
    return $found
}

# Every way this step can fail ends in the same place - the entries are still there - and
# leaving somebody to work out the two dsacls calls from an ACL editor is how a hardening
# step gets skipped. dsacls is on a domain controller and on anything with the AD DS
# tools; the /P:Y is not optional, because /R on an inherited entry does nothing.
function Write-AdcsContainerStripFallback {
    param(
        [Parameter(Mandatory)][string]$ContainerDn,
        [Parameter(Mandatory)][string[]]$Sid
    )

    Write-Log "    By hand on a domain controller - protect the container first, or inheritance undoes the removal:" -Tag "Info"
    Write-Log "    dsacls `"$ContainerDn`" /P:Y" -Tag "Info"
    foreach ($sidValue in $Sid) {
        $display = $sidValue
        try {
            $account = (New-Object System.Security.Principal.SecurityIdentifier($sidValue)).Translate([System.Security.Principal.NTAccount])
            $display = [string]$account
        }
        catch {
            Write-Log "Could not resolve $sidValue to a name for the fallback line" -Tag "Debug"
        }
        Write-Log "    dsacls `"$ContainerDn`" /R `"$display`"" -Tag "Info"
    }
}

# A lifetime as AD stores it: a negative FILETIME interval, little endian.
function ConvertTo-AdcsPeriodByte {
    param(
        [Parameter(Mandatory)][string]$Period,
        [Parameter(Mandatory)][int]$Units
    )

    $seconds = switch ($Period) {
        "Hours"  { 3600 }
        "Days"   { 86400 }
        "Weeks"  { 604800 }
        "Months" { 2592000 }
        "Years"  { 31536000 }
        default  { 31536000 }
    }

    $ticks = [int64]$Units * [int64]$seconds * [int64]10000000

    # The leading comma is load-bearing. 'return <array>' unrolls into the pipeline, so
    # the caller gets an Object[] of eight boxed bytes rather than the byte[] this built
    # - and pKIExpirationPeriod is an octet string, which takes one byte[] value and
    # refuses that with "Unspecified error". Wrapping in an outer array stops the
    # unrolling; PowerShell hands back the inner byte[] intact.
    return ,[byte[]][System.BitConverter]::GetBytes(-$ticks)
}

# Every template needs an OID of its own beneath the forest's arc, plus the object
# under CN=OID that makes the console show a name instead of a number.
# ADSI wants a scalar or a *typed* array. A multi-valued attribute read off another
# entry comes back as object[], which marshals into COM as VT_ARRAY|VT_VARIANT, and
# the DirectoryString syntaxes reject that with a bare "Unspecified error" - naming
# neither the attribute, nor the value, nor the reason. Casting to string[] is the
# whole fix. A byte[] is one octet-string value rather than a list, so it is passed
# through untouched: re-shaping pKIExpirationPeriod would write eight integers.
# The catch exists because that error is otherwise unattributable - four templates
# failing identically says nothing about which of twenty attributes did it.
function Set-AdcsDirectoryProperty {
    param(
        [Parameter(Mandatory)][object]$Entry,
        [Parameter(Mandatory)][string]$Name,
        [object]$Value
    )

    if ($null -eq $Value) { return }

    $payload = $Value
    if (($Value -is [System.Array]) -and ($Value -isnot [byte[]])) {
        $items = @($Value)
        # Nothing to write, and an empty typed array is not the same as "leave it alone".
        if ($items.Count -eq 0) { return }
        $allStrings = $true
        $allBytes   = $true
        foreach ($item in $items) {
            if ($item -isnot [string]) { $allStrings = $false }
            if ($item -isnot [byte])   { $allBytes   = $false }
            if ((-not $allStrings) -and (-not $allBytes)) { break }
        }
        # An octet string is one value. A byte[] that has been through a pipeline comes
        # back as Object[] of boxed bytes, and re-typing it is the difference between
        # writing one eight-byte value and being refused outright.
        if ($allBytes)        { $payload = [byte[]]$items }
        elseif ($allStrings)  { $payload = [string[]]$items }
    }

    try {
        $Entry.Properties[$Name].Value = $payload
    }
    catch {
        throw "the attribute '$Name' would not take a $($payload.GetType().Name) value: $($_.Exception.Message)"
    }
}

function New-AdcsTemplateOid {
    param(
        [Parameter(Mandatory)][string]$ConfigurationNamingContext,
        [Parameter(Mandatory)][string]$DisplayName
    )

    $oidContainerDn = "CN=OID,CN=Public Key Services,CN=Services,$ConfigurationNamingContext"
    $oidContainer = Get-AdcsDirectoryEntry -DistinguishedName $oidContainerDn
    $forestOid = [string]$oidContainer.Properties["msPKI-Cert-Template-OID"].Value

    if ([string]::IsNullOrWhiteSpace($forestOid)) {
        throw "The forest has no enterprise OID arc under $oidContainerDn."
    }

    $suffix = "{0}.{1}" -f (Get-Random -Minimum 10000000 -Maximum 99999999), (Get-Random -Minimum 10000000 -Maximum 99999999)
    $templateOid = "$forestOid.$suffix"

    try {
        $oidEntry = $oidContainer.Children.Add("CN=$suffix", "msPKI-Enterprise-Oid")
        Set-AdcsDirectoryProperty -Entry $oidEntry -Name "msPKI-Cert-Template-OID" -Value $templateOid
        Set-AdcsDirectoryProperty -Entry $oidEntry -Name "flags" -Value 1
        Set-AdcsDirectoryProperty -Entry $oidEntry -Name "displayName" -Value $DisplayName
        $oidEntry.CommitChanges()
    }
    catch {
        throw "Could not register the template OID: $($_.Exception.Message)"
    }

    Write-Log "Registered OID $templateOid for '$DisplayName'" -Tag "Debug"
    return $templateOid
}

# One entry of enrollPrincipals / autoEnrollPrincipals, resolved to the SID the ACE is
# written with. Two shapes in that list, and the difference is the whole point:
#
#   "Certificate - Web Services"                                a group this design names
#   { wellKnown = "domainControllers"; name = "Domain Contr..." }   a Windows principal
#
# The second carries a code because its NAME is written in the language the forest was
# installed in, and `name` is a label that rides along for the log. The code is resolved
# through $script:adcsWellKnownPrincipal and the name is never looked up.
#
# Sid is $null when nothing resolved, which is the caller's to report - a template
# granted to nobody is what this whole path exists to make impossible.
function Resolve-AdcsEnrollmentPrincipal {
    param([Parameter(Mandatory)][object]$Entry)

    $label = ""
    if ($Entry -isnot [string]) {
        $code = [string](Get-ConfigValue -InputObject $Entry -Name "wellKnown" -Default "")
        $label = [string](Get-ConfigValue -InputObject $Entry -Name "name" -Default "")
        if (-not [string]::IsNullOrWhiteSpace($code)) {
            $key = $code.Trim()
            if ([string]::IsNullOrWhiteSpace($label) -and $script:adcsWellKnownPrincipal.ContainsKey($key)) {
                $label = $script:adcsWellKnownPrincipal[$key].Label
            }
            if ([string]::IsNullOrWhiteSpace($label)) { $label = $key }

            $sid = Get-AdcsWellKnownPrincipalSid -Code $key
            if ($null -eq $sid) { return [pscustomobject]@{ Label = $label; Sid = $null } }
            # Named in the language this domain actually uses, so the log line matches
            # what the console shows. The SID is what gets written either way.
            $localName = Get-AdcsSidAccountName -Sid $sid
            if (-not [string]::IsNullOrWhiteSpace($localName)) { $label = $localName }
            return [pscustomobject]@{ Label = $label; Sid = $sid }
        }
    }
    else {
        $label = [string]$Entry
    }

    $label = $label.Trim()
    if ([string]::IsNullOrWhiteSpace($label)) { return $null }

    # A group this run created is taken from the cache rather than looked up: name
    # resolution can land on a DC that has not seen the new object yet, and the SID
    # read off the object at creation is not subject to that race.
    if ($script:adcsPrincipalSid.ContainsKey($label)) {
        return [pscustomobject]@{ Label = $label; Sid = $script:adcsPrincipalSid[$label] }
    }
    try {
        $account = New-Object System.Security.Principal.NTAccount($label)
        return [pscustomobject]@{ Label = $label
            Sid = [System.Security.Principal.SecurityIdentifier]$account.Translate([System.Security.Principal.SecurityIdentifier]) }
    }
    catch {
        return [pscustomobject]@{ Label = $label; Sid = $null }
    }
}

# The ACE, from a SID that is already resolved. Principal is the label for the log and
# is never resolved here - see Resolve-AdcsEnrollmentPrincipal.
function Grant-AdcsTemplateEnrollment {
    param(
        [Parameter(Mandatory)][object]$TemplateEntry,
        [Parameter(Mandatory)][string]$Principal,
        [Parameter(Mandatory)][object]$Sid,
        [switch]$AutoEnroll
    )

    try {
        $read = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $Sid, [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $TemplateEntry.ObjectSecurity.AddAccessRule($read)

        $enroll = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $Sid, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow, $script:adcsEnrollRight)
        $TemplateEntry.ObjectSecurity.AddAccessRule($enroll)

        if ($AutoEnroll) {
            $auto = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $Sid, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                [System.Security.AccessControl.AccessControlType]::Allow, $script:adcsAutoEnrollRight)
            $TemplateEntry.ObjectSecurity.AddAccessRule($auto)
        }

        $TemplateEntry.CommitChanges()
    }
    catch {
        Write-Log "Could not grant enrollment to '$Principal': $($_.Exception.Message)" -Tag "Error"
        $script:adcsGrantFailure += $Principal
        return $false
    }

    $what = "enroll"
    if ($AutoEnroll) { $what = "enroll and autoenroll" }
    Write-Log "Granted $what to '$Principal'" -Tag "Ok"
    return $true
}

# Applied to a new template and to one that already exists alike - the mapping is the
# part of a template that is expected to change between runs.
# The built-in administrators on a template object, which arrive from the schema's
# defaultSecurityDescriptor when the object is created - nothing copies them from the
# source template, and nothing here put them there.
#
# Worth being straight about what removing them buys. Enterprise Admins own the
# Configuration NC: they can take ownership of any of these objects and grant
# themselves back in, and no setting below the forest owner changes that. So this
# records who edits templates *routinely* and keeps an accidental edit from being
# anybody's, which is worth something - it is not a boundary against those two groups.
# NT AUTHORITY\SYSTEM on a template this run created, which is the schema's doing and not
# this design's. An object created without an explicit security descriptor gets the
# defaultSecurityDescriptor of its class, and pKICertificateTemplate's hands SYSTEM and
# the two admin groups RPWPCRCCDCLCLORCWOWDSDDTSW - everything, CR included. CR on a
# template object is Enroll and Autoenroll, so every template this tool has ever built
# came out with SYSTEM holding both and the console showing all five boxes ticked for it.
# Microsoft's own templates carry none of this: theirs were written with an explicit
# descriptor at domain prep, which is why the built-in Domain Controller Authentication
# has no SYSTEM entry at all and issues perfectly well without one.
#
# Removed, and not only for parity. Nothing needs it - the CA reaches the directory as
# its own computer account, never as SYSTEM, and the resume task presents as HOST$ for
# the same reason. What the ACE does buy is a way around the delegation this role just
# built: WriteDacl and WriteOwner mean anything running as LocalSystem on a domain
# controller can rewrite any of these templates, which is the ESC4 shape the template
# managers group was narrowed to avoid.
#
# Unconditional, unlike the built-in admin strip below it. That one is a hardening choice
# about who administers this PKI. This is an ACE the design never asked for and the
# product does not put there, so there is nothing to weigh up.
function Remove-AdcsTemplateSystemAce {
    param([Parameter(Mandatory)][object]$TemplateEntry)

    $systemSid = $null
    try {
        $systemSid = New-Object System.Security.Principal.SecurityIdentifier(
            [System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    }
    catch {
        Write-Log "Could not build the SYSTEM SID - its access to this template was left alone: $($_.Exception.Message)" -Tag "Warn"
        return
    }

    try {
        # A freshly created template is holding a descriptor read before the object
        # existed, so ask the directory for the current one first.
        $TemplateEntry.RefreshCache(@("nTSecurityDescriptor"))
        $security = $TemplateEntry.ObjectSecurity

        $explicit = @($security.Access | Where-Object {
            (-not $_.IsInherited) -and ([string](Get-AdcsAccessRuleSid -Rule $_) -eq [string]$systemSid.Value)
        })
        if ($explicit.Count -eq 0) { return }

        # PurgeAccessRules for the same reason the built-in strip uses it: the specific
        # form matches on the whole rule and removes nothing at all when it does not.
        $security.PurgeAccessRules($systemSid)
        $TemplateEntry.ObjectSecurity = $security
        $TemplateEntry.CommitChanges()
    }
    catch {
        Write-Log "Could not remove SYSTEM from the template: $($_.Exception.Message)" -Tag "Warn"
        return
    }

    # Read it back rather than report what was asked for - an ACL step that says
    # 'removed' for a run in which nothing came off is the worst way to be wrong.
    try {
        $TemplateEntry.RefreshCache(@("nTSecurityDescriptor"))
        $left = @($TemplateEntry.ObjectSecurity.Access | Where-Object {
            [string](Get-AdcsAccessRuleSid -Rule $_) -eq [string]$systemSid.Value
        })
        if ($left.Count -eq 0) {
            Write-Log "    SYSTEM removed from the template - the schema default had handed it enroll and autoenroll" -Tag "Debug"
        }
        else {
            Write-Log "    SYSTEM still holds access on this template" -Tag "Warn"
        }
    }
    catch {
        # Reporting must never be what fails an ACL step that already succeeded.
    }
}

function Remove-AdcsTemplateBuiltinAdmin {
    param(
        [Parameter(Mandatory)][object]$TemplateEntry,
        [Parameter(Mandatory)][object]$CertificateServices
    )

    $roleGroups = Get-ConfigValue -InputObject $CertificateServices -Name "roleGroups"
    if ($null -eq $roleGroups) { return }
    if (-not [bool](Get-ConfigValue -InputObject $roleGroups -Name "removeBuiltinAdmins" -Default $false)) { return }
    if (-not [bool](Get-ConfigValue -InputObject $roleGroups -Name "applyCaSecurity" -Default $false)) { return }

    # Only the two domain groups. The local Administrators group is not on a template's
    # access control list, and Authenticated Users is the read that enrollment itself
    # needs - Microsoft's own templates carry it and nothing else in common with these.
    # SYSTEM used to be excluded here on the same reasoning and that reasoning was wrong:
    # it is not needed for anything, and Remove-AdcsTemplateSystemAce now takes it off.
    $builtin = @(Get-AdcsBuiltinAdminSid | Where-Object { $_ -ne $script:adcsBuiltinAdministratorsSid })
    if ($builtin.Count -eq 0) { return }

    $wanted = @()
    $inherited = @()
    try {
        # The descriptor this entry is holding was read before the object existed on a
        # freshly created template, so ask the directory for the current one first.
        $TemplateEntry.RefreshCache(@("nTSecurityDescriptor"))
        $security = $TemplateEntry.ObjectSecurity

        foreach ($rule in @($security.Access)) {
            $ruleSid = Get-AdcsAccessRuleSid -Rule $rule
            if ($null -eq $ruleSid) { continue }
            if ($builtin -notcontains $ruleSid) { continue }

            # An inherited ACE cannot be removed from the object that inherited it - it
            # belongs to a decision made further up the tree. Enterprise Admins reaches a
            # template that way, from the container the templates live in, which is where
            # Remove-AdcsTemplateContainerBuiltinAdmin takes it off instead.
            if ($rule.IsInherited) {
                if ($inherited -notcontains $ruleSid) { $inherited += $ruleSid }
                continue
            }
            if ($wanted -notcontains $ruleSid) { $wanted += $ruleSid }
        }

        foreach ($sid in $inherited) {
            Write-Log "    $sid reaches this template from the container above - stripped there, not here" -Tag "Debug"
        }
        if ($wanted.Count -eq 0) { return }

        # PurgeAccessRules, not RemoveAccessRuleSpecific. The specific form matches on the
        # access mask, both inheritance and propagation flags and both object-type GUIDs
        # together, returns void when it matches none of them, and leaves the descriptor
        # unmodified - so CommitChanges wrote nothing and every template still carried the
        # ACE this said it had removed. Purging by principal removes every explicit rule
        # it holds, which is what "strip the built-in administrators" means anyway.
        foreach ($sid in $wanted) {
            $security.PurgeAccessRules((New-Object System.Security.Principal.SecurityIdentifier($sid)))
        }
        # Assigning it back is what marks the entry's descriptor dirty. Mutating the object
        # the getter returned is enough on most builds and free everywhere.
        $TemplateEntry.ObjectSecurity = $security
        $TemplateEntry.CommitChanges()
    }
    catch {
        Write-Log "Could not remove the built-in administrators from the template: $($_.Exception.Message)" -Tag "Warn"
        return
    }

    # Read it back rather than reporting what was asked for. This step said 'removed' for
    # a run in which nothing came off, which is the worst way to be wrong about an ACL.
    $survivors = @()
    try {
        $TemplateEntry.RefreshCache(@("nTSecurityDescriptor"))
        foreach ($rule in @($TemplateEntry.ObjectSecurity.Access)) {
            if ($rule.IsInherited) { continue }
            $ruleSid = Get-AdcsAccessRuleSid -Rule $rule
            if ($null -eq $ruleSid) { continue }
            if (($wanted -contains $ruleSid) -and ($survivors -notcontains $ruleSid)) {
                $survivors += $ruleSid
            }
        }
    }
    catch {
        Write-Log "    could not read the template's access control list back - the removal is unverified" -Tag "Warn"
        return
    }

    foreach ($sid in $wanted) {
        if ($survivors -contains $sid) {
            Write-Log "    $sid is still on the template's access control list - the removal did not take" -Tag "Warn"
            continue
        }
        Write-Log "    removed $sid from the template's access control list" -Tag "Ok"
    }

    Set-AdcsTemplateOwner -TemplateEntry $TemplateEntry -CertificateServices $CertificateServices
}

# Taking the ACE off is only half of it. The owner of a new directory object is its
# creator, and when the creator belongs to Domain Admins the directory records Domain
# Admins as the owner - which is what happens here, because this script runs as one. An
# owner holds READ_CONTROL and WRITE_DAC whatever the access control list says, so the
# group just stripped from every template can put itself straight back on all of them,
# and nothing in the console suggests it. Handing the templates to the group that is
# meant to hold them is what makes the removal mean something.
function Set-AdcsTemplateOwner {
    param(
        [Parameter(Mandatory)][object]$TemplateEntry,
        [Parameter(Mandatory)][object]$CertificateServices
    )

    $roleGroups = Get-ConfigValue -InputObject $CertificateServices -Name "roleGroups"
    if ($null -eq $roleGroups) { return }

    $manager = @(Get-ConfigArray -InputObject $roleGroups -Name "groups" |
        Where-Object { [string](Get-ConfigText -InputObject $_ -Name "role" -Default "") -eq "templateManager" })
    if ($manager.Count -eq 0) { return }
    $managerName = [string](Get-ConfigText -InputObject $manager[0] -Name "name" -Default "")
    if ([string]::IsNullOrWhiteSpace($managerName)) { return }

    $sidValue = Get-AdcsPrincipalSidValue -Name $managerName
    if ($null -eq $sidValue) { return }
    $sid = New-Object System.Security.Principal.SecurityIdentifier($sidValue)

    try {
        $TemplateEntry.RefreshCache(@("nTSecurityDescriptor"))
        $current = $TemplateEntry.ObjectSecurity.GetOwner([System.Security.Principal.SecurityIdentifier])
        if (($null -ne $current) -and ([string]$current -eq $sidValue)) {
            Write-Log "    '$managerName' already owns this template" -Tag "Debug"
            return
        }

        $security = $TemplateEntry.ObjectSecurity
        $security.SetOwner($sid)
        $TemplateEntry.ObjectSecurity = $security
        $TemplateEntry.CommitChanges()
    }
    catch {
        # Windows lets a caller holding WRITE_OWNER set the owner to itself or to a group
        # it is a member of; anything else wants SeRestorePrivilege. The role groups this
        # run creates are seeded with Domain Admins, so the account usually is a member -
        # but only in a token minted after the group existed, which a session that just
        # created it is not. Say what to run rather than failing the templates over it.
        Write-Log "    could not hand ownership to '$managerName': $($_.Exception.Message)" -Tag "Warn"
        Write-Log "    Domain Admins still owns this template, and an owner can restore its own access whatever the ACL says" -Tag "Warn"
        Write-Log "    Sign in again so the token carries the group and re-run, or set it on the template's Advanced security page" -Tag "Info"
        return
    }

    Write-Log "    '$managerName' now owns this template" -Tag "Ok"
}

function Set-AdcsTemplateEnrollmentAcl {
    param(
        [Parameter(Mandatory)][object]$TemplateEntry,
        [Parameter(Mandatory)][object]$Template
    )

    # SIDs, not names: what this design wanted is compared against what the template
    # holds, and the two are the same principal under two spellings often enough that
    # comparing the spellings is how a grant this run just wrote gets reported as
    # somebody else's.
    $wanted = @()
    foreach ($pair in @(@{ Name = "autoEnrollPrincipals"; Auto = $true }, @{ Name = "enrollPrincipals"; Auto = $false })) {
        foreach ($principal in (Get-ConfigArray -InputObject $Template -Name $pair.Name)) {
            $resolved = Resolve-AdcsEnrollmentPrincipal -Entry $principal
            if ($null -eq $resolved) { continue }
            if ($null -eq $resolved.Sid) {
                Write-Log "Could not resolve '$($resolved.Label)' - nothing was granted on this template" -Tag "Error"
                $script:adcsGrantFailure += $resolved.Label
                continue
            }
            $wanted += [string]$resolved.Sid.Value
            if ($pair.Auto) {
                $null = Grant-AdcsTemplateEnrollment -TemplateEntry $TemplateEntry -Principal $resolved.Label -Sid $resolved.Sid -AutoEnroll
            }
            else {
                $null = Grant-AdcsTemplateEnrollment -TemplateEntry $TemplateEntry -Principal $resolved.Label -Sid $resolved.Sid
            }
        }
    }

    Write-AdcsTemplateExtraEnrollment -TemplateEntry $TemplateEntry -WantedSid $wanted
}



# Reports rather than removes. An enrollment right this design did not put there is
# worth knowing about - it is how a template ends up wider than the page describing
# it - but stripping ACEs the operator added by hand is not this script's call.
function Write-AdcsTemplateExtraEnrollment {
    param(
        [Parameter(Mandatory)][object]$TemplateEntry,
        # The SIDs this design granted, as strings. Names were compared here once, and a
        # localised name is not the one in the catalogue: on a German domain every grant
        # this run wrote came back reported as coming from outside the design.
        [string[]]$WantedSid = @()
    )

    try {
        $rules = $TemplateEntry.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    }
    catch {
        Write-Log "Could not read the template's existing permissions: $($_.Exception.Message)" -Tag "Debug"
        return
    }

    $extra = @()
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        if ($rule.ActiveDirectoryRights -ne [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) { continue }
        if (($rule.ObjectType -ne $script:adcsEnrollRight) -and ($rule.ObjectType -ne $script:adcsAutoEnrollRight)) { continue }

        $sidValue = Get-AdcsAccessRuleSid -Rule $rule
        if ([string]::IsNullOrWhiteSpace($sidValue)) { continue }
        if ($WantedSid -contains $sidValue) { continue }

        # Reported by name where this machine has one, because a bare SID sends the
        # reader to the security tab to find out what it is.
        $identity = Get-AdcsSidAccountName -Sid (New-Object System.Security.Principal.SecurityIdentifier($sidValue))
        if ([string]::IsNullOrWhiteSpace($identity)) { $identity = $sidValue }
        if ($extra -contains $identity) { continue }
        $extra += $identity
    }

    if ($extra.Count -eq 0) { return }
    Write-Log "Also holds an enrollment right on this template, from outside this design: $($extra -join ', ')" -Tag "Info"
}

# The design resolves the pair to numbers - it holds the table of Windows releases,
# and this side has no business carrying a second copy of it. Missing or partial means
# the studio's own default, which is the highest level in that table: a config written
# before this setting existed produced 2016-compatible templates, and quietly dropping
# them to schema 2 because a key is absent would be the worst possible reading.
function Get-AdcsTemplateCompatibility {
    param([object]$Templates)

    $compatibility = Get-ConfigValue -InputObject $Templates -Name "compatibility"
    $resolved = [pscustomobject]@{
        Level         = [string](Get-ConfigText -InputObject $compatibility -Name "level" -Default "WindowsServer2016")
        SchemaVersion = [int](Get-ConfigValue -InputObject $compatibility -Name "schemaVersion" -Default $script:adcsTemplateSchemaVersion)
        CaVersion     = [int](Get-ConfigValue -InputObject $compatibility -Name "caVersion" -Default $script:adcsTemplateCaVersion)
        ClientVersion = [int](Get-ConfigValue -InputObject $compatibility -Name "clientVersion" -Default $script:adcsTemplateClientVersion)
    }

    if (($resolved.SchemaVersion -lt 2) -or ($resolved.SchemaVersion -gt 4)) {
        Write-Log "Template schema '$($resolved.SchemaVersion)' is not one this script writes - using $($script:adcsTemplateSchemaVersion)" -Tag "Warn"
        $resolved.SchemaVersion = $script:adcsTemplateSchemaVersion
    }

    Write-Log "Templates: schema $($resolved.SchemaVersion), compatibility $($resolved.Level)" -Tag "Info"
    return $resolved
}

# Every setting the design states, applied to a template object - the one that has just
# been duplicated, or one that already existed and is being overridden. Extracted from
# Copy-AdcsCertificateTemplate rather than written twice: two copies of the flag
# arithmetic below would disagree within a release, and the ESC9 clear and the manager
# approval bit are exactly the settings that must not differ between the create path and
# the override path.
#
# $Source is the built-in template this one was duplicated from, and is only read for
# the extended key usage fallback - so an override with no resolvable source still works
# as long as the design names a purpose, which every entry in TEMPLATE_CATALOG does.
function Set-AdcsTemplateDesignedSetting {
    param(
        [Parameter(Mandatory)][object]$Entry,
        [object]$Source,
        [string]$SourceName = "",
        [Parameter(Mandatory)][object]$Template,
        [Parameter(Mandatory)][object]$Compatibility,
        [Parameter(Mandatory)][string]$DisplayName
    )

    Set-AdcsDirectoryProperty -Entry $Entry -Name "msPKI-Minimal-Key-Size" -Value ([int](Get-ConfigValue -InputObject $Template -Name "minimalKeySize" -Default 2048))

    if ($Compatibility.SchemaVersion -ge 3) {
        # Key Storage Provider, RSA, SHA-256 - replacing the CryptoAPI defaults the
        # built-in templates still carry. The algorithm names go into
        # msPKI-RA-Application-Policies; there are no attributes of those names.
        #
        # The provider is a per-template value because one template genuinely needs a
        # different one. A certificate meant to live in the Windows Hello for Business
        # container has to be created by the **Microsoft Passport Key Storage Provider**
        # - that is what puts the private key behind the TPM and the user's PIN or
        # biometric, and what makes Windows treat the certificate as a smart card. There
        # is no console field for it: Microsoft's own instruction is to dump the template
        # with certutil -dstemplate, edit pKIDefaultCSPs in the text file and load it
        # back with -dsaddtemplate. It is one directory attribute, and this script is
        # already writing every other attribute on this object, so it writes that one too.
        $hashAlgorithm = [string](Get-ConfigValue -InputObject $Template -Name "hashAlgorithm" -Default "SHA256")
        $provider = [string](Get-ConfigText -InputObject $Template -Name "keyStorageProvider" -Default "Microsoft Software Key Storage Provider")
        Set-AdcsDirectoryProperty -Entry $Entry -Name "pKIDefaultCSPs" -Value ("1,{0}" -f $provider)
        Set-AdcsDirectoryProperty -Entry $Entry -Name "msPKI-RA-Application-Policies" -Value ($script:adcsCngPolicyFormat -f $hashAlgorithm)
        if ($provider -ne "Microsoft Software Key Storage Provider") {
            Write-Log "'$DisplayName' requires the $provider" -Tag "Info"
        }
    }
    else {
        # Schema version 2 predates CNG. The Key Storage Provider does not exist at this
        # version, and the block the algorithm settings live in is read as a list of RA
        # policy OIDs rather than as name`type`value triples (MS-CRTD 2.23.1) - writing
        # the CNG string here would not be ignored, it would be misread. Legacy
        # providers instead, and the hash is whatever the CA signs with.
        Set-AdcsDirectoryProperty -Entry $Entry -Name "pKIDefaultCSPs" -Value ([string[]]@(
            "1,Microsoft RSA SChannel Cryptographic Provider",
            "2,Microsoft Enhanced Cryptographic Provider v1.0"))
        Write-Log "'$DisplayName' is schema 2 - legacy providers, no hash algorithm" -Tag "Info"
    }

    # The key usage extension, stated by the design rather than inherited from whatever
    # built-in this template was duplicated from. It matters more here than it looks,
    # and for a different reason in each connector mode:
    #
    #   SCEP  NDES picks which of its three registry slots serves a request by the key
    #         usage in the CSR, and the template at the end of that slot has to agree -
    #         so the one attribute the whole slot model rests on must not be whatever
    #         CN=WebServer happens to carry in this forest.
    #   PKCS  there is no slot and no routing, and a PKCS profile has no key usage field
    #         at all - so the template is the ONLY thing that states it and nothing
    #         downstream can correct a template that carries the wrong pair.
    #
    # A built-in can be edited, and this one is load-bearing either way.
    #
    #   0x80  digitalSignature                     console purpose "Signature"
    #   0x20  keyEncipherment                      console purpose "Encryption"
    #   0xA0  both                                 console purpose "Signature and encryption"
    #
    # Absent means inherited, which is what every template that does not state one wants.
    $keyUsage = Get-ConfigValue -InputObject $Template -Name "keyUsage"
    if ($null -ne $keyUsage) {
        $usageByte = [byte]([int]$keyUsage -band 0xFF)
        Set-AdcsDirectoryProperty -Entry $Entry -Name "pKIKeyUsage" -Value ([byte[]]@($usageByte))
        Write-Log ("'{0}' key usage 0x{1:X2}{2}" -f $DisplayName, $usageByte, $(
            switch ($usageByte) {
                0x80 { " - signature" }
                0x20 { " - encryption" }
                0xA0 { " - signature and encryption" }
                default { "" }
            })) -Tag "Debug"
    }

    # AT_KEYEXCHANGE (1) or AT_SIGNATURE (2). Legacy on a CNG template, and stated
    # anyway for the one that needs it: Microsoft's smart card requirements say a smart
    # card logon certificate must have a key exchange private key type, and inheriting
    # that from a built-in is the same bet as above.
    $keySpec = Get-ConfigValue -InputObject $Template -Name "keySpec"
    if ($null -ne $keySpec) {
        Set-AdcsDirectoryProperty -Entry $Entry -Name "pKIDefaultKeySpec" -Value ([int]$keySpec)
    }

    $validityPeriod = [string](Get-ConfigValue -InputObject $Template -Name "validityPeriod" -Default "Years")
    $validityUnits  = [int](Get-ConfigValue -InputObject $Template -Name "validityUnits" -Default 1)
    $renewalPeriod  = [string](Get-ConfigValue -InputObject $Template -Name "renewalPeriod" -Default "Weeks")
    $renewalUnits   = [int](Get-ConfigValue -InputObject $Template -Name "renewalUnits" -Default 6)
    Set-AdcsDirectoryProperty -Entry $Entry -Name "pKIExpirationPeriod" -Value (ConvertTo-AdcsPeriodByte -Period $validityPeriod -Units $validityUnits)
    Set-AdcsDirectoryProperty -Entry $Entry -Name "pKIOverlapPeriod"    -Value (ConvertTo-AdcsPeriodByte -Period $renewalPeriod -Units $renewalUnits)

    $nameFlag   = [int]$Entry.Properties["msPKI-Certificate-Name-Flag"].Value
    $keyFlag    = [int]$Entry.Properties["msPKI-Private-Key-Flag"].Value
    $enrollFlag = [int]$Entry.Properties["msPKI-Enrollment-Flag"].Value

    if ([bool](Get-ConfigValue -InputObject $Template -Name "enrolleeSuppliesSubject" -Default $false)) {
        $nameFlag = $nameFlag -bor $script:ctFlagEnrolleeSuppliesSubject
    }
    # Set *and* cleared, on both attributes that carry it. Export is a decision the design
    # makes rather than a setting it inherits: a schema 1 source states its own answer in
    # the legacy flags attribute, that value is copied wholesale a few lines up, and a
    # template whose two export bits disagree is a template whose behaviour depends on
    # which one the client happens to read.
    $legacyFlags   = [int]$Entry.Properties["flags"].Value
    $allowKeyExport = [bool](Get-ConfigValue -InputObject $Template -Name "allowPrivateKeyExport" -Default $false)
    if ($allowKeyExport) {
        $keyFlag     = $keyFlag -bor $script:ctFlagExportableKey
        $legacyFlags = $legacyFlags -bor $script:ctFlagLegacyExportableKey
    }
    else {
        $keyFlag     = $keyFlag -band (-bnot $script:ctFlagExportableKey)
        $legacyFlags = $legacyFlags -band (-bnot $script:ctFlagLegacyExportableKey)
    }
    Set-AdcsDirectoryProperty -Entry $Entry -Name "flags" -Value $legacyFlags

    # Strong private key protection, and the consent prompt that goes with it. The two are
    # one console radio button and two attributes: without the second the key is protected
    # and nobody is asked, which on the software provider means no prompt at all. On a
    # smart card or a hardware module the provider asks for its PIN either way, so this
    # costs nothing there and is the whole control on a software key.
    if ([bool](Get-ConfigValue -InputObject $Template -Name "strongKeyProtection" -Default $false)) {
        $keyFlag    = $keyFlag -bor $script:ctFlagStrongKeyProtection
        $enrollFlag = $enrollFlag -bor $script:ctFlagUserInteractionRequired
        Write-Log "'$DisplayName': strong private key protection" -Tag "Info"
    }
    else {
        $keyFlag    = $keyFlag -band (-bnot $script:ctFlagStrongKeyProtection)
        $enrollFlag = $enrollFlag -band (-bnot $script:ctFlagUserInteractionRequired)
    }

    # Basic Constraints with cA=FALSE on an end-entity certificate. Only App Control for
    # Business asks for it, and it asks on the certificate that signs a policy - a policy
    # signed by a certificate Windows will not accept is a boot failure, not an error
    # message, which is why this is a stated setting rather than an inherited one.
    if ([bool](Get-ConfigValue -InputObject $Template -Name "includeBasicConstraints" -Default $false)) {
        $enrollFlag = $enrollFlag -bor $script:ctFlagIncludeBasicConstraints
        Write-Log "'$DisplayName': Basic Constraints cA=FALSE" -Tag "Info"
    }
    else {
        $enrollFlag = $enrollFlag -band (-bnot $script:ctFlagIncludeBasicConstraints)
    }

    # The compatibility pair, masked out of the copied value before it is set: these
    # two fields are enumerations sharing one attribute with the bit flags above, so
    # OR-ing without clearing them first would merge a source's version into ours and
    # produce a number that means neither.
    $keyFlag = ($keyFlag -band (-bnot $script:adcsTemplateVersionMask)) -bor
        $Compatibility.CaVersion -bor $Compatibility.ClientVersion

    # A template where the requester names the subject and nobody reviews the result
    # issues whatever was asked for, to whoever asked. Manager approval is what turns
    # that into a request somebody has to look at first.
    if ([bool](Get-ConfigValue -InputObject $Template -Name "requireManagerApproval" -Default $false)) {
        $enrollFlag = $enrollFlag -bor $script:ctFlagPendAllRequests
        Write-Log "'$DisplayName': manager approval" -Tag "Info"
    }
    else {
        $enrollFlag = $enrollFlag -band (-bnot $script:ctFlagPendAllRequests)
    }

    # The Autoenroll right on the ACL is only half of it - without this bit the client
    # never asks, and the template looks configured while nothing is ever issued.
    # Cleared explicitly when the design grants no autoenrollment, so a copied source
    # cannot turn it on behind the design's back.
    if ((Get-ConfigArray -InputObject $Template -Name "autoEnrollPrincipals").Count -gt 0) {
        $enrollFlag = $enrollFlag -bor $script:ctFlagAutoEnrollment
    }
    else {
        $enrollFlag = $enrollFlag -band (-bnot $script:ctFlagAutoEnrollment)
    }

    # Publication into the requester's directory object. Off unless the design asks for
    # it: every template here issues an authentication certificate, which nobody looks
    # up in the directory, and the one that matters is the Intune connector's - the
    # PKCS guide has "Deselect Publish certificate in Active Directory" as a numbered
    # step. Cleared rather than left alone for the same reason as the bit above: a
    # source template carrying it would turn it on behind the design's back.
    if ([bool](Get-ConfigValue -InputObject $Template -Name "publishToDirectory" -Default $false)) {
        $enrollFlag = $enrollFlag -bor $script:ctFlagPublishToDs
        Write-Log "'$DisplayName': published to the directory" -Tag "Info"
    }
    else {
        $enrollFlag = $enrollFlag -band (-bnot $script:ctFlagPublishToDs)
    }

    # ESC9. The bit suppresses the SID extension on everything this template issues,
    # which downgrades every one of those certificates to the weak UPN mapping. The only
    # way it arrives is a source template somebody edited, so it is cleared, not copied.
    if (($enrollFlag -band $script:ctFlagNoSecurityExtension) -ne 0) {
        Write-Log "'$SourceName' carries CT_FLAG_NO_SECURITY_EXTENSION (ESC9) - cleared on '$DisplayName'; check who edited the source" -Tag "Warn"
        $enrollFlag = $enrollFlag -band (-bnot $script:ctFlagNoSecurityExtension)
    }

    # The subject and SAN settings are inherited, never written - they are the source
    # template's, which is the point of duplicating that particular one. Logged in hex
    # because the one that matters here is invisible everywhere else: the certificate
    # templates console has checkboxes for the DNS name, the UPN and the SPN, and none
    # for CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS. That flag puts the *domain's* DNS name
    # in the SAN, which is what proves the holder is a domain controller for that domain
    # and what Strict KDC Validation checks. Only 'Kerberos Authentication' carries it;
    # Domain Controller and Domain Controller Authentication do not, which is the entire
    # reason the deployment guide says to copy that template and no other.
    if ($SourceName.Equals("KerberosAuthentication", [System.StringComparison]::OrdinalIgnoreCase) -and
        (($nameFlag -band $script:ctFlagSubjectAltRequireDomainDns) -eq 0)) {
        Write-Log "'$SourceName' lost CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS - '$DisplayName' carries no domain in its SAN, which Strict KDC Validation needs" -Tag "Warn"
    }
    Write-Log ("'{0}' name flags 0x{1:X8}, key flags 0x{2:X8}, enrollment flags 0x{3:X8}" -f $DisplayName, $nameFlag, $keyFlag, $enrollFlag) -Tag "Debug"

    Set-AdcsDirectoryProperty -Entry $Entry -Name "msPKI-Certificate-Name-Flag" -Value $nameFlag
    Set-AdcsDirectoryProperty -Entry $Entry -Name "msPKI-Private-Key-Flag" -Value $keyFlag
    Set-AdcsDirectoryProperty -Entry $Entry -Name "msPKI-Enrollment-Flag" -Value $enrollFlag

    # Two attributes carry the purpose and they must agree: pKIExtendedKeyUsage becomes
    # the EKU extension, msPKI-Certificate-Application-Policy the application policy
    # extension - and the application policy is what a v2+ template, the console and
    # most consumers actually read.
    #
    # A **schema v1** source has no application policy attribute at all: it predates
    # the concept, and 'CN=WebServer' is one of them. Copying it gives a v3 template
    # with an EKU and no application policy, which the console reports as intended
    # purpose <All> - and 'all' is not cosmetic on a template whose requester names its
    # own subject and exports its own key. So whatever the purpose ends up being, it is
    # written to both attributes here rather than inherited from whichever attribute
    # the source happened to have.
    $extendedKeyUsage = @(Get-ConfigArray -InputObject $Template -Name "extendedKeyUsage")
    if ($extendedKeyUsage.Count -eq 0) {
        # Remote Desktop Authentication replaces the source's list; everything else
        # keeps it, whichever of the two attributes it arrived in.
        # Each candidate is emptied of blanks *before* its count decides anything:
        # @($null) is an array of length one, so an absent attribute would otherwise
        # read as "found something" and stop the fallback from ever being tried.
        foreach ($attribute in @("pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy")) {
            if ($null -eq $Source) { break }
            $candidate = @(@($Source.Properties[$attribute].Value) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
            if ($candidate.Count -gt 0) {
                $extendedKeyUsage = $candidate
                break
            }
        }
    }

    if ($extendedKeyUsage.Count -gt 0) {
        Set-AdcsDirectoryProperty -Entry $Entry -Name "pKIExtendedKeyUsage" -Value ([string[]]$extendedKeyUsage)
        Set-AdcsDirectoryProperty -Entry $Entry -Name "msPKI-Certificate-Application-Policy" -Value ([string[]]$extendedKeyUsage)
        Write-Log "Extended key usage set to $($extendedKeyUsage -join ', ')" -Tag "Debug"
    }
    else {
        # Neither the design nor the source names a purpose. That is a certificate good
        # for every purpose there is, client authentication included, which is the half
        # of ESC1 that is not about the subject name.
        Write-Log "'$DisplayName' has no extended key usage - valid for every purpose, client authentication included" -Tag "Warn"
        Write-Log "Give the template an extendedKeyUsage in the design unless that is genuinely wanted" -Tag "Warn"
    }

    $supersede = Get-ConfigArray -InputObject $Template -Name "supersedeTemplates"
    if ($supersede.Count -gt 0) {
        Set-AdcsDirectoryProperty -Entry $Entry -Name "msPKI-Supersede-Templates" -Value ([string[]]$supersede)
    }
}

function Copy-AdcsCertificateTemplate {
    param(
        [Parameter(Mandatory)][object]$Template,
        [Parameter(Mandatory)][string]$ConfigurationNamingContext,
        [Parameter(Mandatory)][object]$Compatibility,
        # Only for the built-in administrator removal, which is a role-group decision
        # and so lives in the section this template's own entry knows nothing about.
        [Parameter(Mandatory)][object]$CertificateServices,
        # issuing.templates.overwriteExisting. Off unless the design says otherwise -
        # see the existing-object branch below for what it changes and why the default
        # is the other way round.
        [bool]$OverwriteExisting = $false
    )

    $templatesDn  = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigurationNamingContext"
    $sourceName   = [string](Get-ConfigValue -InputObject $Template -Name "sourceTemplate" -Default "")
    $displayName  = [string](Get-ConfigValue -InputObject $Template -Name "displayName" -Default "")
    # The console derives the object name by stripping the spaces out of the display
    # name, and everything downstream refers to the template by that name.
    $templateName = [string](Get-ConfigValue -InputObject $Template -Name "templateName" -Default ($displayName -replace "\s", ""))

    # Before anything is read or written. A name that collides with a built-in never
    # reaches the create path - it reaches the "already exists" path below and takes
    # Microsoft's own template as the thing to reconcile, which is how a design that
    # states 3072-bit keys, manager approval and one EKU ends up publishing a schema 1
    # template with none of them. Nothing about that is visible in the log.
    if ($script:adcsBuiltInTemplateNames -contains $templateName) {
        throw ("'$templateName' is the name of a template Windows ships, so this design would edit or publish the built-in " +
            "rather than build its own. Give it a different template name in the studio - '$displayName' currently resolves to CN=$templateName.")
    }

    $targetDn = "CN=$templateName,$templatesDn"
    if ((Test-StudioDirectoryObject -DistinguishedName $targetDn)) {
        $existing = Get-AdcsDirectoryEntry -DistinguishedName $targetDn

        if (-not $OverwriteExisting) {
            # Its settings are left alone - the object may have been tuned by hand since.
            # The enrollment rights are not: they are the design, they change between
            # runs, and a grant that failed the first time has to be retried, or "create
            # the group and run this again" would never be true.
            Write-Log "Template '$templateName' exists - settings left alone, enrollment rights reconciled" -Tag "Info"
            Set-AdcsTemplateEnrollmentAcl -TemplateEntry $existing -Template $Template
            Remove-AdcsTemplateSystemAce -TemplateEntry $existing
            Remove-AdcsTemplateBuiltinAdmin -TemplateEntry $existing -CertificateServices $CertificateServices
            return $templateName
        }

        # Override. Every setting the design states is written over what is there; the
        # attributes it does not state are left, because "make it match the design" is
        # not the same instruction as "delete anything the design forgot to mention".
        # The object's identity - its name, its OID, the certificates already issued
        # from it - is untouched, which is what makes this different from deleting it
        # and duplicating a fresh one.
        Write-Log "Template '$templateName' exists and the design overrides it - applying this design's settings" -Tag "Warn"

        # Only for the extended key usage fallback, and only when the design names no
        # purpose. A source that has since been removed from the forest is not a reason
        # to refuse the override.
        $overrideSource = $null
        $sourceDnForOverride = "CN=$sourceName,$templatesDn"
        if (-not [string]::IsNullOrWhiteSpace($sourceName) -and
            (Test-StudioDirectoryObject -DistinguishedName $sourceDnForOverride)) {
            $overrideSource = Get-AdcsDirectoryEntry -DistinguishedName $sourceDnForOverride
        }

        Set-AdcsDirectoryProperty -Entry $existing -Name "displayName" -Value $displayName
        Set-AdcsTemplateDesignedSetting -Entry $existing -Source $overrideSource -SourceName $sourceName `
            -Template $Template -Compatibility $Compatibility -DisplayName $displayName

        # The revision is what makes the change reach anybody. A template edited without
        # it is a template the CA keeps serving from cache and autoenrollment sees no
        # reason to act on - the major number is the one that means "re-enrol, this is
        # not the certificate you were issued", and the console resets the minor when it
        # bumps the major. Both are read back rather than assumed: this object's history
        # is not this design's to know.
        $currentRevision = 100
        try { $currentRevision = [int]$existing.Properties["revision"].Value } catch { $currentRevision = 100 }
        if ($currentRevision -lt 100) { $currentRevision = 100 }
        Set-AdcsDirectoryProperty -Entry $existing -Name "revision" -Value ($currentRevision + 1)
        Set-AdcsDirectoryProperty -Entry $existing -Name "msPKI-Template-Minor-Revision" -Value 0

        try {
            $existing.CommitChanges()
        }
        catch {
            throw "Could not override the template '$templateName': $($_.Exception.Message)"
        }
        Write-Log "Template '$displayName' overridden - revision $($currentRevision + 1)" -Tag "Ok"

        Set-AdcsTemplateEnrollmentAcl -TemplateEntry $existing -Template $Template
        Remove-AdcsTemplateSystemAce -TemplateEntry $existing
        Remove-AdcsTemplateBuiltinAdmin -TemplateEntry $existing -CertificateServices $CertificateServices
        return $templateName
    }

    $sourceDn = "CN=$sourceName,$templatesDn"
    if (-not (Test-StudioDirectoryObject -DistinguishedName $sourceDn)) {
        throw "The template '$sourceName' this one is copied from does not exist in the forest."
    }

    $source = Get-AdcsDirectoryEntry -DistinguishedName $sourceDn
    $container = Get-AdcsDirectoryEntry -DistinguishedName $templatesDn

    Write-Log "Duplicating '$sourceName' as '$displayName'" -Tag "Run"
    $new = $container.Children.Add("CN=$templateName", "pKICertificateTemplate")

    foreach ($attribute in $script:adcsTemplateCopyAttributes) {
        Set-AdcsDirectoryProperty -Entry $new -Name $attribute -Value $source.Properties[$attribute].Value
    }

    Set-AdcsDirectoryProperty -Entry $new -Name "displayName" -Value $displayName
    Set-AdcsDirectoryProperty -Entry $new -Name "revision" -Value 100
    Set-AdcsDirectoryProperty -Entry $new -Name "msPKI-Template-Minor-Revision" -Value 0
    Set-AdcsDirectoryProperty -Entry $new -Name "msPKI-Template-Schema-Version" -Value $Compatibility.SchemaVersion
    Set-AdcsDirectoryProperty -Entry $new -Name "msPKI-Cert-Template-OID" -Value (New-AdcsTemplateOid -ConfigurationNamingContext $ConfigurationNamingContext -DisplayName $displayName)

    Set-AdcsTemplateDesignedSetting -Entry $new -Source $source -SourceName $sourceName -Template $Template -Compatibility $Compatibility -DisplayName $displayName

    try {
        $new.CommitChanges()
    }
    catch {
        throw "Could not create the template '$templateName': $($_.Exception.Message)"
    }
    Write-Log "Template '$displayName' created" -Tag "Ok"

    Set-AdcsTemplateEnrollmentAcl -TemplateEntry $new -Template $Template
    Remove-AdcsTemplateSystemAce -TemplateEntry $new
    Remove-AdcsTemplateBuiltinAdmin -TemplateEntry $new -CertificateServices $CertificateServices

    return $templateName
}

# What a CA issues is one multi-valued attribute on its own Enrollment Services
# object, and that object is what the console writes when a template is published.
# The CN is the sanitized CA name - the same string the Active registry value holds.
function Get-AdcsEnrollmentServiceEntry {
    $caName = Get-AdcsActiveCaName
    if ([string]::IsNullOrWhiteSpace($caName)) {
        throw "This machine has no active certification authority to publish templates on."
    }

    $configurationNamingContext = Get-AdcsConfigurationNamingContext
    $enrollmentDn = "CN=$caName,CN=Enrollment Services,CN=Public Key Services,CN=Services,$configurationNamingContext"
    return Get-AdcsDirectoryEntry -DistinguishedName $enrollmentDn
}

# What a NAMED CA publishes, read out of the configuration naming context rather than
# off the local machine. Get-AdcsEnrollmentServiceEntry answers for the CA running here,
# which is no help on the NDES box - that server has no CA and still needs to know what
# the issuing one publishes.
function Get-AdcsPublishedTemplateForCa {
    param([Parameter(Mandatory)][string]$CaCommonName)

    $configurationNamingContext = Get-AdcsConfigurationNamingContext
    $enrollmentDn = "CN=$CaCommonName,CN=Enrollment Services,CN=Public Key Services,CN=Services,$configurationNamingContext"
    if (-not (Test-StudioDirectoryObject -DistinguishedName $enrollmentDn)) {
        Write-Log "There is no enrollment services object for a CA called '$CaCommonName'" -Tag "Warn"
        return @()
    }
    return @(Get-AdcsPublishedTemplateFrom -Entry (Get-AdcsDirectoryEntry -DistinguishedName $enrollmentDn))
}

function Get-AdcsPublishedTemplateFrom {
    param([Parameter(Mandatory)][object]$Entry)

    $values = $Entry.Properties["certificateTemplates"]
    if ($null -eq $values) { return @() }

    $published = @()
    foreach ($value in $values) {
        $name = [string]$value
        if (-not [string]::IsNullOrWhiteSpace($name)) { $published += $name }
    }
    return $published
}

function Set-AdcsPublishedTemplate {
    param(
        [Parameter(Mandatory)][object]$Entry,
        [string[]]$TemplateName = @()
    )

    if ($TemplateName.Count -eq 0) {
        # Set-AdcsDirectoryProperty leaves an attribute alone when handed an empty
        # array, which is right everywhere else and wrong here: withdrawing the last
        # template means the attribute has to be cleared, not skipped.
        $Entry.Properties["certificateTemplates"].Clear()
    }
    else {
        Set-AdcsDirectoryProperty -Entry $Entry -Name "certificateTemplates" -Value ([string[]]$TemplateName)
    }
    $Entry.CommitChanges()
}

# Written straight into the directory rather than through 'certutil -SetCATemplates'.
# That command resolves the name against the client's certificate template cache
# before it writes anything, and a template created seconds earlier is not in it yet:
# every publish of a freshly duplicated template failed with "Element not found /
# Invalid Template" (0x80070490) while the object sat in the Configuration NC, ACEs
# and all. The attribute write is the same operation the console performs, it needs
# no lookup, and it is idempotent - so a re-run is a no-op rather than a second entry.
function Publish-AdcsTemplate {
    param([Parameter(Mandatory)][string]$TemplateName)

    $entry = Get-AdcsEnrollmentServiceEntry
    # @() is load-bearing: a one-element return unrolls to a bare string, and '+' on a
    # string concatenates rather than appends - which published one value named
    # 'WebServicesRemoteDesktopAuthentication...' and nothing the CA could issue.
    $published = @(Get-AdcsPublishedTemplateFrom -Entry $entry)
    if ($published -contains $TemplateName) {
        Write-Log "'$TemplateName' is already published on this CA" -Tag "Debug"
        return
    }

    Set-AdcsPublishedTemplate -Entry $entry -TemplateName ($published + $TemplateName)
    Write-Log "Published '$TemplateName' on this CA" -Tag "Ok"
}

function Unpublish-AdcsTemplate {
    param([Parameter(Mandatory)][string]$TemplateName)

    $entry = Get-AdcsEnrollmentServiceEntry
    $published = @(Get-AdcsPublishedTemplateFrom -Entry $entry)
    if ($published -notcontains $TemplateName) {
        Write-Log "'$TemplateName' is not published here - nothing to withdraw" -Tag "Debug"
        return
    }

    $remaining = @($published | Where-Object { $_ -ne $TemplateName })
    Set-AdcsPublishedTemplate -Entry $entry -TemplateName $remaining
    Write-Log "Withdrew '$TemplateName' - superseded by the new template" -Tag "Ok"
}

# A CA issues only what is published to it, so the smallest useful list is the one
# the design actually asks for. This withdraws the rest from *this CA* - it does not
# delete the template objects, which are forest-wide and may be published elsewhere.
function Get-AdcsPublishedTemplate {
    return @(Get-AdcsPublishedTemplateFrom -Entry (Get-AdcsEnrollmentServiceEntry))
}

# The templates NDES enrolls its own registration authority certificates from. They are
# Windows built-ins, not catalogue entries, and the NDES configuration routine assigns
# them to the CA itself - which is exactly why the withdraw sweep would take them: they
# are published on the CA and named nowhere in the design.
#
# Withdrawing them does not break NDES today. It breaks it in two years, when the RA
# certificates expire and cannot be re-enrolled because the templates they came from are
# no longer published. A silent, delayed failure on the one component whose expiry
# everything else here is built to watch.
$script:adcsRaTemplateName = @("CEPEncryption", "EnrollmentAgentOffline")

# The three the NDES installer insists on, and which of them anything actually uses.
# Install-AdcsNetworkDeviceEnrollmentService tries to publish all three to the CA and to
# update their security, from the NDES server, and it fails as a batch:
#
#   Failed to add the following certificate templates to the enterprise Active Directory
#   Certificate Services or update security settings on those templates:
#       EnrollmentAgentOffline / CEPEncryption / IPSEC (Offline request)
#   Element not found. 0x80070490 (WIN32: 1168 ERROR_NOT_FOUND)
#
# 0x80070490 is the same certificate-template-cache failure Publish-AdcsTemplate exists
# to avoid: the name is resolved against a cache on the machine doing the write, and the
# NDES server is not the CA. Publication is a CA decision made on the CA, which is where
# every other template in this design is published - so it is done here, on the issuing
# CA run, and the NDES installer finds all three already there. Field-verified
# 2026-08-16: without this, a first NDES configuration on a clean build cannot complete.
#
# IPSECIntermediateOffline is in the list and nothing in this design enrolls from it,
# and that stays true - it is here because the installer refuses to work without it, and
# that was TESTED rather than assumed. Field experiment 2026-08-16, same day, both
# directions: with all three published the configuration proceeds; with only the two RA
# templates published, a clean build failed 0x80070490 naming ALL THREE - the published
# two included - because the installer processes the batch atomically and cannot publish
# its own third from a member server. So the design publishes all three, gives the IPSec
# one no group and no grant (nothing ever enrolls from it; its Enroll stays Domain and
# Enterprise Admins, and its EKU is IKE intermediate, not an authentication EKU), and
# repoints the MSCEP slots away from it minutes after the installer writes them.
$script:adcsNdesTemplate = @(
    [pscustomobject]@{
        Name    = "CEPEncryption"
        Display = "CEP Encryption"
        Why     = "NDES enrolls one at configuration time - it encrypts the SCEP exchange with the device"
        # The enrollee is the NDES server's COMPUTER account, and the default ACL on this
        # built-in grants Enroll to Domain Admins and Enterprise Admins and nobody else -
        # so a configuration run by an Enterprise Admin still fails, because the identity
        # asking for this one is not the identity typing. Field-hit 2026-08-16:
        # CMSCEPSetup::Install: Access is denied. 0x80070005.
        GroupKey = "cepEncryption"
    }
    [pscustomobject]@{
        Name    = "EnrollmentAgentOffline"
        Display = "Exchange Enrollment Agent (Offline request)"
        Why     = "NDES enrolls one at configuration time - it re-signs a device's request on its behalf"
        # Enrolled by the USER running the configuration, not by the machine - so its
        # group ships empty and the run says so: Domain and Enterprise Admins hold Enroll
        # on this built-in already, and who else may act as an enrollment agent is a
        # decision, never a default.
        GroupKey = "enrollmentAgent"
    }
    [pscustomobject]@{
        Name    = "IPSECIntermediateOffline"
        Display = "IPSEC (Offline request)"
        Why     = "nothing here enrolls from it - the NDES installer demands it for its own default MSCEP slots and fails its whole template batch without it (field-tested 2026-08-16)"
        # No GroupKey on purpose: a group grants Enroll, and nobody ever enrolls from
        # this one. Publication is the entire requirement.
    }
)

function Publish-AdcsNdesTemplate {
    param([Parameter(Mandatory)][object]$CertificateServices)

    # Only where this design has a SCEP tier. A CA with no NDES needs none of these, and
    # an Exchange Enrollment Agent template published where nothing uses it is a
    # certificate that requests certificates on behalf of other subjects.
    if ($null -eq (Get-AdcsScepSection -CertificateServices $CertificateServices)) { return }

    # And only in SCEP mode. These three are the templates the NDES INSTALLER insists
    # on - CEP Encryption and the offline enrollment agent are the registration
    # authority pair, IPSEC (Offline request) is published only so the installer's
    # atomic batch succeeds. The PKCS connector enrols none of them: it has no
    # registration authority, it talks to the CA directly as its own machine account.
    # Publishing them for a PKCS design put an enrollment-agent template into a forest
    # with nothing to use it, and then warned twice about RA groups that mode never
    # creates. Field-hit 2026-09-19 on a German forest.
    if ((Get-AdcsConnectorMode -CertificateServices $CertificateServices) -ne "scep") {
        Write-Log "The connector is in PKCS mode - NDES's registration authority templates are not needed and are left alone" -Tag "Info"

        # And say so here rather than leaving it to the connector's own run: this is the
        # CA, it is where the templates are written, and a PKCS design that names none
        # produces a connector with nothing to enrol and a group with nothing to hold.
        # Silence at this point is what let one run look successful and do nothing.
        $connector = Get-AdcsTierSection -CertificateServices $CertificateServices -TierName "scep"
        $named = @(Get-ConfigArray -InputObject $connector -Name "templateNames" | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        if ($named.Count -eq 0) {
            Write-Log "The PKCS connector names NO certificate template, so this CA publishes none for it" -Tag "Warn"
            Write-Log "    turn a template on under 'Templates this connector issues' in the studio and export again" -Tag "Warn"
        }
        else {
            Write-Log "The PKCS connector asks for: $($named -join ', ')" -Tag "Info"

            # Named implies built. The studio asserts this on export and corrects it on
            # import, and it is asserted again here because a config can reach a CA
            # without passing through either - by hand, or from a build old enough to
            # predate the check. The symptom without this is a run that reports success
            # on the CA and a connector run minutes later saying both of its templates
            # are missing, with nothing joining the two.
            $issuing = Get-ConfigValue -InputObject $CertificateServices -Name "issuing"
            $templates = Get-ConfigValue -InputObject $issuing -Name "templates"
            $built = @()
            foreach ($item in @(Get-ConfigArray -InputObject $templates -Name "items")) {
                $itemName = [string](Get-ConfigText -InputObject $item -Name "templateName" -Default "")
                if (-not [string]::IsNullOrWhiteSpace($itemName)) { $built += $itemName }
            }
            foreach ($wanted in $named) {
                $match = @($built | Where-Object { $_.Equals($wanted, [System.StringComparison]::OrdinalIgnoreCase) })
                if ($match.Count -gt 0) { continue }
                Write-Log "The connector asks for '$wanted' but this design does not build it - nothing here will publish it" -Tag "Warn"
                Write-Log "    re-open the design in the studio and export it again; the template switch is under 'Templates this connector issues'" -Tag "Warn"
            }
        }
        return
    }

    $configurationNamingContext = Get-AdcsConfigurationNamingContext
    if ([string]::IsNullOrWhiteSpace($configurationNamingContext)) { return }
    $templatesDn = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configurationNamingContext"

    Write-Log "SCEP tier in this design - publishing the templates NDES requires" -Tag "Run"

    foreach ($template in $script:adcsNdesTemplate) {
        $dn = "CN=$($template.Name),$templatesDn"
        if (-not (Test-StudioDirectoryObject -DistinguishedName $dn)) {
            # A Windows built-in that is not in the forest was removed, not never made.
            # certutil -dstemplate rewrites the default set without touching the ones
            # that are there.
            Write-Log "'$($template.Display)' ($($template.Name)) is not in this forest at all" -Tag "Error"
            Write-Log "    It is a Windows built-in, so it is restored rather than created:  certutil -dstemplate" -Tag "Error"
            Write-Log "    NDES cannot be configured until it is back - $($template.Why)" -Tag "Error"
            $script:adcsTemplateFailure += $template.Name
            continue
        }
        Write-Log "    $($template.Display): $($template.Why)" -Tag "Debug"
        Publish-AdcsTemplate -TemplateName $template.Name
        $groupKey = [string](Get-ConfigValue -InputObject $template -Name "GroupKey" -Default "")
        if (-not [string]::IsNullOrWhiteSpace($groupKey)) {
            $groupName = Get-AdcsScepRaGroupName -CertificateServices $CertificateServices -Key $groupKey
            $null = Grant-AdcsNdesTemplateEnrollment -GroupName $groupName -TemplateDn $dn -Display $template.Display
        }
        $null = Grant-AdcsNdesTemplateManagement -CertificateServices $CertificateServices -TemplateDn $dn -Display $template.Display
    }
}

# The template managers group reaches every template this design creates through the
# container grant - the ACE is inheritable, and an object made after it exists is born
# carrying it. The three NDES built-ins predate the forest's first CA, carry explicit
# ACLs, and so inherit nothing: after the container strip takes the built-in admins off,
# the design's own templates answer to the managers group while the three this design
# made load-bearing answer only to Domain and Enterprise Admins - exactly the accounts
# the strip exists to retire from template work. So the managers group is granted on
# them directly, with the same right and the same reasoning as the container: GenericAll,
# because the console's five checkboxes map nothing smaller to 'Full Control', and a
# group that can edit a template but not its security shows up on the tab with nothing
# ticked. Additive - the built-ins' own ACEs stay, this design does not strip objects it
# does not own.
function Grant-AdcsNdesTemplateManagement {
    param(
        [Parameter(Mandatory)][object]$CertificateServices,
        [Parameter(Mandatory)][string]$TemplateDn,
        [Parameter(Mandatory)][string]$Display
    )

    # The same two gates the container grant uses: a design with no role groups, or one
    # not applying CA security, has not asked for managed template permissions at all.
    $roleGroups = Get-ConfigValue -InputObject $CertificateServices -Name "roleGroups"
    if ($null -eq $roleGroups) { return $true }
    if (-not [bool](Get-ConfigValue -InputObject $roleGroups -Name "applyCaSecurity" -Default $false)) { return $true }

    $manager = @(Get-ConfigArray -InputObject $roleGroups -Name "groups" |
        Where-Object { [string](Get-ConfigText -InputObject $_ -Name "role" -Default "") -eq "templateManager" })
    if ($manager.Count -eq 0) { return $true }
    $groupName = [string](Get-ConfigText -InputObject $manager[0] -Name "name" -Default "")
    if ([string]::IsNullOrWhiteSpace($groupName)) { return $true }

    $sid = Get-AdcsPrincipalSidValue -Name $groupName
    if ($null -eq $sid) {
        Write-Log "'$groupName' could not be resolved, so it was not granted management of '$Display'" -Tag "Warn"
        return $false
    }
    $securityIdentifier = New-Object System.Security.Principal.SecurityIdentifier($sid)

    try {
        $entry = Get-AdcsDirectoryEntry -DistinguishedName $TemplateDn
        $security = $entry.ObjectSecurity

        # Explicit or inherited, either satisfies - a forest whose built-ins do inherit
        # from the container already carries the right, and a second explicit copy would
        # only be noise on an ACL somebody audits.
        $wanted = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
        $already = @($security.Access | Where-Object {
            $identity = ""
            try { $identity = [string]$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
            catch { $identity = "" }
            ($identity -eq [string]$sid) -and
            (($_.ActiveDirectoryRights -band $wanted) -eq $wanted) -and
            ($_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow)
        })
        if ($already.Count -gt 0) {
            Write-Log "'$groupName' already manages '$Display'" -Tag "Debug"
            return $true
        }

        $security.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $securityIdentifier, $wanted, [System.Security.AccessControl.AccessControlType]::Allow)))
        $entry.ObjectSecurity = $security
        $entry.CommitChanges()
    }
    catch {
        Write-Log "Could not give '$groupName' management of '$Display': $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    Write-Log "'$groupName' manages '$Display'" -Tag "Ok"
    return $true
}

# The other half of publishing CEP Encryption, and the half that is easy to miss because
# the error it prevents names neither an identity nor a template: the NDES server enrolls
# that certificate as ITSELF - its computer account - while the person running the
# configuration is a user. The default ACL on this built-in grants Enroll to Domain
# Admins and Enterprise Admins and nobody else, so a configuration run by an Enterprise
# Admin is still refused: the identity asking is not the identity typing. Field-hit
# 2026-08-16, as CMSCEPSetup::Install: Access is denied. 0x80070005.
#
# The grant names a GROUP, never the machine - the rule the CA permissions already
# follow. An ACE naming one computer is invisible to anybody auditing group membership,
# outlives the machine it was written for, and has to be written again by hand the day a
# second NDES server appears. The directory tier creates the group and puts the computer
# account in it; this only gives the group Read and Enroll. Enroll is an extended right
# rather than a permission bit, which is why it is two rules and not one.
function Grant-AdcsNdesTemplateEnrollment {
    param(
        [Parameter(Mandatory)][string]$GroupName,
        [Parameter(Mandatory)][string]$TemplateDn,
        [Parameter(Mandatory)][string]$Display
    )

    $groupName = $GroupName
    if ([string]::IsNullOrWhiteSpace($groupName)) { return $true }

    $sid = Get-AdcsPrincipalSidValue -Name $groupName
    if ($null -eq $sid) {
        # The directory tier creates it. A CA run that happens first is a normal order to
        # run these in, not a failure - it is said once and the next run finds it there.
        Write-Log "'$groupName' does not exist yet, so it was not granted Enroll on '$Display'" -Tag "Warn"
        Write-Log "    The domain controller run creates it with the NDES computer account in it - run this again after that" -Tag "Warn"
        return $false
    }

    $securityIdentifier = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $enrollRight = New-Object System.Guid("0e10c968-78fb-11d2-90d4-00c04f79dc55")

    try {
        $entry = Get-AdcsDirectoryEntry -DistinguishedName $TemplateDn
        $security = $entry.ObjectSecurity

        # Idempotent, the same way every other grant here is: a re-run must not stack a
        # second identical ACE on a Windows built-in. Translate inside a try - an ACE
        # naming a SID this forest can no longer resolve is a normal thing to find on an
        # object this old, and it must not throw the grant away with it.
        $already = @($security.Access | Where-Object {
            $identity = ""
            try { $identity = [string]$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
            catch { $identity = "" }
            ($identity -eq [string]$sid) -and
            ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -and
            ([string]$_.ObjectType -eq [string]$enrollRight)
        })
        if ($already.Count -gt 0) {
            Write-Log "'$groupName' already has Enroll on '$Display'" -Tag "Debug"
            return $true
        }

        $security.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $securityIdentifier, [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
            [System.Security.AccessControl.AccessControlType]::Allow)))
        $security.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $securityIdentifier, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow, $enrollRight)))
        $entry.ObjectSecurity = $security
        $entry.CommitChanges()
    }
    catch {
        Write-Log "Could not give '$groupName' Enroll on '$Display': $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    Write-Log "'$groupName' can enroll '$Display'" -Tag "Ok"
    return $true
}

function Limit-AdcsPublishedTemplate {
    param(
        [Parameter(Mandatory)][string[]]$KeepTemplateName,
        # Names kept that the design does not otherwise ask for. Separate from
        # -KeepTemplateName so the log can say *why* each one survived.
        [string[]]$Protect = @()
    )

    $published = @(Get-AdcsPublishedTemplate)

    if ($published.Count -eq 0) {
        Write-Log "This CA publishes no templates at all - nothing to withdraw" -Tag "Info"
        return
    }

    $protected = @($Protect | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($protected.Count -gt 0) {
        Write-Log "Protected from the withdrawal below: $($protected -join ', ')" -Tag "Info"
        Write-Log "    This design has a SCEP tier: NDES enrolls its RA certificates from two of them and its installer fails without the third" -Tag "Debug"
        Write-Log "    They are Windows built-ins this run publishes on the CA, named nowhere in the design" -Tag "Debug"
    }

    $removed = @()
    $removedRa = @()
    foreach ($name in $published) {
        if ($KeepTemplateName -contains $name) { continue }
        if ($protected -contains $name) { continue }
        Unpublish-AdcsTemplate -TemplateName $name
        $removed += $name
        if ($script:adcsRaTemplateName -contains $name) { $removedRa += $name }
    }

    if ($removed.Count -eq 0) {
        Write-Log "Nothing extra is published on this CA" -Tag "Ok"
        return
    }

    # Every name, not a count. A withdrawal is the one operation here that takes
    # something away from a CA, and "withdrew 7 templates" is not something anybody can
    # check afterwards or undo without knowing which seven.
    Write-Log "Withdrew $($removed.Count) template(s) the design does not ask for:" -Tag "Ok"
    foreach ($name in $removed) { Write-Log "    $name" -Tag "Info" }
    Write-Log "Publication is per CA and reversible - none of these objects was deleted:" -Tag "Info"
    Write-Log "    certutil -SetCATemplates +<TemplateName>    puts one back" -Tag "Info"

    if ($removedRa.Count -gt 0) {
        # Reached only when the design has no SCEP tier, because the tier protects them.
        # Said loudly anyway: the person who adds NDES to this estate in six months is
        # not necessarily the person reading this log today.
        Write-Log "$($removedRa -join ' and ') withdrawn - the template(s) NDES enrolls its registration authority certificates from" -Tag "Warn"
        Write-Log "    No SCEP tier here, so nothing needs them - and an Enrollment Agent template nobody uses is a certificate requestable on somebody else's behalf" -Tag "Warn"
        Write-Log "    If NDES is ever added to this CA, publish them again FIRST or its configuration fails:" -Tag "Warn"
        Write-Log "        certutil -SetCATemplates +$($removedRa -join ' ; certutil -SetCATemplates +')" -Tag "Warn"
    }
}

function Set-AdcsCertificateTemplate {
    param([Parameter(Mandatory)][object]$CertificateServices)

    $script:adcsGrantFailure    = @()
    $script:adcsTemplateFailure = @()

    $issuing   = Get-ConfigValue -InputObject $CertificateServices -Name "issuing"
    $access    = Get-ConfigValue -InputObject $CertificateServices -Name "access"
    $templates = Get-ConfigValue -InputObject $issuing -Name "templates"

    # Before the switch below, deliberately: these three are not this design's templates
    # to write, they are the built-ins NDES's installer needs to find published. A design
    # that deploys no templates of its own still has an NDES server that cannot configure
    # itself without them.
    # $null = deliberately: the connector path reads this function's output as its
    # success flag, so nothing new is allowed to fall into the pipeline here.
    $null = Publish-AdcsNdesTemplate -CertificateServices $CertificateServices

    if (-not [bool](Get-ConfigValue -InputObject $templates -Name "enabled" -Default $false)) {
        Write-Log "Certificate template deployment is switched off" -Tag "Info"
        return
    }

    $items = Get-ConfigArray -InputObject $templates -Name "items"
    if ($items.Count -eq 0) {
        Write-Log "No certificate templates are defined" -Tag "Info"
        return
    }

    # Before the first ACE: an access rule naming a group that does not exist yet is
    # a template published with nobody able to enroll for it.
    Set-AdcsAccessGroup -Access $access

    $configurationNamingContext = Get-AdcsConfigurationNamingContext
    Write-Log "Writing templates into $configurationNamingContext" -Tag "Get"

    $compatibility = Get-AdcsTemplateCompatibility -Templates $templates

    # Read once and announced once, rather than per template: this is the setting that
    # changes what a re-run does to objects somebody else made, and it should be visible
    # at the top of the template pass instead of inferred from six identical warnings.
    $overwriteExisting = [bool](Get-ConfigValue -InputObject $templates -Name "overwriteExisting" -Default $false)
    if ($overwriteExisting) {
        Write-Log "Existing templates will be overridden with this design's settings and their revision bumped" -Tag "Warn"
    }

    $keep = @()
    foreach ($template in $items) {
        if (-not [bool](Get-ConfigValue -InputObject $template -Name "enabled" -Default $true)) { continue }

        $displayName = [string](Get-ConfigValue -InputObject $template -Name "displayName" -Default "")
        if ([string]::IsNullOrWhiteSpace($displayName)) {
            Write-Log "A template entry has no displayName - skipping it" -Tag "Error"
            $script:adcsTemplateFailure += "(unnamed entry)"
            continue
        }

        try {
            # One compatibility level for the whole design - except where the enrollee
            # demands otherwise. NDES enrolls on behalf of devices through the SCEP
            # template and wants the v2 shape Microsoft's own guide asks for, so a
            # template item can carry its own compatibility block and the SCEP one
            # does. Everything else stays on the shared level, which is the rule that
            # keeps templates from disagreeing about which clients may enroll.
            $itemCompatibility = $compatibility
            if ($null -ne (Get-ConfigValue -InputObject $template -Name "compatibility")) {
                $itemCompatibility = Get-AdcsTemplateCompatibility -Templates $template
            }
            $templateName = Copy-AdcsCertificateTemplate -Template $template -ConfigurationNamingContext $configurationNamingContext `
                -Compatibility $itemCompatibility -CertificateServices $CertificateServices -OverwriteExisting $overwriteExisting
            Publish-AdcsTemplate -TemplateName $templateName
            $keep += $templateName

            # Only once the replacement is actually issuing, so there is never a gap
            # where neither the old nor the new template can be enrolled.
            if ([bool](Get-ConfigValue -InputObject $template -Name "unpublishSuperseded" -Default $false)) {
                foreach ($superseded in (Get-ConfigArray -InputObject $template -Name "supersedeTemplates")) {
                    Unpublish-AdcsTemplate -TemplateName ([string]$superseded)
                }
            }
        }
        catch {
            Write-Log "Template '$displayName': $($_.Exception.Message)" -Tag "Error"
            # The one way this reads 'Access is denied' on a design that just ran the
            # container strip: the built-ins are off the container and this session's
            # token predates the role group that replaced them. The right is real, the
            # token is stale, and nothing else about the session says so.
            # Matched by HRESULT as well as by the English words: a German server says
            # "Zugriff verweigert" and the hint below is exactly the one that reader
            # needs, since the cause is a stale token rather than a missing right.
            if ($_.Exception.Message -match "(?i)access is denied|0x80070005|E_ACCESSDENIED|-2147024891") {
                Write-Log "    If the built-in administrators were just stripped from the templates container, this token predates the replacement group - sign out and back in, then re-run" -Tag "Info"
            }
            $script:adcsTemplateFailure += $displayName
        }
    }

    # Only after every wanted template is published, so the CA is never left with
    # nothing it can issue.
    if ([bool](Get-ConfigValue -InputObject $templates -Name "unpublishOthers" -Default $false)) {
        if ($keep.Count -eq 0) {
            Write-Log "No template was published successfully - not withdrawing anything" -Tag "Error"
        }
        else {
            # The three NDES built-ins survive the sweep when - and only when - this
            # design has a SCEP tier. Two are what NDES enrolls its registration
            # authority certificates from - withdrawing them breaks that quietly in two
            # years. The third, IPSECIntermediateOffline, was withdrawn experimentally
            # on 2026-08-16 and put back the same evening: the installer fails its whole
            # template batch when any of the three cannot be resolved and published, so
            # a repair reinstall against a swept CA would fail with an error naming
            # three templates and no cause.
            $protect = @()
            if ($null -ne (Get-AdcsScepSection -CertificateServices $CertificateServices)) {
                $protect = @($script:adcsNdesTemplate | ForEach-Object { $_.Name })
            }
            Limit-AdcsPublishedTemplate -KeepTemplateName $keep -Protect $protect
        }
    }

    if ($script:adcsTemplateFailure.Count -gt 0) {
        Write-Log "$($script:adcsTemplateFailure.Count) of $($items.Count) template(s) not written: $(($script:adcsTemplateFailure | Select-Object -Unique) -join ', ')" -Tag "Error"
    }

    if ($keep.Count -gt 0) {
        Write-Log "$($keep.Count) template(s) applied" -Tag "Ok"
        Write-Log "    gpupdate /force   then   certreq -autoenroll -q   on a domain controller to test it now" -Tag "Info"
    }

    if ($script:adcsGrantFailure.Count -gt 0) {
        $unresolved = ($script:adcsGrantFailure | Select-Object -Unique) -join ", "
        Write-Log "No enrollment right was written for: $unresolved" -Tag "Error"
        Write-Log "Those templates are published and nobody can enroll for them - create the groups, then re-run" -Tag "Info"
    }
}

# ---------------------------[ Expiry reporting ]---------------------------
# There is no watchdog here on purpose. The root CRL and the issuing CA's own
# certificate are deliberately given the same lifetime, so the trip that re-signs the
# certificate is the trip that refreshes the CRL - and that trip cannot be forgotten,
# because without it the issuing CA stops issuing. A daily task warning about a
# deadline that is already enforced by a harder deadline is noise. What is left is a
# plain report of both dates on every run.

# Reads the CRLs this CA publishes locally. On the offline root that is the root CRL,
# which is the whole point of the ceremony; on the issuing CA it is the issuing CA's
# own. It does not try to speak for the other machine's CRL - that one lives in the
# transfer folder and in the directory, not here.
function Get-AdcsLocalCrlNextUpdate {
    $candidates = @(Get-ChildItem -Path (Join-Path -Path $script:adcsCertEnrollPath -ChildPath "*.crl") -File -ErrorAction SilentlyContinue)
    if ($candidates.Count -eq 0) { return $null }

    # (see Get-AdcsCrlNextUpdateFromDump above)
    # Several generations accumulate in this folder. The one in force is the newest,
    # so this takes the latest NextUpdate rather than the earliest. The dump is read
    # through Get-AdcsCrlNextUpdateFromDump, which does not depend on the label.
    $newest = $null
    foreach ($candidate in $candidates) {
        try {
            $dump = & certutil.exe -dump $candidate.FullName 2>&1 | Out-String
        }
        catch {
            continue
        }

        $parsed = Get-AdcsCrlNextUpdateFromDump -Dump $dump
        if ($null -ne $parsed) {
            if (($null -eq $newest) -or ($parsed -gt $newest)) { $newest = $parsed }
        }
    }
    return $newest
}

function Get-AdcsCrlExpiryMessage {
    $nextUpdate = Get-AdcsLocalCrlNextUpdate
    if ($null -eq $nextUpdate) { return "The CRL expiry could not be read" }

    $daysLeft = [int]([math]::Floor(($nextUpdate - (Get-Date)).TotalDays))
    return ("The CRL published here is valid until {0} - {1} day(s) left" -f $nextUpdate.ToString("yyyy-MM-dd"), $daysLeft)
}

# The date that actually drives the annual trip to the offline root. When this
# certificate expires the issuing CA stops issuing, so nothing softer is needed to
# make the ceremony happen - and the same trip brings a fresh root CRL back.
function Write-AdcsIssuingExpiry {
    param([Parameter(Mandatory)][object]$Issuing)

    $caName = [string](Get-ConfigValue -InputObject $Issuing -Name "caCommonName" -Default "")
    if ([string]::IsNullOrWhiteSpace($caName)) { return }

    $certificates = @(Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -like "CN=$caName,*" -or $_.Subject -eq "CN=$caName" })
    if ($certificates.Count -eq 0) {
        Write-Log "The issuing CA certificate could not be read from the local store" -Tag "Info"
        return
    }

    $expiry = ($certificates | Sort-Object -Property NotAfter -Descending)[0].NotAfter
    $daysLeft = [int]([math]::Floor(($expiry - (Get-Date)).TotalDays))
    Write-Log ("Issuing CA certificate valid until {0} - {1} day(s) left" -f $expiry.ToString("yyyy-MM-dd"), $daysLeft) -Tag "Info"
    Write-Log "Renewing it is the same trip to the offline root that refreshes the root CRL" -Tag "Debug"
}

# ---------------------------[ Issuing certificate renewal ]---------------------------
# The renewal is the ceremony the card in the studio already describes, not a new
# procedure: the issuing CA writes a renewal request into the transfer folder, the
# same trip to the offline root signs it (the root tier needs no change - a request
# is a request), and the run after the folder comes back installs it. State-driven
# like everything else here: the '_renewal' suffix in the file name is the in-flight
# marker, and it survives the round trip because the root names the signed .cer
# after the request it came from.
#
# What decides each state:
#   - a *_renewal.cer whose hash is NOT a generation in CACertHash  -> install it
#   - the *_renewal.req still in the folder                          -> waiting on the trip
#   - the certificate in force inside renewal.windowDays of expiry   -> write a request
#   - anything else                                                  -> nothing to do
#
# The generation test is exact where "newest file" is not: every past renewal leaves
# its .cer in the folder forever (nothing ever cleans the transfer folder), and each
# of those is a generation in CACertHash, so it reads as installed rather than as
# pending. windowDays 0 switches the whole thing off.

function Get-AdcsAuthorityCertificateHash {
    # Every generation from CACertHash, oldest first - the value is multi-valued and
    # grows one entry per renewal. The last entry is the certificate in force.
    $caName = Get-AdcsActiveCaName
    if ([string]::IsNullOrWhiteSpace($caName)) { return @() }

    try {
        $caKey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName" -ErrorAction Stop
    }
    catch {
        return @()
    }
    $value = Get-ConfigValue -InputObject $caKey -Name "CACertHash"
    if ($null -eq $value) { return @() }

    # The hash is stored as space-separated byte pairs; the store indexes by the
    # packed uppercase form.
    return @(@($value) | ForEach-Object { ([string]$_ -replace '\s', '').ToUpperInvariant() } | Where-Object { $_ })
}

function Get-AdcsAuthorityCertificate {
    $hashes = @(Get-AdcsAuthorityCertificateHash)
    if ($hashes.Count -eq 0) { return $null }

    $current = $hashes[$hashes.Count - 1]
    return (Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $current } | Select-Object -First 1)
}

function Get-AdcsRenewalSetting {
    param([object]$Issuing)

    $renewal = $null
    if ($null -ne $Issuing) { $renewal = Get-ConfigValue -InputObject $Issuing -Name "renewal" }

    $windowDays = 60
    $reuseKeys = $true
    $rekey = $false
    $rekeyKeyLength = 4096
    $forceNow = $false
    if ($null -ne $renewal) {
        $windowDays = [int](Get-ConfigValue -InputObject $renewal -Name "windowDays" -Default 60)
        $reuseKeys = [bool](Get-ConfigValue -InputObject $renewal -Name "reuseKeys" -Default $true)
        $rekey = [bool](Get-ConfigValue -InputObject $renewal -Name "rekey" -Default $false)
        $rekeyKeyLength = [int](Get-ConfigValue -InputObject $renewal -Name "rekeyKeyLength" -Default 4096)
        $forceNow = [bool](Get-ConfigValue -InputObject $renewal -Name "forceNow" -Default $false)
    }
    if ($windowDays -lt 0) { $windowDays = 0 }
    # A re-key is a renewal with a new key by definition, so it settles the argument
    # rather than co-existing with it: reusing the key is exactly the thing it is not
    # doing. Said out loud instead of silently winning, because a design that asks for
    # both is a design somebody should look at.
    if ($rekey -and $reuseKeys) {
        Write-Log "Design asks to re-key and to reuse the key - re-key wins" -Tag "Info"
        $reuseKeys = $false
    }
    # Either way in. The command line is for a run somebody is watching; the design's
    # own switch is for the far more common lab shape, where the whole workflow is
    # "export the config, run the script" and a flag nobody typed is a flag nobody
    # remembers. Same effect, and the studio makes the cost loud.
    return @{ WindowDays = $windowDays; ReuseKeys = $reuseKeys; Rekey = $rekey; RekeyKeyLength = $rekeyKeyLength;
              ForceNow = ($forceNow -or [bool]$script:forceRenewal) }
}

# The key size of a renewal, which is the one thing about a CA's key that can change
# without rebuilding the CA. Microsoft's own words, from the CAPolicy.inf reference:
# "RenewalKeyLength sets the key size for renewal only. This is only used when a new key
# pair is generated during CA certificate renewal. The key size for the initial CA
# certificate is set when the CA is installed." So this file, in %systemroot%, before
# certutil -renewcert runs - after it, the size is already decided.
#
# Merged rather than written. A CAPolicy.inf that is already there may carry policy
# statement OIDs, a CDP section or an AIA section, and those go into the renewed
# certificate; replacing the file would silently drop them. So the existing content is
# kept line for line and only RenewalKeyLength is set, in the [certsrv_server] section,
# which is created when it is missing. The original is copied aside first regardless -
# this file decides what a CA certificate looks like, and it is worth a backup.
function Set-AdcsRenewalKeyLength {
    param([Parameter(Mandatory)][int]$KeyLength)

    $policyPath = Join-Path -Path $env:SystemRoot -ChildPath "CAPolicy.inf"
    $lines = @()

    if (Test-Path -LiteralPath $policyPath) {
        try {
            $lines = @(Get-Content -LiteralPath $policyPath -ErrorAction Stop)
        }
        catch {
            Write-Log "'$policyPath' exists but could not be read: $($_.Exception.Message)" -Tag "Error"
            return $false
        }
        $backupPath = "$policyPath.{0}.bak" -f (Get-Date -Format "yyyyMMdd-HHmmss")
        try {
            Copy-Item -LiteralPath $policyPath -Destination $backupPath -ErrorAction Stop
            Write-Log "The existing CAPolicy.inf was copied to '$backupPath'" -Tag "Info"
        }
        catch {
            Write-Log "'$policyPath' could not be backed up ($($_.Exception.Message)) - not touching it" -Tag "Error"
            return $false
        }
    }
    else {
        # The minimum a CAPolicy.inf needs to be read at all. Without [Version] the
        # file is ignored in silence, which would look exactly like a re-key that
        # decided to keep the old key size.
        $lines = @('[Version]', 'Signature="$Windows NT$"')
    }

    $output = @()
    $inServerSection = $false
    $written = $false
    $sectionSeen = $false
    foreach ($line in $lines) {
        $trimmed = ([string]$line).Trim()
        if ($trimmed -match '^\[.+\]$') {
            # Leaving [certsrv_server] without having found the key means it was not
            # there - add it as the section's last line before the next one opens.
            if ($inServerSection -and (-not $written)) {
                $output += "RenewalKeyLength=$KeyLength"
                $written = $true
            }
            $inServerSection = ($trimmed -match '^\[\s*certsrv_server\s*\]$')
            if ($inServerSection) { $sectionSeen = $true }
            $output += $line
            continue
        }
        if ($inServerSection -and ($trimmed -match '^RenewalKeyLength\s*=')) {
            if (-not $written) {
                $output += "RenewalKeyLength=$KeyLength"
                $written = $true
            }
            # A second one would be the file arguing with itself - dropped.
            continue
        }
        $output += $line
    }
    if ($inServerSection -and (-not $written)) {
        $output += "RenewalKeyLength=$KeyLength"
        $written = $true
    }
    if (-not $sectionSeen) {
        $output += "[certsrv_server]"
        $output += "RenewalKeyLength=$KeyLength"
    }

    try {
        # ASCII because the documented procedure says ANSI, and a CAPolicy.inf saved
        # with a byte order mark is a CAPolicy.inf that is not read.
        Set-Content -LiteralPath $policyPath -Value $output -Encoding ASCII -ErrorAction Stop
    }
    catch {
        Write-Log "'$policyPath' could not be written: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
    Write-Log "CAPolicy.inf: RenewalKeyLength=$KeyLength" -Tag "Ok"
    return $true
}

function Get-AdcsRenewalBaseName {
    param([Parameter(Mandatory)][object]$Issuing)

    $commonName = [string](Get-ConfigValue -InputObject $Issuing -Name "caCommonName" -Default "")
    return ("{0}_{1}_renewal" -f $env:COMPUTERNAME, ($commonName -replace '[^A-Za-z0-9-]', '-'))
}

function Find-AdcsRenewalRequestFile {
    # Where certutil -renewcert left the request. The documented place is the
    # RequestFileName value the renewal writes into the CA's configuration key; the
    # observed fallbacks are the system drive root and CertEnroll. Time-fenced so a
    # fossil request from some earlier operation is never picked up.
    param([Parameter(Mandatory)][datetime]$Since)

    $caName = Get-AdcsActiveCaName
    if (-not [string]::IsNullOrWhiteSpace($caName)) {
        try {
            $caKey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName" -ErrorAction Stop
            $registered = [string](Get-ConfigValue -InputObject $caKey -Name "RequestFileName" -Default "")
            if (-not [string]::IsNullOrWhiteSpace($registered)) {
                $expanded = [System.Environment]::ExpandEnvironmentVariables($registered)
                if (Test-Path -LiteralPath $expanded) { return (Get-Item -LiteralPath $expanded) }
            }
        }
        catch {
            Write-Log "RequestFileName could not be read from the CA configuration: $($_.Exception.Message)" -Tag "Debug"
        }
    }

    foreach ($folder in @(("{0}\" -f $env:SystemDrive), $script:adcsCertEnrollPath)) {
        $candidates = @(Get-ChildItem -Path (Join-Path -Path $folder -ChildPath "*.req") -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $Since } |
            Sort-Object -Property LastWriteTime -Descending)
        if ($candidates.Count -gt 0) { return $candidates[0] }
    }
    return $null
}

function Invoke-AdcsRenewalRequest {
    param(
        [Parameter(Mandatory)][object]$Issuing,
        [Parameter(Mandatory)][string]$TransferPath,
        [Parameter(Mandatory)][bool]$ReuseKeys
    )

    $started = Get-Date

    $arguments = @("-f", "-renewcert")
    if ($ReuseKeys) { $arguments += "ReuseKeys" }

    # **A dialog is about to appear, and cancelling it is the correct answer.**
    #
    # certutil -renewcert builds the request and then tries to submit it to a parent CA.
    # This design's parent is an offline root, so there is nothing to submit to: certutil
    # puts up "Select Certification Authority", and whatever is chosen or typed there is
    # refused, because the machine that could answer is powered off in a safe. The
    # request file is written regardless - that is documented behaviour and the reason
    # every offline-root guide says to click Cancel - and the file on disk is what this
    # function treats as success, the same reading Install-AdcsIssuingAuthority applies
    # to its own setup error.
    #
    # Said before the call rather than explained after it, because the operator meets the
    # dialog first and a run that springs an unexplained CA picker on somebody looks like
    # it has gone wrong at exactly the moment it has not.
    Write-Log "certutil will now ask which certification authority to submit to - press Cancel" -Tag "Info"
    Write-Log "    The parent is the offline root, so nothing here can sign it. The request file is written either way" -Tag "Debug"

    $null = Invoke-AdcsUtility -FilePath "certutil.exe" -ArgumentList $arguments -IgnoreExitCode

    # The renewal cycles certsvc itself; the CA carries on under the old certificate,
    # but it has the same not-answering-yet window as any other restart.
    $null = Wait-AdcsAuthorityReady

    $request = Find-AdcsRenewalRequestFile -Since $started.AddMinutes(-1)
    if ($null -eq $request) {
        throw "certutil -renewcert did not leave a request file - the certutil output above says why."
    }

    $target = Join-Path -Path $TransferPath -ChildPath ((Get-AdcsRenewalBaseName -Issuing $Issuing) + ".req")
    Move-Item -LiteralPath $request.FullName -Destination $target -Force
    return $target
}

function Install-AdcsRenewedCertificate {
    param([Parameter(Mandatory)][object]$CertificateFile)

    Write-Log "Installing the renewed CA certificate '$($CertificateFile.Name)'" -Tag "Run"

    # certsvc is stopped for the swap and started again whatever happens - a renewal
    # that fails on a file problem must not leave a working CA offline.
    try {
        Stop-Service -Name "certsvc" -Force -ErrorAction Stop
    }
    catch {
        throw "Could not stop certsvc for the certificate swap: $($_.Exception.Message)"
    }

    try {
        $null = Invoke-AdcsUtility -FilePath "certutil.exe" -ArgumentList @("-f", "-installcert", $CertificateFile.FullName)
    }
    finally {
        try {
            Start-Service -Name "certsvc" -ErrorAction Stop
        }
        catch {
            Write-Log "certsvc did not start again after the certificate swap: $($_.Exception.Message)" -Tag "Error"
        }
        $null = Wait-AdcsAuthorityReady
    }
}

function Test-AdcsRenewalCeiling {
    # The root signs no further than its own notAfter and truncates silently rather
    # than refusing, which is how a renewal comes back months short with nothing
    # having reported an error. Warned here, before the request is written, because
    # after the trip is too late to decide the root needed renewing first.
    param([Parameter(Mandatory)][object]$Current)

    $issuerCertificates = @(Get-ChildItem -Path "Cert:\LocalMachine\Root" -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq $Current.Issuer })
    if ($issuerCertificates.Count -eq 0) { return }

    $rootNotAfter = ($issuerCertificates | Sort-Object -Property NotAfter -Descending)[0].NotAfter
    $grantDays = [int]([math]::Floor(($Current.NotAfter - $Current.NotBefore).TotalDays))
    if ($rootNotAfter -lt (Get-Date).AddDays($grantDays)) {
        Write-Log ("The root itself expires {0} - the renewed certificate is truncated to that date rather than getting its full {1} day(s)" -f $rootNotAfter.ToString("yyyy-MM-dd"), $grantDays) -Tag "Warn"
        Write-Log "Renewing the root is its own ceremony and is not automated here" -Tag "Warn"
    }
}

function Invoke-AdcsRenewalStep {
    # Returns "" (nothing to do), "Requested" (a fresh request was written),
    # "Waiting" (a request is out on its trip), "Installed", or "Failed:<message>".
    param(
        [Parameter(Mandatory)][object]$Issuing,
        [Parameter(Mandatory)][string]$TransferPath
    )

    $current = Get-AdcsAuthorityCertificate
    if ($null -eq $current) {
        Write-Log "CA certificate in force unreadable from the local store - renewal skipped this run" -Tag "Warn"
        return ""
    }

    $baseName = Get-AdcsRenewalBaseName -Issuing $Issuing
    $pendingRequestPath = Join-Path -Path $TransferPath -ChildPath ($baseName + ".req")

    # A signed renewal certificate that is not yet a generation of this CA is the one
    # thing to install.
    $generations = @(Get-AdcsAuthorityCertificateHash)
    $candidate = $null
    $renewalCertificates = @(Get-ChildItem -Path (Join-Path -Path $TransferPath -ChildPath "*_renewal.cer") -File -ErrorAction SilentlyContinue)
    foreach ($file in $renewalCertificates) {
        try {
            $parsed = New-Object -TypeName "System.Security.Cryptography.X509Certificates.X509Certificate2" -ArgumentList $file.FullName
        }
        catch {
            Write-Log "'$($file.Name)' could not be read as a certificate and was skipped" -Tag "Warn"
            continue
        }
        if ($generations -contains $parsed.Thumbprint.ToUpperInvariant()) { continue }
        if ($parsed.Subject -ne $current.Subject) {
            Write-Log "'$($file.Name)' names '$($parsed.Subject)', not this CA - skipped" -Tag "Warn"
            continue
        }
        $candidate = @{ File = $file; Certificate = $parsed }
    }

    if ($null -ne $candidate) {
        # The air gap is the security control; what crossed it is verified before it
        # becomes this CA's certificate, exactly as the initial chain install does.
        if (-not (Test-AdcsTransferManifest -Path $TransferPath)) {
            return "Failed:The transfer folder does not match its manifest - the renewed certificate was not installed."
        }

        $previousNotAfter = $current.NotAfter
        Install-AdcsRenewedCertificate -CertificateFile $candidate.File
        Remove-Item -LiteralPath $pendingRequestPath -Force -ErrorAction SilentlyContinue
        Publish-AdcsCrl

        $renewed = Get-AdcsAuthorityCertificate
        if (($null -ne $renewed) -and ($renewed.Thumbprint -eq $candidate.Certificate.Thumbprint.ToUpperInvariant())) {
            Write-Log ("CA certificate renewed - valid until {0} (was {1})" -f $renewed.NotAfter.ToString("yyyy-MM-dd"), $previousNotAfter.ToString("yyyy-MM-dd")) -Tag "Ok"
        }
        else {
            Write-Log "certutil -installcert ran and the certificate in force did not change - check the CA's Application event log" -Tag "Warn"
        }
        return "Installed"
    }

    if (Test-Path -LiteralPath $pendingRequestPath) {
        Write-Log "A renewal request is waiting in '$TransferPath' - carry the folder to the offline root" -Tag "Info"
        return "Waiting"
    }

    $setting = Get-AdcsRenewalSetting -Issuing $Issuing
    # -ForceRenewal is the one thing that opens this gate early. The ceremony is
    # state-driven by design - the dates decide, not a person - but "the dates decide"
    # makes the whole path untestable until the year is nearly up, and a ceremony nobody
    # has rehearsed is a ceremony that goes wrong at the one moment it matters. The
    # switch is on the command line rather than in the config for exactly that reason:
    # it belongs to the run somebody is watching, not to the design.
    $daysLeft = ($current.NotAfter - (Get-Date)).TotalDays
    if ($setting.ForceNow) {
        Write-Log ("Forced renewal: writing a request {0} day(s) before this certificate expires" -f [int][math]::Floor($daysLeft)) -Tag "Run"
        Write-Log "    The root signs it the same way and the issuing CA installs it early - the new certificate starts sooner" -Tag "Debug"
    }
    else {
        if ($setting.WindowDays -le 0) { return "" }
        if ($daysLeft -gt $setting.WindowDays) { return "" }
    }

    # Inside the window. The root takes one request at a time, so a foreign .req
    # already in the folder blocks this one rather than riding along with it.
    $otherRequests = @(Get-ChildItem -Path (Join-Path -Path $TransferPath -ChildPath "*.req") -File -ErrorAction SilentlyContinue)
    if ($otherRequests.Count -gt 0) {
        Write-Log "A request is already in '$TransferPath' ('$($otherRequests[0].Name)') - the root signs one at a time, so none was written" -Tag "Warn"
        return ""
    }

    Test-AdcsRenewalCeiling -Current $current

    if (-not $setting.ForceNow) {
        Write-Log ("CA certificate expires in {0} day(s) - inside the {1}-day renewal window" -f [int][math]::Floor($daysLeft), $setting.WindowDays) -Tag "Info"
    }

    # Before the request, never after: the key is generated by certutil -renewcert, and
    # RenewalKeyLength is only read on the way in. A file that cannot be written stops
    # the renewal rather than producing a request at the old size - a request signed at
    # 2048 when the design asked for 4096 is a whole ceremony spent going nowhere, and
    # the next one cannot start until this certificate is near expiry again.
    if ($setting.Rekey) {
        Write-Log ("Re-keying: a new {0}-bit key rather than the current one" -f $setting.RekeyKeyLength) -Tag "Run"
        if (-not (Set-AdcsRenewalKeyLength -KeyLength $setting.RekeyKeyLength)) {
            Write-Log "Renewal request not written - fix CAPolicy.inf and run again inside the window" -Tag "Error"
            return "Failed:CAPolicy.inf could not be written, so the re-key request was not created."
        }
    }

    $requestPath = Invoke-AdcsRenewalRequest -Issuing $Issuing -TransferPath $TransferPath -ReuseKeys $setting.ReuseKeys
    New-AdcsTransferManifest -Path $TransferPath
    Write-Log "Renewal request written to '$([System.IO.Path]::GetFileName($requestPath))'" -Tag "Ok"
    if (-not $setting.ReuseKeys) {
        Write-Log "    After installation the CRL and CA certificate gain a (1) suffix and both generations stay served - delete nothing in the web folder" -Tag "Debug"
    }
    if ($setting.Rekey) {
        Write-Log "Re-keying changes what this CA signs with - Microsoft: every certificate it has issued has to be reissued" -Tag "Warn"
        Write-Log "    The old ones stay valid while the previous certificate and its CRL are published - that buys time, it is not a reprieve" -Tag "Warn"
    }
    return "Requested"
}

# ---------------------------[ Database backup ]---------------------------
# The root gets the four-part ceremony checklist; the issuing CA gets this. Its database
# is the record of everything issued and revoked - lose it and revocation history goes
# with it - and 'the hypervisor snapshots it' is a statement about the disk, not about a
# restorable CA. The nightly job takes certutil -backupdb (a consistent online copy, no
# service stop) plus a registry export of the CertSvc configuration into a dated folder,
# and prunes old ones. Deliberately NOT the private key: -backupkey wants a password and
# where that lands is a decision, the key never changes after the build, and the
# checklist already owns it. A key copied to the same disk nightly protects nothing.
$script:adcsBackupTaskName = "WSRS-CaBackup"
$script:adcsBackupScriptName = "Backup-CaDatabase.ps1"

# The nightly job is certutil, reg and a prune - so it gets a script of its own, and
# nothing else is put beside it. This used to stage the whole project into the deploy
# folder the way the certificate task does: the entry script, the config and every part
# in pwsh\, refreshed on each run, so that a task whose whole content is three commands
# could dot-source a framework to reach them. The certificate task genuinely needs all
# of it (ACME, the mail report, the role providers); this one never did, and the copy
# also put config.json - which carries exported secrets - on disk for a job that reads
# neither.
#
# It is written from a template rather than shipped as a file because the two values it
# needs are the design's, and baking them in as parameter defaults is what keeps the
# scheduled action down to one -File argument. The next configuration run overwrites it,
# which is said in the file itself so nobody edits it in place.
$script:adcsBackupScriptTemplate = @'
<#
    Nightly backup of the certification authority database: the database itself and the
    CertSvc configuration, into a folder named for the day, with folders older than the
    retention window pruned.

    Written by Windows Server Role Studio (Configure-ServerRoles.ps1) on __WRITTEN__ and
    OVERWRITTEN by the next configuration run - change config.json, not this file.

    Self-contained on purpose. The scheduled task needs certutil.exe, reg.exe and a
    prune; it does not need the project that wrote it, so none of it is here.

    Deliberately NOT the private key. certutil -backupkey wants a password and where
    that lands is a decision, the key never changes after the build, and a key copied to
    the same disk every night protects nothing - removable media, once, per the build
    checklist.
#>
param(
    [string]$Directory = '__DIRECTORY__',
    [int]$RetentionDays = __RETENTION__
)

$ErrorActionPreference = "Stop"
if ($RetentionDays -lt 1) { $RetentionDays = 1 }
$script:logPath = ""

function Write-BackupLog {
    param([string]$Message)

    $line = "{0}  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Write-Output $line
    # The task runs as SYSTEM at 02:30 and nobody is watching the console, so the log
    # beside the backups is the only account of what happened. Never fatal: a backup
    # that ran and could not be written about still ran.
    if ($script:logPath) {
        try { Add-Content -LiteralPath $script:logPath -Value $line } catch { }
    }
}

try {
    if (-not (Test-Path -LiteralPath $Directory)) {
        $null = New-Item -ItemType Directory -Path $Directory -Force
    }
    # SYSTEM and Administrators only, by SID rather than by name - "BUILTIN\Administrators"
    # is VORDEFINIERT\Administratoren on a German server. Repeated on every run because a
    # folder somebody recreated by hand comes back with inheritance on, and this one holds
    # every certificate the CA ever issued.
    $acl = Get-Acl -Path $Directory
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($wellKnown in @([System.Security.Principal.WellKnownSidType]::LocalSystemSid,
                             [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($wellKnown, $null)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
    }
    Set-Acl -Path $Directory -AclObject $acl
}
catch {
    Write-Output ("Could not prepare '{0}': {1}" -f $Directory, $_.Exception.Message)
    exit 1
}

# A native command's stderr, merged into the output stream, arrives as a
# NativeCommandError record - and with $ErrorActionPreference = "Stop" that record is
# TERMINATING. So a certutil that failed would kill this script at the exact moment it
# has something worth writing down, and the log would end mid-sentence. The preference
# is therefore dropped for the call itself and the exit code is what decides; the Stop
# above still covers every cmdlet around it.
function Invoke-BackupCommand {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList
    )

    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $FilePath @ArgumentList 2>&1
        return @{ ExitCode = [int]$LASTEXITCODE; Text = (($output | ForEach-Object { [string]$_ } | Where-Object { $_.Trim() } | Select-Object -Last 3) -join " ") }
    }
    finally {
        $ErrorActionPreference = $previous
    }
}

# One log per run, and the newest fourteen kept. Same rule and same number as the run
# logs the studio writes, for the same reason: what anybody wants from this folder is the
# last few nights, and counting files is something you can check by looking. A job that
# exists to stop a disk filling up has no business keeping its own account of that
# forever.
function Limit-BackupLog {
    param([Parameter(Mandatory)][string]$Directory)

    try {
        Get-ChildItem -LiteralPath $Directory -Filter "backup-*.log" -File -ErrorAction Stop |
            Sort-Object -Property LastWriteTime -Descending |
            Select-Object -Skip 14 |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
    catch { }
}

$script:logPath = Join-Path -Path $Directory -ChildPath ("backup-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmm"))
Limit-BackupLog -Directory $Directory
$target = Join-Path -Path $Directory -ChildPath (Get-Date -Format "yyyy-MM-dd")
$failed = $false

# -f: certutil refuses a target folder that already has content, and the task running
# twice in a day is a fresher copy of the same backup, not an error.
$result = Invoke-BackupCommand -FilePath "certutil.exe" -ArgumentList @("-f", "-backupdb", $target)
if ($result.ExitCode -ne 0) {
    Write-BackupLog ("certutil -backupdb failed with {0}: {1}" -f $result.ExitCode, $result.Text)
    $failed = $true
}
else {
    Write-BackupLog ("Database backed up to '{0}'" -f $target)
}

if (-not (Test-Path -LiteralPath $target)) { $null = New-Item -ItemType Directory -Path $target -Force }
$registryTarget = Join-Path -Path $target -ChildPath "certsvc-configuration.reg"
$result = Invoke-BackupCommand -FilePath "reg.exe" `
    -ArgumentList @("export", "HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration", $registryTarget, "/y")
if ($result.ExitCode -ne 0) {
    Write-BackupLog ("The registry export failed with {0}: {1}" -f $result.ExitCode, $result.Text)
    $failed = $true
}
else {
    Write-BackupLog ("CertSvc configuration exported to '{0}'" -f $registryTarget)
}

# Matched on the name pattern rather than on the folder's age, so nothing else somebody
# parked in here is ever removed.
try {
    $cutoff = (Get-Date).AddDays(-$RetentionDays)
    foreach ($old in @(Get-ChildItem -Path $Directory -Directory -ErrorAction SilentlyContinue)) {
        if ($old.Name -notmatch '^\d{4}-\d{2}-\d{2}$') { continue }
        $parsed = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($old.Name, "yyyy-MM-dd", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) { continue }
        if ($parsed -ge $cutoff) { continue }
        Remove-Item -LiteralPath $old.FullName -Recurse -Force
        Write-BackupLog ("Pruned '{0}' - older than {1} day(s)" -f $old.Name, $RetentionDays)
    }
}
catch {
    Write-BackupLog ("Could not prune old backups: {0}" -f $_.Exception.Message)
}

if ($failed) { exit 1 }
exit 0
'@

# Where the nightly backup keeps its dated folders. Config first, then the documented
# default - the same answer Invoke-AdcsCaBackupTask used to work out for itself, in one
# place now that the generated script and the task registration both need it.
function Get-AdcsBackupDirectory {
    param([object]$Backup)

    $directory = [string](Get-ConfigText -InputObject $Backup -Name "directory" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($directory)) { return $directory }

    $systemDrive = $env:SystemDrive
    if ([string]::IsNullOrWhiteSpace($systemDrive)) { $systemDrive = "C:" }
    return (Join-Path -Path $systemDrive -ChildPath "CABackup")
}

# The generated script on disk, returned as a path. Everything about how it is written
# lives in Write-StudioTaskScript; what is here is the two values this one needs.
function Write-AdcsBackupScript {
    param([Parameter(Mandatory)][object]$Backup)

    $retentionDays = [int](Get-ConfigValue -InputObject $Backup -Name "retentionDays" -Default 14)
    if ($retentionDays -lt 1) { $retentionDays = 1 }

    return (Write-StudioTaskScript -FileName $script:adcsBackupScriptName -Template $script:adcsBackupScriptTemplate `
        -Task $Backup -Purpose "the whole of what the nightly backup task runs" `
        -Value @{
            DIRECTORY = (ConvertTo-StudioScriptLiteral -Value (Get-AdcsBackupDirectory -Backup $Backup))
            RETENTION = [string]$retentionDays
        })
}

function Register-AdcsBackupTask {
    param([Parameter(Mandatory)][object]$CertificateServices)

    $issuing = Get-ConfigValue -InputObject $CertificateServices -Name "issuing"
    $backup  = Get-ConfigValue -InputObject $issuing -Name "backup"
    $enabled = ($null -ne $backup) -and [bool](Get-ConfigValue -InputObject $backup -Name "enabled" -Default $false)

    if (-not (Get-Command -Name "Register-ScheduledTask" -ErrorAction SilentlyContinue)) {
        if ($enabled) { Write-Log "ScheduledTasks module unavailable - database backup task not registered" -Tag "Error" }
        return
    }

    $existing = Get-ScheduledTask -TaskName $script:adcsBackupTaskName -ErrorAction SilentlyContinue
    if (-not $enabled) {
        if ($null -ne $existing) {
            try {
                Unregister-ScheduledTask -TaskName $script:adcsBackupTaskName -Confirm:$false -ErrorAction Stop
                Write-Log "Removed '$($script:adcsBackupTaskName)' - backups are off in this design" -Tag "Ok"
            }
            catch {
                Write-Log "Could not remove '$($script:adcsBackupTaskName)': $($_.Exception.Message)" -Tag "Warn"
            }
        }
        return
    }

    $startTime = Get-ConfigText -InputObject $backup -Name "time" -Default "02:30"

    try {
        # The same rule as the certificate task - the job must not depend on wherever this
        # run was started from - reached with one generated file instead of a copy of the
        # project. The values are its parameter defaults, so the action is one -File.
        $deployedScript = Write-AdcsBackupScript -Backup $backup
        $deployDirectory = Split-Path -Path $deployedScript -Parent

        $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $deployedScript

        if ($null -ne $existing) {
            Unregister-ScheduledTask -TaskName $script:adcsBackupTaskName -Confirm:$false -ErrorAction Stop
        }

        $action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arguments -WorkingDirectory $deployDirectory
        $trigger = New-ScheduledTaskTrigger -Daily -At ([datetime]::Parse($startTime))
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)

        $null = Register-ScheduledTask -TaskName $script:adcsBackupTaskName -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings `
            -Description "Windows Server Role Studio - nightly backup of the certification authority database" -ErrorAction Stop
    }
    catch {
        Write-Log "Could not register '$($script:adcsBackupTaskName)': $($_.Exception.Message)" -Tag "Error"
        return
    }

    Write-Log "Registered '$($script:adcsBackupTaskName)' - daily at $startTime as SYSTEM" -Tag "Ok"
    Write-Log "    It backs up the database and the CertSvc configuration, never the key - the key belongs on removable media" -Tag "Debug"
}

function Invoke-AdcsCaBackupTask {
    param([Parameter(Mandatory)][object]$Config)

    $certificateServices = Get-ConfigValue -InputObject $Config -Name "certificateServices"
    $issuing = Get-ConfigValue -InputObject $certificateServices -Name "issuing"
    $backup  = Get-ConfigValue -InputObject $issuing -Name "backup"

    if (($null -eq $backup) -or (-not [bool](Get-ConfigValue -InputObject $backup -Name "enabled" -Default $false))) {
        Write-Log "The database backup is switched off in config.json - nothing to do" -Tag "Info"
        return 0
    }
    if (-not (Test-AdcsAuthorityInstalled)) {
        Write-Log "No certification authority is installed on this server - nothing to back up" -Tag "Error"
        return 1
    }

    # -Task CaBackup runs the generated script rather than a second copy of the same
    # certutil, reg and prune. Two implementations of one job drift, and the one that
    # drifts is always the one nobody runs by hand - so this path exercises exactly what
    # the scheduled task does at 02:30. The task registered by an older build still
    # points here, which is the other reason this entry point stays.
    #
    # Rewritten every time rather than reused: the design may have moved the folder or
    # the retention since the file was written, and re-running the configuration is how
    # anybody would expect that to take effect.
    try {
        $scriptPath = Write-AdcsBackupScript -Backup $backup
    }
    catch {
        Write-Log "Could not write the backup script: $($_.Exception.Message)" -Tag "Error"
        return 1
    }

    # In this process, not a second powershell.exe - the task already is one.
    $exitCode = 0
    try {
        foreach ($line in @(& $scriptPath)) {
            $text = [string]$line
            if (-not [string]::IsNullOrWhiteSpace($text)) { Write-Log $text -Tag "Info" }
        }
        $exitCode = [int]$LASTEXITCODE
    }
    catch {
        Write-Log "The backup script failed: $($_.Exception.Message)" -Tag "Error"
        return 1
    }

    if ($exitCode -ne 0) {
        Write-Log "The backup script reported a failure - see the lines above and '$((Get-AdcsBackupDirectory -Backup $backup))\backup.log'" -Tag "Error"
        return 1
    }
    Write-Log "    The private key is not in this backup - certutil -backupkey to removable media covers it" -Tag "Debug"
    return 0
}

# Renew mode on the issuing CA. Three states, the same three the ceremony has always
# had - a request goes out, a certificate comes back, or there is nothing to do yet -
# and the republish that makes the new certificate reachable.
# The re-key an adopt run performs for itself. Returns "" (nothing asked for, or the new
# key is already in force), "Requested", or "Failed:<message>".
#
# The guard that matters is the last one: a CA already signing with the size the design
# asks for does not get re-keyed every time somebody re-runs the adoption. Without it
# this would start a fresh ceremony on every visit, and each one costs a trip to the
# safe and a reissue of everything the CA ever signed.
function Invoke-AdcsAdoptRekey {
    param(
        [Parameter(Mandatory)][object]$Issuing,
        [Parameter(Mandatory)][string]$TransferPath
    )

    $setting = Get-AdcsRenewalSetting -Issuing $Issuing
    if (-not $setting.Rekey) { return "" }

    $current = Get-AdcsAuthorityCertificate
    if ($null -eq $current) {
        Write-Log "The CA certificate in force could not be read, so the re-key was not started" -Tag "Warn"
        return ""
    }

    $currentSize = 0
    try { $currentSize = [int]$current.PublicKey.Key.KeySize } catch { $currentSize = 0 }
    if (($currentSize -gt 0) -and ($currentSize -ge $setting.RekeyKeyLength)) {
        Write-Log "Already signs with a $currentSize-bit key, design asks for $($setting.RekeyKeyLength) - nothing to re-key" -Tag "Ok"
        return ""
    }

    $baseName = Get-AdcsRenewalBaseName -Issuing $Issuing
    $pendingRequestPath = Join-Path -Path $TransferPath -ChildPath ($baseName + ".req")
    if (Test-Path -LiteralPath $pendingRequestPath) {
        Write-Log "A re-key request is already in '$TransferPath' - carry it to the root rather than writing a second" -Tag "Info"
        return ""
    }

    $otherRequests = @(Get-ChildItem -Path (Join-Path -Path $TransferPath -ChildPath "*.req") -File -ErrorAction SilentlyContinue)
    if ($otherRequests.Count -gt 0) {
        Write-Log "Another request is in '$TransferPath' ('$($otherRequests[0].Name)') - the root signs one at a time, so the re-key was not started" -Tag "Warn"
        return ""
    }

    Write-Log ("Re-keying this CA from {0} bit to {1} bit" -f $currentSize, $setting.RekeyKeyLength) -Tag "Run"
    Test-AdcsRenewalCeiling -Current $current
    if (-not (Set-AdcsRenewalKeyLength -KeyLength $setting.RekeyKeyLength)) {
        return "Failed:CAPolicy.inf could not be written, so the re-key request was not created."
    }

    try {
        $requestPath = Invoke-AdcsRenewalRequest -Issuing $Issuing -TransferPath $TransferPath -ReuseKeys $false
    }
    catch {
        return ("Failed:" + $_.Exception.Message)
    }

    Write-Log "Re-key request written to '$([System.IO.Path]::GetFileName($requestPath))'" -Tag "Ok"
    Write-Log "    After installation the CRL and CA certificate gain a (1) suffix and both generations stay served - delete nothing in the web folder" -Tag "Debug"
    Write-Log "    Microsoft on re-keying: every certificate this CA has issued has to be reissued. The old ones work while the previous certificate and CRL are published" -Tag "Warn"
    return "Requested"
}

function Invoke-AdcsRenewalOnlyRun {
    param(
        [Parameter(Mandatory)][object]$CertificateServices,
        [Parameter(Mandatory)][object]$Issuing,
        [Parameter(Mandatory)][string]$TransferPath
    )

    if (-not (Test-AdcsAuthorityInstalled)) {
        return (New-RoleResult -Status "ManualStepRequired" -Message "This design is a renewal ceremony and there is no certification authority on this server to renew.")
    }
    if (-not (Test-AdcsAuthorityCertified)) {
        return (New-RoleResult -Status "ManualStepRequired" -Message "This CA has never been certified, so there is nothing to renew - a first certificate is a build-mode run.")
    }

    # The same order the adopt path uses, for the same reason: the root CRL that came
    # back has to be reachable before certutil -installcert checks the chain of the
    # certificate that root just signed. This is the ceremony's own material, not the
    # design being reapplied, so it belongs in a run that touches nothing else.
    Publish-AdcsIncomingRootMaterial -CertificateServices $CertificateServices -TransferPath $TransferPath

    $outcome = Invoke-AdcsRenewalStep -Issuing $Issuing -TransferPath $TransferPath
    if ($outcome -like "Failed:*") {
        return (New-RoleResult -Status "Failed" -Message $outcome.Substring(7))
    }

    if ($outcome -eq "Requested") {
        return (New-RoleResult -Status "ManualStepRequired" -Message ("The renewal request is in '{0}' - carry the folder to the offline root and run the same command there." -f $TransferPath))
    }
    if ($outcome -eq "Waiting") {
        return (New-RoleResult -Status "ManualStepRequired" -Message ("A renewal request is already waiting in '{0}' - the root has not signed it yet." -f $TransferPath))
    }

    if ($outcome -eq "Installed") {
        # The only work this mode does beyond the swap, and it is not optional: the new
        # certificate and a fresh CRL have to be where the CDP and AIA say they are, or
        # every client checking revocation against the new generation finds nothing.
        $null = Confirm-AdcsWebPath -CertificateServices $CertificateServices
        Publish-AdcsCrl
        Set-AdcsWebPublishing -CertificateServices $CertificateServices -TransferPath $TransferPath
        return (New-RoleResult -Status "Completed" -Message "The renewed certificate is installed and republished. Nothing else was changed - this design is the ceremony only.")
    }

    $current = Get-AdcsAuthorityCertificate
    $daysLeft = if ($null -ne $current) { [int][math]::Floor(($current.NotAfter - (Get-Date)).TotalDays) } else { 0 }
    return (New-RoleResult -Status "Completed" -Message ("Nothing to renew yet - the CA certificate has {0} day(s) left and the window has not opened. Force it from the studio's Renewal tab when you want to rehearse." -f $daysLeft))
}

function Invoke-AdcsIssuingTier {
    param(
        [Parameter(Mandatory)][object]$CertificateServices,
        [Parameter(Mandatory)][string]$TransferPath
    )

    $issuing = Get-ConfigValue -InputObject $CertificateServices -Name "issuing"
    $mode = Get-AdcsMode -CertificateServices $CertificateServices

    # Renew mode leaves before any of the build-or-adopt machinery below. The ceremony
    # is the whole job: write the request, or install the certificate that came back,
    # then republish. Nothing else is touched - not the registry, not the templates, not
    # the endpoint - because the run that renews a CA certificate is not the run that
    # decides what the CA should look like, and doing both on the same visit is how a
    # ceremony acquires a second way to fail.
    if ($mode -eq "renew") {
        return (Invoke-AdcsRenewalOnlyRun -CertificateServices $CertificateServices -Issuing $issuing -TransferPath $TransferPath)
    }

    # The connector retrofit's half of the issuing CA, and the whole of it. Three
    # objects on a CA this design does not own: the SCEP templates, their enrollment
    # rights, and Issue and Manage Certificates for the group holding the NDES account
    # so Intune can revoke. Nothing that adopt does - no registry, no CRL periods, no
    # issued validity, no hardening, no publication URLs, no re-key, no web publishing -
    # because "I need a template published here" is not the same instruction as "this
    # design now describes your CA".
    if ($mode -eq "connector") {
        if (-not (Test-AdcsAuthorityInstalled)) {
            return (New-RoleResult -Status "ManualStepRequired" -Message "This design retrofits a connector onto an existing CA, but no certification authority is installed on this server - check certificateServices.issuing.computerName.")
        }

        # Same guard adopt uses, and for a smaller reason that is still worth having:
        # a design pointed at the wrong CA would publish its templates into the right
        # forest from the wrong machine and grant a group on a CA nobody meant.
        $liveName = Get-AdcsActiveCaName
        $designName = [string](Get-ConfigValue -InputObject $issuing -Name "caCommonName" -Default "")
        if (-not [string]::IsNullOrWhiteSpace($designName) -and
            -not $liveName.Equals($designName, [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Log "This server runs the CA '$liveName'; the design names '$designName'" -Tag "Error"
            return (New-RoleResult -Status "ManualStepRequired" -Message ("The design names the CA '{0}' but this server runs '{1}' - correct the name in the design." -f $designName, $liveName))
        }

        Write-Log "Connector retrofit on '$liveName': publishing the SCEP templates and granting the certificate managers group" -Tag "Run"

        $templatesApplied = Set-AdcsCertificateTemplate -CertificateServices $CertificateServices
        $securityApplied  = Set-AdcsCaSecurity -CertificateServices $CertificateServices

        if (-not $templatesApplied) {
            return (New-RoleResult -Status "ManualStepRequired" -Message "Not every SCEP template could be published or granted - the log above names which. NDES asks this CA for them by name, so it cannot issue until they are here.")
        }
        if (-not $securityApplied) {
            return (New-RoleResult -Status "ManualStepRequired" -Message "The templates are published, but the certificate managers group could not be given Issue and Manage Certificates - Intune cannot revoke until it has it.")
        }
        Write-Log "This CA keeps every other setting it has" -Tag "Debug"
        return (New-RoleResult -Status "Completed" -Message "The SCEP templates are published and the connector's group can revoke - run the same config on the NDES server next.")
    }

    if (-not (Test-AdcsAuthorityInstalled)) {
        if ($mode -eq "adopt") {
            return (New-RoleResult -Status "ManualStepRequired" -Message "The design adopts an existing CA, but no certification authority is installed on this server - check the computer name, or switch the design to build mode if a new CA is actually wanted.")
        }
        $requestPath = Install-AdcsIssuingAuthority -Issuing $issuing -TransferPath $TransferPath
        New-AdcsTransferManifest -Path $TransferPath
        return (New-RoleResult -Status "ManualStepRequired" -Message ("Carry '{0}' to the offline root and run the same command there. It holds '{1}'." -f $TransferPath, [System.IO.Path]::GetFileName($requestPath)))
    }

    if (-not (Test-AdcsAuthorityCertified)) {
        if (-not (Test-AdcsTransferManifest -Path $TransferPath)) {
            return (New-RoleResult -Status "Failed" -Message "The transfer folder does not match its manifest - do not install this chain.")
        }

        $signed = @(Get-ChildItem -Path (Join-Path -Path $TransferPath -ChildPath "*.cer") -File -ErrorAction SilentlyContinue)
        if ($signed.Count -eq 0) {
            # No certificate back yet. Two very different states hide behind that, and
            # telling somebody to "carry the folder over" when the folder holds nothing
            # to carry sends them round the loop again: the root answers "no request was
            # waiting", refreshes its CRL, and reports success.
            $pending = @(Get-ChildItem -Path (Join-Path -Path $TransferPath -ChildPath "*.req") -File -ErrorAction SilentlyContinue)
            if ($pending.Count -eq 0) {
                Write-Log "This CA is installed but not certified, and no .req is in '$TransferPath'" -Tag "Error"
                Write-Log "The request was written by the install and has since been deleted or overwritten - copying the root's folder over this one does that" -Tag "Error"
                Write-Log "The key pair it was made from is still here, but nothing on this server can rebuild the request file from it. Start the subordinate over:" -Tag "Info"
                Write-Log "    Uninstall-AdcsCertificationAuthority -Force" -Tag "Info"
                Write-Log "    then run this script again - it installs the CA and writes a fresh .req" -Tag "Info"
                Write-Log "Keep the two folders apart from here on: carry files into the transfer folder, never replace it" -Tag "Info"
                return (New-RoleResult -Status "ManualStepRequired" -Message ("The certificate request is missing from '{0}' - reinstall the subordinate CA to write a new one." -f $TransferPath))
            }
            return (New-RoleResult -Status "ManualStepRequired" -Message ("The subordinate CA is waiting for its certificate. Carry '{0}' - it holds '{1}' - to the offline root, run the same command there, and bring the folder back." -f $TransferPath, $pending[0].Name))
        }
        if ($signed.Count -gt 1) {
            return (New-RoleResult -Status "Failed" -Message "More than one .cer is in '$TransferPath' - leave only the certificate for this CA.")
        }

        # The root has to be trusted and reachable in the directory before the chain
        # is installed, or the service refuses to start.
        Publish-AdcsRootToDirectory -CertificateServices $CertificateServices -TransferPath $TransferPath

        $null = Invoke-AdcsUtility -FilePath "certutil.exe" -ArgumentList @("-installcert", $signed[0].FullName)
        Write-Log "Subordinate CA certificate installed" -Tag "Ok"

        Set-AdcsAuthorityConfiguration -CertificateServices $CertificateServices -TierName "issuing"

        Write-Log "Starting the certification authority service" -Tag "Run"
        Start-Service -Name "certsvc" -ErrorAction Stop
        $null = Wait-AdcsAuthorityReady
        Restart-AdcsService
        Publish-AdcsCrl

        Set-AdcsWebPublishing -CertificateServices $CertificateServices -TransferPath $TransferPath
        Set-AdcsRoleUserRight -CertificateServices $CertificateServices
        $null = Set-AdcsCaSecurity -CertificateServices $CertificateServices
        $null = Set-AdcsTemplateContainerAcl -CertificateServices $CertificateServices
        Set-AdcsCertificateTemplate -CertificateServices $CertificateServices
        # After the templates, never before: the account running this is a Domain Admin,
        # and its logon token predates the role groups created this same visit - so the
        # moment Domain Admins comes off the container, this run's own template writes
        # are refused. Everything the templates needed happens first; the strip is last.
        Remove-AdcsTemplateContainerBuiltinAdmin -CertificateServices $CertificateServices
        Register-AdcsBackupTask -CertificateServices $CertificateServices
        Write-AdcsIssuingExpiry -Issuing $issuing

        if ($script:adcsTemplateFailure.Count -gt 0) {
            return (New-RoleResult -Status "ManualStepRequired" -Message ("The issuing CA is online, but these template(s) could not be written: {0}. Fix the cause and run this again." -f (($script:adcsTemplateFailure | Select-Object -Unique) -join ", ")))
        }
        if ($script:adcsGrantFailure.Count -gt 0) {
            return (New-RoleResult -Status "ManualStepRequired" -Message ("The issuing CA is online, but no enrollment right could be written for: {0}. Create the group(s) and run this again." -f (($script:adcsGrantFailure | Select-Object -Unique) -join ", ")))
        }
        if (-not [string]::IsNullOrWhiteSpace($script:adcsWebFailure)) {
            return (New-RoleResult -Status "ManualStepRequired" -Message ("The CA is online, but its publication endpoint does not answer: {0}. That URL is inside every certificate this CA issues, so nothing should enroll until it does." -f $script:adcsWebFailure))
        }
        return (New-RoleResult -Status "Completed" -Message "The issuing CA is online and publishing.")
    }

    # Fully built. A run from here re-publishes whatever the root sent over, moves
    # the renewal along when its date has come, and reports the dates.
    Write-Log "The issuing CA is already certified" -Tag "Info"

    if ($mode -eq "adopt") {
        # Everything the design says about this CA is keyed to its common name - the
        # publication file names above all, which are frozen into every certificate it
        # issues from here on. A design describing a different CA is not a diff to
        # apply, it is the wrong file, and the fix is the assessment import.
        $liveName = Get-AdcsActiveCaName
        $designName = [string](Get-ConfigValue -InputObject $issuing -Name "caCommonName" -Default "")
        if (-not $liveName.Equals($designName, [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Log "This server runs the CA '$liveName'; the design describes '$designName'" -Tag "Error"
            Write-Log "Run '-Task AdcsAssess' here and import the assessment into the studio, so the design starts from what actually exists" -Tag "Info"
            return (New-RoleResult -Status "ManualStepRequired" -Message ("The design describes the CA '{0}' but this server runs '{1}' - import the assessment and re-export the config." -f $designName, $liveName))
        }

        # Adoption is the whole registry-and-hardening pass the install branch runs,
        # applied to a CA somebody else built: CRL periods, issued validity, audit,
        # the ESC mitigations and the publication URL layout. Forward-acting where
        # the values are frozen into certificates at issuance - the new CDP and AIA
        # reach certificates issued from now on, and whatever URL the old ones carry
        # has to keep answering until the last of them expires. Nothing here removes
        # a URL from being served; the design only adds its own layout.
        Write-Log "Adopting: applying this design's configuration to the existing CA" -Tag "Run"
        $null = Confirm-AdcsWebPath -CertificateServices $CertificateServices
        Set-AdcsAuthorityConfiguration -CertificateServices $CertificateServices -TierName "issuing"
        Restart-AdcsService
        Write-Log "CDP and AIA changes reach certificates issued from now on - the old publication location must stay served until the last one expires" -Tag "Debug"

        # Re-keying belongs to adopt and happens on this run, not on a later ceremony.
        # Taking over a 2048-bit CA and being told to come back at renewal time is a
        # year of waiting for the one thing the takeover was for, so the request is
        # written here: CAPolicy.inf first, then certutil -renewcert with a new key. The
        # root signs it exactly as it signs any other request, and the run after the
        # folder comes back installs it - the same three-visit shape the ceremony has,
        # started deliberately instead of by a date.
        $rekeyOutcome = Invoke-AdcsAdoptRekey -Issuing $issuing -TransferPath $TransferPath
        if ($rekeyOutcome -like "Failed:*") {
            return (New-RoleResult -Status "Failed" -Message $rekeyOutcome.Substring(7))
        }
        if ($rekeyOutcome -eq "Requested") {
            New-AdcsTransferManifest -Path $TransferPath
            return (New-RoleResult -Status "ManualStepRequired" -Message ("The design is adopted and a re-key request is in '{0}' - carry the folder to the offline root, then run this again here." -f $TransferPath))
        }
    }

    # Whatever the root sent over goes out before anything else touches a certificate -
    # see Publish-AdcsIncomingRootMaterial. The chain check inside certutil -installcert
    # is what stops the run otherwise, and it stops it on a dialog.
    Publish-AdcsIncomingRootMaterial -CertificateServices $CertificateServices -TransferPath $TransferPath

    # Then the renewal step, still ahead of the web publishing below: when the ceremony
    # folder holds a renewed certificate, the swap has to happen before that copies
    # CertEnroll into the web folder, or the new CA certificate is served one run late.
    $renewalOutcome = Invoke-AdcsRenewalStep -Issuing $issuing -TransferPath $TransferPath
    if ($renewalOutcome -like "Failed:*") {
        return (New-RoleResult -Status "Failed" -Message $renewalOutcome.Substring(7))
    }

    $incoming = @(Get-ChildItem -Path (Join-Path -Path $TransferPath -ChildPath "*.crl") -File -ErrorAction SilentlyContinue)
    if (($incoming.Count -gt 0) -or ($renewalOutcome -eq "Installed")) {
        if (-not (Test-AdcsTransferManifest -Path $TransferPath)) {
            return (New-RoleResult -Status "Failed" -Message "The transfer folder does not match its manifest - the incoming CRL was not published.")
        }
        Publish-AdcsRootToDirectory -CertificateServices $CertificateServices -TransferPath $TransferPath
        Set-AdcsWebPublishing -CertificateServices $CertificateServices -TransferPath $TransferPath
    }

    # Re-publish this CA's own CRL as well. It costs a second and it is the only thing
    # that repairs a first run whose publish failed - a CA can be certified, configured
    # and running with no CRL behind its own CDP, and every branch above this one is
    # skipped from then on, so nothing would ever try again until the weekly timer.
    $null = Confirm-AdcsWebPath -CertificateServices $CertificateServices
    Publish-AdcsCrl

    Set-AdcsRoleUserRight -CertificateServices $CertificateServices
    $null = Set-AdcsCaSecurity -CertificateServices $CertificateServices
    $null = Set-AdcsTemplateContainerAcl -CertificateServices $CertificateServices
    Set-AdcsCertificateTemplate -CertificateServices $CertificateServices
    # Same order rule as the first-build branch: the strip runs after every template
    # write, because the writing account is losing exactly the right it is using.
    Remove-AdcsTemplateContainerBuiltinAdmin -CertificateServices $CertificateServices
    Register-AdcsBackupTask -CertificateServices $CertificateServices
    Write-AdcsIssuingExpiry -Issuing $issuing
    if ($script:adcsTemplateFailure.Count -gt 0) {
        return (New-RoleResult -Status "ManualStepRequired" -Message ("These template(s) could not be written: {0}. Fix the cause and run this again." -f (($script:adcsTemplateFailure | Select-Object -Unique) -join ", ")))
    }
    if ($script:adcsGrantFailure.Count -gt 0) {
        return (New-RoleResult -Status "ManualStepRequired" -Message ("No enrollment right could be written for: {0}. Those templates are published and nobody can enroll for them." -f (($script:adcsGrantFailure | Select-Object -Unique) -join ", ")))
    }
    if (-not [string]::IsNullOrWhiteSpace($script:adcsWebFailure)) {
        return (New-RoleResult -Status "ManualStepRequired" -Message ("The CA is online, but its publication endpoint does not answer: {0}. That URL is inside every certificate this CA issues, so nothing should enroll until it does." -f $script:adcsWebFailure))
    }
    if (($renewalOutcome -eq "Requested") -or ($renewalOutcome -eq "Waiting")) {
        return (New-RoleResult -Status "ManualStepRequired" -Message ("The CA is current, but its certificate is inside the renewal window. Carry '{0}' - it holds '{1}.req' - to the offline root, run the same command there, and bring the folder back." -f $TransferPath, (Get-AdcsRenewalBaseName -Issuing $issuing)))
    }
    if ($renewalOutcome -eq "Installed") {
        return (New-RoleResult -Status "Completed" -Message "The issuing CA is configured and its certificate was renewed.")
    }
    return (New-RoleResult -Status "Completed" -Message "The issuing CA is configured and current.")
}

# ---------------------------[ Directory tier ]---------------------------
# The third machine, and the only one that is not a CA. Everything a PKI needs to
# exist *before* a CA does - the enrollment groups, so somebody can put servers in
# them while the root ceremony is still going on, and the publication alias, without
# which the issuing CA refuses to build at all - lives in Active Directory and DNS,
# and both of those belong to a domain controller. Doing it from the issuing CA works
# and is still the fallback, but it puts the work at the end of the last run, which is
# exactly when there is no time left to notice a group nobody has filled.
#
# Nothing here is exclusive to this tier: every step is the same idempotent function
# the issuing CA calls, so a design with no directory tier loses nothing, and one that
# has it simply gets there first.
# A question, and nothing else. It used to answer *and* explain, in the words of the one
# caller that wants a yes - and the two callers that want a no are the SCEP tier, which
# is a member server on purpose. So the NDES run opened with two red lines about the
# directory tier, on a machine that was correctly not a domain controller, and then
# carried on and configured NDES perfectly. Field-hit 2026-08-16: the reader has no way
# to tell that from a run that failed. Whoever asks now says what a no means to them.
function Test-AdcsDomainController {
    $domainRole = -1
    try {
        $computerSystem = Get-CimInstance -ClassName "Win32_ComputerSystem" -ErrorAction Stop
        $domainRole = [int]$computerSystem.DomainRole
    }
    catch {
        Write-Log "Could not read this machine's domain role: $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    # 4 is a backup domain controller, 5 the one holding the PDC emulator. Anything
    # below 4 is a workstation or a member server.
    return (($domainRole -eq 4) -or ($domainRole -eq 5))
}

# The alias every certificate the PKI issues names in its CDP and AIA. Created here,
# on the machine that owns the zone, rather than on the CA: the CA is a member server
# that would need RSAT and delegated rights to write DNS remotely. The CA still
# refuses to build while the name does not resolve - this is what keeps that from
# being a manual step, not a replacement for the check.
#
# The record is never repointed. An alias that already exists belongs to whoever made
# it, and taking it over would silently move revocation checking for an entire PKI.
function Set-AdcsPublicationAlias {
    param([Parameter(Mandatory)][object]$CertificateServices)

    $shared      = Get-ConfigValue -InputObject $CertificateServices -Name "shared"
    $issuing     = Get-ConfigValue -InputObject $CertificateServices -Name "issuing"
    $pkiBaseUrl  = [string](Get-ConfigText -InputObject $shared -Name "pkiBaseUrl" -Default "")
    $issuingName = [string](Get-ConfigText -InputObject $issuing -Name "computerName" -Default "")
    if ([string]::IsNullOrWhiteSpace($pkiBaseUrl) -or [string]::IsNullOrWhiteSpace($issuingName)) { return $true }

    $hostName = ""
    try { $hostName = ([uri]$pkiBaseUrl).Host }
    catch { $hostName = "" }
    if ([string]::IsNullOrWhiteSpace($hostName)) {
        Write-Log "certificateServices.shared.pkiBaseUrl is not a URL - no publication alias to create" -Tag "Error"
        return $false
    }

    $label = $hostName.Split(".")[0]
    if ($label.Length + 1 -ge $hostName.Length) {
        Write-Log "The publication URL names the zone itself ('$hostName') - nothing to alias" -Tag "Info"
        return $true
    }
    $zoneName = $hostName.Substring($label.Length + 1)
    $target   = "$issuingName.$([string](Get-ConfigText -InputObject $shared -Name 'forestDomainName' -Default $zoneName))"

    if (-not (Get-Command -Name "Get-DnsServerZone" -ErrorAction SilentlyContinue)) {
        Write-Log "The DnsServer module is not available here, so '$hostName' has to be created wherever the zone is served:" -Tag "Warn"
        Write-Log "    Add-DnsServerResourceRecordCName -ZoneName $zoneName -Name $label -HostNameAlias $target" -Tag "Warn"
        return $true
    }

    if ($null -eq (Get-DnsServerZone -Name $zoneName -ErrorAction SilentlyContinue)) {
        Write-Log "This server does not host '$zoneName', so the publication alias has to be created wherever that zone lives:" -Tag "Warn"
        Write-Log "    Add-DnsServerResourceRecordCName -ZoneName $zoneName -Name $label -HostNameAlias $target" -Tag "Warn"
        return $true
    }

    $existing = @(Get-DnsServerResourceRecord -ZoneName $zoneName -Name $label -ErrorAction SilentlyContinue)
    if ($existing.Count -gt 0) {
        $alias = ""
        foreach ($record in $existing) {
            if ($record.RecordType -eq "CNAME") { $alias = ([string]$record.RecordData.HostNameAlias).TrimEnd(".") }
        }
        if ($alias.Equals($target, [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Log "'$hostName' already points at $target" -Tag "Info"
        }
        else {
            Write-Log "'$hostName' already exists and this run did not create it - leaving it alone" -Tag "Warn"
            Write-Log "It is the CDP and AIA host of every certificate this PKI issues, so make sure it reaches $target" -Tag "Warn"
        }
        return $true
    }

    Write-Log "Creating the publication alias '$hostName' -> $target" -Tag "Run"
    try {
        Add-DnsServerResourceRecordCName -ZoneName $zoneName -Name $label -HostNameAlias $target -ErrorAction Stop
    }
    catch {
        Write-Log "Add-DnsServerResourceRecordCName failed for '$hostName': $($_.Exception.Message)" -Tag "Error"
        return $false
    }
    Write-Log "The certificate authority's publication URL now resolves" -Tag "Ok"
    return $true
}

# Group Policy objects for the PKI. Two kinds, and only one of them has an ADMX file
# behind it - which is worth knowing before reading the values below, because they look
# like raw registry writes and are not.
#
# An ADMX file *describes* registry values; it is not a storage format. What a GPO
# stores is registry.pol, and Set-GPRegistryValue writes exactly that file plus the
# Registry client-side extension registration - the same bytes GPMC writes when the
# setting is clicked in the editor. A value that matches a loaded ADMX definition is
# rendered by GPMC under Administrative Templates with its friendly name and stays
# editable there; one that matches nothing shows up as "Extra Registry Settings".
#
#   Remote Desktop settings -> TerminalServer.admx, so they render as
#     Administrative Templates > Windows Components > Remote Desktop Services >
#     Remote Desktop Session Host > Security
#   Auto-enrollment         -> no ADMX exists. It is a Public Key Policies node
#     (Certificate Services Client - Auto-Enrollment), and registry.pol is what the
#     GPMC UI itself writes for it. There is no other mechanism.
#
# Both live under HKLM\Software\Policies, which is what makes them *policy* rather than
# preferences: the values are revoked when the GPO stops applying.
$script:adcsAutoEnrollmentKey = "HKLM\Software\Policies\Microsoft\Cryptography\AutoEnrollment"
$script:adcsTerminalServerKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

# AEPolicy is a bit field: 1 enables auto-enrollment at all, 2 renews expired
# certificates and cleans up revoked ones, 4 re-enrolls when the template changes.
# 1 alone enrolls once and never notices anything afterwards, which is why every
# guide says 7 and none of them says why.
$script:adcsAutoEnrollmentPolicy = 7

function Get-AdcsGroupPolicySetting {
    param([Parameter(Mandatory)][object]$Item)

    $kind = [string](Get-ConfigText -InputObject $Item -Name "kind" -Default "")

    if ($kind -eq "autoEnrollment") {
        return @(
            [pscustomobject]@{ Key = $script:adcsAutoEnrollmentKey; Name = "AEPolicy"; Type = "DWord"; Value = $script:adcsAutoEnrollmentPolicy
                               Describe = "Certificate Services Client - Auto-Enrollment: enabled, renewing and updating from templates" }
        )
    }

    if ($kind -eq "remoteDesktopAuthentication") {
        # The template name and nothing else. The security layer and Network Level
        # Authentication belong to whatever owns RDS hardening - this policy exists to
        # point the listener at a certificate, and a policy that quietly also sets two
        # security settings is one nobody can link without reading it first.
        $templateName = [string](Get-ConfigText -InputObject $Item -Name "templateName" -Default "RemoteDesktopAuthentication")
        return @(
            [pscustomobject]@{ Key = $script:adcsTerminalServerKey; Name = "CertTemplateName"; Type = "String"; Value = $templateName
                               Describe = "Server authentication certificate template: $templateName" }
        )
    }

    return @()
}

function New-AdcsGroupPolicy {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][object]$Item
    )

    $settings = @(Get-AdcsGroupPolicySetting -Item $Item)
    if ($settings.Count -eq 0) {
        Write-Log "'$Name' names no known kind of policy - skipping it" -Tag "Error"
        return $false
    }

    Write-Log "Creating the group policy object '$Name'" -Tag "Run"
    try {
        $null = New-GPO -Name $Name -Comment "Created by Windows Server Role Studio for the PKI. Computer settings only." -ErrorAction Stop
    }
    catch {
        Write-Log "Could not create '$Name': $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    foreach ($setting in $settings) {
        try {
            $null = Set-GPRegistryValue -Name $Name -Key $setting.Key -ValueName $setting.Name -Type $setting.Type -Value $setting.Value -ErrorAction Stop
        }
        catch {
            Write-Log "Could not set '$($setting.Name)' in '$Name': $($_.Exception.Message)" -Tag "Error"
            return $false
        }
        Write-Log "    $($setting.Describe)" -Tag "Debug"
    }

    # Every one of these is a computer policy. Leaving the user half enabled costs a
    # pointless pass on every user logon for settings the object does not contain.
    try {
        $gpo = Get-GPO -Name $Name -ErrorAction Stop
        $gpo.GpoStatus = "UserSettingsDisabled"
    }
    catch {
        Write-Log "Could not disable the user half of '$Name': $($_.Exception.Message)" -Tag "Warn"
    }

    Write-Log "'$Name' created - user configuration disabled" -Tag "Ok"
    return $true
}

# The WMI filter lookup and attachment moved to Directory.ps1 as Set-StudioGpoWmiFilter -
# the FSLogix policy the Remote Desktop design creates attaches one too, and the reasoning
# about not creating these objects belongs with the shared helper rather than here.
#
# The link machinery moved there too (Get-StudioGpoLinkTarget, Add-StudioGpoLink,
# Set-StudioGpoLink). Every role that creates a policy object now says where it belongs,
# so where a link goes and what happens when the container is missing is one answer for
# the whole studio rather than this file's private one.

function Set-AdcsGroupPolicy {
    param([Parameter(Mandatory)][object]$CertificateServices)

    $directory   = Get-ConfigValue -InputObject $CertificateServices -Name "directory"
    $groupPolicy = Get-ConfigValue -InputObject $directory -Name "groupPolicy"
    if ($null -eq $groupPolicy) {
        Write-Log "This config has no certificateServices.directory.groupPolicy section, so no policy objects are created" -Tag "Info"
        Write-Log "It was exported before that section existed - re-export the design to pick it up" -Tag "Debug"
        return $true
    }
    if (-not [bool](Get-ConfigValue -InputObject $groupPolicy -Name "enabled" -Default $false)) {
        Write-Log "Group policy creation is switched off" -Tag "Info"
        return $true
    }

    $items = @(Get-ConfigArray -InputObject $groupPolicy -Name "items" | Where-Object {
        [bool](Get-ConfigValue -InputObject $_ -Name "enabled" -Default $true) })
    if ($items.Count -eq 0) { return $true }

    if (-not (Get-Command -Name "New-GPO" -ErrorAction SilentlyContinue)) {
        Write-Log "The GroupPolicy module is not available, so no policy objects were created" -Tag "Error"
        Write-Log "    Install-WindowsFeature -Name GPMC" -Tag "Error"
        return $false
    }

    Write-Log "Creating the $($items.Count) group policy object(s) this design describes" -Tag "Run"
    # Resolved only if something actually asks for a filter or a 'domainControllers'
    # link. Reading it up front made a directory hiccup fail the whole step before a
    # single object was created.
    $domainDn = ""
    $allDone = $true
    $linkedAny = $false

    foreach ($item in $items) {
        $name = [string](Get-ConfigText -InputObject $item -Name "name" -Default "")
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        $existing = $null
        try { $existing = Get-GPO -Name $name -ErrorAction SilentlyContinue }
        catch { $existing = $null }

        if ($null -ne $existing) {
            # Same rule as the enrollment groups and the certificate templates: the
            # object is here, so somebody may have tuned it, and a run that quietly
            # rewrites what it finds is a run nobody can leave a change in.
            Write-Log "'$name' already exists - leaving its settings alone" -Tag "Info"
        }
        elseif (-not (New-AdcsGroupPolicy -Name $name -Item $item)) {
            $allDone = $false
            continue
        }

        # Attached whether this run created the object or found it: the filter is the part
        # that changes between runs - a domain built after the design was written now has
        # the filter the last run had to report missing.
        $filterName = [string](Get-ConfigText -InputObject $item -Name "wmiFilter" -Default "")
        if (-not [string]::IsNullOrWhiteSpace($filterName)) {
            if ([string]::IsNullOrWhiteSpace($domainDn)) { $domainDn = Get-AdcsDefaultNamingContext }
            $aliases = @(Get-ConfigArray -InputObject $item -Name "wmiFilterAliases")
            Set-StudioGpoWmiFilter -Name $name -FilterName $filterName -Alias $aliases -DomainDn $domainDn
        }

        # Linked wherever the design says, whether this run created the object or found
        # one that was already here: a container that did not exist when the object was
        # built exists now, and the link is the step that makes any of this take effect.
        # 'domainControllers' still expands to that OU's DN - the studio writes plain
        # distinguished names, but the keyword predates it and a hand-written config
        # that uses it is naming exactly what it means.
        $linkTo = @(Get-StudioGpoLinkTarget -InputObject $item -Name "linkTo" -DomainDn $domainDn)
        if ($linkTo.Count -gt 0) { $linkedAny = $true }
        if (-not (Set-StudioGpoLink -Name $name -TargetDn $linkTo `
                    -UnlinkedNote "it changes nothing until you link it where those machines are")) {
            $allDone = $false
        }
    }

    if (-not $linkedAny) {
        Write-Log "None of these is linked - they change nothing until you link them where they belong" -Tag "Info"
    }
    return $allDone
}

function Invoke-AdcsDirectoryTier {
    param([Parameter(Mandatory)][object]$CertificateServices)

    $script:adcsGrantFailure = @()
    $access = Get-ConfigValue -InputObject $CertificateServices -Name "access"
    $mode = Get-AdcsMode -CertificateServices $CertificateServices

    # The connector retrofit does the three directory objects NDES needs and stops.
    # The publication alias belongs to a PKI this design does not own - the CA already
    # publishes wherever it publishes - and the group policy objects are a whole
    # enrolment design nobody asked this run to have an opinion about. Creating either
    # against somebody else's CA would be the retrofit quietly becoming an adoption.
    if ($mode -eq "connector") {
        Write-Log "Connector retrofit: the service account, its enrollment group and the certificate managers group" -Tag "Info"

        $rolesApplied = Set-AdcsRoleGroup -CertificateServices $CertificateServices
        Set-AdcsAccessGroup -Access $access
        $scepApplied  = Set-AdcsScepDirectory -CertificateServices $CertificateServices
        # The CA in this mode is somebody else's and its publication alias is left to
        # them - but the SCEP endpoint's name is this design's own, and a connector
        # nobody inside can resolve is half a connector.
        $null = Set-AdcsScepDnsRecord -CertificateServices $CertificateServices

        if (-not $scepApplied) {
            return (New-RoleResult -Status "ManualStepRequired" -Message "The SCEP service account or its memberships could not be written. NDES refuses to configure until the account exists.")
        }
        if (-not $rolesApplied) {
            return (New-RoleResult -Status "ManualStepRequired" -Message "The service account is ready, but the certificate managers group could not be created or is unusable - Intune cannot revoke until it is.")
        }
        Write-Log "The directory half is done - run the same config on the issuing CA for the templates and the CA permission" -Tag "Info"
        return (New-RoleResult -Status "Completed" -Message "The SCEP service account and its groups are ready - run the same config on the issuing CA next.")
    }

    Write-Log "Preparing the directory and DNS for this PKI - no CA is installed here" -Tag "Info"

    $rolesApplied  = Set-AdcsRoleGroup -CertificateServices $CertificateServices
    Set-AdcsAccessGroup -Access $access
    $scepApplied   = Set-AdcsScepDirectory -CertificateServices $CertificateServices
    $aliasApplied  = Set-AdcsPublicationAlias -CertificateServices $CertificateServices
    # The SCEP endpoint's public name, made to answer indoors as well - the same split
    # DNS the Exchange namespace and the Remote Desktop published name each need.
    $scepDnsApplied = Set-AdcsScepDnsRecord -CertificateServices $CertificateServices
    $policyApplied = Set-AdcsGroupPolicy -CertificateServices $CertificateServices

    if (-not $aliasApplied) {
        return (New-RoleResult -Status "ManualStepRequired" -Message "The enrollment groups are ready, but the publication alias could not be created. The issuing CA refuses to build until that name resolves.")
    }
    if (-not $policyApplied) {
        return (New-RoleResult -Status "ManualStepRequired" -Message "The directory and DNS are ready, but not every group policy object could be created. Nothing enrolls automatically until they are.")
    }
    if (-not $rolesApplied) {
        return (New-RoleResult -Status "ManualStepRequired" -Message "The directory and DNS are ready, but not every role group could be created or is usable. Fix those before the CA is given its permissions.")
    }
    if (-not $scepApplied) {
        return (New-RoleResult -Status "ManualStepRequired" -Message "The directory is ready, but the SCEP service account or its memberships could not be written. NDES refuses to configure until the account exists.")
    }
    # Last of the four, and the least fatal: everything else here is something a later
    # run cannot proceed without, while a missing record is an endpoint that works from
    # outside and not from a desk. Reported, never silent.
    if (-not $scepDnsApplied) {
        return (New-RoleResult -Status "ManualStepRequired" -Message "The directory is ready, but the SCEP endpoint's internal record could not be created - clients inside the network cannot reach the connector until it exists.")
    }

    # ESC10 is the KDC-side half of what the SID extension check on the CA covers: weak
    # certificate-to-account mapping. Nothing to configure any more - since the September
    # 2025 update the StrongCertificateBindingEnforcement registry value is permanently
    # ignored and every domain controller enforces strong mapping. Said out loud so the
    # report reads complete rather than silently depending on a Windows update.
    Write-Log "Strong certificate mapping (KB5014754) is enforced by Windows itself since September 2025" -Tag "Debug"

    Write-Log "The certification authorities can be built now - this half is done" -Tag "Info"
    return (New-RoleResult -Status "Completed" -Message "Active Directory and DNS are prepared for the PKI.")
}

# ---------------------------[ Entry Points ]---------------------------
# The host name in the CDP and AIA URLs is frozen into every certificate this CA
# issues, for that certificate's whole life. A name that does not resolve is therefore
# checked here, with the CA still unbuilt, rather than discovered by a client failing
# a revocation check a year later - by which time the only fix is reissuing everything.
# The published guidance is a dedicated alias (pki.<domain>) rather than the CA's own
# host name, so the CA can be rebuilt, renamed or put behind a pair of web servers
# without touching a single issued certificate; naming the machine is a warning, not a
# refusal, because it works - it just cannot be undone later.
# 'Web-Server' is a container. Installed with its default role services it serves
# files; installed as a *dependency* of something else, Windows brings only what that
# something needed - which is how a CA ends up with an IIS that starts, answers, and
# has no static file handler. A CRL is a static file, so that IIS 404s every CDP fetch
# while looking perfectly healthy: the tell in IIS Manager is a Default Web Site with
# almost no icons in Features View.
#
# This **reports**; it does not refuse. Feature inventories are the wrong thing to gate
# a CA on - the names and their defaults move between Windows builds, and being wrong
# here would block a build that works. What decides is Test-AdcsPublicationEndpoint,
# which asks the endpoint for a CRL once it exists. This runs first only because it can
# name the missing piece before the CA is built rather than after.
#
# Answered from IIS's own configuration rather than from Get-WindowsFeature, which
# walks the whole component store - tens of seconds a call, painting "Collecting
# data..." across the console while it does. It is also the more direct question: a
# role service matters here because of the module it registers, and that is exactly
# what applicationHost.config lists.
function Get-AdcsIisGlobalModule {
    if ($null -ne $script:adcsIisModuleCache) { return $script:adcsIisModuleCache }

    $script:adcsIisModuleCache = @()
    $configPath = Join-Path -Path $env:SystemRoot -ChildPath "system32\inetsrv\config\applicationHost.config"
    if (-not (Test-Path -LiteralPath $configPath)) { return $script:adcsIisModuleCache }

    try { $text = Get-Content -LiteralPath $configPath -Raw -ErrorAction Stop }
    catch {
        Write-Log "Could not read applicationHost.config: $($_.Exception.Message)" -Tag "Debug"
        return $script:adcsIisModuleCache
    }

    # A globalModules entry carries an image path. The name-only <add> elements in the
    # other sections do not, which is what keeps this to the modules really registered.
    foreach ($match in [regex]::Matches($text, '<add\s+name="([^"]+)"\s+image=')) {
        $script:adcsIisModuleCache += $match.Groups[1].Value
    }
    return $script:adcsIisModuleCache
}

function Test-AdcsWebRoleService {
    $wanted = @(
        [pscustomobject]@{ Name = "Web-Server"
                           Why = "the endpoint that serves this CA's CRLs and certificates" },
        [pscustomobject]@{ Name = "Web-Static-Content"
                           Why = "a CRL is a static file; without this handler every CDP and AIA fetch answers 404.3" },
        [pscustomobject]@{ Name = "Web-Filtering"
                           Why = "carries allowDoubleEscaping; absent, nothing blocks the '+' in a delta CRL name either" },
        [pscustomobject]@{ Name = "Web-Dir-Browsing"
                           Why = "the folder listing this endpoint offers" }
    )

    # Each role service is present exactly when the thing it installs is: appcmd for the
    # web server itself, a registered module for the other three.
    $modules = @(Get-AdcsIisGlobalModule)
    $state = @{
        "Web-Server"         = (Test-Path -LiteralPath (Join-Path -Path $env:SystemRoot -ChildPath "system32\inetsrv\appcmd.exe"))
        "Web-Static-Content" = ($modules -contains "StaticFileModule")
        "Web-Filtering"      = ($modules -contains "RequestFilteringModule")
        "Web-Dir-Browsing"   = ($modules -contains "DirectoryListingModule")
    }

    $missing = @()
    foreach ($service in $wanted) {
        if ($state.ContainsKey($service.Name) -and $state[$service.Name]) { continue }
        $missing += $service.Name
        Write-Log "'$($service.Name)' is not installed - $($service.Why)" -Tag "Warn"
    }

    if ($missing.Count -eq 0) { return }
    Write-Log "    Install-WindowsFeature -Name $($missing -join ', ')" -Tag "Warn"
    Write-Log "The run carries on and checks the endpoint for real once the CRL is published" -Tag "Warn"
}

function Test-AdcsPublicationName {
    param([Parameter(Mandatory)][object]$CertificateServices)

    $shared     = Get-ConfigValue -InputObject $CertificateServices -Name "shared"
    $pkiBaseUrl = [string](Get-ConfigValue -InputObject $shared -Name "pkiBaseUrl" -Default "")
    if ([string]::IsNullOrWhiteSpace($pkiBaseUrl)) { return $true }

    $hostName = ""
    try { $hostName = ([uri]$pkiBaseUrl).Host }
    catch { $hostName = "" }

    if ([string]::IsNullOrWhiteSpace($hostName)) {
        Write-Log "certificateServices.shared.pkiBaseUrl is not a URL: '$pkiBaseUrl'" -Tag "Error"
        return $false
    }

    $addresses = @()
    try { $addresses = @([System.Net.Dns]::GetHostAddresses($hostName)) }
    catch { $addresses = @() }

    if ($addresses.Count -eq 0) {
        $label = $hostName.Split(".")[0]
        $zone  = $hostName.Substring([math]::Min($label.Length + 1, $hostName.Length))
        Write-Log "'$hostName' does not resolve - it is the CDP and AIA host in every certificate this CA would issue" -Tag "Error"
        Write-Log "    Add-DnsServerResourceRecordCName -ZoneName $zone -Name $label -HostNameAlias $env:COMPUTERNAME.$zone" -Tag "Error"
        return $false
    }

    $local = @()
    try { $local = @([System.Net.Dns]::GetHostAddresses([string]$env:COMPUTERNAME) | ForEach-Object { $_.IPAddressToString }) }
    catch { $local = @() }

    $servedHere = $false
    foreach ($address in $addresses) {
        if ($local -contains $address.IPAddressToString) { $servedHere = $true }
    }
    if (-not $servedHere) {
        Write-Log "'$hostName' resolves to $(($addresses | ForEach-Object { $_.IPAddressToString }) -join ', '), which is not this server - make sure that host serves the CRL folder" -Tag "Warn"
    }

    if ($hostName.Split(".")[0].Equals([string]$env:COMPUTERNAME, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Log "The CDP and AIA URLs name this server directly. A dedicated alias - pki.<domain> as a CNAME - is what lets the CA be rebuilt or moved without reissuing every certificate." -Tag "Warn"
    }

    Write-Log "CDP and AIA will be published as $pkiBaseUrl" -Tag "Info"
    return $true
}

function Test-AdcsPrerequisite {
    param([object]$Config)

    $certificateServices = Get-ConfigValue -InputObject $Config -Name "certificateServices"
    $tierName = Resolve-AdcsTier -CertificateServices $certificateServices

    if ([string]::IsNullOrWhiteSpace($tierName)) {
        $named = @()
        foreach ($candidate in @("root", "issuing", "scep", "directory")) {
            $name = [string](Get-ConfigText -InputObject (Get-AdcsTierSection -CertificateServices $certificateServices -TierName $candidate) -Name "computerName" -Default "")
            if (-not [string]::IsNullOrWhiteSpace($name)) { $named += "'$name' ($candidate)" }
        }
        Write-Log "This machine is '$env:COMPUTERNAME' but the config describes $($named -join ', ')" -Tag "Error"
        return $false
    }

    Write-Log "This server is the $tierName tier of the PKI" -Tag "Info"
    $tier = Get-AdcsTierSection -CertificateServices $certificateServices -TierName $tierName
    $passed = $true

    # The directory tier installs nothing and signs nothing. What it needs is to be a
    # domain controller, and for the groups it is about to create to have somewhere to
    # go - both checked before anything is written, because a half-prepared directory
    # is what the CA runs behind it would trip over.
    if ($tierName -eq "directory") {
        if (-not (Test-AdcsDomainController)) {
            # The one caller that wants a yes, so the one that explains a no.
            Write-Log "The directory tier names this server, but it is not a domain controller" -Tag "Error"
            Write-Log "It creates groups in the directory and a record in the forest zone - both belong on a DC" -Tag "Error"
            return $false
        }
        return (Test-AdcsAccessContainer -CertificateServices $certificateServices)
    }

    # The SCEP tier holds no CA either - what it needs is to be a domain member that
    # is not a domain controller, with the NDES role service's payload on disk. The
    # tier run repeats the mscep.dll check with the Install-WindowsFeature line, so a
    # missing role service reports there rather than blocking the plan here.
    if ($tierName -eq "scep") {
        if (Test-AdcsDomainController) {
            Write-Log "NDES must not run on a domain controller - point the SCEP tier at a member server" -Tag "Error"
            return $false
        }
        # PKCS mode installs nothing at all, so there is no feature, no payload and no
        # role service to check for here - the tier run does its own prerequisites.
        return $true
    }

    # The two CA tiers need the role the engine no longer checks for them - see the empty
    # Feature in the registry, which exists so a domain controller is not asked for a CA
    # feature. Asked of the service registration rather than Get-WindowsFeature:
    # installing the role service is what creates CertSvc, and reading one registry key
    # is instant where the feature query walks the component store for most of a minute.
    if (-not (Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc")) {
        Write-Log "The Active Directory Certificate Services role is not installed on this server" -Tag "Error"
        Write-Log "    Install-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools" -Tag "Error"
        $passed = $false
    }

    if ([string]::IsNullOrWhiteSpace([string](Get-ConfigValue -InputObject $tier -Name "caCommonName" -Default ""))) {
        Write-Log "certificateServices.$tierName.caCommonName is empty" -Tag "Error"
        $passed = $false
    }

    $isDomainMember = $false
    try {
        $computerSystem = Get-CimInstance -ClassName "Win32_ComputerSystem" -ErrorAction Stop
        $isDomainMember = [bool]$computerSystem.PartOfDomain
    }
    catch {
        Write-Log "Could not read the domain membership: $($_.Exception.Message)" -Tag "Info"
    }

    if ($tierName -eq "root") {
        if ($isDomainMember) {
            Write-Log "This root CA is domain joined - a root belongs on a standalone workgroup machine, kept offline" -Tag "Warn"
        }
        # An offline root has no domain time source and spends most of its life
        # powered off. Its clock decides what 'not before' means on the certificate
        # it signs, and a drifted one produces a chain nothing will accept yet.
        Write-Log "This server believes it is $(Get-Date -Format 'yyyy-MM-dd HH:mm') - check that against a trusted clock before signing anything" -Tag "Info"
        return $passed
    }

    $null = Test-AdcsWebEnrollmentAbsent

    # The HTTP endpoint is the only revocation path a non-domain client has, and the
    # URL is stamped into every certificate this CA issues from the first one onward.
    # Building the CA without it means certificates carrying a dead URL for their whole
    # life, so a missing Web Server role stops the run rather than being logged and
    # skipped. This script configures roles; installing one stays a deliberate step.
    $web = Get-ConfigValue -InputObject $tier -Name "webPublishing"
    if (($null -ne $web) -and [bool](Get-ConfigValue -InputObject $web -Name "enabled" -Default $false)) {
        Test-AdcsWebRoleService
        if (-not (Test-AdcsPublicationName -CertificateServices $certificateServices)) { $passed = $false }
    }

    if (-not $isDomainMember) {
        Write-Log "An enterprise subordinate CA has to be domain joined" -Tag "Error"
        $passed = $false
    }

    # Registering an enterprise CA writes to the Configuration naming context, which
    # nothing below Enterprise Admins is allowed to do.
    $isEnterpriseAdmin = $false
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        foreach ($group in $identity.Groups) {
            if ([string]$group.Value -match "-519$") { $isEnterpriseAdmin = $true }
        }
    }
    catch {
        Write-Log "Could not read the group membership of this session: $($_.Exception.Message)" -Tag "Info"
    }

    if (-not $isEnterpriseAdmin) {
        Write-Log "This session is not a member of Enterprise Admins - installing an enterprise CA will be refused by AD" -Tag "Error"
        $passed = $false
    }

    return $passed
}

function Invoke-AdcsConfiguration {
    param([object]$Config)

    # The SCEP tier registers the shared nightly certificate task, which needs the whole
    # document rather than this role's section - the task renews every certificate the
    # server holds, whichever role asked for it.
    $script:currentConfig = $Config

    $certificateServices = Get-ConfigValue -InputObject $Config -Name "certificateServices"
    $tierName = Resolve-AdcsTier -CertificateServices $certificateServices
    if ([string]::IsNullOrWhiteSpace($tierName)) {
        return (New-RoleResult -Status "Failed" -Message "This machine matches none of the root, issuing or directory computer names.")
    }

    # Before the transfer folder: neither of these has an air gap to cross, and
    # creating that folder on a domain controller or the NDES box would be litter.
    if ($tierName -eq "directory") {
        return (Invoke-AdcsDirectoryTier -CertificateServices $certificateServices)
    }
    if ($tierName -eq "scep") {
        return (Invoke-AdcsScepTier -CertificateServices $certificateServices)
    }

    # The connector retrofit has no air gap to cross either: it never installs a CA,
    # never renews one and never carries a certificate to an offline root, so creating
    # the transfer folder on somebody else's issuing CA would be litter with a manifest
    # in it. The tier is called with an empty path it never reads.
    # Parenthesised deliberately: `Get-AdcsMode -X $y -eq "z"` binds -eq as a parameter
    # name rather than comparing anything. And the path is resolved but NOT confirmed -
    # Confirm-AdcsTransferPath is what creates the folder, and this tier never reads it.
    if ((Get-AdcsMode -CertificateServices $certificateServices) -eq "connector") {
        return (Invoke-AdcsIssuingTier -CertificateServices $certificateServices `
            -TransferPath (Get-AdcsTransferPath -CertificateServices $certificateServices))
    }

    $transferPath = Confirm-AdcsTransferPath -Path (Get-AdcsTransferPath -CertificateServices $certificateServices)

    if ($tierName -eq "root") {
        return (Invoke-AdcsRootTier -CertificateServices $certificateServices -TransferPath $transferPath)
    }
    return (Invoke-AdcsIssuingTier -CertificateServices $certificateServices -TransferPath $transferPath)
}

# ---------------------------[ Assessment ]---------------------------
# The read-only half of adopt mode. See Invoke-AdcsAssessment at the bottom of this
# region for what the task does and why both CAs get visited.

function Get-AdcsAssessmentRegistry {
    param([Parameter(Mandatory)][string]$CaName)

    $base = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName"
    $values = @{}
    foreach ($path in @($base, "$base\CSP", "$base\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")) {
        try {
            $key = Get-ItemProperty -Path $path -ErrorAction Stop
        }
        catch {
            continue
        }
        foreach ($property in $key.PSObject.Properties) {
            if ($property.Name -like "PS*") { continue }
            $values[$property.Name] = $property.Value
        }
    }
    return $values
}

# The first http:// entry in the CRL publication list, with the file name stripped -
# which is what this design calls the publication base URL. A CA that publishes no
# HTTP CDP reports an empty string, and the studio then derives its own.
function Get-AdcsAssessedBaseUrl {
    param([object]$UrlList)

    foreach ($entry in @($UrlList)) {
        $text = [string]$entry
        $match = [regex]::Match($text, '^\d+:(https?://\S+)$')
        if (-not $match.Success) { continue }
        $url = $match.Groups[1].Value
        $cut = $url.LastIndexOf("/")
        if ($cut -gt "http://".Length) { return $url.Substring(0, $cut) }
    }
    return ""
}

function Get-AdcsAssessedCommonName {
    param([Parameter(Mandatory)][string]$DistinguishedName)

    $match = [regex]::Match($DistinguishedName, '^CN=([^,]+)')
    if ($match.Success) { return $match.Groups[1].Value }
    return $DistinguishedName
}

# What the offline root can be asked about itself. Deliberately a shorter list than
# the issuing tier's: a standalone root has no directory objects, no templates, no
# IIS and no enrollment - what it has is the two numbers that bound everything
# downstream (how long it lives, how long its CRL lives) and the key it signs with.
function Get-AdcsRootAssessment {
    param(
        [Parameter(Mandatory)][string]$CaName,
        [Parameter(Mandatory)][hashtable]$Registry
    )

    $registryObject = [pscustomobject]$Registry
    $certificate = Get-AdcsAuthorityCertificate

    $keyLength = 0
    $notAfter = ""
    $notBefore = ""
    $signatureAlgorithm = ""
    $daysLeft = 0
    if ($null -ne $certificate) {
        try { $keyLength = [int]$certificate.PublicKey.Key.KeySize } catch { Write-Log "The root key size could not be read" -Tag "Debug" }
        $notBefore = $certificate.NotBefore.ToString("yyyy-MM-dd")
        $notAfter = $certificate.NotAfter.ToString("yyyy-MM-dd")
        $signatureAlgorithm = [string]$certificate.SignatureAlgorithm.FriendlyName
        $daysLeft = [int][math]::Floor(($certificate.NotAfter - (Get-Date)).TotalDays)
    }

    # The number that decides whether the ceremony is already overdue - and the one
    # nobody can read from the issuing CA, which is the whole reason the root gets
    # assessed at all.
    $crlNextUpdate = Get-AdcsLocalCrlNextUpdate
    $crlNextUpdateText = ""
    $crlDaysLeft = 0
    if ($null -ne $crlNextUpdate) {
        $crlNextUpdateText = $crlNextUpdate.ToString("yyyy-MM-dd")
        $crlDaysLeft = [int][math]::Floor(($crlNextUpdate - (Get-Date)).TotalDays)
    }

    $hashAlgorithm = [string](Get-ConfigValue -InputObject $registryObject -Name "CNGHashAlgorithm" -Default "")
    if ([string]::IsNullOrWhiteSpace($hashAlgorithm) -and ($signatureAlgorithm -match '(?i)sha(\d+)')) {
        $hashAlgorithm = "SHA" + $Matches[1]
    }
    if ([string]::IsNullOrWhiteSpace($hashAlgorithm)) { $hashAlgorithm = "SHA256" }

    $policyPath = Join-Path -Path $env:SystemRoot -ChildPath "CAPolicy.inf"

    return @{
        Config = [ordered]@{
            computerName = [string]$env:COMPUTERNAME
            caCommonName = $CaName
            keyLength    = $keyLength
            hashAlgorithm = $hashAlgorithm
            crl = [ordered]@{
                period             = [string](Get-ConfigValue -InputObject $registryObject -Name "CRLPeriod" -Default "Years")
                periodUnits        = [int](Get-ConfigValue -InputObject $registryObject -Name "CRLPeriodUnits" -Default 1)
                deltaPeriod        = [string](Get-ConfigValue -InputObject $registryObject -Name "CRLDeltaPeriod" -Default "Days")
                deltaPeriodUnits   = [int](Get-ConfigValue -InputObject $registryObject -Name "CRLDeltaPeriodUnits" -Default 0)
                overlapPeriod      = [string](Get-ConfigValue -InputObject $registryObject -Name "CRLOverlapPeriod" -Default "Weeks")
                overlapPeriodUnits = [int](Get-ConfigValue -InputObject $registryObject -Name "CRLOverlapPeriodUnits" -Default 6)
            }
            # What the root stamps on the certificate it signs for the issuing CA.
            issuedValidityPeriod = [string](Get-ConfigValue -InputObject $registryObject -Name "ValidityPeriod" -Default "Years")
            issuedValidityUnits  = [int](Get-ConfigValue -InputObject $registryObject -Name "ValidityPeriodUnits" -Default 1)
            auditFilter          = [int](Get-ConfigValue -InputObject $registryObject -Name "AuditFilter" -Default 0)
        }
        Observed = [ordered]@{
            caName               = $CaName
            certificateNotBefore = $notBefore
            certificateNotAfter  = $notAfter
            certificateDaysLeft  = $daysLeft
            keyProvider          = [string](Get-ConfigValue -InputObject $registryObject -Name "Provider" -Default "")
            signatureAlgorithm   = $signatureAlgorithm
            crlNextUpdate        = $crlNextUpdateText
            crlDaysLeft          = $crlDaysLeft
            policyFilePresent    = [bool](Test-Path -LiteralPath $policyPath)
            crlPublicationUrls   = @(@(Get-ConfigValue -InputObject $registryObject -Name "CRLPublicationURLs" -Default @()) | ForEach-Object { [string]$_ })
        }
    }
}

function Get-AdcsIssuingAssessment {
    param(
        [Parameter(Mandatory)][string]$CaName,
        [Parameter(Mandatory)][hashtable]$Registry
    )

    $registryObject = [pscustomobject]$Registry
    $certificate = Get-AdcsAuthorityCertificate
    $generations = @(Get-AdcsAuthorityCertificateHash)

    $keyLength = 0
    $notAfter = ""
    $notBefore = ""
    $issuerName = ""
    $signatureAlgorithm = ""
    $daysLeft = 0
    if ($null -ne $certificate) {
        try { $keyLength = [int]$certificate.PublicKey.Key.KeySize } catch { Write-Log "The key size could not be read off the certificate" -Tag "Debug" }
        $notBefore = $certificate.NotBefore.ToString("yyyy-MM-dd")
        $notAfter = $certificate.NotAfter.ToString("yyyy-MM-dd")
        $issuerName = Get-AdcsAssessedCommonName -DistinguishedName $certificate.Issuer
        $signatureAlgorithm = [string]$certificate.SignatureAlgorithm.FriendlyName
        $daysLeft = [int][math]::Floor(($certificate.NotAfter - (Get-Date)).TotalDays)
    }

    $hashAlgorithm = [string](Get-ConfigValue -InputObject $registryObject -Name "CNGHashAlgorithm" -Default "")
    if ([string]::IsNullOrWhiteSpace($hashAlgorithm) -and ($signatureAlgorithm -match '(?i)sha(\d+)')) {
        $hashAlgorithm = "SHA" + $Matches[1]
    }
    if ([string]::IsNullOrWhiteSpace($hashAlgorithm)) { $hashAlgorithm = "SHA256" }

    $crlUrls = @(Get-ConfigValue -InputObject $registryObject -Name "CRLPublicationURLs" -Default @())
    $aiaUrls = @(Get-ConfigValue -InputObject $registryObject -Name "CACertPublicationURLs" -Default @())

    $publishedTemplates = @()
    try { $publishedTemplates = @(Get-AdcsPublishedTemplate) } catch { Write-Log "The published template list could not be read: $($_.Exception.Message)" -Tag "Debug" }

    return @{
        BaseUrl = Get-AdcsAssessedBaseUrl -UrlList $crlUrls
        Config = [ordered]@{
            computerName = [string]$env:COMPUTERNAME
            caCommonName = $CaName
            keyLength    = $keyLength
            hashAlgorithm = $hashAlgorithm
            crl = [ordered]@{
                period             = [string](Get-ConfigValue -InputObject $registryObject -Name "CRLPeriod" -Default "Weeks")
                periodUnits        = [int](Get-ConfigValue -InputObject $registryObject -Name "CRLPeriodUnits" -Default 1)
                deltaPeriod        = [string](Get-ConfigValue -InputObject $registryObject -Name "CRLDeltaPeriod" -Default "Days")
                deltaPeriodUnits   = [int](Get-ConfigValue -InputObject $registryObject -Name "CRLDeltaPeriodUnits" -Default 0)
                overlapPeriod      = [string](Get-ConfigValue -InputObject $registryObject -Name "CRLOverlapPeriod" -Default "Hours")
                overlapPeriodUnits = [int](Get-ConfigValue -InputObject $registryObject -Name "CRLOverlapPeriodUnits" -Default 12)
            }
            issuedValidityPeriod = [string](Get-ConfigValue -InputObject $registryObject -Name "ValidityPeriod" -Default "Years")
            issuedValidityUnits  = [int](Get-ConfigValue -InputObject $registryObject -Name "ValidityPeriodUnits" -Default 1)
            auditFilter          = [int](Get-ConfigValue -InputObject $registryObject -Name "AuditFilter" -Default 0)
            # What exists is reported; whether this design should manage it stays the
            # operator's tick. Withdrawing templates on a CA somebody else runs is the
            # wrong default, so it arrives off.
            templates = [ordered]@{ enabled = $true; unpublishOthers = $false }
        }
        Observed = [ordered]@{
            caName               = $CaName
            issuerName           = $issuerName
            certificateNotBefore = $notBefore
            certificateNotAfter  = $notAfter
            certificateDaysLeft  = $daysLeft
            thumbprint           = $(if ($null -ne $certificate) { [string]$certificate.Thumbprint } else { "" })
            generations          = $generations.Count
            keyProvider          = [string](Get-ConfigValue -InputObject $registryObject -Name "Provider" -Default "")
            signatureAlgorithm   = $signatureAlgorithm
            sidExtensionIntact   = [bool](Test-AdcsSidExtension)
            webEnrollmentAbsent  = [bool](Test-AdcsWebEnrollmentAbsent)
            publishedTemplates   = @($publishedTemplates)
            crlPublicationUrls   = @($crlUrls | ForEach-Object { [string]$_ })
            caCertPublicationUrls = @($aiaUrls | ForEach-Object { [string]$_ })
        }
    }
}

# '-Task AdcsAssess': read the CA this server runs and merge what was found into
# assessment.json in the transfer folder - shaped exactly like config.json, so the
# studio's normal import reads it and the design starts from what exists rather than
# from what somebody remembers. Everything the design cannot change - the certificate
# in force, the key provider, what is published - rides in an 'observed' block the
# studio shows as facts and never re-exports.
#
# **Run it on both CAs.** The tiers know different things and neither can answer for
# the other: only the root can say how long it lives and when its CRL expires (the
# ceiling on every renewal, and whether the ceremony is already overdue), and only the
# issuing CA can say what it publishes, what it issues and who may enroll. Each run
# merges *its own tier* into whatever the file already holds and leaves the rest
# alone - so the folder that already crosses the air gap carries the assessment back
# with the CRL, and the studio imports one file.
#
# Zero writes to the CA, the directory or IIS. The transfer folder is this script's
# own; creating it is the one thing the task touches.
# Which tier this CA is, asked of the CA rather than of a design. CAType is the
# authority's own answer - 0 and 3 are the two root flavours, 1 and 4 the two
# subordinate ones - and a self-signed certificate is the fallback for a hive that does
# not carry it. This is what lets the task run with no config.json at all: the machine
# already knows everything the question needed the design for.
function Get-AdcsAssessedTier {
    param([Parameter(Mandatory)][hashtable]$Registry)

    if ($Registry.ContainsKey("CAType")) {
        $caType = [int]$Registry["CAType"]
        if (@(0, 3) -contains $caType) { return "root" }
        if (@(1, 4) -contains $caType) { return "issuing" }
    }

    $certificate = Get-AdcsAuthorityCertificate
    if ($null -ne $certificate -and ([string]$certificate.Subject -eq [string]$certificate.Issuer)) { return "root" }
    return "issuing"
}

function Invoke-AdcsAssessment {
    # Optional, and the only task where it is. An assessment applies nothing - it reads
    # a CA and writes down what it found, which is the input to a design rather than
    # its output. Asking for the config.json it exists to help write is backwards.
    param([object]$Config)

    $certificateServices = Get-ConfigValue -InputObject $Config -Name "certificateServices"

    $caName = Get-AdcsActiveCaName
    if ([string]::IsNullOrWhiteSpace($caName)) {
        Write-Log "No certification authority is configured on this server - nothing to assess" -Tag "Error"
        return 1
    }

    $registry = Get-AdcsAssessmentRegistry -CaName $caName

    # A design that names this machine is believed; without one - or when it names this
    # machine as something else - the CA speaks for itself.
    $tierName = ""
    if ($null -ne $certificateServices) { $tierName = Resolve-AdcsTier -CertificateServices $certificateServices }
    if (@("root", "issuing") -notcontains $tierName) {
        $tierName = Get-AdcsAssessedTier -Registry $registry
        Write-Log "No design names this machine, so the CA answered for itself: this is the $tierName tier" -Tag "Info"
    }
    Write-Log "Assessing the $tierName CA '$caName'" -Tag "Info"

    $legacyAuditOverride = 0
    try {
        $lsa = Get-ItemProperty -Path $script:adcsLsaKeyPath -ErrorAction Stop
        $legacyAuditOverride = [int](Get-ConfigValue -InputObject $lsa -Name "SCENoApplyLegacyAuditPolicy" -Default 0)
    }
    catch {
        Write-Log "The LSA audit override could not be read" -Tag "Debug"
    }

    $editFlags = 0
    if ($registry.ContainsKey("EditFlags")) { $editFlags = [int64]$registry["EditFlags"] }
    $interfaceFlags = 0
    if ($registry.ContainsKey("InterfaceFlags")) { $interfaceFlags = [int64]$registry["InterfaceFlags"] }
    $roleSeparation = 0
    if ($registry.ContainsKey("RoleSeparationEnabled")) { $roleSeparation = [int]$registry["RoleSeparationEnabled"] }

    $tierResult = $null
    if ($tierName -eq "root") {
        $tierResult = Get-AdcsRootAssessment -CaName $caName -Registry $registry
    }
    else {
        $tierResult = Get-AdcsIssuingAssessment -CaName $caName -Registry $registry
    }

    # One file per tier, named after the tier, and no merging between them. The two CAs
    # do not share a folder - that is the whole point of an offline root - so a single
    # assessment.json meant carrying one machine's file to the other before either was
    # readable. Each CA writes its own; the studio takes both at once and merges there,
    # where they finally are in the same place.
    $transferPath = Confirm-AdcsTransferPath -Path (Get-AdcsTransferPath -CertificateServices $certificateServices)
    $outputPath = Join-Path -Path $transferPath -ChildPath "$tierName-assessment.json"

    $services = [ordered]@{}
    $observed = [ordered]@{}

    $services["mode"] = "adopt"

    # The shared half is this tier's view of it, and only this tier's. The issuing CA is
    # the better witness for the publication URL and the forest name - the root has
    # never seen a domain - so a root file simply carries neither, and the studio's
    # merge has nothing to choose between.
    $shared = [ordered]@{}
    $shared["transferDirectory"] = "transfer"
    if ($tierName -eq "issuing") {
        $forestDomain = [string]$env:USERDNSDOMAIN
        try {
            $computerSystem = Get-CimInstance -ClassName "Win32_ComputerSystem" -ErrorAction Stop
            if (-not [string]::IsNullOrWhiteSpace([string]$computerSystem.Domain)) { $forestDomain = [string]$computerSystem.Domain }
        }
        catch {
            Write-Log "The machine domain could not be read from CIM; using USERDNSDOMAIN" -Tag "Debug"
        }
        $shared["forestDomainName"] = $forestDomain.ToLowerInvariant()
        $shared["dsConfigDN"] = [string](Get-ConfigValue -InputObject ([pscustomobject]$registry) -Name "DSConfigDN" -Default "")
        $shared["pkiBaseUrl"] = [string]$tierResult.BaseUrl
    }
    # Hardening is read in the design's own semantics - true means the mitigation is
    # in place - so the studio's existing grading names every gap without a second
    # vocabulary. Both tiers carry these registry values and both write them; the
    # issuing CA is the one whose state matters for the ESC findings, and the studio is
    # where that precedence is applied now that the tiers write separate files.
    $shared["hardening"] = [ordered]@{
        disableSanAttribute      = (($editFlags -band 0x40000) -eq 0)
        enforceEncryptedRequests = (($interfaceFlags -band 0x200) -ne 0)
        enableRoleSeparation     = ($roleSeparation -eq 1)
        auditSubcategory         = ($legacyAuditOverride -eq 1)
    }
    $services["shared"] = $shared

    $services[$tierName] = $tierResult.Config
    $observed[$tierName] = $tierResult.Observed
    $observed["assessedOn"] = (Get-Date).ToString("yyyy-MM-dd HH:mm")
    $services["observed"] = $observed

    $output = [ordered]@{
        assessedComputer    = [string]$env:COMPUTERNAME
        roles               = @("AD-Certificate")
        certificateServices = $services
    }

    ($output | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $outputPath -Encoding UTF8
    Write-Log "Assessment written to '$outputPath'" -Tag "Ok"

    $other = if ($tierName -eq "root") { "issuing" } else { "root" }
    Write-Log "Run the same task on the $other CA - it writes '$other-assessment.json' beside this one" -Tag "Info"
    Write-Log "Then take both files to the studio's Adopt tab and import them together" -Tag "Info"
    return 0
}
