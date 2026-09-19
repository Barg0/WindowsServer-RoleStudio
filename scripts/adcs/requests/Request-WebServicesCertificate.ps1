<#
.SYNOPSIS
    Requests a certificate from the Web Services template and writes out the whole
    bundle a Linux appliance or a web server needs, in a folder of its own.

.DESCRIPTION
    Standalone by design. It dot-sources nothing, needs no modules, and carries its own
    console UI, its own logging and its own DER encoder, so it can be copied to a server
    on its own. Windows only: the request goes through the CertEnroll COM API, which is
    what the certificates console uses.

    Four questions, each on its own screen with Continue and Back, then a review. Every
    other decision is made for you, because there is one right answer to each:

        the key goes in the machine store  which is where a service reads it from, and
                                           what needs the elevated session

    Who the certification authority sees is the account the script RUNS as, not -Context.
    Started from a normal elevated prompt that is you, and your account needs Enroll on
    the template. Started as SYSTEM - psexec -s -i powershell.exe, or a scheduled task
    running as SYSTEM - it is the computer account instead, and the computer's group
    membership is what counts. Both are legitimate; pick one and grant that.
        every file is written            a bundle with a piece missing is a support call
        the PKCS#12 password is generated and written beside it, in password.txt
        the store copy is removed        this exists to produce files, not to bind IIS

    A certificates.json beside the script turns it into a batch: every entry is requested
    in turn, each into its own folder, and the only screen is one review of the lot. One
    refusal does not stop the rest.

    Everything lands in a folder named after the certificate, beside the script unless
    -OutputFolder says otherwise. A certificate for web-01.ad.lab.invalid produces:

        web-01.ad.lab.invalid\
            web-01.ad.lab.invalid.cer            the certificate, PEM
            web-01.ad.lab.invalid.key            the private key, PEM PKCS#1
            web-01.ad.lab.invalid.pkcs8.key      the same key as PEM PKCS#8, for Java
            web-01.ad.lab.invalid.der.cer        the same certificate as binary DER
            web-01.ad.lab.invalid.chain.pem      the issuers above it, without the leaf
            web-01.ad.lab.invalid.fullchain.pem  leaf first, then its issuers, for nginx
            web-01.ad.lab.invalid.pfx            certificate, key and chain in one file
            web-01.ad.lab.invalid.txt            what was issued, and which file goes where
            password.txt                       the PKCS#12 password

    Every file in that folder is written with inheritance removed and an access list of
    the account that ran the script, SYSTEM and the local administrators. Two of them are
    unencrypted private keys and one is a password in clear, which is the point of asking
    for a bundle - move the folder to the appliance that needs it and delete it here.

.PARAMETER BulkFile
    A JSON file of certificates to request in one go. Left empty the script looks for a
    certificates.json beside itself and beside wherever it was started from; finding one
    skips the wizard and goes straight to a review of the whole batch.

.PARAMETER NoBulk
    Ignore any certificates.json lying about and go to the wizard.

.PARAMETER NoGui
    Skip the wizard and use the parameters below.

.PARAMETER OutputFolder
    The PARENT folder. The certificate's own folder is created inside it. Defaults to the
    folder the script itself is in.

.EXAMPLE
    .\Request-WebServicesCertificate.ps1

.EXAMPLE
    .\Request-WebServicesCertificate.ps1 -NoGui -CommonName portal.ad.lab.invalid -OutputFolder D:\certs
#>
[CmdletBinding()]
param(
    [switch]$NoGui,
    [string]$CommonName,
    [string[]]$SubjectAlternativeName = @(),
    [string]$TemplateName = 'WebServices',
    [ValidateSet(2048, 3072, 4096)]
    [int]$KeyLength = 2048,
    # Where the key and the issued certificate LIVE - LocalMachine\My or CurrentUser\My -
    # and nothing else. It is NOT who asks. An interactive CertEnroll request authenticates
    # to the CA as the signed-in user in both cases; only the autoenrollment service,
    # running as SYSTEM, ever submits as the computer account. The wizard does not ask
    # because the machine store is the right answer for a certificate a service will use.
    [ValidateSet('Machine', 'User')]
    [string]$Context = 'Machine',
    [string]$OutputFolder,
    # A certificates.json to work from. Left empty the script looks for one beside
    # itself and beside wherever it was started from, and uses it when it finds one.
    [string]$BulkFile,
    # Ignore any certificates.json that happens to be lying there and go to the wizard.
    [switch]$NoBulk,
    [string]$LogRoot,
    [switch]$LogDebug
)

$ErrorActionPreference = 'Stop'

# =================================================================================
# Kaido Dark, the studio's default theme, as the console's palette.
#
# Every hex is lifted verbatim from FAMILIES[kaido].dark in the studio HTML - with one
# stated exception, `yellow`, documented where it is defined below - so the tool and the
# studio are the same colours rather than two guesses at them. Truecolor when the
# console does virtual terminal processing, the nearest named colour when it does not.
#
# This is a COPY of the table in pwsh\Logging.ps1, not a reference to it, for the same
# reason the rest of this file copies Write-Log: a retrofit has to keep working when
# somebody puts it on a server on its own. The cost is that the two can drift, and the
# rule is that a change to one is made by hand in the other on the same day.
# =================================================================================
$script:studioPalette = @{
    bg       = "#16171e"; elevated  = "#1d1f28"; subtle = "#1a1c24"; hover = "#262a38"
    fg       = "#d7dbec"; muted     = "#8b93ad"
    border   = "#2b2f3d"; borderStrong = "#3d4356"; divider = "#23262f"
    accent   = "#7aa2f7"; accentHover = "#93b3fa"; accentSoft = "#22304f"; accentFg = "#11141c"
    success  = "#9ece6a"; danger    = "#f7768e"; warn = "#e0af68"
    bandHost = "#7dcfff"; bandIdent = "#bb9af7"; bandWork = "#9ece6a"; bandDeploy = "#ff9e64"
    # THE ONE VALUE IN THIS TABLE THAT IS NOT THE STUDIO'S. Kaido has exactly two warm
    # colours - warn #e0af68, a gold, and deploy #ff9e64, an orange - and a log needs
    # three warm steps, because `info` is the commonest tag there is and it has to sit
    # below `warn` without either reading as the other. Console-only, no studio
    # counterpart, and none needed: the studio has no log. Same value, same reason, in
    # pwsh\Logging.ps1.
    yellow   = "#e6de78"
}

# One per key, for a console that cannot do truecolor. Chosen for the JOB the hex does,
# not the nearest RGB: muted and borderStrong both land on DarkGray because both are
# "quieter than the text", and that is what has to survive.
$script:studioFallback = @{
    bg       = "Black";    elevated  = "Black";  subtle = "Black";     hover = "Black"
    fg       = "Gray";     muted     = "DarkGray"
    border   = "DarkGray"; borderStrong = "DarkGray"; divider = "DarkGray"
    accent   = "Cyan";     accentHover = "White"; accentSoft = "DarkBlue"; accentFg = "Black"
    success  = "Green";    danger    = "Red";     warn = "DarkYellow"
    bandHost = "Cyan";     bandIdent = "Magenta"; bandWork = "Green";   bandDeploy = "Yellow"
    # Yellow against warn's DarkYellow - the pair the sixteen-colour version of this log
    # already used, which is what the truecolor palette had to grow a third warm step to
    # be able to say.
    yellow   = "Yellow"
}

# Write-Host with a palette key instead of a colour name. Everything on screen goes
# through here, which is what makes the theme one table rather than forty scattered
# -ForegroundColor arguments.
function Write-Studio {
    param(
        [AllowEmptyString()][string]$Text = "",
        [string]$Key = "fg",
        [switch]$NoNewline
    )

    $hex = [string]$script:studioPalette[$Key]
    if ([string]::IsNullOrWhiteSpace($hex)) { $hex = [string]$script:studioPalette["fg"] }

    # Cheap after the first call - Enable-MenuVtProcessing caches - and it has to be
    # here rather than only in Show-MenuHeader, because log lines print before any
    # header does.
    Enable-MenuVtProcessing
    if (Test-MenuAnsiSupported) {
        $rgb = ConvertFrom-HexColor -Hex $hex
        $escape = [char]27
        # Foreground only, never a background fill: that paints the terminal's default
        # foreground into every cell behind the text as well. Same rule as the mark.
        Write-Host ("{0}[38;2;{1};{2};{3}m{4}{0}[0m" -f $escape, $rgb[0], $rgb[1], $rgb[2], $Text) -NoNewline:$NoNewline
        return
    }

    $named = [string]$script:studioFallback[$Key]
    if ([string]::IsNullOrWhiteSpace($named)) { $named = "Gray" }
    Write-Host $Text -NoNewline:$NoNewline -ForegroundColor $named
}

# =================================================================================
# Logging. A copy of pwsh\Logging.ps1's behaviour rather than a reference to it: a
# script that only works inside a full checkout is not standalone. Same line format,
# same tag spellings, same five-wide column.
# =================================================================================
$scriptStartTime   = Get-Date
$script:logEnabled = $true
$script:logDebug   = [bool]$LogDebug
# Empty on purpose. The bracket after the tag names the ROLE a line was written under,
# and this script is not running one - a [AD-Certificate] on every line of a hand-run
# tool claims a run that never happened. The log still lands in logs\adcs\, because
# that is where somebody looks for what happened to this CA.
$script:currentRole = ''
$scriptName = "Request-WebServicesCertificate"

if ([string]::IsNullOrWhiteSpace($LogRoot)) {
    # Beside the role's own runs when this is still in the toolbox, beside the
    # script when it has been copied out alone.
    # Walk up looking for the toolbox root rather than checking one level. The scripts
    # folder is nested by area now - scripts\adcs\requests - so the sibling pwsh folder
    # that marks the root is three levels above this file, not one. Four levels is
    # plenty and stops dead at the drive root; finding nothing means this script has
    # been copied out on its own, and then its own folder is the right answer.
    $LogRoot = $PSScriptRoot
    $probe = $PSScriptRoot
    for ($up = 0; $up -lt 4; $up++) {
        if ([string]::IsNullOrWhiteSpace($probe)) { break }
        if (Test-Path -LiteralPath (Join-Path -Path $probe -ChildPath 'pwsh')) { $LogRoot = $probe; break }
        $probe = Split-Path -Path $probe -Parent
    }
}

$script:logFileName = (Get-Date -Format 'yyyyMMdd-HHmm') + '.log'
$script:logTargets  = @()
foreach ($folder in @('run', 'adcs')) {
    $directory = Join-Path -Path (Join-Path -Path $LogRoot -ChildPath 'logs') -ChildPath $folder
    try {
        if (-not (Test-Path -LiteralPath $directory)) {
            $null = New-Item -ItemType Directory -Path $directory -Force
        }
        $script:logTargets += (Join-Path -Path $directory -ChildPath $script:logFileName)
    }
    catch {
        # Logging must never block execution.
    }
}

function Write-Log {
    [CmdletBinding()]
    param(
        [string]$Message,
        [string]$Tag = 'Info'
    )

    if (-not $script:logEnabled) { return }
    if (($Tag -eq 'Debug') -and (-not $script:logDebug)) { return }

    # InvariantCulture, not -Format. In a .NET custom format string ':' is the TIME
    # SEPARATOR placeholder, not a literal, so on a Finnish-locale server 'HH:mm:ss'
    # renders as 10.44.39 and the log stops being greppable by the shape everything
    # else in this estate writes.
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)

    $tagMap = @{
        'start' = 'start'; 'get' = 'get'; 'run' = 'run'; 'info' = 'info'
        'warn'  = 'warn';  'warning' = 'warn'; 'ok' = 'o.k.'; 'success' = 'o.k.'
        'error' = 'error'; 'debug' = 'debug'; 'end' = 'end'
    }

    $key = $Tag.Trim().ToLowerInvariant()
    # A tag outside the map renders as an error rather than being dropped, so a typo
    # is loud instead of invisible.
    $shown = $tagMap[$key]
    if ([string]::IsNullOrWhiteSpace($shown)) { $shown = 'error' }
    $rawTag = $shown.PadRight(5)

    # Palette keys, not ConsoleColor names, and the pairing that has to survive is info
    # reading QUIETER than warn without either of them reading as the other. Kaido's own
    # two warm colours are one step apart and came out orange-on-orange; info as plain
    # text was tried in an earlier build and the log read as undifferentiated. So the
    # palette carries a third warm step and info takes it.
    $color = switch ($shown) {
        'start' { 'accent' }
        'get'   { 'bandHost' }
        'run'   { 'bandIdent' }
        'info'  { 'yellow' }
        'warn'  { 'warn' }
        'o.k.'  { 'success' }
        'error' { 'danger' }
        'debug' { 'muted' }
        'end'   { 'accent' }
        default { 'fg' }
    }

    $scope = ''
    if (-not [string]::IsNullOrWhiteSpace($script:currentRole)) {
        $scope = '[' + $script:currentRole + '] '
    }
    $logMessage = "$timestamp [ $rawTag ] $scope$Message"

    foreach ($target in $script:logTargets) {
        # -ErrorAction Stop is what makes the catch a catch: without it Add-Content
        # reports a locked file as a NON-TERMINATING error, which walks past try/catch
        # and prints a red block mid-run. A lock is transient, so it is retried.
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try {
                Add-Content -Path $target -Value $logMessage -Encoding UTF8 -ErrorAction Stop
                break
            }
            catch {
                if ($attempt -eq 3) { break }
                Start-Sleep -Milliseconds 120
            }
        }
    }

    # The brackets are the BRIGHTEST chrome on the line, not the dimmest. They were
    # drawn in 'border' for one build - #2b2f3d on a #16171e background, about 1.3:1 -
    # and they simply were not there. The toolbox draws them in White for the same
    # reason: they are the frame the eye uses to find the tag column.
    Write-Studio -Text "$timestamp " -Key 'muted' -NoNewline
    Write-Studio -Text '[ ' -Key 'fg' -NoNewline
    Write-Studio -Text "$rawTag" -Key $color -NoNewline
    Write-Studio -Text ' ] ' -Key 'fg' -NoNewline
    Write-Studio -Text "$scope$Message" -Key 'fg'
}

function Complete-Script {
    param([int]$ExitCode)

    $duration = (Get-Date) - $scriptStartTime
    Write-Log "Runtime $($duration.ToString('hh\:mm\:ss\.ff'))" -Tag 'Info'
    Write-Log "Exit $ExitCode" -Tag 'Info'
    Write-Log '==================== End ====================' -Tag 'End'
    exit $ExitCode
}

# =================================================================================
# DER and PEM. Written out by hand because .NET Framework 4.x - which is what Windows
# PowerShell 5.1 runs on - has no ExportRSAPrivateKey and no PEM export; those arrived
# in .NET Core 3.0. Shelling out to openssl was the alternative and it is not on a
# Windows Server by default, so it would have made a self-contained script depend on
# something nobody installed.
# =================================================================================
function New-DerLength {
    param([Parameter(Mandatory)][int]$Length)

    if ($Length -lt 0x80) { return [byte[]]@([byte]$Length) }
    $bytes = [System.Collections.Generic.List[byte]]::new()
    $value = $Length
    while ($value -gt 0) {
        $bytes.Insert(0, [byte]($value -band 0xFF))
        $value = $value -shr 8
    }
    # Long form: the high bit set, and the low seven bits counting the length bytes.
    return (,[byte](0x80 -bor $bytes.Count)) + $bytes.ToArray()
}

function New-DerInteger {
    param([byte[]]$Value)

    if (($null -eq $Value) -or ($Value.Length -eq 0)) { $Value = [byte[]]@(0) }
    # DER integers are minimal: leading zero bytes go, except the one that keeps the
    # value positive. RSAParameters hands these over big-endian and unsigned, so a
    # component whose top bit is set needs that byte put back or it reads as negative.
    $index = 0
    while (($index -lt $Value.Length - 1) -and ($Value[$index] -eq 0)) { $index++ }
    $trimmed = $Value[$index..($Value.Length - 1)]
    if ($trimmed[0] -ge 0x80) { $trimmed = (,[byte]0) + $trimmed }
    return (,[byte]0x02) + (New-DerLength -Length $trimmed.Length) + $trimmed
}

function New-DerSequence {
    param([byte[]]$Content)
    return (,[byte]0x30) + (New-DerLength -Length $Content.Length) + $Content
}

# One tag-length-value at an offset. Enough of a reader to walk a PKCS#8 wrapper,
# which is all this script ever has to parse.
function Get-DerElement {
    param(
        [Parameter(Mandatory)][byte[]]$Data,
        [Parameter(Mandatory)][int]$Offset
    )

    if ($Offset -ge $Data.Length) { throw "DER ran out at offset $Offset" }
    $tag = $Data[$Offset]
    $cursor = $Offset + 1
    $length = [int]$Data[$cursor]
    $cursor++
    if ($length -ge 0x80) {
        $count = $length -band 0x7F
        if ($count -eq 0) { throw "DER indefinite lengths are not valid here" }
        $length = 0
        for ($i = 0; $i -lt $count; $i++) {
            $length = ($length -shl 8) -bor [int]$Data[$cursor]
            $cursor++
        }
    }
    return [pscustomobject]@{
        Tag           = $tag
        ContentOffset = $cursor
        ContentLength = $length
        NextOffset    = $cursor + $length
    }
}

# PKCS#1 RSAPrivateKey. The nine integers in the order RFC 8017 states them; get one
# out of order and openssl reports a key that loads and does not work.
function ConvertTo-Pkcs1PrivateKey {
    param([Parameter(Mandatory)][System.Security.Cryptography.RSAParameters]$Parameters)

    $body = [byte[]]@()
    $body += New-DerInteger -Value ([byte[]]@(0))
    foreach ($part in @(
        $Parameters.Modulus, $Parameters.Exponent, $Parameters.D,
        $Parameters.P, $Parameters.Q, $Parameters.DP, $Parameters.DQ, $Parameters.InverseQ)) {
        $body += New-DerInteger -Value $part
    }
    return (New-DerSequence -Content $body)
}

# PKCS#8 PrivateKeyInfo around a PKCS#1 key. The AlgorithmIdentifier is a constant -
# rsaEncryption with the explicit NULL parameters RFC 3447 requires - so it is written
# as the bytes it always is rather than assembled from an OID encoder this script would
# use exactly once.
function ConvertTo-Pkcs8PrivateKey {
    param([Parameter(Mandatory)][byte[]]$Pkcs1)

    $algorithm = [byte[]]@(0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00)
    $octet = (,[byte]0x04) + (New-DerLength -Length $Pkcs1.Length) + $Pkcs1
    $body = (New-DerInteger -Value ([byte[]]@(0))) + $algorithm + $octet
    return (New-DerSequence -Content $body)
}

# The other direction: the RSAPrivateKey out of a PrivateKeyInfo. This is the path a
# CNG key comes back on, because Pkcs8PrivateBlob is what NCrypt will hand over.
function ConvertFrom-Pkcs8PrivateKey {
    param([Parameter(Mandatory)][byte[]]$Pkcs8)

    $outer = Get-DerElement -Data $Pkcs8 -Offset 0
    if ($outer.Tag -ne 0x30) { throw "not a PKCS#8 PrivateKeyInfo" }
    $version = Get-DerElement -Data $Pkcs8 -Offset $outer.ContentOffset
    $algorithm = Get-DerElement -Data $Pkcs8 -Offset $version.NextOffset
    $key = Get-DerElement -Data $Pkcs8 -Offset $algorithm.NextOffset
    if ($key.Tag -ne 0x04) { throw "the PKCS#8 private key is not an OCTET STRING" }
    return $Pkcs8[$key.ContentOffset..($key.ContentOffset + $key.ContentLength - 1)]
}

function ConvertTo-Pem {
    param(
        [Parameter(Mandatory)][byte[]]$Der,
        [Parameter(Mandatory)][string]$Label
    )

    $base64 = [Convert]::ToBase64String($Der)
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("-----BEGIN $Label-----")
    for ($index = 0; $index -lt $base64.Length; $index += 64) {
        $take = [Math]::Min(64, $base64.Length - $index)
        $lines.Add($base64.Substring($index, $take))
    }
    $lines.Add("-----END $Label-----")
    # LF, not CRLF. Every consumer of these files reads both, and half of them are
    # going to be an nginx or a HAProxy that the files were copied to.
    return ($lines -join "`n") + "`n"
}

# The account that ran this, SYSTEM and the local administrators, and nothing else -
# with inheritance off, because a key file that inherits the Users group from the
# folder above is a private key anybody on the box can read.
function Protect-KeyFile {
    param([Parameter(Mandatory)][string]$Path)

    try {
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $acl.SetAccessRuleProtection($true, $false)

        $identities = @(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
            (New-Object System.Security.Principal.SecurityIdentifier(
                [System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)),
            (New-Object System.Security.Principal.SecurityIdentifier(
                [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null))
        )
        foreach ($identity in $identities) {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $identity,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.AccessControlType]::Allow)))
        }
        $acl.SetOwner([System.Security.Principal.WindowsIdentity]::GetCurrent().User)
        Set-Acl -LiteralPath $Path -AclObject $acl
        return $true
    }
    catch {
        # Reported loudly rather than swallowed: the file is on disk either way, and an
        # unencrypted private key readable by everyone is worth interrupting for.
        Write-Log "    $(Split-Path -Path $Path -Leaf) was written but its permissions could not be set: $($_.Exception.Message)" -Tag 'Error'
        return $false
    }
}

# The private key out of an issued certificate, as both DER forms.
#
# Two paths, and the order matters. RSACng.ExportParameters($true) asks CNG for a
# PLAINTEXT export, which needs NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG on the key. A key
# created with ALLOW_EXPORT alone answers "The requested operation is not supported",
# which is a bench failure this script had: the request set ExportPolicy = 1, the
# certificate issued perfectly, and the key would not come out. The request sets 3 now.
# The CNG blob path is still tried first, because it is the one that also works on a
# key somebody else created and because it hands back PKCS#8 without going through
# RSAParameters at all.
function Get-CertificateKeyMaterial {
    param([Parameter(Mandatory)][object]$Certificate)

    $rsa = $null
    try { $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate) }
    catch { $rsa = $null }
    if ($null -eq $rsa) {
        Write-Log "The certificate's private key is missing or is not an RSA key" -Tag 'Error'
        return $null
    }

    $pkcs1 = $null
    if ($rsa -is [System.Security.Cryptography.RSACng]) {
        try {
            $blob = $rsa.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
            $pkcs1 = ConvertFrom-Pkcs8PrivateKey -Pkcs8 $blob
            Write-Log "    key read as a CNG PKCS#8 blob" -Tag 'Debug'
        }
        catch {
            Write-Log "    the CNG blob export refused: $($_.Exception.Message)" -Tag 'Debug'
            $pkcs1 = $null
        }
    }

    if ($null -eq $pkcs1) {
        try {
            $pkcs1 = ConvertTo-Pkcs1PrivateKey -Parameters $rsa.ExportParameters($true)
            Write-Log "    key read through RSAParameters" -Tag 'Debug'
        }
        catch {
            Write-Log "The private key could not be exported: $($_.Exception.Message)" -Tag 'Error'
            Write-Log "    the key has to allow PLAINTEXT export, not just export - a key made by something else, or under a policy that forbids it, will refuse" -Tag 'Info'
            return $null
        }
    }

    return [pscustomobject]@{
        Pkcs1 = $pkcs1
        Pkcs8 = (ConvertTo-Pkcs8PrivateKey -Pkcs1 $pkcs1)
    }
}

# What a commercial certificate authority posts you, and what each piece is for. Forced
# entries are not offered as a choice: a run that writes neither the certificate nor the
# key has done nothing.
$script:outputFileCatalog = @(
    [pscustomobject]@{ Id = 'leafPem';      Extension = '.cer';           Forced = $true
                       Label = 'Certificate, PEM'
                       Detail = 'the leaf on its own - IIS, nginx, almost everything' }
    [pscustomobject]@{ Id = 'keyPem';       Extension = '.key';           Forced = $true
                       Label = 'Private key, PEM PKCS#1'
                       Detail = 'BEGIN RSA PRIVATE KEY - nginx, Apache, HAProxy' }
    [pscustomobject]@{ Id = 'keyPkcs8';     Extension = '.pkcs8.key';     Forced = $true
                       Label = 'Private key, PEM PKCS#8'
                       Detail = 'BEGIN PRIVATE KEY - Java, Tomcat, a lot of appliances' }
    [pscustomobject]@{ Id = 'leafDer';      Extension = '.der.cer';       Forced = $true
                       Label = 'Certificate, DER'
                       Detail = 'the same certificate as binary - Windows and keytool' }
    [pscustomobject]@{ Id = 'chainPem';     Extension = '.chain.pem';     Forced = $true
                       Label = 'Issuer chain, PEM'
                       Detail = 'the issuers above the leaf, without it - Apache SSLCertificateChainFile' }
    [pscustomobject]@{ Id = 'fullchainPem'; Extension = '.fullchain.pem'; Forced = $true
                       Label = 'Full chain, PEM'
                       Detail = 'leaf first, then its issuers - nginx ssl_certificate' }
    [pscustomobject]@{ Id = 'pfx';          Extension = '.pfx';           Forced = $true
                       Label = 'PKCS#12 bundle'
                       Detail = 'certificate, key and chain in one password-protected file - IIS, Exchange' }
    [pscustomobject]@{ Id = 'readme';       Extension = '.txt';           Forced = $true
                       Label = 'Summary'
                       Detail = 'what was issued, and which file goes where' }
    [pscustomobject]@{ Id = 'password';     Extension = '';               Forced = $true
                       Label = 'PKCS#12 password'
                       Detail = 'the password that opens the .pfx above' }
)

# Every entry is written, every time. There used to be a screen for choosing, and it was
# nine lines of tick boxes in front of an answer that is always "all of them" - a bundle
# with a piece missing is a support call three weeks later from whoever needed the piece.
$script:passwordFileName = 'password.txt'

# DNS or IP, decided once and then carried rather than guessed at again.
#
# The guess exists only for -NoGui and for a name typed without a type; the wizard asks
# outright. It looks for a dot or a colon BEFORE trying IPAddress.TryParse, because on
# its own TryParse accepts "12345" and hands back 0.0.48.57 - so a host whose name is
# all digits would go into the certificate as an IP address nothing ever matches.
function Get-SanTypeGuess {
    param([Parameter(Mandatory)][string]$Value)

    if (($Value -notmatch '\.') -and ($Value -notmatch ':')) { return 'DNS' }
    $address = $null
    if ([System.Net.IPAddress]::TryParse($Value, [ref]$address)) { return 'IP' }
    return 'DNS'
}

function ConvertTo-SanEntry {
    param([object]$InputObject)

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -isnot [string]) {
        $value = ([string]$InputObject.Value).Trim()
        if ([string]::IsNullOrWhiteSpace($value)) { return $null }
        $type = [string]$InputObject.Type
        if ($type -ne 'IP') { $type = 'DNS' }
        return [pscustomobject]@{ Type = $type; Value = $value }
    }

    $text = ([string]$InputObject).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return [pscustomobject]@{ Type = (Get-SanTypeGuess -Value $text); Value = $text }
}

function Get-OutputFileEntry {
    param([Parameter(Mandatory)][string]$Id)
    return ($script:outputFileCatalog | Where-Object { $_.Id -eq $Id } | Select-Object -First 1)
}

# A password nobody has to invent. Ambiguous characters are left out on purpose -
# this gets read off a screen and typed into an IIS dialog.
function New-PfxPassword {
    $alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789".ToCharArray()

    # Rejection sampling, not modulo. The alphabet is 57 characters and a byte has 256
    # values, so 256 mod 57 leaves 28 of them over - and a plain $byte % 57 hands those
    # 28 extra weight, making the first half of the alphabet a quarter more likely than
    # the second. Bytes at or above the largest exact multiple are drawn again instead.
    $limit = [int]([Math]::Floor(256 / $alphabet.Length) * $alphabet.Length)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $text = ""
        $one = New-Object byte[] 1
        while ($text.Length -lt 24) {
            $rng.GetBytes($one)
            if ($one[0] -ge $limit) { continue }
            $text += $alphabet[$one[0] % $alphabet.Length]
        }
    }
    finally { $rng.Dispose() }
    return $text
}

function ConvertFrom-SecureStringPlain {
    param([securestring]$Secure)

    if ($null -eq $Secure) { return "" }
    $pointer = [System.IntPtr]::Zero
    try {
        $pointer = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Secure)
        return [System.Runtime.InteropServices.Marshal]::PtrToStringUni($pointer)
    }
    finally {
        if ($pointer -ne [System.IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($pointer)
        }
    }
}

# =================================================================================
# The request itself. CertEnroll, which is the API the certificates console drives -
# so a template that enrolls by hand enrolls here, and one that does not fails with
# the same message.
# =================================================================================
function Invoke-WebServicesCertificateRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CommonName,
        # Strings or { Type = 'DNS' | 'IP'; Value = '...' } objects, mixed freely. A
        # bare string is typed by Get-SanTypeGuess; an object says what it is.
        [object[]]$AlternativeName = @(),
        [Parameter(Mandatory)][string]$Template,
        [Parameter(Mandatory)][int]$Length,
        [Parameter(Mandatory)][string]$MachineOrUser,
        # The PARENT. The certificate's own folder is made inside it and named after
        # the certificate, so a run never drops nine files loose in somebody's Desktop.
        [Parameter(Mandatory)][string]$ParentFolder
    )

    # X509CertificateEnrollmentContext: 1 = user, 2 = machine.
    $machine = ($MachineOrUser -eq 'Machine')
    $enrollmentContext = 1
    if ($machine) { $enrollmentContext = 2 }

    # A certificate whose name is only in the subject is a certificate no current
    # browser accepts, so the common name goes in the SAN list as a DNS entry whether
    # it was listed or not. CN=Contoso in the subject has been decorative since
    # Chrome 58.
    $entries = @()
    foreach ($candidate in (@($CommonName) + @($AlternativeName))) {
        $entry = ConvertTo-SanEntry -InputObject $candidate
        if ($null -eq $entry) { continue }
        $duplicate = $false
        foreach ($held in $entries) {
            if (($held.Type -eq $entry.Type) -and ($held.Value -eq $entry.Value)) { $duplicate = $true; break }
        }
        if (-not $duplicate) { $entries += $entry }
    }
    $names = @($entries | ForEach-Object { $_.Value })

    # One folder per certificate, named after it. Path characters a CN may legally
    # carry and a folder may not - a wildcard star, a slash - become underscores, so
    # *.ad.lab.invalid lands in _.ad.lab.invalid rather than failing the create.
    $FileBaseName = ($CommonName -replace '[^A-Za-z0-9._-]', '_')
    $Folder = [System.IO.Path]::Combine($ParentFolder, $FileBaseName)
    $Want = @($script:outputFileCatalog | ForEach-Object { $_.Id })

    Write-Log "Requesting '$Template' for $CommonName" -Tag 'Info'
    Write-Log ("    subject alternative names: " + (($entries | ForEach-Object { "$($_.Type) $($_.Value)" }) -join ', ')) -Tag 'Info'
    Write-Log "    $Length bit key, $MachineOrUser context" -Tag 'Debug'

    try {
        $privateKey = New-Object -ComObject X509Enrollment.CX509PrivateKey
        $privateKey.ProviderName   = 'Microsoft Software Key Storage Provider'
        $privateKey.KeySpec        = 1       # XCN_AT_KEYEXCHANGE
        $privateKey.Length         = $Length
        # 3, not 1. XCN_NCRYPT_ALLOW_EXPORT_FLAG alone lets the key leave the store
        # inside an encrypted PFX and nothing else; reading it out as RSAParameters or
        # as a PKCS#8 blob is a PLAINTEXT export and needs bit 2 as well. With 1 the
        # certificate issues, the store shows a private key, and every attempt to write
        # a .key file answers "The requested operation is not supported". Bench-found.
        $privateKey.ExportPolicy   = 3       # ALLOW_EXPORT + ALLOW_PLAINTEXT_EXPORT
        $privateKey.MachineContext = $machine
        $privateKey.Create()
        Write-Log 'Key pair created' -Tag 'Ok'
    }
    catch {
        Write-Log "The key pair could not be created: $($_.Exception.Message)" -Tag 'Error'
        if ($machine) {
            Write-Log '    a machine-context key needs an elevated session' -Tag 'Info'
        }
        return $false
    }

    try {
        $pkcs10 = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
        # The template is named by its CN, not its display name - 'WebServices', not
        # 'Web Services'. The console shows one and the directory holds the other.
        $pkcs10.InitializeFromPrivateKey($enrollmentContext, $privateKey, $Template)

        $subject = New-Object -ComObject X509Enrollment.CX500DistinguishedName
        $subject.Encode("CN=$CommonName", 0)
        $pkcs10.Subject = $subject

        $alternatives = New-Object -ComObject X509Enrollment.CAlternativeNames
        foreach ($entry in $entries) {
            $alternative = New-Object -ComObject X509Enrollment.CAlternativeName
            if ($entry.Type -eq 'IP') {
                # XCN_CERT_ALT_NAME_IP_ADDRESS = 8, with XCN_CRYPT_STRING_BASE64 = 1 for
                # the value. What goes in is the RAW ADDRESS OCTETS - four for IPv4,
                # sixteen for IPv6 - which is exactly what RFC 5280 puts in an iPAddress
                # GeneralName. Not the text, and not a length-prefixed anything.
                $address = [System.Net.IPAddress]::Parse($entry.Value)
                $alternative.InitializeFromRawData(8, 1, [Convert]::ToBase64String($address.GetAddressBytes()))
            }
            else {
                # XCN_CERT_ALT_NAME_DNS_NAME = 3
                $alternative.InitializeFromString(3, $entry.Value)
            }
            $alternatives.Add($alternative)
        }
        $extension = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
        $extension.InitializeEncode($alternatives)
        $pkcs10.X509Extensions.Add($extension)
    }
    catch {
        Write-Log "The request could not be built: $($_.Exception.Message)" -Tag 'Error'
        return $false
    }

    try {
        $enrollment = New-Object -ComObject X509Enrollment.CX509Enrollment
        $enrollment.InitializeFromRequest($pkcs10)
        $enrollment.CertificateFriendlyName = $CommonName
        # Enroll() finds the CA through the enrollment policy, submits, and installs the
        # answer. It throws when the CA refuses, and the message it throws is the CA's.
        $enrollment.Enroll()
        Write-Log 'The certification authority issued the certificate' -Tag 'Ok'
    }
    catch {
        Write-Log "The certification authority refused the request: $($_.Exception.Message)" -Tag 'Error'
        # The signed-in user, in BOTH contexts. -Context decides where the key is stored,
        # not who asks: an interactive CertEnroll request authenticates to the CA as the
        # caller, and only the autoenrollment service, running as SYSTEM, ever submits as
        # the computer account. This message used to name the computer, which sent an
        # afternoon into group memberships that had nothing to do with it.
        $who = Get-RequestingIdentity
        Write-Log "    the identity asking is $($who.Name), and it has to hold Enroll on '$Template'" -Tag 'Info'
        Write-Log "    -Context Machine only puts the key in LocalMachine\My; it does not change who the CA sees" -Tag 'Info'
        if (-not $who.IsSystem) {
            Write-Log "    so either that account goes in the template's enrollment group, or run this whole script as SYSTEM" -Tag 'Info'
            Write-Log "    as SYSTEM the CA sees $env:COMPUTERNAME`$ instead, and the COMPUTER's membership is what counts: psexec -s -i powershell.exe" -Tag 'Info'
        }
        return $false
    }

    try {
        # XCN_CRYPT_STRING_BASE64 = 1.
        $issued = [Convert]::FromBase64String($enrollment.Certificate(1))
        $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$issued)
        Write-Log "Issued to $($certificate.Subject), expires $($certificate.NotAfter.ToString('yyyy-MM-dd'))" -Tag 'Info'
        Write-Log "    thumbprint $($certificate.Thumbprint)" -Tag 'Debug'
    }
    catch {
        Write-Log "The issued certificate could not be read back: $($_.Exception.Message)" -Tag 'Error'
        return $false
    }

    # The private key lives in the store, not on the object above - Enroll() installed
    # it there and the base64 it returned is the public half only.
    $storeLocation = 'CurrentUser'
    if ($machine) { $storeLocation = 'LocalMachine' }

    $installed = $null
    try {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', $storeLocation)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        $installed = $store.Certificates | Where-Object { $_.Thumbprint -eq $certificate.Thumbprint } | Select-Object -First 1
        $store.Close()
    }
    catch {
        Write-Log "The $storeLocation store could not be read: $($_.Exception.Message)" -Tag 'Error'
        return $false
    }

    if (($null -eq $installed) -or (-not $installed.HasPrivateKey)) {
        Write-Log "The certificate was issued but no private key is attached to it in the $storeLocation store" -Tag 'Error'
        return $false
    }

    $material = Get-CertificateKeyMaterial -Certificate $installed
    if ($null -eq $material) { return $false }

    # Generated, never asked for. A password somebody invents for a file they are about
    # to copy to an appliance is a password they reuse, and the screen that asked for it
    # was one more decision in front of an answer that is always "make one up".
    $pfxPassword = New-PfxPassword

    # Leaf first, then upward - the order a web server expects and the opposite of the
    # order people assemble by hand. Revocation is not checked: this certificate was
    # issued seconds ago and the CRL that covers it may not be published yet.
    $chainCertificates = @()
    try {
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $null = $chain.Build($installed)
        foreach ($element in $chain.ChainElements) { $chainCertificates += $element.Certificate }
    }
    catch {
        Write-Log "The issuing chain could not be built: $($_.Exception.Message)" -Tag 'Warn'
        $chainCertificates = @($installed)
    }
    $issuers = @($chainCertificates | Where-Object { $_.Thumbprint -ne $installed.Thumbprint })

    $written = New-Object System.Collections.Generic.List[string]
    try {
        if (-not (Test-Path -LiteralPath $Folder)) {
            $null = New-Item -ItemType Directory -Path $Folder -Force
            Write-Log "Created $Folder" -Tag 'Debug'
        }

        # Path.Combine, not Join-Path. Join-Path resolves through the PowerShell provider
        # and THROWS on a drive that does not exist, which takes the screen down on a
        # typo rather than failing the write with a message. This is string work.
        $pathFor = {
            param([string]$Id)
            $entry = Get-OutputFileEntry -Id $Id
            return [System.IO.Path]::Combine($Folder, $FileBaseName + $entry.Extension)
        }

        $leafPem = ConvertTo-Pem -Der $issued -Label 'CERTIFICATE'

        if ($Want -contains 'leafPem') {
            $path = & $pathFor 'leafPem'
            [System.IO.File]::WriteAllText($path, $leafPem)
            $written.Add($path)
            Write-Log "Wrote $(Split-Path -Path $path -Leaf)" -Tag 'Ok'
        }
        if ($Want -contains 'leafDer') {
            $path = & $pathFor 'leafDer'
            [System.IO.File]::WriteAllBytes($path, $issued)
            $written.Add($path)
            Write-Log "Wrote $(Split-Path -Path $path -Leaf)" -Tag 'Ok'
        }
        if ($Want -contains 'keyPem') {
            $path = & $pathFor 'keyPem'
            [System.IO.File]::WriteAllText($path, (ConvertTo-Pem -Der $material.Pkcs1 -Label 'RSA PRIVATE KEY'))
            $null = Protect-KeyFile -Path $path
            $written.Add($path)
            Write-Log "Wrote $(Split-Path -Path $path -Leaf)" -Tag 'Ok'
        }
        if ($Want -contains 'keyPkcs8') {
            $path = & $pathFor 'keyPkcs8'
            [System.IO.File]::WriteAllText($path, (ConvertTo-Pem -Der $material.Pkcs8 -Label 'PRIVATE KEY'))
            $null = Protect-KeyFile -Path $path
            $written.Add($path)
            Write-Log "Wrote $(Split-Path -Path $path -Leaf)" -Tag 'Ok'
        }
        if ($Want -contains 'chainPem') {
            $path = & $pathFor 'chainPem'
            $text = ""
            foreach ($item in $issuers) { $text += ConvertTo-Pem -Der $item.RawData -Label 'CERTIFICATE' }
            [System.IO.File]::WriteAllText($path, $text)
            $written.Add($path)
            Write-Log "Wrote $(Split-Path -Path $path -Leaf) - $($issuers.Count) issuer(s)" -Tag 'Ok'
        }
        if ($Want -contains 'fullchainPem') {
            $path = & $pathFor 'fullchainPem'
            $text = $leafPem
            foreach ($item in $issuers) { $text += ConvertTo-Pem -Der $item.RawData -Label 'CERTIFICATE' }
            [System.IO.File]::WriteAllText($path, $text)
            $written.Add($path)
            Write-Log "Wrote $(Split-Path -Path $path -Leaf) - leaf plus $($issuers.Count) issuer(s)" -Tag 'Ok'
        }
        if ($Want -contains 'pfx') {
            $path = & $pathFor 'pfx'
            # Export the COLLECTION, not the certificate: X509Certificate2.Export puts
            # the leaf and its key in the file and nothing else, and a PFX without the
            # chain is the one IIS binds and every client then reports as untrusted.
            $collection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
            $null = $collection.Add($installed)
            foreach ($item in $issuers) { $null = $collection.Add($item) }
            $bytes = $collection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $pfxPassword)
            [System.IO.File]::WriteAllBytes($path, $bytes)
            $null = Protect-KeyFile -Path $path
            $written.Add($path)
            Write-Log "Wrote $(Split-Path -Path $path -Leaf) - certificate, key and $($issuers.Count) issuer(s)" -Tag 'Ok'
        }
        if ($Want -contains 'password') {
            $path = [System.IO.Path]::Combine($Folder, $script:passwordFileName)
            [System.IO.File]::WriteAllText($path, $pfxPassword + "`r`n")
            $null = Protect-KeyFile -Path $path
            $written.Add($path)
            Write-Log "Wrote $script:passwordFileName - the password for the .pfx" -Tag 'Ok'
        }
        if ($Want -contains 'readme') {
            $path = & $pathFor 'readme'
            $report = New-Object System.Collections.Generic.List[string]
            $report.Add("Certificate request")
            $report.Add("===================")
            $report.Add("")
            $report.Add("Requested  : $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture))")
            $report.Add("Template   : $Template")
            $report.Add("Subject    : $($installed.Subject)")
            $report.Add("Names      : $($names -join ', ')")
            $report.Add("Issuer     : $($installed.Issuer)")
            $report.Add("Serial     : $($installed.SerialNumber)")
            $report.Add("Thumbprint : $($installed.Thumbprint)")
            $report.Add("Valid from : $($installed.NotBefore.ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture))")
            $report.Add("Valid to   : $($installed.NotAfter.ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture))")
            $report.Add("Key        : RSA $Length bit")
            $report.Add("")
            $report.Add("Files")
            $report.Add("-----")
            foreach ($id in $Want) {
                $entry = Get-OutputFileEntry -Id $id
                if ($null -eq $entry) { continue }
                $report.Add(("{0,-22} {1}" -f ($FileBaseName + $entry.Extension), $entry.Detail))
            }
            $report.Add("")
            $report.Add("The .key and .pkcs8.key files are UNENCRYPTED private keys and password.txt")
            $report.Add("is the .pfx password in clear. Move this whole folder to the machine that")
            $report.Add("needs it and delete it here.")
            [System.IO.File]::WriteAllText($path, (($report -join "`r`n") + "`r`n"))
            $written.Add($path)
            Write-Log "Wrote $(Split-Path -Path $path -Leaf)" -Tag 'Ok'
        }
    }
    catch {
        Write-Log "The files could not be written: $($_.Exception.Message)" -Tag 'Error'
        return $false
    }

    # Info, not Warn. Warn means "look at this, it may be wrong"; this is the script
    # doing exactly what it was asked to do, and tagging intended behaviour as a warning
    # is how an operator learns to read past warnings.
    Write-Log 'This folder holds two unencrypted private keys and a password in clear - move it and delete it here' -Tag 'Info'

    # Only ever after every file is on disk, and never in the same breath as the write:
    # a removal that ran first would take the only copy of the key with it.
    #
    # And matched three ways before anything goes. The thumbprint is the SHA-1 of the
    # whole certificate, so one match is the same bytes - but the collection is filtered
    # and COUNTED first, and the subject and NotBefore of what came back are compared
    # against what was just issued. "Remove the certificate" against an empty or a wide
    # match is how a script takes out something somebody else was using.
    try {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', $storeLocation)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $found = @($store.Certificates | Where-Object { $_.Thumbprint -eq $certificate.Thumbprint })

        if ($found.Count -ne 1) {
            Write-Log "Expected exactly one certificate with thumbprint $($certificate.Thumbprint) in $storeLocation\My and found $($found.Count) - nothing was removed" -Tag 'Warn'
        }
        elseif (($found[0].Subject -ne $installed.Subject) -or ($found[0].NotBefore -ne $installed.NotBefore)) {
            Write-Log "The certificate at that thumbprint no longer matches the one just issued - nothing was removed" -Tag 'Warn'
        }
        else {
            $store.Remove($found[0])
            Write-Log "Removed $($certificate.Thumbprint) from $storeLocation\My" -Tag 'Ok'
        }
        $store.Close()
    }
    catch {
        Write-Log "The files are written; the store entry could not be removed: $($_.Exception.Message)" -Tag 'Warn'
    }

    Write-Log "$($written.Count) file(s) in $Folder" -Tag 'Ok'
    return $true
}

# =================================================================================
# The console UI, copied from pwsh\ConsoleUi.ps1 down to the end of Show-Menu: the
# studio mark, the accent picked against the real console background, the fastfetch
# header and the arrow-key list. Copied rather than dot-sourced because a script that
# only works inside a full checkout is not standalone - and the colours are routed
# through Write-Studio so the whole thing renders in Kaido Dark.
# =================================================================================

# ===========================[ Console UI ]===========================
# Same shape as the New-Vhdx builder in the HyperV-Scripts repo: a fastfetch-style
# header with the studio's own mark - no vendor logo is drawn anywhere - then the
# then continue or cancel. It is a review screen, not a wizard - the design already
# happened in the studio, and config.json is the answer.

# THE ONE DELIBERATE DIVERGENCE FROM ConsoleUi.ps1's ARTWORK.
#
# The toolbox draws the studio mark - three role bars docking into a server unit -
# because a run configures roles. This script issues one certificate, so it draws the
# studio's own certificate glyph instead: the same three lines of text and the same
# sealed ribbon that certificate.svg draws in the HTML, in the same visual language as
# the mark it replaces. Descending bars on the left, a seal on the right.
#
# Stored as a plain ASCII mask ('#' paints a cell, '.' leaves it bare) and coloured at
# render time, 22x10 whole cells - and drawn for a CONSOLE CELL, which is about twice as
# tall as it is wide. A shape that is square on graph paper comes out stretched here, so
# the seal is eight cells across and four down to read as round, its cap is inset two
# cells each side, and the three bars descend 9, 7, 5 against a left margin they share.
# Everything is centred on one axis: seal body, cap and ribbons all sit on column 15.5. Every painted cell is a full block written with a
# FOREGROUND colour only - never a background fill, which would paint the terminal's
# default foreground into the gaps and draw a grey seam through the mark.
#
# Ten lines of 22, padded to the width constant below by Show-MenuHeader. Change the
# art and change that constant with it.
$script:serverLogoMask = @(
    "......................",
    "..#########...........",
    "..#########...........",
    "..............####....",
    "..#######...########..",
    "..#######...########..",
    "..............####....",
    "..#####......##..##...",
    "..#####...............",
    "......................"
)
$script:serverLogoAnsiWidth = 24

# The three studio accents, dark-mode and light-mode value each, in the order the
# studio lists its families. Kaido is the default and wins unless its hue collides
# with the console background.
$script:markAccents = @(
    [pscustomobject]@{ Family = "kaido"; Dark = "#7aa2f7"; Light = "#3457c4"; Console = "Cyan" },
    [pscustomobject]@{ Family = "vitrine"; Dark = "#a78bfa"; Light = "#6d46d6"; Console = "Magenta" },
    [pscustomobject]@{ Family = "ember"; Dark = "#e0955c"; Light = "#a85f21"; Console = "Yellow" }
)
$script:markAccent = $null
$script:menuConsoleType = $null
$script:menuVtEnabled = $false

function Get-MenuConsoleType {
    # The one P/Invoke surface the console UI needs: virtual terminal processing, and
    # the screen buffer's extended info, which is the only place the console's real
    # background colour is written down. Added once per session and cached - a resume
    # run dot-sources these parts a second time into a session where the type already
    # exists, and Add-Type would throw rather than return it.
    if ($script:menuConsoleType) { return $script:menuConsoleType }

    $existing = "WsrsRoles.WsrsVtConsole" -as [type]
    if ($existing) {
        $script:menuConsoleType = $existing
        return $script:menuConsoleType
    }

    try {
        $added = Add-Type -MemberDefinition @"
[StructLayout(LayoutKind.Sequential)]
public struct WsrsCoord { public short X; public short Y; }

[StructLayout(LayoutKind.Sequential)]
public struct WsrsSmallRect { public short Left; public short Top; public short Right; public short Bottom; }

[StructLayout(LayoutKind.Sequential)]
public struct WsrsBufferInfoEx {
    public int cbSize;
    public WsrsCoord dwSize;
    public WsrsCoord dwCursorPosition;
    public ushort wAttributes;
    public WsrsSmallRect srWindow;
    public WsrsCoord dwMaximumWindowSize;
    public ushort wPopupAttributes;
    public bool bFullscreenSupported;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public uint[] ColorTable;
}

[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr GetStdHandle(int nStdHandle);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool GetConsoleScreenBufferInfoEx(IntPtr hConsoleOutput, ref WsrsBufferInfoEx lpInfo);
"@ -Name WsrsVtConsole -Namespace WsrsRoles -PassThru -ErrorAction Stop

        $script:menuConsoleType = @($added) | Where-Object { $_.Name -eq "WsrsVtConsole" } | Select-Object -First 1
    }
    catch {
        # Older hosts, or a host with no console at all: every caller falls back
        $script:menuConsoleType = $null
    }

    return $script:menuConsoleType
}

function Enable-MenuVtProcessing {
    # Turns on virtual terminal processing so truecolor ANSI renders on
    # conhost-based Windows consoles. Safe no-op everywhere else.
    if ($script:menuVtEnabled) { return }
    $script:menuVtEnabled = $true

    try {
        $vt = Get-MenuConsoleType
        if ($null -eq $vt) { return }
        $handle = $vt::GetStdHandle(-11)
        $mode = [uint32]0
        if ($vt::GetConsoleMode($handle, [ref]$mode)) {
            [void]$vt::SetConsoleMode($handle, ($mode -bor 0x4))
        }
    }
    catch {
        # Older hosts without VT support fall back to the plain ASCII logo
    }
}

function Test-MenuAnsiSupported {
    try {
        if ($env:NO_COLOR) { return $false }
        if ($Host.UI.SupportsVirtualTerminal) { return $true }
        if ($env:WT_SESSION -or $env:TERM_PROGRAM -or $env:TERM) { return $true }
        return $false
    }
    catch {
        return $false
    }
}

function Test-MenuHostSupported {
    try {
        if ($null -eq $Host -or $null -eq $Host.UI -or $null -eq $Host.UI.RawUI) { return $false }
        if ($Host.Name -match "ISE") { return $false }
        return $true
    }
    catch {
        return $false
    }
}

function ConvertFrom-HexColor {
    param([string]$Hex)

    $h = $Hex.TrimStart("#")
    return @(
        [Convert]::ToInt32($h.Substring(0, 2), 16),
        [Convert]::ToInt32($h.Substring(2, 2), 16),
        [Convert]::ToInt32($h.Substring(4, 2), 16)
    )
}

function Get-ColorLuminance {
    # WCAG relative luminance, 0 (black) to 1 (white).
    param([int[]]$Rgb)

    $parts = @()
    foreach ($c in $Rgb) {
        $s = $c / 255.0
        if ($s -le 0.03928) { $parts += ($s / 12.92) }
        else { $parts += [Math]::Pow((($s + 0.055) / 1.055), 2.4) }
    }
    return (0.2126 * $parts[0]) + (0.7152 * $parts[1]) + (0.0722 * $parts[2])
}

function Get-ColorContrast {
    param([int[]]$First, [int[]]$Second)

    $a = Get-ColorLuminance -Rgb $First
    $b = Get-ColorLuminance -Rgb $Second
    if ($a -lt $b) { $t = $a; $a = $b; $b = $t }
    return (($a + 0.05) / ($b + 0.05))
}

function Get-ColorHue {
    # HSL hue in degrees. Meaningless for a grey, which is what Get-ColorChroma
    # is checked for first.
    param([int[]]$Rgb)

    $r = $Rgb[0] / 255.0; $g = $Rgb[1] / 255.0; $b = $Rgb[2] / 255.0
    $max = [Math]::Max($r, [Math]::Max($g, $b))
    $min = [Math]::Min($r, [Math]::Min($g, $b))
    $d = $max - $min
    if ($d -eq 0) { return 0.0 }

    if ($max -eq $r) { $h = 60.0 * ((($g - $b) / $d) % 6.0) }
    elseif ($max -eq $g) { $h = 60.0 * ((($b - $r) / $d) + 2.0) }
    else { $h = 60.0 * ((($r - $g) / $d) + 4.0) }
    if ($h -lt 0) { $h += 360.0 }
    return $h
}

function Get-ColorChroma {
    # Absolute chroma, 0 to 1. Deliberately not HSL saturation: the studio's own dark
    # background is #16171e, whose eight-step spread between channels is invisible and
    # yet scores 0.15 saturation once HSL divides it by a near-zero lightness term.
    # A background this close to black has no hue worth avoiding.
    param([int[]]$Rgb)

    $max = [Math]::Max($Rgb[0], [Math]::Max($Rgb[1], $Rgb[2]))
    $min = [Math]::Min($Rgb[0], [Math]::Min($Rgb[1], $Rgb[2]))
    return (($max - $min) / 255.0)
}

function Get-ColorHueDistance {
    # 0 to 180: how far apart two hues are on the wheel.
    param([double]$First, [double]$Second)

    $d = [Math]::Abs($First - $Second)
    if ($d -gt 180.0) { $d = 360.0 - $d }
    return $d
}

# The legacy console palette, used only when GetConsoleScreenBufferInfoEx could not
# answer. One entry is not the legacy value: **DarkMagenta as a background is the
# PowerShell 5.1 shortcut's #012456**, not purple. That shortcut remaps the palette
# slot rather than the colour name, so every stock Windows PowerShell console on a
# server reports DarkMagenta and paints navy - and nothing else sets a genuinely
# magenta console background by accident.
$script:consoleColorRgb = @{
    "Black"       = "#0c0c0c"; "DarkBlue" = "#000080"; "DarkGreen" = "#008000"
    "DarkCyan"    = "#008080"; "DarkRed" = "#800000"; "DarkMagenta" = "#012456"
    "DarkYellow"  = "#808000"; "Gray" = "#c0c0c0"; "DarkGray" = "#808080"
    "Blue"        = "#0000ff"; "Green" = "#00ff00"; "Cyan" = "#00ffff"
    "Red"         = "#ff0000"; "Magenta" = "#ff00ff"; "Yellow" = "#ffff00"
    "White"       = "#ffffff"
}

function Get-ConsoleBackgroundRgb {
    # The console's real background colour, or $null when nothing can answer.
    #
    # GetConsoleScreenBufferInfoEx is the only exact source: it hands back the live
    # 16-entry colour table plus the current attribute, so a remapped palette (the
    # PowerShell shortcut), a Windows Terminal scheme and a hand-set background all
    # read correctly. The RawUI fall-back below only knows a colour *name*.
    try {
        $vt = Get-MenuConsoleType
        if ($vt) {
            $infoType = $vt.GetNestedType("WsrsBufferInfoEx")
            if ($infoType) {
                $info = [Activator]::CreateInstance($infoType)
                $info.cbSize = [System.Runtime.InteropServices.Marshal]::SizeOf($infoType)
                $handle = $vt::GetStdHandle(-11)
                if ($vt::GetConsoleScreenBufferInfoEx($handle, [ref]$info)) {
                    $index = ([int]$info.wAttributes -shr 4) -band 0xF
                    $ref = [uint32]$info.ColorTable[$index]
                    # COLORREF is 0x00BBGGRR
                    return @(
                        [int]($ref -band 0xFF),
                        [int](($ref -shr 8) -band 0xFF),
                        [int](($ref -shr 16) -band 0xFF)
                    )
                }
            }
        }
    }
    catch {
        # No console, no kernel32, or a host that does not own a screen buffer
    }

    try {
        $name = [string]$Host.UI.RawUI.BackgroundColor
        if ($script:consoleColorRgb.ContainsKey($name)) {
            return (ConvertFrom-HexColor -Hex $script:consoleColorRgb[$name])
        }
    }
    catch {
        # RawUI is absent in a host with no console
    }

    return $null
}

function Get-MarkAccent {
    # Which colour the mark is drawn in, decided against the console background.
    #
    # The rule is "keep the brand unless it collides": Kaido - the studio's default
    # accent - is used whenever it is legible and its hue is clear of the background.
    # It is not clear of #012456, which is why the stock PowerShell console gets
    # Ember instead: same 6:1 contrast, 193 degrees of hue away, so it reads as a
    # mark rather than as a lighter patch of background. A background too close to
    # every accent at once drops the mark to a flat neutral, which always separates.
    if ($script:markAccent) { return $script:markAccent }

    $bg = Get-ConsoleBackgroundRgb
    if ($null -eq $bg) { $bg = ConvertFrom-HexColor -Hex "#0c0c0c" }

    $bgLum = Get-ColorLuminance -Rgb $bg
    $bgHue = Get-ColorHue -Rgb $bg
    $achromatic = (Get-ColorChroma -Rgb $bg) -lt 0.10
    $mode = "Dark"
    if ($bgLum -gt 0.35) { $mode = "Light" }

    $scored = @()
    foreach ($accent in $script:markAccents) {
        $rgb = ConvertFrom-HexColor -Hex $accent.$mode
        $contrast = Get-ColorContrast -First $rgb -Second $bg
        $hueGap = 180.0
        if (-not $achromatic) { $hueGap = Get-ColorHueDistance -First (Get-ColorHue -Rgb $rgb) -Second $bgHue }
        $score = (($hueGap / 180.0) * 0.6) + (([Math]::Min($contrast, 10.0) / 10.0) * 0.4)
        if ($contrast -lt 4.5) { $score -= 1.0 }
        $scored += [pscustomobject]@{
            Family   = $accent.Family
            Console  = $accent.Console
            Hex      = $accent.$mode
            Rgb      = $rgb
            Contrast = $contrast
            HueGap   = $hueGap
            Score    = $score
        }
    }

    $chosen = $scored | Where-Object { $_.Family -eq "kaido" } | Select-Object -First 1
    if ($chosen.Contrast -lt 4.5 -or $chosen.HueGap -lt 60.0) {
        $chosen = $scored | Sort-Object -Property Score -Descending | Select-Object -First 1
    }

    if ($chosen.Contrast -lt 3.0) {
        # Nothing in the palette separates - a mid-tone or a saturated background.
        # Fall to a flat neutral, and pick which one by contrast rather than by the
        # mode: a mid grey is neither dark nor light, and near-black beats near-white
        # on it by a full contrast step.
        $chosen = @("#e8ecf5", "#16171e") | ForEach-Object {
            $neutralConsole = "White"
            if ($_ -eq "#16171e") { $neutralConsole = "Black" }
            $neutralRgb = ConvertFrom-HexColor -Hex $_
            [pscustomobject]@{
                Family   = "neutral"
                Console  = $neutralConsole
                Hex      = $_
                Rgb      = $neutralRgb
                Contrast = (Get-ColorContrast -First $neutralRgb -Second $bg)
                HueGap   = 0.0
                Score    = 0.0
            }
        } | Sort-Object -Property Contrast -Descending | Select-Object -First 1
    }

    $script:markAccent = $chosen
    return $script:markAccent
}

function Get-ServerLogoLine {
    # Truecolor pixel-art mark when the console supports ANSI, plain ASCII otherwise.
    param([switch]$Plain)

    if ($Plain) {
        $plainLines = @()
        foreach ($row in $script:serverLogoMask) { $plainLines += $row.Replace(".", " ") }
        return $plainLines
    }

    $accent = Get-MarkAccent
    $esc = [char]27
    $block = [string][char]0x2588
    $open = "{0}[38;2;{1};{2};{3}m" -f $esc, $accent.Rgb[0], $accent.Rgb[1], $accent.Rgb[2]
    $close = "{0}[0m" -f $esc

    $lines = @()
    foreach ($row in $script:serverLogoMask) {
        # One escape opens the line and one closes it: the mark is a single flat
        # colour, and an unpainted cell is a space, which needs no colour at all.
        $lines += ($open + $row.Replace(".", " ").Replace("#", $block) + $close)
    }
    return $lines
}

function Write-ColoredLogoLine {
    # The no-ANSI path: the same mask in the nearest of the sixteen console colours.
    param([string]$Line)

    Write-Host $Line -NoNewline -ForegroundColor (Get-MarkAccent).Console
}

function Get-AnsiVisibleLength {
    # Counts printable characters only (strips CSI / OSC escape sequences).
    param([string]$Text)

    if ([string]::IsNullOrEmpty($Text)) { return 0 }
    $stripped = [regex]::Replace($Text, '\x1b\[[0-9;?]*[ -/]*[@-~]', '')
    $stripped = [regex]::Replace($stripped, '\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)', '')
    return $stripped.Length
}

function Get-PaddedAnsiLine {
    param(
        [string]$Line,
        [int]$Width
    )

    $visible = Get-AnsiVisibleLength -Text $Line
    if ($visible -ge $Width) { return $Line }
    return ($Line + (" " * ($Width - $visible)))
}

function Write-FastfetchInfoRow {
    # Fastfetch-style aligned "label: value" (colons and values in one column).
    param(
        [string]$Label,
        [string]$Value,
        [int]$LabelWidth = 8,
        [int]$IndentWidth = 0
    )

    if ($IndentWidth -gt 0) { Write-Host (" " * $IndentWidth) -NoNewline }
    $paddedLabel = ("{0,-$LabelWidth}" -f $Label)
    Write-Studio -Text $paddedLabel -Key 'muted' -NoNewline
    Write-Studio -Text ": " -Key 'muted' -NoNewline
    Write-Studio -Text $Value -Key 'fg'
}

function Show-MenuHeader {
    # Fastfetch-style header: colored server logo (left) + aligned facts (right).
    param(
        [string]$Title = "Role configuration",
        [hashtable]$StatusLines,
        [string]$Subtitle
    )

    Enable-MenuVtProcessing
    Clear-Host
    Write-Host ""

    $useAnsi = Test-MenuAnsiSupported
    $logo = @(Get-ServerLogoLine -Plain:(-not $useAnsi))
    $logoWidth = [int]$script:serverLogoAnsiWidth
    $pad = " " * $logoWidth
    $labelWidth = 8

    $info = New-Object System.Collections.Generic.List[object]
    $info.Add([pscustomobject]@{ Label = "toolkit"; Value = $scriptName; Accent = $true }) | Out-Null
    $info.Add([pscustomobject]@{ Label = "menu"; Value = $Title; Accent = $false }) | Out-Null
    if (-not [string]::IsNullOrWhiteSpace($Subtitle)) {
        $info.Add([pscustomobject]@{ Label = "section"; Value = $Subtitle; Accent = $false }) | Out-Null
    }
    $info.Add([pscustomobject]@{ Label = ""; Value = ""; Accent = $false }) | Out-Null

    if ($StatusLines) {
        foreach ($key in $StatusLines.Keys) {
            $info.Add([pscustomobject]@{
                    Label  = ([string]$key).ToLowerInvariant()
                    Value  = [string]$StatusLines[$key]
                    Accent = $false
                }) | Out-Null
        }
        $info.Add([pscustomobject]@{ Label = ""; Value = ""; Accent = $false }) | Out-Null
    }

    $info.Add([pscustomobject]@{ Label = "host"; Value = $env:COMPUTERNAME; Accent = $false }) | Out-Null
    $info.Add([pscustomobject]@{ Label = "user"; Value = $env:USERNAME; Accent = $false }) | Out-Null
    $info.Add([pscustomobject]@{ Label = "shell"; Value = ("PS " + $PSVersionTable.PSVersion.ToString()); Accent = $false }) | Out-Null

    $rows = [Math]::Max($logo.Count, $info.Count)
    for ($i = 0; $i -lt $rows; $i++) {
        Write-Host "  " -NoNewline

        if ($i -lt $logo.Count) {
            if ($useAnsi) {
                Write-Host (Get-PaddedAnsiLine -Line $logo[$i] -Width $logoWidth) -NoNewline
            }
            else {
                $line = $logo[$i]
                if ($line.Length -lt $logoWidth) { $line = $line + (" " * ($logoWidth - $line.Length)) }
                elseif ($line.Length -gt $logoWidth) { $line = $line.Substring(0, $logoWidth) }
                Write-ColoredLogoLine -Line $line
            }
        }
        else {
            Write-Host $pad -NoNewline
        }

        Write-Host "   " -NoNewline

        if ($i -lt $info.Count) {
            $row = $info[$i]
            if ([string]::IsNullOrWhiteSpace($row.Label) -and [string]::IsNullOrWhiteSpace($row.Value)) {
                Write-Host ""
                continue
            }
            if ($row.Accent) { Write-Studio -Text $row.Value -Key 'accent' }
            else { Write-FastfetchInfoRow -Label $row.Label -Value $row.Value -LabelWidth $labelWidth }
        }
        else {
            Write-Host ""
        }
    }

    Write-Host ""
    Write-Studio -Text ("  " + ("-" * 62)) -Key 'borderStrong'
    Write-Host ""
}

# The dim lines under a menu item. A `Detail` property on an item is optional and is
# whatever the caller wants said about that one entry - a disk's model and serial, an
# adapter's driver and PCIe width. It is never the answer to the question, which is what
# keeps it out of `Label`: the label is what the item *is*, the detail is how to tell it
# apart from the one below it.
function Get-MenuDetailLine {
    param([object]$Item)

    if ($null -eq $Item) { return @() }
    if (-not ($Item.PSObject.Properties.Name -contains "Detail")) { return @() }
    return @(@($Item.Detail) |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
        ForEach-Object { [string]$_ })
}

function Show-Menu {
    param(
        [string]$Title,
        [object[]]$Items,
        [int]$SelectedIndex = 0,
        [hashtable]$StatusLines,
        [string]$Subtitle,
        [scriptblock]$PreItems,
        [string]$Heading,
        [string]$HeadingHint
    )

    if (-not $Items -or $Items.Count -eq 0) {
        throw "Show-Menu requires at least one item."
    }

    $index = $SelectedIndex
    if ($index -lt 0) { $index = 0 }
    if ($index -ge $Items.Count) { $index = $Items.Count - 1 }

    $useRawUi = Test-MenuHostSupported

    while ($true) {
        Show-MenuHeader -Title $Title -StatusLines $StatusLines -Subtitle $Subtitle

        if ($PreItems) { & $PreItems }

        if (-not [string]::IsNullOrWhiteSpace($Heading)) {
            Write-Studio -Text "  $Heading" -Key 'fg'
            if (-not [string]::IsNullOrWhiteSpace($HeadingHint)) {
                Write-Studio -Text "  $HeadingHint" -Key 'muted'
            }
            Write-Host ""
        }

        for ($i = 0; $i -lt $Items.Count; $i++) {
            $item  = $Items[$i]
            $label = if ($item.Label) { [string]$item.Label } else { [string]$item }

            if ($i -eq $index) {
                Write-Studio -Text "  > " -Key 'accent' -NoNewline
                Write-Studio -Text $label -Key 'accentHover'
            }
            else {
                Write-Host "    " -NoNewline
                Write-Studio -Text $label -Key 'fg'
            }
            # One blank line after an item that carried detail, and none after one that
            # did not. A DIVERGENCE from ConsoleUi.ps1, on purpose: the toolbox's menus
            # are mostly bare labels, where blank lines would stretch a list of roles
            # into two screens. Every list here is two or three items each carrying two
            # dim lines, and run together they read as one paragraph with an arrow in
            # it - the detail of one item sits against the label of the next. Continue,
            # Back and Cancel have no detail, so they stay grouped as the buttons they are.
            $detail = @(Get-MenuDetailLine -Item $item)
            foreach ($line in $detail) {
                Write-Studio -Text ("      " + $line) -Key 'muted'
            }
            if ($detail.Count -gt 0) { Write-Host "" }
        }

        Write-Host ""
        Write-Studio -Text ("  " + ("-" * 62)) -Key 'borderStrong'
        if ($useRawUi) {
            Write-Studio -Text "  Up/Down move   Enter select   Esc/Q cancel" -Key 'muted'
        }
        else {
            Write-Studio -Text "  Enter number + Enter   (Q to cancel)" -Key 'muted'
        }
        Write-Host ""

        if ($useRawUi) {
            $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            $virtualKey = [int]$key.VirtualKeyCode
            $charKey = [string]$key.Character

            if ($virtualKey -eq 38) {
                $index = if ($index -le 0) { $Items.Count - 1 } else { $index - 1 }
                continue
            }
            if ($virtualKey -eq 40) {
                $index = if ($index -ge ($Items.Count - 1)) { 0 } else { $index + 1 }
                continue
            }
            if ($virtualKey -eq 36) { $index = 0; continue }
            if ($virtualKey -eq 35) { $index = $Items.Count - 1; continue }
            if ($virtualKey -eq 13) { return $Items[$index].Id }
            if ($virtualKey -eq 27 -or $charKey -eq "q" -or $charKey -eq "Q") { return $null }
        }
        else {
            $raw = Read-Host "Select"
            if ([string]::IsNullOrWhiteSpace($raw)) { continue }
            if ($raw -match "^[Qq]$") { return $null }
            if ($raw -match "^\d+$") {
                $num = [int]$raw
                if ($num -ge 1 -and $num -le $Items.Count) { return $Items[$num - 1].Id }
            }
        }
    }
}
# The mark is pinned to Kaido rather than chosen.
#
# Get-MarkAccent normally decides against the console's real background - keep the brand
# unless its hue collides - and on the stock 5.1 console, whose background is #012456,
# it correctly picks Ember instead. That rule is right for the toolbox and wrong here,
# because the point of this build is to see Kaido Dark. Pre-setting the cache is all it
# takes: Get-MarkAccent returns $script:markAccent untouched when it is already set.
$script:markAccent = [pscustomobject]@{
    Family = "kaido"; Console = "Cyan"; Hex = $script:studioPalette.accent
    Rgb = (ConvertFrom-HexColor -Hex $script:studioPalette.accent)
    Contrast = 0.0; HueGap = 0.0; Score = 0.0
}

# ===========================[ The wizard ]===========================
# Everything above is a copy of pwsh\ConsoleUi.ps1 down to the end of Show-Menu.
# Copied rather than dot-sourced for the reason in the description, and that has a cost
# worth stating: if the mark or the header changes there, nothing here follows.
#
# One question per screen, and every screen has Continue and Back. The toolbox puts up
# a review screen because its answer already exists in config.json; here the answer is
# being made up on the spot, so it is a wizard - with a review at the end, which is the
# screen the toolbox would have shown.

# A heading, in the accent. The studio draws a card title as the loudest thing in the
# card, and a summary whose headings were the same colour as its rows read as one list
# with two stray words in it.
function Write-SummarySection {
    param(
        [Parameter(Mandatory)][string]$Title,
        # The blank line is what separates one section from the last, so the first
        # section on a screen does not want it - the header already left one.
        [switch]$First
    )

    if (-not $First) { Write-Host "" }
    Write-Studio -Text "  $Title" -Key 'accent'
}

function Show-ScreenNotice {
    param(
        [Parameter(Mandatory)][string]$Text,
        [string]$Tag = "Warn"
    )

    $key = "fg"
    if ($Tag -eq "Warn") { $key = "warn" }
    if ($Tag -eq "Error") { $key = "danger" }

    Write-Host ""
    Write-Studio -Text "  $Text" -Key $key
    Write-Host ""
    Write-Studio -Text "  Press Enter to go back" -Key 'muted'
    $null = Read-Host
}

# What the certification authority will see on the wire, which is the running identity
# and not the -Context. SYSTEM is the one case where it is the computer account: a
# process running as SYSTEM on a domain member authenticates over the network as
# COMPUTERNAME$, which is why autoenrollment shows up in Failed Requests as a machine.
function Get-RequestingIdentity {
    # Wrapped, because the environment variables are the only answer a host without
    # Windows principals can give - and a review screen that throws while describing
    # who is asking is a worse failure than one that names the account less precisely.
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $isSystem = ($identity.User.Value -eq 'S-1-5-18')
        $shown = $identity.Name
        if ($isSystem) { $shown = "SYSTEM - the CA sees $env:COMPUTERNAME`$" }
        return [pscustomobject]@{ Name = $identity.Name; IsSystem = $isSystem; Shown = $shown }
    }
    catch {
        $fallback = "$env:USERDOMAIN\$env:USERNAME"
        return [pscustomobject]@{ Name = $fallback; IsSystem = $false; Shown = $fallback }
    }
}

function Get-WizardBaseName {
    param([Parameter(Mandatory)][hashtable]$State)

    $name = [string]$State.BaseName
    if (-not [string]::IsNullOrWhiteSpace($name)) { return $name }
    return (([string]$State.CommonName) -replace "[^A-Za-z0-9._-]", "_")
}

function Get-WizardNameList {
    param([Parameter(Mandatory)][hashtable]$State)

    return @($State.SanEntries)
}

$script:wizardNamesPreamble = {
    Write-Studio -Text ("  " + $script:wizardQuestion) -Key 'fg'
    Write-Studio -Text ("  " + $script:wizardHint) -Key 'muted'
    Write-Host ""
    foreach ($row in $script:wizardNameRows) {
        Write-Studio -Text ("    " + $row.Type.PadRight(5) + " ") -Key 'bandHost' -NoNewline
        Write-Studio -Text $row.Value -Key 'fg' -NoNewline
        if (-not [string]::IsNullOrWhiteSpace($row.Note)) {
            Write-Studio -Text ("   " + $row.Note) -Key 'muted'
        }
        else { Write-Host "" }
    }
    Write-Host ""
}

# One entry, added by type rather than guessed at. The type is asked outright because
# the two are encoded completely differently - a DNS name goes in as text, an IP goes
# in as its raw octets - and a name that looks like one and is meant as the other is a
# certificate that silently matches nothing.
function Invoke-WizardNameStep {
    param(
        [Parameter(Mandatory)][hashtable]$State,
        [int]$StepNumber = 1,
        [int]$StepTotal = 1
    )

    $selected = 0
    while ($true) {
        $entries = @($State.SanEntries)

        $script:wizardQuestion = "Which other names must this certificate answer to?"
        $script:wizardHint     = "Browsers match the subject alternative names and nothing else."
        $script:wizardNameRows = @()
        $script:wizardNameRows += [pscustomobject]@{
            Type = "DNS"; Value = [string]$State.CommonName; Note = "the common name, always included"
        }
        foreach ($entry in $entries) {
            $script:wizardNameRows += [pscustomobject]@{ Type = $entry.Type; Value = $entry.Value; Note = "" }
        }

        $items = @(
            [pscustomobject]@{ Id = "addDns"; Label = "Add a DNS name"
                               Detail = "a host name - portal.ad.lab.invalid, or the short name as well" }
            [pscustomobject]@{ Id = "addIp";  Label = "Add an IP address"
                               Detail = "IPv4 or IPv6, written in as raw octets" }
        )
        if ($entries.Count -gt 0) {
            $items += [pscustomobject]@{ Id = "remove"; Label = "Remove one"
                                         Detail = "$($entries.Count) added so far" }
        }
        $items += [pscustomobject]@{ Id = "next";   Label = "Continue" }
        $items += [pscustomobject]@{ Id = "back";   Label = "Back" }
        $items += [pscustomobject]@{ Id = "cancel"; Label = "Cancel" }

        $choice = Show-Menu -Title "Other names" -Subtitle "Step $StepNumber of $StepTotal" -Items $items `
            -SelectedIndex $selected -PreItems $script:wizardNamesPreamble `
            -StatusLines (Get-WizardStatus -State $State)

        if ($null -eq $choice) { return "cancel" }
        if ($choice -eq "cancel") { return "cancel" }
        if ($choice -eq "back") { return "back" }
        if ($choice -eq "next") { return "next" }

        for ($i = 0; $i -lt $items.Count; $i++) {
            if ($items[$i].Id -eq $choice) { $selected = $i; break }
        }

        if ($choice -eq "addDns") {
            $typed = Read-WizardField -Question "A DNS name" -Hint "No scheme and no port - just the name"
            if ([string]::IsNullOrWhiteSpace($typed)) { continue }
            if ((Get-SanTypeGuess -Value $typed) -eq "IP") {
                Show-ScreenNotice -Text "'$typed' is an IP address. Add it with 'Add an IP address' so it is encoded as one."
                continue
            }
            $State.SanEntries = @($entries + [pscustomobject]@{ Type = "DNS"; Value = $typed })
            continue
        }

        if ($choice -eq "addIp") {
            $typed = Read-WizardField -Question "An IP address" -Hint "IPv4 or IPv6, for example 10.11.12.13"
            if ([string]::IsNullOrWhiteSpace($typed)) { continue }
            $address = $null
            # The dot-or-colon test first, for the same reason the guess uses it:
            # TryParse alone accepts "12345" and returns 0.0.48.57.
            $looksNumeric = ($typed -match '\.') -or ($typed -match ':')
            if ((-not $looksNumeric) -or (-not [System.Net.IPAddress]::TryParse($typed, [ref]$address))) {
                Show-ScreenNotice -Text "'$typed' is not an IP address."
                continue
            }
            $State.SanEntries = @($entries + [pscustomobject]@{ Type = "IP"; Value = $address.ToString() })
            continue
        }

        if ($choice -eq "remove") {
            $removeItems = @()
            foreach ($entry in $entries) {
                $removeItems += [pscustomobject]@{ Id = ($entry.Type + "|" + $entry.Value)
                                                   Label = ($entry.Type.PadRight(5) + " " + $entry.Value) }
            }
            $removeItems += [pscustomobject]@{ Id = "back"; Label = "Back - remove nothing" }
            $picked = Show-Menu -Title "Remove a name" -Subtitle "Step $StepNumber of $StepTotal" `
                -Items $removeItems -SelectedIndex 0 -StatusLines (Get-WizardStatus -State $State)
            if (($null -eq $picked) -or ($picked -eq "back")) { continue }
            $State.SanEntries = @($entries | Where-Object { ($_.Type + "|" + $_.Value) -ne $picked })
        }
    }
}

function Get-WizardStatus {
    param([Parameter(Mandatory)][hashtable]$State)

    $subject = [string]$State.CommonName
    if ([string]::IsNullOrWhiteSpace($subject)) { $subject = "not set" }
    # No step count here - the subtitle already says "Step 4 of 11", and a header that
    # says it twice in two different shapes reads as two different facts.
    return @{
        subject  = $subject
        template = [string]$State.Template
        folder   = [string]$State.Folder
    }
}

# The question, its hint and the answer so far, above whatever list the step shows.
# A PLAIN scriptblock reading $script: variables, never .GetNewClosure(): that binds
# the block to a fresh dynamic module, and on Windows PowerShell 5.1 a module scope
# cannot see functions defined at script scope, so Write-Studio would come back as
# CommandNotFoundException on a real 5.1 host while working fine on 7.
$script:wizardPreamble = {
    # No leading blank. Show-MenuHeader already closes with one after its rule, and a
    # second here pushed every question two lines clear of the header it belongs to.
    Write-Studio -Text ("  " + $script:wizardQuestion) -Key 'fg'
    if (-not [string]::IsNullOrWhiteSpace($script:wizardHint)) {
        Write-Studio -Text ("  " + $script:wizardHint) -Key 'muted'
    }
    Write-Host ""
    if (-not [string]::IsNullOrWhiteSpace($script:wizardValue)) {
        Write-Studio -Text "  Answer: " -Key 'muted' -NoNewline
        Write-Studio -Text $script:wizardValue -Key 'accentHover'
        Write-Host ""
    }
}

# The typing half of a field. Enter alone keeps what is there, a single - clears it,
# and the caret sits under the question rather than after a label, so the screen reads
# as a form being filled in.
function Read-WizardField {
    param(
        [Parameter(Mandatory)][string]$Question,
        [string]$Hint = "",
        [string]$Current = ""
    )

    Write-Studio -Text "  $Question" -Key 'fg'
    if (-not [string]::IsNullOrWhiteSpace($Hint)) { Write-Studio -Text "  $Hint" -Key 'muted' }
    if (-not [string]::IsNullOrWhiteSpace($Current)) {
        Write-Studio -Text "  Enter keeps '$Current', a single - clears it" -Key 'muted'
    }
    Write-Host ""
    Write-Studio -Text "  > " -Key 'accent' -NoNewline

    # The rule belongs UNDER the prompt, and a console cannot write below a line it is
    # still reading from - so it is drawn first and the cursor is put back. The drift
    # correction is not decoration: near the bottom of the buffer those three lines
    # scroll the screen, every recorded coordinate shifts up by however many lines it
    # scrolled, and the cursor would be restored into the middle of the header.
    $anchor = $null
    if (Test-MenuHostSupported) {
        try {
            $before = $Host.UI.RawUI.CursorPosition
            Write-Host ""
            Write-Host ""
            Write-Studio -Text ("  " + ("-" * 62)) -Key 'borderStrong'
            $after = $Host.UI.RawUI.CursorPosition
            $drift = ($before.Y + 3) - $after.Y
            $anchor = $before
            $anchor.Y = $before.Y - $drift
            if ($anchor.Y -lt 0) { $anchor.Y = 0 }
            $Host.UI.RawUI.CursorPosition = $anchor
        }
        catch {
            # A host without a real screen buffer. The rule goes after the answer
            # instead, which is the wrong place and better than a crash in the right one.
            $anchor = $null
        }
    }

    $raw = Read-Host
    if ($null -eq $anchor) {
        Write-Host ""
        Write-Studio -Text ("  " + ("-" * 62)) -Key 'borderStrong'
    }
    if ([string]::IsNullOrWhiteSpace($raw)) { return $Current }
    if ($raw.Trim() -eq "-") { return "" }
    return $raw.Trim()
}

function Invoke-WizardTextStep {
    param(
        [Parameter(Mandatory)][hashtable]$State,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Question,
        [string]$Hint = "",
        [string]$Placeholder = "not set",
        [int]$StepNumber = 1,
        [int]$StepTotal = 1,
        [switch]$Required
    )

    # An empty required field opens straight into the prompt rather than making the
    # operator press Enter on a box to be allowed to type in it. Only on arrival, and
    # only while it is empty, so coming Back to a filled field shows the field.
    $arriving = $true

    while ($true) {
        $current = [string]$State[$Key]
        if ($arriving -and $Required -and [string]::IsNullOrWhiteSpace($current)) {
            $arriving = $false
            Show-MenuHeader -Title $Title -Subtitle "Step $StepNumber of $StepTotal" -StatusLines (Get-WizardStatus -State $State)
            $State[$Key] = Read-WizardField -Question $Question -Hint $Hint -Current $current
            continue
        }
        $arriving = $false

        $script:wizardQuestion = $Question
        $script:wizardHint     = $Hint
        $script:wizardValue    = $current
        if ([string]::IsNullOrWhiteSpace($script:wizardValue)) { $script:wizardValue = $Placeholder }

        # The first item IS the field, drawn as one - an empty box when there is
        # nothing in it. It used to read "Type an answer", which named the verb rather
        # than showing the thing, so the screen had a button where a form should be.
        $fieldText = $current
        $fieldHint = "Enter to type over it"
        if ([string]::IsNullOrWhiteSpace($fieldText)) {
            $fieldText = " " * 34
            $fieldHint = "empty - Enter to fill it in"
            if ($Required) { $fieldHint = "empty, and required - Enter to fill it in" }
        }
        $items = @(
            [pscustomobject]@{ Id = "edit";   Label = "[ " + $fieldText + " ]"; Detail = $fieldHint }
            [pscustomobject]@{ Id = "next";   Label = "Continue" }
            [pscustomobject]@{ Id = "back";   Label = "Back" }
            [pscustomobject]@{ Id = "cancel"; Label = "Cancel" }
        )
        $default = 1
        if ([string]::IsNullOrWhiteSpace($current)) { $default = 0 }

        $choice = Show-Menu -Title $Title -Subtitle "Step $StepNumber of $StepTotal" -Items $items `
            -SelectedIndex $default -PreItems $script:wizardPreamble `
            -StatusLines (Get-WizardStatus -State $State)

        if ($null -eq $choice) { return "cancel" }
        if ($choice -eq "cancel") { return "cancel" }
        if ($choice -eq "back") { return "back" }
        if ($choice -eq "next") {
            if ($Required -and [string]::IsNullOrWhiteSpace([string]$State[$Key])) {
                Show-ScreenNotice -Text "This one is required - nothing else can be worked out without it."
                continue
            }
            return "next"
        }

        $State[$Key] = Read-WizardField -Question $Question -Hint $Hint -Current $current
    }
}

function Invoke-WizardChoiceStep {
    param(
        [Parameter(Mandatory)][hashtable]$State,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Question,
        [string]$Hint = "",
        [Parameter(Mandatory)][object[]]$Options,
        [int]$StepNumber = 1,
        [int]$StepTotal = 1,
        [switch]$AsInt
    )

    $script:wizardQuestion = $Question
    $script:wizardHint     = $Hint
    $script:wizardValue    = ""

    $ids = @($Options | ForEach-Object { [string]$_.Id })
    $default = [array]::IndexOf($ids, [string]$State[$Key])
    if ($default -lt 0) { $default = 0 }

    $items = @()
    foreach ($option in $Options) { $items += $option }
    $items += [pscustomobject]@{ Id = "back";   Label = "Back" }
    $items += [pscustomobject]@{ Id = "cancel"; Label = "Cancel" }

    $choice = Show-Menu -Title $Title -Subtitle "Step $StepNumber of $StepTotal" -Items $items `
        -SelectedIndex $default -PreItems $script:wizardPreamble `
        -StatusLines (Get-WizardStatus -State $State)

    if ($null -eq $choice) { return "cancel" }
    if ($choice -eq "cancel") { return "cancel" }
    if ($choice -eq "back") { return "back" }

    if ($AsInt) { $State[$Key] = [int]$choice } else { $State[$Key] = [string]$choice }
    return "next"
}

$script:wizardReviewPreamble = {
    Write-SummarySection -Title "Certificate" -First
    foreach ($row in $script:wizardReviewRows) {
        Write-Studio -Text ("    {0,-14}" -f $row.Label) -Key 'muted' -NoNewline
        Write-Studio -Text ([string]$row.Value) -Key 'fg'
    }
    Write-SummarySection -Title "Files"
    Write-Studio -Text ("    " + $script:wizardReviewFolder) -Key 'accentHover'
    foreach ($line in $script:wizardReviewFiles) {
        Write-Studio -Text ("      " + $line) -Key 'fg'
    }
    Write-Host ""
}

function Invoke-WizardReviewStep {
    param(
        [Parameter(Mandatory)][hashtable]$State,
        [int]$StepNumber = 1,
        [int]$StepTotal = 1
    )

    $baseName = Get-WizardBaseName -State $State
    # Split by kind, same as the bulk screen. The common name is always a DNS entry.
    $dns = @([string]$State.CommonName)
    $ip = @()
    foreach ($entry in (Get-WizardNameList -State $State)) {
        if ($entry.Type -eq 'IP') { $ip += $entry.Value } else { $dns += $entry.Value }
    }
    $dns = @($dns | Select-Object -Unique)
    $ip = @($ip | Select-Object -Unique)

    $script:wizardReviewRows = @(
        [pscustomobject]@{ Label = "Subject";   Value = [string]$State.CommonName }
        [pscustomobject]@{ Label = "DNS names"; Value = ($dns -join ", ") }
    )
    if ($ip.Count -gt 0) {
        $script:wizardReviewRows += [pscustomobject]@{ Label = "IP addresses"; Value = ($ip -join ", ") }
    }
    $script:wizardReviewRows += @(
        [pscustomobject]@{ Label = "Template"; Value = [string]$State.Template }
        [pscustomobject]@{ Label = "Key";      Value = "RSA $($State.Length) bit" }
        [pscustomobject]@{ Label = "Asks as";  Value = (Get-RequestingIdentity).Shown }
        [pscustomobject]@{ Label = "Key store"; Value = "LocalMachine\My" }
        [pscustomobject]@{ Label = "Store";    Value = "removed once every file is written" }
    )

    $script:wizardReviewFolder = [System.IO.Path]::Combine([string]$State.Folder, $baseName)
    # The column is measured, not guessed. A fixed width fits a short name and breaks on
    # fullchain.pem under a long name, and a ragged second column is unreadable.
    $names = @()
    foreach ($entry in $script:outputFileCatalog) {
        $name = $baseName + $entry.Extension
        if ($entry.Id -eq 'password') { $name = $script:passwordFileName }
        $names += $name
    }
    $width = 0
    foreach ($name in $names) { if ($name.Length -gt $width) { $width = $name.Length } }

    $script:wizardReviewFiles = @()
    for ($i = 0; $i -lt $names.Count; $i++) {
        $script:wizardReviewFiles += ($names[$i].PadRight($width + 2) + $script:outputFileCatalog[$i].Detail)
    }

    $items = @(
        [pscustomobject]@{ Id = "request"; Label = "Request the certificate"; Detail = "asks the certification authority and writes the folder above" }
        [pscustomobject]@{ Id = "back";    Label = "Back" }
        [pscustomobject]@{ Id = "cancel";  Label = "Cancel - change nothing" }
    )

    $choice = Show-Menu -Title "Review" -Subtitle "Step $StepNumber of $StepTotal" -Items $items `
        -SelectedIndex 0 -PreItems $script:wizardReviewPreamble `
        -StatusLines (Get-WizardStatus -State $State)

    if ($null -eq $choice) { return "cancel" }
    return $choice
}

function Show-RequestWizard {
    param([Parameter(Mandatory)][hashtable]$State)

    # Four questions and a review. Every screen that used to sit between them asked
    # something with one right answer - which identity asks, where the files go, what
    # they are called, which of them to write, what the PKCS#12 password is, what happens
    # to the store copy - and a screen in front of a foregone answer is not a choice,
    # it is a keystroke. They are all decided in Invoke-WebServicesCertificateRequest
    # now, where the reasoning sits next to the code that acts on it.
    $steps = @("commonName", "names", "template", "length", "review")

    # 'issued', 'failed' or 'cancelled'. Not a boolean: a run that asked and was refused
    # is a different answer from one that never asked, and the exit code has to tell
    # them apart.
    $stepIndex = 0

    while ($true) {
        if ($stepIndex -lt 0) { $stepIndex = 0 }
        if ($stepIndex -ge $steps.Count) { $stepIndex = $steps.Count - 1 }
        $step = $steps[$stepIndex]
        $number = $stepIndex + 1
        $total = $steps.Count

        $result = "next"
        switch ($step) {
            "commonName" {
                $result = Invoke-WizardTextStep -State $State -Key "CommonName" -Title "Common name" `
                    -Question "What name is this certificate for?" `
                    -Hint "The name a browser will be asked to match, such as portal.ad.lab.invalid" `
                    -StepNumber $number -StepTotal $total -Required
            }
            "names" { $result = Invoke-WizardNameStep -State $State -StepNumber $number -StepTotal $total }
            "template" {
                $result = Invoke-WizardTextStep -State $State -Key "Template" -Title "Template" `
                    -Question "Which certificate template?" `
                    -Hint "The common name of the template object - WebServices, not 'Web Services'" `
                    -StepNumber $number -StepTotal $total -Required
            }
            "length" {
                $result = Invoke-WizardChoiceStep -State $State -Key "Length" -Title "Key size" `
                    -Question "How large should the RSA key be?" -AsInt `
                    -Options @(
                        [pscustomobject]@{ Id = "2048"; Label = "2048 bit"; Detail = "the template's floor, and what every client accepts" }
                        [pscustomobject]@{ Id = "3072"; Label = "3072 bit"; Detail = "the CA/Browser Forum's current floor for new issuance" }
                        [pscustomobject]@{ Id = "4096"; Label = "4096 bit"; Detail = "slower handshakes, no practical gain over 3072 today" }
                    ) -StepNumber $number -StepTotal $total
            }
            "review" {
                $result = Invoke-WizardReviewStep -State $State -StepNumber $number -StepTotal $total
                if ($result -eq "request") {
                    Clear-Host
                    Write-Host ""
                    $issued = Invoke-WebServicesCertificateRequest `
                        -CommonName ([string]$State.CommonName) `
                        -AlternativeName (Get-WizardNameList -State $State) `
                        -Template ([string]$State.Template) `
                        -Length ([int]$State.Length) `
                        -MachineOrUser ([string]$State.Context) `
                        -ParentFolder ([string]$State.Folder)
                    # The wizard ENDS here, whether the CA issued or refused. Going
                    # back to a review screen that still says "Request the certificate"
                    # invites a second request nobody wanted - and on success the second
                    # one would overwrite the folder the first just wrote, key and all.
                    #
                    # And it ends WITHOUT a pause. The script is started from a prompt
                    # that is still there afterwards, so nothing needs holding open - a
                    # "press Enter" only costs a keystroke and splits the run log from
                    # the runtime and exit lines that close it.
                    if ($issued) { return "issued" }
                    return "failed"
                }
            }
        }

        if ($result -eq "cancel") { return "cancelled" }
        if ($result -eq "back")   { $stepIndex-- ; continue }
        if ($stepIndex -eq ($steps.Count - 1)) { return "cancelled" }
        $stepIndex++
    }
}


# ===========================[ Bulk ]===========================
# A file of certificates instead of a wizard. It is found rather than asked for: a
# certificates.json beside the script, or beside wherever it was started from, means
# somebody has already answered every question and the only screen worth showing is
# the one that says what is about to happen.
#
# The shape, with the top level acting as defaults that an entry may override:
#
#   {
#     "template": "WebServices",
#     "keyLength": 2048,
#     "outputFolder": "C:\\certs",   (optional - the script's own folder otherwise)
#     "certificates": [
#       { "commonName": "fw-01.ad.lab.invalid",
#         "dnsNames": [ "fw-01", "fw.ad.lab.invalid" ],
#         "ipAddresses": [ "10.11.12.13", "10.11.12.14" ] },
#       { "commonName": "portal.ad.lab.invalid", "keyLength": 3072 }
#     ]
#   }
#
# A bare array of those entries is accepted too, for a file somebody hand-wrote.
$script:bulkFileName = 'certificates.json'

# A property that may not be there at all. ConvertFrom-Json gives back a PSCustomObject
# whose missing members throw under Set-StrictMode rather than returning $null, and a
# config file is exactly where a missing member is normal.
function Get-JsonValue {
    param(
        [object]$InputObject,
        [Parameter(Mandatory)][string]$Name,
        [object]$Default = $null
    )

    if ($null -eq $InputObject) { return $Default }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    if ($null -eq $property.Value) { return $Default }
    return $property.Value
}

# A list of names out of whatever shape the file used. A JSON array is the documented
# form, but a single string holding several names is what everybody writes first - and
# left alone that becomes ONE subject alternative name with commas inside it, which is
# a name nothing will ever match and nothing will ever complain about. Split on both
# separators people reach for. An IPv6 address is safe: it is built from colons.
function ConvertTo-NameList {
    param([object]$Value)

    if ($null -eq $Value) { return @() }
    $names = @()
    foreach ($item in @($Value)) {
        $text = ([string]$item).Trim()
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        foreach ($part in ($text -split '[;,]')) {
            $trimmed = $part.Trim()
            if (-not [string]::IsNullOrWhiteSpace($trimmed)) { $names += $trimmed }
        }
    }
    return $names
}

function Get-BulkFilePath {
    param([string]$Explicit = "")

    if (-not [string]::IsNullOrWhiteSpace($Explicit)) {
        if (Test-Path -LiteralPath $Explicit) { return (Resolve-Path -LiteralPath $Explicit).Path }
        Write-Log "No file at '$Explicit'" -Tag 'Error'
        return ""
    }

    # Beside the script first, then beside wherever it was started from. The two are
    # usually the same folder and are not when somebody dot-sources from elsewhere.
    foreach ($folder in @($PSScriptRoot, (Get-Location).Path)) {
        if ([string]::IsNullOrWhiteSpace($folder)) { continue }
        $candidate = [System.IO.Path]::Combine($folder, $script:bulkFileName)
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    return ""
}

# Parsed, validated, and turned into the same shape the wizard produces. Problems are
# collected rather than thrown one at a time: somebody editing a file of twenty
# certificates wants every complaint at once, not twenty runs.
function Read-BulkPlan {
    param([Parameter(Mandatory)][string]$Path)

    $problems = New-Object System.Collections.Generic.List[string]
    $items = New-Object System.Collections.Generic.List[object]

    $document = $null
    try { $document = (Get-Content -LiteralPath $Path -Raw -ErrorAction Stop) | ConvertFrom-Json -ErrorAction Stop }
    catch {
        $problems.Add("The file is not valid JSON: $($_.Exception.Message)")
        return [pscustomobject]@{ Path = $Path; Items = @(); Problems = @($problems) }
    }

    # A bare array is the list; an object carries the list under 'certificates'.
    $rows = $null
    if ($document -is [System.Array]) { $rows = @($document); $document = $null }
    else { $rows = @(Get-JsonValue -InputObject $document -Name 'certificates' -Default @()) }

    if ($rows.Count -eq 0) {
        $problems.Add("No certificates in it - expected a 'certificates' array, or an array at the top level")
        return [pscustomobject]@{ Path = $Path; Items = @(); Problems = @($problems) }
    }

    # The shared defaults are checked ONCE. An empty top-level template is one mistake,
    # and reporting it against every certificate in the file buries the others under
    # twenty copies of the same line.
    $defaultTemplate = ([string](Get-JsonValue -InputObject $document -Name 'template' -Default 'WebServices')).Trim()
    $defaultLength   = [int](Get-JsonValue -InputObject $document -Name 'keyLength' -Default 2048)
    $folderFallback = $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($folderFallback)) { $folderFallback = (Get-Location).Path }
    $defaultFolder   = ([string](Get-JsonValue -InputObject $document -Name 'outputFolder' -Default $folderFallback)).Trim()

    if ([string]::IsNullOrWhiteSpace($defaultTemplate)) {
        $problems.Add("The top-level template is empty - set it, or give every certificate its own")
    }
    if (@(2048, 3072, 4096) -notcontains $defaultLength) {
        $problems.Add("The top-level keyLength is $defaultLength - it has to be 2048, 3072 or 4096")
    }
    if ([string]::IsNullOrWhiteSpace($defaultFolder)) {
        $problems.Add("The top-level outputFolder is empty - set it, or give every certificate its own")
    }

    $seen = @{}
    $index = 0
    foreach ($row in $rows) {
        $index++

        # Every complaint about one certificate at once. Bailing on the first meant a
        # file with a typo in the name AND a bad key size took two runs to fix.
        $faults = New-Object System.Collections.Generic.List[string]

        $commonName = ([string](Get-JsonValue -InputObject $row -Name 'commonName' -Default "")).Trim()
        $label = "certificate $index"
        if ([string]::IsNullOrWhiteSpace($commonName)) { $faults.Add("$label has no commonName") }
        else { $label = "'$commonName'" }

        # Two entries with the same name would land in the same folder and the second
        # would overwrite the first - including its private key, which by then is the
        # only copy. Caught here rather than discovered afterwards.
        if (-not [string]::IsNullOrWhiteSpace($commonName)) {
            $key = $commonName.ToLowerInvariant()
            if ($seen.ContainsKey($key)) {
                $faults.Add("$label appears twice - the second would overwrite the first folder, key and all")
            }
            $seen[$key] = $true
        }

        # Only complain per certificate when the certificate itself is at fault. An empty
        # top-level default is already one line above; repeating it against all twenty
        # entries is how the line that matters gets lost.
        $ownTemplate = ([string](Get-JsonValue -InputObject $row -Name 'template' -Default "")).Trim()
        $template = $ownTemplate
        if ([string]::IsNullOrWhiteSpace($template)) { $template = $defaultTemplate }
        if ([string]::IsNullOrWhiteSpace($template) -and (-not [string]::IsNullOrWhiteSpace($ownTemplate))) {
            $faults.Add("$label has an empty template")
        }

        $length = [int](Get-JsonValue -InputObject $row -Name 'keyLength' -Default $defaultLength)
        if (@(2048, 3072, 4096) -notcontains $length) {
            $faults.Add("$label has keyLength $length - it has to be 2048, 3072 or 4096")
        }

        $ownFolder = ([string](Get-JsonValue -InputObject $row -Name 'outputFolder' -Default "")).Trim()
        $folder = $ownFolder
        if ([string]::IsNullOrWhiteSpace($folder)) { $folder = $defaultFolder }
        if ([string]::IsNullOrWhiteSpace($folder) -and (-not [string]::IsNullOrWhiteSpace($ownFolder))) {
            $faults.Add("$label has an empty outputFolder")
        }

        $entries = @()
        foreach ($name in (ConvertTo-NameList -Value (Get-JsonValue -InputObject $row -Name 'dnsNames' -Default @()))) {
            $text = ([string]$name).Trim()
            if ([string]::IsNullOrWhiteSpace($text)) { continue }
            if ((Get-SanTypeGuess -Value $text) -eq 'IP') {
                $faults.Add("$label lists '$text' under dnsNames and it is an IP address - move it to ipAddresses or it goes in as text nothing matches")
                continue
            }
            $entries += [pscustomobject]@{ Type = 'DNS'; Value = $text }
        }
        foreach ($address in (ConvertTo-NameList -Value (Get-JsonValue -InputObject $row -Name 'ipAddresses' -Default @()))) {
            $text = ([string]$address).Trim()
            if ([string]::IsNullOrWhiteSpace($text)) { continue }
            $parsed = $null
            $looksNumeric = ($text -match '\.') -or ($text -match ':')
            if ((-not $looksNumeric) -or (-not [System.Net.IPAddress]::TryParse($text, [ref]$parsed))) {
                $faults.Add("$label lists '$text' under ipAddresses and it is not an IP address")
                continue
            }
            $entries += [pscustomobject]@{ Type = 'IP'; Value = $parsed.ToString() }
        }

        # Faults first. The silent skip below has to come AFTER them, or an entry that
        # is missing a shared default takes its own real faults down with it and the
        # operator fixes the file twice.
        if ($faults.Count -gt 0) {
            foreach ($fault in $faults.ToArray()) { $problems.Add($fault) }
            continue
        }

        if ([string]::IsNullOrWhiteSpace($template) -or [string]::IsNullOrWhiteSpace($folder)) {
            # Nothing to add - the top-level problem above already says why - but the
            # entry cannot be built, so it must not reach the plan.
            continue
        }

        $baseName = ($commonName -replace '[^A-Za-z0-9._-]', '_')
        $items.Add([pscustomobject]@{
            CommonName   = $commonName
            Entries      = $entries
            Template     = $template
            Length       = $length
            ParentFolder = $folder
            Folder       = [System.IO.Path]::Combine($folder, $baseName)
        })
    }

    # ToArray(), not @(...). The array subexpression over a generic List whose members
    # are PSCustomObjects throws "Argument types do not match" on PowerShell 7.6.5 -
    # reproduced on this machine, and it takes the whole bulk read down with it. The
    # list's own ToArray is unambiguous and works on 5.1 and 7 alike.
    return [pscustomobject]@{ Path = $Path; Items = $items.ToArray(); Problems = $problems.ToArray() }
}

$script:bulkReviewPreamble = {
    Write-SummarySection -Title "From $($script:bulkPlanName)" -First
    Write-Studio -Text ("    " + $script:bulkPlanPath) -Key 'muted'
    Write-Host ""
    foreach ($row in $script:bulkReviewRows) {
        Write-Studio -Text ("    " + $row.Name) -Key 'accentHover'
        Write-Studio -Text "      DNS  " -Key 'bandHost' -NoNewline
        Write-Studio -Text $row.Dns -Key 'fg'
        if (-not [string]::IsNullOrWhiteSpace($row.Ip)) {
            Write-Studio -Text "      IP   " -Key 'bandHost' -NoNewline
            Write-Studio -Text $row.Ip -Key 'fg'
        }
        Write-Studio -Text ("      " + $row.Settings) -Key 'muted'
        Write-Studio -Text ("      " + $row.Folder) -Key 'muted'
        Write-Host ""
    }
}

$script:bulkProblemPreamble = {
    Write-SummarySection -Title "This file cannot be used yet" -First
    Write-Studio -Text ("    " + $script:bulkPlanPath) -Key 'muted'
    Write-Host ""
    foreach ($problem in $script:bulkProblems) {
        Write-Studio -Text ("    " + $problem) -Key 'danger'
    }
    Write-Host ""
}

function Show-BulkReview {
    param([Parameter(Mandatory)][object]$Plan)

    $script:bulkPlanPath = $Plan.Path
    $script:bulkPlanName = Split-Path -Path $Plan.Path -Leaf

    if ($Plan.Problems.Count -gt 0) {
        $script:bulkProblems = $Plan.Problems
        $items = @(
            [pscustomobject]@{ Id = "wizard"; Label = "Open the wizard instead"; Detail = "request one certificate by hand and leave the file alone" }
            [pscustomobject]@{ Id = "cancel"; Label = "Cancel - change nothing" }
        )
        $choice = Show-Menu -Title "Bulk request" -Subtitle "$($Plan.Problems.Count) problem(s) in the file" `
            -Items $items -SelectedIndex 0 -PreItems $script:bulkProblemPreamble `
            -StatusLines @{ file = $script:bulkPlanName; certificates = "$($Plan.Items.Count) usable" }
        if ($null -eq $choice) { return "cancel" }
        return $choice
    }

    # One line per KIND of name, the way the wizard's own list reads. A single line
    # holding "DNS a, DNS b, IP c" makes the reader parse the types out of a sentence;
    # two lines with the type in front of each let the eye find the addresses at once.
    $script:bulkReviewRows = @()
    foreach ($item in $Plan.Items) {
        $dns = @($item.CommonName)
        $ip = @()
        foreach ($entry in $item.Entries) {
            if ($entry.Type -eq 'IP') { $ip += $entry.Value } else { $dns += $entry.Value }
        }
        $script:bulkReviewRows += [pscustomobject]@{
            Name     = $item.CommonName
            Dns      = (@($dns | Select-Object -Unique) -join ", ")
            Ip       = (@($ip | Select-Object -Unique) -join ", ")
            Settings = "$($item.Template), RSA $($item.Length) bit"
            Folder   = $item.Folder
        }
    }

    $items = @(
        [pscustomobject]@{ Id = "request"; Label = "Request all $($Plan.Items.Count) of them"
                           Detail = "each one asks the certification authority and writes its own folder" }
        [pscustomobject]@{ Id = "wizard";  Label = "Open the wizard instead"
                           Detail = "ignore the file and request one certificate by hand" }
        [pscustomobject]@{ Id = "cancel";  Label = "Cancel - change nothing" }
    )
    $choice = Show-Menu -Title "Bulk request" -Subtitle "$($Plan.Items.Count) certificate(s) from $($script:bulkPlanName)" `
        -Items $items -SelectedIndex 0 -PreItems $script:bulkReviewPreamble `
        -StatusLines @{ file = $script:bulkPlanName; certificates = "$($Plan.Items.Count)" }
    if ($null -eq $choice) { return "cancel" }
    return $choice
}

# One failure does not stop the rest. A batch of twelve where the fourth is refused
# should still produce eleven folders and one clear line about the one that is missing.
function Invoke-BulkPlan {
    param([Parameter(Mandatory)][object]$Plan)

    $issued = 0
    $failed = @()
    foreach ($item in $Plan.Items) {
        Write-Host ""
        $ok = Invoke-WebServicesCertificateRequest `
            -CommonName $item.CommonName `
            -AlternativeName $item.Entries `
            -Template $item.Template `
            -Length $item.Length `
            -MachineOrUser 'Machine' `
            -ParentFolder $item.ParentFolder
        if ($ok) { $issued++ } else { $failed += $item.CommonName }
    }

    Write-Host ""
    Write-Log "$issued of $($Plan.Items.Count) certificate(s) issued" -Tag 'Info'
    if ($failed.Count -gt 0) {
        Write-Log "Not issued: $($failed -join ', ')" -Tag 'Error'
    }
    return ($failed.Count -eq 0)
}

# =================================================================================
Write-Log '==================== Start ====================' -Tag 'Start'

# Beside the script, not beside whatever directory the shell happens to be in. The
# script is what gets copied to a server, and a run that drops nine files into
# C:\Windows\System32 because that is where the prompt opened is a support call.
if ([string]::IsNullOrWhiteSpace($OutputFolder)) { $OutputFolder = $PSScriptRoot }
if ([string]::IsNullOrWhiteSpace($OutputFolder)) { $OutputFolder = (Get-Location).Path }

# A file beats the wizard, and beats it silently: if somebody has written down what they
# want there is nothing left to ask. -NoBulk and an explicit -CommonName both mean the
# operator is asking for one certificate by hand, so neither goes looking for a file.
$bulkPath = ""
if ((-not $NoBulk) -and ([string]::IsNullOrWhiteSpace($CommonName) -or (-not [string]::IsNullOrWhiteSpace($BulkFile)))) {
    $bulkPath = Get-BulkFilePath -Explicit $BulkFile
}

if (-not [string]::IsNullOrWhiteSpace($bulkPath)) {
    Write-Log "Found $bulkPath" -Tag 'Info'
    $plan = Read-BulkPlan -Path $bulkPath

    if ($NoGui) {
        foreach ($problem in $plan.Problems) { Write-Log "    $problem" -Tag 'Error' }
        if ($plan.Problems.Count -gt 0) { Complete-Script -ExitCode 1 }
        $allOk = Invoke-BulkPlan -Plan $plan
        if (-not $allOk) { Complete-Script -ExitCode 1 }
        Complete-Script -ExitCode 0
    }

    $decision = Show-BulkReview -Plan $plan
    foreach ($problem in $plan.Problems) { Write-Log "    $problem" -Tag 'Error' }

    if ($decision -eq "cancel") {
        Write-Log 'Nothing was requested' -Tag 'Info'
        Complete-Script -ExitCode 0
    }
    if ($decision -eq "request") {
        Clear-Host
        $allOk = Invoke-BulkPlan -Plan $plan
        if (-not $allOk) { Complete-Script -ExitCode 1 }
        Complete-Script -ExitCode 0
    }
    # "Open the wizard instead" falls through to it.
}

if ($NoGui) {
    if ([string]::IsNullOrWhiteSpace($CommonName)) {
        Write-Log '-NoGui needs -CommonName' -Tag 'Error'
        Complete-Script -ExitCode 1
    }
    $ok = Invoke-WebServicesCertificateRequest `
        -CommonName $CommonName `
        -AlternativeName (ConvertTo-NameList -Value $SubjectAlternativeName) `
        -Template $TemplateName `
        -Length $KeyLength `
        -MachineOrUser $Context `
        -ParentFolder $OutputFolder
    if (-not $ok) { Complete-Script -ExitCode 1 }
    Complete-Script -ExitCode 0
}

$outcome = Show-RequestWizard -State @{
    CommonName = [string]$CommonName
    # Through ConvertTo-NameList first, exactly as the bulk file goes. -File mode does
    # not split an array argument, so -SubjectAlternativeName a,b arrives as the single
    # string "a,b" and without this it became one name with a comma in it.
    SanEntries = @(ConvertTo-NameList -Value $SubjectAlternativeName | ForEach-Object { ConvertTo-SanEntry -InputObject $_ } | Where-Object { $_ })
    Template   = $TemplateName
    Length     = $KeyLength
    Context    = $Context
    Folder     = $OutputFolder
}

Write-Host ""
if ($outcome -eq 'failed') {
    Write-Log 'The certificate was not issued' -Tag 'Error'
    Complete-Script -ExitCode 1
}
if ($outcome -ne 'issued') { Write-Log 'Nothing was requested' -Tag 'Info' }
Complete-Script -ExitCode 0
