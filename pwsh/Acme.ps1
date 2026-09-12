# Certificates and ACME, shared by every role that holds one.
#
# Dot-sourced by Configure-ServerRoles.ps1 - not runnable on its own. Everything
# here lands in that script's scope, so $script: variables and functions are shared
# with every other part. Use $scriptRootPath, never $PSScriptRoot: inside this file
# $PSScriptRoot is the pwsh folder, not the folder the run was started from.
#
# This started inside the Windows Admin Center provider and moved here when the Remote
# Desktop deployment needed the same four things: a certificate from somewhere, a PFX
# imported without re-keying it, a private key the right service can read, and a nightly
# task that redoes all three before the certificate expires. Two copies of code that
# took a reboot cycle to get right would have drifted; a role provider that needs a
# certificate calls in here instead.
#
# Everything takes a `certificate` config object rather than a role's whole section, so
# nothing in this file knows which role asked.

# ===========================[ Certificates and ACME ]===========================

# ---------------------------[ Private key access ]---------------------------
# A certificate in LocalMachine\My is only half of it. The key material sits in a
# file whose ACL does not mention the gateway's service account, and a gateway that
# cannot read its own key fails to start with nothing useful in its log.
function Get-CertificateKeyPath {
    param([Parameter(Mandatory)][object]$Certificate)

    $candidates = @()

    try {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
        if (($null -ne $rsa) -and ($rsa -is [System.Security.Cryptography.RSACng])) {
            $candidates += [string]$rsa.Key.UniqueName
        }
    }
    catch {
        Write-Log "Could not read the CNG key name: $($_.Exception.Message)" -Tag "Debug"
    }

    if ($candidates.Count -eq 0) {
        try {
            $legacy = $Certificate.PrivateKey
            if (($null -ne $legacy) -and ($null -ne $legacy.CspKeyContainerInfo)) {
                $candidates += [string]$legacy.CspKeyContainerInfo.UniqueKeyContainerName
            }
        }
        catch {
            Write-Log "Could not read the CAPI key container name: $($_.Exception.Message)" -Tag "Debug"
        }
    }

    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }

        # CNG usually hands back a bare file name, CAPI a container name; both have
        # been seen as a full path, so an absolute one is taken as it stands.
        if ($candidate.Contains("\") -and (Test-Path -LiteralPath $candidate)) { return $candidate }

        $roots = @(
            (Join-Path -Path $env:ProgramData -ChildPath "Microsoft\Crypto\Keys"),
            (Join-Path -Path $env:ProgramData -ChildPath "Microsoft\Crypto\RSA\MachineKeys"),
            (Join-Path -Path $env:ProgramData -ChildPath "Microsoft\Crypto\SystemKeys")
        )
        foreach ($root in $roots) {
            $path = Join-Path -Path $root -ChildPath ([System.IO.Path]::GetFileName($candidate))
            if (Test-Path -LiteralPath $path) { return $path }
        }
    }

    return ""
}

# The certificate is read straight out of the store rather than through the Cert: drive.
# The provider caches, and a certificate that has just been re-imported can still hand back
# the *previous* key association - which is how an ACL lands on a key file nothing uses any
# more, while the run reports success.
function Get-StoreCertificate {
    param([Parameter(Mandatory)][string]$Thumbprint)

    $wanted = $Thumbprint.Replace(" ", "").ToUpperInvariant()
    $store  = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "LocalMachine")
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        foreach ($candidate in $store.Certificates) {
            if ($candidate.Thumbprint.ToUpperInvariant() -eq $wanted) { return $candidate }
        }
    }
    catch {
        Write-Log "Could not open LocalMachine\My: $($_.Exception.Message)" -Tag "Error"
    }
    finally {
        $store.Close()
    }
    return $null
}

# Compared by SID, never by name. "NT Authority\NetworkService" is what the service control
# manager reports, "NT AUTHORITY\NETWORK SERVICE" is what an ACE says, and on a localised
# Windows both are something else again - all three are S-1-5-20.
function Test-CertificateKeyRead {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Identity
    )

    $wanted = $null
    try {
        $account = New-Object System.Security.Principal.NTAccount($Identity)
        $wanted  = $account.Translate([System.Security.Principal.SecurityIdentifier])
    }
    catch {
        Write-Log "Could not resolve '$Identity' to a SID: $($_.Exception.Message)" -Tag "Debug"
        return $false
    }

    try {
        $acl = Get-Acl -Path $Path
    }
    catch {
        return $false
    }

    # The rights the OPEN demands, not "any read bit". NCrypt opens the key file with
    # GENERIC_READ, which the file system maps to FILE_GENERIC_READ - the whole Read
    # composite PLUS Synchronize. An ACE holding Read alone passes an any-bit check and
    # still fails that open, so the service dies on its key at startup while the check
    # keeps saying the grant is already there. certlm's own dialog hands out
    # FILE_GENERIC_READ, which is why fixing it by hand always worked.
    $needed = [System.Security.AccessControl.FileSystemRights]"Read, Synchronize"

    $held = [System.Security.AccessControl.FileSystemRights]0
    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }

        $sid = $null
        try {
            if ($ace.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
                $sid = [System.Security.Principal.SecurityIdentifier]$ace.IdentityReference
            }
            else {
                $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
            }
        }
        catch {
            continue
        }

        if ($sid -ne $wanted) { continue }
        $held = $held -bor $ace.FileSystemRights
    }

    return (($held -band $needed) -eq $needed)
}

function Grant-CertificateKeyRead {
    param(
        [Parameter(Mandatory)][string]$Thumbprint,
        [Parameter(Mandatory)][string]$Identity
    )

    if ([string]::IsNullOrWhiteSpace($Identity)) {
        Write-Log "The gateway service account is unknown - grant read on the private key by hand" -Tag "Error"
        return $false
    }
    if ($Identity -match "^(LocalSystem|NT AUTHORITY\\SYSTEM)$") {
        Write-Log "The gateway runs as SYSTEM, which can already read the key - nothing to grant" -Tag "Info"
        return $true
    }

    $certificate = Get-StoreCertificate -Thumbprint $Thumbprint
    if ($null -eq $certificate) {
        Write-Log "Certificate $Thumbprint is not in LocalMachine\My" -Tag "Error"
        return $false
    }

    $keyPath = Get-CertificateKeyPath -Certificate $certificate
    if ([string]::IsNullOrWhiteSpace($keyPath)) {
        Write-Log "Could not locate the private key file for $Thumbprint - grant read to '$Identity' by hand" -Tag "Error"
        return $false
    }

    if (Test-CertificateKeyRead -Path $keyPath -Identity $Identity) {
        Write-Log "'$Identity' can already read the private key" -Tag "Debug"
        return $true
    }

    try {
        $acl  = Get-Acl -Path $keyPath
        # Read AND Synchronize - what FILE_GENERIC_READ actually is. See the comment on
        # Test-CertificateKeyRead: a Read-only ACE fails the GENERIC_READ open NCrypt does.
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($Identity, "Read, Synchronize", "Allow")
        $acl.AddAccessRule($rule)
        Set-Acl -Path $keyPath -AclObject $acl -ErrorAction Stop
    }
    catch {
        Write-Log "Could not grant '$Identity' read on '$keyPath': $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    # Read it back. Set-Acl reports success for a write the file system then does not show,
    # and this particular lie is invisible until the next reboot: the service keeps the key
    # handle it already holds, so the gateway works all day and is unreachable in the
    # morning with nothing but "0x8009030D" in the System log to say why.
    if (-not (Test-CertificateKeyRead -Path $keyPath -Identity $Identity)) {
        Write-Log "The grant on '$keyPath' did not take - '$Identity' still cannot read the key" -Tag "Error"
        Write-Log "The gateway will serve TLS until it next restarts, then fail with 0x8009030D" -Tag "Error"
        return $false
    }

    Write-Log "Granted '$Identity' read on '$keyPath'" -Tag "Ok"
    return $true
}

# ---------------------------[ What is actually served ]---------------------------
# The one check that is not inference. A certificate in the store, an ACL that took, a
# cmdlet that returned without an error and an http.sys binding are four things that are
# all true on a server presenting the wrong certificate - and on a modern Windows Admin
# Center gateway three of them are not even the mechanism: it serves TLS from its own
# process (Kestrel) and picks its certificate out of LocalMachine\My by *subject name*,
# so "netsh http show sslcert" is empty on a perfectly healthy machine. Opening a TLS
# connection and reading what comes back answers the question directly, for any service,
# whichever way it is bound.
function Get-StudioServedCertificate {
    param(
        [Parameter(Mandatory)][int]$Port,
        [string]$Name = "",
        [string]$Address = "127.0.0.1",
        [int]$TimeoutSeconds = 10
    )

    # The name is the SNI value, not the address: a host serving several certificates
    # picks by it, so probing without one can be answered by the wrong one.
    if ([string]::IsNullOrWhiteSpace($Name)) { $Name = $Address }

    $client = $null
    $stream = $null
    $secure = $null

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $connect = $client.BeginConnect($Address, $Port, $null, $null)
        if (-not $connect.AsyncWaitHandle.WaitOne([timespan]::FromSeconds($TimeoutSeconds))) {
            Write-Log "Nothing accepted a connection on $Address port $Port within $TimeoutSeconds seconds" -Tag "Debug"
            return $null
        }
        $client.EndConnect($connect)

        # The handshake needs its own clock. AuthenticateAsClient has no timeout of its
        # own - a listener that accepts the connection and then never answers the
        # ClientHello holds it forever, and a gateway wedged on a certificate it cannot
        # validate does exactly that. The socket timeouts are what the synchronous
        # handshake reads actually honor.
        $client.ReceiveTimeout = $TimeoutSeconds * 1000
        $client.SendTimeout    = $TimeoutSeconds * 1000

        # Everything presented is accepted on purpose: the question is which certificate
        # the service serves, not whether this machine trusts it. A gateway still on its
        # own self-signed certificate has to be readable here, or the check can never say
        # so - which is the case it exists for.
        # No param block: the delegate is handed four arguments, none of which this cares
        # about, and naming them only to ignore them is a parameter that is never read.
        $accept = [System.Net.Security.RemoteCertificateValidationCallback] { return $true }

        $stream = $client.GetStream()
        $secure = New-Object System.Net.Security.SslStream($stream, $false, $accept)
        $secure.AuthenticateAsClient($Name, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)

        $remote = $secure.RemoteCertificate
        if ($null -eq $remote) { return $null }
        return (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($remote))
    }
    catch {
        Write-Log "No TLS answer from $Address port $Port as '$Name': $($_.Exception.Message)" -Tag "Debug"
        return $null
    }
    finally {
        if ($null -ne $secure)      { $secure.Dispose() }
        elseif ($null -ne $stream)  { $stream.Dispose() }
        if ($null -ne $client)      { $client.Close() }
    }
}

# Every address this machine holds, read straight out of .NET so it works the same on 5.1
# and 7 and needs no cmdlet that might not be there. Loopback is included on purpose: a
# name that resolves to 127.0.0.1 still reaches this server, which is the whole question.
function Get-StudioLocalAddress {
    $addresses = @()

    try {
        foreach ($adapter in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($adapter.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
            foreach ($unicast in $adapter.GetIPProperties().UnicastAddresses) {
                $addresses += [string]$unicast.Address.ToString()
            }
        }
    }
    catch {
        Write-Log "Could not read this machine's own addresses: $($_.Exception.Message)" -Tag "Debug"
    }

    return @($addresses | Select-Object -Unique)
}

# "Does it resolve" is the wrong question by half. A name that resolves to *somewhere else*
# - an old A record, a load balancer, a machine that used to hold it - is not a name this
# server can reach itself by, and treating it as one is how a gateway ends up unable to
# call its own service endpoints while every check says the name is fine. So the answer is
# three-valued: it resolves here, it resolves elsewhere, or it does not resolve at all.
function Test-StudioNameResolvesHere {
    param([Parameter(Mandatory)][string]$Name)

    $resolved = @()
    try {
        $resolved = @([System.Net.Dns]::GetHostAddresses($Name) | ForEach-Object { $_.ToString() })
    }
    catch {
        $resolved = @()
    }

    $matched = @()
    if ($resolved.Count -gt 0) {
        $local   = Get-StudioLocalAddress
        $matched = @($resolved | Where-Object { $local -contains $_ })
    }

    return [pscustomobject]@{
        Name     = $Name
        Resolved = $resolved
        Matched  = $matched
        Resolves = ($resolved.Count -gt 0)
        Here     = ($matched.Count -gt 0)
    }
}

function Get-StudioServedThumbprint {
    param(
        [Parameter(Mandatory)][int]$Port,
        [string]$Name = "",
        [string]$Address = "127.0.0.1"
    )

    $certificate = Get-StudioServedCertificate -Port $Port -Name $Name -Address $Address
    if ($null -eq $certificate) { return "" }
    return ([string]$certificate.Thumbprint).ToUpperInvariant()
}

# The name a certificate is reached by: the first SAN entry, falling back to the common
# name. Used for the SNI value of the probe above and for the gateway's own endpoint name.
function Get-StudioCertificatePrimaryName {
    param([Parameter(Mandatory)][string]$Thumbprint)

    $certificate = Get-StoreCertificate -Thumbprint $Thumbprint
    if ($null -eq $certificate) { return "" }

    $dnsNames = @($certificate.DnsNameList | ForEach-Object { [string]$_.Unicode } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($dnsNames.Count -gt 0) { return $dnsNames[0] }

    $cnMatch = [regex]::Match([string]$certificate.Subject, "(?i)CN=([^,]+)")
    if ($cnMatch.Success) { return $cnMatch.Groups[1].Value.Trim() }
    return ""
}

# A service that selects its certificate by subject name rather than by thumbprint has no
# way to tell this year's from last year's: a renewal puts a second certificate with the
# identical CN into LocalMachine\My, and which one gets picked is the store's enumeration
# order. Windows Admin Center v2 is one of those services - so is anything reading
# Kestrel's Certificate:Subject - and the failure is the quiet kind: the gateway restarts,
# comes back on the expired certificate, and the run that renewed it reports success.
#
# Only what this certificate supersedes is removed: same subject, an expiry no later than
# ours, and never the certificate we just installed. Anything with a longer life is
# somebody's deliberate arrangement and is left alone with a line saying so.
function Remove-StudioSupersededCertificate {
    param([Parameter(Mandatory)][string]$Thumbprint)

    $current = Get-StoreCertificate -Thumbprint $Thumbprint
    if ($null -eq $current) { return 0 }

    $wanted  = ([string]$current.Thumbprint).ToUpperInvariant()
    $subject = [string]$current.Subject
    if ([string]::IsNullOrWhiteSpace($subject)) { return 0 }

    $removed  = 0
    $store    = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "LocalMachine")
    $doomed   = @()
    $retained = @()

    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)

        foreach ($candidate in $store.Certificates) {
            if (([string]$candidate.Thumbprint).ToUpperInvariant() -eq $wanted) { continue }
            if (-not ([string]$candidate.Subject).Equals($subject, [System.StringComparison]::OrdinalIgnoreCase)) { continue }

            if ($candidate.NotAfter -gt $current.NotAfter) { $retained += $candidate; continue }
            $doomed += $candidate
        }

        foreach ($candidate in $retained) {
            Write-Log "$($candidate.Thumbprint) shares the subject '$subject' and outlives the new one - left in the store, the service may pick either" -Tag "Warn"
        }

        foreach ($candidate in $doomed) {
            try {
                Write-Log "Removing superseded $($candidate.Thumbprint) - '$subject', expires $($candidate.NotAfter.ToString('yyyy-MM-dd'))" -Tag "Run"
                $store.Remove($candidate)
                $removed = $removed + 1
            }
            catch {
                Write-Log "Could not remove $($candidate.Thumbprint): $($_.Exception.Message)" -Tag "Warn"
            }
        }
    }
    catch {
        Write-Log "Could not tidy LocalMachine\My: $($_.Exception.Message)" -Tag "Warn"
    }
    finally {
        $store.Close()
    }

    if ($removed -gt 0) {
        Write-Log "Removed $removed superseded certificate(s) for '$subject'" -Tag "Ok"
    }
    return $removed
}

# ---------------------------[ Certificate: internal CA ]---------------------------
# What a failed enrollment actually means, by HRESULT. Every one of these has cost a
# field afternoon, and each one arrives as the same shape of sentence - CertEnroll
# quoting a chain or a template, never an identity and never an action.
function Write-InternalCaEnrollmentDiagnosis {
    param(
        [Parameter(Mandatory)][string]$Message,
        [string]$Template = ""
    )

    # 0x800b0109 - the chain ends in a root this machine does not trust. On a two-tier
    # PKI built by this toolbox the root certificate is published into the forest by the
    # CA run; a member server picks it up through Group Policy, and one that has not
    # refreshed since the PKI was built has an empty Trusted Root store to enroll with.
    if ($Message -match '0x800b0109|CERT_E_UNTRUSTEDROOT|terminated in a root certificate which is not trusted') {
        Write-Log "This machine does not trust the CA's root - the chain, not the template, is what failed" -Tag "Error"
        Write-Log "    The CA run publishes the root into the forest; this machine has to pick it up:" -Tag "Error"
        Write-Log "        gpupdate /force   then   certutil -pulse" -Tag "Error"
        Write-Log "    What it currently trusts from the directory:  certutil -store -enterprise Root" -Tag "Error"
        Write-Log "    A machine still empty after a refresh never had the root published for it:  certutil -dspublish -f <root>.crt RootCA  on a DC" -Tag "Error"
        return
    }

    # 0x80094012 - rights. The enrollee is this machine's computer account, because the
    # run and every task it registers act as SYSTEM. The administrator who tested the
    # template by hand is a different identity, and a group added to a running machine is
    # not in its token until the machine reboots.
    if ($Message -match '0x80094012|CERTSRV_E_TEMPLATE_DENIED|permissions on the certificate template') {
        $name = $env:COMPUTERNAME
        Write-Log "The template refused this enrollee - rights, not trust" -Tag "Error"
        Write-Log "    The enrollee is this machine's computer account ('$name`$'), not the account that started this run" -Tag "Error"
        Write-Log "    Put '$name`$' into the enrollment group of '$Template', then REBOOT - a membership added to a running machine is not in its token" -Tag "Error"
        return
    }

    # 0x80094800 - the object exists in the forest and the CA does not issue it, which is
    # the withdraw sweep's signature.
    if ($Message -match '0x80094800|CERTSRV_E_UNSUPPORTED_CERT_TYPE|not supported by this certification authority') {
        Write-Log "No certification authority in this forest publishes '$Template'" -Tag "Error"
        Write-Log "    Publication is per CA and reversible:  certutil -SetCATemplates +$Template   on the issuing CA" -Tag "Error"
        return
    }
}

# Enrolls against the PKI this toolbox builds. The machine account needs the
# template's Enroll right, which is what the studio's enrollment mapping grants.
function New-InternalCaCertificate {
    param([Parameter(Mandatory)][object]$Certificate)

    if (-not (Get-Command -Name "Get-Certificate" -ErrorAction SilentlyContinue)) {
        throw "The PKI client module is unavailable, so this server cannot enroll on its own."
    }

    $internal = Get-ConfigValue -InputObject $Certificate -Name "internalCa"
    $template = [string](Get-ConfigValue -InputObject $internal -Name "templateName" -Default "")
    if ([string]::IsNullOrWhiteSpace($template)) {
        throw "certificate.internalCa.templateName is empty."
    }

    $dnsNames = @(Get-CertificateNameList -Certificate $Certificate)
    $subject  = "CN=" + $dnsNames[0]

    Write-Log "Enrolling for '$subject' from template '$template'" -Tag "Run"
    try {
        $request = Get-Certificate -Template $template -SubjectName $subject -DnsName $dnsNames `
            -CertStoreLocation "Cert:\LocalMachine\My" -ErrorAction Stop
    }
    catch {
        # The three that account for nearly every failed enrollment in this project, and
        # all three arrive as one long CertEnroll sentence whose HRESULT is the only part
        # that says which. The message names a template or a chain and never the thing to
        # go and do, so the run says it here.
        Write-InternalCaEnrollmentDiagnosis -Message ([string]$_.Exception.Message) -Template $template
        throw
    }

    # A template that holds requests for a certificate manager comes back pending,
    # which is a state to report rather than an error to throw.
    if ([string]$request.Status -eq "Pending") {
        Write-Log "The request is pending a certificate manager's approval - re-run once it is issued" -Tag "Info"
        return ""
    }
    if ($null -eq $request.Certificate) {
        throw "Enrollment returned no certificate (status $($request.Status))."
    }

    Write-Log "Enrolled $($request.Certificate.Thumbprint)" -Tag "Ok"
    return [string]$request.Certificate.Thumbprint
}

# ---------------------------[ Certificate: ACME ]---------------------------
# "PowerShell Gallery is currently unavailable. Please try again later." is the one
# message PackageManagement gives for half a dozen unrelated causes, and almost never
# means the gallery is down - the tell is that the same Install-Module typed by hand a
# minute later works. So this readies every part of the path explicitly and says which
# one it fixed, rather than calling Install-Module and hoping.
#
# The causes, in the order they bite on a fresh Windows Server:
#   - TLS. The gallery has been TLS 1.2 only for years; 5.1 still offers 1.0 first.
#   - The NuGet provider is on disk but not *loaded*. Get-PackageProvider -ListAvailable
#     finds it either way, which is why the old check here passed and Install-Module
#     still failed: it then tries to bootstrap the provider itself, and a bootstrap that
#     cannot run surfaces as "gallery unavailable".
#   - PSGallery is not registered at all, or is registered against the old http source.
#   - PSGallery is untrusted, which prompts - and a prompt nobody answers is a hang on
#     an unattended run.
function Initialize-PackageSource {
    [System.Net.ServicePointManager]::SecurityProtocol =
        [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

    # PowerShellGet 1.0.0.1 is what ships in the box and is the single most common
    # reason for the message. Worth naming in the log, because the fix is a one-liner
    # somebody has to run once.
    $powerShellGet = @(Get-Module -ListAvailable -Name "PowerShellGet" | Sort-Object -Property Version -Descending)
    if ($powerShellGet.Count -gt 0) {
        Write-Log "PowerShellGet $($powerShellGet[0].Version), PackageManagement $((@(Get-Module -ListAvailable -Name 'PackageManagement' | Sort-Object -Property Version -Descending)[0]).Version)" -Tag "Debug"
        if ([version]$powerShellGet[0].Version -le [version]"1.0.0.1") {
            Write-Log "    PowerShellGet is the in-box 1.0.0.1 - the version that most often reports the gallery as unavailable when it is not" -Tag "Debug"
        }
    }

    # Installed when missing, and imported either way: on disk is not the same as
    # loaded, and only loaded counts.
    #
    # Every one of these takes -ForceBootstrap, and every one of them needs it. When the
    # provider assembly is absent PackageManagement asks "Would you like PackageManagement
    # to automatically download and install 'nuget' now?" and waits - and -Force does not
    # suppress that, it is a different switch for a different thing. On an unattended run
    # the answer never comes and the step hangs rather than fails. -Confirm:$false is
    # belt and braces for the same reason.
    #
    # Detection is -ListAvailable only, deliberately: a bare Get-PackageProvider -Name
    # for a provider that is not there triggers the same bootstrap prompt, so the check
    # for whether we need to install would itself be the thing that blocks.
    try {
        $provider = @(Get-PackageProvider -Name "NuGet" -ListAvailable -ErrorAction SilentlyContinue |
            Sort-Object -Property Version -Descending)
        if ($provider.Count -eq 0) {
            Write-Log "Installing the NuGet package provider" -Tag "Run"
            $null = Install-PackageProvider -Name "NuGet" -MinimumVersion "2.8.5.201" `
                -Force -ForceBootstrap -Scope AllUsers -Confirm:$false -ErrorAction Stop
            Write-Log "NuGet package provider installed" -Tag "Ok"
        }
        else {
            Write-Log "NuGet package provider $($provider[0].Version) is present" -Tag "Debug"
        }
        $null = Import-PackageProvider -Name "NuGet" -Force -ForceBootstrap -ErrorAction Stop
        Write-Log "NuGet package provider loaded" -Tag "Debug"
    }
    catch {
        Write-Log "The NuGet package provider could not be readied: $($_.Exception.Message)" -Tag "Warn"
    }

    try {
        $repository = Get-PSRepository -Name "PSGallery" -ErrorAction SilentlyContinue
        if ($null -eq $repository) {
            # Unregistered entirely - rare, but then nothing downstream can resolve a
            # module name and the message says the gallery is unavailable.
            Write-Log "PSGallery is not registered - registering the default" -Tag "Run"
            Register-PSRepository -Default -ErrorAction Stop
            $repository = Get-PSRepository -Name "PSGallery" -ErrorAction SilentlyContinue
        }
        if ($null -ne $repository) {
            $source = [string]$repository.SourceLocation
            if ($source -like "http://*") {
                # An old registration pointing at the http endpoint fails the TLS-only
                # gallery with the same unhelpful message.
                Write-Log "PSGallery is registered against '$source' - repointing it at https" -Tag "Run"
                Set-PSRepository -Name "PSGallery" -SourceLocation "https://www.powershellgallery.com/api/v2" -ErrorAction Stop
            }
            if ($repository.InstallationPolicy -ne "Trusted") {
                Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted -ErrorAction Stop
                Write-Log "PSGallery marked trusted - an untrusted repository prompts, and a prompt nobody answers is a hung run" -Tag "Debug"
            }
        }
    }
    catch {
        Write-Log "PSGallery could not be readied: $($_.Exception.Message)" -Tag "Warn"
    }
}

# What the log should say when the gallery genuinely cannot be reached, so the next
# person does not have to guess which of the six causes it was.
function Write-PackageSourceDiagnostic {
    try {
        foreach ($repository in @(Get-PSRepository -ErrorAction SilentlyContinue)) {
            Write-Log "    repository '$($repository.Name)' $($repository.InstallationPolicy) $($repository.SourceLocation)" -Tag "Info"
        }
    }
    catch {
        Write-Log "    no repository could be listed" -Tag "Info"
    }
    Write-Log "    TLS: $([System.Net.ServicePointManager]::SecurityProtocol)" -Tag "Info"
    Write-Log "    Install by hand, then re-run: Install-Module -Name Posh-ACME -Scope AllUsers -Force" -Tag "Info"
    Write-Log "    If that fails too, update the tooling first: Install-Module -Name PowerShellGet -Force -AllowClobber, then reopen the console" -Tag "Info"
}

function Install-PoshAcmeModule {
    $existing = @(Get-Module -ListAvailable -Name "Posh-ACME" | Sort-Object -Property Version -Descending)
    if ($existing.Count -gt 0) {
        Write-Log "Posh-ACME $($existing[0].Version) is installed" -Tag "Debug"
        return
    }

    Initialize-PackageSource

    # Its own retries, short ones: a 5xx from the gallery is transient and common, and
    # this used to sit inside the ACME retry loop - where a gallery hiccup burned an
    # ACME attempt and reported itself as an ACME failure, which it never was.
    $attempts = 3
    for ($attempt = 1; $attempt -le $attempts; $attempt++) {
        try {
            Write-Log "Installing Posh-ACME from the PowerShell Gallery (attempt $attempt of $attempts)" -Tag "Run"
            # -Force alone still leaves the provider bootstrap free to prompt, and a
            # prompt on an unattended run is a hang rather than a failure.
            Install-Module -Name "Posh-ACME" -Repository "PSGallery" -Scope AllUsers `
                -Force -AllowClobber -Confirm:$false -ErrorAction Stop
            $installed = @(Get-Module -ListAvailable -Name "Posh-ACME" | Sort-Object -Property Version -Descending)
            if ($installed.Count -eq 0) { throw "Install-Module reported success but the module is not there." }
            Write-Log "Posh-ACME $($installed[0].Version) installed" -Tag "Ok"
            return
        }
        catch {
            if ($attempt -eq $attempts) {
                Write-Log "Posh-ACME could not be installed: $($_.Exception.Message)" -Tag "Error"
                Write-PackageSourceDiagnostic
                throw
            }
            Write-Log "Install attempt $attempt of $attempts failed: $($_.Exception.Message)" -Tag "Warn"
            Write-Log "Retrying in 10 seconds" -Tag "Info"
            Start-Sleep -Seconds 10
        }
    }
}

# The daily task is the only place this belongs. A plugin whose provider changed its API
# is fixed in the module, not here, and a gateway that renews once every 60 days would
# otherwise run whatever version happened to be current the day it was built - for years.
# It never throws: an offline server, a blocked gallery or a locked file is a reason to
# renew with the version already installed, not a reason to fail the renewal.
function Update-PoshAcmeModule {
    $installed = @(Get-Module -ListAvailable -Name "Posh-ACME" | Sort-Object -Property Version -Descending)
    if ($installed.Count -eq 0) { return }

    $current = $installed[0].Version

    try {
        [System.Net.ServicePointManager]::SecurityProtocol =
            [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

        $available = Find-Module -Name "Posh-ACME" -Repository "PSGallery" -ErrorAction Stop
        if ($null -eq $available) { return }

        if ([version]$available.Version -le [version]$current) {
            Write-Log "Posh-ACME $current is current" -Tag "Debug"
            return
        }

        Write-Log "Updating Posh-ACME $current to $($available.Version)" -Tag "Run"
        # Install-Module -Force rather than Update-Module: the module may have been
        # installed by hand or side by side, and Update-Module refuses both.
        Install-Module -Name "Posh-ACME" -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
        Write-Log "Posh-ACME updated to $($available.Version)" -Tag "Ok"
    }
    catch {
        Write-Log "Could not check for a newer Posh-ACME: $($_.Exception.Message)" -Tag "Info"
        Write-Log "Renewing with the installed $current" -Tag "Info"
    }
}

# Posh-ACME encrypts saved plugin credentials with DPAPI by default, and DPAPI is
# per user: an account created interactively cannot be read back by SYSTEM, which is
# what the renewal task runs as. AltPluginEncryption keeps an AES key in
# POSHACME_HOME instead. An account that predates the switch is migrated here, which
# means dropping the credentials nothing can decrypt and re-saving them from config.
function Enable-AcmeAltEncryption {
    param([Parameter(Mandatory)][string]$PoshAcmeHome)

    $patterns = @("pluginargs.json", "plugindata.xml", "plugindata.xml.v3")
    foreach ($pattern in $patterns) {
        $files = @(Get-ChildItem -Path $PoshAcmeHome -Filter $pattern -Recurse -ErrorAction SilentlyContinue)
        foreach ($file in $files) {
            Remove-Item -LiteralPath $file.FullName -Force -ErrorAction SilentlyContinue
            Write-Log "Removed unreadable '$($file.Name)' - the credentials are re-saved from the config" -Tag "Debug"
        }
    }

    Set-PAAccount -UseAltPluginEncryption -ErrorAction Stop
    Write-Log "ACME account credentials stored with an AES key SYSTEM can read" -Tag "Ok"
}

function Test-AcmeAltEncryption {
    param([object]$Account)

    if ($null -eq $Account) { return $false }
    if ($Account.PSObject.Properties.Name -notcontains "sskey") { return $false }
    return (-not [string]::IsNullOrWhiteSpace([string]$Account.sskey))
}

# ConvertFrom-Json hands back PSCustomObject; a plugin parameter typed as a
# Hashtable wants a Hashtable, and nothing converts one to the other on its own.
function ConvertTo-StudioHashtable {
    param([object]$InputObject)

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) { return $InputObject }
    if (-not ($InputObject -is [System.Management.Automation.PSCustomObject])) { return $InputObject }

    $table = @{}
    foreach ($property in $InputObject.PSObject.Properties) {
        $table[$property.Name] = ConvertTo-StudioHashtable -InputObject $property.Value
    }
    return $table
}

# A Posh-ACME plugin does not take a bag of strings. Its parameters are typed, and
# the type decides what has to be handed over: a SecureString parameter given a
# plain string throws, a PSCredential one wants a pair, a switch wants a bool. The
# studio exports the types it read out of the module's own parameter block, so this
# converts rather than guesses. A parameter with no declared type - one typed by
# hand against a newer Posh-ACME - falls back to reading its name, which is what
# every parameter used to get.
function Get-AcmePluginArgument {
    param([Parameter(Mandatory)][object]$Acme)

    $pluginArgs = @{}
    $source = Get-ConfigValue -InputObject $Acme -Name "pluginArgs"
    if ($null -eq $source) { return $pluginArgs }

    $types = Get-ConfigValue -InputObject $Acme -Name "pluginArgTypes"
    $skipped = @()

    foreach ($property in $source.PSObject.Properties) {
        $name = $property.Name
        $value = $property.Value

        $type = ""
        if ($null -ne $types) { $type = [string](Get-ConfigValue -InputObject $types -Name $name -Default "") }
        if ([string]::IsNullOrWhiteSpace($type)) {
            if ($name -match "(?i)pass|secret|token|key") { $type = "secret" } else { $type = "string" }
        }

        switch ($type) {
            "secret" {
                # An empty secret means the design was exported without them. Handing
                # over an empty SecureString would overwrite the copy Posh-ACME saved
                # on the last successful run, so the parameter is left out instead.
                if ([string]::IsNullOrEmpty([string]$value)) { $skipped += $name; break }
                $pluginArgs[$name] = ConvertTo-SecureString -String ([string]$value) -AsPlainText -Force
            }
            "credential" {
                $user = [string](Get-ConfigValue -InputObject $value -Name "username" -Default "")
                $password = [string](Get-ConfigValue -InputObject $value -Name "password" -Default "")
                if ([string]::IsNullOrEmpty($password)) { $skipped += $name; break }
                $secure = ConvertTo-SecureString -String $password -AsPlainText -Force
                $pluginArgs[$name] = New-Object System.Management.Automation.PSCredential($user, $secure)
            }
            "switch"     { $pluginArgs[$name] = [bool]$value }
            "int"        { $pluginArgs[$name] = [int]$value }
            "list"       { $pluginArgs[$name] = [string[]]@($value) }
            "json"       { $pluginArgs[$name] = ConvertTo-StudioHashtable -InputObject $value }
            default      { $pluginArgs[$name] = [string]$value }
        }
    }

    if ($skipped.Count -gt 0) {
        Write-Log "Plugin credentials left out of the config: $($skipped -join ', ') - Posh-ACME's own copy is used" -Tag "Info"
    }
    return $pluginArgs
}

# The ACME server's own Date header against this clock. A skewed server produces a
# certificate that is not valid yet, which looks like a trust problem for hours.
function Test-AcmeSystemClock {
    param([int]$MaxSkewMinutes = 5)

    try {
        $previousProgress = $ProgressPreference
        $ProgressPreference = "SilentlyContinue"
        $response = Invoke-WebRequest -Uri "https://acme-v02.api.letsencrypt.org/directory" -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
        $ProgressPreference = $previousProgress

        $dateHeader = [string]$response.Headers["Date"]
        if ([string]::IsNullOrWhiteSpace($dateHeader)) { return }

        $skew = [math]::Abs((([datetime]::Parse($dateHeader)).ToUniversalTime() - [datetime]::UtcNow).TotalMinutes)
        if ($skew -gt $MaxSkewMinutes) {
            throw "This server's clock is $([math]::Round($skew, 1)) minutes off the ACME server's. Correct the time before renewing."
        }
        Write-Log "Clock is within $([math]::Round($skew, 1)) minute(s) of the ACME server" -Tag "Debug"
    }
    catch {
        if ($_.Exception.Message -match "clock is") { throw }
        Write-Log "Clock check skipped: $($_.Exception.Message)" -Tag "Debug"
    }
}

# The PFX exists for the seconds between Posh-ACME writing it and this script importing
# it into the machine store - same machine, same run, nothing else reads it. So it does
# not have to be memorable, written down, or in config.json at all: a fresh random one
# per run is strictly better than a typed one, and the studio's field is only there for
# somebody who wants to open the file by hand.
function New-StudioPfxPassword {
    # No symbols and no look-alike characters. Not for a human to read - for a command
    # line and a config file where a quote or a colon is somebody else's bug.
    $alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    $limit    = [int]([math]::Floor(256 / $alphabet.Length) * $alphabet.Length)
    $password = ""

    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $buffer = New-Object byte[] 1
        while ($password.Length -lt 40) {
            $generator.GetBytes($buffer)
            # Rejection sampling: taking the modulo of every byte would favour the first
            # 256 % 57 characters of the alphabet.
            if ($buffer[0] -ge $limit) { continue }
            $password = $password + $alphabet[$buffer[0] % $alphabet.Length]
        }
    }
    finally {
        $generator.Dispose()
    }

    return $password
}

# A Posh-ACME home that is not a rooted Windows path is a typo, and New-Item turns it
# into "cannot find drive '<whatever was pasted>'" - which names the value but not the
# setting it came from, and leaves the module writing to its own default anyway.
function Get-AcmeHome {
    param([Parameter(Mandatory)][object]$Acme)

    $fallback  = Join-Path -Path $env:ProgramData -ChildPath "Posh-ACME"
    $configured = Get-ConfigText -InputObject $Acme -Name "poshAcmeHome" -Default $fallback
    if ($configured -eq $fallback) { return $fallback }

    # Same shape the studio validates: drive letter, colon, backslash, and none of the
    # characters Windows will not put in a path. IsPathRooted is not used - it answers
    # for the platform this happens to run on, and the answer has to be about Windows.
    if ($configured -notmatch '^[A-Za-z]:\\[^<>:"/\\|?*\r\n]*') {
        Write-Log "certificate.acme.poshAcmeHome is '$configured', which is not a full Windows path - using '$fallback'" -Tag "Error"
        return $fallback
    }
    return $configured
}

function New-AcmeCertificate {
    param([Parameter(Mandatory)][object]$Certificate)

    $acme = Get-ConfigValue -InputObject $Certificate -Name "acme"
    if ($null -eq $acme) { throw "certificate.acme is missing." }

    $dnsNames = @(Get-CertificateNameList -Certificate $Certificate)
    $plugin   = Get-ConfigText -InputObject $acme -Name "dnsPlugin"
    if ([string]::IsNullOrWhiteSpace($plugin)) { throw "certificate.acme.dnsPlugin is empty." }

    $contact  = Get-ConfigText -InputObject $acme -Name "contactEmail"
    $server   = Get-ConfigText -InputObject $acme -Name "server" -Default "LE_PROD"
    $acmeHome = Get-AcmeHome -Acme $acme

    Install-PoshAcmeModule
    Test-AcmeSystemClock

    if (-not (Test-Path -LiteralPath $acmeHome)) {
        $null = New-Item -ItemType Directory -Path $acmeHome -Force
    }
    Protect-StudioDirectory -Path $acmeHome

    # Set before the import: the module reads it once, when it loads.
    $env:POSHACME_HOME = $acmeHome
    Import-Module -Name "Posh-ACME" -Force -ErrorAction Stop
    Write-Log "Posh-ACME loaded with POSHACME_HOME '$acmeHome'" -Tag "Debug"

    Set-PAServer -DirectoryUrl $server -ErrorAction Stop

    # A contact is where the expiry warnings go, not something the protocol needs, so
    # an empty one is left out rather than passed as a blank address.
    $contactParam = @{}
    if (-not [string]::IsNullOrWhiteSpace($contact)) { $contactParam["Contact"] = $contact }

    $account = Get-PAAccount -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $account) {
        Write-Log "Creating an ACME account for '$contact'" -Tag "Run"
        $null = New-PAAccount @contactParam -AcceptTOS -UseAltPluginEncryption -ErrorAction Stop
    }
    elseif (-not (Test-AcmeAltEncryption -Account $account)) {
        Enable-AcmeAltEncryption -PoshAcmeHome $acmeHome
    }

    $pluginArgs  = Get-AcmePluginArgument -Acme $acme
    $pluginList  = @($dnsNames | ForEach-Object { $plugin })
    $orderName   = $dnsNames[0]
    # Left empty in the design, a fresh one is minted for this run rather than falling
    # back to Posh-ACME's well-known default. The renewal path below writes it onto the
    # stored order, so the password this run imports with is the one the PFX was written
    # with even though it is different every time.
    $pfxPlain = Get-ConfigText -InputObject $acme -Name "pfxPassword"
    if ([string]::IsNullOrWhiteSpace($pfxPlain)) {
        $pfxPlain = New-StudioPfxPassword
        Write-Log "No PFX password in the design - generated one for this run" -Tag "Info"
    }
    $pfxPassword = ConvertTo-SecureString -String $pfxPlain -AsPlainText -Force

    $order = Get-PAOrder -Name $orderName -ErrorAction SilentlyContinue
    $result = $null

    if ($null -eq $order) {
        Write-Log "No order for '$orderName' yet - requesting the first certificate" -Tag "Run"
        $result = New-PACertificate -Domain $dnsNames -Name $orderName -AcceptTOS @contactParam `
            -Plugin $pluginList -PluginArgs $pluginArgs -PfxPassSecure $pfxPassword -ErrorAction Stop
    }
    else {
        # The names may have changed since the order was written; a certificate that
        # no longer covers what the gateway answers on is worse than no renewal.
        $current = @([string]$order.MainDomain)
        if ($null -ne $order.SANs) { $current += @($order.SANs) }
        $drifted = @(@($dnsNames | Where-Object { $current -notcontains $_ }) +
                     @($current  | Where-Object { $dnsNames -notcontains $_ }))

        if ($drifted.Count -gt 0) {
            Write-Log "The names changed ($($drifted -join ', ')) - re-issuing rather than renewing" -Tag "Info"
            $result = New-PACertificate -Domain $dnsNames -Name $orderName -AcceptTOS @contactParam `
                -Plugin $pluginList -PluginArgs $pluginArgs -PfxPassSecure $pfxPassword -Force -ErrorAction Stop
        }
        else {
            # PfxPassSecure as well as the plugin arguments: Submit-Renewal writes the
            # PFX with whatever the order has stored, and the import below uses what this
            # run holds. A generated password makes those two different every time.
            $null = Set-PAOrder -Name $orderName -PluginArgs $pluginArgs -PfxPassSecure $pfxPassword -ErrorAction Stop
            # -ForceRenewal on the command line. Without it Posh-ACME declines while the
            # certificate is comfortably inside its window, which is right every night
            # of the year and useless when the renewal is the thing being tested.
            if ($script:forceRenewal) {
                Write-Log "Forcing a renewal for '$orderName' - the certificate is not necessarily due" -Tag "Run"
                $result = Submit-Renewal -Force -ErrorAction Stop
            }
            else {
                Write-Log "Submitting a renewal for '$orderName'" -Tag "Run"
                $result = Submit-Renewal -ErrorAction Stop
            }
        }
    }

    if ($null -eq $result) {
        Write-Log "Posh-ACME reported nothing to renew - the certificate is still inside its window" -Tag "Info"
        $existing = Get-PACertificate -MainDomain $orderName -ErrorAction SilentlyContinue
        if ($null -eq $existing) { return "" }
        $result = $existing
    }

    if ([string]::IsNullOrWhiteSpace([string]$result.PfxFile)) {
        throw "Posh-ACME returned no PFX path for '$orderName'."
    }

    # The design says whether this key has to be exportable, because the design is what
    # knows whether the certificate is going to a second machine.
    $exportable = [bool](Get-ConfigValue -InputObject $Certificate -Name "exportable" -Default $false)
    return (Import-StudioPfxCertificate -PfxPath ([string]$result.PfxFile) -Password $pfxPassword -Exportable:$exportable)
}

# Import-PfxCertificate mints a **new key file** on every call, and re-points the store
# entry at it. Importing a certificate that is already installed therefore silently
# re-keys it: the old key file is orphaned, and any read granted on it - to the account
# the gateway runs as, for instance - now applies to a key nothing uses. Schannel keeps
# working until the service next opens the key, so the gateway runs all day and comes back
# after a reboot with 0x8009030D and nothing else to say. The daily task ran this path
# every morning, renewal or not.
#
# So the PFX is read first and imported only when the store does not already hold that
# thumbprint with a usable private key. Same certificate, same key file, same ACL.
# The PFX into LocalMachine\My, and the one rule that governs the whole function: **an
# import only happens when there is something new to import.**
#
# Import-PfxCertificate mints a new key file on every call and re-points the store entry
# at it. Importing a certificate that is already installed therefore silently re-keys it:
# the old key file is orphaned, and any read granted on it - to the account a gateway
# runs as, for instance - now applies to a key nothing uses. Schannel keeps working until
# the service next opens the key, so the gateway runs all day and comes back after a
# reboot with 0x8009030D and nothing else to say. The daily task ran this path every
# morning, renewal or not.
#
# The 2026-08-09 bench added a second reason, and a louder one. A version of this
# function re-imported whenever a provider check disliked the key it found, which on an
# Exchange server meets `Import-ExchangeCertificate` refusing outright - *"a certificate
# with the thumbprint ... already exists"* - and turned the renewal into a retry loop
# that could never finish. So the thumbprint being present with a usable private key ends
# this function, full stop. Nothing about the key's provider changes that: an import
# cannot fix a certificate that is already imported.
function Import-StudioPfxCertificate {
    param(
        [Parameter(Mandatory)][string]$PfxPath,
        [Parameter(Mandatory)][System.Security.SecureString]$Password,
        # Off unless the design says otherwise, and the design only says so for a
        # certificate that has to LEAVE this machine: Remote Desktop's portal on its own
        # server, where the deployment hands the certificate over as a PFX because
        # Set-RDCertificate -Thumbprint needs it in the store of every server holding the
        # role. Without it Export-PfxCertificate refuses and the portal keeps last
        # quarter's certificate - quarterly, on a 90 day one.
        [switch]$Exportable
    )

    $thumbprint = ""
    $probe      = $null
    try {
        # No PersistKeySet: the container this creates is transient and goes away with the
        # object. All that is wanted here is the thumbprint.
        $probe = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $PfxPath, $Password, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)
        $thumbprint = [string]$probe.Thumbprint
    }
    catch {
        Write-Log "Could not read '$PfxPath' before importing it: $($_.Exception.Message)" -Tag "Debug"
    }
    finally {
        if ($null -ne $probe) { $probe.Dispose() }
    }

    if (-not [string]::IsNullOrWhiteSpace($thumbprint)) {
        $installed = Get-StoreCertificate -Thumbprint $thumbprint
        if (($null -ne $installed) -and $installed.HasPrivateKey) {
            Write-Log "$thumbprint is already in LocalMachine\My with its key - not re-importing it" -Tag "Info"
            $null = Test-StudioCertificateProvider -Thumbprint $thumbprint
            return $thumbprint
        }
    }

    # Import-ExchangeCertificate where it exists, which is the path the field-proven
    # script this role grew out of uses, and the supported one on a mailbox server.
    # Everywhere else the general cmdlet.
    if (Get-Command -Name "Import-ExchangeCertificate" -ErrorAction SilentlyContinue) {
        Write-Log "Importing '$PfxPath' with Import-ExchangeCertificate" -Tag "Run"
        $bytes = [System.IO.File]::ReadAllBytes($PfxPath)
        try {
            $imported = Import-ExchangeCertificate -FileData $bytes -Password $Password -ErrorAction Stop
            $thumbprint = [string]$imported.Thumbprint
        }
        catch {
            # "A certificate with the thumbprint ... already exists" is not a failure -
            # it is this function's own success condition arriving by another route. The
            # short-circuit above catches it whenever the PFX could be read for its
            # thumbprint; this catches the case where it could not, which would otherwise
            # turn an installed certificate into a failed run and, above this function, a
            # retry of the whole ACME acquisition.
            $existing = [regex]::Match([string]$_.Exception.Message, "thumbprint\s+([0-9A-Fa-f]{40})")
            if (-not $existing.Success) { throw }

            $thumbprint = $existing.Groups[1].Value.ToUpperInvariant()
            $installed = Get-StoreCertificate -Thumbprint $thumbprint
            if ($null -eq $installed) { throw }

            Write-Log "$thumbprint was already in the store - taking that as the import" -Tag "Info"
            $null = Test-StudioCertificateProvider -Thumbprint $thumbprint
            return $thumbprint
        }
        Write-Log "Imported $thumbprint" -Tag "Ok"
        $null = Test-StudioCertificateProvider -Thumbprint $thumbprint
        return $thumbprint
    }

    Write-Log "Importing '$PfxPath' into LocalMachine\My" -Tag "Run"
    # Note the early exit above: a certificate already in the store is not re-imported,
    # so switching a design to Exportable takes effect at the next renewal rather than
    # retroactively. That is the right way round - a re-import would re-key a certificate
    # something is already serving.
    $arguments = @{
        FilePath          = $PfxPath
        CertStoreLocation = "Cert:\LocalMachine\My"
        Password          = $Password
        ErrorAction       = "Stop"
    }
    if ($Exportable) {
        Write-Log "Importing with an exportable key - the deployment hands this certificate to another server" -Tag "Info"
        $arguments["Exportable"] = $true
    }
    $imported = Import-PfxCertificate @arguments

    Write-Log "Imported $($imported.Thumbprint), valid until $($imported.NotAfter.ToString('yyyy-MM-dd'))" -Tag "Ok"
    return [string]$imported.Thumbprint
}

# Which provider holds the private key - **reported, never acted on**.
#
# Exchange's OWA and ECP go through the legacy CryptoAPI, and Microsoft's guidance is
# that they do not support keys in a CNG Key Storage Provider. This says which one a
# certificate has so that a sign-in failure has somewhere to start, and it says it once.
#
# It drives nothing, and that is deliberate: an earlier version let it trigger a
# re-import, which on an Exchange server is a cmdlet refusing a thumbprint it already
# has, retried five times. A check that changes the flow has to be right every time; a
# check that only writes a line has to be right often enough to be worth reading.
#
# Asked of certutil rather than of .NET, because the .NET answer is not trustworthy here:
# `GetRSAPrivateKey` returns an `RSACng` wrapper for CAPI-stored keys on some runtimes,
# which is exactly the false positive that started the loop.
function Test-StudioCertificateProvider {
    param([Parameter(Mandatory)][string]$Thumbprint)

    if (-not (Get-Command -Name "certutil.exe" -ErrorAction SilentlyContinue)) { return $true }

    $output = ""
    try { $output = (& certutil.exe -store My $Thumbprint 2>&1 | Out-String) }
    catch {
        Write-Log "The key provider of $Thumbprint could not be read: $($_.Exception.Message)" -Tag "Debug"
        return $true
    }

    $match = [regex]::Match($output, "(?im)^\s*Provider\s*=\s*(.+)$")
    if (-not $match.Success) {
        Write-Log "certutil did not report a provider for $Thumbprint" -Tag "Debug"
        return $true
    }

    $provider = $match.Groups[1].Value.Trim()
    if ($provider -match "(?i)key storage provider") {
        Write-Log "$Thumbprint holds its key in '$provider'" -Tag "Info"
        Write-Log "    Microsoft's guidance is that Exchange's OWA and ECP support CryptoAPI keys only. If sign-in fails, start here - re-issue the certificate against a CryptoAPI provider rather than re-importing this one." -Tag "Debug"
        return $false
    }
    Write-Log "$Thumbprint holds its key in '$provider'" -Tag "Debug"
    return $true
}

# ---------------------------[ Certificate: dispatch ]---------------------------
function Get-CertificateNameList {
    param([Parameter(Mandatory)][object]$Certificate)

    $names = @(Get-ConfigArray -InputObject $Certificate -Name "dnsNames" |
        ForEach-Object { [string]$_ } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    if ($names.Count -eq 0) {
        throw "certificate.dnsNames is empty - the gateway needs at least the name clients open it by."
    }
    return $names
}

# Whatever the role, the answer is a thumbprint in LocalMachine\My or an empty string
# meaning "nothing to bind - keep what is there".
function Resolve-StudioCertificate {
    param([Parameter(Mandatory)][object]$Certificate)

    $certificate = $Certificate
    $source      = [string](Get-ConfigValue -InputObject $certificate -Name "source" -Default "generate")

    switch ($source) {
        "generate" {
            Write-Log "The self-signed certificate is being kept - clients see a trust warning" -Tag "Info"
            return ""
        }
        # What the Remote Desktop side calls the same thing.
        "leave" {
            Write-Log "The certificate the deployment made for itself is being kept - clients see a trust warning" -Tag "Info"
            return ""
        }
        # A PFX staged on the server by hand, which Set-RDCertificate would otherwise
        # want to import itself - doing it here means one import path and one key ACL.
        "pfx" {
            $pfxPath = Get-ConfigText -InputObject $certificate -Name "pfxPath"
            if ([string]::IsNullOrWhiteSpace($pfxPath)) { throw "certificate.pfxPath is empty." }
            if (-not (Test-Path -LiteralPath $pfxPath)) { throw "The PFX '$pfxPath' is not on this server." }
            $pfxPlain = Get-ConfigText -InputObject $certificate -Name "pfxPassword"
            $secure = New-Object System.Security.SecureString
            if (-not [string]::IsNullOrWhiteSpace($pfxPlain)) {
                $secure = ConvertTo-SecureString -String $pfxPlain -AsPlainText -Force
            }
            $exportable = [bool](Get-ConfigValue -InputObject $certificate -Name "exportable" -Default $false)
            return (Import-StudioPfxCertificate -PfxPath $pfxPath -Password $secure -Exportable:$exportable)
        }
        "existingThumbprint" {
            $thumbprint = ([string](Get-ConfigValue -InputObject $certificate -Name "thumbprint" -Default "")).Replace(" ", "").ToUpperInvariant()
            if ([string]::IsNullOrWhiteSpace($thumbprint)) { throw "certificate.thumbprint is empty." }
            if ($null -eq (Get-Item -LiteralPath ("Cert:\LocalMachine\My\" + $thumbprint) -ErrorAction SilentlyContinue)) {
                throw "Certificate $thumbprint is not in LocalMachine\My on this server."
            }
            Write-Log "Using the certificate already in the store: $thumbprint" -Tag "Info"
            return $thumbprint
        }
        "internalCa" { return (New-InternalCaCertificate -Certificate $certificate) }
        # Retried, because everything between here and the certificate is somebody
        # else's network: the ACME directory, the DNS provider's API, the resolvers in
        # between. A DNS answer that has not converged or an API that is mid-deploy
        # heals on its own; five attempts half a minute apart cover that without
        # hammering anybody. What does not heal - wrong credentials, a refused
        # validation - fails five times the same way and arrives as the same error,
        # thirty seconds later than it used to.
        "acme" {
            # Before the retry loop on purpose: getting the module is not part of what
            # the loop exists to retry, and inside it a gallery problem spent ACME
            # attempts and logged itself as an ACME failure.
            Install-PoshAcmeModule

            $attempts = 5
            for ($attempt = 1; $attempt -le $attempts; $attempt++) {
                try {
                    return (New-AcmeCertificate -Certificate $certificate)
                }
                catch {
                    if ($attempt -eq $attempts) { throw }
                    Write-Log "ACME attempt $attempt of $attempts failed: $($_.Exception.Message)" -Tag "Warn"
                    Write-Log "Retrying in 30 seconds" -Tag "Info"
                    Start-Sleep -Seconds 30
                }
            }
        }
        default      { throw "Unknown certificate source '$source'." }
    }
}

# ---------------------------[ Deployment and the daily task ]---------------------------
# SYSTEM and Administrators only: the config next to the script carries the DNS
# plugin credentials and the PFX password in clear text whenever the studio was
# asked to export secrets.
function Protect-StudioDirectory {
    param([Parameter(Mandatory)][string]$Path)

    try {
        $acl = Get-Acl -Path $Path
        $acl.SetAccessRuleProtection($true, $false)
        # The SIDs, not the names. "BUILTIN\Administrators" is VORDEFINIERT\Administratoren
        # on a German server and this whole block would throw - which the catch below turns
        # into "tighten it by hand" on the one directory holding DNS plugin credentials and
        # a PFX password in clear text. FileSystemAccessRule takes an IdentityReference, so
        # the SID goes in directly and no name is ever involved.
        foreach ($wellKnown in @([System.Security.Principal.WellKnownSidType]::LocalSystemSid,
                                 [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)) {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($wellKnown, $null)
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $sid, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $acl.AddAccessRule($rule)
        }
        Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop
        Write-Log "'$Path' is readable by SYSTEM and Administrators only" -Tag "Ok"
    }
    catch {
        Write-Log "Could not restrict '$Path': $($_.Exception.Message)" -Tag "Error"
        Write-Log "It holds credentials in clear text - tighten it by hand" -Tag "Error"
    }
}

function Get-StudioDeployDirectory {
    param([object]$RenewalTask)

    $configured = [string](Get-ConfigValue -InputObject $RenewalTask -Name "deployDirectory" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($configured)) { return $configured }

    # Queried, never assumed - a server that boots from D: gets D:\tasks.
    #
    # 'tasks', not 'scripts'. What lands here is what the scheduled tasks run and
    # nothing else, and a folder called scripts on a Windows server is where everybody
    # keeps their own - which is a folder this project empties and rewrites.
    $systemDrive = $env:SystemDrive
    if ([string]::IsNullOrWhiteSpace($systemDrive)) { $systemDrive = "C:" }
    return (Join-Path -Path $systemDrive -ChildPath "tasks")
}

# Two paths naming the same file. Compared as full paths rather than as strings, because
# "C:\tasks\pwsh" and "C:\tasks\.\pwsh\" are the same folder and neither Copy-Item nor
# Remove-Item is forgiving about being handed it twice.
function Test-StudioSamePath {
    param(
        [string]$Left,
        [string]$Right
    )

    if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) { return $false }

    try {
        $leftFull  = [System.IO.Path]::GetFullPath($Left).TrimEnd([char]92)
        $rightFull = [System.IO.Path]::GetFullPath($Right).TrimEnd([char]92)
    }
    catch {
        return $false
    }

    return $leftFull.Equals($rightFull, [System.StringComparison]::OrdinalIgnoreCase)
}

# ---------------------------[ A task that carries itself ]---------------------------
# The rule this project now follows: a scheduled task gets a script of its own, and the
# project is staged only where the job genuinely needs it. Most of these jobs are a
# handful of commands - certutil and a prune, a log sweep - and copying the entry
# script, twenty-odd parts and a config.json that may carry exported secrets onto a
# server so that a five-line job can dot-source a framework to reach them is bloat with
# a security cost attached.
#
# So: one generated file per task, its design values substituted in as parameter
# defaults, which is what keeps the scheduled action down to a single -File and lets the
# script be read on the server by whoever is standing in front of it at 03:00. The
# template is written as a single-quoted here-string (nothing interpolates, so the
# script's own $variables survive) with __TOKEN__ placeholders; this writes it out.
#
# __WRITTEN__ is always available and always the same sentence's worth of provenance:
# a generated file with no date on it is a file nobody can tell from a hand-edited one.
function Write-StudioTaskScript {
    param(
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][string]$Template,
        [hashtable]$Value = @{},
        [object]$Task = $null,
        [string]$Purpose = ""
    )

    $deployDirectory = Get-StudioDeployDirectory -RenewalTask $Task
    if (-not (Test-Path -LiteralPath $deployDirectory)) {
        $null = New-Item -ItemType Directory -Path $deployDirectory -Force -ErrorAction Stop
        Write-Log "Created '$deployDirectory'" -Tag "Info"
    }

    $content = $Template.Replace("__WRITTEN__", (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))
    foreach ($key in $Value.Keys) {
        $content = $content.Replace(("__{0}__" -f $key), [string]$Value[$key])
    }
    # A placeholder nobody substituted is a value that silently became the literal
    # string __THING__ inside a script running as SYSTEM at three in the morning.
    $left = [regex]::Matches($content, "__[A-Z0-9_]+__")
    if ($left.Count -gt 0) {
        throw ("The generated script still carries {0}" -f (($left | ForEach-Object { $_.Value } | Select-Object -Unique) -join ", "))
    }

    # UTF-8 with a BOM, like every file this project ships: 5.1 reads one without as the
    # ANSI code page.
    $path = Join-Path -Path $deployDirectory -ChildPath $FileName
    [System.IO.File]::WriteAllText($path, $content, (New-Object System.Text.UTF8Encoding($true)))
    if ($Purpose) { Write-Log "Wrote '$path' - $Purpose" -Tag "Ok" }
    else { Write-Log "Wrote '$path'" -Tag "Ok" }
    return $path
}

# A value going into a single-quoted PowerShell string in a generated script. One
# apostrophe in a folder name would otherwise end the string and take the rest of the
# line with it.
function ConvertTo-StudioScriptLiteral {
    param([string]$Value)

    if ($null -eq $Value) { return "" }
    return $Value.Replace("'", "''")
}

# ---------------------------[ What a task actually loads ]---------------------------
# The two jobs that cannot be a script of their own - the nightly renewal and the Remote
# Desktop portal watchdog - need this project, because the renewal is Posh-ACME plus the
# binder for whichever role holds the certificate and both of them send the studio's
# HTML report. What they do not need is ALL of it: twenty-seven parts and 2.1 MB, every
# role this studio can configure, staged onto a gateway so that four of them can be
# dot-sourced.
#
# So the task's action names its parts and the deploy folder holds exactly those. The
# lists below were derived by walking the call graph from each entry function (every
# command an entry calls that this project defines, transitively) and they are the
# reason each branch of Invoke-CertificateTask is gated on its own config section:
# a section that is not in the design is a part that is not staged, and a branch that
# therefore never runs. Re-derive them the same way after moving a function between
# parts, and remember that the entry script's own preamble is in the base list -
# Get-RunState is in Engine.ps1 and runs before the task does.
#
#   base            Logging, Config, Engine (the preamble), Acme (the task itself)
#   windowsAdminCenter  Mail, Role.Wac
#   remoteDesktop       Mail, Role.Rds
#   exchange            Mail, Role.Exchange
#   the Hyper-V owner   Role.Hyperv, Role.Hyperv.Cluster, Role.Hyperv.S2d
#   the SCEP owner      Mail, Role.Adcs, Role.Adcs.Ndes
$script:studioTaskBasePart = @("Logging.ps1", "Config.ps1", "Engine.ps1", "Acme.ps1")

function Get-StudioTaskPart {
    param(
        [Parameter(Mandatory)][string]$Task,
        [object]$Config
    )

    $parts = @($script:studioTaskBasePart)

    if ($Task -eq "RdsPortal") {
        return @($parts + @("Mail.ps1", "Role.Rds.ps1"))
    }

    # The renewal: one part set per branch that this config can actually reach.
    if ($null -ne (Get-ConfigValue -InputObject $Config -Name "windowsAdminCenter")) {
        $parts += @("Mail.ps1", "Role.Wac.ps1")
    }
    if ($null -ne (Get-ConfigValue -InputObject $Config -Name "remoteDesktop")) {
        $parts += @("Mail.ps1", "Role.Rds.ps1")
    }
    if ($null -ne (Get-ConfigValue -InputObject $Config -Name "exchange")) {
        $parts += @("Mail.ps1", "Role.Exchange.ps1")
    }
    # These two are the same tests the task dispatches on, so the staged set and the
    # branch that runs cannot disagree - which is the whole safety argument here.
    if (Test-CertificateTaskHypervOwner -Config $Config) {
        $parts += @("Role.Hyperv.ps1", "Role.Hyperv.Cluster.ps1", "Role.Hyperv.S2d.ps1")
    }
    if (Test-CertificateTaskScepOwner -Config $Config) {
        $parts += @("Mail.ps1", "Role.Adcs.ps1", "Role.Adcs.Ndes.ps1")
    }

    return @($parts | Select-Object -Unique)
}

# Both remaining stagers share one deploy folder and need different parts of it, so the
# folder holds the UNION of what this run staged into it. Pruned once per run - the
# first stager empties it, every later one adds - because a part left behind by an
# older version of this project is exactly the stale file the old wholesale delete
# existed to prevent, and keeping it would make an upgrade silently load yesterday's
# code.
$script:studioDeployPrimed = $false
$script:studioStagedPart = @()

# Both registered tasks stage the same three things into the same folder, and both used to
# do it unconditionally - which fails the moment the run is already *in* that folder, and
# that is the normal case on the second visit to a server: the first run copies itself to
# C:\tasks, somebody runs it again from there, and Copy-Item refuses with "Cannot
# overwrite the item C:\tasks\Configure-ServerRoles.ps1 with itself". The failure landed
# on the task registration, so a gateway that was configured correctly reported a manual
# step. Worse was waiting behind it: the parts folder is *deleted* before it is copied, so
# the same run would have removed the pwsh folder it was executing out of.
function Copy-StudioDeployment {
    param(
        [Parameter(Mandatory)][string]$DeployDirectory,
        [string]$ConfigFilePath = "",
        [Parameter(Mandatory)][string[]]$Part
    )

    if (-not (Test-Path -LiteralPath $DeployDirectory)) {
        $null = New-Item -ItemType Directory -Path $DeployDirectory -Force -ErrorAction Stop
        Write-Log "Created '$DeployDirectory'" -Tag "Info"
    }
    Protect-StudioDirectory -Path $DeployDirectory

    $deployedScript = Join-Path -Path $DeployDirectory -ChildPath ([System.IO.Path]::GetFileName($script:entryScriptPath))
    $deployedConfig = Join-Path -Path $DeployDirectory -ChildPath "config.json"
    $deployedParts  = Join-Path -Path $DeployDirectory -ChildPath "pwsh"
    $copied         = $false

    if (Test-StudioSamePath -Left $script:entryScriptPath -Right $deployedScript) {
        Write-Log "This run already starts from '$DeployDirectory' - the task points at it where it is" -Tag "Info"
    }
    else {
        Copy-Item -LiteralPath $script:entryScriptPath -Destination $deployedScript -Force -ErrorAction Stop
        $copied = $true
    }

    if (-not [string]::IsNullOrWhiteSpace($ConfigFilePath)) {
        if (Test-StudioSamePath -Left $ConfigFilePath -Right $deployedConfig) {
            $deployedConfig = $ConfigFilePath
        }
        else {
            Copy-Item -LiteralPath $ConfigFilePath -Destination $deployedConfig -Force -ErrorAction Stop
            $copied = $true
        }
    }

    # The entry script is not the whole script: without the parts it loads beside it the
    # task would stop at the first missing file every night. Only the parts the task
    # NAMES are staged - see Get-StudioTaskPart - and the folder ends up holding the
    # union of what this run's tasks asked for.
    #
    # Emptied once per run and added to after that. Wholesale replacement is what keeps
    # an older part from surviving an upgrade; doing it on every call would mean the
    # second task of a run deleting the first one's parts. And it must never run against
    # the folder this process is dot-sourced from - it would remove the pwsh folder it
    # is executing out of.
    if (Test-StudioSamePath -Left $script:moduleDirectory -Right $deployedParts) {
        Write-Log "The parts are already in '$deployedParts' - left where they are" -Tag "Info"
    }
    else {
        if (-not $script:studioDeployPrimed) {
            if (Test-Path -LiteralPath $deployedParts) {
                Remove-Item -LiteralPath $deployedParts -Recurse -Force -ErrorAction Stop
            }
            $script:studioDeployPrimed = $true
            $script:studioStagedPart = @()
        }
        if (-not (Test-Path -LiteralPath $deployedParts)) {
            $null = New-Item -ItemType Directory -Path $deployedParts -Force -ErrorAction Stop
        }
        foreach ($partName in $Part) {
            if ($script:studioStagedPart -contains $partName) { continue }
            $source = Join-Path -Path $script:moduleDirectory -ChildPath $partName
            if (-not (Test-Path -LiteralPath $source)) {
                throw "The task needs '$partName' and this copy of the script does not have it."
            }
            Copy-Item -LiteralPath $source -Destination (Join-Path -Path $deployedParts -ChildPath $partName) -Force -ErrorAction Stop
            $script:studioStagedPart += $partName
            $copied = $true
        }
    }

    if ($copied) {
        Write-Log ("Staged the script, its config and {0} part(s) into '{1}'" -f $Part.Count, $DeployDirectory) -Tag "Ok"
    }

    return @{ ScriptPath = $deployedScript; ConfigPath = $deployedConfig }
}

# ---------------------------[ The nightly task ]---------------------------
# One task for the server, not one per role. A gateway certificate and a Remote Desktop
# deployment certificate expire the same way and are renewed by the same code above, so
# a second nightly job would only be a second thing to forget.
#
# The name is what Task Scheduler shows, so it says what the task renews rather than
# which tool registered it: "Certificate Renewal - Remote Desktop Services". The prefix
# is the stable half - registration removes every task carrying it before it writes the
# new one, which is what keeps the name honest when the config gains or loses a role.
$script:certificateTaskPrefix = "Certificate Renewal"
# What the task was called before it carried the service name, and before that while it
# belonged to Windows Admin Center alone. Removed on sight, so a server that has been
# through the older versions is not left with two jobs renewing the same certificate an
# hour apart.
$script:legacyCertificateTaskNames = @("WSRS-Certificate", "WSRS-WacCertificate")

# Same sections Invoke-CertificateTask dispatches on, so the name never promises a
# renewal the task would not attempt.
# Is this machine the connector host, and does its certificate expire? Both halves
# matter: the SCEP tier lives inside certificateServices, so its mere presence says
# nothing about *this* server - the config travels to the CAs and the DC as well.
function Test-CertificateTaskScepOwner {
    param([Parameter(Mandatory)][object]$Config)

    $certificateServices = Get-ConfigValue -InputObject $Config -Name "certificateServices"
    if ($null -eq $certificateServices) { return $false }
    $scep = Get-ConfigValue -InputObject $certificateServices -Name "scep"
    if ($null -eq $scep) { return $false }
    if (-not [bool](Get-ConfigValue -InputObject $scep -Name "enabled" -Default $false)) { return $false }

    # An empty name means this machine. That is not a shortcut: the standalone Let's
    # Encrypt retrofit is run *on* the target, so the only correct answer to "which
    # computer" would be the hostname of the server already running the script - a
    # field whose only valid value is a tautology is a field that gets typed wrong.
    $name = [string](Get-ConfigText -InputObject $scep -Name "computerName" -Default "")
    if ((-not [string]::IsNullOrWhiteSpace($name)) -and
        (-not $name.Equals([string]$env:COMPUTERNAME, [System.StringComparison]::OrdinalIgnoreCase))) {
        return $false
    }

    $source = [string](Get-ConfigText -InputObject (Get-ConfigValue -InputObject $scep -Name "certificate") -Name "source" -Default "leave")
    return (@("acme", "internalCa") -contains $source)
}

# Does this config give the Hyper-V management endpoint a certificate to renew? Asked in
# two places - the task's display name and the task itself - so it is one function rather
# than the same four lookups written twice.
function Test-CertificateTaskHypervOwner {
    param([Parameter(Mandatory)][object]$Config)

    $hyperv = Get-ConfigValue -InputObject $Config -Name "hyperV"
    if ($null -eq $hyperv) { return $false }
    $s2d = Get-ConfigValue -InputObject $hyperv -Name "s2dCluster"
    if ($null -eq $s2d) { return $false }
    $management = Get-ConfigValue -InputObject $s2d -Name "management"
    if ($null -eq $management) { return $false }
    return [bool](Get-ConfigValue -InputObject $management -Name "winRmHttps" -Default $false)
}

function Get-CertificateTaskDisplayName {
    param([Parameter(Mandatory)][object]$Config)

    $services = @()
    if ($null -ne (Get-ConfigValue -InputObject $Config -Name "windowsAdminCenter")) { $services += "Windows Admin Center" }
    if ($null -ne (Get-ConfigValue -InputObject $Config -Name "remoteDesktop")) { $services += "Remote Desktop Services" }
    # Asked of the machine, not of the section: one config describes several servers, so
    # an exchange section reaching the connector host must not put "Exchange Server" in
    # that machine's task name.
    if (($null -ne (Get-ConfigValue -InputObject $Config -Name "exchange")) -and (Test-ExchangeInstalled)) { $services += "Exchange Server" }
    # The SCEP tier is a section inside another role's, so it is asked for by name -
    # and only when this machine is the one holding that certificate.
    if (Test-CertificateTaskScepOwner -Config $Config) { $services += "Intune Certificate Connector" }
    # The Hyper-V S2D management endpoint, when the design gave it one that expires.
    if (Test-CertificateTaskHypervOwner -Config $Config) { $services += "Hyper-V management endpoint" }
    if ($services.Count -eq 0) { return $script:certificateTaskPrefix }
    return ("{0} - {1}" -f $script:certificateTaskPrefix, ($services -join ", "))
}

# certificateTask is the current shape; a config written before the task became shared
# carries it under windowsAdminCenter.renewalTask, and an older file should not silently
# come back with no task at all.
function Get-CertificateTaskSection {
    param([Parameter(Mandatory)][object]$Config)

    $section = Get-ConfigValue -InputObject $Config -Name "certificateTask"
    if ($null -ne $section) { return $section }

    $wac = Get-ConfigValue -InputObject $Config -Name "windowsAdminCenter"
    if ($null -eq $wac) { return $null }

    $legacy = Get-ConfigValue -InputObject $wac -Name "renewalTask"
    if ($null -eq $legacy) { return $null }

    Write-Log "Reading the task from windowsAdminCenter.renewalTask - re-export config.json to move it to certificateTask" -Tag "Info"
    return $legacy
}

# The notification block moved with the task, and is read the same way.
function Get-CertificateNotificationSection {
    param([Parameter(Mandatory)][object]$Config)

    $section = Get-ConfigValue -InputObject $Config -Name "certificateTask"
    if ($null -ne $section) { return (Get-ConfigValue -InputObject $section -Name "notification") }

    $wac = Get-ConfigValue -InputObject $Config -Name "windowsAdminCenter"
    if ($null -eq $wac) { return $null }
    return (Get-ConfigValue -InputObject $wac -Name "notification")
}

function Unregister-LegacyCertificateTask {
    if (-not (Get-Command -Name "Unregister-ScheduledTask" -ErrorAction SilentlyContinue)) { return }
    foreach ($legacyName in $script:legacyCertificateTaskNames) {
        $existing = Get-ScheduledTask -TaskName $legacyName -ErrorAction SilentlyContinue
        if ($null -eq $existing) { continue }

        try {
            Unregister-ScheduledTask -TaskName $legacyName -Confirm:$false -ErrorAction Stop
            Write-Log "Removed the old '$legacyName' task" -Tag "Ok"
        }
        catch {
            Write-Log "Could not remove '$legacyName': $($_.Exception.Message)" -Tag "Info"
        }
    }
}

# The service half of the name changes when the config gains or loses a role, so the
# lookup goes by the stable prefix rather than one exact name.
function Unregister-CurrentCertificateTask {
    $existing = @(Get-ScheduledTask -TaskName ("{0}*" -f $script:certificateTaskPrefix) -ErrorAction SilentlyContinue)
    foreach ($task in $existing) {
        Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction Stop
    }
}

function Register-StudioCertificateTask {
    param(
        [Parameter(Mandatory)][object]$Config,
        [Parameter(Mandatory)][string]$ConfigFilePath
    )

    $task = Get-CertificateTaskSection -Config $Config
    if ($null -eq $task) {
        Write-Log "config.json has no certificateTask section - nothing renews on its own" -Tag "Info"
        return $true
    }
    if (-not [bool](Get-ConfigValue -InputObject $task -Name "enabled" -Default $false)) {
        Write-Log "The nightly certificate task is switched off" -Tag "Info"
        Unregister-LegacyCertificateTask
        if (Get-Command -Name "Unregister-ScheduledTask" -ErrorAction SilentlyContinue) {
            try { Unregister-CurrentCertificateTask }
            catch { Write-Log "Could not remove the nightly certificate task: $($_.Exception.Message)" -Tag "Info" }
        }
        return $true
    }

    if (-not (Get-Command -Name "Register-ScheduledTask" -ErrorAction SilentlyContinue)) {
        Write-Log "The ScheduledTasks module is unavailable - certificates will not renew on their own" -Tag "Error"
        return $false
    }

    $deployDirectory = Get-StudioDeployDirectory -RenewalTask $task
    $startTime       = Get-ConfigText -InputObject $task -Name "time" -Default "03:00"
    $taskDisplayName = Get-CertificateTaskDisplayName -Config $Config

    try {
        # The task must not depend on wherever this run happened to be started from -
        # a share, a USB stick, a folder someone tidies up next week.
        # Only the parts this design can actually reach, and the action names them so
        # the task loads exactly what was staged for it.
        $taskPart       = @(Get-StudioTaskPart -Task "Certificate" -Config $Config)
        $deployment     = Copy-StudioDeployment -DeployDirectory $deployDirectory -ConfigFilePath $ConfigFilePath -Part $taskPart
        $deployedScript = [string]$deployment.ScriptPath
        $deployedConfig = [string]$deployment.ConfigPath

        $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -ConfigPath "{1}" -Task Certificate -NoGui -Part "{2}"' -f `
            $deployedScript, $deployedConfig, ($taskPart -join ",")

        Unregister-CurrentCertificateTask

        $action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arguments -WorkingDirectory $deployDirectory
        $trigger = New-ScheduledTaskTrigger -Daily -At ([datetime]::Parse($startTime))
        # An hour of jitter, so a fleet of servers does not hit the ACME rate limit at
        # the same second every morning.
        $trigger.RandomDelay = "PT1H"
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)

        $null = Register-ScheduledTask -TaskName $taskDisplayName -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings `
            -Description "Windows Server Role Studio - renews the certificates this server serves" -ErrorAction Stop
    }
    catch {
        Write-Log "Could not register '$taskDisplayName': $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    Unregister-LegacyCertificateTask
    Write-Log "Registered '$taskDisplayName' - daily at $startTime as SYSTEM, with up to an hour of jitter" -Tag "Ok"
    return $true
}

# One job, whatever this server holds. Each role's renewal is its own function and
# reports on its own; this only decides which of them there is anything to do for, and
# hands back the worst outcome, so a failure anywhere fails the task.
# One branch of that job. The part it lives in may not be staged beside this task: the
# task's -Part list is written from the same config sections these branches are gated
# on, so the two cannot disagree - but a config edited by hand, or a task registered by
# a run against a different design, can leave a branch reachable and its part absent.
# Without this, that is 'Invoke-WacCertificateTask is not recognized' at 03:00. With it,
# it is the part that is missing and the run that puts it back.
function Invoke-CertificateBranch {
    param(
        [Parameter(Mandatory)][string]$Function,
        [Parameter(Mandatory)][string]$Part,
        [Parameter(Mandatory)][string]$Role,
        [object]$Config
    )

    if ($null -eq (Get-Command -Name $Function -ErrorAction SilentlyContinue)) {
        Write-Log "This task was staged without '$Part', so nothing here can renew the $Role certificate" -Tag "Error"
        Write-Log "    Run the configuration again on this server - the task's part list is written when it is registered" -Tag "Error"
        return 1
    }

    $script:currentRole = $Role
    $result = [int](& $Function -Config $Config)
    $script:currentRole = ""
    return $result
}

function Invoke-CertificateTask {
    param([object]$Config)

    $worst = 0
    $ran   = $false

    # Each branch is gated on its own config section, and that gate is also what decides
    # whether its part is staged beside this task - see Get-StudioTaskPart. Keep the two
    # in step: a new branch here is a new entry there.
    if ($null -ne (Get-ConfigValue -InputObject $Config -Name "windowsAdminCenter")) {
        $ran = $true
        $result = [int](Invoke-CertificateBranch -Function "Invoke-WacCertificateTask" -Part "Role.Wac.ps1" `
            -Role "WindowsAdminCenter" -Config $Config)
        if ($result -gt $worst) { $worst = $result }
    }

    if ($null -ne (Get-ConfigValue -InputObject $Config -Name "remoteDesktop")) {
        $ran = $true
        $result = [int](Invoke-CertificateBranch -Function "Invoke-RdsCertificateTask" -Part "Role.Rds.ps1" `
            -Role "Remote-Desktop-Services" -Config $Config)
        if ($result -gt $worst) { $worst = $result }
    }

    if ($null -ne (Get-ConfigValue -InputObject $Config -Name "exchange")) {
        $ran = $true
        $result = [int](Invoke-CertificateBranch -Function "Invoke-ExchangeCertificateTask" -Part "Role.Exchange.ps1" `
            -Role "Exchange-Server" -Config $Config)
        if ($result -gt $worst) { $worst = $result }
    }

    if (Test-CertificateTaskHypervOwner -Config $Config) {
        $ran = $true
        $result = [int](Invoke-CertificateBranch -Function "Invoke-HypervS2dCertificateTask" -Part "Role.Hyperv.S2d.ps1" `
            -Role "Hyper-V" -Config $Config)
        if ($result -gt $worst) { $worst = $result }
    }

    if (Test-CertificateTaskScepOwner -Config $Config) {
        $ran = $true
        $result = [int](Invoke-CertificateBranch -Function "Invoke-AdcsScepCertificateTask" -Part "Role.Adcs.Ndes.ps1" `
            -Role "AD-Certificate" -Config $Config)
        if ($result -gt $worst) { $worst = $result }
    }

    if (-not $ran) {
        Write-Log "No role in this config holds a certificate - the task has nothing to renew" -Tag "Info"
    }
    return $worst
}