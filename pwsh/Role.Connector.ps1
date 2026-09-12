# Role provider: Microsoft Entra private network connector.
#
# Dot-sourced by Configure-ServerRoles.ps1 - not runnable on its own. Everything
# here lands in that script's scope, so $script: variables and functions are shared
# with every other part. Use $scriptRootPath, never $PSScriptRoot: inside this file
# $PSScriptRoot is the pwsh folder, not the folder the run was started from.

# ===========================[ Entra private network connector ]===========================
# The third vendor-installer role, after Windows Admin Center and Azure Arc, and for
# the same reason: there is no Windows feature for it, only an installer to fetch.
# Two steps, deliberately separable: the installer runs with REGISTERCONNECTOR="false"
# /q so nothing pops an interactive sign-in on a server, then RegisterConnector.ps1 -
# shipped inside the installation - registers against the tenant with a token.
#
# This provider is the user's own Install-EntraPrivateNetworkConnector.ps1 in the
# repo's provider shape (it is kept in old-scripts/ for reference). Everything below
# that looks like a detail was paid for there, in failed registrations that all report
# the same useless string:
#
#   1. The token is acquired ON THIS SERVER with the DEVICE CODE flow, which is the whole
#      point: the server prints a URL and a code, somebody authenticates on a phone or a
#      laptop, and no browser, no second machine and no file copying is involved. Server
#      Core is then no different from a GUI install. Two things make it work rather than
#      return AADSTS90133 or a token the registration backend refuses: the authority is
#      TENANT-SCOPED (device code is unsupported under /common, and a token with an
#      ambiguous tenant context is refused), and the device-code callback is a compiled
#      C# type - PowerShell 5.1 cannot marshal a scriptblock as a Func<> delegate onto a
#      threadpool thread. Conditional Access is what can still refuse it: the
#      "Authentication flows" control blocks device code sign-in and authentication
#      transfer together, and the registration then answers "invalid authenticatedToken",
#      naming neither the flow nor the policy. Allow it, or use the fallback below.
#   2. RegisterConnector.ps1 declares -Token as [String]. Handing it a SecureString makes
#      PowerShell coerce it through .ToString(), so the backend is sent the literal
#      "System.Security.SecureString" and answers "invalid authenticatedToken. Value:''".
#      The raw JWT string is the only thing that works.
#   3. Registration has to run in a FRESH PowerShell process, and step 1 is exactly why:
#      this session has now loaded Microsoft.Identity.Client.dll to do the device-code
#      sign-in, .NET will not load the copy the connector module wants beside it, and
#      RegisterConnector.ps1 then forwards an EMPTY token - the same error string again,
#      from a completely different cause. The GUI installer never meets this because it
#      registers in a clean process; Register-Connector spawns one.
#   4. The installer returns before the connector's registry key exists, and
#      RegisterConnector.ps1 reads that key ($MANUFACTURERREGKEY). Wait-ConnectorReady
#      polls for all three install signals instead of sleeping and hoping.
#
# The fallback, for a tenant whose Conditional Access blocks the device code flow:
# -Task ConnectorToken signs in interactively on a machine that has a browser and a
# connector installed, writes the token to a file, and the server reads that file
# instead. It is the same token either way, so nothing downstream changes.
#
# The token is never in config.json whichever way it was acquired: it expires in about
# an hour, so a copy somebody keeps is a dead value. An unattended run that can neither
# show a device code nor find a token file says which setting is empty rather than
# failing inside the registration - the same rule the Arc secret follows.
#
# Two network truths worth knowing before the first run: the connector authenticates
# with client certificates, so TLS inspection between this server and *.msappproxy.net
# breaks it invisibly - and the Conditional Access control above refuses the sign-in
# before any of this is reached. The studio carries the same warning on the blade.

# The subscription GUID in this URL is Microsoft's own installer distribution id, not a
# tenant of yours - it is the same link the Entra admin center hands out, which is why it
# is a constant here and not a field anybody has to fill in.
$script:connectorDefaultDownloadUrl = "https://download.msappproxy.net/subscription/d3c8b69d-6bf7-42be-a529-3fe9c2e70c90/connector/DownloadConnectorInstaller"
# The SCM name is WAPCSvc; "Microsoft Entra private network connector" is the display name.
$script:connectorServiceName = "WAPCSvc"
$script:connectorModuleName = "MicrosoftEntraPrivateNetworkConnectorPSModule"
# Renamed from "Microsoft AAD App Proxy Connector" in current connector versions.
$script:connectorRegistryKey = "HKLM:\SOFTWARE\Microsoft\Microsoft Entra private network connector"
$script:connectorAppId = "55747057-9b5d-4bd4-b387-abf52a8bd489"
$script:connectorRegistrationScope = "https://proxy.cloudwebappproxy.net/registerapp/user_impersonation"
# .NET Framework 4.7.2 = release key 461808.
$script:connectorDotNetRelease = 461808
$script:connectorReadyTimeoutSeconds = 180
$script:connectorReadyPollSeconds = 5
$script:connectorTokenFileName = "connector-registration-token.txt"

function Get-ConnectorInstallPath {
    return (Join-Path -Path $env:ProgramFiles -ChildPath "Microsoft Entra private network connector")
}

function Get-ConnectorModulePath {
    return (Join-Path -Path (Get-ConnectorInstallPath) -ChildPath "Modules")
}

function Get-ConnectorModuleFolder {
    return (Join-Path -Path (Get-ConnectorModulePath) -ChildPath $script:connectorModuleName)
}

# The service alone is not an installation: an interrupted install leaves it registered
# with no module folder behind it, and the registration script is what needs both.
function Test-ConnectorInstalled {
    $serviceExists = ($null -ne (Get-Service -Name $script:connectorServiceName -ErrorAction SilentlyContinue))
    $moduleExists = Test-Path -LiteralPath (Get-ConnectorModuleFolder)
    $scriptExists = Test-Path -LiteralPath (Join-Path -Path (Get-ConnectorInstallPath) -ChildPath "RegisterConnector.ps1")

    Write-Log "Service $serviceExists, module folder $moduleExists, RegisterConnector.ps1 $scriptExists" -Tag "Debug"
    return ($serviceExists -and $moduleExists -and $scriptExists)
}

# An unregistered connector has nothing to connect to and stops itself, so a service that
# is still running is a connector holding a valid trust certificate. It is only read that
# way for an installation this run did not just create - a service that happens to be up
# seconds after a REGISTERCONNECTOR="false" install has proved nothing yet.
function Test-ConnectorRegistered {
    $service = Get-Service -Name $script:connectorServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service) { return $false }
    return ([string]$service.Status -eq "Running")
}

function Test-ConnectorDotNetVersion {
    $release = 0
    try {
        $key = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction Stop
        $release = [int]$key.Release
    }
    catch {
        Write-Log "The .NET Framework 4 full profile registry key is missing: $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    if ($release -ge $script:connectorDotNetRelease) {
        Write-Log ".NET Framework release key $release meets the connector's 4.7.2 minimum" -Tag "Debug"
        return $true
    }
    Write-Log ".NET Framework release key $release is below $($script:connectorDotNetRelease) (4.7.2) - the connector will not install" -Tag "Error"
    return $false
}

# The connector talks TLS 1.2 only. The process-level setting is for our own download;
# the SCHANNEL keys are the machine's, so they are repaired only when something has
# explicitly switched TLS 1.2 off - a default-configured server has no keys at all and
# is left exactly as it is.
function Confirm-ConnectorTls12 {
    [System.Net.ServicePointManager]::SecurityProtocol =
        [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

    $paths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
    )
    foreach ($path in $paths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }

        $values = $null
        try { $values = Get-ItemProperty -Path $path -ErrorAction Stop }
        catch { continue }

        $disabled = $false
        if (($null -ne $values.Enabled) -and ([int]$values.Enabled -eq 0)) { $disabled = $true }
        if (($null -ne $values.DisabledByDefault) -and ([int]$values.DisabledByDefault -eq 1)) { $disabled = $true }
        if (-not $disabled) { continue }

        Write-Log "TLS 1.2 is switched off at '$path' - the connector cannot reach its service without it" -Tag "Warn"
        try {
            Set-ItemProperty -Path $path -Name "Enabled" -Value 1 -Type DWord -Force -ErrorAction Stop
            Set-ItemProperty -Path $path -Name "DisabledByDefault" -Value 0 -Type DWord -Force -ErrorAction Stop
            Write-Log "TLS 1.2 re-enabled at '$path' - a restart is needed before Schannel picks it up" -Tag "Info"
        }
        catch {
            Write-Log "Could not re-enable TLS 1.2 at '$path': $($_.Exception.Message)" -Tag "Error"
        }
    }
}

# Same shape as the Arc and WAC downloads: lands in <script root>\downloads because
# $env:TEMP is per account and the resume task runs as SYSTEM, refuses an error page
# by size, and proves the file is a PE image before handing it to anything.
function Get-ConnectorInstallerPath {
    param([Parameter(Mandatory)][object]$Agent)

    $source = [string](Get-ConfigText -InputObject $Agent -Name "source" -Default "download")
    if ($source -eq "localPath") {
        $stagedPath = [string](Get-ConfigText -InputObject $Agent -Name "installerPath" -Default "")
        if ([string]::IsNullOrWhiteSpace($stagedPath)) {
            throw "The connector source is 'localPath' but no installerPath is set."
        }
        if (-not (Test-Path -LiteralPath $stagedPath)) {
            throw "The connector installer '$stagedPath' does not exist."
        }
        Write-Log "Using the staged installer '$stagedPath'" -Tag "Info"
        return $stagedPath
    }

    $url = [string](Get-ConfigText -InputObject $Agent -Name "downloadUrl" -Default $script:connectorDefaultDownloadUrl)

    $downloadDirectory = Join-Path -Path $scriptRootPath -ChildPath "downloads"
    try {
        if (-not (Test-Path -LiteralPath $downloadDirectory)) {
            $null = New-Item -Path $downloadDirectory -ItemType Directory -Force -ErrorAction Stop
        }
    }
    catch {
        Write-Log "Could not use '$downloadDirectory' ($($_.Exception.Message)) - downloading to '$env:TEMP' instead" -Tag "Info"
        $downloadDirectory = $env:TEMP
    }

    $target = Join-Path -Path $downloadDirectory -ChildPath "MicrosoftEntraPrivateNetworkConnectorInstaller.exe"
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue
    }
    Invoke-ArcDownload -Url $url -Destination $target

    # The redirector promises nothing about what it serves; the file does. MZ is a
    # PE image and therefore the installer - anything else is an error page that
    # would fail minutes later without naming the cause.
    $stream = $null
    try {
        $stream = [System.IO.File]::OpenRead($target)
        $header = New-Object byte[] 2
        $null = $stream.Read($header, 0, 2)
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
    if (-not ($header[0] -eq 0x4D -and $header[1] -eq 0x5A)) {
        throw "'$target' is not a Windows executable - the download served something else."
    }
    return $target
}

# The installer exits before the files, the registry key and the service are all in
# place. RegisterConnector.ps1 reads that registry key, so registering inside the gap
# fails on $MANUFACTURERREGKEY - an error naming a variable in Microsoft's script.
function Wait-ConnectorReady {
    $elapsed = 0
    $modulesReady = $false
    $registryReady = $false
    $serviceReady = $false

    Write-Log "Waiting for the installation to settle (up to $($script:connectorReadyTimeoutSeconds) seconds)" -Tag "Run"
    while ($elapsed -lt $script:connectorReadyTimeoutSeconds) {
        $modulesReady = Test-Path -LiteralPath (Get-ConnectorModuleFolder)
        $registryReady = Test-Path -LiteralPath $script:connectorRegistryKey
        $serviceReady = ($null -ne (Get-Service -Name $script:connectorServiceName -ErrorAction SilentlyContinue))

        if ($modulesReady -and $registryReady -and $serviceReady) {
            Write-Log "Installation complete after $elapsed seconds" -Tag "Ok"
            return $true
        }

        Write-Log "[$elapsed s] modules $modulesReady, registry $registryReady, service $serviceReady" -Tag "Debug"
        Start-Sleep -Seconds $script:connectorReadyPollSeconds
        $elapsed += $script:connectorReadyPollSeconds
    }

    if (-not $modulesReady) { Write-Log "The module folder '$(Get-ConnectorModuleFolder)' never appeared" -Tag "Error" }
    if (-not $registryReady) { Write-Log "The registry key '$($script:connectorRegistryKey)' never appeared" -Tag "Error" }
    if (-not $serviceReady) { Write-Log "The '$($script:connectorServiceName)' service was never registered" -Tag "Error" }
    return $false
}

function Install-Connector {
    param([Parameter(Mandatory)][string]$InstallerPath)

    Write-Log "Installing the connector quietly, registration deferred" -Tag "Run"
    # REGISTERCONNECTOR="false" keeps the installer from popping the interactive
    # sign-in; /q accepts the EULA without a window to click it in.
    $process = Start-Process -FilePath $InstallerPath -ArgumentList 'REGISTERCONNECTOR="false" /q' -Wait -PassThru
    if ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) {
        throw "The connector installer exited with code $($process.ExitCode)."
    }
    if ($process.ExitCode -eq 3010) {
        Write-Log "Installed - the installer asks for a reboot, which registration does not need" -Tag "Info"
    }
    if (-not (Wait-ConnectorReady)) {
        throw "The installer finished but the installation never became usable."
    }
    Write-Log "Connector installed" -Tag "Ok"
}

# ---------------------------[ The registration token ]---------------------------

function ConvertFrom-ConnectorSecureString {
    param([Parameter(Mandatory)][System.Security.SecureString]$Value)

    $pointer = [IntPtr]::Zero
    try {
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
        return [Runtime.InteropServices.Marshal]::PtrToStringAuto($pointer)
    }
    finally {
        if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    }
}

# A JWT this server cannot verify is still a JWT it can read. The four claims below are
# exactly what the backend checks, so decoding them turns "invalid authenticatedToken"
# into a sentence naming the wrong tenant, the wrong audience or the wrong flow.
function Write-ConnectorTokenDiagnostic {
    param(
        [Parameter(Mandatory)][string]$Token,
        [string]$TenantId = ""
    )

    try {
        $parts = $Token.Split(".")
        if ($parts.Count -lt 2) {
            Write-Log "The registration token is not a JWT ($($Token.Length) characters) - it will be rejected" -Tag "Error"
            return
        }

        $payload = $parts[1].Replace("-", "+").Replace("_", "/")
        switch ($payload.Length % 4) {
            2 { $payload = $payload + "==" }
            3 { $payload = $payload + "=" }
        }

        $json = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payload))
        $claims = $json | ConvertFrom-Json
        $names = @($claims.PSObject.Properties.Name)

        $audience = [string]$claims.aud
        $tenant = [string]$claims.tid
        $user = "unknown"
        if ($names -contains "upn") { $user = [string]$claims.upn }
        elseif ($names -contains "preferred_username") { $user = [string]$claims.preferred_username }

        Write-Log "Token audience $audience, tenant $tenant, user $user" -Tag "Debug"
        if ($audience -notlike "*cloudwebappproxy.net*") {
            Write-Log "The token was not issued for the connector registration service - registration will be refused" -Tag "Error"
        }
        if ((-not [string]::IsNullOrWhiteSpace($TenantId)) -and (-not [string]::IsNullOrWhiteSpace($tenant)) -and ($tenant -ne $TenantId)) {
            Write-Log "The token belongs to tenant $tenant, not $TenantId - registration will be refused" -Tag "Error"
        }
        $expiry = ""
        if ($names -contains "exp") {
            $expiry = ([DateTimeOffset]::FromUnixTimeSeconds([int64]$claims.exp)).LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss")
            Write-Log "Token expires $expiry" -Tag "Debug"
        }
    }
    catch {
        Write-Log "Could not decode the token for diagnostics: $($_.Exception.Message)" -Tag "Debug"
    }
}

# PowerShell 5.1 cannot hand a scriptblock to MSAL as a Func<DeviceCodeResult, Task>:
# the callback is invoked on a threadpool thread, where there is no runspace to run it
# in. A compiled C# type has no such problem, and writing through Console.WriteLine
# reaches the console without one either.
function Register-ConnectorDeviceCodeType {
    if (([System.Management.Automation.PSTypeName]"WsrsDeviceCodeHelper").Type) { return }

    $source = @"
using System;
using System.Threading.Tasks;
using Microsoft.Identity.Client;

public static class WsrsDeviceCodeHelper
{
    public static Func<DeviceCodeResult, Task> GetCallback()
    {
        return (DeviceCodeResult result) =>
        {
            Console.WriteLine("");
            Console.WriteLine("  ====================================================");
            Console.WriteLine("   Sign in to register this connector");
            Console.WriteLine("  ====================================================");
            Console.WriteLine("   1. Open a browser on any device - phone, laptop");
            Console.WriteLine("   2. Go to    : " + result.VerificationUrl);
            Console.WriteLine("   3. Enter    : " + result.UserCode);
            Console.WriteLine("   4. Sign in with an Application Administrator");
            Console.WriteLine("   Code expires: " + result.ExpiresOn.ToLocalTime());
            Console.WriteLine("  ====================================================");
            Console.WriteLine("");
            return Task.FromResult(0);
        };
    }
}
"@

    $msalPath = Join-Path -Path (Get-ConnectorModuleFolder) -ChildPath "Microsoft.Identity.Client.dll"
    Add-Type -TypeDefinition $source -ReferencedAssemblies $msalPath, "System.Runtime", "mscorlib" -ErrorAction Stop
    Write-Log "Device code callback compiled" -Tag "Debug"
}

function Import-ConnectorMsal {
    $moduleFolder = Get-ConnectorModuleFolder
    if (-not (Test-Path -LiteralPath $moduleFolder)) {
        throw "The connector module is not at '$moduleFolder'."
    }

    # From inside the module folder, so the MSAL assembly's neighbours resolve the way
    # the connector's own scripts expect them to.
    Push-Location -LiteralPath $moduleFolder
    try {
        Import-Module (Join-Path -Path ".." -ChildPath $script:connectorModuleName) -ErrorAction Stop
        if (-not ([System.Management.Automation.PSTypeName]"Microsoft.Identity.Client.PublicClientApplicationBuilder").Type) {
            Add-Type -Path ".\Microsoft.Identity.Client.dll" -ErrorAction Stop
        }
    }
    finally {
        Pop-Location
    }
}

# The default path, and the one that makes a headless server no different from a GUI
# install: the code is shown here, the sign-in happens on whatever device the person
# has in their hand.
function Get-ConnectorDeviceCodeToken {
    param([Parameter(Mandatory)][string]$TenantId)

    Import-ConnectorMsal
    Register-ConnectorDeviceCodeType

    # Tenant-scoped, never /common: device code is unsupported there (AADSTS90133), and a
    # token whose tenant context is ambiguous is refused by the registration backend.
    $authority = "https://login.microsoftonline.com/$TenantId"
    $scopes = New-Object -TypeName "System.Collections.ObjectModel.Collection[string]"
    $scopes.Add($script:connectorRegistrationScope)

    Write-Log "Starting the device code sign-in against tenant $TenantId" -Tag "Run"
    $application = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($script:connectorAppId).WithAuthority($authority).WithDefaultRedirectUri().Build()
    $callback = [WsrsDeviceCodeHelper]::GetCallback()
    $result = $application.AcquireTokenWithDeviceCode($scopes, $callback).ExecuteAsync().GetAwaiter().GetResult()

    if (($null -eq $result) -or [string]::IsNullOrEmpty($result.AccessToken)) {
        throw "The sign-in completed but no access token came back."
    }

    $signedInTenant = [string]$result.TenantId
    if ((-not [string]::IsNullOrWhiteSpace($signedInTenant)) -and ($signedInTenant -ne $TenantId)) {
        Write-Log "Signed in to tenant $signedInTenant, not $TenantId - registration will be refused. Use an account whose home tenant is $TenantId" -Tag "Error"
    }
    Write-Log "Token acquired, valid until $($result.ExpiresOn.ToLocalTime())" -Tag "Ok"
    return [string]$result.AccessToken
}

# Precedence, and it is the script this came from: a token file wins when there is one,
# because somebody went to the trouble of minting it; otherwise the server signs in
# itself with the device code flow.
function Get-ConnectorTokenValue {
    param(
        [object]$Connector,
        [Parameter(Mandatory)][string]$TenantId,
        [string]$Mode = "deviceCode"
    )

    $tokenFile = [string](Get-ConfigText -InputObject $Connector -Name "tokenFile" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($tokenFile)) {
        if (-not (Test-Path -LiteralPath $tokenFile)) {
            throw "The registration token file '$tokenFile' does not exist - mint one with -Task ConnectorToken on a machine with a browser."
        }
        Write-Log "Reading the registration token from '$tokenFile'" -Tag "Get"
        return ((Get-Content -LiteralPath $tokenFile -Raw).Trim())
    }

    $candidate = Join-Path -Path $scriptRootPath -ChildPath $script:connectorTokenFileName
    if (Test-Path -LiteralPath $candidate) {
        Write-Log "Using the registration token found beside the script ('$candidate')" -Tag "Get"
        return ((Get-Content -LiteralPath $candidate -Raw).Trim())
    }

    if ($Mode -eq "tokenFile") {
        throw "Registration is set to use a minted token but no token file was found - run -Task ConnectorToken on a machine with a browser and copy the file beside this script."
    }

    # Somebody has to read a code off this screen and type it somewhere else.
    if ($script:noGui -or $script:isResume -or (-not [Environment]::UserInteractive)) {
        throw "The device code sign-in needs somebody at the console. Run this interactively, or mint a token with -Task ConnectorToken elsewhere and set entraConnector.tokenFile."
    }

    try {
        return (Get-ConnectorDeviceCodeToken -TenantId $TenantId)
    }
    catch {
        Write-Log "The device code sign-in failed: $($_.Exception.Message)" -Tag "Error"
        Write-Log "    If Conditional Access blocks the device code flow, mint a token with -Task ConnectorToken elsewhere and copy it beside this script" -Tag "Info"
        throw
    }
}

# ---------------------------[ Registration ]---------------------------

# The connector writes the real reason to the Application log under its own source; the
# PowerShell failure says only that the child process exited non-zero.
function Write-ConnectorRegistrationError {
    param([string]$TenantId = "")

    $entry = $null
    try {
        $filter = @{
            LogName      = "Application"
            ProviderName = "Microsoft Entra private network connector"
            Level        = 2
        }
        $entry = Get-WinEvent -FilterHashtable $filter -MaxEvents 1 -ErrorAction Stop
    }
    catch {
        Write-Log "No connector error event yet - the entry can lag a few seconds" -Tag "Debug"
        return
    }
    if ($null -eq $entry) { return }

    $message = [string]$entry.Message
    Write-Log "Connector event $($entry.TimeCreated): $message" -Tag "Error"

    if ($message -match "invalid authenticatedToken") {
        Write-Log "    Entra refused the token. Check Conditional Access for the device code flow or authentication transfer, and mint one with -Task ConnectorToken" -Tag "Info"
    }
    elseif ($message -match "Global Administrator|Application Administrator|registration request was denied") {
        Write-Log "    The account was refused: it needs an ACTIVE (not PIM-eligible) Application Administrator role in tenant $TenantId" -Tag "Info"
    }
    elseif ($message -match "enabled application proxy|One or more errors occurred") {
        Write-Log "The token was empty by the time the backend saw it - the interactive sign-in did not complete" -Tag "Debug"
    }
}

function Register-Connector {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$Token
    )

    $installPath = Get-ConnectorInstallPath
    $registerScript = Join-Path -Path $installPath -ChildPath "RegisterConnector.ps1"
    if (-not (Test-Path -LiteralPath $registerScript)) {
        throw "RegisterConnector.ps1 is not at '$registerScript' - the installation is not where this version expects it."
    }

    # A fresh process, always: see point 3 in the part header. It is powershell.exe even
    # when this run is PowerShell 7 - the connector module and its MSAL build are .NET
    # Framework, and Microsoft's script is written for Windows PowerShell.
    #
    # Everything crosses into the child as an environment variable rather than on the
    # command line: the token then never appears in the process list, and a path with a
    # trailing backslash cannot be swallowed by Windows argument quoting.
    $bootstrapPath = Join-Path -Path $env:TEMP -ChildPath "Invoke-ConnectorRegistration.ps1"
    $stdoutPath = Join-Path -Path $env:TEMP -ChildPath "ConnectorRegistration.out.log"
    $stderrPath = Join-Path -Path $env:TEMP -ChildPath "ConnectorRegistration.err.log"

    $bootstrap = @'
Set-StrictMode -Off
$ErrorActionPreference = "Stop"

$plainToken = $env:WSRS_CONNECTOR_TOKEN
$registerScript = $env:WSRS_CONNECTOR_SCRIPT
$modulePath = $env:WSRS_CONNECTOR_MODULEPATH
$moduleName = $env:WSRS_CONNECTOR_MODULENAME
$tenantId = $env:WSRS_CONNECTOR_TENANTID

if ([string]::IsNullOrEmpty($plainToken)) {
    Write-Error "The registration token did not reach the child process."
    exit 3
}

# -Token is [String] in RegisterConnector.ps1. A SecureString here is coerced through
# .ToString() and the backend is handed "System.Security.SecureString".
& $registerScript `
    -modulePath $modulePath `
    -moduleName $moduleName `
    -Authenticationmode Token `
    -Token $plainToken `
    -TenantId $tenantId `
    -Feature ApplicationProxy

exit $LASTEXITCODE
'@

    Set-Content -Path $bootstrapPath -Value $bootstrap -Encoding UTF8
    Write-Log "Registering the connector against tenant '$TenantId' in a clean PowerShell process" -Tag "Run"

    $exitCode = 1
    try {
        $env:WSRS_CONNECTOR_TOKEN = $Token
        $env:WSRS_CONNECTOR_SCRIPT = $registerScript
        $env:WSRS_CONNECTOR_MODULEPATH = ((Get-ConnectorModulePath) + "\")
        $env:WSRS_CONNECTOR_MODULENAME = $script:connectorModuleName
        $env:WSRS_CONNECTOR_TENANTID = $TenantId

        $arguments = @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", ('"' + $bootstrapPath + '"'))
        $process = Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -Wait -PassThru -NoNewWindow `
            -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        $exitCode = [int]$process.ExitCode
    }
    finally {
        foreach ($name in @("WSRS_CONNECTOR_TOKEN", "WSRS_CONNECTOR_SCRIPT", "WSRS_CONNECTOR_MODULEPATH", "WSRS_CONNECTOR_MODULENAME", "WSRS_CONNECTOR_TENANTID")) {
            Remove-Item -Path ("Env:\" + $name) -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $bootstrapPath -Force -ErrorAction SilentlyContinue
    }

    foreach ($outputPath in @($stdoutPath, $stderrPath)) {
        if (-not (Test-Path -LiteralPath $outputPath)) { continue }
        $lines = @(Get-Content -LiteralPath $outputPath -ErrorAction SilentlyContinue |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        foreach ($line in $lines) { Write-Log "[RegisterConnector] $line" -Tag "Debug" }
        Remove-Item -LiteralPath $outputPath -Force -ErrorAction SilentlyContinue
    }

    if ($exitCode -ne 0) {
        Write-ConnectorRegistrationError -TenantId $TenantId
        throw "RegisterConnector.ps1 exited with code $exitCode."
    }
    Write-Log "Registration completed" -Tag "Ok"
}

# A connector that registered starts and stays up. One that did not stops itself a few
# seconds later, which is why the state is read twice rather than once.
function Start-ConnectorService {
    param([int]$SettleSeconds = 10)

    $service = Get-Service -Name $script:connectorServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        Write-Log "The '$($script:connectorServiceName)' service does not exist" -Tag "Error"
        return $false
    }

    if ([string]$service.Status -ne "Running") {
        try {
            Start-Service -Name $script:connectorServiceName -ErrorAction Stop
        }
        catch {
            Write-Log "The connector service would not start: $($_.Exception.Message)" -Tag "Error"
            return $false
        }
    }

    if ($SettleSeconds -gt 0) { Start-Sleep -Seconds $SettleSeconds }
    $service = Get-Service -Name $script:connectorServiceName -ErrorAction SilentlyContinue
    if (($null -eq $service) -or ([string]$service.Status -ne "Running")) {
        Write-Log "The connector service started and stopped again - it is installed but not registered" -Tag "Error"
        return $false
    }

    Write-Log "The '$($script:connectorServiceName)' service is running" -Tag "Ok"
    return $true
}

# ---------------------------[ The token task ]---------------------------
# -Task ConnectorToken, run on a machine that has a browser AND a connector installed
# (the connector ships the MSAL build this uses). It signs in interactively, which is
# the only flow the registration backend accepts, and writes the token to a file to
# carry to the server. The token lives about an hour.
function Invoke-ConnectorTokenTask {
    param([object]$Config)

    $connector = Get-ConfigValue -InputObject $Config -Name "entraConnector"
    if ($null -eq $connector) {
        Write-Log "config.json has no entraConnector section - there is no tenant to mint a token for" -Tag "Error"
        return 1
    }

    $tenantId = [string](Get-ConfigText -InputObject $connector -Name "tenantId" -Default "")
    if ([string]::IsNullOrWhiteSpace($tenantId)) {
        Write-Log "entraConnector.tenantId is empty - a token has to be scoped to one tenant" -Tag "Error"
        return 1
    }

    if ($script:noGui -or (-not [Environment]::UserInteractive)) {
        Write-Log "Minting a token needs an interactive sign-in - run this on a machine with a browser, without -NoGui" -Tag "Error"
        return 1
    }

    $moduleFolder = Get-ConnectorModuleFolder
    if (-not (Test-Path -LiteralPath $moduleFolder)) {
        Write-Log "The connector module is not at '$moduleFolder'" -Tag "Error"
        Write-Log "Install the connector on THIS machine first - the token is minted with the MSAL library it ships" -Tag "Error"
        return 1
    }

    Confirm-ConnectorTls12

    try {
        Import-ConnectorMsal
    }
    catch {
        Write-Log "Could not load the connector's MSAL library: $($_.Exception.Message)" -Tag "Error"
        return 1
    }

    # Tenant-scoped, never /common: a token whose tenant context is ambiguous is refused
    # by the registration backend with the same string as everything else.
    $authority = "https://login.microsoftonline.com/$tenantId"
    $scopes = New-Object -TypeName "System.Collections.ObjectModel.Collection[string]"
    $scopes.Add($script:connectorRegistrationScope)

    Write-Log "Opening a browser for interactive sign-in against tenant $tenantId" -Tag "Run"
    Write-Log "Sign in with an account holding an active Application Administrator role" -Tag "Info"

    $token = ""
    try {
        $application = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($script:connectorAppId).WithAuthority($authority).WithDefaultRedirectUri().Build()
        $result = $application.AcquireTokenInteractive($scopes).ExecuteAsync().GetAwaiter().GetResult()
        $token = [string]$result.AccessToken
    }
    catch {
        Write-Log "Interactive sign-in failed: $($_.Exception.Message)" -Tag "Error"
        return 1
    }

    if ([string]::IsNullOrWhiteSpace($token)) {
        Write-Log "Sign-in succeeded but no access token came back" -Tag "Error"
        return 1
    }

    Write-ConnectorTokenDiagnostic -Token $token -TenantId $tenantId

    $outputPath = [string](Get-ConfigText -InputObject $connector -Name "tokenFile" -Default "")
    if ([string]::IsNullOrWhiteSpace($outputPath)) {
        $outputPath = Join-Path -Path $scriptRootPath -ChildPath $script:connectorTokenFileName
    }

    try {
        Set-Content -Path $outputPath -Value $token -Encoding ASCII -NoNewline -ErrorAction Stop
    }
    catch {
        Write-Log "Could not write the token to '$outputPath': $($_.Exception.Message)" -Tag "Error"
        return 1
    }

    Write-Log "Registration token written to '$outputPath'" -Tag "Ok"
    Write-Log "    Valid about an hour. Copy it to the connector server - the run reads it from that path, or from beside the script" -Tag "Info"
    Write-Log "Delete the file once the connector is registered: while it lives, it registers connectors into your tenant." -Tag "Info"
    return 0
}

# ---------------------------[ Prerequisites ]---------------------------
function Test-ConnectorPrerequisite {
    param([object]$Config)

    $connector = Get-ConfigValue -InputObject $Config -Name "entraConnector"
    if ($null -eq $connector) {
        Write-Log "config.json has no entraConnector section" -Tag "Error"
        return $false
    }

    $passed = $true
    if (-not (Test-ConnectorDotNetVersion)) { $passed = $false }

    # Anything that is not "manual" ends up registering, so the tenant is required for
    # the device code sign-in and for a minted token alike.
    $registration = Get-ConfigText -InputObject $connector -Name "registration" -Default "deviceCode"
    if ($registration -ne "manual") {
        $tenantId = Get-ConfigText -InputObject $connector -Name "tenantId"
        if ([string]::IsNullOrWhiteSpace($tenantId)) {
            Write-Log "entraConnector.tenantId is empty - token registration has nowhere to register" -Tag "Error"
            $passed = $false
        }
    }

    # Reported, not enforced - the failure it predicts arrives during registration
    # and names nothing useful when it does.
    Write-Log "    Needs the device code flow and authentication transfer allowed in Conditional Access, and no TLS inspection towards *.msappproxy.net" -Tag "Info"
    return $passed
}

# ---------------------------[ Entry point ]---------------------------
function Invoke-ConnectorConfiguration {
    param([object]$Config)

    $connector = Get-ConfigValue -InputObject $Config -Name "entraConnector"
    if ($null -eq $connector) {
        return (New-RoleResult -Status "Failed" -Message "config.json has no entraConnector section")
    }

    # deviceCode (the default): this server signs in itself and shows the code.
    # tokenFile: a token minted elsewhere, for a tenant that blocks that flow.
    # manual: install only. An older config saying "token" lands on the default, which
    # still prefers a token file when it finds one.
    $registration = Get-ConfigText -InputObject $connector -Name "registration" -Default "deviceCode"
    $tenantId = Get-ConfigText -InputObject $connector -Name "tenantId"
    $force = [bool](Get-ConfigValue -InputObject $connector -Name "forceRegistration" -Default $false)

    Confirm-ConnectorTls12

    $justInstalled = $false
    if (-not (Test-ConnectorInstalled)) {
        try {
            $installer = Get-ConnectorInstallerPath -Agent $connector
            Install-Connector -InstallerPath $installer
            $justInstalled = $true
        }
        catch {
            return (New-RoleResult -Status "Failed" -Message "Install failed: $($_.Exception.Message)")
        }
    }
    else {
        Write-Log "The connector is already installed" -Tag "Info"
    }

    # Registration is read off an installation this run did not create: a service that
    # happens to be up seconds after the installer ran has proved nothing yet.
    if ((-not $justInstalled) -and (Test-ConnectorRegistered)) {
        if (-not $force) {
            return (New-RoleResult -Status "Completed" -Message "Connector installed and registered - it appears in the Entra admin center under Global Secure Access > Connectors")
        }
        Write-Log "forceRegistration is set - registering again to renew the connector's trust certificate" -Tag "Info"
    }

    if ($registration -eq "manual") {
        return (New-RoleResult -Status "ManualStepRequired" -Message "Installed but not registered - run RegisterConnector.ps1 from '$(Get-ConnectorInstallPath)' (registration is set to manual)")
    }

    $token = ""
    try {
        $token = Get-ConnectorTokenValue -Connector $connector -TenantId $tenantId -Mode $registration
    }
    catch {
        return (New-RoleResult -Status "ManualStepRequired" -Message "Installed but not registered: $($_.Exception.Message)")
    }
    if ([string]::IsNullOrWhiteSpace($token)) {
        return (New-RoleResult -Status "ManualStepRequired" -Message "Installed but not registered - the registration token was empty")
    }

    Write-ConnectorTokenDiagnostic -Token $token -TenantId $tenantId

    try {
        Register-Connector -TenantId $tenantId -Token $token
    }
    catch {
        return (New-RoleResult -Status "ManualStepRequired" -Message "Installed but the registration failed: $($_.Exception.Message)")
    }
    finally {
        $token = ""
    }

    if (-not (Start-ConnectorService)) {
        return (New-RoleResult -Status "ManualStepRequired" -Message "Registered but the service is not running - check outbound 443 to *.msappproxy.net and *.servicebus.windows.net")
    }
    return (New-RoleResult -Status "Completed" -Message "Connector installed, registered and running")
}
