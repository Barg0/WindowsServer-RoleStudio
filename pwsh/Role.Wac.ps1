# Role provider: Windows Admin Center.
#
# Dot-sourced by Configure-ServerRoles.ps1 - not runnable on its own. Everything
# here lands in that script's scope, so $script: variables and functions are shared
# with every other part. Use $scriptRootPath, never $PSScriptRoot: inside this file
# $PSScriptRoot is the pwsh folder, not the folder the run was started from.

# ===========================[ Windows Admin Center ]===========================
# The one role in this script that installs rather than only configures. Windows
# Admin Center has no Install-WindowsFeature line to print - on Server 2025 the
# Server Manager entry is a downloader, not a payload - so "a missing role stops
# the run" has nothing to say here. The installer is fetched and run instead, and
# that is a deliberate exception rather than an oversight.
#
# What follows the install is the part that actually breaks in practice: a
# certificate whose private key the gateway service cannot read, or a renewed
# certificate nobody rebound. Both are handled here, and the daily task re-runs
# exactly the same code path.

# ---------------------------[ This provider is v2 only ]---------------------------
# Windows Admin Center v1 - the MSI, the "ServerManagementGateway" service, SME_PORT,
# http.sys as the thing that serves TLS - is gone from this file on purpose, and it is not
# a gap to fill in later. aka.ms/WACDownload has served the v2 gateway for years, v1 is out
# of support, and nobody deploying a new server installs it. Carrying it cost a second
# installer command line, a second uninstall path, a second service name, and - the
# expensive one - a whole netsh binding mechanism that the modern gateway does not use and
# whose *absence* was being read as a fault. Every one of those was a place to be wrong
# about which generation was in front of us, and being wrong there broke the healthy case.
#
# What is left is one shape: an Inno Setup installer, one service, and a Kestrel gateway
# that is configured through its own PowerShell module and verified over TLS.
$script:wacTaskName = "WSRS-WacCertificate"

$script:wacServiceName = "WindowsAdminCenter"

$script:wacDefaultDownloadUrl = "https://aka.ms/WACDownload"

# ---------------------------[ Presence ]---------------------------
function Get-WacService {
    return (Get-Service -Name $script:wacServiceName -ErrorAction SilentlyContinue)
}

function Test-WacInstalled {
    return ($null -ne (Get-WacService))
}

# LocalSystem needs no grant; anything else has to be named on the key file or the
# service starts, fails to open its own certificate, and stops again.
function Get-WacServiceIdentity {
    $service = Get-WacService
    if ($null -eq $service) { return "" }

    try {
        $instance = Get-CimInstance -ClassName "Win32_Service" -Filter ("Name='{0}'" -f $service.Name) -ErrorAction Stop
        return [string]$instance.StartName
    }
    catch {
        Write-Log "Could not read the account '$($service.Name)' runs as: $($_.Exception.Message)" -Tag "Info"
        return ""
    }
}

# ---------------------------[ Download and install ]---------------------------
# Windows PowerShell 5.1 redraws the progress bar on every chunk Invoke-WebRequest
# reads, which turns a 100 MB download into minutes of console rendering. WebClient
# does not draw one at all, and the preference is neutralised anyway for anything
# further down the stack that might.
function Invoke-WacDownload {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Destination
    )

    $previousProgress = $ProgressPreference
    $ProgressPreference = "SilentlyContinue"
    $client = $null

    try {
        # 5.1 defaults to TLS 1.0/1.1, which aka.ms and the PowerShell Gallery both
        # refuse - the failure looks like a connection reset, never like a protocol.
        [System.Net.ServicePointManager]::SecurityProtocol =
            [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

        Write-Log "Downloading $Url" -Tag "Run"
        $client = New-Object System.Net.WebClient
        $client.Headers.Add("User-Agent", "WindowsServerRoleStudio")
        $client.DownloadFile($Url, $Destination)
    }
    finally {
        $ProgressPreference = $previousProgress
        if ($null -ne $client) { $client.Dispose() }
    }

    if (-not (Test-Path -LiteralPath $Destination)) {
        throw "The download reported success but '$Destination' is not there."
    }

    $size = [math]::Round(((Get-Item -LiteralPath $Destination).Length / 1MB), 1)
    Write-Log "Downloaded $size MB to '$Destination'" -Tag "Ok"
}

# The URL is a redirector and its last segment promises nothing, so the first bytes decide
# what actually arrived. A PE image starts "MZ" and is the v2 installer. An OLE compound
# file (D0 CF 11 E0 A1 B1 1A E1) is an MSI - which this provider refuses rather than
# installs: it is the v1 gateway, and an unsupported generation quietly installed by a
# toolbox that then configures it as if it were v2 is worse than a refusal naming it.
# Anything else is an error page saved to disk, which is what a proxy or a captive portal
# hands back, and msiexec's or Inno's version of that failure names neither the file nor
# the reason.
function Get-WacInstallerKind {
    param([Parameter(Mandatory)][string]$Path)

    $bytes  = New-Object byte[] 8
    $read   = 0
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $read = $stream.Read($bytes, 0, 8)
    }
    finally {
        $stream.Dispose()
    }

    if ($read -ge 8) {
        $signature = ($bytes | ForEach-Object { $_.ToString("X2") }) -join ""
        if ($signature -eq "D0CF11E0A1B11AE1") { return "msi" }
    }
    if (($read -ge 2) -and ($bytes[0] -eq 0x4D) -and ($bytes[1] -eq 0x5A)) { return "exe" }

    return "unknown"
}

# One place decides, so the message is the same whether the file was downloaded or staged.
function Confirm-WacInstallerKind {
    param([Parameter(Mandatory)][string]$Path)

    $kind = Get-WacInstallerKind -Path $Path
    if ($kind -eq "exe") { return }

    if ($kind -eq "msi") {
        throw "'$Path' is an MSI, which is the Windows Admin Center v1 gateway. This toolbox configures v2 only - fetch the current installer from $script:wacDefaultDownloadUrl."
    }
    throw "'$Path' is not a Windows executable - a file that lands here is usually an error page saved by a proxy."
}

function Get-WacInstallerPath {
    param([Parameter(Mandatory)][object]$Installer)

    $source = [string](Get-ConfigValue -InputObject $Installer -Name "source" -Default "download")

    if ($source -eq "localPath") {
        # msiPath is what the contract carried while the gateway was still an MSI. It is
        # still read, because an older exported design uses it as the staged-file key -
        # what it points at now has to be the v2 installer, which Confirm-WacInstallerKind
        # is what says.
        $stagedPath = [string](Get-ConfigValue -InputObject $Installer -Name "installerPath" -Default "")
        if ([string]::IsNullOrWhiteSpace($stagedPath)) {
            $stagedPath = [string](Get-ConfigValue -InputObject $Installer -Name "msiPath" -Default "")
        }
        if ([string]::IsNullOrWhiteSpace($stagedPath)) {
            throw "The installer source is 'localPath' but no installerPath is set."
        }
        if (-not (Test-Path -LiteralPath $stagedPath)) {
            throw "The Windows Admin Center installer '$stagedPath' does not exist."
        }
        Confirm-WacInstallerKind -Path $stagedPath
        Write-Log "Using the staged installer '$stagedPath'" -Tag "Info"
        return $stagedPath
    }

    $url = [string](Get-ConfigValue -InputObject $Installer -Name "downloadUrl" -Default $script:wacDefaultDownloadUrl)
    if ([string]::IsNullOrWhiteSpace($url)) { $url = $script:wacDefaultDownloadUrl }

    # Beside the script, where the logs and the run state already live - $env:TEMP is
    # per account, so the same run leaves the installer in one place when a person
    # starts it and in C:\Windows\Temp when the resume task does. A script root that
    # cannot be written to (a share, a read-only copy) falls back to the temp folder.
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

    $download = Join-Path -Path $downloadDirectory -ChildPath "WindowsAdminCenter.download"
    if (Test-Path -LiteralPath $download) {
        Remove-Item -LiteralPath $download -Force -ErrorAction SilentlyContinue
    }
    Invoke-WacDownload -Url $url -Destination $download

    # Checked before it is renamed, so a refusal names the file that was actually fetched
    # rather than one this run invented an extension for.
    Confirm-WacInstallerKind -Path $download

    $target = Join-Path -Path $downloadDirectory -ChildPath "WindowsAdminCenter.exe"
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue
    }
    Move-Item -LiteralPath $download -Destination $target -Force
    Write-Log "Staged the installer as '$target'" -Tag "Info"
    return $target
}

function Install-WacGateway {
    param([Parameter(Mandatory)][object]$WindowsAdminCenter)

    $installer     = Get-ConfigValue -InputObject $WindowsAdminCenter -Name "installer"
    $installerPath = Get-WacInstallerPath -Installer $installer
    $port          = [int](Get-ConfigValue -InputObject $installer -Name "port" -Default 443)

    $installLog = Join-Path -Path (Get-LogRoleDirectory) -ChildPath "windowsadmincenter-install.log"

    # Inno Setup switches: /VERYSILENT is the whole install, and the port is
    # /HTTPSPortNumber. SME_PORT was the v1 MSI property and is silently ignored here, so a
    # design asking for another port would have come up on 443 regardless.
    $arguments = @(Get-ConfigArray -InputObject $installer -Name "exeArguments")
    if ($arguments.Count -eq 0) {
        $arguments = @("/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART")
    }
    if (-not ($arguments -match "^/HTTPSPortNumber=")) { $arguments += "/HTTPSPortNumber=$port" }
    if (-not ($arguments -match "^/LOG="))             { $arguments += "/LOG=`"$installLog`"" }
    $filePath = $installerPath

    # A previous attempt that registered the product but never produced a service leaves
    # the installer refusing to run again, or running and failing the same way. Remove it
    # first - Test-WacInstalled asks the service, so this is the only place that sees it.
    if (Test-WacInRegistry) {
        Write-Log "Windows Admin Center is registered but has no service - removing the half-installed copy first" -Tag "Info"
        if (-not (Uninstall-WacGateway)) {
            throw "A half-installed Windows Admin Center is registered and could not be removed. Remove it from Programs and Features, then run again."
        }
    }

    $process = $null

    try {
        Write-Log "$filePath $($arguments -join ' ')" -Tag "Run"
        Write-Log "The installer is silent and takes several minutes - it writes to '$installLog' while it runs" -Tag "Info"

        $process = Start-Process -FilePath $filePath -ArgumentList $arguments -PassThru -ErrorAction Stop
        # Touching the handle is what makes ExitCode readable afterwards. Without -Wait,
        # PowerShell does not keep one, and the property comes back empty on a process that
        # has plainly finished.
        $null = $process.Handle

        # -Wait would block for the better part of ten minutes with nothing on screen, which
        # is indistinguishable from a hung run - and a run somebody kills halfway through is
        # exactly how a half-installed gateway happens. Waiting in steps costs nothing and
        # says the install is still going.
        $waited      = 0
        $timeout     = 45 * 60
        $announceAt  = 60
        while ((-not $process.HasExited) -and ($waited -lt $timeout)) {
            Start-Sleep -Seconds 15
            $waited = $waited + 15
            if ($waited -ge $announceAt) {
                Write-Log "Still installing - $([int]($waited / 60)) minute(s) so far" -Tag "Info"
                $announceAt = $announceAt + 60
            }
        }

        if (-not $process.HasExited) {
            throw "The installer is still running after $([int]($timeout / 60)) minutes. See '$installLog'."
        }
        $process.WaitForExit()

        # 3010 is "installed, wants a restart" - the gateway itself does not need one.
        if (($process.ExitCode -ne 0) -and ($process.ExitCode -ne 3010)) {
            throw "$filePath exited with code $($process.ExitCode). See '$installLog'."
        }
        if ($process.ExitCode -eq 3010) {
            Write-Log "The installer asked for a restart - the gateway runs without one" -Tag "Info"
        }

        Write-Log "Windows Admin Center installed" -Tag "Ok"

        # The v2 bootstrapper returns before the service registration has settled, so the
        # first look can miss a service that is on its way. Give it a short while rather
        # than failing a run that in fact succeeded.
        $service = Get-WacService
        $waited  = 0
        while (($null -eq $service) -and ($waited -lt 180)) {
            Start-Sleep -Seconds 3
            $waited  = $waited + 3
            $service = Get-WacService
        }
        if ($null -eq $service) {
            throw "The installer finished but no Windows Admin Center service is registered. See '$installLog'."
        }
        Write-Log "Service '$($service.Name)' is $($service.Status)" -Tag "Info"
    }
    catch {
        # A timeout is not a failed install - the installer still holds the machine, and
        # running an uninstaller across it is how a working gateway becomes a broken one.
        if (($null -ne $process) -and (-not $process.HasExited)) {
            Write-Log "The installer is still running - nothing is removed while it holds the machine" -Tag "Error"
            throw
        }

        # Whatever the installer managed to register is worse than nothing: the next run
        # would find no service, install again, and land in the same place. Take it back
        # out so the retry starts from a clean machine, and report the original failure.
        Write-Log "The installation failed - removing anything it registered" -Tag "Info"
        if (-not (Uninstall-WacGateway)) {
            Write-Log "The cleanup did not finish either - check Programs and Features before running again" -Tag "Error"
        }
        throw
    }
}

# ---------------------------[ Uninstall ]---------------------------
# A failed install does not leave nothing behind - it leaves a registered product with
# no working service, and the next run sees no service, installs again, and fails the
# same way. So the failure path removes what the installer registered, read from the same
# Uninstall keys Add/Remove Programs reads, because a bootstrapper's own uninstaller path
# is not derivable from anything else.
$script:wacRegistryDisplayName = "Windows Admin Center*"

$script:wacUninstallKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

function Get-WacUninstallEntry {
    $found = @()

    foreach ($keyPath in $script:wacUninstallKeys) {
        if (-not (Test-Path -Path $keyPath)) { continue }

        $subkeys = Get-ChildItem -Path $keyPath -ErrorAction SilentlyContinue
        foreach ($subkey in $subkeys) {
            $properties = Get-ItemProperty -Path $subkey.PSPath -ErrorAction SilentlyContinue
            if ($null -eq $properties) { continue }

            $displayName = [string]$properties.DisplayName
            if ([string]::IsNullOrWhiteSpace($displayName)) { continue }
            if ($displayName -notlike $script:wacRegistryDisplayName) { continue }

            $found += [pscustomobject]@{
                DisplayName     = $displayName
                DisplayVersion  = [string]$properties.DisplayVersion
                UninstallString = [string]$properties.UninstallString
                ModifyPath      = [string]$properties.ModifyPath
                KeyPath         = $subkey.PSPath
            }
        }
    }

    return $found
}

function Test-WacInRegistry {
    return (@(Get-WacUninstallEntry).Count -gt 0)
}

# The registered string is a command line, not a program: it may be quoted and it carries
# arguments. Splitting it and forcing Inno's quiet switches on is what makes it runnable
# unattended.
#
# An **MSI** uninstall string is refused rather than run. That is a v1 gateway somebody
# installed, and removing another generation's product silently - to clear the way for an
# install this run wants to do - is not a decision this script gets to make on its own.
function ConvertTo-WacUninstallCommand {
    param([Parameter(Mandatory)][string]$UninstallString)

    $command = $UninstallString.Trim()
    if ([string]::IsNullOrWhiteSpace($command)) { return $null }

    if (($command -match '(?i)msiexec(\.exe)?') -or
        ($command -match '(?i)/[ilx]\s*\{[a-f0-9\-]+\}') -or
        ($command -match '(?i)\.msi(\s|"|$)')) {
        Write-Log "'$command' removes an MSI - that is the v1 gateway, which this toolbox does not manage" -Tag "Error"
        Write-Log "Remove it from Programs and Features by hand, then run again" -Tag "Error"
        return $null
    }

    foreach ($switch in @("/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART")) {
        if ($command -notmatch [regex]::Escape($switch)) { $command = $command + " " + $switch }
    }

    if ($command -match '^"([^"]+)"\s*(.*)$') {
        $filePath  = $matches[1]
        $arguments = $matches[2].Trim()
    }
    else {
        $parts     = $command -split '\s+', 2
        $filePath  = $parts[0]
        $arguments = ""
        if ($parts.Count -gt 1) { $arguments = $parts[1].Trim() }
    }

    $filePath = [System.Environment]::ExpandEnvironmentVariables($filePath)
    if ([string]::IsNullOrWhiteSpace($filePath)) {
        Write-Log "Could not read a program out of '$UninstallString'" -Tag "Error"
        return $null
    }
    if (-not (Test-Path -LiteralPath $filePath)) {
        Write-Log "The registered uninstaller '$filePath' is not there" -Tag "Error"
        return $null
    }

    return @{ FilePath = $filePath; Arguments = $arguments }
}

# The registry is the truth anchor, not the exit code: an uninstaller that reports a
# failure but left nothing registered has done the job, and one that reports success
# while the entry stands has not.
function Uninstall-WacGateway {
    $entries = @(Get-WacUninstallEntry)
    if ($entries.Count -eq 0) {
        Write-Log "Nothing matching '$script:wacRegistryDisplayName' is registered - there is nothing to remove" -Tag "Info"
        return $true
    }

    foreach ($entry in $entries) {
        $label = $entry.DisplayName
        if (-not [string]::IsNullOrWhiteSpace($entry.DisplayVersion)) { $label = "$label $($entry.DisplayVersion)" }
        Write-Log "Removing '$label' registered at $($entry.KeyPath)" -Tag "Run"

        # ModifyPath is the fallback, not the choice: it is the maintenance entry point
        # and only some products register a usable one.
        $candidates = @($entry.UninstallString, $entry.ModifyPath) |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        if (@($candidates).Count -eq 0) {
            Write-Log "'$label' registers neither an UninstallString nor a ModifyPath" -Tag "Error"
            continue
        }

        foreach ($candidate in $candidates) {
            $command = ConvertTo-WacUninstallCommand -UninstallString $candidate
            if ($null -eq $command) { continue }

            Write-Log "$($command.FilePath) $($command.Arguments)" -Tag "Run"
            try {
                $arguments = @()
                if (-not [string]::IsNullOrWhiteSpace($command.Arguments)) {
                    $arguments = @($command.Arguments)
                }

                if ($arguments.Count -gt 0) {
                    $process = Start-Process -FilePath $command.FilePath -ArgumentList $arguments -Wait -PassThru -ErrorAction Stop
                }
                else {
                    $process = Start-Process -FilePath $command.FilePath -Wait -PassThru -ErrorAction Stop
                }

                # 3010 wants a restart. The registry check below is what actually decides.
                if (@(0, 3010) -contains $process.ExitCode) {
                    Write-Log "The uninstaller exited with $($process.ExitCode)" -Tag "Info"
                }
                else {
                    Write-Log "The uninstaller exited with $($process.ExitCode) - checking the registry anyway" -Tag "Info"
                }
            }
            catch {
                Write-Log "Could not run the uninstaller: $($_.Exception.Message)" -Tag "Error"
                continue
            }

            if (-not (Test-Path -Path $entry.KeyPath)) { break }
        }
    }

    # Removal is asynchronous often enough to be worth waiting on rather than calling it
    # a failure and leaving the next run to trip over the same entry.
    $waited = 0
    while ((Test-WacInRegistry) -and ($waited -lt 30)) {
        Start-Sleep -Seconds 5
        $waited = $waited + 5
    }

    if (Test-WacInRegistry) {
        Write-Log "Windows Admin Center is still registered after the uninstall - remove it by hand before running again" -Tag "Error"
        return $false
    }

    Write-Log "Windows Admin Center is no longer registered" -Tag "Ok"
    return $true
}


# ---------------------------[ Gateway certificate registration ]---------------------------
# **The gateway is a Kestrel process, and Kestrel does not use http.sys at all.** It opens
# the socket itself and picks its certificate out of LocalMachine\My by *subject name* -
# the configuration module writes that name into appsettings.json under
# Kestrel:Endpoints:WindowsAdminCenter:Certificate:Subject, which is also where
# Set-WACCertificateAcl reads it back from. This one fact is what the whole path hangs off,
# and getting it wrong cost a field run. Three consequences, all of which bit:
#
#   - "netsh http show sslcert" is **empty on a healthy gateway**, because nothing in
#     http.sys serves it. Reading that as a torn-out binding sent every run into a repair
#     it never needed, and reported a working gateway as broken.
#   - Register-WACHttpSys is the other mode's cmdlet and is not idempotent: it runs
#     "netsh http add sslcert" and then "netsh http add urlacl url=https://+:<port>/",
#     *neither a delete-first*, so on a machine that already carries the reservation the
#     urlacl add fails with error 183, "cannot create a file when that file already
#     exists". The module reports that through Write-Error, whose record carries the detail
#     and whose exception carries none, which is why the log said only "Exception of type
#     'Microsoft.PowerShell.Commands.WriteErrorException' was thrown". Nothing in this
#     provider calls it any more.
#   - Selection by subject name makes a renewal ambiguous: two certificates, same CN, and
#     the store's enumeration order decides. Remove-StudioSupersededCertificate is what
#     keeps that from quietly bringing the gateway back on the expired one.
#
# So the run does the three documented calls - Set-WACCertificateSubjectName,
# Set-WACCertificateAcl, restart - and then establishes what the gateway serves by opening
# a TLS connection to it and reading the certificate back (Get-StudioServedCertificate).
# That is the only check here that is not inference, and it is mode-agnostic: if a future
# build ever does serve through http.sys, the probe still tells the truth about it.
$script:wacConfigurationModuleName = "Microsoft.WindowsAdminCenter.Configuration"

function Get-WacConfigurationModulePath {
    $roots = @($env:ProgramFiles, ${env:ProgramW6432}, ${env:ProgramFiles(x86)}) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique

    foreach ($root in $roots) {
        $candidate = Join-Path -Path $root -ChildPath ("WindowsAdminCenter\PowerShellModules\" + $script:wacConfigurationModuleName)
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    return ""
}

function Import-WacConfigurationModule {
    if (Get-Module -Name $script:wacConfigurationModuleName) { return $true }

    $modulePath = Get-WacConfigurationModulePath
    if ([string]::IsNullOrWhiteSpace($modulePath)) {
        Write-Log "No $script:wacConfigurationModuleName module under %ProgramFiles%\WindowsAdminCenter\PowerShellModules" -Tag "Error"
        Write-Log "    Every gateway this toolbox supports ships it - an installation without it is v1 or damaged" -Tag "Error"
        return $false
    }

    try {
        Import-Module -Name $modulePath -Force -ErrorAction Stop
        Write-Log "Loaded $script:wacConfigurationModuleName from '$modulePath'" -Tag "Debug"
        return $true
    }
    catch {
        Write-Log "Could not load '$modulePath': $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

# The installer sets both FQDNs from the machine's hostname and mints a self-signed
# certificate for exactly that name - on a server with no DNS suffix, "hv-01". The gateway
# then reaches its own service endpoints (a port range, 6601-6610 by default) at that name
# over HTTPS, where they present whatever certificate is bound. Replace the certificate
# without replacing the name and every internal call fails validation: the browser shows
# "Connection error - The SSL connection could not be established" the moment a tile is
# clicked, naming neither the name, the port, nor the certificate. So the name follows the
# certificate, and it is taken from the certificate itself rather than from the design -
# what matters is that the two agree, not what anybody typed.
function Set-WacEndpointName {
    # Not Mandatory: a certificate with no readable name yields an empty string, and a
    # mandatory [string] cannot bind one - it would throw where it should do nothing.
    param(
        [string]$Fqdn = "",
        [ValidateSet("auto", "always", "never")][string]$HostsEntry = "auto"
    )

    if ([string]::IsNullOrWhiteSpace($Fqdn)) { return $false }
    if (-not (Get-Command -Name "Set-WACEndpointFqdn" -ErrorAction SilentlyContinue)) { return $false }

    # Get-WACEndpointFqdn hands back a hashtable. Wrapping that in @() yields one element -
    # the hashtable itself - not its entries, so a reader written for rows finds nothing and
    # every run renames a gateway that was already correct. A rename restarts the gateway's
    # own listener, so a run that does it needlessly is a run that drops connections for no
    # reason. Rows are still handled: a future build may return them.
    $endpoint = ""
    $service  = ""
    try {
        $current = Get-WACEndpointFqdn

        if ($current -is [System.Collections.IDictionary]) {
            $endpoint = [string]$current["EndpointFqdn"]
            $service  = [string]$current["ServiceFqdn"]
        }
        else {
            foreach ($row in @($current)) {
                $key = ""
                if ($null -eq $row) { continue }
                if ($row.PSObject.Properties["Name"]) { $key = [string]$row.Name }
                elseif ($row.PSObject.Properties["Key"]) { $key = [string]$row.Key }

                if ($key -eq "EndpointFqdn") { $endpoint = [string]$row.Value }
                elseif ($key -eq "ServiceFqdn") { $service = [string]$row.Value }
            }
        }
    }
    catch {
        Write-Log "Could not read the gateway's endpoint name: $($_.Exception.Message)" -Tag "Info"
    }

    if ([string]::IsNullOrWhiteSpace($endpoint) -and [string]::IsNullOrWhiteSpace($service)) {
        Write-Log "The gateway's current endpoint name could not be read - setting it rather than assuming" -Tag "Debug"
    }

    if (($endpoint -eq $Fqdn) -and ($service -eq $Fqdn)) {
        Write-Log "The gateway already answers to '$Fqdn'" -Tag "Debug"
        return $false
    }

    # Without -NoHosts the cmdlet writes the name into the hosts file. That is a hidden
    # override: it wins over DNS for this machine, it outlives whatever address change comes
    # next, and nothing points at it when the gateway later talks to the wrong server. So
    # "auto" writes one in exactly one case - the name resolves *nowhere*, which is a
    # gateway that cannot reach its own service endpoints at all.
    #
    # A name that resolves somewhere that is not this server is deliberately **not** that
    # case. A hosts entry would paper over a wrong DNS record and hide it for as long as the
    # file survives; the record is the thing that is broken, and it is said out loud instead.
    $writeHosts = $false
    if ($HostsEntry -eq "always") {
        Write-Log "endpointName.hostsEntry is 'always' - a hosts entry for '$Fqdn' is written whatever DNS says" -Tag "Info"
        $writeHosts = $true
    }
    elseif ($HostsEntry -eq "auto") {
        $resolution = Test-StudioNameResolvesHere -Name $Fqdn

        if (-not $resolution.Resolves) {
            Write-Log "'$Fqdn' resolves nowhere from this server - a hosts entry lets the gateway reach its own endpoints" -Tag "Info"
            $writeHosts = $true
        }
        elseif ($resolution.Here) {
            Write-Log "'$Fqdn' already resolves to this server ($($resolution.Matched -join ', ')) - no hosts entry" -Tag "Info"
        }
        else {
            Write-Log "'$Fqdn' resolves to $($resolution.Resolved -join ', '), which is not an address on this server" -Tag "Warn"
            Write-Log "    No hosts entry written - a DNS record pointing elsewhere is the thing to fix, and a hosts file would hide it" -Tag "Warn"
            Write-Log "Until it is corrected the gateway cannot reach its own service endpoints, and a tile fails with an SSL error" -Tag "Warn"
        }
    }

    if ($writeHosts) {
        Write-Log "    The entry lands in %SystemRoot%\System32\drivers\etc\hosts and no later run removes it" -Tag "Warn"
    }

    try {
        if (-not $writeHosts) {
            Write-Log "Set-WACEndpointFqdn -EndpointFqdn $Fqdn -ServiceFqdn $Fqdn -NoHosts (was '$endpoint')" -Tag "Run"
            Set-WACEndpointFqdn -EndpointFqdn $Fqdn -ServiceFqdn $Fqdn -NoHosts -ErrorAction Stop
        }
        else {
            Write-Log "Letting the gateway add '$Fqdn' to the hosts file so it can reach itself" -Tag "Info"
            Write-Log "Set-WACEndpointFqdn -EndpointFqdn $Fqdn -ServiceFqdn $Fqdn (was '$endpoint')" -Tag "Run"
            Set-WACEndpointFqdn -EndpointFqdn $Fqdn -ServiceFqdn $Fqdn -ErrorAction Stop
        }
    }
    catch {
        Write-Log "Could not set the gateway's endpoint name to '$Fqdn': $($_.Exception.Message)" -Tag "Error"
        Write-Log "Until it matches the certificate, opening a connection fails with an SSL error" -Tag "Error"
        return $false
    }

    # During install Set-WACEndpointFqdn runs *before* Register-WACHttpSys, so the module
    # assumes an http.sys registration is created after it. The v2 gateway does not serve
    # through http.sys at all - Kestrel opens the socket itself - so there is nothing here
    # for the rename to tear out and nothing to rebuild. Reading an empty
    # "netsh http show sslcert" as damage is what used to send every run into a repair it
    # never needed. Whether the gateway came back is the caller's TLS probe to answer, and
    # that is the only check that is not inference.
    Write-Log "The gateway now answers to '$Fqdn'" -Tag "Ok"
    return $true
}

# Hands the thumbprint to the gateway itself. Returns false when the configuration module
# is not there to hand it to, which is a gateway this toolbox cannot configure at all.
# The design decides whether the gateway's name is managed at all, what it is, and
# whether the hosts file may be written. Everything defaults to "yes, from the
# certificate, only when needed" - the settings exist for the server that is reached by
# a name the certificate does not carry, which is somebody's deliberate arrangement
# rather than something to overwrite.
function Get-WacEndpointPlan {
    param(
        [object]$WindowsAdminCenter,
        [string]$CertificateName = ""
    )

    $plan = @{ Manage = $true; Fqdn = $CertificateName; HostsEntry = "auto" }

    $endpointName = Get-ConfigValue -InputObject $WindowsAdminCenter -Name "endpointName"
    if ($null -eq $endpointName) { return $plan }

    $plan.Manage = [bool](Get-ConfigValue -InputObject $endpointName -Name "manage" -Default $true)

    $configured = Get-ConfigText -InputObject $endpointName -Name "fqdn"
    if (-not [string]::IsNullOrWhiteSpace($configured)) { $plan.Fqdn = $configured }

    $hosts = Get-ConfigText -InputObject $endpointName -Name "hostsEntry" -Default "auto"
    if (@("auto", "always", "never") -contains $hosts) { $plan.HostsEntry = $hosts }

    return $plan
}

function Set-WacGatewayCertificate {
    param(
        [Parameter(Mandatory)][string]$Thumbprint,
        [object]$WindowsAdminCenter = $null
    )

    if (-not (Import-WacConfigurationModule)) { return $false }

    # Set-WACCertificateSubjectName is the current name and takes the thumbprint; older
    # builds ship Set-WACSubjectName, which takes the subject and nothing else. Both write
    # the same appsettings.json value, which is what Kestrel reads its certificate from.
    $setSubject = Get-Command -Name "Set-WACCertificateSubjectName" -ErrorAction SilentlyContinue
    if ($null -eq $setSubject) { $setSubject = Get-Command -Name "Set-WACSubjectName" -ErrorAction SilentlyContinue }
    if ($null -eq $setSubject) {
        Write-Log "The module has neither Set-WACCertificateSubjectName nor Set-WACSubjectName - the certificate cannot be handed to this gateway" -Tag "Error"
        return $false
    }

    $subjectName = Get-StudioCertificatePrimaryName -Thumbprint $Thumbprint
    $certificate = Get-StoreCertificate -Thumbprint $Thumbprint
    if ($null -ne $certificate) {
        $cnMatch = [regex]::Match([string]$certificate.Subject, "(?i)CN=([^,]+)")
        if ($cnMatch.Success) { $subjectName = $cnMatch.Groups[1].Value.Trim() }
    }

    $subjectArguments = @{ ErrorAction = "SilentlyContinue" }
    if ($setSubject.Parameters.ContainsKey("Thumbprint")) {
        $subjectArguments["Thumbprint"] = $Thumbprint
        Write-Log "$($setSubject.Name) -Thumbprint $Thumbprint" -Tag "Run"
    }
    elseif ($setSubject.Parameters.ContainsKey("SubjectName")) {
        $subjectArguments["SubjectName"] = $subjectName
        Write-Log "$($setSubject.Name) -SubjectName $subjectName" -Tag "Run"
    }
    else {
        Write-Log "$($setSubject.Name) takes neither -Thumbprint nor -SubjectName on this build - the certificate cannot be handed over" -Tag "Error"
        return $false
    }

    $subjectErrors = $null
    try {
        & $setSubject @subjectArguments -ErrorVariable subjectErrors
    }
    catch {
        Write-Log "$($setSubject.Name) failed: $(Get-ErrorDetailText -ErrorRecord $_)" -Tag "Error"
        return $false
    }
    # @($null) is an array of length one - the trap this repo has hit before. An
    # -ErrorVariable that never got written would otherwise read as one error and fail a
    # call that succeeded.
    if (@($subjectErrors | Where-Object { $null -ne $_ }).Count -gt 0) {
        Write-ErrorRecordDetail -ErrorRecord $subjectErrors -Prefix "$($setSubject.Name)" -Tag "Error"
        Write-Log "The gateway did not take the certificate - it keeps whatever it was serving" -Tag "Error"
        return $false
    }

    # Its own ACL step, on top of the one this script already did. The gateway reads the
    # key as NETWORK SERVICE and this is the failure the docs single out, so both run -
    # and this one is best effort, because the grant that matters already happened. Worth
    # knowing that it often does nothing: it reads the key path through
    # PrivateKey.CspKeyContainerInfo, which is CAPI only, so a CNG key - which is what
    # Import-PfxCertificate produces - makes it log "unable to find machine key path" and
    # skip. Grant-CertificateKeyRead handles both, and ran first.
    if (Get-Command -Name "Set-WACCertificateAcl" -ErrorAction SilentlyContinue) {
        if (-not [string]::IsNullOrWhiteSpace($subjectName)) {
            $aclErrors = $null
            Set-WACCertificateAcl -SubjectName $subjectName -ErrorAction SilentlyContinue -ErrorVariable aclErrors
            Write-ErrorRecordDetail -ErrorRecord $aclErrors -Prefix "Set-WACCertificateAcl" -Tag "Debug"
            if (@($aclErrors | Where-Object { $null -ne $_ }).Count -eq 0) {
                Write-Log "The gateway re-applied its own key ACL for '$subjectName'" -Tag "Debug"
            }
        }
    }

    # The name the gateway calls itself has to be one the certificate can present.
    $primaryName = Get-StudioCertificatePrimaryName -Thumbprint $Thumbprint
    if (-not [string]::IsNullOrWhiteSpace($primaryName)) {
        $plan = Get-WacEndpointPlan -WindowsAdminCenter $WindowsAdminCenter -CertificateName $primaryName
        if ($plan.Manage) {
            $null = Set-WacEndpointName -Fqdn ([string]$plan.Fqdn) -HostsEntry ([string]$plan.HostsEntry)
        }
        else {
            Write-Log "endpointName.manage is false - the gateway's own name is left as it is" -Tag "Info"
        }
    }

    Write-Log "The gateway is registered to use $Thumbprint" -Tag "Ok"
    return $true
}

function Restart-WacService {
    $service = Get-WacService
    if ($null -eq $service) {
        Write-Log "No Windows Admin Center service to restart" -Tag "Error"
        return $false
    }

    try {
        Write-Log "Restarting '$($service.Name)'" -Tag "Run"
        Restart-Service -Name $service.Name -Force -ErrorAction Stop
    }
    catch {
        Write-Log "Could not restart '$($service.Name)': $($_.Exception.Message)" -Tag "Error"
        Write-Log "A gateway that cannot read its certificate's private key fails exactly like this" -Tag "Error"
        return $false
    }

    Write-Log "'$($service.Name)' restarted" -Tag "Ok"
    return $true
}

# Returns the outcome rather than a boolean, because the report mail lists what each
# URL answered - a run that says "1 failed" and a mail that says which one are the same
# check read twice, and two readings of the same thing can disagree.
function Get-WacEndpointResult {
    param([Parameter(Mandatory)][string]$Url)

    $previousProgress = $ProgressPreference
    $ProgressPreference = "SilentlyContinue"
    try {
        [System.Net.ServicePointManager]::SecurityProtocol =
            [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        Write-Log "$Url answered $([int]$response.StatusCode)" -Tag "Ok"
        return [pscustomobject]@{ Url = $Url; Ok = $true; Detail = "HTTP $([int]$response.StatusCode)" }
    }
    catch {
        # Any HTTP status means TLS and routing work, which is what is being tested.
        if ($null -ne $_.Exception.Response) {
            $status = [int]$_.Exception.Response.StatusCode
            Write-Log "$Url answered $status" -Tag "Ok"
            return [pscustomobject]@{ Url = $Url; Ok = $true; Detail = "HTTP $status" }
        }
        Write-Log "$Url did not answer: $($_.Exception.Message)" -Tag "Error"
        return [pscustomobject]@{ Url = $Url; Ok = $false; Detail = $_.Exception.Message }
    }
    finally {
        $ProgressPreference = $previousProgress
    }
}

function Test-WacEndpoint {
    param([Parameter(Mandatory)][string]$Url)

    return (Get-WacEndpointResult -Url $Url).Ok
}


# Polls the gateway for what it is actually serving. Kestrel reads its certificate as it
# starts, so this is the only moment the answer changes, and it is not instant - the
# service has a process before it has a listener.
function Wait-WacServedThumbprint {
    param(
        [Parameter(Mandatory)][string]$Thumbprint,
        [Parameter(Mandatory)][int]$Port,
        [string]$Name = "",
        [int]$TimeoutSeconds = 90
    )

    $wanted = $Thumbprint.ToUpperInvariant()
    $served = ""
    $waited = 0

    while ($true) {
        $served = Get-StudioServedThumbprint -Port $Port -Name $Name

        # Loopback is the right address to ask - it needs no DNS and no firewall rule - but
        # it is not the only one a listener can be on. A gateway bound to a specific address
        # answers nothing on 127.0.0.1, and reporting that as "the gateway is down" would be
        # a diagnosis this check invented. So an empty answer is asked again by name.
        if ([string]::IsNullOrWhiteSpace($served) -and (-not [string]::IsNullOrWhiteSpace($Name))) {
            $served = Get-StudioServedThumbprint -Port $Port -Name $Name -Address $Name
        }

        if ($served -eq $wanted) { return $served }
        if ($waited -ge $TimeoutSeconds) { break }
        Start-Sleep -Seconds 5
        $waited = $waited + 5
    }

    return $served
}

# Everything after a thumbprint is known, and the only path the daily task takes.
function Update-WacCertificateBinding {
    param(
        [Parameter(Mandatory)][string]$Thumbprint,
        [Parameter(Mandatory)][int]$Port,
        [object]$WindowsAdminCenter = $null
    )

    $identity = Get-WacServiceIdentity
    $granted  = Grant-CertificateKeyRead -Thumbprint $Thumbprint -Identity $identity

    $name = Get-StudioCertificatePrimaryName -Thumbprint $Thumbprint

    if (-not (Set-WacGatewayCertificate -Thumbprint $Thumbprint -WindowsAdminCenter $WindowsAdminCenter)) {
        Write-Log "The gateway would not take the certificate - it is still serving whatever it had" -Tag "Error"
        return $false
    }

    # Kestrel picks its certificate out of the store by *subject name*, so two certificates
    # with the same CN are not a duplicate - they are a coin toss, and after a renewal the
    # loser is the one that is still valid. The superseded ones go before the restart, since
    # the restart is the moment the choice is made.
    #
    # **After the gateway has accepted the new certificate, never before.** The one being
    # removed is the one currently being served: take it out first and then fail to hand
    # over the replacement, and the next restart finds a subject naming a certificate that
    # is no longer in the store - a gateway broken by the run that was fixing it. In this
    # order a failure above leaves the old certificate in place and serving.
    $null = Remove-StudioSupersededCertificate -Thumbprint $Thumbprint

    # The gateway reads its certificate as it starts, so this restarts it and then asks the
    # gateway itself - over TLS - what it came back on. Nothing about an http.sys binding is
    # inspected: Kestrel has none, and a check that needs one reports a healthy gateway as
    # broken, which is precisely what this used to do.
    if (-not (Restart-WacService)) { return $false }

    $wanted = $Thumbprint.ToUpperInvariant()
    $served = Wait-WacServedThumbprint -Thumbprint $Thumbprint -Port $Port -Name $name

    if ($served -eq $wanted) {
        Write-Log "Port $Port serves $wanted" -Tag "Ok"
        return $granted
    }

    if ([string]::IsNullOrWhiteSpace($served)) {
        Write-Log "The gateway took the certificate but nothing answers TLS on port $Port" -Tag "Error"
        Write-Log "    A gateway that cannot read its certificate's private key fails exactly like this - check the WindowsAdminCenter event log" -Tag "Error"
        Write-Log "Also worth checking: something else already holds port $Port - 'netstat -ano | findstr :$Port'" -Tag "Error"
        return $false
    }

    Write-Log "Port $Port serves $served, not $wanted - the gateway came back on another certificate" -Tag "Error"
    $other = Get-StoreCertificate -Thumbprint $served
    if ($null -ne $other) {
        Write-Log "That is '$($other.Subject)', valid until $($other.NotAfter.ToString('yyyy-MM-dd'))" -Tag "Error"
    }
    Write-Log "The gateway selects by subject name - a second certificate with the same CN in LocalMachine\My is how this happens" -Tag "Error"
    return $false
}


# ---------------------------[ Self-signed, issued by the run ]---------------------------
# The difference between this and `generate` is the whole point of it. `generate` keeps
# whatever the installer minted: a certificate for the machine's hostname, with a lifetime
# nobody chose and a name that is normally not the name the gateway is reached by. This
# source issues one for the names in the design, for a life the design states.
#
# It is still self-signed, so a browser still warns until the certificate is trusted on
# the client - what it buys is a certificate that is right about its names and its dates,
# which is what makes it distributable in the first place.
#
# Not `Resolve-StudioCertificate`'s business, for the same reason the S2D management
# certificate is not: every source that resolver knows either fetches a certificate from
# somewhere or finds one already in the store. This one mints it.

# The gateway is its own client, so the machine has to trust the certificate it serves.
# WAC v2 validates the gateway certificate when the gateway calls its own sub-processes
# over TLS (the service endpoints, 6601-6610) - Microsoft's wording is "WACv2 can't be
# used if an invalid certificate is used when communicating with the sub processes". An
# ACME certificate passes because the machine trusts the public chain, and the
# installer's own one passes because the installer does what the module's
# New-WACSelfSignedCertificate -Trust does: puts it in LocalMachine\Root. A certificate
# this run mints has no chain, so it needs the same treatment - without it the gateway
# takes the certificate, accepts connections on the port, and never finishes a
# handshake, which reads as a hang to everything that asks.
function Add-WacTrustedRootCertificate {
    param([Parameter(Mandatory)][string]$Thumbprint)

    $certificate = Get-StoreCertificate -Thumbprint $Thumbprint
    if ($null -eq $certificate) {
        Write-Log "No certificate $Thumbprint in LocalMachine\My - nothing to trust" -Tag "Error"
        return $false
    }

    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)

        $present = $false
        foreach ($entry in @($store.Certificates)) {
            if ($entry.Thumbprint -eq $certificate.Thumbprint) { $present = $true; continue }
            # A superseded certificate for the same subject would stay trusted forever
            # otherwise. Only self-signed ones are this run's to remove - a CA somebody
            # placed here under the same name is their arrangement.
            if (($entry.Subject -eq $certificate.Subject) -and ($entry.Issuer -eq $entry.Subject)) {
                Write-Log "Removing the superseded $($entry.Thumbprint) for '$($entry.Subject)' from Trusted Root" -Tag "Info"
                $store.Remove($entry)
            }
        }

        if (-not $present) {
            # The public half only - Root is a trust statement, not a home for a key.
            $publicBytes = $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            $publicCopy  = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, $publicBytes)
            $store.Add($publicCopy)
            Write-Log "This server now trusts its own gateway certificate - $($certificate.Thumbprint) is in LocalMachine\Root" -Tag "Ok"
        }
        return $true
    }
    catch {
        Write-Log "The certificate could not be placed in Trusted Root: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
    finally {
        $store.Close()
    }
}

function New-WacSelfSignedCertificate {
    param([Parameter(Mandatory)][object]$Certificate)

    $settings = Get-ConfigValue -InputObject $Certificate -Name "selfSigned"
    $years = [int](Get-ConfigValue -InputObject $settings -Name "years" -Default 5)
    if ($years -lt 1) { $years = 1 }
    if ($years -gt 20) { $years = 20 }

    $names = @()
    foreach ($entry in (Get-ConfigArray -InputObject $Certificate -Name "dnsNames")) {
        $name = ([string]$entry).Trim().ToLowerInvariant()
        if ((-not [string]::IsNullOrWhiteSpace($name)) -and ($names -notcontains $name)) { $names += $name }
    }
    # A design that names no name still has a gateway to serve. The machine's own resolved
    # name is what the installer would have used, so falling back to it changes only the
    # dates - never worse than what is already bound.
    if ($names.Count -eq 0) {
        $hostName = [string]$env:COMPUTERNAME
        try { $hostName = [string][System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName }
        catch { Write-Log "Could not read this machine's own host name: $($_.Exception.Message)" -Tag "Debug" }
        $names = @($hostName.ToLowerInvariant())
        Write-Log "The design names no certificate name - issuing for '$($names[0])', which is what this machine calls itself" -Tag "Warn"
    }

    $subject = "CN=$($names[0])"

    # Idempotent by SUBJECT, by remaining life and by the name list - not by thumbprint.
    #
    # By subject, because Kestrel picks its certificate out of the store by subject name:
    # a run that minted a second one for the same name every time would leave the gateway
    # choosing between them by store enumeration order.
    #
    # By remaining life, because this is also what the daily task runs. Thirty days is the
    # re-issue window: inside it the run mints the replacement, binds it, and
    # Remove-StudioSupersededCertificate takes the old one out after the gateway has
    # accepted the new one.
    #
    # By the name list, because otherwise adding a name to the design would be accepted by
    # the studio, written to config.json, and then quietly never take effect - the existing
    # certificate is for the same subject and still valid, so nothing would ever re-issue.
    $renewAfter = (Get-Date).AddDays(30)
    try {
        $existing = @(Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction Stop |
            Where-Object {
                ($_.Subject -eq $subject) -and
                ($_.NotAfter -gt $renewAfter) -and
                ($_.HasPrivateKey)
            } | Sort-Object -Property NotAfter -Descending)
        foreach ($candidate in $existing) {
            $held = @($candidate.DnsNameList | ForEach-Object { ([string]$_.Unicode).ToLowerInvariant() })
            $missing = @($names | Where-Object { $held -notcontains $_ })
            if ($missing.Count -gt 0) {
                Write-Log ("Re-issuing: the certificate here for '{0}' does not carry {1}" -f $names[0], ($missing -join ", ")) -Tag "Info"
                continue
            }
            Write-Log ("Keeping the certificate already here for '{0}' - valid to {1}" -f $names[0], $candidate.NotAfter.ToString("yyyy-MM-dd")) -Tag "Info"
            # Kept, but the trust is re-checked every time: a certificate an earlier run
            # minted without the Root entry is exactly the one this repairs.
            if (-not (Add-WacTrustedRootCertificate -Thumbprint ([string]$candidate.Thumbprint))) {
                throw "This machine does not trust the gateway certificate, and the gateway cannot call its own sub-processes on an untrusted one."
            }
            return [string]$candidate.Thumbprint
        }
    }
    catch {
        Write-Log "The certificate store could not be read, so nothing here can be kept: $($_.Exception.Message)" -Tag "Debug"
    }

    Write-Log ("Issuing a self-signed certificate for {0} - {1} year(s)" -f ($names -join ", "), $years) -Tag "Run"
    try {
        $issued = New-SelfSignedCertificate -Subject $subject -DnsName $names `
            -CertStoreLocation "Cert:\LocalMachine\My" -KeyAlgorithm RSA -KeyLength 2048 `
            -HashAlgorithm SHA256 -NotAfter ((Get-Date).AddYears($years)) `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") -ErrorAction Stop
        Write-Log ("Issued {0} - valid to {1}" -f $issued.Thumbprint, $issued.NotAfter.ToString("yyyy-MM-dd")) -Tag "Ok"
    }
    catch {
        # Thrown rather than returned empty, unlike the S2D one: an empty thumbprint here
        # reads to the daily task as "nothing came back, leave the binding alone", which is
        # a silent success for a renewal that did not happen. Both callers turn a throw
        # into something somebody sees.
        throw "The self-signed certificate could not be issued: $($_.Exception.Message)"
    }

    # Before the binding, deliberately: a throw here leaves the gateway on whatever it was
    # serving, which beats restarting it onto a certificate it cannot validate.
    if (-not (Add-WacTrustedRootCertificate -Thumbprint ([string]$issued.Thumbprint))) {
        throw "This machine does not trust the gateway certificate, and the gateway cannot call its own sub-processes on an untrusted one."
    }
    return [string]$issued.Thumbprint
}

# One resolution point, so the configure run and the daily task cannot disagree about
# what the design's certificate is. Everything except `selfSigned` is the shared
# machinery, unchanged.
function Resolve-WacCertificate {
    param([Parameter(Mandatory)][object]$Certificate)

    if ((Get-ConfigText -InputObject $Certificate -Name "source" -Default "generate") -eq "selfSigned") {
        return (New-WacSelfSignedCertificate -Certificate $Certificate)
    }
    return (Resolve-StudioCertificate -Certificate $Certificate)
}



# ---------------------------[ Entry Points ]---------------------------
# Reported, never enforced. A standalone server whose name has no DNS suffix is a
# perfectly good gateway - it just cannot guess its own public name, so the installer
# names it after the hostname and every certificate afterwards disagrees. The run fixes
# that itself (Set-WacEndpointName), and saying so before anything is installed beats
# discovering it when a tile fails with an SSL error and names nothing.
function Write-WacNameAdvisory {
    param([object]$WindowsAdminCenter)

    $certificate = Get-ConfigValue -InputObject $WindowsAdminCenter -Name "certificate"
    $source      = Get-ConfigText -InputObject $certificate -Name "source" -Default "generate"
    if ($source -eq "generate") { return }

    $designed = @(Get-ConfigArray -InputObject $certificate -Name "dnsNames" | ForEach-Object { [string]$_ })
    if ($designed.Count -eq 0) { return }
    $wanted = $designed[0]

    $hostName = [string]$env:COMPUTERNAME
    try { $hostName = [string][System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName }
    catch { Write-Log "Could not read this machine's own host name: $($_.Exception.Message)" -Tag "Debug" }

    if ($hostName -eq $wanted) { return }

    Write-Log "This machine calls itself '$hostName'; the certificate is for '$wanted'" -Tag "Info"
    Write-Log "Gateway pointed at '$wanted'" -Tag "Info"

    $resolution = Test-StudioNameResolvesHere -Name $wanted

    if ($resolution.Here) {
        Write-Log "'$wanted' already resolves to this server ($($resolution.Matched -join ', ')) - no hosts entry" -Tag "Info"
    }
    elseif ($resolution.Resolves) {
        Write-Log "'$wanted' resolves to $($resolution.Resolved -join ', '), which is not an address on this server" -Tag "Warn"
        Write-Log "    No hosts entry for it - correct the DNS record instead, or the gateway cannot reach its own endpoints" -Tag "Warn"
    }
    else {
        Write-Log "'$wanted' resolves nowhere from this server - a hosts entry will be added so the gateway can reach itself" -Tag "Info"
        Write-Log "Set the DNS record before the run to avoid that" -Tag "Debug"
        Write-Log "Clients still need their own way to resolve '$wanted' to this server's address" -Tag "Info"
    }

    # None of this needs a domain. What the gateway needs is three names agreeing -
    # EndpointFqdn, ServiceFqdn and a name on the certificate - and a host that can resolve
    # the one it is given. A workgroup server meets all three; it just cannot guess its own
    # public name, which is what the run is about to set.
    Write-Log "    The gateway picks its certificate out of LocalMachine\My by subject name - keep only one for '$wanted' there" -Tag "Info"
}

function Test-WacPrerequisite {
    param([object]$Config)

    $wac    = Get-ConfigValue -InputObject $Config -Name "windowsAdminCenter"
    $passed = $true

    Write-WacNameAdvisory -WindowsAdminCenter $wac

    $installer = Get-ConfigValue -InputObject $wac -Name "installer"
    $source    = [string](Get-ConfigValue -InputObject $installer -Name "source" -Default "download")

    if (-not (Test-WacInstalled)) {
        if (-not [bool](Get-ConfigValue -InputObject $installer -Name "allowInstall" -Default $true)) {
            Write-Log "Windows Admin Center is not installed and installer.allowInstall is false" -Tag "Error"
            $passed = $false
        }
        elseif ($source -eq "localPath") {
            $stagedPath = [string](Get-ConfigValue -InputObject $installer -Name "installerPath" -Default "")
            if ([string]::IsNullOrWhiteSpace($stagedPath)) {
                $stagedPath = [string](Get-ConfigValue -InputObject $installer -Name "msiPath" -Default "")
            }
            if ([string]::IsNullOrWhiteSpace($stagedPath) -or (-not (Test-Path -LiteralPath $stagedPath))) {
                Write-Log "The staged installer '$stagedPath' is not there" -Tag "Error"
                $passed = $false
            }
        }
    }

    # The issuing CA publishes CDP and AIA over HTTP from IIS. Two services cannot
    # both own 0.0.0.0:443, and the one that loses does so at start-up, quietly.
    $port = [int](Get-ConfigValue -InputObject $installer -Name "port" -Default 443)
    if (($port -eq 443) -and (Test-ConfigProperty -InputObject $Config -Name "certificateServices")) {
        $certificateServices = Get-ConfigValue -InputObject $Config -Name "certificateServices"
        $issuing = Get-ConfigValue -InputObject $certificateServices -Name "issuing"
        $web     = Get-ConfigValue -InputObject $issuing -Name "webPublishing"
        $issuingName = [string](Get-ConfigValue -InputObject $issuing -Name "computerName" -Default "")

        if (($null -ne $web) -and [bool](Get-ConfigValue -InputObject $web -Name "enabled" -Default $false) -and
            $issuingName.Equals([string]$env:COMPUTERNAME, [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Log "This server is the issuing CA with an IIS publication endpoint, and the gateway wants port 443 as well" -Tag "Error"
            Write-Log "Give the gateway another port, or put it on another server - whichever binds second fails at start-up" -Tag "Error"
            $passed = $false
        }
    }

    return $passed
}

function Invoke-WacConfiguration {
    param([object]$Config)

    $wac = Get-ConfigValue -InputObject $Config -Name "windowsAdminCenter"
    if ($null -eq $wac) {
        return (New-RoleResult -Status "Failed" -Message "config.json has no windowsAdminCenter section.")
    }

    $installer = Get-ConfigValue -InputObject $wac -Name "installer"
    $port      = [int](Get-ConfigValue -InputObject $installer -Name "port" -Default 443)

    if (-not (Test-WacInstalled)) {
        Install-WacGateway -WindowsAdminCenter $wac
    }
    else {
        Write-Log "Windows Admin Center is already installed" -Tag "Info"
    }

    $thumbprint = Resolve-WacCertificate -Certificate (Get-ConfigValue -InputObject $wac -Name "certificate")
    $manualStep = ""

    if ([string]::IsNullOrWhiteSpace($thumbprint)) {
        $source = [string](Get-ConfigValue -InputObject (Get-ConfigValue -InputObject $wac -Name "certificate") -Name "source" -Default "generate")
        if ($source -ne "generate") {
            $manualStep = "No certificate was obtained from '$source' - the gateway is still on whatever it had."
            Write-Log $manualStep -Tag "Error"
        }
    }
    else {
        if (-not (Update-WacCertificateBinding -Thumbprint $thumbprint -Port $port -WindowsAdminCenter $wac)) {
            $manualStep = "The certificate is in the store but the gateway could not be brought up on it."
        }
    }

    $taskRegistered = Register-StudioCertificateTask -Config $Config -ConfigFilePath $script:configFilePath

    foreach ($url in (Get-ConfigArray -InputObject $wac -Name "validationUrls")) {
        $null = Test-WacEndpoint -Url ([string]$url)
    }

    if (-not [string]::IsNullOrWhiteSpace($manualStep)) {
        return (New-RoleResult -Status "ManualStepRequired" -Message $manualStep)
    }
    if (-not $taskRegistered) {
        return (New-RoleResult -Status "ManualStepRequired" -Message "The gateway is configured, but the daily certificate task could not be registered - it will not renew on its own.")
    }
    return (New-RoleResult -Status "Completed" -Message "Windows Admin Center is serving on port $port.")
}

# What the daily task runs. Same code as the configure path from the certificate
# onward, so a renewal is not a second implementation of the same three steps.
function Invoke-WacCertificateTask {
    param([object]$Config)

    $wac = Get-ConfigValue -InputObject $Config -Name "windowsAdminCenter"
    if ($null -eq $wac) {
        Write-Log "config.json has no windowsAdminCenter section" -Tag "Error"
        return 1
    }

    if (-not (Test-WacInstalled)) {
        Write-Log "Windows Admin Center is not installed on this server - nothing to renew" -Tag "Error"
        return 1
    }

    $installer   = Get-ConfigValue -InputObject $wac -Name "installer"
    $port        = [int](Get-ConfigValue -InputObject $installer -Name "port" -Default 443)
    $certificate = Get-ConfigValue -InputObject $wac -Name "certificate"

    # Only for a certificate that comes from ACME - the module is not involved otherwise,
    # and a nightly gallery lookup on a server that never uses it is noise.
    if ((Get-ConfigText -InputObject $certificate -Name "source" -Default "generate") -eq "acme") {
        Update-PoshAcmeModule
    }

    $names = @()
    try {
        $names = @(Get-ConfigArray -InputObject $certificate -Name "dnsNames" | ForEach-Object { [string]$_ })
    }
    catch {
        $names = @()
    }

    $primaryName = ""
    if ($names.Count -gt 0) { $primaryName = $names[0] }

    # Read before anything changes, so the report can say what was replaced - and read from
    # the gateway rather than from a binding, because the gateway serves TLS from its own
    # process and http.sys holds nothing to read. The name list is what the design asks for,
    # not what the old certificate happened to carry.
    $previous = Get-StudioServedCertificate -Port $port -Name $primaryName
    if (($null -eq $previous) -and (-not [string]::IsNullOrWhiteSpace($primaryName))) {
        # Same reason as Wait-WacServedThumbprint: a listener on a specific address answers
        # nothing on loopback, and "no previous certificate" would then be a report that is
        # simply wrong about what was replaced.
        $previous = Get-StudioServedCertificate -Port $port -Name $primaryName -Address $primaryName
    }
    $previousThumbprint = ""
    $previousNotAfter   = ""
    if ($null -ne $previous) {
        $previousThumbprint = ([string]$previous.Thumbprint).ToUpperInvariant()
        $previousNotAfter   = $previous.NotAfter.ToString("yyyy-MM-dd")
    }
    $source     = Get-ConfigText -InputObject $certificate -Name "source" -Default "generate"
    $pluginName = Get-ConfigText -InputObject (Get-ConfigValue -InputObject $certificate -Name "acme") -Name "dnsPlugin"

    $thumbprint = ""
    try {
        $thumbprint = Resolve-WacCertificate -Certificate (Get-ConfigValue -InputObject $wac -Name "certificate")
    }
    catch {
        Write-Log "The certificate could not be obtained: $($_.Exception.Message)" -Tag "Error"
        $null = Send-CertificateReport -Config $Config -Report (New-WacCertificateReport `
            -Status "Failed" -PrimaryName $primaryName -Names $names -Source $source -PluginName $pluginName -Port $port `
            -PreviousThumbprint $previousThumbprint -PreviousNotAfter $previousNotAfter `
            -ErrorMessage $_.Exception.Message -ErrorStackTrace ([string]$_.ScriptStackTrace))
        return 1
    }

    if ([string]::IsNullOrWhiteSpace($thumbprint)) {
        Write-Log "No certificate came back - the binding is left as it is" -Tag "Info"
        return 0
    }

    $status = "Renewed"
    if ($previousThumbprint -eq $thumbprint.ToUpperInvariant()) {
        Write-Log "The gateway already serves $thumbprint - nothing to do today" -Tag "Ok"
        $status = "Current"
    }
    elseif (-not (Update-WacCertificateBinding -Thumbprint $thumbprint -Port $port -WindowsAdminCenter $wac)) {
        Write-Log "The certificate could not be bound" -Tag "Error"
        $null = Send-CertificateReport -Config $Config -Report (New-WacCertificateReport `
            -Status "Failed" -PrimaryName $primaryName -Names $names -Source $source -PluginName $pluginName -Port $port `
            -Thumbprint $thumbprint -PreviousThumbprint $previousThumbprint -PreviousNotAfter $previousNotAfter `
            -ErrorMessage "The certificate is in the store but the gateway is not serving it on port $port.")
        return 1
    }

    $notAfter = ""
    $issued = Get-Item -Path ("Cert:\LocalMachine\My\" + $thumbprint) -ErrorAction SilentlyContinue
    if ($null -ne $issued) { $notAfter = $issued.NotAfter.ToString("yyyy-MM-dd") }

    $endpoints = @()
    foreach ($url in (Get-ConfigArray -InputObject $wac -Name "validationUrls")) {
        $endpoints += Get-WacEndpointResult -Url ([string]$url)
    }
    $failed = @($endpoints | Where-Object { -not $_.Ok }).Count

    $reportStatus = $status
    $errorMessage = ""
    if ($failed -gt 0) {
        $reportStatus = "Failed"
        $errorMessage = "$failed of $(@($endpoints).Count) validation URLs did not answer. The certificate is bound; what is broken is reaching the gateway."
    }

    $null = Send-CertificateReport -Config $Config -Report (New-WacCertificateReport `
        -Status $reportStatus -PrimaryName $primaryName -Names $names -Source $source -PluginName $pluginName -Port $port `
        -Thumbprint $thumbprint -NotAfter $notAfter `
        -PreviousThumbprint $previousThumbprint -PreviousNotAfter $previousNotAfter `
        -ErrorMessage $errorMessage -Endpoints $endpoints)

    if ($failed -gt 0) { return 1 }
    return 0
}
