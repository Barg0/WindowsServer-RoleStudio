# Role provider: Exchange Server Subscription Edition (Mailbox role, single server).
#
# Dot-sourced by Configure-ServerRoles.ps1 - not runnable on its own. Everything
# here lands in that script's scope, so $script: variables and functions are shared
# with every other part. Use $scriptRootPath, never $PSScriptRoot: inside this file
# $PSScriptRoot is the pwsh folder, not the folder the run was started from.
#
# ===========================[ Exchange Server SE ]===========================
# The one role installed from an ISO: setup.exe is a vendor installer like the
# Windows Admin Center gateway, so - same stated deviation as there - this provider
# runs it, and passes /InstallWindowsComponents so the installer owns its own
# Windows features. Everything else follows the house rules: state-driven (the
# registry says whether Exchange is installed, the schema says whether the forest
# is prepared), idempotent, and a reboot lands on the engine's boundary with the
# post-install configuration in the PostReboot stage.
#
#   1. not installed, forest unprepared  -> setup /PrepareAD           (state: schema/org version)
#   2. not installed, forest prepared    -> setup /Mode:Install        -> RebootRequired
#   3. installed                          -> post-install configuration -> Completed
#
# The post-install half is where the value is, and it re-runs safely: one namespace
# across every virtual directory, the certificate through the shared machinery,
# TLS pinned consistently, POP/IMAP off, the scoped relay connector, and the
# Extended Protection table verified rather than reasserted.

$script:exchangeSetupRegistryPath = "HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup"

function Get-ExchangeInstallPath {
    try {
        $setup = Get-ItemProperty -Path $script:exchangeSetupRegistryPath -ErrorAction Stop
        return [string](Get-ConfigValue -InputObject $setup -Name "MsiInstallPath" -Default "")
    }
    catch {
        return ""
    }
}

function Test-ExchangeInstalled {
    return (-not [string]::IsNullOrWhiteSpace((Get-ExchangeInstallPath)))
}

# The forest's preparation state, read from the directory rather than from a marker
# file - the same instinct as reading CertSvc\Configuration\Active. rangeUpper on
# the schema attribute moves with every CU that extends the schema; SE RTM starts
# at 17000, so anything at or above that is an SE-ready forest.
function Get-ExchangeSchemaVersion {
    try {
        $rootDse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
        $schemaNc = [string]$rootDse.Properties["schemaNamingContext"].Value
        $attribute = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=ms-Exch-Schema-Version-Pt,$schemaNc")
        return [int]$attribute.Properties["rangeUpper"].Value
    }
    catch {
        return 0
    }
}

# How long to wait before restarting this server once setup has finished, or 0 to leave
# it to a person. The engine asks; the answer is this role's, because Exchange is the one
# role in this design that ends by needing a restart it cannot perform for itself. A
# domain controller reboots during promotion and never asks, and every other role here
# finishes on its feet.
#
# On by default, at 90 seconds, and both parts are deliberate. The restart this answers
# is the one immediately after **setup installed Exchange** - a server that is being
# built, with no mailboxes on it and nobody connected, where the next thing that has to
# happen is a reboot and the run after it applies the namespace, the certificate and the
# hardening. Waiting for somebody to notice a console is not a safety feature there, it
# is just delay. The 90 seconds is the safety feature: it is long enough to read the line
# and type 'shutdown /a'.
function Get-ExchangeAutoRestartDelay {
    param([object]$Config)

    $exchange = Get-ConfigValue -InputObject $Config -Name "exchange"
    if ($null -eq $exchange) { return 0 }

    $install = Get-ConfigValue -InputObject $exchange -Name "install"
    if (-not [bool](Get-ConfigValue -InputObject $install -Name "autoRestart" -Default $true)) { return 0 }

    return [int](Get-ConfigValue -InputObject $install -Name "autoRestartDelaySeconds" -Default 15)
}

function Test-ExchangeRebootPending {
    # Never 'pending' from the planner's side: the install's reboot is signalled by
    # its own RebootRequired result, and holding other roles hostage on a guess
    # would stop every mixed plan after this role's Apply.
    return $false
}

# ---------------------------[ Prerequisites ]---------------------------
# Whether this machine is the one the design means. Consulted by the engine while it
# builds the plan, so "not this server" skips the role instead of failing the run - which
# matters because the same config goes to every machine in the design, and the domain
# controller carrying an Exchange design is there to write the namespace's DNS records,
# not to be told Exchange cannot run on it.
#
# Two ways to answer no. The design naming a different computer is the direct one. A
# domain controller is the other and needs no name: Exchange on a DC is never the answer,
# so a DC is never the machine this role meant, whatever the config says.
function Test-ExchangeAppliesHere {
    param([object]$Config)

    $exchange = Get-ConfigValue -InputObject $Config -Name "exchange"
    if ($null -eq $exchange) { return $false }

    $named = ""
    $namespace = Get-ConfigValue -InputObject $exchange -Name "namespace"
    if ($null -ne $namespace) { $named = Get-ConfigText -InputObject $namespace -Name "serverComputerName" }
    if ([string]::IsNullOrWhiteSpace($named)) {
        $install = Get-ConfigValue -InputObject $exchange -Name "install"
        if ($null -ne $install) { $named = Get-ConfigText -InputObject $install -Name "computerName" }
    }

    if (-not [string]::IsNullOrWhiteSpace($named)) {
        if (-not $named.Trim().Equals([string]$env:COMPUTERNAME, [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Log "The design names '$($named.Trim())' as the Exchange server and this is '$env:COMPUTERNAME'" -Tag "Debug"
            return $false
        }
        return $true
    }

    if (Test-StudioDomainController) {
        Write-Log "This is a domain controller, and no Exchange server is named in the design - Exchange is not for this machine" -Tag "Debug"
        return $false
    }
    return $true
}

function Test-ExchangePrerequisite {
    param([object]$Config)

    if ($null -eq (Get-ConfigValue -InputObject $Config -Name "exchange")) {
        Write-Log "config.json has no exchange section" -Tag "Error"
        return $false
    }
    $passed = $true

    if (Test-StudioDomainController) {
        Write-Log "Exchange on a domain controller is supported by nobody who has run one - use a member server" -Tag "Error"
        return $false
    }

    if (Test-ExchangeInstalled) {
        Write-Log "Exchange is installed at '$(Get-ExchangeInstallPath)' - this run configures it" -Tag "Info"
        return $true
    }

    # The data volume, before setup spends an hour discovering it is not there. Setup
    # creates the folders itself, but not the drive they are on.
    $exchange = Get-ConfigValue -InputObject $Config -Name "exchange"
    $install = Get-ConfigValue -InputObject $exchange -Name "install"
    foreach ($key in @("databasePath", "logPath")) {
        $path = Get-ConfigText -InputObject $install -Name $key
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        $root = ""
        try { $root = [System.IO.Path]::GetPathRoot($path) } catch { $root = "" }
        if ([string]::IsNullOrWhiteSpace($root)) { continue }
        if (-not (Test-Path -LiteralPath $root)) {
            # A missing volume is not automatically a missing disk. When the design lets
            # the run prepare its own database volume and there is exactly one
            # uninitialised disk sitting here, that drive letter is about to exist - so
            # refusing the whole run over it would refuse the fix along with the fault.
            $prepareWanted = [bool](Get-ConfigValue -InputObject $install -Name "prepareDatabaseVolume" -Default $true)
            if ($prepareWanted -and ($null -ne (Get-StudioClaimableDisk))) {
                Write-Log "There is no '$root' yet, and one uninitialised disk to build it from - the install step does that first" -Tag "Warn"
                continue
            }
            Write-Log "The design puts the mailbox database on '$root' and that volume is not on this server" -Tag "Error"
            Write-Log "    Add the disk, or change the data drive in the studio" -Tag "Error"
            $passed = $false
        }
    }

    # .NET 4.8+, read where Windows records it. Setup checks this too, hours later.
    $netRelease = 0
    try {
        $netRelease = [int](Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name "Release" -ErrorAction Stop).Release
    }
    catch {
        Write-Log "The .NET Framework release could not be read" -Tag "Debug"
    }
    if ($netRelease -lt 528040) {
        Write-Log ".NET Framework 4.8 or later is required (found release $netRelease)" -Tag "Error"
        $passed = $false
    }

    # Everything from here down is something the run installs itself when
    # exchange.prerequisites.install is on - the deliberate exception to this repo's
    # never-install rule, and the reason these read as pending work rather than as
    # failures. With the toggle off they are refusals again, each naming its own fix.
    $autoInstall = [bool](Get-ConfigValue -InputObject (Get-ConfigValue -InputObject $exchange -Name "prerequisites") -Name "install" -Default $true)
    $pending = @()

    # Remote Registry must not be Disabled - an SE requirement Microsoft documents,
    # whose failure otherwise surfaces deep inside setup.
    try {
        $remoteRegistry = Get-CimInstance -ClassName "Win32_Service" -Filter "Name='RemoteRegistry'" -ErrorAction Stop
        if ([string]$remoteRegistry.StartMode -eq "Disabled") {
            if ($autoInstall) { $pending += "the Remote Registry service (disabled)" }
            else {
                Write-Log "The Remote Registry service is disabled - Exchange requires it not to be:" -Tag "Error"
                Write-Log "    Set-Service -Name RemoteRegistry -StartupType Automatic" -Tag "Error"
                $passed = $false
            }
        }
    }
    catch {
        Write-Log "The Remote Registry service state could not be read" -Tag "Debug"
    }

    # Server-Media-Foundation, because UCMA refuses without it, and RSAT-ADDS for
    # /PrepareAD. The rest of Microsoft's feature list is setup's own job.
    foreach ($feature in @("Server-Media-Foundation", "RSAT-ADDS")) {
        $state = $null
        try { $state = Get-WindowsFeature -Name $feature -ErrorAction Stop } catch { $state = $null }
        if ($null -eq $state -or $state.Installed) { continue }
        if ($autoInstall) { $pending += "the $feature feature" }
        else {
            Write-Log "The Windows feature '$feature' is required before setup can run:" -Tag "Error"
            Write-Log "    Install-WindowsFeature -Name $feature" -Tag "Error"
            $passed = $false
        }
    }

    # UCMA 4.0 ships on the Exchange ISO in \UCMARedist, and setup refuses without it
    # until SE CU1, which drops the requirement. Detected via its uninstall entry -
    # the medium decides whether it is still needed, so this cannot refuse here.
    if (-not (Test-ExchangeUcma)) {
        if ($autoInstall) { $pending += "UCMA 4.0 (from the ISO)" }
        else {
            Write-Log "UCMA 4.0 is not installed - it is on the Exchange ISO:" -Tag "Error"
            Write-Log "    <ISO>:\UCMARedist\UcmaRuntimeSetup.exe -q" -Tag "Error"
            $passed = $false
        }
    }

    # The two redistributables and URL Rewrite, which the Emergency Mitigation service
    # needs. Setup fails late without them.
    if (-not (Test-ExchangeVcRuntime -Version "11.0" -DisplayYear "2012")) {
        if ($autoInstall) { $pending += "Visual C++ 2012 (x64)" }
        else {
            Write-Log "The Visual C++ 2012 redistributable (x64) is not installed:" -Tag "Error"
            Write-Log "    https://www.microsoft.com/download/details.aspx?id=30679" -Tag "Error"
            $passed = $false
        }
    }
    if (-not (Test-ExchangeVcRuntime -Version "12.0" -DisplayYear "2013")) {
        if ($autoInstall) { $pending += "Visual C++ 2013 (x64)" }
        else {
            Write-Log "The Visual C++ 2013 redistributable (x64) is not installed:" -Tag "Error"
            Write-Log "    https://support.microsoft.com/help/4032938" -Tag "Error"
            $passed = $false
        }
    }
    if (-not (Test-ExchangeUrlRewrite)) {
        if ($autoInstall) { $pending += "the IIS URL Rewrite module" }
        else {
            Write-Log "The IIS URL Rewrite module is not installed - the Emergency Mitigation service needs it:" -Tag "Error"
            Write-Log "    https://www.iis.net/downloads/microsoft/url-rewrite" -Tag "Error"
            $passed = $false
        }
    }

    if ($passed -and $pending.Count) {
        Write-Log "The run installs these before setup: $($pending -join ', ')" -Tag "Info"
    }
    elseif ($passed) {
        # The long feature list is setup's own job: it runs with
        # /InstallWindowsComponents, which is Microsoft's recommended path.
        Write-Log "Prerequisites in place - the Windows features come from setup itself" -Tag "Info"
    }
    return $passed
}

# ---------------------------[ Dependencies ]---------------------------
# The exception in this repo, and a deliberate one. Everywhere else a missing role stops
# the run with the Install-WindowsFeature line printed, because a missing Windows role is
# a design mistake worth stopping for. Exchange is not that shape: setup.exe is a vendor
# installer that already installs its own Windows features with /InstallWindowsComponents,
# and three of its prerequisites are redistributables that Install-WindowsFeature cannot
# deliver at all. Refusing on those spends an operator's evening on three download pages
# to arrive exactly where setup was going to start.
#
# What gets installed, in the order it has to happen:
#   1. Server-Media-Foundation, because UCMA refuses to install without it, and
#      RSAT-ADDS, because /PrepareAD needs it.
#   2. UCMA 4.0 from \UCMARedist on the mounted ISO. No download - it is on the media,
#      which is also why this runs after the mount rather than in the prerequisite check.
#      SE CU1 drops the requirement, so a medium without that folder is not an error.
#   3. Visual C++ 2012 and 2013 (x64) and the IIS URL Rewrite module, which the
#      Emergency Mitigation service needs. These three are downloads. URL Rewrite is
#      installed against IIS and refuses without it, which is why Web-Server is in
#      step 1 rather than left to setup.
#
# Not installed, deliberately: the .NET Framework. That is a servicing-level change with
# its own reboot and its own maintenance window, and every OS supported for SE already
# ships 4.8 - a machine below it is a patching problem, not a missing dependency.
#
# Staging for an offline server needs no config: the run looks in <script root>\downloads
# for the exact file names below before it reaches for the network, so dropping them there
# is all an air-gapped install takes. allowDownload:false makes that mandatory.
function Get-ExchangeDependencySpecification {
    return @(
        [pscustomobject]@{
            Id        = "vcredist2012"
            Name      = "Visual C++ Redistributable 2012 (x64)"
            FileName  = "vcredist_x64_2012.exe"
            Url       = "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe"
            Page      = "https://www.microsoft.com/download/details.aspx?id=30679"
            Arguments = @("/install", "/quiet", "/norestart")
            Test      = { Test-ExchangeVcRuntime -Version "11.0" -DisplayYear "2012" }
        }
        [pscustomobject]@{
            Id        = "vcredist2013"
            Name      = "Visual C++ Redistributable 2013 (x64)"
            FileName  = "vcredist_x64_2013.exe"
            # Microsoft's own redirect for this one - KB4032938 has no static file link.
            Url       = "https://aka.ms/highdpimfc2013x64enu"
            Page      = "https://support.microsoft.com/help/4032938"
            Arguments = @("/install", "/quiet", "/norestart")
            Test      = { Test-ExchangeVcRuntime -Version "12.0" -DisplayYear "2013" }
        }
        [pscustomobject]@{
            Id        = "urlrewrite"
            Name      = "IIS URL Rewrite Module 2.1 (x64)"
            FileName  = "rewrite_amd64_en-US.msi"
            Url       = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi"
            Page      = "https://www.iis.net/downloads/microsoft/url-rewrite"
            Arguments = @()
            Test      = { Test-ExchangeUrlRewrite }
        }
    )
}

# Both uninstall hives, because a 64-bit package can be recorded in either.
function Test-ExchangeUninstallEntry {
    param([Parameter(Mandatory)][string]$Pattern)

    foreach ($hive in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")) {
        $entries = @(Get-ChildItem -Path $hive -ErrorAction SilentlyContinue | ForEach-Object {
            [string](Get-ConfigValue -InputObject (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue) -Name "DisplayName" -Default "")
        })
        if ($entries -match $Pattern) { return $true }
    }
    return $false
}

# The runtime key rather than a display name: the display name carries a build number
# that changes with every servicing release, and this key does not.
function Test-ExchangeVcRuntime {
    param(
        # The Visual Studio version that owns the key - 11.0 is the 2012 package, 12.0
        # the 2013 one. The marketing year is only needed for the display-name fallback.
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)][string]$DisplayYear
    )

    foreach ($path in @("HKLM:\SOFTWARE\Microsoft\VisualStudio\$Version\VC\Runtimes\x64", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\$Version\VC\Runtimes\x64")) {
        try {
            $installed = (Get-ItemProperty -Path $path -Name "Installed" -ErrorAction Stop).Installed
            if ([int]$installed -eq 1) { return $true }
        }
        catch {
            # Not this hive - try the other, then fall through to the display name.
        }
    }
    return (Test-ExchangeUninstallEntry -Pattern "Visual C\+\+ $DisplayYear.*x64")
}

function Test-ExchangeUrlRewrite {
    return [bool](Test-Path -LiteralPath (Join-Path -Path $env:SystemRoot -ChildPath "system32\inetsrv\rewrite.dll"))
}

function Test-ExchangeUcma {
    return (Test-ExchangeUninstallEntry -Pattern "Unified Communications Managed API 4\.0")
}

# 3010 and 3011 are "installed, wants a restart"; 1641 is "restart already started";
# 1638 is a newer version of the same package already present, which is success for
# our purposes. Everything else is a failure worth the exit code in the log.
function Get-ExchangeInstallerOutcome {
    param(
        [Parameter(Mandatory)][int]$ExitCode,
        [Parameter(Mandatory)][string]$Name
    )

    if ($ExitCode -eq 0) {
        Write-Log "$Name installed" -Tag "Ok"
        return [pscustomobject]@{ Success = $true; RebootRequired = $false }
    }
    if ($ExitCode -eq 1638) {
        Write-Log "$Name - a newer version is already installed" -Tag "Info"
        return [pscustomobject]@{ Success = $true; RebootRequired = $false }
    }
    if (@(3010, 3011, 1641) -contains $ExitCode) {
        Write-Log "$Name installed and wants a restart (exit $ExitCode)" -Tag "Ok"
        return [pscustomobject]@{ Success = $true; RebootRequired = $true }
    }
    $meaning = Get-ExchangeInstallerExitCodeMeaning -ExitCode $ExitCode
    if ([string]::IsNullOrWhiteSpace($meaning)) {
        Write-Log "$Name failed with exit code $ExitCode" -Tag "Error"
    }
    else {
        Write-Log "$Name failed with exit code $ExitCode - $meaning" -Tag "Error"
    }
    return [pscustomobject]@{ Success = $false; RebootRequired = $false }
}

# A bare exit code sends an operator to a search engine. The codes below are the ones
# these five packages actually return, and 1603 is the one worth a sentence: under /qn
# it is what an unmet launch condition looks like as well as what a genuine mid-install
# failure looks like, and those are opposite problems.
function Get-ExchangeInstallerExitCodeMeaning {
    param([Parameter(Mandatory)][int]$ExitCode)

    switch ($ExitCode) {
        5     { return "access denied - this needs an elevated session" }
        1601  { return "the Windows Installer service could not be reached" }
        1602  { return "the installation was cancelled" }
        1603  { return "a fatal error during installation, and under /qn also what an unmet launch condition looks like - read the verbose log before assuming the package is broken" }
        1618  { return "another installation is already running - let it finish" }
        1619  { return "the package could not be opened" }
        1620  { return "the package could not be read - a truncated download looks exactly like this" }
        1625  { return "policy forbids this installation" }
        1633  { return "the package is not supported on this platform" }
        default { return "" }
    }
}

# What a verbose MSI log says about a failure is three or four lines in several thousand.
# These are the ones that name the cause: the launch condition that was not met, the
# custom action that returned an error, and the value the engine finally returned.
function Get-ExchangeMsiLogFailure {
    param([Parameter(Mandatory)][string]$LogPath)

    $interesting = @()
    try {
        foreach ($line in (Get-Content -LiteralPath $LogPath -ErrorAction Stop)) {
            if ($line -match "LaunchCondition|Product:.*-- Error|returned actual error|MainEngineThread is returning|Installation failed") {
                $interesting += $line.Trim()
            }
        }
    }
    catch {
        return @()
    }
    if ($interesting.Count -le 4) { return $interesting }
    return $interesting[0..3]
}

# Staged copy first, network second. The signature check is the point of this function:
# these files are fetched over the internet and then executed with SYSTEM's rights, so
# an Authenticode signature that names Microsoft is the difference between installing a
# prerequisite and installing whatever answered the request. Hashes are deliberately not
# pinned - Microsoft reissues these packages, and a pinned hash would turn every reissue
# into a broken deployment while adding nothing the signature does not already prove.
function Resolve-ExchangeDependencyPackage {
    param(
        [Parameter(Mandatory)][object]$Specification,
        [bool]$AllowDownload = $true
    )

    $downloadDirectory = Join-Path -Path $scriptRootPath -ChildPath "downloads"
    $staged = Join-Path -Path $downloadDirectory -ChildPath $Specification.FileName
    if (Test-Path -LiteralPath $staged) {
        Write-Log "Using the staged package '$staged'" -Tag "Info"
        return $staged
    }

    if (-not $AllowDownload) {
        Write-Log "$($Specification.Name) is missing and downloads are off:" -Tag "Error"
        Write-Log "    put '$($Specification.FileName)' in '$downloadDirectory'" -Tag "Error"
        Write-Log "    $($Specification.Page)" -Tag "Error"
        return ""
    }

    try {
        if (-not (Test-Path -LiteralPath $downloadDirectory)) {
            $null = New-Item -Path $downloadDirectory -ItemType Directory -Force -ErrorAction Stop
        }
    }
    catch {
        Write-Log "Could not use '$downloadDirectory' ($($_.Exception.Message)) - downloading to '$env:TEMP' instead" -Tag "Info"
        $downloadDirectory = $env:TEMP
        $staged = Join-Path -Path $downloadDirectory -ChildPath $Specification.FileName
    }

    try {
        Invoke-ArcDownload -Url $Specification.Url -Destination $staged
    }
    catch {
        Write-Log "$($Specification.Name) could not be downloaded: $($_.Exception.Message)" -Tag "Error"
        Write-Log "    fetch it by hand from $($Specification.Page) and save it as '$staged'" -Tag "Error"
        return ""
    }

    $signature = $null
    try { $signature = Get-AuthenticodeSignature -FilePath $staged -ErrorAction Stop } catch { $signature = $null }
    if ($null -eq $signature -or [string]$signature.Status -ne "Valid") {
        Write-Log "'$staged' is not validly signed ($(if ($null -eq $signature) { 'unreadable' } else { $signature.Status })) - refusing to run it" -Tag "Error"
        Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
        return ""
    }
    $subject = [string]$signature.SignerCertificate.Subject
    if ($subject -notmatch "O=Microsoft Corporation") {
        Write-Log "'$staged' is signed by '$subject', not Microsoft - refusing to run it" -Tag "Error"
        Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
        return ""
    }
    Write-Log "Signature valid, signed by Microsoft" -Tag "Ok"
    return $staged
}

function Install-ExchangeDependencyPackage {
    param([Parameter(Mandatory)][object]$Specification, [bool]$AllowDownload = $true)

    $path = Resolve-ExchangeDependencyPackage -Specification $Specification -AllowDownload $AllowDownload
    if ([string]::IsNullOrWhiteSpace($path)) {
        return [pscustomobject]@{ Success = $false; RebootRequired = $false }
    }

    $msiLogPath = ""
    if ($path -match '\.msi$') {
        # /l*v costs nothing on a successful install and is the whole difference on a
        # failed one - msiexec's exit code names no cause, and the log names it in a line.
        $msiLogPath = Join-Path -Path (Get-LogRoleDirectory) -ChildPath ("msi-" + $Specification.Id + "-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".log")
        $arguments = @("/i", "`"$path`"", "/qn", "/norestart", "/l*v", "`"$msiLogPath`"")
        Write-Log "msiexec.exe $($arguments -join ' ')" -Tag "Run"
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru -ErrorAction Stop
    }
    else {
        Write-Log "$path $($Specification.Arguments -join ' ')" -Tag "Run"
        $process = Start-Process -FilePath $path -ArgumentList $Specification.Arguments -Wait -PassThru -ErrorAction Stop
    }

    $outcome = Get-ExchangeInstallerOutcome -ExitCode ([int]$process.ExitCode) -Name $Specification.Name
    if (-not $outcome.Success) {
        if (-not [string]::IsNullOrWhiteSpace($msiLogPath)) {
            Write-Log "    the verbose installer log is '$msiLogPath'" -Tag "Error"
            foreach ($line in (Get-ExchangeMsiLogFailure -LogPath $msiLogPath)) {
                Write-Log "    $line" -Tag "Error"
            }
        }
        Write-Log "    install it by hand from $($Specification.Page) and run this again" -Tag "Error"
        return $outcome
    }

    # Exit 0 is the installer's opinion of itself. A package that reported success and
    # left nothing behind fails later, inside setup's readiness check, where the cause is
    # much further from the effect - so the same test that decided to install it decides
    # whether it is there.
    if (-not (Test-ExchangeDependencyPresence -Specification $Specification)) {
        Write-Log "$($Specification.Name) reported success but is still not detected" -Tag "Error"
        if (-not [string]::IsNullOrWhiteSpace($msiLogPath)) {
            Write-Log "    the verbose installer log is '$msiLogPath'" -Tag "Error"
        }
        return [pscustomobject]@{ Success = $false; RebootRequired = $false }
    }
    return $outcome
}

# Retried rather than read once: a package's registry entries and files settle a moment
# after msiexec returns, and a single check that lands in that moment reads false on
# something that did install.
function Test-ExchangeDependencyPresence {
    param(
        [Parameter(Mandatory)][object]$Specification,
        [int]$Attempts = 3,
        [int]$DelaySeconds = 5
    )

    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        if (& $Specification.Test) { return $true }
        if ($attempt -lt $Attempts) {
            Write-Log "$($Specification.Name) is not detected yet - checking again in $DelaySeconds seconds" -Tag "Debug"
            Start-Sleep -Seconds $DelaySeconds
        }
    }
    return $false
}

# UCMA lives on the medium, so this is the one dependency an air-gapped server already
# has. Microsoft documents UcmaRuntimeSetup.exe -q; the folder also carries a setup.exe,
# which is the fallback when a future medium renames the first.
function Install-ExchangeUcmaPackage {
    param([Parameter(Mandatory)][string]$IsoRoot)

    $redistributable = Join-Path -Path $IsoRoot -ChildPath "UCMARedist"
    if (-not (Test-Path -LiteralPath $redistributable)) {
        # SE CU1 removed the UCMA requirement and the folder with it. Nothing to do,
        # and nothing wrong.
        Write-Log "This medium carries no \UCMARedist - the build does not need UCMA" -Tag "Info"
        return [pscustomobject]@{ Success = $true; RebootRequired = $false }
    }

    $installer = ""
    foreach ($candidate in @("UcmaRuntimeSetup.exe", "setup.exe")) {
        $path = Join-Path -Path $redistributable -ChildPath $candidate
        if (Test-Path -LiteralPath $path) { $installer = $path; break }
    }
    if ([string]::IsNullOrWhiteSpace($installer)) {
        Write-Log "'$redistributable' holds neither UcmaRuntimeSetup.exe nor setup.exe" -Tag "Error"
        return [pscustomobject]@{ Success = $false; RebootRequired = $false }
    }

    $arguments = if ($installer -match 'UcmaRuntimeSetup\.exe$') { @("-q") } else { @("/q") }
    Write-Log "$installer $($arguments -join ' ')" -Tag "Run"
    $process = Start-Process -FilePath $installer -ArgumentList $arguments -Wait -PassThru -ErrorAction Stop
    return (Get-ExchangeInstallerOutcome -ExitCode ([int]$process.ExitCode) -Name "UCMA 4.0")
}

# Four features and no more. The rest of the long list from Microsoft's prerequisite page
# is setup's own job through /InstallWindowsComponents, which is the supported path and
# needs no restart afterwards. These four cannot wait for it, each for its own reason:
#
#   Server-Media-Foundation   UCMA refuses to install without it.
#   RSAT-ADDS                 /PrepareAD needs it.
#   Web-Server                the URL Rewrite module's MSI carries a launch condition on
#                             IIS 7 or greater. On a server that has never had IIS the
#                             condition is unmet, and an unmet launch condition under /qn
#                             is not a message - it is exit code 1603 one second after the
#                             process starts. That is what the 2026-08-09 bench run hit.
#   Web-Mgmt-Console          URL Rewrite registers a UI module against it, and setup
#                             wants it regardless.
#
# Installing IIS here does not duplicate what setup does. /InstallWindowsComponents adds
# the rest of the list on top of a role that is already present, which is the same work
# it would have done from nothing.
function Install-ExchangeWindowsPrerequisiteFeature {
    $rebootRequired = $false
    foreach ($feature in @("Server-Media-Foundation", "RSAT-ADDS", "Web-Server", "Web-Mgmt-Console")) {
        $state = $null
        try { $state = Get-WindowsFeature -Name $feature -ErrorAction Stop } catch { $state = $null }
        if ($null -eq $state) {
            Write-Log "The Windows feature '$feature' could not be read" -Tag "Error"
            return [pscustomobject]@{ Success = $false; RebootRequired = $false }
        }
        if ($state.Installed) {
            Write-Log "Windows feature '$feature' is already installed" -Tag "Debug"
            continue
        }

        try {
            Write-Log "Install-WindowsFeature -Name $feature" -Tag "Run"
            $result = Install-WindowsFeature -Name $feature -ErrorAction Stop
            if (-not $result.Success) {
                Write-Log "The Windows feature '$feature' did not install" -Tag "Error"
                return [pscustomobject]@{ Success = $false; RebootRequired = $false }
            }
            Write-Log "Windows feature '$feature' installed" -Tag "Ok"
            if ([string]$result.RestartNeeded -eq "Yes") { $rebootRequired = $true }
        }
        catch {
            Write-Log "The Windows feature '$feature' did not install: $($_.Exception.Message)" -Tag "Error"
            return [pscustomobject]@{ Success = $false; RebootRequired = $false }
        }
    }
    return [pscustomobject]@{ Success = $true; RebootRequired = $rebootRequired }
}

# Documented as an SE requirement, and its failure otherwise surfaces deep inside setup.
# Started as well as set: setup reads it, it does not wait for the next boot.
function Set-ExchangeRemoteRegistryStartup {
    try {
        $service = Get-CimInstance -ClassName "Win32_Service" -Filter "Name='RemoteRegistry'" -ErrorAction Stop
        if ([string]$service.StartMode -ne "Disabled") { return $true }
        Set-Service -Name "RemoteRegistry" -StartupType Automatic -ErrorAction Stop
        Start-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue
        Write-Log "The Remote Registry service was disabled - set to Automatic and started" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "The Remote Registry service could not be enabled: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

# The orchestrator. Returns Success plus RebootRequired, and the caller decides what a
# reboot means - which matters, because a restart before setup has run is not the same
# event as the one after it.
function Invoke-ExchangeDependencyInstall {
    param(
        [Parameter(Mandatory)][object]$Exchange,
        [Parameter(Mandatory)][string]$IsoRoot
    )

    $settings = Get-ConfigValue -InputObject $Exchange -Name "prerequisites"
    if (-not [bool](Get-ConfigValue -InputObject $settings -Name "install" -Default $true)) {
        Write-Log "Installing prerequisites is off - setup will refuse if any of them is missing" -Tag "Info"
        return [pscustomobject]@{ Success = $true; RebootRequired = $false }
    }
    $allowDownload = [bool](Get-ConfigValue -InputObject $settings -Name "allowDownload" -Default $true)

    Write-Log "Checking the Exchange prerequisites" -Tag "Info"
    $rebootRequired = $false

    if (-not (Set-ExchangeRemoteRegistryStartup)) { return [pscustomobject]@{ Success = $false; RebootRequired = $false } }

    $features = Install-ExchangeWindowsPrerequisiteFeature
    if (-not $features.Success) { return [pscustomobject]@{ Success = $false; RebootRequired = $false } }
    if ($features.RebootRequired) { $rebootRequired = $true }

    # UCMA after the feature, never before: it is the feature it refuses without. If the
    # feature run wants a restart, that ordering is a reason to stop rather than push on.
    if (-not (Test-ExchangeUcma)) {
        if ($rebootRequired) {
            Write-Log "UCMA needs Server-Media-Foundation, which asked for a restart first" -Tag "Info"
        }
        else {
            $ucma = Install-ExchangeUcmaPackage -IsoRoot $IsoRoot
            if (-not $ucma.Success) { return [pscustomobject]@{ Success = $false; RebootRequired = $false } }
            if ($ucma.RebootRequired) { $rebootRequired = $true }
        }
    }
    else {
        Write-Log "UCMA 4.0 is already installed" -Tag "Debug"
    }

    # Same reasoning as UCMA above, for the same reason one line further out: URL Rewrite
    # is installed against IIS, and a feature install that asked for a restart has not
    # finished presenting IIS to it. The caller turns this into a pending Apply step, so
    # the next run arrives here with the features settled and installs the three packages.
    if ($rebootRequired) {
        Write-Log "A Windows feature asked for a restart - the downloaded prerequisites install after it" -Tag "Info"
        return [pscustomobject]@{ Success = $true; RebootRequired = $true }
    }

    foreach ($specification in Get-ExchangeDependencySpecification) {
        if (& $specification.Test) {
            Write-Log "$($specification.Name) is already installed" -Tag "Debug"
            continue
        }
        $outcome = Install-ExchangeDependencyPackage -Specification $specification -AllowDownload $allowDownload
        if (-not $outcome.Success) { return [pscustomobject]@{ Success = $false; RebootRequired = $false } }
        if ($outcome.RebootRequired) { $rebootRequired = $true }
    }

    return [pscustomobject]@{ Success = $true; RebootRequired = $rebootRequired }
}

# ---------------------------[ Media ]---------------------------
function Get-ExchangeSetupPath {
    param(
        [object]$Exchange,
        [switch]$NoInteraction
    )

    $media = Get-ConfigValue -InputObject $Exchange -Name "media"
    $configured = ""
    if ($null -ne $media) { $configured = Get-ConfigText -InputObject $media -Name "isoPath" }
    if ([string]::IsNullOrWhiteSpace($configured)) { $configured = "isos\ExchangeServer*.iso" }

    $isoPath = Resolve-StudioIsoPath -ConfiguredPath $configured -Title "Select the Exchange Server ISO" -NoInteraction:$NoInteraction
    if ([string]::IsNullOrWhiteSpace($isoPath)) { return "" }

    $root = Mount-StudioIso -IsoFilePath $isoPath
    $setupPath = Join-Path -Path $root -ChildPath "Setup.exe"

    # Prove it is the Exchange medium before hours are spent in it. Setup.exe plus one
    # of the folders an Exchange ISO carries and a Windows ISO does not - UCMARedist on
    # RTM media, and Exchange Server\Setup on any of it, because SE CU1 drops UCMA and
    # the folder with it. Requiring UCMARedist alone would reject CU1 media outright.
    $exchangeMarkers = @("UCMARedist", "Exchange Server", "Setup\ServerRoles") | Where-Object {
        Test-Path -LiteralPath (Join-Path -Path $root -ChildPath $_)
    }
    if (-not (Test-Path -LiteralPath $setupPath) -or -not @($exchangeMarkers).Count) {
        Write-Log "'$isoPath' does not look like Exchange media - no Setup.exe beside UCMARedist, 'Exchange Server' or Setup\ServerRoles" -Tag "Error"
        return ""
    }

    try {
        $version = [string](Get-Item -LiteralPath $setupPath).VersionInfo.ProductVersion
        Write-Log "Exchange media: $isoPath (setup $version)" -Tag "Info"

        # Compared as numbers, never as text. SE RTM reports itself as 15.02.2562.017 -
        # zero-padded, which is what a string test like '^15\.2\.2' fails on while
        # looking correct. Only the first three parts are read, because the fourth is
        # padded too and nothing here depends on it.
        $parsed = [regex]::Match($version, '(\d+)\.(\d+)\.(\d+)')
        if ($parsed.Success) {
            $major = [int]$parsed.Groups[1].Value
            $minor = [int]$parsed.Groups[2].Value
            $build = [int]$parsed.Groups[3].Value
            # Exchange 2019's CUs run to build 1748; SE starts at 2562. 2500 sits in the
            # gap with room for a 2019 CU that will never come now.
            if (-not ($major -eq 15 -and $minor -eq 2 -and $build -ge 2500)) {
                Write-Log "Not Subscription Edition media (15.2 build 2500+, found $major.$minor.$build) - this design targets SE" -Tag "Warn"
            }
            else {
                Write-Log "Subscription Edition media confirmed (build $build)" -Tag "Debug"
            }
        }
        else {
            Write-Log "The setup version '$version' is not a version number - not checking it for SE" -Tag "Debug"
        }
    }
    catch {
        Write-Log "The setup version could not be read off the media" -Tag "Debug"
    }
    return $setupPath
}

# ---------------------------[ The database volume ]---------------------------
# Exchange's own specification, stated here and nowhere else. The shared volume helper
# in Storage.ps1 deliberately carries no defaults, because the Hyper-V role's ReFS
# numbers are a different answer to a different question and a shared default is how one
# silently becomes the other.
#
# 64 KB: "ReFS allocation unit size - Supported: All allocation unit sizes. Best
# practice: 64 KB for both .edb and log file volumes."
# Integrity streams off: "Data integrity features must be disabled for the Exchange
# database (.edb) files or the volume that hosts these files."
# The label names what the volume holds rather than which product opens it.
$script:exchangeVolumeFileSystem         = "ReFS"
$script:exchangeVolumeAllocationUnitSize = 65536
$script:exchangeVolumeLabel              = "Database"

# ReFS is Microsoft's Preferred Architecture choice, not a requirement - the storage
# table lists NTFS and ReFS as equally supported - so a volume that cannot be brought to
# it is a warning and the install carries on.
function Initialize-ExchangeDatabaseVolume {
    param([Parameter(Mandatory)][object]$Exchange)

    $install      = Get-ConfigValue -InputObject $Exchange -Name "install"
    $databasePath = Get-ConfigText -InputObject $install -Name "databasePath"
    if ([string]::IsNullOrWhiteSpace($databasePath)) {
        Write-Log "The design names no database path - setup picks its own location" -Tag "Info"
        return $true
    }

    $letter = ""
    try { $letter = ([string][System.IO.Path]::GetPathRoot($databasePath)).TrimEnd("\", ":") } catch { $letter = "" }
    if ([string]::IsNullOrWhiteSpace($letter)) {
        Write-Log "'$databasePath' does not start with a drive letter, so no volume was prepared" -Tag "Warn"
        return $true
    }

    $allowPrepare = [bool](Get-ConfigValue -InputObject $install -Name "prepareDatabaseVolume" -Default $true)
    if (-not $allowPrepare) {
        Write-Log "Database volume preparation off - the volume is inspected" -Tag "Info"
    }

    $result = Initialize-StudioDataVolume -DriveLetter $letter `
        -FileSystem $script:exchangeVolumeFileSystem `
        -AllocationUnitSize $script:exchangeVolumeAllocationUnitSize `
        -Label $script:exchangeVolumeLabel `
        -IntegrityStreams $false `
        -AllowPrepare:$allowPrepare

    if (-not $result.Ready) {
        Write-Log $result.Message -Tag "Error"
        return $false
    }
    if (-not $result.ToSpec) {
        Write-Log $result.Message -Tag "Warn"
        Write-Log "    NTFS and other allocation units work - 64K ReFS is Microsoft's best practice, not a requirement" -Tag "Debug"
    }

    # The folders before setup, and cleared before setup, because integrity streams are
    # inherited from the parent directory and toggling a directory does not reach files
    # that already exist. A folder cleared now is a database born cleared; the same call
    # after the install is a correction that never touches the .edb.
    $folders = @()
    $databaseFolder = ""
    try { $databaseFolder = [System.IO.Path]::GetDirectoryName($databasePath) } catch { $databaseFolder = "" }
    if (-not [string]::IsNullOrWhiteSpace($databaseFolder)) { $folders += $databaseFolder }
    $logPath = Get-ConfigText -InputObject $install -Name "logPath"
    if (-not [string]::IsNullOrWhiteSpace($logPath)) { $folders += $logPath }

    foreach ($folder in $folders) {
        if (-not (Test-Path -LiteralPath $folder)) {
            try {
                $null = New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop
                Write-Log "Created '$folder' ahead of setup" -Tag "Info"
            }
            catch {
                # Setup creates these itself, so this is not fatal - it only costs the
                # inherited integrity setting, which the post-install pass reports on.
                Write-Log "'$folder' could not be created ahead of setup: $($_.Exception.Message)" -Tag "Warn"
                continue
            }
        }
        $null = Disable-StudioIntegrityStream -Path $folder
    }

    return $true
}

function Invoke-ExchangeSetup {
    # Both preparation and install funnel through here: same licence switch, same
    # exit-code reading, same log pointer when it goes wrong.
    param(
        [Parameter(Mandatory)][string]$SetupPath,
        [Parameter(Mandatory)][string[]]$ArgumentList
    )

    $arguments = @("/IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF") + $ArgumentList
    Write-Log "$SetupPath $($arguments -join ' ')" -Tag "Run"
    & $SetupPath @arguments 2>&1 | ForEach-Object {
        $line = [string]$_
        if (-not [string]::IsNullOrWhiteSpace($line)) { Write-Log "    $($line.Trim())" -Tag "Debug" }
    }
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        Write-Log "Exchange setup exited with $exitCode - the full story is in C:\ExchangeSetupLogs\ExchangeSetup.log" -Tag "Error"
        return $false
    }
    return $true
}

# ---------------------------[ Management shell ]---------------------------
# The snap-in when it loads, remote PowerShell to localhost when it does not -
# straight from the field-proven renewal script this role absorbed.
function Import-ExchangeManagementShell {
    if (Get-Command -Name "Get-ExchangeCertificate" -ErrorAction SilentlyContinue) { return $true }

    try {
        Write-Log "Loading the Exchange management snap-in" -Tag "Run"
        Add-PSSnapin -Name "Microsoft.Exchange.Management.PowerShell.SnapIn" -ErrorAction Stop
    }
    catch {
        Write-Log "Snap-in failed ($($_.Exception.Message)) - connecting over remote PowerShell" -Tag "Info"
        try {
            $session = New-PSSession -ConfigurationName "Microsoft.Exchange" -ConnectionUri "http://localhost/PowerShell/" -Authentication Kerberos -ErrorAction Stop
            Import-PSSession -Session $session -DisableNameChecking -AllowClobber -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Log "The Exchange management shell could not be loaded: $($_.Exception.Message)" -Tag "Error"
            return $false
        }
    }

    return [bool](Get-Command -Name "Get-ExchangeCertificate" -ErrorAction SilentlyContinue)
}

# ---------------------------[ Post-install configuration ]---------------------------
function Set-ExchangeNamespace {
    # One FQDN for everything, internal equal to external, split DNS assumed - the
    # deployment shape Microsoft's own guidance has settled on. The installer left
    # every URL at the machine's own name, which no certificate anybody buys will
    # carry.
    param([Parameter(Mandatory)][object]$Exchange)

    $namespace = Get-ConfigValue -InputObject $Exchange -Name "namespace"
    $hostName = Get-ConfigText -InputObject $namespace -Name "hostName"
    if ([string]::IsNullOrWhiteSpace($hostName)) {
        Write-Log "No namespace host name in the design - the virtual directories keep the machine name" -Tag "Warn"
        return $true
    }
    $autodiscover = Get-ConfigText -InputObject $namespace -Name "autodiscoverName" -Default ("autodiscover." + ($hostName -replace '^[^.]+\.', ''))
    $base = "https://$hostName"
    $server = $env:COMPUTERNAME

    $applied = $true
    $steps = @(
        @{ Cmdlet = "Set-OwaVirtualDirectory";          Internal = "$base/owa";                       External = "$base/owa" }
        @{ Cmdlet = "Set-EcpVirtualDirectory";          Internal = "$base/ecp";                       External = "$base/ecp" }
        @{ Cmdlet = "Set-WebServicesVirtualDirectory";  Internal = "$base/EWS/Exchange.asmx";         External = "$base/EWS/Exchange.asmx" }
        @{ Cmdlet = "Set-ActiveSyncVirtualDirectory";   Internal = "$base/Microsoft-Server-ActiveSync"; External = "$base/Microsoft-Server-ActiveSync" }
        @{ Cmdlet = "Set-OabVirtualDirectory";          Internal = "$base/OAB";                       External = "$base/OAB" }
        @{ Cmdlet = "Set-MapiVirtualDirectory";         Internal = "$base/mapi";                      External = "$base/mapi" }
    )
    # -Confirm:$false everywhere, and -Force only where the cmdlet has it. That last part
    # is not defensive coding, it is a fact worth encoding: Set-WebServicesVirtualDirectory
    # takes -Force ("hides warning or confirmation messages") and needs it, because it is
    # the one of the six that prompts when the URLs change and the resume task's session
    # has no console to answer - "Windows PowerShell is in NonInteractive mode" is what
    # that prompt looks like from there. Set-MapiVirtualDirectory has no -Force at all,
    # so passing it blindly turns a working call into a parameter-binding failure. Asked
    # of Get-Command rather than of a list in this file, which cannot go stale.
    foreach ($step in $steps) {
        try {
            $directory = & ("Get-" + $step.Cmdlet.Substring(4)) -Server $server -ErrorAction Stop
            $command = Get-Command -Name $step.Cmdlet -ErrorAction SilentlyContinue
            foreach ($entry in @($directory)) {
                $parameters = @{
                    Identity    = $entry.Identity
                    InternalUrl = $step.Internal
                    ExternalUrl = $step.External
                    Confirm     = $false
                    ErrorAction = "Stop"
                }
                if (($null -ne $command) -and $command.Parameters.ContainsKey("Force")) { $parameters["Force"] = $true }
                # Microsoft's own note on the MAPI directory: "When you use the InternalUrl
                # or ExternalUrl parameters, you need to specify one or more authentication
                # values by using the IISAuthenticationMethods parameter." Whatever is
                # there is passed back unchanged - the point is to satisfy the requirement,
                # not to have an opinion about the authentication - and only a directory
                # with none gets the documented default, which includes OAuth because the
                # same page says to always have it on.
                if ($step.Cmdlet -eq "Set-MapiVirtualDirectory") {
                    $methods = @($entry.IISAuthenticationMethods | ForEach-Object { [string]$_ } |
                        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                    if ($methods.Count -eq 0) { $methods = @("NTLM", "Negotiate", "OAuth") }
                    $parameters["IISAuthenticationMethods"] = $methods
                }
                & $step.Cmdlet @parameters
            }
            Write-Log "$($step.Cmdlet): $($step.External)" -Tag "Ok"
        }
        catch {
            Write-Log "$($step.Cmdlet) failed: $($_.Exception.Message)" -Tag "Error"
            $applied = $false
        }
    }

    try {
        Get-OutlookAnywhere -Server $server -ErrorAction Stop | ForEach-Object {
            # SSL offloading off is an Extended Protection prerequisite; SE setup
            # already disables it, so this is reasserting the supported state.
            Set-OutlookAnywhere -Identity $_.Identity -InternalHostname $hostName -ExternalHostname $hostName `
                -InternalClientsRequireSsl $true -ExternalClientsRequireSsl $true `
                -ExternalClientAuthenticationMethod Negotiate -SSLOffloading $false -ErrorAction Stop
        }
        Write-Log "Outlook Anywhere: $hostName, Negotiate, no SSL offloading" -Tag "Ok"
    }
    catch {
        Write-Log "Outlook Anywhere could not be set: $($_.Exception.Message)" -Tag "Error"
        $applied = $false
    }

    # The seventh directory, and the one with a scheme of its own: Microsoft's own
    # verification tables in "Configure mail flow and client access on Exchange servers"
    # give every other directory an https URL and this one
    # http://<namespace>/PowerShell - http, on the shared name, internal and external
    # alike. The runspace is not unencrypted for it; the PowerShell directory does not
    # require SSL in IIS and the session is protected by the WinRM/Kerberos layer rather
    # than by TLS at that URL.
    #
    # An earlier version of this function put it in the loop above with the other six
    # and gave it https, which is what produced "Server Error in '/ecp' Application" on
    # the 2026-08-09 bench build - ECP and EMS do their work by opening a remote
    # runspace against this URL, and an https URL on a directory that is not serving
    # SSL there fails inside ECP with an ASP.NET exception that says nothing about any
    # of this. Setting it explicitly rather than leaving it alone is deliberate: it also
    # repairs a server an older copy of this script already changed.
    # The PowerShell virtual directory is not touched, and the reason is one sentence in
    # the Extended Protection documentation - the current one, which covers Subscription
    # Edition: **"Making modifications to the Default Website/PowerShell virtual
    # directory is not supported unless explicitly advised by Microsoft Customer Service
    # and Support (CSS)."**
    #
    # The older post-install page does list it, with an http URL, in a table written in
    # 2018 - before Extended Protection existed. That table is where two earlier versions
    # of this function got their instructions: the first set it to https like the other
    # six, the second to http because the table said so. Both were modifications, and
    # both were unsupported. The same EP article gives the front-end PowerShell directory
    # `Off` and sslFlags of `SslNegotiateCert` alone - no `Ssl` flag, so the endpoint is
    # deliberately not SSL-required, which is also why remote EMS to an SE server fails
    # with 403.4 the moment somebody switches Require SSL on.
    #
    # So it is read and reported, never written.
    $powershellDirectory = $null
    try { $powershellDirectory = @(Get-PowerShellVirtualDirectory -Server $server -ErrorAction Stop)[0] } catch { $powershellDirectory = $null }
    if ($null -ne $powershellDirectory) {
        $powershellUrl = [string]$powershellDirectory.InternalUrl
        if ([string]::IsNullOrWhiteSpace($powershellUrl)) { $powershellUrl = "(not set)" }
        if ($powershellUrl -like "https://*") {
            Write-Log "The PowerShell virtual directory is set to '$powershellUrl'" -Tag "Warn"
            Write-Log "    Modifying that directory is unsupported, and an https URL on it breaks remote EMS - setup uses 'http://<fqdn>/powershell'" -Tag "Warn"
        }
        else {
            Write-Log "PowerShell virtual directory left as setup wrote it ('$powershellUrl') - modifying it is unsupported" -Tag "Debug"
        }
    }

    try {
        Get-ClientAccessService -Identity $server -ErrorAction Stop | Out-Null
        Set-ClientAccessService -Identity $server -AutoDiscoverServiceInternalUri "https://$autodiscover/Autodiscover/Autodiscover.xml" -ErrorAction Stop
        Write-Log "Autodiscover SCP: https://$autodiscover/Autodiscover/Autodiscover.xml" -Tag "Ok"
    }
    catch {
        Write-Log "The Autodiscover SCP could not be set: $($_.Exception.Message)" -Tag "Error"
        $applied = $false
    }
    return $applied
}

# What this organization answers for. A fresh install accepts mail for the *internal*
# forest domain and nothing else, which on `ad.lab.invalid` means nothing routable
# at all - and Exchange rejects mail for a domain it has not been told about.
#
# Authoritative means every mailbox for the domain is here and an unknown address is
# refused; internal relay means some recipients live elsewhere, so unknown addresses
# are forwarded rather than rejected. An existing entry is left as it is - changing a
# live domain's type changes what happens to mail for every address in it.
function Set-ExchangeAcceptedDomain {
    param([Parameter(Mandatory)][object]$Exchange)

    $domains = @(Get-ConfigArray -InputObject $Exchange -Name "acceptedDomains")
    if ($domains.Count -eq 0) {
        Write-Log "No accepted domain in the design - this organization answers for its internal forest domain only" -Tag "Warn"
        return $true
    }

    $allDone = $true
    foreach ($entry in $domains) {
        $name = Get-ConfigText -InputObject $entry -Name "name"
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $type = Get-ConfigText -InputObject $entry -Name "type" -Default "authoritative"
        $domainType = $(if ($type -eq "internalRelay") { "InternalRelay" } else { "Authoritative" })

        $wantsDefault = [bool](Get-ConfigValue -InputObject $entry -Name "isDefault" -Default $false)

        $existing = $null
        try { $existing = Get-AcceptedDomain -Identity $name -ErrorAction SilentlyContinue } catch { $existing = $null }
        if ($null -ne $existing) {
            if ([string]$existing.DomainType -ne $domainType) {
                Write-Log "'$name' is accepted as $($existing.DomainType), design says $domainType - left as it is; the type decides what happens to mail for every address in it" -Tag "Warn"
            }
            else {
                Write-Log "'$name' is already an accepted $domainType domain" -Tag "Debug"
            }
            if (-not (Set-ExchangeDefaultDomain -Name $name -WantsDefault $wantsDefault -Existing $existing)) { $allDone = $false }
            continue
        }

        try {
            $null = New-AcceptedDomain -Name $name -DomainName $name -DomainType $domainType -ErrorAction Stop
            Write-Log "Accepted domain '$name' created as $domainType" -Tag "Ok"
        }
        catch {
            Write-Log "The accepted domain '$name' could not be created: $($_.Exception.Message)" -Tag "Error"
            $allDone = $false
            continue
        }
        if (-not (Set-ExchangeDefaultDomain -Name $name -WantsDefault $wantsDefault)) { $allDone = $false }
    }
    return $allDone
}

# The default accepted domain: what Exchange falls back to when something needs an
# address and no policy supplied one. A fresh organization makes the **internal forest
# domain** the default, because it is the first accepted domain there is - which is why
# a new install shows "ad.lab.invalid (default domain)" beside a routable domain nobody
# can reply to.
#
# Only ever set, never cleared. Exchange has exactly one default and `-MakeDefault $true`
# on a domain moves it there; there is no "make this not the default", and inventing one
# by picking another domain to promote would be this design choosing something the design
# never said. A row that stops being the default in the studio simply stops being set
# here, and whatever holds it keeps it until something else is marked.
function Set-ExchangeDefaultDomain {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$WantsDefault,
        [object]$Existing = $null
    )

    if (-not $WantsDefault) { return $true }

    if (($null -ne $Existing) -and [bool]$Existing.Default) {
        Write-Log "'$Name' is already the default accepted domain" -Tag "Debug"
        return $true
    }

    try {
        Set-AcceptedDomain -Identity $Name -MakeDefault $true -ErrorAction Stop
        Write-Log "'$Name' is now the default accepted domain" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "'$Name' could not be made the default accepted domain: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

# What a mailbox's address looks like. The built-in policy stamps the *internal* forest
# domain, so without this every mailbox gets an address nobody outside can reply to -
# and nothing about it looks broken until somebody tries.
#
# Applying a policy rewrites the primary address of every mailbox it matches, which is
# what makes it right on a fresh organization and worth thinking about on one that has
# been running - so the run says how many mailboxes it touched.
function Set-ExchangeEmailPolicy {
    param([Parameter(Mandatory)][object]$Exchange)

    $policy = Get-ConfigValue -InputObject $Exchange -Name "emailPolicy"
    if (($null -eq $policy) -or (-not [bool](Get-ConfigValue -InputObject $policy -Name "manage" -Default $false))) {
        Write-Log "Email address policy left alone" -Tag "Info"
        return $true
    }

    $template = Get-ConfigText -InputObject $policy -Name "addressTemplate"
    if ([string]::IsNullOrWhiteSpace($template)) {
        Write-Log "The address policy has no template - nothing to apply" -Tag "Error"
        return $false
    }

    # The internal address is kept as a secondary: it costs nothing and whatever
    # already sends to it carries on working. Lower case 'smtp:' is what makes an
    # entry secondary; upper case 'SMTP:' is the primary, and there can be one.
    $templates = @($template)
    if ([bool](Get-ConfigValue -InputObject $policy -Name "keepInternalAddress" -Default $true)) {
        $internalDomain = [string]$env:USERDNSDOMAIN
        if (-not [string]::IsNullOrWhiteSpace($internalDomain)) {
            $templates += ("smtp:%m@" + $internalDomain.ToLowerInvariant())
        }
    }

    $target = Get-ConfigText -InputObject $policy -Name "target" -Default "default"
    $name = Get-ConfigText -InputObject $policy -Name "name" -Default "Default Policy"

    try {
        if ($target -eq "default") {
            Set-EmailAddressPolicy -Identity "Default Policy" -EnabledEmailAddressTemplates $templates -ErrorAction Stop
            $name = "Default Policy"
            Write-Log "The Default Policy now stamps $template" -Tag "Ok"
        }
        else {
            $existing = $null
            try { $existing = Get-EmailAddressPolicy -Identity $name -ErrorAction SilentlyContinue } catch { $existing = $null }
            if ($null -eq $existing) {
                $null = New-EmailAddressPolicy -Name $name -IncludedRecipients "AllRecipients" `
                    -EnabledEmailAddressTemplates $templates -Priority 1 -ErrorAction Stop
                Write-Log "Email address policy '$name' created, stamping $template" -Tag "Ok"
            }
            else {
                Set-EmailAddressPolicy -Identity $name -EnabledEmailAddressTemplates $templates -ErrorAction Stop
                Write-Log "Email address policy '$name' updated to stamp $template" -Tag "Ok"
            }
        }

        # A policy changes nothing until it is applied - the one step that is easy to
        # miss, because creating it reports success either way.
        Update-EmailAddressPolicy -Identity $name -ErrorAction Stop
        Write-Log "Policy '$name' applied to the mailboxes it matches" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "The email address policy could not be written: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

# The difference between "550 in the SMTP conversation" and "250 OK, then a bounce to
# whoever the sender claimed to be". The second is backscatter, it is how a mail server
# ends up on a blocklist, and it is also why a filter in front cannot verify an address:
# there is nothing to ask when the answer is always yes.
#
# Two steps, and the first is the one everybody misses: Exchange's anti-spam agents are
# **not installed on a Mailbox server** by default - they ship with the product but the
# transport service does not load them until that script has run.
function Set-ExchangeRecipientValidation {
    param([Parameter(Mandatory)][object]$Exchange)

    $hardening = Get-ConfigValue -InputObject $Exchange -Name "hardening"
    if (-not [bool](Get-ConfigValue -InputObject $hardening -Name "recipientValidation" -Default $true)) {
        Write-Log "Recipient validation off - this server accepts mail for addresses that do not exist and bounces it after" -Tag "Warn"
        return $true
    }

    $agentInstalled = $false
    try {
        $agents = @(Get-TransportAgent -ErrorAction Stop)
        $agentInstalled = @($agents | Where-Object { [string]$_.Identity -match "(?i)recipient filter" }).Count -gt 0
    }
    catch {
        Write-Log "The transport agent list could not be read: $($_.Exception.Message)" -Tag "Warn"
    }

    if (-not $agentInstalled) {
        $installPath = Get-ExchangeInstallPath
        $script = Join-Path -Path $installPath -ChildPath "Scripts\Install-AntiSpamAgents.ps1"
        if (-not (Test-Path -LiteralPath $script)) {
            Write-Log "Install-AntiSpamAgents.ps1 was not found under '$installPath' - the anti-spam agents cannot be installed here" -Tag "Error"
            return $false
        }
        Write-Log "Installing the anti-spam agents (they are not on a Mailbox server by default)" -Tag "Run"
        try {
            & $script -ErrorAction Stop | ForEach-Object {
                $line = [string]$_
                if (-not [string]::IsNullOrWhiteSpace($line)) { Write-Log "    $($line.Trim())" -Tag "Debug" }
            }
        }
        catch {
            Write-Log "The anti-spam agents could not be installed: $($_.Exception.Message)" -Tag "Error"
            return $false
        }

        # The agents are loaded at transport start, so nothing above takes effect until
        # this restart. Mail queues for the few seconds it takes.
        try {
            Restart-Service -Name "MSExchangeTransport" -Force -ErrorAction Stop
            Write-Log "Transport restarted so the agents load" -Tag "Ok"
        }
        catch {
            Write-Log "MSExchangeTransport could not be restarted: $($_.Exception.Message)" -Tag "Error"
            return $false
        }
    }
    else {
        Write-Log "The recipient filter agent is already installed" -Tag "Debug"
    }

    try {
        Set-RecipientFilterConfig -Enabled $true -RecipientValidationEnabled $true -ErrorAction Stop
        Write-Log "Recipient validation on - an unknown address is refused with 550 5.1.1" -Tag "Ok"
        Write-Log "The sending server owns the bounce now, which is what stops this one generating backscatter" -Tag "Debug"
        Write-Log "A mail gateway in front can verify an address from here: it gets a real answer to RCPT TO" -Tag "Debug"
        return $true
    }
    catch {
        Write-Log "Recipient validation could not be enabled: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

# The filter in front, on a port of its own. Separate from the anonymous relay: that is
# printers sending outward, this is the gateway delivering inbound mail and asking
# whether an address exists. A port of its own is what keeps the two from ever being
# confused, and lets a firewall rule name one of them.
function Set-ExchangeInboundGateway {
    param([Parameter(Mandatory)][object]$Exchange)

    $gateway = Get-ConfigValue -InputObject $Exchange -Name "inboundGateway"
    if (($null -eq $gateway) -or (-not [bool](Get-ConfigValue -InputObject $gateway -Name "enabled" -Default $false))) {
        return $true
    }

    $name = Get-ConfigText -InputObject $gateway -Name "name" -Default "Inbound Gateway"
    # 2526, not 2525: Exchange's own "Default <server>" Hub Transport connector already
    # listens on 2525, and a Frontend connector cannot share it.
    $port = [int](Get-ConfigValue -InputObject $gateway -Name "port" -Default 2526)
    $requireTls = [bool](Get-ConfigValue -InputObject $gateway -Name "requireTls" -Default $false)
    $ranges = @(Get-ConfigArray -InputObject $gateway -Name "remoteIpRanges" | ForEach-Object { [string]$_ } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    if ($ranges.Count -eq 0) {
        Write-Log "The inbound gateway connector has no addresses - it would accept mail from anything that can reach port $port" -Tag "Error"
        return $false
    }

    try {
        $connectors = @(Get-ReceiveConnector -Server $env:COMPUTERNAME -ErrorAction Stop)
        $existing = $connectors | Where-Object { $_.Name -eq $name }

        # Exchange's rule: two receive connectors in *different* transport roles may not
        # share a local binding. Its own defaults already hold five ports on a Mailbox
        # server, and 2525 - the obvious "not 25" choice, and this design's original
        # default - is one of them: "Default <server>" is the Hub Transport connector and
        # it listens there. Creating a Frontend connector on the same port fails with a
        # message about bindings that names a connector nobody went looking for. Checked
        # here so the reason given is the reason, not the cmdlet's phrasing of it.
        $clash = $connectors | Where-Object {
            ($_.Name -ne $name) -and
            ([string]$_.TransportRole -ne "FrontendTransport") -and
            (@($_.Bindings | ForEach-Object { [string]$_ }) -match (":{0}$" -f $port))
        } | Select-Object -First 1
        if ($null -ne $clash) {
            Write-Log "Port $port is already bound by the '$($clash.Name)' connector, which is $([string]$clash.TransportRole)" -Tag "Error"
            Write-Log "    Two receive connectors in different transport roles cannot share a port - give the gateway another one" -Tag "Error"
            Write-Log "    Exchange's own defaults hold 25, 465, 587, 717 and 2525 on a Mailbox server" -Tag "Debug"
            return $false
        }

        if ($null -eq $existing) {
            $null = New-ReceiveConnector -Name $name -Server $env:COMPUTERNAME -TransportRole "FrontendTransport" `
                -Usage "Custom" -Bindings ("0.0.0.0:{0}" -f $port) -RemoteIPRanges $ranges -ErrorAction Stop
            Write-Log "Receive connector '$name' created on port $port for $($ranges -join ', ')" -Tag "Ok"
        }
        else {
            Set-ReceiveConnector -Identity $existing.Identity -Bindings ("0.0.0.0:{0}" -f $port) -RemoteIPRanges $ranges -ErrorAction Stop
            Write-Log "Receive connector '$name' reconciled on port $port" -Tag "Ok"
        }

        $connector = Get-ReceiveConnector -Identity ("{0}\{1}" -f $env:COMPUTERNAME, $name) -ErrorAction Stop
        # Anonymous, because a filter appliance is not a domain member - but *not* the
        # accept-any-recipient right the relay connector gets. This one delivers to
        # recipients that exist here, which is exactly what makes recipient validation
        # answer a real question.
        Set-ReceiveConnector -Identity $connector.Identity -PermissionGroups "AnonymousUsers" -ErrorAction Stop
        if ($requireTls) {
            Set-ReceiveConnector -Identity $connector.Identity -RequireTLS $true -ErrorAction Stop
            Write-Log "'$name' requires TLS" -Tag "Info"
        }
        Write-Log "'$name' accepts inbound mail from the gateway only" -Tag "Info"
        return $true
    }
    catch {
        Write-Log "The inbound gateway connector could not be written: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

# CVE-2021-1730, and one of the few Exchange settings that is pure gain. Attachments
# are served from a name that is *not* the OWA origin, so the browser applies its
# SameSite cookie rules to them and a cross-site request cannot ride an authenticated
# session. Two settings plus a DNS alias, and the alias is written by the DNS role.
# Does the namespace resolve from here? Reported, not fixed - the records belong to the
# domain controller's run (Set-DnsExchangeRecord). Worth asking on this side because
# Outlook fails at Autodiscover long before a mailbox ever opens, and "the certificate
# is fine but nothing connects" is otherwise an afternoon.
function Test-ExchangeNamespaceResolution {
    param([Parameter(Mandatory)][object]$Exchange)

    $namespace = Get-ConfigValue -InputObject $Exchange -Name "namespace"
    if ($null -eq $namespace) { return }

    $names = @()
    foreach ($key in @("hostName", "autodiscoverName")) {
        $value = Get-ConfigText -InputObject $namespace -Name $key
        if (-not [string]::IsNullOrWhiteSpace($value)) { $names += $value }
    }
    $hardening = Get-ConfigValue -InputObject $Exchange -Name "hardening"
    if ([bool](Get-ConfigValue -InputObject $hardening -Name "downloadDomains" -Default $true)) {
        $download = Get-ConfigText -InputObject $namespace -Name "downloadName"
        if (-not [string]::IsNullOrWhiteSpace($download)) { $names += $download }
    }

    foreach ($name in $names) {
        try {
            $addresses = @([System.Net.Dns]::GetHostAddresses($name) |
                Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork })
            if ($addresses.Count -gt 0) {
                Write-Log "'$name' resolves to $($addresses[0].IPAddressToString)" -Tag "Ok"
                continue
            }
            Write-Log "'$name' resolves to no IPv4 address" -Tag "Warn"
        }
        catch {
            Write-Log "'$name' does not resolve from this server - clients will not reach it either" -Tag "Warn"
            Write-Log "    The domain controller's run creates these records; check that it ran, or create them by hand" -Tag "Info"
        }
    }
}

function Set-ExchangeDownloadDomain {
    param([Parameter(Mandatory)][object]$Exchange)

    $hardening = Get-ConfigValue -InputObject $Exchange -Name "hardening"
    if (-not [bool](Get-ConfigValue -InputObject $hardening -Name "downloadDomains" -Default $true)) {
        Write-Log "Download domains are switched off - attachments come from the OWA origin (CVE-2021-1730 unmitigated)" -Tag "Warn"
        return $true
    }

    $namespace = Get-ConfigValue -InputObject $Exchange -Name "namespace"
    $downloadName = Get-ConfigText -InputObject $namespace -Name "downloadName"
    if ([string]::IsNullOrWhiteSpace($downloadName)) {
        Write-Log "Download domains are on but the design carries no attachment host name" -Tag "Error"
        return $false
    }

    $applied = $true
    try {
        Get-OwaVirtualDirectory -Server $env:COMPUTERNAME -ErrorAction Stop | ForEach-Object {
            Set-OwaVirtualDirectory -Identity $_.Identity `
                -InternalDownloadHostName $downloadName -ExternalDownloadHostName $downloadName -ErrorAction Stop
        }
        Write-Log "OWA serves attachments from '$downloadName'" -Tag "Ok"
    }
    catch {
        Write-Log "The download host name could not be set: $($_.Exception.Message)" -Tag "Error"
        $applied = $false
    }

    # Organization-wide, so it is set once and reported when it is already right.
    try {
        $organization = Get-OrganizationConfig -ErrorAction Stop
        if ([bool]$organization.EnableDownloadDomains) {
            Write-Log "EnableDownloadDomains is already on" -Tag "Debug"
        }
        else {
            Set-OrganizationConfig -EnableDownloadDomains $true -ErrorAction Stop
            Write-Log "EnableDownloadDomains switched on for the organization" -Tag "Ok"
        }
    }
    catch {
        Write-Log "EnableDownloadDomains could not be set: $($_.Exception.Message)" -Tag "Error"
        $applied = $false
    }

    Write-Log "'$downloadName' has to resolve and the certificate has to carry it, or OWA shows broken attachments" -Tag "Info"
    return $applied
}

# The admin console, and the one place here where the obvious cmdlet is the wrong answer.
#
# ECP is served from the same virtual directory as OWA's own Settings page, so by default
# anything that can reach webmail can reach the login page of the tool that administers
# the organization. There are two ways to narrow that and they are not equivalent:
#
#   internalOnly  a **Client Access Rule** denying the `ExchangeAdminCenter` protocol
#                 except from listed addresses. This one is genuinely per-origin - the
#                 rule matches the address the request arrives from, so the console keeps
#                 working inside and stops answering outside. It is scoped to the
#                 *protocol*, not the virtual directory, so OWA's Options page is
#                 untouched. Microsoft's own "turn off access to the EAC" document now
#                 says the AdminEnabled procedure below is no longer recommended for
#                 2019 and later and points here instead.
#   adminOff      `-AdminEnabled $false`. Per **virtual directory**, not per origin: with
#                 one ECP directory on one server the console goes away internally too,
#                 and keeping internal access means a second directory - a second server,
#                 or a second IIS web site with its own ECP *and* OWA directories, which a
#                 CU does not update and which therefore has to be rebuilt every CU.
#
# Rules live in Active Directory, so a new one is not instant. And a DenyAccess rule with
# no exceptions denies the console to everybody including whoever ran this, which is why
# an empty list refuses instead of writing it.
function Set-ExchangeEcpAccess {
    param([Parameter(Mandatory)][object]$Exchange)

    $access = Get-ConfigValue -InputObject $Exchange -Name "ecpAccess"
    $mode = [string](Get-ConfigValue -InputObject $access -Name "mode" -Default "leave")
    # A document written before this was a mode said the same thing with a boolean.
    $hardening = Get-ConfigValue -InputObject $Exchange -Name "hardening"
    if (-not $mode -or $mode -eq "leave") {
        if ([bool](Get-ConfigValue -InputObject $hardening -Name "disableEcpAdmin" -Default $false)) { $mode = "adminOff" }
    }

    switch ($mode) {
        "internalOnly" {
            $ranges = @(Get-ConfigArray -InputObject $access -Name "internalRanges" | Where-Object { $_ })
            if (-not $ranges.Count) {
                Write-Log "Admin console restricted to internal addresses and none listed - a deny rule with no exceptions locks everybody out, so nothing was written" -Tag "Error"
                return $false
            }
            if (-not (Get-Command -Name "New-ClientAccessRule" -ErrorAction SilentlyContinue)) {
                Write-Log "Client Access Rules unavailable - the ExchangeAdminCenter protocol needs Exchange 2019 or later" -Tag "Error"
                return $false
            }

            $ruleName = "Block ExchangeAdminCenter from outside"
            try {
                $existing = Get-ClientAccessRule -Identity $ruleName -ErrorAction SilentlyContinue
                if ($existing) {
                    Set-ClientAccessRule -Identity $ruleName -ExceptAnyOfClientIPAddressesOrRanges $ranges -Enabled $true -ErrorAction Stop
                    Write-Log "Client Access Rule '$ruleName' updated: $($ranges -join ', ')" -Tag "Ok"
                }
                else {
                    New-ClientAccessRule -Name $ruleName -Action DenyAccess -AnyOfProtocols ExchangeAdminCenter `
                        -ExceptAnyOfClientIPAddressesOrRanges $ranges -Priority 1 -ErrorAction Stop | Out-Null
                    Write-Log "Client Access Rule '$ruleName' created: the admin console answers only from $($ranges -join ', ')" -Tag "Ok"
                }
                Write-Log "    OWA's Settings and Options page is untouched - the rule is scoped to the admin protocol" -Tag "Debug"
                Write-Log "The rule is read from Active Directory, so give it a moment before testing" -Tag "Debug"
                return $true
            }
            catch {
                Write-Log "The Client Access Rule could not be written: $($_.Exception.Message)" -Tag "Error"
                return $false
            }
        }
        "adminOff" {
            try {
                $directories = @(Get-EcpVirtualDirectory -Server $env:COMPUTERNAME -ErrorAction Stop)
                foreach ($directory in $directories) {
                    Set-EcpVirtualDirectory -Identity $directory.Identity -AdminEnabled $false -ErrorAction Stop
                    Write-Log "Admin console disabled on '$($directory.Identity)'" -Tag "Ok"
                }
                Write-Log "AdminEnabled is per virtual directory, not per origin - the console is gone internally too, leaving the Management Shell" -Tag "Warn"
                Write-Log "    Microsoft no longer recommends this for 2019+; a Client Access Rule keeps the console for internal addresses" -Tag "Info"
                Write-Log "    OWA's Settings and Options page is unaffected" -Tag "Debug"
                return $true
            }
            catch {
                Write-Log "The admin console could not be disabled: $($_.Exception.Message)" -Tag "Error"
                return $false
            }
        }
        default {
            Write-Log "The admin console answers wherever OWA does - restrict /ecp at the reverse proxy if it is published" -Tag "Info"
            return $true
        }
    }
}

function Set-ExchangeTransportLimit {
    param([Parameter(Mandatory)][object]$Exchange)

    $transport = Get-ConfigValue -InputObject $Exchange -Name "transport"
    if ($null -eq $transport) { return $true }

    $sizeMb = [int](Get-ConfigValue -InputObject $transport -Name "maxMessageSizeMb" -Default 35)
    $size = "{0}MB" -f $sizeMb
    $applied = $true

    # The organization limit and both connector limits, because the smallest of the
    # three decides and Exchange ships them at different values - a message rejected
    # by the one nobody changed looks like a mail loop rather than a limit.
    try {
        Set-TransportConfig -MaxSendSize $size -MaxReceiveSize $size -ErrorAction Stop
        Write-Log "Organization message size limit: $size" -Tag "Ok"
    }
    catch {
        Write-Log "The organization message size could not be set: $($_.Exception.Message)" -Tag "Error"
        $applied = $false
    }

    try {
        Get-ReceiveConnector -Server $env:COMPUTERNAME -ErrorAction Stop | ForEach-Object {
            Set-ReceiveConnector -Identity $_.Identity -MaxMessageSize $size -ErrorAction Stop
        }
        Get-SendConnector -ErrorAction Stop | ForEach-Object {
            Set-SendConnector -Identity $_.Identity -MaxMessageSize $size -ErrorAction Stop
        }
        Write-Log "Connector message size limits: $size" -Tag "Ok"
    }
    catch {
        Write-Log "A connector message size could not be set: $($_.Exception.Message)" -Tag "Warn"
    }

    # Whose name is on a bounce leaving the organization. Unset it is the server's own
    # machine name, which leaks the hostname and reaches nobody.
    $postmaster = Get-ConfigText -InputObject $transport -Name "externalPostmaster"
    if (-not [string]::IsNullOrWhiteSpace($postmaster)) {
        try {
            Set-TransportConfig -ExternalPostmasterAddress $postmaster -ErrorAction Stop
            Write-Log "External postmaster address: $postmaster" -Tag "Ok"
        }
        catch {
            Write-Log "The external postmaster address could not be set: $($_.Exception.Message)" -Tag "Warn"
        }
    }

    Write-Log "A ${sizeMb}MB limit passes roughly $([int]($sizeMb * 0.73))MB of real attachment - base64 adds about a third" -Tag "Debug"
    return $applied
}

function Set-ExchangeDatabaseDefault {
    # Exchange's own quota defaults are effectively unlimited, which turns a full
    # volume into an outage rather than a warning.
    param([Parameter(Mandatory)][object]$Exchange)

    $defaults = Get-ConfigValue -InputObject $Exchange -Name "databaseDefaults"
    if (($null -eq $defaults) -or (-not [bool](Get-ConfigValue -InputObject $defaults -Name "enabled" -Default $true))) {
        Write-Log "Mailbox database quotas and retention are left as they are" -Tag "Info"
        return $true
    }

    $warningGb = [int](Get-ConfigValue -InputObject $defaults -Name "quotaWarningGb" -Default 45)
    $sendGb = [int](Get-ConfigValue -InputObject $defaults -Name "quotaSendGb" -Default 48)
    $bothGb = [int](Get-ConfigValue -InputObject $defaults -Name "quotaSendReceiveGb" -Default 50)
    $retention = [int](Get-ConfigValue -InputObject $defaults -Name "deletedItemRetentionDays" -Default 30)
    $circular = [bool](Get-ConfigValue -InputObject $defaults -Name "circularLogging" -Default $false)

    $applied = $true
    try {
        $databases = @(Get-MailboxDatabase -Server $env:COMPUTERNAME -ErrorAction Stop)
        foreach ($database in $databases) {
            Set-MailboxDatabase -Identity $database.Identity `
                -IssueWarningQuota ("{0}GB" -f $warningGb) `
                -ProhibitSendQuota ("{0}GB" -f $sendGb) `
                -ProhibitSendReceiveQuota ("{0}GB" -f $bothGb) `
                -DeletedItemRetention ("{0}.00:00:00" -f $retention) `
                -CircularLoggingEnabled $circular -ErrorAction Stop
            Write-Log "'$($database.Name)': warn ${warningGb}GB, stop sending ${sendGb}GB, stop receiving ${bothGb}GB, dumpster $retention day(s)" -Tag "Ok"
        }
        if ($databases.Count -eq 0) { Write-Log "No mailbox database on this server yet" -Tag "Info" }
    }
    catch {
        Write-Log "The mailbox database defaults could not be applied: $($_.Exception.Message)" -Tag "Error"
        $applied = $false
    }

    if ($circular) {
        Write-Log "Circular logging ON - no point-in-time recovery, the logs to roll a restore forward are overwritten" -Tag "Warn"
    }
    else {
        Write-Log "    Logs accumulate until an Exchange-aware backup truncates them" -Tag "Debug"
    }
    return $applied
}

# The Health Checker's operating-system findings, which are the same four on every
# Exchange server anybody has ever run. All of them are read at boot or at service
# start, so the reboot the install already owed covers them.
function Set-ExchangeOperatingSystemTuning {
    param([Parameter(Mandatory)][object]$Exchange)

    $hardening = Get-ConfigValue -InputObject $Exchange -Name "hardening"
    if (-not [bool](Get-ConfigValue -InputObject $hardening -Name "tuneOperatingSystem" -Default $true)) {
        Write-Log "The operating-system tuning is switched off - the Health Checker will flag it" -Tag "Info"
        return $true
    }

    # KeepAliveTime. Without it the default is two hours, and every load balancer and
    # firewall in the path cuts an idle RPC session long before that - which arrives
    # as Outlook disconnecting for no reason anybody can reproduce.
    $tcpPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $keepAlive = $null
    try { $keepAlive = [int](Get-ItemProperty -Path $tcpPath -Name "KeepAliveTime" -ErrorAction Stop).KeepAliveTime } catch { $keepAlive = $null }
    if ($keepAlive -ne 1800000) {
        Set-ItemProperty -Path $tcpPath -Name "KeepAliveTime" -Value 1800000 -Type DWord
        Write-Log "KeepAliveTime = 1800000 (30 minutes)" -Tag "Ok"
    }

    # RPC minimum connection timeout, 120 seconds. Same family of symptom.
    $rpcPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\RPC"
    $rpcTimeout = $null
    try { $rpcTimeout = [int](Get-ItemProperty -Path $rpcPath -Name "MinimumConnectionTimeout" -ErrorAction Stop).MinimumConnectionTimeout } catch { $rpcTimeout = $null }
    if ($rpcTimeout -ne 120) {
        if (-not (Test-Path -LiteralPath $rpcPath)) { $null = New-Item -Path $rpcPath -Force }
        Set-ItemProperty -Path $rpcPath -Name "MinimumConnectionTimeout" -Value 120 -Type DWord
        Write-Log "RPC MinimumConnectionTimeout = 120 seconds" -Tag "Ok"
    }

    # High Performance. Exchange is latency-sensitive and the balanced plan parks
    # cores; the GUID is the built-in scheme's and is the same on every Windows.
    try {
        $null = & powercfg.exe "/setactive" "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" 2>&1
        if ($LASTEXITCODE -eq 0) { Write-Log "Power plan: High Performance" -Tag "Ok" }
        else { Write-Log "The power plan could not be set - powercfg exited $LASTEXITCODE" -Tag "Warn" }
    }
    catch {
        Write-Log "The power plan could not be set: $($_.Exception.Message)" -Tag "Warn"
    }

    # A page file Exchange can actually dump into. Microsoft's rule for a server with
    # 32 GB or less is RAM plus 10 MB, capped at 32778 MB above that - and a
    # system-managed page file on a big-memory box is what makes a crash dump useless.
    try {
        $totalMb = [int]([math]::Round((Get-CimInstance -ClassName "Win32_ComputerSystem" -ErrorAction Stop).TotalPhysicalMemory / 1MB))
        $wanted = $totalMb + 10
        if ($wanted -gt 32778) { $wanted = 32778 }

        $computer = Get-CimInstance -ClassName "Win32_ComputerSystem" -ErrorAction Stop
        if ($computer.AutomaticManagedPagefile) {
            $null = Set-CimInstance -InputObject $computer -Property @{ AutomaticManagedPagefile = $false } -ErrorAction Stop
            Write-Log "The page file was system-managed - taking it over so a crash dump is usable" -Tag "Info"
        }
        $pageFile = Get-CimInstance -ClassName "Win32_PageFileSetting" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -eq $pageFile) {
            $null = New-CimInstance -ClassName "Win32_PageFileSetting" -Property @{ Name = "$env:SystemDrive\pagefile.sys"; InitialSize = $wanted; MaximumSize = $wanted } -ErrorAction Stop
            Write-Log "Page file created at ${wanted}MB, fixed" -Tag "Ok"
        }
        elseif (([int]$pageFile.InitialSize -ne $wanted) -or ([int]$pageFile.MaximumSize -ne $wanted)) {
            $null = Set-CimInstance -InputObject $pageFile -Property @{ InitialSize = $wanted; MaximumSize = $wanted } -ErrorAction Stop
            Write-Log "Page file set to ${wanted}MB, fixed (was $($pageFile.InitialSize)-$($pageFile.MaximumSize)MB)" -Tag "Ok"
        }
        else {
            Write-Log "Page file is already ${wanted}MB, fixed" -Tag "Debug"
        }
    }
    catch {
        Write-Log "The page file could not be set: $($_.Exception.Message)" -Tag "Warn"
        Write-Log "Set it by hand to RAM + 10 MB, capped at 32778 MB, initial equal to maximum" -Tag "Info"
    }

    # "Do you have a sleepy NIC?" - the Exchange team's own phrase. A network card
    # allowed to power down drops sessions for no visible reason, and in a DAG it flips
    # databases. PnPCapabilities bit 0x18 under the network class key is what the
    # checkbox in Device Manager writes; the Health Checker accepts 24 or 280.
    $networkClassPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}"
    try {
        $adapters = @(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -ne "Disabled" })
        foreach ($adapter in $adapters) {
            # The class key is indexed by the adapter's own four-digit instance, which
            # is the tail of its PnP device id - matching on the description would hit
            # every card of the same model, including ones that are not here.
            $index = ""
            try {
                $pnp = Get-CimInstance -ClassName "Win32_NetworkAdapter" -Filter ("DeviceID='{0}'" -f $adapter.DeviceID) -ErrorAction Stop
                $index = "{0:D4}" -f [int]$pnp.Index
            }
            catch {
                $index = ""
            }
            if ([string]::IsNullOrWhiteSpace($index)) {
                Write-Log "The class key index for '$($adapter.Name)' could not be read - power management left alone" -Tag "Warn"
                continue
            }
            $adapterKey = Join-Path -Path $networkClassPath -ChildPath $index
            if (-not (Test-Path -LiteralPath $adapterKey)) { continue }

            $capabilities = $null
            try { $capabilities = [int](Get-ItemProperty -Path $adapterKey -Name "PnPCapabilities" -ErrorAction Stop).PnPCapabilities } catch { $capabilities = $null }
            if (($capabilities -eq 24) -or ($capabilities -eq 280)) {
                Write-Log "'$($adapter.Name)' already has power management off" -Tag "Debug"
                continue
            }
            Set-ItemProperty -Path $adapterKey -Name "PnPCapabilities" -Value 24 -Type DWord
            Write-Log "'$($adapter.Name)': NIC power management off (PnPCapabilities 24) - applies at the next restart" -Tag "Ok"
        }
    }
    catch {
        Write-Log "The network adapters could not be read, so NIC power management was left alone: $($_.Exception.Message)" -Tag "Warn"
    }

    # The data volume: reported, never formatted. Microsoft's guidance for a database
    # volume is ReFS with integrity streams **off** and a 64K allocation unit - the
    # format is destructive, so the only thing safe to do here is turn integrity
    # streams off on the folder when the volume already is ReFS. Leaving them on is a
    # supportability problem rather than a preference: ReFS integrity streams and a
    # database that writes in place do not agree.
    $exchangeSection = $Exchange
    $install = Get-ConfigValue -InputObject $exchangeSection -Name "install"
    $databasePath = Get-ConfigText -InputObject $install -Name "databasePath"
    if (-not [string]::IsNullOrWhiteSpace($databasePath)) {
        $driveLetter = ""
        try { $driveLetter = ([string][System.IO.Path]::GetPathRoot($databasePath)).TrimEnd("\", ":") } catch { $driveLetter = "" }
        if (-not [string]::IsNullOrWhiteSpace($driveLetter)) {
            try {
                $volume = Get-Volume -DriveLetter $driveLetter[0] -ErrorAction Stop
                $fileSystem = [string]$volume.FileSystemType
                if ($fileSystem -match "(?i)refs") {
                    Write-Log "The database volume ${driveLetter}: is ReFS" -Tag "Ok"
                    # Integrity streams are cleared before setup by
                    # Initialize-ExchangeDatabaseVolume, where it reaches the database
                    # because the database does not exist yet. This is the check that it
                    # held, and the repair for a volume this run did not build - the
                    # sweep of existing files is the half a folder-level toggle misses.
                    $folder = [System.IO.Path]::GetDirectoryName($databasePath)
                    $null = Disable-StudioIntegrityStream -Path $folder
                }
                else {
                    Write-Log "Database volume ${driveLetter}: is $fileSystem - Microsoft asks for ReFS, integrity streams off, 64K units" -Tag "Info"
                    Write-Log "    Reformatting is destructive, so not done here: Format-Volume -DriveLetter $driveLetter -FileSystem ReFS -AllocationUnitSize 65536 -SetIntegrityStreams `$false" -Tag "Info"
                    Write-Log "    NTFS is supported and works; this is a performance and resiliency recommendation, not a requirement" -Tag "Debug"
                }
                if ([int]$volume.AllocationUnitSize -ne 65536) {
                    Write-Log "Database volume allocation unit is $($volume.AllocationUnitSize) bytes, Microsoft asks for 65536" -Tag "Info"
                    Write-Log "    Only a reformat changes it - the volume holds a database now, so this is for the next build" -Tag "Debug"
                }
            }
            catch {
                Write-Log "The database volume could not be inspected: $($_.Exception.Message)" -Tag "Debug"
            }
        }
    }

    if ([bool](Get-ConfigValue -InputObject $hardening -Name "disableSmb1" -Default $true)) {
        try {
            $smb1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction Stop
            if ($smb1.State -eq "Enabled") {
                $null = Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction Stop
                Write-Log "SMB1 removed - takes effect at the next restart" -Tag "Ok"
            }
            else {
                Write-Log "SMB1 is already gone" -Tag "Debug"
            }
        }
        catch {
            Write-Log "SMB1 could not be checked or removed: $($_.Exception.Message)" -Tag "Warn"
        }
    }

    # Named rather than left as "these settings", because the volume block above is the
    # one thing here a restart does *not* fix: an allocation unit is decided at format
    # time and nowhere else, and a closing line saying "the reboot applies them" read as
    # though it covered that too.
    Write-Log "    Power, network and SMB settings above are read at boot or service start" -Tag "Debug"
    return $true
}

function Set-ExchangeServiceCertificate {
    param([Parameter(Mandatory)][object]$Exchange)

    $certificate = Get-ConfigValue -InputObject $Exchange -Name "certificate"
    if ($null -eq $certificate) { return $true }

    $thumbprint = Resolve-StudioCertificate -Certificate $certificate
    if ([string]::IsNullOrWhiteSpace($thumbprint)) {
        Write-Log "The certificate source resolves to nothing to bind - IIS keeps what it has" -Tag "Info"
        return $true
    }

    return (Set-ExchangeCertificateBinding -Thumbprint $thumbprint)
}

# What the Exchange Back End site serves on 444, read straight out of IIS. Empty means
# nothing is bound, which is the broken state this file exists to notice.
# The certificate a site is actually presenting on a port, straight out of IIS. Empty
# means nothing is bound there; "unknown" means the question could not be asked, which is
# not the same answer and must not be treated as one.
function Get-ExchangeSiteCertificateHash {
    param(
        [Parameter(Mandatory)][string]$SiteName,
        [Parameter(Mandatory)][int]$Port
    )

    if (-not (Get-Command -Name "Get-WebBinding" -ErrorAction SilentlyContinue)) {
        try { Import-Module -Name "WebAdministration" -ErrorAction Stop }
        catch {
            Write-Log "The WebAdministration module is not available - the '$SiteName' binding cannot be checked" -Tag "Warn"
            return "unknown"
        }
    }
    try {
        $binding = Get-WebBinding -Name $SiteName -Port $Port -Protocol "https" -ErrorAction Stop
        if ($null -eq $binding) { return "" }
        return ([string]$binding.certificateHash).Trim()
    }
    catch {
        Write-Log "The '$SiteName' binding on port $Port could not be read: $($_.Exception.Message)" -Tag "Debug"
        return ""
    }
}

function Get-ExchangeBackEndCertificateHash {
    # Present on any Exchange server by definition, but imported rather than assumed:
    # this runs inside the Exchange snap-in's session, and an auto-load that does not
    # happen would read as "nothing is bound" and start a repair nobody needs.
    if (-not (Get-Command -Name "Get-WebBinding" -ErrorAction SilentlyContinue)) {
        try { Import-Module -Name "WebAdministration" -ErrorAction Stop }
        catch {
            Write-Log "The WebAdministration module is not available - the Exchange Back End binding cannot be checked" -Tag "Warn"
            return "unknown"
        }
    }
    try {
        $binding = Get-WebBinding -Name "Exchange Back End" -Port 444 -Protocol "https" -ErrorAction Stop
        if ($null -eq $binding) { return "" }
        return ([string]$binding.certificateHash).Trim()
    }
    catch {
        Write-Log "The Exchange Back End binding could not be read: $($_.Exception.Message)" -Tag "Debug"
        return ""
    }
}

# Binding a certificate to IIS, and then repairing what that does behind your back.
#
# Setup binds a self-signed certificate called "Microsoft Exchange" to the **Exchange
# Back End** site on port 444. Microsoft's own words for what it is: "The certificate is
# for communication between the Default Web Site and Exchange Back End websites. When
# the certificate is removed, the Default Web Site can't proxy connections to the
# Exchange Back End website." Every client protocol goes through that proxy hop - OWA,
# ECP, ActiveSync, EWS, remote PowerShell.
#
# `Enable-ExchangeCertificate -Services IIS` rebinds the front end, and it is widely
# observed to take the back end's binding with it: the new certificate lands on 443 and
# 444 is left with nothing. The front end then serves perfectly while everything behind
# it fails, which is why the symptom is a runtime error on /ecp rather than anything
# resembling a certificate problem. This cost the 2026-08-09 bench build two rebuilds
# and a wrong diagnosis before the cause was found.
#
# So the binding is read before and after, and put back when it moved. The *previous*
# thumbprint is restored rather than a fresh certificate minted - the certificate that
# was there is the right answer, and New-ExchangeCertificate is only the fallback for
# the case where it has genuinely gone.
function Set-ExchangeCertificateBinding {
    param([Parameter(Mandatory)][string]$Thumbprint)

    # Reported here because this is the one place the role binds anything, and an
    # internal-CA certificate from a schema 3 template reaches it without going near the
    # ACME import path. It is a line in the log and nothing more - see the function for
    # why it is not allowed to change what happens next.
    $null = Test-StudioCertificateProvider -Thumbprint $Thumbprint

    # Nothing below needs doing when the certificate is already the one being served,
    # and "nothing below" includes the restart. The post-install pass and the PostReboot
    # stage both reach here, and the nightly task reaches it every night - a function
    # that always restarted IIS would restart it for no reason far more often than for
    # a reason.
    #
    # "Enabled for the service" and "the certificate IIS is actually serving" are two
    # different facts, and only the second one is what a browser meets. A run interrupted
    # between Enable-ExchangeCertificate and the restart - or any earlier version of this
    # function, which had the restart behind an inverted condition - leaves Exchange
    # saying the certificate is bound while Default Web Site still presents the previous
    # one. So both are checked, and the front-end binding is the tie-breaker.
    if (Test-ExchangeCertificateBound -Thumbprint $Thumbprint) {
        $served = Get-ExchangeSiteCertificateHash -SiteName "Default Web Site" -Port 443
        if (($served -eq "unknown") -or $served.Equals($Thumbprint, [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Log "$Thumbprint is already the certificate IIS and SMTP serve - nothing to bind" -Tag "Info"
            return $true
        }
        Write-Log "$Thumbprint is enabled for IIS but Default Web Site is still serving $served - restarting IIS so it picks it up" -Tag "Warn"
        $null = Restart-ExchangeIisService
        return $true
    }

    $backEndBefore = Get-ExchangeBackEndCertificateHash

    try {
        # -Force, or the cmdlet stops to ask about replacing the default SMTP
        # certificate - the self-signed one, which stays in the store on purpose:
        # it carries the internal back-end bindings and removing it breaks them.
        Enable-ExchangeCertificate -Thumbprint $Thumbprint -Services "IIS", "SMTP" -Force -ErrorAction Stop
        Write-Log "Certificate $Thumbprint bound to IIS and SMTP" -Tag "Ok"
    }
    catch {
        Write-Log "The certificate could not be bound: $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    # The restart the certificate change itself needs: the binding takes effect on the
    # next connection, but the worker processes hold the old SSL context and Exchange's
    # services cache what they started with.
    #
    # This used to hang off `-not (Repair-...)`, which reads as "restart unless the
    # repair already did" and behaved as the opposite: the repair returns **true** when
    # the back end was *fine*, so the ordinary case - nothing to repair - never restarted
    # anything. The bench found it by the absence of a line.
    $null = Repair-ExchangeBackEndBinding -Previous $backEndBefore -FrontEndThumbprint $Thumbprint
    $null = Restart-ExchangeIisService
    return $true
}

# Whether IIS and SMTP already serve this certificate, asked of Exchange rather than of
# IIS: Enable-ExchangeCertificate is the cmdlet this would call, so the right question is
# the one that cmdlet answers - which services this thumbprint is enabled for.
function Test-ExchangeCertificateBound {
    param([Parameter(Mandatory)][string]$Thumbprint)

    try {
        $certificate = Get-ExchangeCertificate -Thumbprint $Thumbprint -ErrorAction Stop
        if ($null -eq $certificate) { return $false }
        $services = [string]$certificate.Services
        return (($services -match "(?i)IIS") -and ($services -match "(?i)SMTP"))
    }
    catch {
        Write-Log "Which services $Thumbprint is enabled for could not be read: $($_.Exception.Message)" -Tag "Debug"
        return $false
    }
}

# After the certificate changes, always. The binding itself takes effect on the next
# connection, but the worker processes hold the old SSL context and Exchange's own
# services cache what they were started with - so without this the server is correctly
# configured and still serving the previous certificate to anything with an open
# connection. Cheap on a server being built, and the renewal path only reaches it on the
# roughly ninety-day occasions when the certificate actually changed.
function Restart-ExchangeIisService {
    try {
        Write-Log "iisreset /noforce" -Tag "Run"
        $reset = Start-Process -FilePath "iisreset.exe" -ArgumentList @("/noforce") -Wait -PassThru -NoNewWindow -ErrorAction Stop
        if ([int]$reset.ExitCode -eq 0) {
            Write-Log "IIS restarted so the new certificate is the one being served" -Tag "Ok"
            return $true
        }
        Write-Log "iisreset returned $([int]$reset.ExitCode) - restart IIS before testing OWA or ECP" -Tag "Warn"
    }
    catch {
        Write-Log "iisreset did not run ($($_.Exception.Message)) - restart IIS before testing OWA or ECP" -Tag "Warn"
    }
    return $false
}

function Repair-ExchangeBackEndBinding {
    param(
        [string]$Previous = "",
        [Parameter(Mandatory)][string]$FrontEndThumbprint
    )

    $current = Get-ExchangeBackEndCertificateHash
    if ($current -eq "unknown") {
        Write-Log "Check by hand that 'Exchange Back End' still has a certificate on port 444 - OWA and ECP fail without one" -Tag "Warn"
        return $false
    }
    $wanted = $Previous

    # The back end must not end up serving the public certificate. It is not what that
    # certificate is for, the name on it is not the server's, and the front end's proxy
    # hop does not check the name anyway - but a public certificate on an internal
    # endpoint is a renewal away from breaking the same thing again.
    if ((-not [string]::IsNullOrWhiteSpace($current)) -and
        (-not $current.Equals($FrontEndThumbprint, [System.StringComparison]::OrdinalIgnoreCase))) {
        Write-Log "The Exchange Back End site still serves its own certificate on port 444" -Tag "Debug"
        return $true
    }

    if ($current.Equals($FrontEndThumbprint, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Log "Binding to IIS moved the public certificate onto the Exchange Back End site too - putting the internal one back" -Tag "Warn"
    }
    else {
        Write-Log "Binding to IIS left Exchange Back End on port 444 with no certificate - OWA, ECP and remote PowerShell cannot proxy" -Tag "Warn"
    }

    # The one that was there, if it is still in the store. Otherwise the self-signed
    # certificate Exchange keeps for itself: subject equal to issuer, and this server's
    # own name on it.
    if ((-not [string]::IsNullOrWhiteSpace($wanted)) -and
        $wanted.Equals($FrontEndThumbprint, [System.StringComparison]::OrdinalIgnoreCase)) {
        $wanted = ""
    }
    if ([string]::IsNullOrWhiteSpace($wanted) -or
        (-not (Test-Path -LiteralPath ("Cert:\LocalMachine\My\{0}" -f $wanted)))) {
        $wanted = ""
        try {
            $candidate = @(Get-ExchangeCertificate -ErrorAction Stop |
                Where-Object { $_.IsSelfSigned -and ($_.Thumbprint -ne $FrontEndThumbprint) } |
                Sort-Object -Property NotAfter -Descending)
            if ($candidate.Count -gt 0) { $wanted = [string]$candidate[0].Thumbprint }
        }
        catch {
            Write-Log "The Exchange certificate list could not be read: $($_.Exception.Message)" -Tag "Debug"
        }
    }

    if ([string]::IsNullOrWhiteSpace($wanted)) {
        Write-Log "No self-signed Exchange certificate is left to put back on port 444 - create one and bind it by hand:" -Tag "Error"
        Write-Log "    New-ExchangeCertificate   then bind it to 'Exchange Back End' on 444 in IIS Manager, then iisreset" -Tag "Error"
        return $false
    }

    try {
        $binding = Get-WebBinding -Name "Exchange Back End" -Port 444 -Protocol "https" -ErrorAction Stop
        $binding.AddSslCertificate($wanted, "My")
        Write-Log "Exchange Back End on port 444 bound back to $wanted" -Tag "Ok"
    }
    catch {
        Write-Log "The Exchange Back End binding could not be repaired: $($_.Exception.Message)" -Tag "Error"
        Write-Log "    Bind '$wanted' to 'Exchange Back End' on port 444 in IIS Manager, then run iisreset" -Tag "Error"
        return $false
    }

    # Deliberately no restart here. The proxy hop needs one - the KB's own last step is
    # an iisreset - but Set-ExchangeCertificateBinding owns that decision and performs it
    # immediately after this returns. Two in a row is a minute of downtime for no second
    # effect.
    return $true
}

function Set-ExchangeTlsConfiguration {
    # The registry half of Microsoft's TLS best-practice guide: strong crypto and
    # OS-default TLS versions for both .NET bitnesses, 1.2 on both sides, 1.0/1.1
    # off, NTLMv2 only. SE demands consistency across every server in the org, and
    # a single server is trivially consistent - this is what keeps it so. All of it
    # is read at process start, so the reboot the install already owed covers it.
    $changed = $false
    foreach ($netKey in @("HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319")) {
        foreach ($name in @("SchUseStrongCrypto", "SystemDefaultTlsVersions")) {
            $current = $null
            try { $current = [int](Get-ItemProperty -Path $netKey -Name $name -ErrorAction Stop).$name } catch { $current = $null }
            if ($current -eq 1) { continue }
            if (-not (Test-Path -LiteralPath $netKey)) { $null = New-Item -Path $netKey -Force }
            Set-ItemProperty -Path $netKey -Name $name -Value 1 -Type DWord
            Write-Log "$netKey\$name = 1" -Tag "Ok"
            $changed = $true
        }
    }

    $protocolBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
    $wanted = @(
        @{ Protocol = "TLS 1.2"; Enabled = 1 },
        @{ Protocol = "TLS 1.1"; Enabled = 0 },
        @{ Protocol = "TLS 1.0"; Enabled = 0 }
    )
    foreach ($entry in $wanted) {
        foreach ($side in @("Server", "Client")) {
            $key = Join-Path -Path $protocolBase -ChildPath ("{0}\{1}" -f $entry.Protocol, $side)
            $currentEnabled = $null
            try { $currentEnabled = [int](Get-ItemProperty -Path $key -Name "Enabled" -ErrorAction Stop).Enabled } catch { $currentEnabled = $null }
            if ($currentEnabled -eq $entry.Enabled) { continue }
            if (-not (Test-Path -LiteralPath $key)) { $null = New-Item -Path $key -Force }
            Set-ItemProperty -Path $key -Name "Enabled" -Value $entry.Enabled -Type DWord
            Set-ItemProperty -Path $key -Name "DisabledByDefault" -Value (1 - $entry.Enabled) -Type DWord
            Write-Log "$($entry.Protocol) $side = $(if ($entry.Enabled -eq 1) { 'on' } else { 'off' })" -Tag "Ok"
            $changed = $true
        }
    }

    # NTLMv2 only - an Extended Protection prerequisite (NTLMv1 cannot carry the
    # channel binding token) and current guidance regardless.
    $lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $lmLevel = $null
    try { $lmLevel = [int](Get-ItemProperty -Path $lsaKey -Name "LmCompatibilityLevel" -ErrorAction Stop).LmCompatibilityLevel } catch { $lmLevel = $null }
    if ($lmLevel -ne 5) {
        Set-ItemProperty -Path $lsaKey -Name "LmCompatibilityLevel" -Value 5 -Type DWord
        Write-Log "LmCompatibilityLevel = 5 (NTLMv2 only)" -Tag "Ok"
        $changed = $true
    }

    if ($changed) {
        Write-Log "The TLS settings are read at process start - they take effect at the next restart" -Tag "Info"
    }
    else {
        Write-Log "TLS configuration already matches the design" -Tag "Info"
    }
    return $true
}

function Set-ExchangeLegacyProtocol {
    # POP and IMAP arrive installed and stopped; disabling the services is what
    # keeps a later administrator from starting a plaintext-capable protocol nobody
    # asked for. Off is the default and a design can keep them.
    param([Parameter(Mandatory)][object]$Exchange)

    $hardening = Get-ConfigValue -InputObject $Exchange -Name "hardening"
    if (-not [bool](Get-ConfigValue -InputObject $hardening -Name "disablePopImap" -Default $true)) {
        Write-Log "POP and IMAP are left as they are - the design says so" -Tag "Info"
        return $true
    }

    foreach ($serviceName in @("MSExchangePOP3", "MSExchangePOP3BE", "MSExchangeIMAP4", "MSExchangeIMAP4BE")) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -eq $service) { continue }
        try {
            if ($service.Status -eq "Running") { Stop-Service -Name $serviceName -Force -ErrorAction Stop }
            Set-Service -Name $serviceName -StartupType Disabled -ErrorAction Stop
            Write-Log "$serviceName stopped and disabled" -Tag "Ok"
        }
        catch {
            Write-Log "$serviceName could not be disabled: $($_.Exception.Message)" -Tag "Warn"
        }
    }
    return $true
}

# Outbound. A fresh install has **no send connector at all**, so internal mail flows
# and everything addressed outside the organization queues silently - which is the
# single most common "Exchange is installed and mail does not work" cause.
#
# An existing connector by this name is reconciled rather than replaced: the address
# space and the smart hosts are the design's, and dropping and recreating one loses
# whatever else somebody set on it.
function Set-ExchangeSendConnector {
    param([Parameter(Mandatory)][object]$Exchange)

    $send = Get-ConfigValue -InputObject $Exchange -Name "sendConnector"
    if (($null -eq $send) -or (-not [bool](Get-ConfigValue -InputObject $send -Name "enabled" -Default $false))) {
        Write-Log "No send connector in the design - if this organization has none, nothing leaves it" -Tag "Warn"
        return $true
    }

    $name = Get-ConfigText -InputObject $send -Name "name" -Default "Internet"
    $mode = Get-ConfigText -InputObject $send -Name "mode" -Default "smartHost"
    $addressSpace = Get-ConfigText -InputObject $send -Name "addressSpace" -Default "*"
    if ([string]::IsNullOrWhiteSpace($addressSpace)) { $addressSpace = "*" }
    $requireTls = [bool](Get-ConfigValue -InputObject $send -Name "requireTls" -Default $true)
    $port = [int](Get-ConfigValue -InputObject $send -Name "port" -Default 25)
    $smartHosts = @(Get-ConfigArray -InputObject $send -Name "smartHosts" | ForEach-Object { [string]$_ } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    if (($mode -eq "smartHost") -and ($smartHosts.Count -eq 0)) {
        Write-Log "The send connector relays through a smart host but the design names none - nothing to create" -Tag "Error"
        return $false
    }

    $existing = $null
    try { $existing = Get-SendConnector -Identity $name -ErrorAction SilentlyContinue } catch { $existing = $null }

    try {
        if ($null -eq $existing) {
            $parameters = @{
                Name          = $name
                AddressSpaces = @($addressSpace)
                Internet      = $true
                ErrorAction   = "Stop"
            }
            if ($mode -eq "smartHost") {
                $parameters.Remove("Internet")
                $parameters["SmartHosts"] = $smartHosts
                $parameters["DNSRoutingEnabled"] = $false
            }
            $null = New-SendConnector @parameters
            Write-Log "Send connector '$name' created for $addressSpace" -Tag "Ok"
        }
        else {
            $parameters = @{ Identity = $name; AddressSpaces = @($addressSpace); ErrorAction = "Stop" }
            if ($mode -eq "smartHost") {
                $parameters["SmartHosts"] = $smartHosts
                $parameters["DNSRoutingEnabled"] = $false
            }
            else {
                $parameters["DNSRoutingEnabled"] = $true
            }
            Set-SendConnector @parameters
            Write-Log "Send connector '$name' reconciled" -Tag "Ok"
        }

        # Port and TLS are set on both paths, because an adopted connector may carry
        # neither and both are the point of naming a relay at all.
        Set-SendConnector -Identity $name -Port $port -RequireTLS:$requireTls -ErrorAction Stop

        if ($mode -eq "smartHost") {
            $authentication = Get-ConfigText -InputObject $send -Name "authentication" -Default "none"
            if ($authentication -eq "basic") {
                $userName = Get-ConfigText -InputObject $send -Name "username"
                $password = Get-ConfigText -InputObject $send -Name "password"
                if ([string]::IsNullOrWhiteSpace($userName) -or [string]::IsNullOrWhiteSpace($password)) {
                    Write-Log "The relay wants basic authentication but the design carries no credential - export with secrets included" -Tag "Error"
                    return $false
                }
                if (-not $requireTls) {
                    Write-Log "Refusing to send basic credentials without TLS - switch RequireTLS on" -Tag "Error"
                    return $false
                }
                $secure = ConvertTo-SecureString -String $password -AsPlainText -Force
                $credential = New-Object System.Management.Automation.PSCredential($userName, $secure)
                Set-SendConnector -Identity $name -SmartHostAuthMechanism "BasicAuth" -AuthenticationCredential $credential -ErrorAction Stop
                Write-Log "Relay authentication: basic as '$userName', over TLS" -Tag "Ok"
            }
            else {
                Set-SendConnector -Identity $name -SmartHostAuthMechanism "None" -ErrorAction Stop
                Write-Log "Relay authentication: none - the relay has to know this server by address" -Tag "Info"
            }
            Write-Log "Mail leaves through $($smartHosts -join ', ') on port $port$(if ($requireTls) { ', TLS required' } else { '' })" -Tag "Info"
            Write-Log "With a relay in front, its SPF, PTR and address are what receivers judge" -Tag "Debug"
        }
        else {
            Write-Log "Direct delivery by MX lookup on port $port - needs a static public address, a matching PTR and this address in SPF" -Tag "Warn"
        }
        return $true
    }
    catch {
        Write-Log "The send connector could not be written: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

function Set-ExchangeRelayConnector {
    # The scoped anonymous relay every site ends up needing for printers and
    # appliances - a dedicated connector bound to listed addresses, so the Default
    # Frontend connector is never loosened. The ms-Exch-SMTP-Accept-Any-Recipient
    # grant on ANONYMOUS LOGON is what makes it a relay rather than merely a
    # receive endpoint, which is exactly why it is scoped to the list.
    param([Parameter(Mandatory)][object]$Exchange)

    $relay = Get-ConfigValue -InputObject $Exchange -Name "relayConnector"
    if (($null -eq $relay) -or (-not [bool](Get-ConfigValue -InputObject $relay -Name "enabled" -Default $false))) { return $true }

    $name = Get-ConfigText -InputObject $relay -Name "name" -Default "Anonymous Relay"
    $ranges = @(Get-ConfigArray -InputObject $relay -Name "remoteIpRanges" | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($ranges.Count -eq 0) {
        Write-Log "The relay connector has no remote addresses - an unscoped anonymous relay is an open relay, so it is not created" -Tag "Error"
        return $false
    }

    try {
        $existing = Get-ReceiveConnector -Server $env:COMPUTERNAME -ErrorAction Stop | Where-Object { $_.Name -eq $name }
        if ($null -eq $existing) {
            $null = New-ReceiveConnector -Name $name -Server $env:COMPUTERNAME -TransportRole "FrontendTransport" `
                -Usage "Custom" -Bindings "0.0.0.0:25" -RemoteIPRanges $ranges -ErrorAction Stop
            Write-Log "Receive connector '$name' created for $($ranges -join ', ')" -Tag "Ok"
        }
        else {
            Set-ReceiveConnector -Identity $existing.Identity -RemoteIPRanges $ranges -ErrorAction Stop
            Write-Log "Receive connector '$name' reconciled to $($ranges -join ', ')" -Tag "Ok"
        }

        $connector = Get-ReceiveConnector -Identity ("{0}\{1}" -f $env:COMPUTERNAME, $name) -ErrorAction Stop
        Set-ReceiveConnector -Identity $connector.Identity -PermissionGroups "AnonymousUsers" -ErrorAction Stop
        $null = $connector | Add-ADPermission -User "NT AUTHORITY\ANONYMOUS LOGON" -ExtendedRights "ms-Exch-SMTP-Accept-Any-Recipient" -ErrorAction SilentlyContinue
        Write-Log "'$name' relays for the listed addresses only" -Tag "Info"
        return $true
    }
    catch {
        Write-Log "The relay connector could not be written: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

# Verify, never assert: SE setup configures Extended Protection itself, and
# Microsoft's ExchangeExtendedProtectionManagement script owns changing it. What
# this run adds is reading the table back out of IIS so drift is a report today
# instead of an authentication mystery later.
$script:exchangeExtendedProtectionTable = @(
    @{ Site = "Default Web Site";  Path = "API";                            Expected = "Require" },
    # Off, both of these, and neither is an omission. AutoDiscover is anonymous, and the
    # front-end PowerShell directory does not accept NTLM at all - "therefore, Extended
    # Protection is not applicable", in Microsoft's words. Listed rather than left out so
    # that a future reader does not add them back as Require.
    @{ Site = "Default Web Site";  Path = "AutoDiscover";                   Expected = "None" },
    @{ Site = "Default Web Site";  Path = "PowerShell";                     Expected = "None" },
    @{ Site = "Default Web Site";  Path = "ECP";                            Expected = "Require" },
    @{ Site = "Default Web Site";  Path = "EWS";                            Expected = "Allow" },
    @{ Site = "Default Web Site";  Path = "mapi";                           Expected = "Require" },
    @{ Site = "Default Web Site";  Path = "Microsoft-Server-ActiveSync";    Expected = "Allow" },
    @{ Site = "Default Web Site";  Path = "Microsoft-Server-ActiveSync/Proxy"; Expected = "Allow" },
    @{ Site = "Default Web Site";  Path = "OAB";                            Expected = "Allow" },
    @{ Site = "Default Web Site";  Path = "owa";                            Expected = "Require" },
    @{ Site = "Default Web Site";  Path = "Rpc";                            Expected = "Require" },
    @{ Site = "Exchange Back End"; Path = "API";                            Expected = "Require" },
    @{ Site = "Exchange Back End"; Path = "AutoDiscover";                   Expected = "None" },
    @{ Site = "Exchange Back End"; Path = "ECP";                            Expected = "Require" },
    @{ Site = "Exchange Back End"; Path = "EWS";                            Expected = "Require" },
    @{ Site = "Exchange Back End"; Path = "mapi/emsmdb";                    Expected = "Require" },
    @{ Site = "Exchange Back End"; Path = "mapi/nspi";                      Expected = "Require" },
    @{ Site = "Exchange Back End"; Path = "Microsoft-Server-ActiveSync";    Expected = "Require" },
    @{ Site = "Exchange Back End"; Path = "Microsoft-Server-ActiveSync/Proxy"; Expected = "Require" },
    @{ Site = "Exchange Back End"; Path = "OAB";                            Expected = "Require" },
    @{ Site = "Exchange Back End"; Path = "owa";                            Expected = "Require" },
    @{ Site = "Exchange Back End"; Path = "PowerShell";                     Expected = "Require" },
    @{ Site = "Exchange Back End"; Path = "PushNotifications";              Expected = "Require" },
    @{ Site = "Exchange Back End"; Path = "Rpc";                            Expected = "Require" },
    @{ Site = "Exchange Back End"; Path = "RpcWithCert";                    Expected = "Require" }
)

function Test-ExchangeExtendedProtection {
    param([object]$Exchange)

    $hardening = Get-ConfigValue -InputObject $Exchange -Name "hardening"
    if (-not [bool](Get-ConfigValue -InputObject $hardening -Name "verifyExtendedProtection" -Default $true)) { return $true }

    $appCmd = Join-Path -Path $env:SystemRoot -ChildPath "system32\inetsrv\appcmd.exe"
    if (-not (Test-Path -LiteralPath $appCmd)) { return $true }

    $drift = @()
    foreach ($entry in $script:exchangeExtendedProtectionTable) {
        $location = "{0}/{1}" -f $entry.Site, $entry.Path
        $value = ""
        try {
            $value = (& $appCmd "list" "config" $location "-section:system.webServer/security/authentication/windowsAuthentication" "/text:extendedProtection.tokenChecking" 2>&1 | Out-String).Trim()
        }
        catch {
            continue
        }
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        if ($value -ne $entry.Expected) { $drift += "$location is '$value' (expected $($entry.Expected))" }
    }

    if ($drift.Count -eq 0) {
        Write-Log "Extended Protection matches Microsoft's table on every virtual directory checked" -Tag "Ok"
    }
    else {
        foreach ($item in $drift) { Write-Log "Extended Protection drift: $item" -Tag "Warn" }
        Write-Log "Fix with Microsoft's own script, never by hand: https://aka.ms/ExchangeEPScript" -Tag "Warn"
    }
    return $true
}

# ---------------------------[ Log cleanup ]---------------------------
# Exchange writes diagnostic logs continuously and **prunes almost none of them**. On a
# server nobody watches, the logging trees are what fills the system volume - and a full
# volume dismounts the databases. It is the single most common way an otherwise healthy
# Exchange server stops working.
#
# Deliberately conservative: files only, never folders, only under the roots the
# generated script names, only extensions Exchange and IIS actually write, and only past
# the retention. Nothing here touches the transaction logs beside a database - those are
# truncated by a successful backup and deleting one costs you the ability to roll a
# restore forward. The roots and that extension list moved into the generated script
# below, which is the only thing that does the sweep now.
$script:exchangeLogTaskName = "WSRS-ExchangeLogs"
function Invoke-ExchangeLogCleanupTask {
    param([object]$Config)

    $exchange = Get-ConfigValue -InputObject $Config -Name "exchange"
    if ($null -eq $exchange) {
        Write-Log "config.json has no exchange section" -Tag "Error"
        return 1
    }

    # -Task ExchangeLogs runs the generated script rather than a second copy of the same
    # sweep. Two implementations of one job drift, and the one that drifts is always the
    # one nobody runs by hand - so this path is exactly what the task does at 01:00. The
    # task registered by an older build still comes through here, which is the other
    # reason this entry point stays.
    try {
        $scriptPath = Write-ExchangeLogScript -Exchange $exchange
    }
    catch {
        Write-Log "Could not write the log cleanup script: $($_.Exception.Message)" -Tag "Error"
        return 1
    }

    $exitCode = 0
    try {
        foreach ($line in @(& $scriptPath)) {
            $text = [string]$line
            if (-not [string]::IsNullOrWhiteSpace($text)) { Write-Log $text -Tag "Info" }
        }
        $exitCode = [int]$LASTEXITCODE
    }
    catch {
        Write-Log "The log cleanup script failed: $($_.Exception.Message)" -Tag "Error"
        return 1
    }

    if ($exitCode -ne 0) { return 1 }
    return 0
}

$script:exchangeLogScriptName = "Clear-ExchangeLogs.ps1"

# The nightly sweep is Get-ChildItem, a date comparison and Remove-Item, so it gets a
# script of its own rather than a copy of this project - see Write-StudioTaskScript for
# the rule. It reads no config: the two decisions in it (how long to keep, whether the
# IIS trees are included) are substituted in as parameter defaults, and the Exchange
# installation path is read out of the registry the same way this part reads it.
$script:exchangeLogScriptTemplate = @'
<#
    Prunes the Exchange and IIS logging trees, which Exchange itself does not.

    Written by Windows Server Role Studio (Configure-ServerRoles.ps1) on __WRITTEN__ and
    OVERWRITTEN by the next configuration run - change config.json, not this file.

    Self-contained on purpose: the job is a directory walk and Remove-Item, and a task
    that small has no business carrying the project that wrote it onto this server.
#>
param(
    [int]$RetentionDays = __RETENTION__,
    [bool]$IncludeIisLogs = $__INCLUDEIIS__
)

$ErrorActionPreference = "Stop"

$logPath = Join-Path -Path $PSScriptRoot -ChildPath ("ExchangeLogCleanup-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmm"))
function Write-CleanupLog {
    param([string]$Message)

    $line = "{0}  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Write-Output $line
    try { Add-Content -LiteralPath $logPath -Value $line } catch { }
}

# A log-cleanup task whose own log grows forever would be a joke with a long setup. One
# log per run and the newest fourteen kept, the same rule and the same number as the run
# logs the studio writes - counting files is something anybody can check by looking.
try {
    Get-ChildItem -LiteralPath $PSScriptRoot -Filter "ExchangeLogCleanup-*.log" -File -ErrorAction Stop |
        Sort-Object -Property LastWriteTime -Descending |
        Select-Object -Skip 14 |
        Remove-Item -Force -ErrorAction SilentlyContinue
}
catch { }

# Refused rather than clamped: a retention this run cannot make sense of is a design
# somebody has to look at, and the wrong guess here deletes logs written this morning.
if ($RetentionDays -lt 1) {
    Write-CleanupLog "The retention is $RetentionDays day(s) - refusing to run, that would delete logs written today"
    exit 1
}

$installPath = ""
try {
    $setup = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup" -ErrorAction Stop
    $installPath = [string]$setup.MsiInstallPath
}
catch {
    $installPath = ""
}
if ([string]::IsNullOrWhiteSpace($installPath)) {
    Write-CleanupLog "Exchange is not installed on this server - no logs of its own to clean"
    exit 0
}

$paths = @(
    (Join-Path -Path $installPath -ChildPath "Logging"),
    (Join-Path -Path $installPath -ChildPath "TransportRoles\Logs")
)
if ($IncludeIisLogs) {
    $paths += (Join-Path -Path $env:SystemDrive -ChildPath "inetpub\logs\LogFiles")
    $paths += (Join-Path -Path $env:SystemRoot -ChildPath "System32\LogFiles\HTTPERR")
}
$paths = @($paths | Where-Object { Test-Path -LiteralPath $_ })
if ($paths.Count -eq 0) {
    Write-CleanupLog "None of the Exchange logging folders exist on this server"
    exit 0
}

# By extension, never by "everything in the folder": these trees also hold the
# configuration and the per-service subfolders, and one of them is somebody's evidence.
$extensions = @(".log", ".blg", ".etl", ".txt")
$threshold = (Get-Date).AddDays(-$RetentionDays)
$removedCount = 0
$removedBytes = [long]0
$failedCount = 0

foreach ($path in $paths) {
    $files = @()
    try {
        $files = @(Get-ChildItem -LiteralPath $path -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { ($extensions -contains $_.Extension.ToLowerInvariant()) -and ($_.LastWriteTime -lt $threshold) })
    }
    catch {
        Write-CleanupLog ("'{0}' could not be listed: {1}" -f $path, $_.Exception.Message)
        continue
    }

    $pathBytes = [long]0
    $pathCount = 0
    foreach ($file in $files) {
        try {
            $size = [long]$file.Length
            Remove-Item -LiteralPath $file.FullName -Force
            $pathCount++
            $pathBytes += $size
        }
        catch {
            # A log the transport service still holds open is normal, not a failure -
            # the next run takes it.
            $failedCount++
        }
    }
    if ($pathCount -gt 0) {
        Write-CleanupLog ("{0}: removed {1} file(s), {2} MB" -f $path, $pathCount, [math]::Round($pathBytes / 1MB, 1))
    }
    $removedCount += $pathCount
    $removedBytes += $pathBytes
}

if ($failedCount -gt 0) {
    Write-CleanupLog "$failedCount file(s) were in use and left alone - the next run takes them"
}
Write-CleanupLog ("Log cleanup done: {0} file(s), {1} MB reclaimed, keeping {2} day(s)" -f $removedCount, [math]::Round($removedBytes / 1MB, 1), $RetentionDays)
exit 0
'@

function Write-ExchangeLogScript {
    param([Parameter(Mandatory)][object]$Exchange)

    $cleanup = Get-ConfigValue -InputObject $Exchange -Name "logCleanup"
    $retentionDays = [int](Get-ConfigValue -InputObject $cleanup -Name "retentionDays" -Default 14)
    $includeIis = [bool](Get-ConfigValue -InputObject $cleanup -Name "includeIisLogs" -Default $true)

    return (Write-StudioTaskScript -FileName $script:exchangeLogScriptName -Template $script:exchangeLogScriptTemplate `
        -Purpose "the whole of what the log cleanup task runs" `
        -Value @{
            RETENTION    = [string]$retentionDays
            INCLUDEIIS   = $(if ($includeIis) { "true" } else { "false" })
        })
}

function Register-ExchangeLogCleanupTask {
    param([Parameter(Mandatory)][object]$Exchange)

    $cleanup = Get-ConfigValue -InputObject $Exchange -Name "logCleanup"
    $wanted = [bool](Get-ConfigValue -InputObject $cleanup -Name "enabled" -Default $true)

    if (-not (Get-Command -Name "Register-ScheduledTask" -ErrorAction SilentlyContinue)) {
        Write-Log "The ScheduledTasks module is unavailable - the log cleanup cannot be registered" -Tag "Error"
        return $false
    }

    if (-not $wanted) {
        try {
            if ($null -ne (Get-ScheduledTask -TaskName $script:exchangeLogTaskName -ErrorAction SilentlyContinue)) {
                Unregister-ScheduledTask -TaskName $script:exchangeLogTaskName -Confirm:$false -ErrorAction Stop
                Write-Log "Removed '$($script:exchangeLogTaskName)' - the design does not want it" -Tag "Info"
            }
        }
        catch {
            Write-Log "Could not remove '$($script:exchangeLogTaskName)': $($_.Exception.Message)" -Tag "Warn"
        }
        Write-Log "Nothing prunes the Exchange logging trees - watch the system volume" -Tag "Warn"
        return $true
    }

    $startTime = Get-ConfigText -InputObject $cleanup -Name "time" -Default "01:00"
    $retentionDays = [int](Get-ConfigValue -InputObject $cleanup -Name "retentionDays" -Default 14)

    try {
        # Same deployment folder as every other task, one generated file in it. Not a
        # copy of the project: this job reads no config and calls nothing this project
        # defines, and a config.json staged beside it would put exported secrets on an
        # Exchange server for a task that reads neither.
        $scriptPath = Write-ExchangeLogScript -Exchange $Exchange
        $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $scriptPath

        if ($null -ne (Get-ScheduledTask -TaskName $script:exchangeLogTaskName -ErrorAction SilentlyContinue)) {
            Unregister-ScheduledTask -TaskName $script:exchangeLogTaskName -Confirm:$false -ErrorAction SilentlyContinue
        }

        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arguments
        $trigger = New-ScheduledTaskTrigger -Daily -At ([datetime]::Parse($startTime))
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 2)
        $null = Register-ScheduledTask -TaskName $script:exchangeLogTaskName -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings `
            -Description "Windows Server Role Studio - prunes the Exchange and IIS logging trees" -ErrorAction Stop
        Write-Log "Registered '$($script:exchangeLogTaskName)' - daily at $startTime as SYSTEM, keeping $retentionDays day(s)" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "Could not register '$($script:exchangeLogTaskName)': $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

function Write-ExchangeReport {
    # Reported, not changed: the settings whose blast radius is the organization or
    # whose owner is another tool.
    $mitigation = Get-Service -Name "MSExchangeMitigation" -ErrorAction SilentlyContinue
    if ($null -ne $mitigation) {
        if (($mitigation.Status -eq "Running") -and ($mitigation.StartType -ne "Disabled")) {
            Write-Log "The Emergency Mitigation service is running" -Tag "Ok"
        }
        else {
            Write-Log "Emergency Mitigation service not running - it is how Microsoft pushes URL-rewrite mitigations" -Tag "Warn"
        }
    }

    # AMSI body inspection and serialization payload signing are both ON by default in
    # Subscription Edition, and both are switched off by a *setting override* - so the
    # honest check is whether somebody created one, not whether a value is present. No
    # override is created here either way: these are organization-wide, they need a
    # topology refresh and an IIS restart to take effect, and turning one on before
    # every server in the org can handle it is how mail flow breaks.
    try {
        $overrides = @(Get-SettingOverride -ErrorAction Stop)
        $amsiOff = @($overrides | Where-Object { [string]$_.SectionName -eq "BypassBodyScanning" -or ([string]$_.Parameters -match "(?i)enabled=false" -and [string]$_.ComponentName -match "(?i)amsi") })
        if ($amsiOff.Count -gt 0) {
            Write-Log "An override disables AMSI body inspection ('$($amsiOff[0].Name)') - Exchange's own request-body malware scan is off" -Tag "Warn"
        }
        else {
            Write-Log "No override disables AMSI body inspection" -Tag "Ok"
        }

        $signingOff = @($overrides | Where-Object { [string]$_.SectionName -eq "EnableSerializationDataSigning" -and [string]$_.Parameters -match "(?i)enabled=false" })
        if ($signingOff.Count -gt 0) {
            Write-Log "An override disables PowerShell serialization signing ('$($signingOff[0].Name)') - remove it, that signature is what makes a deserialization payload unusable" -Tag "Warn"
        }
        else {
            Write-Log "No override disables serialization payload signing - on by default in SE" -Tag "Ok"
        }
    }
    catch {
        Write-Log "Setting overrides unreadable ($($_.Exception.Message)) - check AMSI and serialization signing with the Health Checker" -Tag "Info"
    }

    Write-Log "Run Microsoft's health check against this server once mail flows: https://aka.ms/ExchangeHealthChecker" -Tag "Info"
    Write-Log "Add the Defender exclusions for Exchange (paths and processes both) - the HealthChecker names the current list" -Tag "Info"
    Write-Log "Split permissions stays a decision, not a default - it is not applied here" -Tag "Info"

    # The three records this design cannot write, and mail is broken without them.
    $namespace = Get-ConfigValue -InputObject $script:currentExchange -Name "namespace"
    $hostName = Get-ConfigText -InputObject $namespace -Name "hostName"
    $domain = ""
    if (-not [string]::IsNullOrWhiteSpace($hostName)) { $domain = $hostName -replace '^[^.]+\.', '' }
    Write-Log "Public DNS is outside this design - three records still needed, in the zone your registrar or ISP holds:" -Tag "Info"
    if (-not [string]::IsNullOrWhiteSpace($domain)) {
        Write-Log "    MX    $domain -> $hostName (or whatever filters mail in front of it)" -Tag "Info"
        Write-Log "    TXT   $domain -> an SPF record naming everything that sends as @$domain" -Tag "Info"
    }
    Write-Log "    PTR   the public address this server sends from -> a name that resolves back" -Tag "Info"
}

# ---------------------------[ Recipients ]---------------------------
# Mailboxes and distribution groups: the first two things anybody does to an Exchange
# organization after it stands up, and the last thing this role does to it.
#
# Everything here **enables** rather than creates. A mailbox is given to an Active
# Directory account that already exists - Enable-Mailbox, never New-Mailbox - because a
# UPN in this design means the same thing it means on the File Server and Print Server
# blades: an account somebody else already made. Creating accounts is the directory's
# job and would put a password per user into a config file. A UPN that does not resolve
# is reported by name and skipped; it is never invented.
#
# That reading is also what makes the organizational unit sweep possible: "every user in
# this OU gets a mailbox" is a sentence about accounts that exist.

# Two lists, because the two halves are genuinely different operations and the
# difference is not a preference - it is what the cmdlets allow.
#
#   USER mailboxes are ENABLED on accounts that already exist. New-Mailbox for a user
#   requires -Password, so creating one would mean a password per person in a config
#   file. Enable-Mailbox needs no secret at all, and a person's account is the
#   directory's to create anyway.
#
#   SHARED, ROOM and EQUIPMENT mailboxes are CREATED outright, account and all. On those
#   parameter sets -Password is optional and the associated Active Directory account is
#   created **disabled** - nobody signs in to a room - so there is no secret to carry
#   and nothing to pre-create. Expecting somebody to have made a disabled placeholder
#   account for every meeting room first would be asking for busywork the cmdlet does
#   not need.
$script:exchangeResourceSwitch = @{
    "shared"    = "Shared"
    "room"      = "Room"
    "equipment" = "Equipment"
}

function Get-ExchangeMailboxSection {
    param([Parameter(Mandatory)][object]$Exchange)

    $mailboxes = Get-ConfigValue -InputObject $Exchange -Name "mailboxes"
    if ($null -eq $mailboxes) { return $null }
    return $mailboxes
}

# One user mailbox, on an account that has to be there. Returns $true when the account
# ends the run with a mailbox, whether or not this call is what gave it one.
function Enable-ExchangeMailboxFor {
    param([Parameter(Mandatory)][string]$Identity)

    $existing = $null
    try { $existing = Get-Mailbox -Identity $Identity -ErrorAction SilentlyContinue }
    catch { $existing = $null }
    if ($null -ne $existing) {
        Write-Log "'$Identity' already has a mailbox ($($existing.RecipientTypeDetails)) - left exactly as it is" -Tag "Debug"
        return $true
    }

    # Get-User answers for an account with no mailbox; Get-Mailbox above answered for one
    # that has. Neither finding it means the design names somebody the directory has not.
    $account = $null
    try { $account = Get-User -Identity $Identity -ErrorAction SilentlyContinue }
    catch { $account = $null }
    if ($null -eq $account) {
        Write-Log "'$Identity' is not an account in this forest - no mailbox was created, and this run does not create people" -Tag "Error"
        Write-Log "    Create the user first, then run this again - the step is idempotent and will pick it up" -Tag "Error"
        return $false
    }

    try {
        $null = Enable-Mailbox -Identity $Identity -ErrorAction Stop
    }
    catch {
        Write-Log "Could not give '$Identity' a mailbox: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
    Write-Log "'$Identity' now has a user mailbox" -Tag "Ok"
    return $true
}

# One shared, room or equipment mailbox, created outright.
function New-ExchangeResourceMailbox {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Type,
        [string]$Alias = "",
        [string]$OrganizationalUnit = ""
    )

    if (-not $script:exchangeResourceSwitch.ContainsKey($Type)) {
        Write-Log "'$Name' asks for the mailbox type '$Type', which is not one this run knows" -Tag "Error"
        return $false
    }
    $switch = $script:exchangeResourceSwitch[$Type]

    $existing = $null
    try { $existing = Get-Mailbox -Identity $Name -ErrorAction SilentlyContinue }
    catch { $existing = $null }
    if ($null -ne $existing) {
        # Same rule as every other object this project adopts. Converting a mailbox
        # between types is a real operation with real consequences and is never done
        # here on the strength of a design file disagreeing with what is there.
        if ([string]$existing.RecipientTypeDetails -notmatch "(?i)$switch") {
            Write-Log "'$Name' already exists as $($existing.RecipientTypeDetails) and the design says $switch - left as it is" -Tag "Warn"
        }
        else {
            Write-Log "'$Name' already exists as a $switch mailbox" -Tag "Debug"
        }
        return $true
    }

    # The switch's NAME is what varies, so the call is splatted from a hashtable - an
    # inline @{...} after a cmdlet is a positional argument, not splatting.
    $arguments = @{ Name = $Name; ErrorAction = "Stop" }
    $arguments[$switch] = $true
    if (-not [string]::IsNullOrWhiteSpace($Alias)) { $arguments["Alias"] = $Alias }
    if (-not [string]::IsNullOrWhiteSpace($OrganizationalUnit)) { $arguments["OrganizationalUnit"] = $OrganizationalUnit }

    try {
        $null = New-Mailbox @arguments
    }
    catch {
        Write-Log "Could not create the $switch mailbox '$Name': $($_.Exception.Message)" -Tag "Error"
        return $false
    }
    Write-Log "$switch mailbox '$Name' created - its account is disabled" -Tag "Ok"
    return $true
}

function Set-ExchangeMailbox {
    param([Parameter(Mandatory)][object]$Exchange)

    $mailboxes = Get-ExchangeMailboxSection -Exchange $Exchange
    if ($null -eq $mailboxes) { return $true }

    $allDone = $true
    $touched = 0

    foreach ($entry in @(Get-ConfigArray -InputObject $mailboxes -Name "users")) {
        $identity = Get-ConfigText -InputObject $entry -Name "identity"
        if ([string]::IsNullOrWhiteSpace($identity)) { continue }
        if (Enable-ExchangeMailboxFor -Identity $identity) { $touched++ }
        else { $allDone = $false }
    }

    # The sweep, and it is user mailboxes only - "everybody in this organizational unit"
    # is a sentence about people. RecipientTypeDetails 'User' is precisely an account
    # that has no mailbox yet, so this asks for the ones that need one rather than
    # filtering the whole directory afterwards.
    $organizationalUnit = Get-ConfigText -InputObject $mailboxes -Name "organizationalUnit"
    if (-not [string]::IsNullOrWhiteSpace($organizationalUnit)) {
        Write-Log "Giving every account in '$organizationalUnit' a mailbox that does not have one" -Tag "Run"
        $pending = @()
        try {
            $pending = @(Get-User -OrganizationalUnit $organizationalUnit -RecipientTypeDetails "User" -ResultSize Unlimited -ErrorAction Stop)
        }
        catch {
            Write-Log "Could not read '$organizationalUnit': $($_.Exception.Message)" -Tag "Error"
            Write-Log "    The organizational unit has to exist - this run does not create one" -Tag "Error"
            $allDone = $false
            $pending = @()
        }

        if ($pending.Count -eq 0) {
            Write-Log "Every account in '$organizationalUnit' already has a mailbox" -Tag "Info"
        }
        foreach ($account in $pending) {
            $name = [string]$account.UserPrincipalName
            if ([string]::IsNullOrWhiteSpace($name)) { $name = [string]$account.DistinguishedName }
            if (Enable-ExchangeMailboxFor -Identity $name) { $touched++ }
            else { $allDone = $false }
        }
    }

    $bookable = 0
    foreach ($entry in @(Get-ConfigArray -InputObject $mailboxes -Name "resources")) {
        $name = Get-ConfigText -InputObject $entry -Name "name"
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $type = Get-ConfigText -InputObject $entry -Name "type" -Default "shared"
        if (@("room", "equipment") -contains $type) { $bookable++ }
        $created = New-ExchangeResourceMailbox `
            -Name $name `
            -Type $type `
            -Alias (Get-ConfigText -InputObject $entry -Name "alias" -Default "") `
            -OrganizationalUnit (Get-ConfigText -InputObject $entry -Name "organizationalUnit" -Default "")
        if ($created) { $touched++ } else { $allDone = $false }
    }

    if ($touched -gt 0) {
        Write-Log "$touched mailbox(es) in place" -Tag "Ok"
        Write-Log "    Addresses come from the email address policy above - a mailbox made before it carries the wrong domain forever" -Tag "Debug"
    }
    if ($bookable -gt 0) {
        Write-Log "    Room and equipment mailboxes accept bookings on their defaults; Set-CalendarProcessing tunes that" -Tag "Debug"
    }
    return $allDone
}

# Distribution groups, and members added one at a time. The directory refuses an entire
# write for one illegal value, so a single unresolvable member must not take the
# resolvable ones with it - the same rule the AD CS role groups and the shared access
# groups already follow. Members are only ever added; removing one is not this script's
# decision.
function Set-ExchangeDistributionGroup {
    param([Parameter(Mandatory)][object]$Exchange)

    $groups = @(Get-ConfigArray -InputObject $Exchange -Name "distributionGroups")
    if ($groups.Count -eq 0) { return $true }

    $allDone = $true
    foreach ($entry in $groups) {
        $name = Get-ConfigText -InputObject $entry -Name "name"
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $alias = Get-ConfigText -InputObject $entry -Name "alias" -Default ""
        $organizationalUnit = Get-ConfigText -InputObject $entry -Name "organizationalUnit" -Default ""

        $existing = $null
        try { $existing = Get-DistributionGroup -Identity $name -ErrorAction SilentlyContinue }
        catch { $existing = $null }

        if ($null -eq $existing) {
            $arguments = @{ Name = $name; Type = "Distribution"; ErrorAction = "Stop" }
            if (-not [string]::IsNullOrWhiteSpace($alias)) { $arguments["Alias"] = $alias }
            if (-not [string]::IsNullOrWhiteSpace($organizationalUnit)) { $arguments["OrganizationalUnit"] = $organizationalUnit }
            try {
                $null = New-DistributionGroup @arguments
                Write-Log "Distribution group '$name' created" -Tag "Ok"
            }
            catch {
                Write-Log "The distribution group '$name' could not be created: $($_.Exception.Message)" -Tag "Error"
                $allDone = $false
                continue
            }
        }
        else {
            # Same rule as every other object this project adopts: it is here, so
            # somebody may have tuned it, and a run that rewrites what it finds is a run
            # nobody can leave a change in. Only the membership is reconciled.
            Write-Log "'$name' already exists - settings left alone, members added" -Tag "Info"
        }

        $current = @()
        try {
            $current = @(Get-DistributionGroupMember -Identity $name -ResultSize Unlimited -ErrorAction Stop |
                ForEach-Object { [string]$_.PrimarySmtpAddress; [string]$_.Name })
        }
        catch { $current = @() }

        foreach ($member in @(Get-ConfigArray -InputObject $entry -Name "members")) {
            $value = [string]$member
            if ([string]::IsNullOrWhiteSpace($value)) { continue }
            if ($current -contains $value) {
                Write-Log "'$value' is already in '$name'" -Tag "Debug"
                continue
            }
            try {
                $null = Add-DistributionGroupMember -Identity $name -Member $value -ErrorAction Stop
                Write-Log "Added '$value' to '$name'" -Tag "Ok"
            }
            catch {
                Write-Log "Could not add '$value' to '$name': $($_.Exception.Message)" -Tag "Error"
                Write-Log "    A member has to be a recipient Exchange knows - a mailbox, a mail user or another group" -Tag "Error"
                $allDone = $false
            }
        }
    }
    return $allDone
}

function Invoke-ExchangePostInstall {
    param([Parameter(Mandatory)][object]$Exchange)

    if (-not (Import-ExchangeManagementShell)) {
        return (New-RoleResult -Status "Failed" -Message "The Exchange management shell could not be loaded - is the installation healthy?")
    }

    $script:currentExchange = $Exchange
    $failures = @()
    Test-ExchangeNamespaceResolution -Exchange $Exchange
    if (-not (Set-ExchangeNamespace -Exchange $Exchange)) { $failures += "the namespace" }
    # Accepted domains before the policy: a policy cannot stamp an address in a domain
    # the organization does not accept, and the cmdlet's refusal names neither.
    if (-not (Set-ExchangeAcceptedDomain -Exchange $Exchange)) { $failures += "the accepted domains" }
    if (-not (Set-ExchangeEmailPolicy -Exchange $Exchange)) { $failures += "the email address policy" }
    if (-not (Set-ExchangeServiceCertificate -Exchange $Exchange)) { $failures += "the certificate" }
    # After the certificate: the download name has to be in it, and a broken binding
    # is the more urgent of the two failures.
    if (-not (Set-ExchangeDownloadDomain -Exchange $Exchange)) { $failures += "the attachment download domain" }
    $hardening = Get-ConfigValue -InputObject $Exchange -Name "hardening"
    if ([bool](Get-ConfigValue -InputObject $hardening -Name "configureTls" -Default $true)) {
        $null = Set-ExchangeTlsConfiguration
    }
    $null = Set-ExchangeOperatingSystemTuning -Exchange $Exchange
    $null = Set-ExchangeLegacyProtocol -Exchange $Exchange
    # Before the transport limits: those set a size on every connector, so the
    # connector has to exist first or its limit is set on the next run instead.
    if (-not (Set-ExchangeSendConnector -Exchange $Exchange)) { $failures += "the send connector" }
    if (-not (Set-ExchangeTransportLimit -Exchange $Exchange)) { $failures += "the transport limits" }
    if (-not (Set-ExchangeDatabaseDefault -Exchange $Exchange)) { $failures += "the database defaults" }
    if (-not (Set-ExchangeRelayConnector -Exchange $Exchange)) { $failures += "the relay connector" }
    if (-not (Set-ExchangeInboundGateway -Exchange $Exchange)) { $failures += "the inbound gateway connector" }
    # After the connectors: the agent restart it may perform would otherwise land in
    # the middle of writing them.
    if (-not (Set-ExchangeRecipientValidation -Exchange $Exchange)) { $failures += "recipient validation" }
    # Last of the hardening: it can take the admin console away, so everything that might
    # want to report through it has already run.
    if (-not (Set-ExchangeEcpAccess -Exchange $Exchange)) { $failures += "the admin console restriction" }
    # Recipients last: the server first, then what lives on it. Mailboxes before groups,
    # because a distribution group in this design may well name a mailbox it just made.
    if (-not (Set-ExchangeMailbox -Exchange $Exchange)) { $failures += "the mailboxes" }
    if (-not (Set-ExchangeDistributionGroup -Exchange $Exchange)) { $failures += "the distribution groups" }
    $null = Test-ExchangeExtendedProtection -Exchange $Exchange
    $null = Register-ExchangeLogCleanupTask -Exchange $Exchange
    # Only a certificate that expires on a schedule of its own earns the nightly
    # task - a thumbprint or a PFX is whatever put it there.
    $certificateSource = Get-ConfigText -InputObject (Get-ConfigValue -InputObject $Exchange -Name "certificate") -Name "source" -Default "leave"
    if (@("acme", "internalCa") -contains $certificateSource) {
        $null = Register-StudioCertificateTask -Config $script:currentConfig -ConfigFilePath $script:configFilePath
    }
    Write-ExchangeReport

    if ($failures.Count -gt 0) {
        return (New-RoleResult -Status "ManualStepRequired" -Message ("Exchange is configured, but these did not go in: {0}. Fix the cause and run this again." -f ($failures -join ", ")))
    }
    return (New-RoleResult -Status "Completed" -Message "Exchange is configured - namespace, certificate, TLS and the hardening described in the design.")
}

# ---------------------------[ Nightly renewal ]---------------------------
# The third consumer of the shared certificate machinery, dispatched from
# Invoke-CertificateTask beside the Windows Admin Center and Remote Desktop halves.
# The field-proven shape from the standalone renewal script this role absorbed:
# read what IIS serves before anything changes, renew, bind without re-keying,
# validate the endpoints a mailbox actually needs, report either way.
function Invoke-ExchangeCertificateTask {
    param([object]$Config)

    $exchange = Get-ConfigValue -InputObject $Config -Name "exchange"
    if ($null -eq $exchange) {
        Write-Log "config.json has no exchange section" -Tag "Error"
        return 1
    }
    # Not an error, and the distinction matters: one config describes several machines,
    # so this section reaches the connector host and both CAs as well. The shared task
    # asks every consumer in the file, and "not my job" has to answer 0 or the task
    # reports a failure every night on every server that is not the mail server.
    if (-not (Test-ExchangeInstalled)) {
        Write-Log "Exchange is not installed on this server - nothing here for this task to renew" -Tag "Info"
        return 0
    }
    if (-not (Import-ExchangeManagementShell)) { return 1 }

    $certificate = Get-ConfigValue -InputObject $exchange -Name "certificate"
    $source = Get-ConfigText -InputObject $certificate -Name "source" -Default "leave"
    if (@("acme", "internalCa") -notcontains $source) {
        Write-Log "The Exchange certificate source is '$source' - nothing renews on a schedule" -Tag "Info"
        return 0
    }
    if ($source -eq "acme") { Update-PoshAcmeModule }

    $names = @(Get-ConfigArray -InputObject $certificate -Name "dnsNames" | ForEach-Object { [string]$_ })
    $primaryName = ""
    if ($names.Count -gt 0) { $primaryName = $names[0] }
    $pluginName = Get-ConfigText -InputObject (Get-ConfigValue -InputObject $certificate -Name "acme") -Name "dnsPlugin"

    # What IIS serves now, read from Exchange itself - the report has to say what
    # was replaced.
    $previousThumbprint = ""
    $previousNotAfter = ""
    try {
        $current = Get-ExchangeCertificate -ErrorAction Stop | Where-Object { $_.Services -match "IIS" } | Select-Object -First 1
        if ($null -ne $current) {
            $previousThumbprint = ([string]$current.Thumbprint).ToUpperInvariant()
            $previousNotAfter = $current.NotAfter.ToString("yyyy-MM-dd")
        }
    }
    catch {
        Write-Log "The current IIS certificate could not be read: $($_.Exception.Message)" -Tag "Warn"
    }

    $thumbprint = ""
    try {
        $thumbprint = Resolve-StudioCertificate -Certificate $certificate
    }
    catch {
        Write-Log "The certificate could not be obtained: $($_.Exception.Message)" -Tag "Error"
        $null = Send-CertificateReport -Config $Config -Report (New-WacCertificateReport `
            -Status "Failed" -RoleLabel "Exchange Server" -PrimaryName $primaryName -Names $names -Source $source -PluginName $pluginName `
            -PreviousThumbprint $previousThumbprint -PreviousNotAfter $previousNotAfter `
            -ErrorMessage $_.Exception.Message -ErrorStackTrace ([string]$_.ScriptStackTrace))
        return 1
    }
    if ([string]::IsNullOrWhiteSpace($thumbprint)) {
        Write-Log "No certificate came back - the bindings are left as they are" -Tag "Info"
        return 0
    }

    $status = "Renewed"
    if ($previousThumbprint -eq $thumbprint.ToUpperInvariant()) {
        Write-Log "Exchange already serves $thumbprint - nothing to do today" -Tag "Ok"
        $status = "Current"
    }
    else {
        try {
            # The same back-end guard the install pass uses. A renewal rebinds IIS every
            # ninety days, so without it this would break OWA and ECP on a schedule.
            if (-not (Set-ExchangeCertificateBinding -Thumbprint $thumbprint)) {
                throw "Enable-ExchangeCertificate did not bind the renewed certificate."
            }
        }
        catch {
            Write-Log "The renewed certificate could not be bound: $($_.Exception.Message)" -Tag "Error"
            $null = Send-CertificateReport -Config $Config -Report (New-WacCertificateReport `
                -Status "Failed" -RoleLabel "Exchange Server" -PrimaryName $primaryName -Names $names -Source $source -PluginName $pluginName `
                -Thumbprint $thumbprint -PreviousThumbprint $previousThumbprint -PreviousNotAfter $previousNotAfter `
                -ErrorMessage $_.Exception.Message -ErrorStackTrace ([string]$_.ScriptStackTrace))
            return 1
        }
    }

    # Any HTTP answer means TLS and routing work - EWS answers 401 to an
    # unauthenticated probe, and that is the healthy state.
    $endpoints = @()
    if (-not [string]::IsNullOrWhiteSpace($primaryName)) {
        foreach ($url in @("https://$primaryName/owa/healthcheck.htm", "https://$primaryName/EWS/Exchange.asmx")) {
            $reached = $false
            $detail = ""
            try {
                $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
                $reached = $true
                $detail = "HTTP $([int]$response.StatusCode)"
            }
            catch {
                if ($null -ne $_.Exception.Response) {
                    $reached = $true
                    try { $detail = "HTTP $([int]$_.Exception.Response.StatusCode)" } catch { $detail = "answered" }
                }
                else {
                    $detail = $_.Exception.Message
                }
            }
            $endpoints += [pscustomobject]@{ Url = $url; Ok = $reached; Detail = $detail }
            Write-Log ("{0}: {1} ({2})" -f $url, $(if ($reached) { "reachable" } else { "FAILED" }), $detail) -Tag $(if ($reached) { "Ok" } else { "Error" })
        }
    }

    $renewed = $null
    try { $renewed = Get-Item -LiteralPath ("Cert:\LocalMachine\My\" + $thumbprint) -ErrorAction SilentlyContinue } catch { $renewed = $null }
    $notAfter = ""
    if ($null -ne $renewed) { $notAfter = $renewed.NotAfter.ToString("yyyy-MM-dd") }

    $null = Send-CertificateReport -Config $Config -Report (New-WacCertificateReport `
        -Status $status -RoleLabel "Exchange Server" -PrimaryName $primaryName -Names $names -Source $source -PluginName $pluginName `
        -Thumbprint $thumbprint -NotAfter $notAfter -PreviousThumbprint $previousThumbprint -PreviousNotAfter $previousNotAfter `
        -Endpoints $endpoints)
    return 0
}

function Invoke-ExchangePostReboot {
    param([object]$Config)

    $exchange = Get-ConfigValue -InputObject $Config -Name "exchange"
    if (-not (Test-ExchangeInstalled)) {
        # Two different reboots reach this point and they are not the same news. Setup
        # leaves a log behind the moment it starts, so its presence separates "setup ran
        # and failed" from "the restart was for a prerequisite and setup is still ahead".
        if (Test-Path -LiteralPath "C:\ExchangeSetupLogs\ExchangeSetup.log") {
            return (New-RoleResult -Status "Failed" -Message "The reboot happened but Exchange is not installed - C:\ExchangeSetupLogs\ExchangeSetup.log says why.")
        }
        return (New-RoleResult -Status "ManualStepRequired" -Message "Setup has not run yet - that restart was for a prerequisite. Run this script again to install Exchange.")
    }
    $script:currentConfig = $Config
    return (Invoke-ExchangePostInstall -Exchange $exchange)
}

function Invoke-ExchangeConfiguration {
    param([object]$Config)

    $exchange = Get-ConfigValue -InputObject $Config -Name "exchange"
    if ($null -eq $exchange) {
        return (New-RoleResult -Status "Failed" -Message "config.json has no exchange section.")
    }
    $script:currentConfig = $Config

    if (Test-ExchangeInstalled) {
        Write-Log "Exchange is already installed - running the post-install configuration" -Tag "Info"
        return (Invoke-ExchangePostInstall -Exchange $exchange)
    }

    # Before the ISO is even looked for, because this is the one moment the volume can
    # still be brought to specification: an allocation unit is a format-time property,
    # and after setup there is a database sitting on it.
    if (-not (Initialize-ExchangeDatabaseVolume -Exchange $exchange)) {
        return (New-RoleResult -Status "Failed" -Message "The database volume is not usable - the lines above say why. Setup was not started.")
    }

    $setupPath = Get-ExchangeSetupPath -Exchange $exchange -NoInteraction:$script:noGui
    if ([string]::IsNullOrWhiteSpace($setupPath)) {
        return (New-RoleResult -Status "ManualStepRequired" -Message "No Exchange ISO - put it in isos\ next to the script (or set exchange.media.isoPath) and run this again.")
    }

    try {
        # Dependencies before anything reads the directory: /PrepareAD needs RSAT-ADDS,
        # and UCMA is on the medium that is mounted right now.
        $dependencies = Invoke-ExchangeDependencyInstall -Exchange $exchange -IsoRoot (Split-Path -Path $setupPath -Parent)
        if (-not $dependencies.Success) {
            return (New-RoleResult -Status "Failed" -Message "A prerequisite could not be installed - the lines above name it.")
        }
        if ($dependencies.RebootRequired) {
            # Not RebootRequired: the engine marks a step complete on that status, and
            # this step has not installed Exchange yet. ManualStepRequired leaves Apply
            # pending, so the next run re-enters here with the prerequisites in place -
            # and the resume task is registered so that next run happens on its own.
            if ([bool](Get-ConfigValue -InputObject (Get-ConfigValue -InputObject $Config -Name "general") -Name "autoResumeAfterReboot" -Default $true)) {
                $null = Register-ResumeTask -ConfigFilePath $script:configFilePath
            }
            return (New-RoleResult -Status "ManualStepRequired" -Message "A prerequisite asked for a restart before setup can run. Restart this server - the run picks up here and installs Exchange.")
        }

        # Forest preparation, state-driven: /PrepareAD covers the schema when run
        # with Schema plus Enterprise Admins, which the account running an Exchange
        # install holds anyway. The version read decides, never a marker.
        if ([bool](Get-ConfigValue -InputObject $exchange -Name "prepareActiveDirectory" -Default $true)) {
            $schemaVersion = Get-ExchangeSchemaVersion
            if ($schemaVersion -lt 17000) {
                $organizationName = Get-ConfigText -InputObject $exchange -Name "organizationName"
                if ([string]::IsNullOrWhiteSpace($organizationName)) {
                    return (New-RoleResult -Status "Failed" -Message "The forest is not prepared for Exchange and the design carries no organization name.")
                }
                Write-Log "Schema rangeUpper is $schemaVersion - preparing Active Directory (needs Schema Admins and Enterprise Admins)" -Tag "Info"
                if (-not (Invoke-ExchangeSetup -SetupPath $setupPath -ArgumentList @("/PrepareAD", "/OrganizationName:$organizationName"))) {
                    return (New-RoleResult -Status "Failed" -Message "Active Directory preparation failed - the setup log says why.")
                }
                Write-Log "Directory prepared. On a multi-DC forest let replication settle before installing." -Tag "Info"
            }
            else {
                Write-Log "The forest is already prepared (schema rangeUpper $schemaVersion)" -Tag "Info"
            }
        }

        $arguments = @("/Mode:Install", "/Roles:Mailbox", "/InstallWindowsComponents")
        $install = Get-ConfigValue -InputObject $exchange -Name "install"
        $targetDirectory = Get-ConfigText -InputObject $install -Name "targetDirectory"
        if (-not [string]::IsNullOrWhiteSpace($targetDirectory)) { $arguments += "/TargetDir:$targetDirectory" }
        $databaseName = Get-ConfigText -InputObject $install -Name "databaseName"
        if (-not [string]::IsNullOrWhiteSpace($databaseName)) {
            $arguments += "/MdbName:$databaseName"
            $databasePath = Get-ConfigText -InputObject $install -Name "databasePath"
            if (-not [string]::IsNullOrWhiteSpace($databasePath)) { $arguments += "/DbFilePath:$databasePath" }
            $logPath = Get-ConfigText -InputObject $install -Name "logPath"
            if (-not [string]::IsNullOrWhiteSpace($logPath)) { $arguments += "/LogFolderPath:$logPath" }
        }

        Write-Log "Installing the Exchange Mailbox role - this takes the better part of an hour" -Tag "Info"
        if (-not (Invoke-ExchangeSetup -SetupPath $setupPath -ArgumentList $arguments)) {
            return (New-RoleResult -Status "Failed" -Message "The Exchange install failed - C:\ExchangeSetupLogs\ExchangeSetup.log has the story.")
        }
    }
    finally {
        Dismount-StudioIso
    }

    return (New-RoleResult -Status "RebootRequired" -Message "Exchange is installed - restart this server, and the run after the reboot applies the namespace, certificate and hardening.")
}
