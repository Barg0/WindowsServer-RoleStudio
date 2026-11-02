#Requires -Version 5.1
<#
.SYNOPSIS
    Onboards this server into Azure Arc and keeps checking that it stays there.
    Built to run every hour from a Group Policy scheduled task.

.DESCRIPTION
    Self-contained: one file, nothing beside it, nothing from the toolbox it ships in.
    Fill in the parameter defaults below once, put the file into the GPO, and every
    server the GPO applies to runs it as SYSTEM.

    Each run looks at what is already there and does the next possible thing:

      agent missing          download it from aka.ms and install it
      not connected          azcmagent connect, three attempts
      connected, healthy     nothing - one log line, exit 0
      service stopped        start it once (never a Disabled one, never arcproxy)
      Disconnected           report the unreachable endpoints - the agent comes back
                             on its own once the network lets it
      Expired                report only - reconnecting needs the Azure resource
                             deleted, which this script never does
      other resource group   report only - moving a machine deletes its resource

    The health check is five steps, each depending on the one before: agent installed,
    connected to this design's resource group, agent status Connected, services
    running, and a managed identity token issued by Azure through the local HIMDS
    endpoint.

    A mail goes out only when the state changes - Onboarded, Repaired, Failed,
    Recovered, Action needed. An hourly run that finds nothing new sends nothing.

    Exit codes: 0 healthy (or nothing to do this run), 1 failed, 2 needs a person,
    3 skipped (this is an Azure VM).

    Working folder, closed to everyone but SYSTEM and Administrators:

      <ProgramData>\AzureArcOnboarding\
        logs\        yyyyMMdd.log and yyyyMMdd-msiexec.log, the last 14 of each
        download\    the agent installer, only while it is being installed
        temp\        the connect secret file, only while azcmagent connect runs
        state.json   the last state, which decides whether a mail goes out

    GROUP POLICY SETUP

    1.  Service principal. Create one for onboarding only and give it the role
        "Azure Connected Machine Onboarding" on the target resource group - nothing
        wider. Register the resource providers Microsoft.HybridCompute,
        Microsoft.GuestConfiguration and Microsoft.HybridConnectivity on the
        subscription. Put a short expiry on the secret and rotate it.

    2.  Group. Create a security group, e.g. "Azure Arc Servers", and add the
        COMPUTER accounts that should be onboarded.

    3.  GPO. Create a GPO and link it where those servers live. On its Delegation tab
        (Security Filtering), remove "Authenticated Users" and add the group from
        step 2 with Read and Apply. GPMC copies that ACL onto the GPO's SYSVOL folder,
        which is what keeps the secret in this file away from users. If GPMC reports
        that the SYSVOL permissions are inconsistent, the protection is not in place.

    4.  Script. Copy this file, with its defaults filled in, into the GPO's folder:
        \\<domain>\SYSVOL\<domain>\Policies\{<GPO GUID>}\Machine\Scripts\

    5.  Task. Computer Configuration > Preferences > Control Panel Settings >
        Scheduled Tasks > New > Scheduled Task (At least Windows 7):
          General   Action: Replace. User: NT AUTHORITY\System.
                    Run whether user is logged on or not. Run with highest privileges.
          Triggers  At startup, delay task for 5 minutes.
                    Daily, repeat task every 1 hour for a duration of Indefinitely.
          Actions   Start a program
                    Program:   powershell.exe
                    Arguments: -NoProfile -NonInteractive -ExecutionPolicy Bypass
                               -File "\\<domain>\SYSVOL\<domain>\Policies\{<GPO GUID>}\Machine\Scripts\Connect-ArcServer.ps1"
          Settings  Stop the task if it runs longer than 30 minutes.
                    If the task is already running: Do not start a new instance.
        -ExecutionPolicy Bypass is needed: a script on a UNC path with dots in the
        name is in the Internet zone, which RemoteSigned refuses.

    6.  Never put the secret into the task's arguments. A process command line ends
        up in event 4688, Sysmon and EDR logs; this file does not.

    7.  Test. Run it once by hand with -TestMail to see all five mails before the GPO
        goes live.

.PARAMETER SubscriptionId
    Subscription the Arc resources are created in.

.PARAMETER TenantId
    Entra tenant of the subscription and the service principal.

.PARAMETER ResourceGroup
    Resource group the Arc resources are created in.

.PARAMETER Location
    Azure region of the Arc resources, e.g. westeurope.

.PARAMETER ServicePrincipalAppId
    Application (client) ID of the onboarding service principal.

.PARAMETER ServicePrincipalSecret
    Secret of the onboarding service principal. Lives in this file; the GPO ACL is
    what protects it. Passed to azcmagent through a short-lived file, never on its
    command line.

.PARAMETER ProxyUrl
    Proxy for the agent, e.g. http://proxy.ad.lab.invalid:8080. Empty means direct.
    Written into the agent's own configuration - the agent is a service and never
    sees a per-user proxy.

.PARAMETER ProxyBypass
    Agent proxy bypass list, passed to azcmagent unchanged.

.PARAMETER Tags
    Azure tags set when the machine connects, as "Name=Value". Empty means none.
    Tags belong to the Azure resource afterwards: changing them here does not
    change a machine that is already connected. Set them in the default below:
    powershell.exe -File cannot pass an array, so "a=1","b=2" on a task's command
    line arrives as one string and is refused for its comma.

.PARAMETER MailSmartHost
    SMTP relay for the state-change mails. Empty means no mail.

.PARAMETER MailPort
    SMTP port of the relay.

.PARAMETER MailUseSsl
    Use STARTTLS towards the relay.

.PARAMETER MailFrom
    Sender address.

.PARAMETER MailFromDisplayName
    Sender display name.

.PARAMETER MailTo
    One or more recipients.

.PARAMETER MailOrganization
    Shown at the top right of every mail. Empty shows nothing.

.PARAMETER TestMail
    Sends one sample of each of the five mails and changes nothing on this server.
    With no MailSmartHost set, writes them as .html files into the log folder instead.

.PARAMETER LogDebug
    Turns the Debug tag on.

.EXAMPLE
    .\Connect-ArcServer.ps1
    What the scheduled task runs: everything comes from the defaults below.

.EXAMPLE
    .\Connect-ArcServer.ps1 -TestMail
    Sends the five sample mails to MailTo and exits.

.NOTES
    Standalone by design, like everything in scripts\: the logging, the agent handling
    and the mail design are copies of what the toolbox does elsewhere, not references
    to it. If one of those changes in the toolbox, this file does not follow.
#>
[CmdletBinding()]
param(
    # ---------------------------[ Azure ]---------------------------
    [string]$SubscriptionId         = "",
    [string]$TenantId               = "",
    [string]$ResourceGroup          = "",
    [string]$Location               = "",
    [string]$ServicePrincipalAppId  = "",
    [string]$ServicePrincipalSecret = "",

    # ---------------------------[ Agent ]---------------------------
    [string]$ProxyUrl      = "",
    [string[]]$ProxyBypass = @(),
    [string[]]$Tags        = @(),

    # ---------------------------[ Mail ]---------------------------
    [string]$MailSmartHost       = "",
    [int]$MailPort               = 25,
    [switch]$MailUseSsl,
    [string]$MailFrom            = "",
    [string]$MailFromDisplayName = "Azure Arc Onboarding",
    [string[]]$MailTo            = @(),
    [string]$MailOrganization    = "",

    # ---------------------------[ Run ]---------------------------
    [switch]$TestMail,
    [switch]$LogDebug
)

# ---------------------------[ Script Start Timestamp ]---------------------------
$scriptStartTime = Get-Date

# ---------------------------[ Script Name ]---------------------------
$scriptName  = "Connect-ArcServer"
$logFileName = (Get-Date -Format "yyyyMMdd") + ".log"

# ---------------------------[ Logging Setup ]---------------------------
# Logging configuration
$log           = $true
$logDebug      = [bool]$LogDebug
$logGet        = $true    # enable/disable all [Get] logs
$logRun        = $true    # enable/disable all [Run] logs
$enableLogFile = $true

# Not beside the script, which is the guideline default: this one runs from SYSVOL,
# where the computer that runs it cannot write. ProgramData is resolved by Windows
# rather than assumed to be on C:.
$workDirectory    = Join-Path -Path $env:ProgramData -ChildPath "AzureArcOnboarding"
$logFileDirectory = Join-Path -Path $workDirectory -ChildPath "logs"
$logFile          = Join-Path -Path $logFileDirectory -ChildPath $logFileName

if ($enableLogFile -and -not (Test-Path -Path $logFileDirectory)) {
    New-Item -ItemType Directory -Path $logFileDirectory -Force | Out-Null
}

# ---------------------------[ Logging Function ]---------------------------
function Write-Log {
    [CmdletBinding()]
    param (
        [string]$Message,
        [string]$Tag = "Info"
    )

    if (-not $log) { return }

    # Per-tag switches
    if (($Tag -eq "Debug") -and (-not $logDebug)) { return }
    if (($Tag -eq "Get")   -and (-not $logGet))   { return }
    if (($Tag -eq "Run")   -and (-not $logRun))   { return }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    # Lower case, five wide - the width of the longest tags there are, so the message
    # column starts in the same place on every line. 'Success' and 'Warning' still map,
    # for call sites that predate the short names.
    $tagMap = @{
        "start" = "start"; "get" = "get"; "run" = "run"; "info" = "info"
        "warn"  = "warn";  "warning" = "warn"
        "ok"    = "o.k.";  "success" = "o.k."
        "error" = "error"; "debug" = "debug"; "end" = "end"
    }
    $shown  = $tagMap[$Tag.Trim().ToLowerInvariant()]
    if ([string]::IsNullOrWhiteSpace($shown)) { $shown = "error" }
    $rawTag = $shown.PadRight(5)

    $color = switch ($shown) {
        "start" { "Cyan" }
        "get"   { "Blue" }
        "run"   { "Magenta" }
        "info"  { "Yellow" }
        "warn"  { "DarkYellow" }
        "o.k."  { "Green" }
        "error" { "Red" }
        "debug" { "DarkGray" }
        "end"   { "Cyan" }
        default   { "White" }
    }

    $logMessage = "$timestamp [ $rawTag ] $Message"

    if ($enableLogFile) {
        try {
            Add-Content -Path $logFile -Value $logMessage -Encoding UTF8
        }
        catch {
            # Logging must never block script execution
        }
    }

    Write-Host "$timestamp " -NoNewline
    Write-Host "[ " -NoNewline -ForegroundColor White
    Write-Host "$rawTag" -NoNewline -ForegroundColor $color
    Write-Host " ] " -NoNewline -ForegroundColor White
    Write-Host "$Message"
}

# ---------------------------[ Exit Function ]---------------------------
function Complete-Script {
    param([int]$ExitCode)

    $scriptEndTime = Get-Date
    $duration      = $scriptEndTime - $scriptStartTime

    Write-Log "Runtime $($duration.ToString('hh\:mm\:ss\.ff'))" -Tag "Info"
    Write-Log "Exit $ExitCode" -Tag "Info"
    Write-Log "==================== End ====================" -Tag "End"

    exit $ExitCode
}

# ---------------------------[ Constants ]---------------------------
$exitHealthy      = 0
$exitFailed       = 1
$exitActionNeeded = 2
$exitSkipped      = 3

$logRetentionCount     = 14
$agentDownloadUrl      = "https://aka.ms/AzureConnectedMachineAgent"
$installerMinimumBytes = 1MB
$connectAttemptCount   = 3
$connectFirstDelay     = 60
$statusWaitSeconds     = 60
$serviceStartSeconds   = 30
$imdsTimeoutMs         = 2000
$himdsTimeoutMs        = 10000

# Documented in Microsoft's agent overview: himds is the one service the agent cannot
# work without, and the two below it can be switched off on purpose for sensitive
# servers. arcproxy is deliberately absent - it is meant to be off without a gateway.
$agentServiceName  = "himds"
$optionalServices  = [ordered]@{
    "GCArcService"     = "guestconfiguration.enabled"
    "ExtensionService" = "extensions.enabled"
}

$azureInstanceMetadataUrl = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
$himdsTokenUrl            = "http://localhost:40342/metadata/identity/oauth2/token?api-version=2020-06-01&resource=https%3A%2F%2Fmanagement.azure.com%2F"

# A connect that fails with one of these will fail the same way a minute later:
# invalid arguments, unknown region, bad credentials, resource name taken, already
# connected. Everything else - exit 42 above all - is usually propagation and worth
# the wait.
$connectPermanentExitCodes = @(20, 23, 41, 44, 67)

$downloadDirectory = Join-Path -Path $workDirectory -ChildPath "download"
$tempDirectory     = Join-Path -Path $workDirectory -ChildPath "temp"
$stateFilePath     = Join-Path -Path $workDirectory -ChildPath "state.json"
$secretFilePrefix  = "connect-"

# The only two principals the working folder admits. Everything SYSTEM writes there -
# the installer it is about to run, the secret, the state that decides the mails - is
# out of reach of an ordinary user, who can create files anywhere under ProgramData.
$trustedSids = @("S-1-5-18", "S-1-5-32-544")
$installerSigner = "O=Microsoft Corporation"

# ===========================[ Housekeeping ]===========================

function Remove-ExpiredLogFile {
    $pattern = '^\d{8}(-msiexec)?\.log$'
    $files = @(Get-ChildItem -LiteralPath $logFileDirectory -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $pattern })

    foreach ($group in @($files | Group-Object -Property { $_.Name -match '-msiexec' })) {
        $expired = @($group.Group | Sort-Object -Property Name -Descending | Select-Object -Skip $logRetentionCount)
        foreach ($file in $expired) {
            try {
                Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
                Write-Log "Removed old log '$($file.Name)'" -Tag "Debug"
            }
            catch {
                Write-Log "Could not remove old log '$($file.Name)': $($_.Exception.Message)" -Tag "Warn"
            }
        }
    }
}

# A run killed between writing the secret file and removing it leaves one behind.
function Remove-StaleSecretFile {
    $stale = @(Get-ChildItem -LiteralPath $tempDirectory -Filter ($secretFilePrefix + "*.json") -File -ErrorAction SilentlyContinue)
    foreach ($file in $stale) {
        try {
            Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
            Write-Log "Removed leftover connect file '$($file.Name)'" -Tag "Warn"
        }
        catch {
            Write-Log "Could not remove leftover connect file '$($file.FullName)': $($_.Exception.Message)" -Tag "Error"
        }
    }
}

function New-WorkDirectorySecurity {
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner((New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")))
    $inherit = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
    foreach ($sid in $trustedSids) {
        $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, "FullControl", $inherit, "None", "Allow")
        $security.AddAccessRule($rule)
    }
    return $security
}

function Test-WorkDirectorySecurity {
    $acl = Get-Acl -LiteralPath $workDirectory -ErrorAction Stop
    if (-not $acl.AreAccessRulesProtected) { return $false }

    $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($trustedSids -notcontains $ownerSid) { return $false }

    foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if ($trustedSids -notcontains $rule.IdentityReference.Value) { return $false }
    }
    return $true
}

# Anything created in the folder by another account still belongs to that account, and an
# owner can rewrite its own ACL. Its owner becomes Administrators and its explicit entries
# go, so only what the folder hands down applies. An item that refuses even that - a user
# can protect a file of their own - is removed instead. An admin running this by hand
# under a "default owner: object creator" policy lands here too, harmlessly.
function Reset-UntrustedWorkItem {
    $administrators = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")

    foreach ($item in @(Get-ChildItem -LiteralPath $workDirectory -Recurse -Force -ErrorAction SilentlyContinue)) {
        $ownerSid = ""
        try { $ownerSid = (Get-Acl -LiteralPath $item.FullName -ErrorAction Stop).GetOwner([System.Security.Principal.SecurityIdentifier]).Value }
        catch { Write-Log "Could not read the owner of '$($item.FullName)'" -Tag "Debug" }
        if ($trustedSids -contains $ownerSid) { continue }

        try {
            if ($item.PSIsContainer) { $security = New-Object System.Security.AccessControl.DirectorySecurity }
            else { $security = New-Object System.Security.AccessControl.FileSecurity }
            $security.SetOwner($administrators)
            $security.SetAccessRuleProtection($false, $false)
            Set-Acl -LiteralPath $item.FullName -AclObject $security -ErrorAction Stop
            Write-Log "'$($item.FullName)' was owned by '$ownerSid' -> Administrators, inherited permissions only" -Tag "Warn"
        }
        catch {
            Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop
            Write-Log "Removed '$($item.FullName)' - owned by '$ownerSid' and its permissions could not be reset" -Tag "Warn"
        }
    }
}

# Throws when the folder cannot be closed: a run that cannot keep its own installer and
# secret away from users must not download or connect.
function Protect-WorkDirectory {
    foreach ($directory in @($workDirectory, $logFileDirectory, $downloadDirectory, $tempDirectory)) {
        if (-not (Test-Path -LiteralPath $directory)) { $null = New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop }
    }

    if (Test-WorkDirectorySecurity) {
        Write-Log "'$workDirectory' is closed to SYSTEM and Administrators" -Tag "Debug"
    }
    else {
        Set-Acl -LiteralPath $workDirectory -AclObject (New-WorkDirectorySecurity) -ErrorAction Stop
        Write-Log "'$workDirectory' -> SYSTEM and Administrators only" -Tag "Ok"
    }
    Reset-UntrustedWorkItem
}

function Test-Elevation {
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ===========================[ Configuration ]===========================

function Get-ConfigurationFault {
    $faults = @()

    $required = [ordered]@{
        "SubscriptionId"         = $SubscriptionId
        "TenantId"               = $TenantId
        "ResourceGroup"          = $ResourceGroup
        "Location"               = $Location
        "ServicePrincipalAppId"  = $ServicePrincipalAppId
        "ServicePrincipalSecret" = $ServicePrincipalSecret
    }
    foreach ($name in $required.Keys) {
        if ([string]::IsNullOrWhiteSpace([string]$required[$name])) { $faults += "$name is empty" }
    }

    # azcmagent takes every tag as one "a=b,c=d" string, so a comma or a second equals
    # sign silently becomes a different set of tags.
    foreach ($tag in @($Tags)) {
        $isWellFormed = ($tag -match '^[^=,]+=[^=,]*$')
        if (-not $isWellFormed) { $faults += "Tag '$tag' is not Name=Value, or contains ',' or a second '='" }
    }

    if (-not [string]::IsNullOrWhiteSpace($MailSmartHost)) {
        if ([string]::IsNullOrWhiteSpace($MailFrom)) { $faults += "MailFrom is empty but MailSmartHost is set" }
        if (@($MailTo | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -eq 0) {
            $faults += "MailTo is empty but MailSmartHost is set"
        }
    }

    return $faults
}

# The secret in this file is only as private as the file. The GPO's security filtering
# is what keeps it from users; this says so when it does not.
function Test-ScriptReadAccess {
    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) { return }

    $broadSids = @("S-1-1-0", "S-1-5-11", "S-1-5-32-545")
    $readRights = [System.Security.AccessControl.FileSystemRights]::ReadData

    try {
        $acl = Get-Acl -LiteralPath $PSCommandPath -ErrorAction Stop
    }
    catch {
        Write-Log "Could not read the ACL of '$PSCommandPath': $($_.Exception.Message)" -Tag "Warn"
        return
    }

    $exposedTo = @()
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        if (($rule.FileSystemRights -band $readRights) -ne $readRights) { continue }

        $sid = ""
        try { $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
        catch { Write-Log "Could not resolve '$($rule.IdentityReference)' to a SID" -Tag "Debug" }

        $isDomainUsers = ($sid -match '^S-1-5-21-.+-513$')
        if (($broadSids -contains $sid) -or $isDomainUsers) { $exposedTo += [string]$rule.IdentityReference }
    }

    if ($exposedTo.Count -gt 0) {
        Write-Log "This script and its secret are readable by $($exposedTo -join ', ') - restrict the GPO's security filtering to the Arc server group: $PSCommandPath" -Tag "Warn"
    }
}

# ===========================[ Environment ]===========================

# Arc refuses Azure VMs, and an Azure VM answers on the instance metadata service with
# an azEnvironment. Another cloud's metadata service on the same address does not
# answer this path with that field.
function Test-AzureVirtualMachine {
    try {
        $request = [System.Net.WebRequest]::Create($azureInstanceMetadataUrl)
        $request.Headers.Add("Metadata", "true")
        $request.Proxy   = $null
        $request.Timeout = $imdsTimeoutMs
        $response = $request.GetResponse()
        try {
            $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
            $body   = $reader.ReadToEnd()
        }
        finally {
            $response.Close()
        }
        $document = $body | ConvertFrom-Json
        return (-not [string]::IsNullOrWhiteSpace([string]$document.compute.azEnvironment))
    }
    catch {
        Write-Log "No Azure instance metadata service answered: $($_.Exception.Message)" -Tag "Debug"
        return $false
    }
}

# Windows Installer holds this mutex while it is executing a package - an agent
# upgrade from Windows Update included, during which its services are briefly down.
function Test-InstallerBusy {
    $mutex = $null
    $isHeld = [System.Threading.Mutex]::TryOpenExisting("Global\_MSIExecute", [ref]$mutex)
    if ($null -ne $mutex) { $mutex.Dispose() }
    return $isHeld
}

# ===========================[ Agent ]===========================

# Every azcmagent call goes through here: stderr folded into the output rather than
# raised, which on 5.1 would otherwise turn the first warning line into an exception.
function Invoke-AgentCommand {
    param(
        [Parameter(Mandatory)][string]$AgentPath,
        [Parameter(Mandatory)][string[]]$Argument
    )

    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $AgentPath @Argument 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }

    $lines = @($output | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    return [pscustomobject]@{ ExitCode = [int]$exitCode; Lines = $lines; Text = ($lines -join "`n") }
}

# The himds service is the agent: it exists exactly when the agent is installed, and
# its image path says where it was installed - azcmagent.exe sits in the same folder.
function Get-ArcAgent {
    $agent = [pscustomobject]@{
        IsInstalled = $false
        Folder      = ""
        AgentPath   = ""
        Version     = ""
    }

    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$agentServiceName'" -ErrorAction SilentlyContinue
    if ($null -eq $service) { return $agent }

    $imagePath = ([string]$service.PathName).Trim()
    if ($imagePath -match '^"([^"]+)"') { $imagePath = $Matches[1] }
    elseif ($imagePath -match '^(.+?\.exe)') { $imagePath = $Matches[1] }

    $folder    = Split-Path -Path $imagePath -Parent
    $agentPath = Join-Path -Path $folder -ChildPath "azcmagent.exe"
    if (-not (Test-Path -LiteralPath $agentPath)) {
        Write-Log "Service '$agentServiceName' exists but '$agentPath' does not" -Tag "Warn"
        return $agent
    }

    $agent.IsInstalled = $true
    $agent.Folder      = $folder
    $agent.AgentPath   = $agentPath

    $versionResult = Invoke-AgentCommand -AgentPath $agentPath -Argument @("version")
    if ($versionResult.Text -match '(\d+\.\d+(\.\d+)*)') { $agent.Version = $Matches[1] }
    return $agent
}

function Get-AgentDownloadProxy {
    if ([string]::IsNullOrWhiteSpace($ProxyUrl)) { return $null }
    return (New-Object System.Net.WebProxy($ProxyUrl, $true))
}

# WebClient rather than Invoke-WebRequest: 5.1 redraws a progress bar per chunk and
# offers TLS 1.0, which aka.ms answers with what looks like a connection reset.
function Save-AgentInstaller {
    $target = Join-Path -Path $downloadDirectory -ChildPath "AzureConnectedMachineAgent.msi"
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force -ErrorAction Stop }

    [System.Net.ServicePointManager]::SecurityProtocol =
        [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

    $client = New-Object System.Net.WebClient
    try {
        $client.Headers.Add("User-Agent", $scriptName)
        $proxy = Get-AgentDownloadProxy
        if ($null -ne $proxy) { $client.Proxy = $proxy }
        Write-Log "Downloading $agentDownloadUrl" -Tag "Run"
        $client.DownloadFile($agentDownloadUrl, $target)
    }
    finally {
        $client.Dispose()
    }

    # An error page installs as cleanly as a corrupt package: not at all, minutes later.
    $length = (Get-Item -LiteralPath $target).Length
    if ($length -lt $installerMinimumBytes) {
        throw "'$target' is only $length bytes - an error page, not the agent installer"
    }
    Write-Log "Downloaded $([math]::Round(($length / 1MB), 1)) MB to '$target'" -Tag "Ok"
    return $target
}

# msiexec runs whatever package it is handed, signed or not. Microsoft's own onboarding
# script refuses an installer that fails this check (AZCM0171); so does this one.
function Test-InstallerSignature {
    param([Parameter(Mandatory)][string]$Path)

    $signature = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "'$Path' signature is $($signature.Status): $($signature.StatusMessage)"
    }
    $subject = [string]$signature.SignerCertificate.Subject
    if ($subject -notmatch [regex]::Escape($installerSigner)) {
        throw "'$Path' is signed by '$subject', not Microsoft"
    }
    Write-Log "Installer signature valid - $subject" -Tag "Ok"
}

function Install-ArcAgent {
    $installerPath = Save-AgentInstaller
    try {
        Test-InstallerSignature -Path $installerPath
    }
    catch {
        Remove-Item -LiteralPath $installerPath -Force -ErrorAction SilentlyContinue
        throw
    }
    $installLog    = Join-Path -Path $logFileDirectory -ChildPath ((Get-Date -Format "yyyyMMdd") + "-msiexec.log")
    $arguments     = @("/i", "`"$installerPath`"", "/qn", "/norestart", "/L*v+", "`"$installLog`"")

    Write-Log "msiexec.exe $($arguments -join ' ')" -Tag "Run"
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru
    $exitCode = [int]$process.ExitCode
    Remove-Item -LiteralPath $installerPath -Force -ErrorAction SilentlyContinue

    # 3010 is "installed, wants a restart" - the agent does not need one to connect.
    if (($exitCode -ne 0) -and ($exitCode -ne 3010)) {
        throw "msiexec exited with $exitCode - see '$installLog'"
    }
    Write-Log "Connected Machine agent installed" -Tag "Ok"
}

# Only written when it differs: setting a proxy restarts the agent's services, and
# this runs every hour.
function Set-ArcProxy {
    param([Parameter(Mandatory)][string]$AgentPath)

    if ([string]::IsNullOrWhiteSpace($ProxyUrl)) { return }

    $current = Invoke-AgentCommand -AgentPath $AgentPath -Argument @("config", "get", "proxy.url")
    if ($current.Text -match [regex]::Escape($ProxyUrl)) {
        Write-Log "Agent proxy is '$ProxyUrl'" -Tag "Debug"
    }
    else {
        $result = Invoke-AgentCommand -AgentPath $AgentPath -Argument @("config", "set", "proxy.url", $ProxyUrl)
        if ($result.ExitCode -ne 0) { throw "azcmagent config set proxy.url failed (exit $($result.ExitCode)): $($result.Text)" }
        Write-Log "Agent proxy -> '$ProxyUrl'" -Tag "Ok"
    }

    $bypass = @($ProxyBypass | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($bypass.Count -eq 0) { return }

    $bypassList    = $bypass -join ","
    $currentBypass = Invoke-AgentCommand -AgentPath $AgentPath -Argument @("config", "get", "proxy.bypass")
    if ($currentBypass.Text -match [regex]::Escape($bypassList)) { return }

    $result = Invoke-AgentCommand -AgentPath $AgentPath -Argument @("config", "set", "proxy.bypass", $bypassList)
    if ($result.ExitCode -ne 0) { throw "azcmagent config set proxy.bypass failed (exit $($result.ExitCode)): $($result.Text)" }
    Write-Log "Agent proxy bypass -> '$bypassList'" -Tag "Ok"
}

# ===========================[ Connection ]===========================

# The agent's own record, readable without calling Azure. A machine that was never
# connected has the file with the fields empty.
function Get-ArcConnection {
    $connection = [pscustomobject]@{
        IsConnected    = $false
        SubscriptionId = ""
        ResourceGroup  = ""
        ResourceName   = ""
        Location       = ""
    }

    $configPath = Join-Path -Path $env:ProgramData -ChildPath "AzureConnectedMachineAgent\Config\agentconfig.json"
    if (-not (Test-Path -LiteralPath $configPath)) { return $connection }

    try {
        $document = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $connection.SubscriptionId = [string]$document.subscriptionId
        $connection.ResourceGroup  = [string]$document.resourceGroup
        $connection.ResourceName   = [string]$document.resourceName
        $connection.Location       = [string]$document.location
    }
    catch {
        Write-Log "Could not read '$configPath': $($_.Exception.Message)" -Tag "Warn"
    }

    $connection.IsConnected = (-not [string]::IsNullOrWhiteSpace($connection.SubscriptionId)) -and
                              (-not [string]::IsNullOrWhiteSpace($connection.ResourceGroup))
    return $connection
}

function Test-DesignedConnection {
    param([Parameter(Mandatory)][object]$Connection)

    return (($Connection.SubscriptionId -eq $SubscriptionId) -and ($Connection.ResourceGroup -eq $ResourceGroup))
}

# 'status' and 'lastHeartbeat' are the JSON keys Microsoft documents for azcmagent show.
function Get-ArcAgentStatus {
    param([Parameter(Mandatory)][string]$AgentPath)

    $status = [pscustomobject]@{ Status = ""; LastHeartbeat = "" }
    $result = Invoke-AgentCommand -AgentPath $AgentPath -Argument @("show", "-j")

    $start = $result.Text.IndexOf("{")
    $end   = $result.Text.LastIndexOf("}")
    if (($start -lt 0) -or ($end -le $start)) {
        Write-Log "azcmagent show -j returned no JSON (exit $($result.ExitCode)): $($result.Text)" -Tag "Warn"
        return $status
    }

    try {
        $document = $result.Text.Substring($start, ($end - $start + 1)) | ConvertFrom-Json
        $status.Status        = [string]$document.status
        $status.LastHeartbeat = [string]$document.lastHeartbeat
    }
    catch {
        Write-Log "Could not parse azcmagent show -j: $($_.Exception.Message)" -Tag "Warn"
    }
    return $status
}

function Wait-ArcAgentConnected {
    param([Parameter(Mandatory)][string]$AgentPath)

    $deadline = (Get-Date).AddSeconds($statusWaitSeconds)
    do {
        $status = Get-ArcAgentStatus -AgentPath $AgentPath
        if ($status.Status -eq "Connected") { return $status }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    return $status
}

function Get-TagArgument {
    $pairs = @($Tags | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    return ($pairs -join ",")
}

# Microsoft's own advice for at-scale onboarding: the secret goes to azcmagent through
# --config rather than on its command line, which ends up in process auditing. The file
# lives in the closed working folder and is removed the moment azcmagent returns.
function New-ConnectSecretFile {
    $path = Join-Path -Path $tempDirectory -ChildPath ($secretFilePrefix + [guid]::NewGuid().ToString("N") + ".json")
    $content = @{ "service-principal-secret" = $ServicePrincipalSecret } | ConvertTo-Json -Compress
    [System.IO.File]::WriteAllText($path, $content, (New-Object System.Text.UTF8Encoding($false)))
    return $path
}

function Get-ConnectArgument {
    $arguments = @(
        "connect",
        "--subscription-id", $SubscriptionId,
        "--resource-group", $ResourceGroup,
        "--tenant-id", $TenantId,
        "--location", $Location,
        "--service-principal-id", $ServicePrincipalAppId
    )
    $tagArgument = Get-TagArgument
    if (-not [string]::IsNullOrWhiteSpace($tagArgument)) { $arguments += @("--tags", $tagArgument) }
    return $arguments
}

function Connect-ArcMachine {
    param(
        [Parameter(Mandatory)][string]$AgentPath,
        [Parameter(Mandatory)][object]$Report
    )

    $arguments = Get-ConnectArgument
    Write-Log ("azcmagent " + ($arguments -join " ") + " --config <secret file>") -Tag "Run"

    $delay = $connectFirstDelay
    for ($attempt = 1; $attempt -le $connectAttemptCount; $attempt++) {
        $Report.Attempt = $attempt
        Write-Log "Connecting - attempt $attempt of $connectAttemptCount" -Tag "Run"

        $secretFile = $null
        try {
            $secretFile = New-ConnectSecretFile
            $result = Invoke-AgentCommand -AgentPath $AgentPath -Argument ($arguments + @("--config", $secretFile))
        }
        finally {
            if (($null -ne $secretFile) -and (Test-Path -LiteralPath $secretFile)) {
                Remove-Item -LiteralPath $secretFile -Force -ErrorAction SilentlyContinue
            }
        }

        foreach ($line in $result.Lines) { Write-Log "azcmagent: $line" -Tag "Debug" }
        $Report.ConnectExitCode = $result.ExitCode

        if ($result.ExitCode -eq 0) {
            Write-Log "Connected - attempt $attempt of $connectAttemptCount" -Tag "Ok"
            return $true
        }

        $lastLine = ""
        if ($result.Lines.Count -gt 0) { $lastLine = $result.Lines[-1] }
        Write-Log "azcmagent connect exit $($result.ExitCode): $lastLine" -Tag "Error"
        $Report.ErrorText = "azcmagent connect returned exit $($result.ExitCode). $lastLine"

        if ($connectPermanentExitCodes -contains $result.ExitCode) {
            Write-Log "Exit $($result.ExitCode) does not change on a retry - not retrying" -Tag "Info"
            return $false
        }
        if ($attempt -lt $connectAttemptCount) {
            Write-Log "Retrying in $delay s" -Tag "Info"
            Start-Sleep -Seconds $delay
            $delay = $delay * 2
        }
    }
    return $false
}

# ===========================[ Endpoint check ]===========================

# Microsoft does not document the shape of azcmagent check's output, so the parser
# takes what it can recognise - an object with a reachable flag and an endpoint name -
# and the mail falls back to the raw text when it recognises nothing. Bench-check it.
function Get-ArcEndpointResult {
    param([Parameter(Mandatory)][string]$AgentPath)

    $result = Invoke-AgentCommand -AgentPath $AgentPath -Argument @("check", "--location", $Location, "-j")
    $check = [pscustomobject]@{ Endpoints = @(); RawText = $result.Text }

    $start = $result.Text.IndexOfAny([char[]]@("[", "{"))
    if ($start -lt 0) { return $check }

    try { $document = $result.Text.Substring($start) | ConvertFrom-Json }
    catch {
        Write-Log "azcmagent check -j did not parse: $($_.Exception.Message)" -Tag "Debug"
        return $check
    }

    $check.Endpoints = @(ConvertTo-EndpointRow -Node $document)
    foreach ($endpoint in $check.Endpoints) {
        $tag = "Ok"
        if (-not $endpoint.Ok) { $tag = "Error" }
        Write-Log "Endpoint $($endpoint.Name) - $($endpoint.Detail)" -Tag $tag
    }
    if ($check.Endpoints.Count -eq 0) { Write-Log "azcmagent check: $($result.Text)" -Tag "Info" }
    return $check
}

function ConvertTo-EndpointRow {
    param([object]$Node)

    if ($null -eq $Node) { return }
    if ($Node -is [System.Array]) {
        foreach ($item in $Node) { ConvertTo-EndpointRow -Node $item }
        return
    }
    if ($Node -isnot [System.Management.Automation.PSCustomObject]) { return }

    $properties   = @($Node.PSObject.Properties)
    $reachable    = $properties | Where-Object { $_.Name -match '^reachable$' } | Select-Object -First 1
    $endpointName = $properties | Where-Object { $_.Name -match '^(endpoint|url|address|host)$' } | Select-Object -First 1

    if (($null -ne $reachable) -and ($null -ne $endpointName)) {
        $isReachable = ([string]$reachable.Value -eq "True")
        $detail = "unreachable"
        if ($isReachable) { $detail = "reachable" }
        [pscustomobject]@{ Ok = $isReachable; Name = [string]$endpointName.Value; Detail = $detail }
        return
    }
    foreach ($property in $properties) { ConvertTo-EndpointRow -Node $property.Value }
}

function Add-EndpointCheck {
    param(
        [Parameter(Mandatory)][string]$AgentPath,
        [Parameter(Mandatory)][object]$Report
    )

    $check = Get-ArcEndpointResult -AgentPath $AgentPath
    $Report.Endpoints = @($check.Endpoints)
    $Report.CheckText = $check.RawText

    $unreachable = @($check.Endpoints | Where-Object { -not $_.Ok })
    if ($unreachable.Count -gt 0) {
        $Report.Reason = "$($unreachable.Count) Arc endpoint(s) unreachable"
    }
}

# ===========================[ Services ]===========================

# A component switched off in the agent's own configuration is a decision somebody made
# for this server; the service behind it is left alone.
function Test-ComponentEnabled {
    param(
        [Parameter(Mandatory)][string]$AgentPath,
        [Parameter(Mandatory)][string]$ConfigKey
    )

    $result = Invoke-AgentCommand -AgentPath $AgentPath -Argument @("config", "get", $ConfigKey)
    if ($result.Text -match '\bfalse\b') { return $false }
    return $true
}

function Start-AgentService {
    param([Parameter(Mandatory)][string]$Name)

    Write-Log "Starting service '$Name'" -Tag "Run"
    Start-Service -Name $Name -ErrorAction Stop
    $service = Get-Service -Name $Name
    $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, (New-TimeSpan -Seconds $serviceStartSeconds))
    Write-Log "Service '$Name' running" -Tag "Ok"
}

# Returns the services that are expected to run, with what happened to each.
function Repair-AgentService {
    param(
        [Parameter(Mandatory)][string]$AgentPath,
        [Parameter(Mandatory)][object]$Report
    )

    $expected = @($agentServiceName)
    foreach ($name in $optionalServices.Keys) {
        if (Test-ComponentEnabled -AgentPath $AgentPath -ConfigKey $optionalServices[$name]) { $expected += $name }
        else { Write-Log "Service '$name' left alone - $($optionalServices[$name]) is false" -Tag "Info" }
    }

    $running = @()
    $broken  = @()
    foreach ($name in $expected) {
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
        if ($null -eq $service) { $broken += "$name missing"; continue }
        if ($service.State -eq "Running") { $running += $name; continue }

        if ($service.StartMode -eq "Disabled") {
            if ($name -eq $agentServiceName) {
                $Report.Outcome = "ActionNeeded"
                $Report.Reason  = "$name is disabled"
                $Report.ActionText = "The service '$name' is set to Disabled on this server. The agent cannot work without it, and this script never changes a start type somebody set. Set it back to Automatic if that was not intended."
                $Report.ActionCommand = "Set-Service -Name $name -StartupType Automatic; Start-Service -Name $name"
            }
            Write-Log "Service '$name' is Disabled - not started" -Tag "Warn"
            $broken += "$name disabled"
            continue
        }

        try {
            Start-AgentService -Name $name
            $Report.Repairs += [pscustomobject]@{ Name = "Service started"; Detail = $name }
            $running += $name
        }
        catch {
            Write-Log "Service '$name' did not start: $($_.Exception.Message)" -Tag "Error"
            $broken += "$name stopped"
        }
    }

    return [pscustomobject]@{ Running = $running; Broken = $broken }
}

# ===========================[ Managed identity ]===========================

# The documented Arc token flow: the first request is refused with the path of a key
# file only an administrator can read, and the second request presents its content.
# A token coming back proves the identity works end to end.
function Get-HimdsResponse {
    param([string]$Authorization = "")

    $request = [System.Net.WebRequest]::Create($himdsTokenUrl)
    $request.Headers.Add("Metadata", "true")
    if (-not [string]::IsNullOrWhiteSpace($Authorization)) { $request.Headers.Add("Authorization", $Authorization) }
    $request.Proxy   = $null
    $request.Timeout = $himdsTimeoutMs

    $response = $request.GetResponse()
    try {
        $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
        return $reader.ReadToEnd()
    }
    finally {
        $response.Close()
    }
}

function Test-ManagedIdentityToken {
    $challenge = ""
    try {
        $null = Get-HimdsResponse
        Write-Log "HIMDS issued a token without a challenge" -Tag "Debug"
        return $true
    }
    catch {
        # A .NET method call surfaces as MethodInvocationException on some hosts, with
        # the WebException - the one carrying the challenge - inside it.
        $webException = $_.Exception
        if (($webException -isnot [System.Net.WebException]) -and ($null -ne $webException.InnerException)) {
            $webException = $webException.InnerException
        }
        $response = $null
        if ($webException -is [System.Net.WebException]) { $response = $webException.Response }
        if ($null -eq $response) { throw "HIMDS did not answer: $($webException.Message)" }
        $challenge = [string]$response.Headers["WWW-Authenticate"]
    }

    if ($challenge -notmatch 'realm=(.+)$') { throw "HIMDS answered without a key file challenge" }
    $keyPath = $Matches[1].Trim()
    $key = Get-Content -LiteralPath $keyPath -Raw -ErrorAction Stop

    $body = Get-HimdsResponse -Authorization ("Basic " + $key.Trim())
    $document = $body | ConvertFrom-Json
    return (-not [string]::IsNullOrWhiteSpace([string]$document.access_token))
}

# ===========================[ The run ]===========================

function New-ArcReport {
    return [pscustomobject]@{
        Outcome          = "Failed"
        Kind             = ""
        Reason           = ""
        ComputerName     = $env:COMPUTERNAME
        Fqdn             = ""
        ResourceName     = ""
        ResourceGroup    = $ResourceGroup
        SubscriptionId   = $SubscriptionId
        Location         = $Location
        AgentVersion     = ""
        InstalledThisRun = $false
        ConnectedThisRun = $false
        Attempt          = 0
        ConnectExitCode  = $null
        Checks           = [ordered]@{}
        Endpoints        = @()
        CheckText        = ""
        Repairs          = @()
        ErrorText        = ""
        ActionText       = ""
        ActionCommand    = ""
        OtherGroup       = ""
        OtherSubscription = ""
        LastHeartbeat    = ""
        PreviousSince    = ""
        FailingSince     = ""
        Tags             = @($Tags)
        RunAt            = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    }
}

$healthCheckNames = @("Agent installed", "Connected", "Agent status", "Services", "Managed identity")

function Set-HealthCheck {
    param(
        [Parameter(Mandatory)][object]$Report,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet("ok", "fail", "fixed", "warn", "skip")][string]$State,
        [string]$Detail = ""
    )
    $Report.Checks[$Name] = [pscustomobject]@{ State = $State; Name = $Name; Detail = $Detail }
}

# Whatever was not reached by the time the run stopped is shown as not reached rather
# than left out: the ladder shows where it broke.
function Complete-HealthCheck {
    param([Parameter(Mandatory)][object]$Report)

    foreach ($name in $healthCheckNames) {
        if (-not $Report.Checks.Contains($name)) {
            Set-HealthCheck -Report $Report -Name $name -State "skip" -Detail "not reached"
        }
    }
    $ordered = [ordered]@{}
    foreach ($name in $healthCheckNames) { $ordered[$name] = $Report.Checks[$name] }
    $Report.Checks = $ordered
}

function Get-ComputerFqdn {
    try { return [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName.ToLowerInvariant() }
    catch { return $env:COMPUTERNAME.ToLowerInvariant() }
}

function Invoke-ArcOnboarding {
    param([Parameter(Mandatory)][object]$Report)

    # ---- 1. agent
    $agent = Get-ArcAgent
    if (-not $agent.IsInstalled) {
        Write-Log "Connected Machine agent not installed" -Tag "Get"
        $Report.Reason = "agent install failed"
        Install-ArcAgent
        $agent = Get-ArcAgent
        if (-not $agent.IsInstalled) { throw "The installer reported success but service '$agentServiceName' is not there" }
        $Report.InstalledThisRun = $true
    }
    $Report.AgentVersion = $agent.Version
    Write-Log "Agent $($agent.Version) at '$($agent.Folder)'" -Tag "Get"

    $installDetail = "$($agent.Version) - already present"
    if ($Report.InstalledThisRun) { $installDetail = "$($agent.Version) - installed this run" }
    Set-HealthCheck -Report $Report -Name "Agent installed" -State "ok" -Detail $installDetail

    Set-ArcProxy -AgentPath $agent.AgentPath

    # ---- 2. connection
    $connection = Get-ArcConnection
    if ($connection.IsConnected -and (-not (Test-DesignedConnection -Connection $connection))) {
        Write-Log "Connected to '$($connection.ResourceGroup)' in '$($connection.SubscriptionId)', not '$ResourceGroup' in '$SubscriptionId' - not changed" -Tag "Warn"
        $Report.Outcome           = "ActionNeeded"
        $Report.Reason            = "connected to $($connection.ResourceGroup)"
        $Report.OtherGroup        = $connection.ResourceGroup
        $Report.OtherSubscription = $connection.SubscriptionId
        $Report.ActionText        = "This script never moves a machine. Disconnecting deletes the Azure resource and every extension, policy assignment and machine configuration on it. To move it, run on $($Report.ComputerName):"
        $Report.ActionCommand     = "azcmagent disconnect"
        Set-HealthCheck -Report $Report -Name "Connected" -State "warn" -Detail "$($connection.ResourceGroup) - not this design"
        return
    }

    if (-not $connection.IsConnected) {
        Write-Log "Not connected" -Tag "Get"
        $isConnected = Connect-ArcMachine -AgentPath $agent.AgentPath -Report $Report
        if (-not $isConnected) {
            Set-HealthCheck -Report $Report -Name "Connected" -State "fail" -Detail "exit $($Report.ConnectExitCode)"
            $Report.Reason = "connect failed (exit $($Report.ConnectExitCode))"
            Add-EndpointCheck -AgentPath $agent.AgentPath -Report $Report
            return
        }
        $Report.ConnectedThisRun = $true
        $connection = Get-ArcConnection
    }
    $Report.ResourceName = $connection.ResourceName
    $connectDetail = $connection.ResourceGroup
    if ($Report.ConnectedThisRun) { $connectDetail = "$($connection.ResourceGroup), attempt $($Report.Attempt) of $connectAttemptCount" }
    Set-HealthCheck -Report $Report -Name "Connected" -State "ok" -Detail $connectDetail

    # ---- 3. status
    $status = Wait-ArcAgentConnected -AgentPath $agent.AgentPath
    $Report.LastHeartbeat = $status.LastHeartbeat
    Write-Log "Agent status '$($status.Status)', last heartbeat '$($status.LastHeartbeat)'" -Tag "Get"

    if ($status.Status -eq "Expired") {
        $Report.Outcome       = "ActionNeeded"
        $Report.Reason        = "agent expired"
        $Report.ActionText    = "The agent has not reached Azure for more than 45 days and its identity has expired. Microsoft's only way back is a disconnect and a new connect, which deletes the Azure resource and everything on it - extensions, policy assignments, history. This script never does that. When it is what you want, run on $($Report.ComputerName) as an account allowed to delete the resource; the next run connects it again:"
        $Report.ActionCommand = "azcmagent disconnect"
        Set-HealthCheck -Report $Report -Name "Agent status" -State "warn" -Detail "Expired, last heartbeat $($status.LastHeartbeat)"
        return
    }
    if ($status.Status -ne "Connected") {
        $shown = $status.Status
        if ([string]::IsNullOrWhiteSpace($shown)) { $shown = "unknown" }
        Set-HealthCheck -Report $Report -Name "Agent status" -State "fail" -Detail "$shown, last heartbeat $($status.LastHeartbeat)"
        $Report.Reason    = "agent $($shown.ToLowerInvariant())"
        $Report.ErrorText = "The agent reports '$shown'. It reconnects on its own once it can reach Azure again; nothing was changed on this server."
        Add-EndpointCheck -AgentPath $agent.AgentPath -Report $Report
        return
    }
    Set-HealthCheck -Report $Report -Name "Agent status" -State "ok" -Detail "Connected, heartbeat $($status.LastHeartbeat)"

    # ---- 4. services
    $services = Repair-AgentService -AgentPath $agent.AgentPath -Report $Report
    if ($Report.Outcome -eq "ActionNeeded") {
        Set-HealthCheck -Report $Report -Name "Services" -State "warn" -Detail ($services.Broken -join ", ")
        return
    }
    if ($services.Broken.Count -gt 0) {
        Set-HealthCheck -Report $Report -Name "Services" -State "fail" -Detail ($services.Broken -join ", ")
        $Report.Reason    = ($services.Broken -join ", ")
        $Report.ErrorText = "Agent service(s) not running: $($services.Broken -join ', ')."
        return
    }
    $serviceState = "ok"
    if ($Report.Repairs.Count -gt 0) { $serviceState = "fixed" }
    Set-HealthCheck -Report $Report -Name "Services" -State $serviceState -Detail (($services.Running -join ", ") + " running")

    # ---- 5. identity
    try {
        $hasToken = Test-ManagedIdentityToken
    }
    catch {
        $hasToken = $false
        Write-Log "Managed identity token: $($_.Exception.Message)" -Tag "Error"
    }
    if (-not $hasToken) {
        Set-HealthCheck -Report $Report -Name "Managed identity" -State "fail" -Detail "no token"
        $Report.Reason    = "managed identity issued no token"
        $Report.ErrorText = "The local HIMDS endpoint did not issue a managed identity token. The agent is connected but cannot act as this machine in Azure."
        return
    }
    Set-HealthCheck -Report $Report -Name "Managed identity" -State "ok" -Detail "token issued by Azure"
    Write-Log "Managed identity token issued" -Tag "Ok"

    $Report.Outcome = "Healthy"
    $Report.Reason  = ""
}

# ===========================[ State and mail decision ]===========================

function Get-PreviousState {
    if (-not (Test-Path -LiteralPath $stateFilePath)) { return $null }
    try { return (Get-Content -LiteralPath $stateFilePath -Raw -Encoding UTF8 | ConvertFrom-Json) }
    catch {
        Write-Log "Could not read '$stateFilePath': $($_.Exception.Message)" -Tag "Warn"
        return $null
    }
}

function Save-RunState {
    param(
        [Parameter(Mandatory)][object]$Report,
        [object]$Previous
    )

    $since = $Report.RunAt
    $isOnboarded = ($Report.Outcome -eq "Healthy")
    if ($null -ne $Previous) {
        if ($Previous.state -eq $Report.Outcome) { $since = [string]$Previous.since }
        if ([bool]$Previous.onboarded) { $isOnboarded = $true }
    }

    $document = [ordered]@{
        state     = $Report.Outcome
        reason    = $Report.Reason
        since     = $since
        onboarded = $isOnboarded
        lastRun   = $Report.RunAt
    }
    try {
        $json = $document | ConvertTo-Json
        [System.IO.File]::WriteAllText($stateFilePath, $json, (New-Object System.Text.UTF8Encoding($false)))
    }
    catch {
        Write-Log "Could not write '$stateFilePath': $($_.Exception.Message)" -Tag "Warn"
    }
}

# One mail per change of state, never one per run.
function Get-MailKind {
    param(
        [Parameter(Mandatory)][object]$Report,
        [object]$Previous
    )

    $previousState = ""
    $previousReason = ""
    $wasOnboarded = $false
    if ($null -ne $Previous) {
        $previousState  = [string]$Previous.state
        $previousReason = [string]$Previous.reason
        $wasOnboarded   = [bool]$Previous.onboarded
    }

    switch ($Report.Outcome) {
        "Healthy" {
            if (-not $wasOnboarded) { return "Onboarded" }
            if (($previousState -eq "Failed") -or ($previousState -eq "ActionNeeded")) { return "Recovered" }
            if ($Report.Repairs.Count -gt 0) { return "Repaired" }
            return ""
        }
        "Failed" {
            if ($previousState -ne "Failed") { return "Failed" }
            return ""
        }
        "ActionNeeded" {
            if (($previousState -ne "ActionNeeded") -or ($previousReason -ne $Report.Reason)) { return "ActionNeeded" }
            return ""
        }
    }
    return ""
}

function Format-Duration {
    param([string]$Since)

    try { $span = (Get-Date) - [datetime]::ParseExact($Since, "yyyy-MM-dd HH:mm:ss", $null) }
    catch { return "" }
    if ($span.TotalHours -ge 1) { return ("{0} h" -f [math]::Round($span.TotalHours)) }
    return ("{0} min" -f [math]::Max(1, [math]::Round($span.TotalMinutes)))
}

# ===========================[ Mail - design ]===========================
# The design is the toolbox's mail report, which is the studio's own design in what mail
# clients accept: tables and inline styles, no <style> block, no flexbox, no SVG. The
# palette is the studio's Kaido Dark, token for token.
$mailFontFamily = "font-family:'Segoe UI','Segoe UI Web (West European)',-apple-system,BlinkMacSystemFont,Roboto,'Helvetica Neue',Arial,sans-serif"
$mailMonoFamily = "font-family:Consolas,'Courier New','Liberation Mono',monospace"

$mailPalette = @{
    Background   = "#16171e"
    Card         = "#1d1f28"
    Subtle       = "#1a1c24"
    Border       = "#2b2f3d"
    BorderStrong = "#3d4356"
    Divider      = "#23262f"
    Text         = "#d7dbec"
    Muted        = "#8b93ad"
    Accent       = "#7aa2f7"
    AccentSoft   = "#22304f"
    AccentText   = "#93b3fa"
    Danger       = "#f7768e"
    DangerSoft   = "#3a222c"
    Success      = "#9ece6a"
    SuccessSoft  = "#28321f"
    Warn         = "#e0af68"
    WarnSoft     = "#352d1e"
    Topbar       = "#7aa2f7"
    TopbarText   = "#11141c"
    TopbarMuted  = "#22304f"
}

# The studio's glyphs, rasterised to 64 px PNG. They travel as linked resources and are
# referenced as cid: - Outlook draws no SVG, and Outlook and Gmail both block data: URIs.
$mailIcons = @{
    mark = @(
        "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAEn0lEQVR4AexaT4gbZRR/b5LNdhvTbJJpu5vZgyBKVQQFpVVEKxb1",
        "UFEvHhRv6qEXC1ZqRdiKh1KqUA9SRG968eg/RK1YPViLBUHRQ0FQTLLbOtnM2t3Wbifz+nJoSzLfzJdv+k12ZjtDHpt533u/773f",
        "fPlmf5kYcJ0fGQHX+QKAbAVkKyBlDNxQnbpt0pzZLrNS1bq3WNw4JWsvLR8BrNTquyqmtTRm5H9HgO9kljfwx8LE+FylZv1UMq1b",
        "gohIBQGV2sxeQONdACyC6oG4NUd4vFwuV0SpiSdgvWnWAeGAqPhhfYhQxbHSIVF84gnIdwsPiApX9SHR/aKcxBOQM+BO0HAQwM0A",
        "9fWDUGEE5DdUpx8rm/U9vOPu12o16/WKOfPsRNWaGSzIf244fp+6BxENgNbFwUx2DroAisWNU7x7/pozcl8aYBziHXdWqyG+ybN+",
        "tM7AUxWz/gy/X7WXkIDCusIsIN46gqomgIwjpZJVG8FcwimEBBDCU8LoOJwIG3DMuycO6GEwfQRM8oGAm4dJ1hXDH7MturBkOIPj",
        "PgIcxzk3GBT3OSK5cc8RhO8jIChwrfozAgRXdgUIFgX+2Fz8T0ojNnAJsHAFENBJSZ62YSLyyHV/0waoCCQkwIPuPgAazWaIcHhx",
        "8cyfinVrCxcS8F97/uf/PdoC5B1kIr7gJfq9ViP6lvE+IPKedOzmy9q6iQAkJKCHc36h9U+n3Xq1Yzd3OnZju1ZrN3cw3gtOu/VJ",
        "b67VtEACVrOoUc6dERCV7bI5ffdkzTrMX1d9xVL5mJLVrKMc/365aj0ddX5deZFWADf+HJJxgjX2S4DwCAI8qGSID3P884aBH0+a",
        "1tu6momCE4kABDzAzUfK9RVJsLtc3nSTzz8ih3ITvS9L+KpbuurrEYn5/B268FRxlAkYmxjXL10Jb1QtXFe8MgEE3SVdk1/GiVMO",
        "X54j6K8yAUFAafVnBKheOXTJVs2RxbMuSJYcDivYceYbBHQ6LEZljCiBcljSgAsErxCRJ4kbbjiJclhWudNufkjobSWid5iMr3kJ",
        "q8nlNMhhGQmL9txJJmJ3p9141FGVy5kcltE7uvHsNhgX1xXT2sn2HivHb1j69svltMthGWnc8CwAfsb2IoudHTgol9MuhyHkKBY3",
        "beY7w2shIf1DaZPD/dX7z3LjubsQoeAfEXsQ0UiVHBa3cdUb6UlvmuTw1VaD3pHyY7VMDgdxGcGvmmKoJqy1eO0EeEBzqiSxlkiP",
        "HJY1173Q/YVF0tBKsRebuKfDsibDxpeXz5xGwLfCYvrG0iiH+xoQnLBC3AtAj/PSfiPcvCecpD4dFvSl5OrYzc8du7E/3FqfKoHG",
        "EKx9E9RdY9fz/tKByXvN34wz3E9lOTAxLze38oOWYhCPinASvwLO2XaLxdU+UfHD+oigA+7SHlF84gnoFc2b6kEg2sUbq/pTKaIT",
        "XaRtDh89rEFLBQFcNHXazSO8sZYueu7tfGd5SGauR/etnL8wzXnbztrNU4whfKWFgCvFLy3M/8F3lmMyO7vQPL68/O/8lcSAN6kj",
        "IKCPyO6MgMjUrZHE1K+Aa70OlwAAAP//ocohowAAAAZJREFUAwCLw2+fnQaL8AAAAABJRU5ErkJggg=="
    )
    arc = @(
        "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"
    )
    server = @(
        "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",
        "rifMSaoAAAAASUVORK5CYII="
    )
    security = @(
        "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",
        "+QAAAABJRU5ErkJggg=="
    )
    proxy = @(
        "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAE9UlEQVR4AexY/29TVRQ/p92sczC+ONoYlM1f0Bh0mmhMjMYuk8KM",
        "MQY10YBu7esvgx/8xS+/8TcQE8DEvnYUE/1RWbQwpsyoRIzxS4YajDEBykyKhAFbtm60l3O6tXu777V9LX19wHsv9+zde8+553zO",
        "55533+s84PDLJcDhBQBuBbgV4HAG3EfA4QXgHoLuI+A+Ag5nwH0E7CqA/a8HVx0Ib911cLDvjQ939nfYhcO2CsD2lq8o6cMCPZ96",
        "71r4nPq2NFsIKOw44nPFjBGwN/lWqL04tvIu+7aFAF9LdoMMZLo1F5DnmjG2hYBmJGY2hkuAWabuVDu3AqzcWaFGnhSqsp/kmIhH",
        "x4sy8EzXsBw38vSmQ0X90n1UxJV9gnzIto0cW1IBQgAKNfoegOckIO4mCRHo54via/U+u9m//NZ7ONAOPFfUL923AuA77IOIeJd9",
        "ggWXJQRALLqRsO4FhFa6G7a+hzrhpS1+ePnRAPRu7jS0KUyyDwF7IRG+vzBu8B9rCPDALkp+VTWsD6xrg41r765mBoC4GoR3J1hw",
        "WUMAwuPQ6MsKn4TRkACRULbTMywfSqVDjJ5JVSSiQVpfpglDv2WMzU3TuVLOkLEUMGkO2qWDdAmzMsw5Ga3XAaWFb4LAFCC8TQtK",
        "B9fKPkZAwAkOTPO2NnpL9DMWAMIEUA7vAFBOhdxg5aUjAEBsW2lSYSTEKxW0zVEhmsdrkJsBAdhtFnl6aq7n4OALQVkmp2bXmPVh",
        "1i49NbtWjsPjC4TBrA8AfW4GBMACVLnmr+cheeo8jExkggLxhCxfTFwMHf4pDddz+SqeqqsXKBb7GjmdCclxeHyEMCRPpYHtqnuD",
        "ednGiADZRjc+e3kWZuYrJzedzUH68pxuba0T5ykW+6q0bmY+B+emZg1Nqk3WRUALVnO7qPfU5X1xbfGv12vOiZdO7eKaWu7mvEse",
        "H+xsh651lT9guu9tg03r75FW1j7sWt9WNRZj6e6sL1ZdBHAaL24JwI6e+46gEL2yvNYTSPU/4mezhgjHerXHn5Lj8HjHY4ER1tcb",
        "yIAAccGss0BH619Dw2Pjsmzo8E2b9WHWzr+67Zoch8eBNb5/zfqgV/ykbKsnAOEz2ajsOA+flNU1S4E51XQog9x0BGBYPUo/ZvuJ",
        "rUPk+FtjEXE6c3oxqp4mva0Nw8MTjIXwxgmIMV4BSc6pkBsZaZuOAFayIUbUQYzEgsaiKhiOjbPtrSCMBSOEqRxeJTaAvLEGYA0J",
        "MLCrbUrgL7UtMGX9qymrGo2sIcCDR6kkdV9dWmz85fZ3Zgb+yUwDf1lqdbq+4K/TfEo334AJSwjA8Me/0a+vDyrh+/KPDHx95n84",
        "fuYSpP7MVDJl3fuoxH/nTqPFEgIYJCqxfSDyT4GAj2h8nKR0QM0t5L7/72qWphbb5JUsfcvnvqNRyQaEGCU5AIhPFHyR0opmGQEM",
        "lnbtZwI/hJFYiKR0oCZPnh1kvVZiP55beegq6jZU1D2FatIaNrhvKQENxmqJO5cAS2i9jZzecRVQK/e2ENDizereez6Yu1gr+EbY",
        "20KAEv/hmgCRXE6A/mlNc8vj5vVsIYDT25MYG0AQ2xGwb3diLMJzdohtBHCyQ4mxY0OJ0W+4b5fYSoBdSWvjugRo2XBi360AJ+66",
        "Nme3ArRsOLHvVoATd12bs1sBWjac2L/tK+BmN+0GAAAA//+Q1NhXAAAABklEQVQDAItL65C9cIEWAAAAAElFTkSuQmCC"
    )
    tags = @(
        "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",
        "YII="
    )
    restart = @(
        "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",
        "AElFTkSuQmCC"
    )
    info = @(
        "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAGrElEQVR4AexaXWwUVRQ+Z2bpFrQiBqQYiiCCEKBigkLkQXwwKASK",
        "3UWJD0bEhBi6i0J3C6IxKEK7CxF2qQlRDDESQ9mtFhQlMYKJxmh8UEEthdZiDVSo8lOkP3bnem7LVtLde3d+dmC3dDN37vT8fPc7",
        "39yZ3JmpAjf4b0CAG3wCwMAMGJgBN7gC1/QSqKysurlia809FduiDwfD0acC4epS3oJ0HAzvncN9POZanhNbBQhUVuX3FBd9JxiO",
        "NFzW1FZF7apVFPiCityNwIK88WMA5RD38RgeGwhF3w5ur16yMVQ1gvy2bbYIEAhFng2EIz+hpp4m5rupLQPAcaD7h+MQ4Tlg7INB",
        "qJ7hWMFw9VLd6QYC0ypARTi6MBiKHkHEnQg4zQAPaWgPFns3QKIS/nxpsEFnWgQIhKofCoSi3xBYDSBMNchBd3i3EAgfB8LRr7Zs",
        "2/ug7kRJIHGWeHW4gqHqMkR2GBFm6QhPSwgCzNYU5Wu6V6yzCmhJgEA4sgmQlVslYT4fNwRC0dfN54P5lSAN/BYCrrEyeDpyaea9",
        "HAxFw2axTM2AYChSTgM/b3bQtOchlHBOZnANC7A5FHUDYpmZweI5WiwGfzb/ASfqjsLxY0eg+XQTxGJdcbe5njgFt0WeSJXc129I",
        "gC2h6nsZsPf6ghj9u/74r/B74wk493cLnD/3FzSdrIf6up+NwiTGI+wKVH44PdEhtugWYPOO/cM1ZPvp7A8Ww6X2dHV1wfnzLQmB",
        "Fy6cg4729gS7IQPiYNS0fZyr3jzdAmidndsJtICapa2jo02Y39Ep9gmTEh0FV7gmepJYdAlQvj0yBQGeTJJv2OR0iidQbu4Qw3jJ",
        "EjjX4NZIYTJfX5suAVSGW/ommv3b4XDA0KHDEtLz8m6FnBxngt20QcWAntyUAvDHVAKaSy1t290Tp8KYsRNh2G3Du1vBneNhwqS0",
        "r6DnXuEu5Z1SAGD4hhTBhFNRVRiZfwdwIXjLH1UAquowgZQqRVmfMkIWULGzJo8BzJDFZLKPMTYrFDpwi4yjdAYobbH5iJgjA8hk",
        "H+feobTPk3GUCkAKLpIlZ4MvVQ1CAXbs+H4QMvaYXUVear0Iv9XXQmNDHVxqvWDXMITLHqWdcBMK0NrZOJ5WfdLrR4iqw9FAxbec",
        "bYazZ05BQ/0xHRnmQhBw6OZwZJIoWygArfnzRUlW7W1t/9Cy93IvTEf7ZeC2XkOaD2S1iAVgytg08+iFwySvIRAVsO2HqvBkikdF",
        "JkyyjahdwJq4FrEAAP1CAK4pQyaczTIBeG6/bzIBmvtL9ciwUVSLWACG/UYAUMS1CAVA1ISqidTMWDuLCU+mWAAQq5axhQqIoaQW",
        "oQB5OWPraQFh5xpVQDfNZsYu8lpEqEIBli+f8S8AfgZZ/mOIn/bUkrwQoQA8nB4nP+J9NrdUNUgFcGq5B+hxsjNbBeDctcHqJzL+",
        "UgG83nkXScFDMoBM9nHuZcuKWmUcpQL0JGrX8etvDwPz+9TcUwrg8yw+TAQOUsu27eAV7lLeKQXoztawtLvPmh2LxZCt1kNXlwC+",
        "lcVHGcAePYAZEvP+mhK3rq+tugTgRSk5OSXUN1HL9K0Jc5y6Z6xuAUqXL2hhirIQGLP8BdOZ6wRFVXuFVB2DwOlMw2cxxtoUhgs4",
        "117wFAe6BeA4/hWP/wAMngGLP/76a3TBOHDSx1AnfSwtGHMXIBqikpQBrfmfXu0t/jGpU2A0PKpvpbuKZkGFAE+3eWT+aCic/gAU",
        "3jcTRtw+SneeJHB9qdcVkfiTugwLwFFKPa61jMErdEz3Rtpf340WfOzV0pLilN8Bk9E0JQCtsJjf69qgASwiBf5/v51sBDtt9KRH",
        "l+QCv9f9GudkZihTAsQHKvO49oGizKbZcD1enpxUFOV+n9clXevHuYp6SwJwUH5jZDc5CundwZskhMV/9eKI8tY9BoOt2hDHtNUl",
        "xXXy6NReywLwIfgDh9/jXsU0x1Qi+CW32dE4Nh+DzvqLfMx0jJEWAeJEyl4oOkb3hjl0X1gCwGrjdss9Y7+Ahos4Nh/DMt5VAGkV",
        "II7r97j2+DzuyQhsMl0aa0mMb8lHutBe30Z3dvgOEF5SFccEn9c9hZbjNfpSjUXZIkCcQqnHXUuXRjmJMUsDx2haPzyCDBbTVF5K",
        "anipX9fdAPjxUu7jMTzW73XN9JW4Nq1aUXQijmdHb6sAVxMu8xSd8nndn/PFit/r2uX3uMLUb+xuPce7uM9HMTz26lw7j6+ZAHYW",
        "YQV7QAAr6vWH3IEZkO1n0Sr//wAAAP//W50X3AAAAAZJREFUAwA0Zx2fG2879AAAAABJRU5ErkJggg=="
    )
}

$mailKindWords = @{
    Onboarded    = "Onboarded"
    Repaired     = "Repaired"
    Failed       = "Failed"
    Recovered    = "Recovered"
    ActionNeeded = "Action needed"
}

function ConvertTo-MailText {
    param([string]$Value)

    if ([string]::IsNullOrEmpty($Value)) { return "" }
    $text = $Value -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;'
    return ($text -replace "(`r`n|`r|`n)", '<br>')
}

function New-MailIcon {
    param(
        [Parameter(Mandatory)][string]$Name,
        [int]$Size = 16
    )
    return '<img src="cid:icon-' + $Name + '" width="' + $Size + '" height="' + $Size +
        '" alt="" style="display:block;border:0;outline:none;text-decoration:none;">'
}

function New-MailPill {
    param(
        [string]$Label,
        [string]$Value,
        [ValidateSet("off", "on", "success", "warn", "danger")][string]$Tone = "off"
    )

    $colour = $mailPalette.Muted; $background = $mailPalette.Subtle; $border = $mailPalette.Border
    if ($Tone -eq "on")      { $colour = $mailPalette.AccentText; $background = $mailPalette.AccentSoft;  $border = $mailPalette.Accent }
    if ($Tone -eq "success") { $colour = $mailPalette.Success;    $background = $mailPalette.SuccessSoft; $border = $mailPalette.Success }
    if ($Tone -eq "warn")    { $colour = $mailPalette.Warn;       $background = $mailPalette.WarnSoft;    $border = $mailPalette.Warn }
    if ($Tone -eq "danger")  { $colour = $mailPalette.Danger;     $background = $mailPalette.DangerSoft;  $border = $mailPalette.Danger }

    return '<td style="padding:0 8px 8px 0;"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>' +
        '<td style="' + $mailFontFamily + ';font-size:10px;letter-spacing:1px;text-transform:uppercase;padding:5px 10px;' +
        'color:' + $colour + ';background:' + $background + ';border:1px solid ' + $border + ';border-radius:4px;white-space:nowrap;">' +
        '<span style="color:' + $mailPalette.Muted + ';">' + (ConvertTo-MailText $Label) + '</span>&nbsp;&nbsp;<b>' +
        (ConvertTo-MailText $Value) + '</b></td></tr></table></td>'
}

function New-MailFactRow {
    param(
        [string]$Label,
        [string]$Value,
        [string]$Why = "",
        [string]$ValueColor = "",
        [switch]$Monospace
    )

    $colour = $ValueColor
    if ([string]::IsNullOrWhiteSpace($colour)) { $colour = $mailPalette.Text }
    $face = $mailFontFamily; $size = "13px"; $wrap = "word-break:break-word;"
    if ($Monospace) { $face = $mailMonoFamily; $size = "12px"; $wrap = "word-break:break-all;" }

    $text = ConvertTo-MailText $Value
    if ([string]::IsNullOrWhiteSpace($text)) { $text = "&mdash;"; $colour = $mailPalette.Muted }

    $row = '<tr><td width="150" valign="top" style="width:150px;' + $mailFontFamily +
        ';font-size:11px;letter-spacing:.6px;text-transform:uppercase;color:' + $mailPalette.Muted +
        ';padding:9px 20px 3px 0;white-space:nowrap;">' + (ConvertTo-MailText $Label) + '</td>' +
        '<td valign="top" style="' + $face + ';font-size:' + $size + ';color:' + $colour + ';padding:8px 0 3px 0;line-height:1.5;' + $wrap + '">' + $text
    if (-not [string]::IsNullOrWhiteSpace($Why)) {
        $row += '<div style="' + $mailFontFamily + ';font-size:11.5px;color:' + $mailPalette.Muted + ';padding-top:3px;line-height:1.5;">' +
            (ConvertTo-MailText $Why) + '</div>'
    }
    return ($row + '</td></tr>')
}

function New-MailCheckRow {
    param(
        [ValidateSet("ok", "fail", "fixed", "warn", "skip")][string]$State,
        [string]$Name,
        [string]$Detail,
        [switch]$Monospace
    )

    $chip = $mailPalette.Success; $label = "OK"; $ink = $mailPalette.TopbarText; $nameColour = $mailPalette.Text
    if ($State -eq "fail")  { $chip = $mailPalette.Danger; $label = "FAIL" }
    if ($State -eq "fixed") { $chip = $mailPalette.Warn;   $label = "FIXED" }
    if ($State -eq "warn")  { $chip = $mailPalette.Warn;   $label = "WARN" }
    if ($State -eq "skip")  { $chip = $mailPalette.BorderStrong; $label = "SKIP"; $ink = $mailPalette.Muted; $nameColour = $mailPalette.Muted }

    $face = $mailFontFamily + ';font-size:13px;'
    if ($Monospace) { $face = $mailMonoFamily + ';font-size:12px;word-break:break-all;' }

    return '<tr><td width="56" valign="top" style="width:56px;padding:6px 12px 6px 0;">' +
        '<div style="' + $mailFontFamily + ';font-size:10px;font-weight:600;letter-spacing:1px;text-align:center;color:' + $ink +
        ';background:' + $chip + ';padding:3px 0;">' + $label + '</div></td>' +
        '<td valign="top" style="' + $face + 'color:' + $nameColour + ';padding:6px 12px 6px 0;">' + (ConvertTo-MailText $Name) + '</td>' +
        '<td valign="top" align="right" style="' + $mailFontFamily + ';font-size:11.5px;color:' + $mailPalette.Muted + ';padding:6px 0;">' +
        (ConvertTo-MailText $Detail) + '</td></tr>'
}

function New-MailNotice {
    param(
        [string]$Title,
        [string]$Text,
        [ValidateSet("danger", "warn", "info")][string]$Tone = "danger"
    )

    $edge = $mailPalette.Danger; $back = $mailPalette.DangerSoft
    if ($Tone -eq "warn") { $edge = $mailPalette.Warn;   $back = $mailPalette.WarnSoft }
    if ($Tone -eq "info") { $edge = $mailPalette.Accent; $back = $mailPalette.AccentSoft }

    return '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:' + $back +
        ';border-left:3px solid ' + $edge + ';"><tr><td style="padding:14px 18px;">' +
        '<div style="' + $mailFontFamily + ';font-size:11px;font-weight:600;letter-spacing:1px;text-transform:uppercase;color:' + $edge +
        ';padding-bottom:6px;">' + (ConvertTo-MailText $Title) + '</div>' +
        '<div style="' + $mailFontFamily + ';font-size:12.5px;line-height:1.6;color:' + $mailPalette.Text + ';">' + (ConvertTo-MailText $Text) +
        '</div></td></tr></table>'
}

function New-MailCodeBox {
    param([string]$Text)

    return '<div style="' + $mailMonoFamily + ';font-size:12px;color:' + $mailPalette.Text + ';background:' + $mailPalette.Subtle +
        ';border:1px solid ' + $mailPalette.Border + ';padding:10px 14px;margin-top:10px;word-break:break-all;">' + (ConvertTo-MailText $Text) + '</div>'
}

function New-MailSection {
    param(
        [string]$Label,
        [string]$Icon,
        [string]$Content,
        [string]$Padding = "2px 26px 22px"
    )

    return '<tr><td style="padding:18px 26px 6px;"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>' +
        '<td width="16" valign="middle" style="width:16px;padding-right:10px;">' + (New-MailIcon -Name $Icon -Size 16) + '</td>' +
        '<td valign="middle" style="' + $mailFontFamily + ';font-size:11px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:' +
        $mailPalette.Muted + ';">' + (ConvertTo-MailText $Label) + '</td></tr></table></td></tr>' +
        '<tr><td style="padding:' + $Padding + ';">' + $Content + '</td></tr>'
}

function New-MailTable {
    param([string]$Rows)
    return '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">' + $Rows + '</table>'
}

# ===========================[ Mail - content ]===========================

function New-HealthSection {
    param([Parameter(Mandatory)][object]$Report)

    $rows = ""
    foreach ($check in $Report.Checks.Values) { $rows += New-MailCheckRow -State $check.State -Name $check.Name -Detail $check.Detail }
    return (New-MailSection -Label "Health checks" -Icon "server" -Content (New-MailTable $rows))
}

function New-EndpointSection {
    param([Parameter(Mandatory)][object]$Report)

    if (@($Report.Endpoints).Count -gt 0) {
        $rows = ""
        foreach ($endpoint in $Report.Endpoints) {
            $state = "ok"
            if (-not $endpoint.Ok) { $state = "fail" }
            $rows += New-MailCheckRow -State $state -Name $endpoint.Name -Detail $endpoint.Detail -Monospace
        }
        return (New-MailSection -Label "Endpoints" -Icon "proxy" -Content (New-MailTable $rows))
    }
    if (-not [string]::IsNullOrWhiteSpace($Report.CheckText)) {
        return (New-MailSection -Label "azcmagent check" -Icon "proxy" -Content (New-MailCodeBox $Report.CheckText))
    }
    return ""
}

function Get-MailHeadline {
    param([Parameter(Mandatory)][object]$Report)

    $hostName = $Report.ComputerName
    $bold = '<b style="color:' + $mailPalette.Text + ';">' + (ConvertTo-MailText $hostName) + '</b>'

    switch ($Report.Kind) {
        "Onboarded"    {
            # A machine somebody connected by hand before the GPO reached it is reported
            # once too, but not as a first connect.
            $subtitle = "Already connected - now checked every hour on $bold"
            if ($Report.ConnectedThisRun) { $subtitle = "Connected to Azure Arc for the first time on $bold" }
            return @("$hostName onboarded", $subtitle, "Onboarded", "on")
        }
        "Repaired"     { return @("$hostName repaired",      "Agent repaired on $bold", "Repaired", "warn") }
        "Failed"       { return @("$hostName failed",        "Azure Arc onboarding failed on $bold", "Failed", "danger") }
        "Recovered"    { return @("$hostName recovered",     "Connected to Azure Arc again on $bold", "Recovered", "success") }
        "ActionNeeded" { return @("$hostName needs action",  "Nothing was changed on $bold", "Action needed", "warn") }
    }
}

function Get-MailSubject {
    param([Parameter(Mandatory)][object]$Report)

    $detail = $Report.Reason
    if ($Report.Kind -eq "Onboarded") { $detail = $Report.ResourceGroup }
    if ($Report.Kind -eq "Repaired")  { $detail = "service started: " + (@($Report.Repairs | ForEach-Object { $_.Detail }) -join ", ") }
    if ($Report.Kind -eq "Recovered") { $detail = "connected again after " + $Report.PreviousSince }
    return ("[Azure Arc] {0}: {1} - {2}" -f $mailKindWords[$Report.Kind], $Report.ComputerName, $detail)
}

function Get-MailPreheader {
    param([Parameter(Mandatory)][object]$Report)

    switch ($Report.Kind) {
        "Onboarded"    { return "$($Report.ComputerName) is connected to Azure Arc in $($Report.ResourceGroup). All five health checks passed." }
        "Repaired"     { return "$($Report.ComputerName) was repaired - service started: $(@($Report.Repairs | ForEach-Object { $_.Detail }) -join ', ')." }
        "Failed"       { return "$($Report.ComputerName): $($Report.Reason)." }
        "Recovered"    { return "$($Report.ComputerName) is connected again after $($Report.PreviousSince). All five health checks passed." }
        "ActionNeeded" { return "$($Report.ComputerName): $($Report.Reason). Nothing was changed." }
    }
}

function Get-MailBody {
    param([Parameter(Mandatory)][object]$Report)

    $mono = @{ Monospace = $true }
    $pills = ""; $facts = ""; $sections = ""

    switch ($Report.Kind) {
        "Onboarded" {
            $pills += New-MailPill -Label "Agent" -Value $Report.AgentVersion
            $pills += New-MailPill -Label "Region" -Value $Report.Location
            if ($Report.Attempt -gt 0) { $pills += New-MailPill -Label "Attempt" -Value "$($Report.Attempt) of $connectAttemptCount" }
            $facts += New-MailFactRow -Label "Resource" -Value $Report.ResourceName @mono
            $facts += New-MailFactRow -Label "Resource group" -Value $Report.ResourceGroup @mono
            $facts += New-MailFactRow -Label "Subscription" -Value $Report.SubscriptionId @mono
            $facts += New-MailFactRow -Label "Run at" -Value $Report.RunAt
            $sections += New-HealthSection -Report $Report
            if (@($Report.Tags).Count -gt 0) {
                $tagRows = ""
                foreach ($tag in $Report.Tags) {
                    $parts = $tag -split "=", 2
                    $tagRows += New-MailFactRow -Label $parts[0] -Value $parts[1] @mono
                }
                $sections += New-MailSection -Label "Tags" -Icon "tags" -Content (New-MailTable $tagRows)
            }
        }
        "Repaired" {
            $pills += New-MailPill -Label "Agent" -Value $Report.AgentVersion
            $pills += New-MailPill -Label "Region" -Value $Report.Location
            $facts += New-MailFactRow -Label "Resource group" -Value $Report.ResourceGroup @mono
            $facts += New-MailFactRow -Label "Run at" -Value $Report.RunAt
            $repairRows = ""
            foreach ($repair in $Report.Repairs) { $repairRows += New-MailCheckRow -State "fixed" -Name $repair.Name -Detail $repair.Detail }
            $sections += New-MailSection -Label "What was repaired" -Icon "restart" -Content (New-MailTable $repairRows)
            $sections += New-HealthSection -Report $Report
        }
        "Failed" {
            if ($null -ne $Report.ConnectExitCode) {
                $pills += New-MailPill -Label "Exit" -Value ([string]$Report.ConnectExitCode)
                $pills += New-MailPill -Label "Attempts" -Value "$($Report.Attempt) of $connectAttemptCount"
            }
            $pills += New-MailPill -Label "Region" -Value $Report.Location
            $facts += New-MailFactRow -Label "Target" -Value $Report.ResourceGroup @mono
            $agentText = "not installed"
            if (-not [string]::IsNullOrWhiteSpace($Report.AgentVersion)) { $agentText = $Report.AgentVersion }
            $facts += New-MailFactRow -Label "Agent" -Value $agentText
            $facts += New-MailFactRow -Label "Run at" -Value $Report.RunAt -Why "Next run within the hour. Another mail only when this changes."
            $errorText = $Report.ErrorText
            if ([string]::IsNullOrWhiteSpace($errorText)) { $errorText = "The run failed without a message. The log has the detail." }
            $sections += New-MailSection -Label "What went wrong" -Icon "security" -Content (New-MailNotice -Title "Error" -Text $errorText) -Padding "2px 26px 14px"
            $sections += New-EndpointSection -Report $Report
            $sections += New-HealthSection -Report $Report
        }
        "Recovered" {
            $pills += New-MailPill -Label "Down for" -Value $Report.PreviousSince
            $pills += New-MailPill -Label "Agent" -Value $Report.AgentVersion
            $facts += New-MailFactRow -Label "Resource group" -Value $Report.ResourceGroup @mono
            $facts += New-MailFactRow -Label "Failing since" -Value $Report.FailingSince -ValueColor $mailPalette.Muted
            $facts += New-MailFactRow -Label "Recovered at" -Value $Report.RunAt
            $sections += New-HealthSection -Report $Report
        }
        "ActionNeeded" {
            if (-not [string]::IsNullOrWhiteSpace($Report.OtherGroup)) {
                $facts += New-MailFactRow -Label "Connected to" -Value $Report.OtherGroup -ValueColor $mailPalette.Warn @mono
                $facts += New-MailFactRow -Label "Subscription" -Value $Report.OtherSubscription -ValueColor $mailPalette.Warn @mono
            }
            $facts += New-MailFactRow -Label "This script wants" -Value $Report.ResourceGroup @mono
            $facts += New-MailFactRow -Label "Subscription" -Value $Report.SubscriptionId @mono
            if (-not [string]::IsNullOrWhiteSpace($Report.LastHeartbeat)) { $facts += New-MailFactRow -Label "Last heartbeat" -Value $Report.LastHeartbeat }
            $action = New-MailNotice -Title "Decision" -Text $Report.ActionText -Tone "warn"
            if (-not [string]::IsNullOrWhiteSpace($Report.ActionCommand)) { $action += New-MailCodeBox $Report.ActionCommand }
            $sections += New-MailSection -Label "What to do" -Icon "info" -Content $action
            $sections += New-HealthSection -Report $Report
        }
    }

    $headline = Get-MailHeadline -Report $Report
    $pills = (New-MailPill -Label "Status" -Value $headline[2] -Tone $headline[3]) + $pills
    $palette = $mailPalette
    $font = $mailFontFamily

    return @"
<div style="display:none;max-height:0;overflow:hidden;mso-hide:all;">$(ConvertTo-MailText (Get-MailPreheader -Report $Report))</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="$($palette.Background)" style="background:$($palette.Background);margin:0;padding:0;">
<tr><td align="center" style="padding:32px 16px;">
<table role="presentation" width="640" cellpadding="0" cellspacing="0" border="0" bgcolor="$($palette.Card)" style="width:640px;max-width:640px;background:$($palette.Card);border:1px solid $($palette.Border);">
  <tr><td style="background:$($palette.Topbar);padding:14px 26px;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
      <td width="24" style="width:24px;padding-right:12px;">$(New-MailIcon -Name "mark" -Size 20)</td>
      <td style="$font;font-size:13px;font-weight:600;color:$($palette.TopbarText);">Azure Arc Onboarding</td>
      <td align="right" style="$font;font-size:11.5px;color:$($palette.TopbarMuted);">$(ConvertTo-MailText $MailOrganization)</td>
    </tr></table>
  </td></tr>
  <tr><td style="padding:26px 26px 0;">
    <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
      <td width="28" valign="top" style="width:28px;padding:2px 14px 0 0;">$(New-MailIcon -Name "arc" -Size 28)</td>
      <td valign="top">
        <div style="$font;font-size:20px;font-weight:600;color:$($palette.Text);line-height:1.3;">$(ConvertTo-MailText $headline[0])</div>
        <div style="$font;font-size:12.5px;color:$($palette.Muted);padding-top:6px;">$($headline[1])</div>
      </td>
    </tr></table>
  </td></tr>
  <tr><td style="padding:20px 26px 0;"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>$pills</tr></table></td></tr>
  <tr><td style="padding:10px 26px 22px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">$facts</table></td></tr>
  <tr><td style="padding:0 26px;"><div style="height:1px;line-height:1px;font-size:0;background:$($palette.Divider);">&nbsp;</div></td></tr>
  $sections
  <tr><td style="padding:20px 26px 24px;background:$($palette.Subtle);border-top:1px solid $($palette.Divider);">
    <div style="$font;font-size:11.5px;color:$($palette.Muted);line-height:1.7;">
      $scriptName.ps1 &middot; $(ConvertTo-MailText $Report.Fqdn) &middot; $(ConvertTo-MailText ([Environment]::UserName))<br>
      Log: <span style="$mailMonoFamily;">$(ConvertTo-MailText $logFile)</span><br>
      <span style="color:$($palette.BorderStrong);">Automated notification &mdash; nobody reads replies to it.</span>
    </div>
  </td></tr>
</table>
</td></tr>
</table>
"@
}

# ===========================[ Mail - transport ]===========================

function Get-MailUsedIcon {
    param([Parameter(Mandatory)][string]$BodyHtml)
    return @($mailIcons.Keys | Where-Object { $BodyHtml -match ("cid:icon-" + [regex]::Escape($_) + '"') })
}

# SmtpClient rather than Send-MailMessage: the cmdlet cannot attach a linked resource,
# so the glyphs would not travel, and on PowerShell 7 it warns on every call.
function Send-ArcMail {
    param(
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$BodyHtml
    )

    $message = $null
    $client  = $null
    try {
        $encoding = New-Object System.Text.UTF8Encoding($false)
        $message  = New-Object System.Net.Mail.MailMessage
        $message.From            = New-Object System.Net.Mail.MailAddress($MailFrom, $MailFromDisplayName)
        $message.Subject         = $Subject
        $message.SubjectEncoding = $encoding
        $message.IsBodyHtml      = $true
        $message.Body            = $BodyHtml
        $message.BodyEncoding    = $encoding
        foreach ($recipient in @($MailTo | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) { $message.To.Add($recipient) }

        $view = [System.Net.Mail.AlternateView]::CreateAlternateViewFromString($BodyHtml, $encoding, "text/html")
        foreach ($name in (Get-MailUsedIcon -BodyHtml $BodyHtml)) {
            $bytes    = [Convert]::FromBase64String(($mailIcons[$name] -join ""))
            $stream   = New-Object System.IO.MemoryStream(, $bytes)
            $resource = New-Object System.Net.Mail.LinkedResource($stream, "image/png")
            $resource.ContentId        = "icon-" + $name
            $resource.TransferEncoding = [System.Net.Mime.TransferEncoding]::Base64
            $view.LinkedResources.Add($resource)
        }
        $message.AlternateViews.Add($view)

        [System.Net.ServicePointManager]::SecurityProtocol =
            [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        $client = New-Object System.Net.Mail.SmtpClient($MailSmartHost, $MailPort)
        $client.EnableSsl = [bool]$MailUseSsl
        $client.Timeout   = 30000
        $client.Send($message)
        Write-Log "Mail '$Subject' -> $($MailTo -join ', ') via ${MailSmartHost}:$MailPort" -Tag "Ok"
    }
    catch {
        # A report that cannot be sent never changes what the run did.
        Write-Log "Mail '$Subject' not sent: $($_.Exception.Message)" -Tag "Warn"
    }
    finally {
        if ($null -ne $message) { $message.Dispose() }
        if ($null -ne $client)  { $client.Dispose() }
    }
}

# Without a smart host the mail lands on disk, with the glyphs inlined so a browser
# shows what a mail client would.
function Save-ArcMailFile {
    param(
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$BodyHtml
    )

    $html = $BodyHtml
    foreach ($name in $mailIcons.Keys) {
        $html = $html.Replace("cid:icon-$name`"", "data:image/png;base64,$($mailIcons[$name] -join '')`"")
    }
    $page = "<!DOCTYPE html><html><head><meta charset=`"utf-8`"><title>" + (ConvertTo-MailText $Subject) +
        "</title></head><body style=`"margin:0;`">" + $html + "</body></html>"
    $path = Join-Path -Path $logFileDirectory -ChildPath ("testmail-" + $Kind + ".html")
    [System.IO.File]::WriteAllText($path, $page, (New-Object System.Text.UTF8Encoding($false)))
    Write-Log "Mail '$Subject' -> '$path'" -Tag "Ok"
}

function Publish-ArcReport {
    param([Parameter(Mandatory)][object]$Report)

    $subject  = Get-MailSubject -Report $Report
    $bodyHtml = Get-MailBody -Report $Report
    if ([string]::IsNullOrWhiteSpace($MailSmartHost)) {
        if ($TestMail) { Save-ArcMailFile -Kind $Report.Kind -Subject $subject -BodyHtml $bodyHtml }
        else { Write-Log "No MailSmartHost - '$subject' not sent" -Tag "Info" }
        return
    }
    Send-ArcMail -Subject $subject -BodyHtml $bodyHtml
}

# ===========================[ Test mail ]===========================

function New-SampleReport {
    param([Parameter(Mandatory)][string]$Kind)

    $report = New-ArcReport
    $report.Kind         = $Kind
    $report.Fqdn         = Get-ComputerFqdn
    $report.ResourceName = $env:COMPUTERNAME
    $report.AgentVersion = "1.0 (sample)"
    if ([string]::IsNullOrWhiteSpace($report.ResourceGroup)) { $report.ResourceGroup = "rg-arc-servers" }
    if ([string]::IsNullOrWhiteSpace($report.Location)) { $report.Location = "westeurope" }
    if ([string]::IsNullOrWhiteSpace($report.SubscriptionId)) { $report.SubscriptionId = "00000000-0000-0000-0000-000000000000" }

    $isHealthy = @("Onboarded", "Repaired", "Recovered") -contains $Kind
    if ($isHealthy) {
        Set-HealthCheck -Report $report -Name "Agent installed" -State "ok" -Detail "1.0 (sample) - already present"
        Set-HealthCheck -Report $report -Name "Connected" -State "ok" -Detail $report.ResourceGroup
        Set-HealthCheck -Report $report -Name "Agent status" -State "ok" -Detail "Connected, heartbeat (sample)"
        Set-HealthCheck -Report $report -Name "Services" -State "ok" -Detail "himds, GCArcService, ExtensionService running"
        Set-HealthCheck -Report $report -Name "Managed identity" -State "ok" -Detail "token issued by Azure"
    }

    switch ($Kind) {
        "Onboarded" { $report.Attempt = 1; $report.ConnectedThisRun = $true }
        "Repaired" {
            $report.Reason  = "service started: himds"
            $report.Repairs = @([pscustomobject]@{ Name = "Service started"; Detail = "himds" })
            Set-HealthCheck -Report $report -Name "Services" -State "fixed" -Detail "himds, GCArcService, ExtensionService running"
        }
        "Recovered" { $report.PreviousSince = "26 h"; $report.FailingSince = "(sample)" }
        "Failed" {
            $report.Reason          = "2 Arc endpoint(s) unreachable"
            $report.ConnectExitCode = 42
            $report.Attempt         = $connectAttemptCount
            $report.ErrorText       = "azcmagent connect returned exit 42. Sample text - a real failure shows azcmagent's own last line here."
            $report.Endpoints = @(
                [pscustomobject]@{ Ok = $false; Name = "gbl.his.arc.azure.com"; Detail = "unreachable" },
                [pscustomobject]@{ Ok = $false; Name = "$($report.Location).his.arc.azure.com"; Detail = "unreachable" },
                [pscustomobject]@{ Ok = $true;  Name = "login.microsoftonline.com"; Detail = "reachable" }
            )
            Set-HealthCheck -Report $report -Name "Agent installed" -State "ok" -Detail "1.0 (sample) - already present"
            Set-HealthCheck -Report $report -Name "Connected" -State "fail" -Detail "exit 42"
        }
        "ActionNeeded" {
            $report.Reason            = "connected to rg-other-servers"
            $report.OtherGroup        = "rg-other-servers"
            $report.OtherSubscription = "11111111-1111-1111-1111-111111111111"
            $report.ActionText        = "Sample. This script never moves a machine. Disconnecting deletes the Azure resource and every extension, policy assignment and machine configuration on it. To move it, run on $($report.ComputerName):"
            $report.ActionCommand     = "azcmagent disconnect"
            Set-HealthCheck -Report $report -Name "Agent installed" -State "ok" -Detail "1.0 (sample) - already present"
            Set-HealthCheck -Report $report -Name "Connected" -State "warn" -Detail "rg-other-servers - not this design"
        }
    }
    Complete-HealthCheck -Report $report
    return $report
}

function Send-ArcTestMail {
    foreach ($kind in @("Onboarded", "Repaired", "Failed", "Recovered", "ActionNeeded")) {
        Publish-ArcReport -Report (New-SampleReport -Kind $kind)
    }
}

# ===========================[ Main ]===========================

Write-Log "==================== Start ====================" -Tag "Start"
Write-Log "$env:COMPUTERNAME | $([Environment]::UserName) | $scriptName" -Tag "Info"

Remove-ExpiredLogFile

if ($TestMail) {
    Send-ArcTestMail
    Complete-Script -ExitCode $exitHealthy
}

if (-not (Test-Elevation)) {
    Write-Log "Not elevated - run as SYSTEM from the scheduled task, or from an elevated console" -Tag "Error"
    Complete-Script -ExitCode $exitFailed
}

try {
    Protect-WorkDirectory
}
catch {
    Write-Log "Could not close '$workDirectory' to SYSTEM and Administrators - nothing downloaded or connected: $($_.Exception.Message)" -Tag "Error"
    Complete-Script -ExitCode $exitFailed
}

Remove-StaleSecretFile
Test-ScriptReadAccess

if (Test-AzureVirtualMachine) {
    Write-Log "This is an Azure VM - Azure Arc does not onboard those" -Tag "Info"
    Complete-Script -ExitCode $exitSkipped
}

if (Test-InstallerBusy) {
    Write-Log "Windows Installer is busy - nothing checked this run" -Tag "Info"
    Complete-Script -ExitCode $exitHealthy
}

$report = New-ArcReport
$report.Fqdn = Get-ComputerFqdn
$faults = @(Get-ConfigurationFault)

if ($faults.Count -gt 0) {
    foreach ($fault in $faults) { Write-Log "Configuration: $fault" -Tag "Error" }
    $report.Reason    = "configuration incomplete"
    $report.ErrorText = "The parameter defaults in the script are incomplete: " + ($faults -join "; ") + "."
}
else {
    try {
        Invoke-ArcOnboarding -Report $report
    }
    catch {
        $report.Outcome = "Failed"
        if ([string]::IsNullOrWhiteSpace($report.Reason)) { $report.Reason = "run failed" }
        $report.ErrorText = $_.Exception.Message
        Write-Log "Run failed: $($_.Exception.Message)" -Tag "Error"
    }
}
Complete-HealthCheck -Report $report

$previous = Get-PreviousState
$report.Kind = Get-MailKind -Report $report -Previous $previous
if (($report.Kind -eq "Recovered") -and ($null -ne $previous)) {
    $report.FailingSince  = [string]$previous.since
    $report.PreviousSince = Format-Duration -Since $report.FailingSince
}
Save-RunState -Report $report -Previous $previous

if ([string]::IsNullOrWhiteSpace($report.Kind)) {
    Write-Log "State '$($report.Outcome)' unchanged - no mail" -Tag "Info"
}
else {
    Publish-ArcReport -Report $report
}

switch ($report.Outcome) {
    "Healthy"      { Write-Log "Healthy - $($report.ResourceName) in $($report.ResourceGroup)" -Tag "Ok"; Complete-Script -ExitCode $exitHealthy }
    "ActionNeeded" { Write-Log "Action needed - $($report.Reason)" -Tag "Warn"; Complete-Script -ExitCode $exitActionNeeded }
    default        { Write-Log "Failed - $($report.Reason)" -Tag "Error"; Complete-Script -ExitCode $exitFailed }
}
