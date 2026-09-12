# Logging and the single exit path.
#
# Dot-sourced by Configure-ServerRoles.ps1 - not runnable on its own. Everything
# here lands in that script's scope, so $script: variables and functions are shared
# with every other part. Use $scriptRootPath, never $PSScriptRoot: inside this file
# $PSScriptRoot is the pwsh folder, not the folder the run was started from.

# ---------------------------[ Run Timestamp ]---------------------------
# Read by Complete-Script for the runtime line, so it is stamped as this part loads -
# which is the first thing the entry script does.
$scriptStartTime = Get-Date

# ---------------------------[ Logging Setup ]---------------------------
$log           = $true
$logDebug      = $false
$logGet        = $true
$logRun        = $true
$enableLogFile = $true

# Set while a role provider is on the stack, so every line it writes says which role
# wrote it - and, since the per-role file below keys off this, decides where it lands.
$script:currentRole = ""

# One file per run, named for the minute it started, under the folder the entry script
# was started from - $scriptRootPath, set there before this part loads.
$logFileName      = (Get-Date -Format "yyyyMMdd-HHmm") + ".log"
$script:logRoot   = Join-Path -Path $scriptRootPath -ChildPath "logs"
$logFileDirectory = Join-Path -Path $script:logRoot -ChildPath "run"
$logFile          = Join-Path -Path $logFileDirectory -ChildPath $logFileName

if ($enableLogFile -and -not (Test-Path -Path $logFileDirectory)) {
    New-Item -ItemType Directory -Path $logFileDirectory -Force | Out-Null
}

# ---------------------------[ One folder per role ]---------------------------
# Every line still goes to the run log - that file is the whole story of one run, in
# order, and a run that touches three roles is one story. A line written while a role is
# on the stack ALSO goes to that role's own folder, which is what somebody actually opens
# six months later: "what did this script last do to the file server" is a question about
# a role, not about a run, and the answer used to be a grep through a folder of runs.
#
# The folder name is stated rather than derived from the role Id - 'AD-Certificate' would
# give 'ad-certificate', and the folder people look for is 'adcs'. An Id with no entry
# here falls back to its own name, lowercased and stripped, so a new role logs somewhere
# sensible on the day it is added and gets a proper name when somebody adds one line.
$script:logRoleFolder = @{
    "Hyper-V"                       = "hv"
    "AD-Domain-Services"            = "adds"
    "DNS"                           = "dns"
    "AD-Certificate"                = "adcs"
    "File-Services"                 = "files"
    "Print-Services"                = "print"
    "DHCP"                          = "dhcp"
    "WindowsAdminCenter"            = "wac"
    "AzureArc"                      = "arc"
    "EntraPrivateNetworkConnector"  = "connector"
    "Remote-Desktop-Services"       = "rds"
    "Exchange-Server"               = "exchange"
    "AcmeRenewal"                   = "acme"
}

# Created on first use rather than up front: a run that never reaches a role should not
# leave an empty folder suggesting it did.
$script:logRoleFileCache = @{}

# The folder itself, for the run's other artefacts: an installer's own log, an MSI
# verbose log. Those used to land beside the run log, which meant the Exchange MSI logs
# and the Arc installer log shared one folder with every run of every role.
function Get-LogRoleDirectory {
    param([string]$Role = "")

    $name = $Role
    if ([string]::IsNullOrWhiteSpace($name)) { $name = $script:currentRole }
    if ([string]::IsNullOrWhiteSpace($name)) { return $logFileDirectory }

    $file = Get-LogRoleFile -Role $name
    if ([string]::IsNullOrWhiteSpace($file)) { return $logFileDirectory }
    return (Split-Path -Path $file -Parent)
}

function Get-LogRoleFile {
    param([string]$Role)

    if ([string]::IsNullOrWhiteSpace($Role)) { return "" }
    if ($script:logRoleFileCache.ContainsKey($Role)) { return $script:logRoleFileCache[$Role] }

    $folder = $script:logRoleFolder[$Role]
    if ([string]::IsNullOrWhiteSpace($folder)) {
        $folder = ($Role -replace "[^A-Za-z0-9]", "").ToLowerInvariant()
    }
    if ([string]::IsNullOrWhiteSpace($folder)) { return "" }

    $directory = Join-Path -Path $script:logRoot -ChildPath $folder
    try {
        if (-not (Test-Path -LiteralPath $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
    }
    catch {
        # Same rule as everywhere else here: logging never blocks the run. A folder that
        # cannot be created costs the per-role copy, not the line.
        $script:logRoleFileCache[$Role] = ""
        return ""
    }

    $path = Join-Path -Path $directory -ChildPath $logFileName
    $script:logRoleFileCache[$Role] = $path
    return $path
}

# ---------------------------[ Log Retention ]---------------------------
# One file per run was a folder that grew by a handful of files a year while every run
# was somebody starting the script. The registered tasks changed that - the nightly ones
# add one a day each, and the Remote Desktop portal watchdog adds one an hour - so a
# server left alone for a year would hold nine thousand log files, and the folder that is
# meant to be the first place you look becomes the last.
#
# COUNT, not age. It was ninety days, then fourteen, and a date cutoff answers the wrong
# question: what somebody wants when they open this folder is the last few runs, and on a
# server nobody has touched for a month an age rule leaves nothing at all - which is the
# one case where the last run is the run they came to read. Fourteen files per folder is
# also something anybody can check by looking - fifteen while a run is in progress,
# because the file this run is about to write is not one of the fourteen it keeps.
#
# Narrow on purpose: only files whose name is the timestamp pattern this script writes,
# never the one this run is about to append to, and counted PER FOLDER - the per-role
# folders fill up at their own rates, and a busy role must not evict a quiet one. It runs
# as this part loads, before anything has logged, so a run costs one directory read.
$logRetentionCount = 14

if ($enableLogFile -and (Test-Path -LiteralPath $script:logRoot)) {
    try {
        Get-ChildItem -LiteralPath $script:logRoot -Filter "*.log" -File -Recurse -ErrorAction Stop |
            Where-Object { ($_.Name -match "^\d{8}-\d{4}\.log$") -and ($_.Name -ne $logFileName) } |
            Group-Object -Property DirectoryName |
            ForEach-Object {
                $_.Group |
                    Sort-Object -Property LastWriteTime -Descending |
                    Select-Object -Skip $logRetentionCount |
                    Remove-Item -Force -ErrorAction SilentlyContinue
            }
    }
    catch {
        # Same rule as the write below: logging must never block script execution, and
        # tidying the log folder is the least important thing this script does.
    }
}

# ---------------------------[ Logging Function ]---------------------------
function Write-Log {
    [CmdletBinding()]
    param (
        [string]$Message,
        [string]$Tag = "Info"
    )

    if (-not $log) { return }

    if (($Tag -eq "Debug") -and (-not $logDebug)) { return }
    if (($Tag -eq "Get")   -and (-not $logGet))   { return }
    if (($Tag -eq "Run")   -and (-not $logRun))   { return }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Lower case, and five characters wide - 'error', 'debug' and 'start' are the longest
    # tags there are, so the message column starts in the same place on every line and the
    # eye reads down the text rather than down a ragged edge. 'ok' renders as 'o.k.' and
    # 'warn' is the word in full: the two that used to be 'Success' and 'Warning' were what
    # forced a seven-wide column, and neither said anything the short form does not.
    #
    # Both old spellings still map, on purpose. Two thousand call sites were rewritten
    # mechanically and a missed one has to keep working rather than render as an error.
    $tagMap = @{
        "start"   = "start"
        "get"     = "get"
        "run"     = "run"
        "info"    = "info"
        "warn"    = "warn"
        "warning" = "warn"
        "ok"      = "o.k."
        "success" = "o.k."
        "error"   = "error"
        "debug"   = "debug"
        "end"     = "end"
    }

    $key = $Tag.Trim().ToLowerInvariant()
    # A tag outside the map renders as an error rather than being dropped, so a typo is
    # loud instead of invisible.
    $shown = $tagMap[$key]
    if ([string]::IsNullOrWhiteSpace($shown)) { $shown = "error" }
    $rawTag = $shown.PadRight(5)

    $color = switch ($shown) {
        "start" { "Cyan" }
        "get"   { "Blue" }
        "run"   { "Magenta" }
        "info"  { "Yellow" }
        # There is no orange in ConsoleColor. DarkYellow is ANSI 3, which every current
        # scheme renders orange-brown (Campbell #C19C00), against info's Yellow = ANSI 11,
        # the pale bright one - so warn reads as the louder of the two, not the dimmer.
        "warn"  { "DarkYellow" }
        "o.k."  { "Green" }
        "error" { "Red" }
        "debug" { "DarkGray" }
        "end"   { "Cyan" }
        default { "White" }
    }

    # Square brackets, like the tag beside it. Round ones were a second punctuation style
    # in a line that already had one.
    $scope = ""
    if (-not [string]::IsNullOrWhiteSpace($script:currentRole)) {
        $scope = "[" + $script:currentRole + "] "
    }

    $logMessage = "$timestamp [ $rawTag ] $scope$Message"

    if ($enableLogFile) {
        # -ErrorAction Stop is what makes the catch below a catch. Without it Add-Content
        # reports a locked file as a NON-TERMINATING error, which walks straight past
        # try/catch and prints the whole red block to the console - four of them landed in
        # the middle of a clean bench run on 2026-08-18, from nothing worse than somebody
        # tailing the log in another window. The catch was there and had never run.
        #
        # And a lock on a log file is transient by nature, so it is retried rather than
        # simply swallowed: the old shape would have dropped the line silently once the
        # error was caught, which is a worse failure than the noise it replaced. Three
        # attempts, briefly spaced; after that the line is lost and the run carries on,
        # because logging must never block execution.
        # The run log always, the role's own file as well when a role is on the stack.
        $targets = @($logFile)
        $roleFile = Get-LogRoleFile -Role $script:currentRole
        if (-not [string]::IsNullOrWhiteSpace($roleFile)) { $targets += $roleFile }

        foreach ($target in $targets) {
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
    }

    Write-Host "$timestamp " -NoNewline
    Write-Host "[ " -NoNewline -ForegroundColor White
    Write-Host "$rawTag" -NoNewline -ForegroundColor $color
    Write-Host " ] " -NoNewline -ForegroundColor White
    Write-Host "$scope$Message"
}

# ---------------------------[ Error detail ]---------------------------
# $_.Exception.Message is the wrong place to read a failed cmdlet from. A command that
# reports through Write-Error raises a WriteErrorException, and when the message rides on
# the record rather than on the exception, .NET renders the exception as "Exception of
# type 'Microsoft.PowerShell.Commands.WriteErrorException' was thrown" - a line naming
# neither the command, the cause, nor the failure. Everything that says something is on
# the *record*: its own detail message, the category (which carries the activity, so the
# command names itself), and the id the command stamped on it.
function Get-ErrorDetailText {
    param([object]$ErrorRecord)

    if ($null -eq $ErrorRecord) { return "no error record" }

    $parts   = @()
    $message = ""

    try {
        if ($null -ne $ErrorRecord.ErrorDetails) { $message = [string]$ErrorRecord.ErrorDetails.Message }
    }
    catch { $message = "" }

    if ([string]::IsNullOrWhiteSpace($message)) {
        try { $message = [string]$ErrorRecord.Exception.Message }
        catch { $message = "" }
    }

    # The placeholder .NET renders for an exception carrying no message of its own. It is
    # worse than nothing, because it looks like a diagnosis.
    if ($message -match "^Exception of type '.+' was thrown\.$") { $message = "" }
    if (-not [string]::IsNullOrWhiteSpace($message)) { $parts += $message.Trim() }

    try {
        if ($null -ne $ErrorRecord.CategoryInfo) {
            $category = [string]$ErrorRecord.CategoryInfo.ToString()
            if (-not [string]::IsNullOrWhiteSpace($category)) { $parts += "category $category" }
        }
    }
    catch { }

    try {
        $id = [string]$ErrorRecord.FullyQualifiedErrorId
        if (-not [string]::IsNullOrWhiteSpace($id)) { $parts += "id $id" }
    }
    catch { }

    if ($parts.Count -eq 0) { return "the error carried no detail at all" }
    return ($parts -join " | ")
}

# Every record a command wrote, not only the one that stopped it. Cmdlets that report
# several failures and keep going - Register-WACHttpSys does exactly that - put the
# useful one in the middle of the list.
function Write-ErrorRecordDetail {
    param(
        [object]$ErrorRecord,
        [string]$Prefix = "",
        [string]$Tag = "Error"
    )

    $label = ""
    if (-not [string]::IsNullOrWhiteSpace($Prefix)) { $label = $Prefix + ": " }

    foreach ($record in @($ErrorRecord)) {
        if ($null -eq $record) { continue }
        Write-Log ($label + (Get-ErrorDetailText -ErrorRecord $record)) -Tag $Tag
    }
}

# ---------------------------[ Exit Function ]---------------------------
function Complete-Script {
    param([int]$ExitCode)

    $script:currentRole = ""

    $scriptEndTime = Get-Date
    $duration      = $scriptEndTime - $scriptStartTime

    Write-Log "Runtime $($duration.ToString('hh\:mm\:ss\.ff'))" -Tag "Info"
    Write-Log "Exit $ExitCode" -Tag "Info"
    Write-Log "==================== End ====================" -Tag "End"

    exit $ExitCode
}
