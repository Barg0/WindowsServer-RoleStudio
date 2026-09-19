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

# =====================================================================================
# Kaido Dark, the studio's default theme, as the console's palette.
#
# Every hex is lifted verbatim from FAMILIES[kaido].dark in the studio HTML - with one
# stated exception, `yellow`, which the studio has no counterpart for and which is
# documented where it is defined. A run and the studio that designed it are otherwise
# the same colours rather than two guesses at them.
# Truecolor where the console does virtual terminal processing, the nearest named colour
# where it does not.
#
# It lives in THIS file rather than in ConsoleUi.ps1 because Logging.ps1 is the first
# part the entry script dot-sources and Write-Log is called while the others are still
# loading: a palette defined in the last part would be undefined for the first lines of
# every run. Everything that reaches the screen goes through Write-Studio, which is what
# makes the theme one table instead of ninety scattered -ForegroundColor arguments.
# =====================================================================================
$script:menuConsoleType = $null
$script:menuVtEnabled = $false

$script:studioPalette = @{
    bg       = "#16171e"; elevated  = "#1d1f28"; subtle = "#1a1c24"; hover = "#262a38"
    fg       = "#d7dbec"; muted     = "#8b93ad"
    border   = "#2b2f3d"; borderStrong = "#3d4356"; divider = "#23262f"
    accent   = "#7aa2f7"; accentHover = "#93b3fa"; accentSoft = "#22304f"; accentFg = "#11141c"
    success  = "#9ece6a"; danger    = "#f7768e"; warn = "#e0af68"
    bandHost = "#7dcfff"; bandIdent = "#bb9af7"; bandWork = "#9ece6a"; bandDeploy = "#ff9e64"
    # THE ONE VALUE IN THIS TABLE THAT IS NOT THE STUDIO'S.
    #
    # Kaido has exactly two warm colours - warn #e0af68, a gold, and deploy #ff9e64, an
    # orange - and a log needs three warm steps, because `info` is the commonest tag
    # there is and it has to sit below `warn` without either of them reading as the
    # other. Mapping info onto the gold put the two one step apart and the pair read as
    # orange-on-orange; mapping info onto the plain text colour was tried in an earlier
    # build and the log came out undifferentiated.
    #
    # So this is a console-only colour, chosen to be the yellow the gold is not, and it
    # is written down here rather than being quietly one more entry: everything else in
    # this table can be checked against FAMILIES[kaido].dark in the studio HTML and this
    # cannot. It has no studio counterpart and needs none - the studio has no log.
    #
    # Pick it by HUE, not by eye. The first attempt at this value was #f0d080, which
    # looks yellow written down and sits at 43 degrees - seven degrees off Kaido's gold
    # and still inside the amber band, so the log read exactly as orange as before.
    # 30 degrees is orange, 45 gold, 60 pure yellow; this is 56, which is far enough
    # from warn's 35 to separate at a glance and short of the acid-lemon end.
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
    # Yellow against warn's DarkYellow, which is the pair the sixteen-colour version of
    # this log used for exactly the same reason - the truecolor palette had to grow a
    # third warm step to say what ConsoleColor could already say with two.
    yellow   = "Yellow"
}

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

function Write-Studio {
    param(
        [AllowEmptyString()][string]$Text = "",
        [string]$Key = "fg",
        [switch]$NoNewline
    )

    $hex = [string]$script:studioPalette[$Key]
    if ([string]::IsNullOrWhiteSpace($hex)) { $hex = [string]$script:studioPalette["fg"] }

    # Cheap after the first call - Enable-MenuVtProcessing caches - and it has to be
    # here rather than only in the menu header, because log lines print long before any
    # header does.
    Enable-MenuVtProcessing
    if (Test-MenuAnsiSupported) {
        $rgb = ConvertFrom-HexColor -Hex $hex
        $escape = [char]27
        Write-Host ("{0}[38;2;{1};{2};{3}m{4}{0}[0m" -f $escape, $rgb[0], $rgb[1], $rgb[2], $Text) -NoNewline:$NoNewline
        return
    }

    $named = [string]$script:studioFallback[$Key]
    if ([string]::IsNullOrWhiteSpace($named)) { $named = "Gray" }
    Write-Host $Text -NoNewline:$NoNewline -ForegroundColor $named
}

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

    # Palette keys, not ConsoleColor names - see Write-Studio above. The pairing this
    # has to preserve is info BELOW warn: info is the commonest tag in any run, warn is
    # the one that wants to be noticed, and the two are adjacent everywhere on screen.
    # Kaido's own two warm colours are one step apart, which read as orange-on-orange,
    # so the palette carries a third - `yellow`, the only value in it that is not the
    # studio's. info takes it and warn keeps Kaido's gold.
    $color = switch ($shown) {
        "start" { "accent" }
        "get"   { "bandHost" }
        "run"   { "bandIdent" }
        "info"  { "yellow" }
        "warn"  { "warn" }
        "o.k."  { "success" }
        "error" { "danger" }
        "debug" { "muted" }
        "end"   { "accent" }
        default { "fg" }
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

    # The timestamp is secondary information on every line, so it takes the muted key
    # rather than the host's default foreground - the one place this port changes what
    # a line looks like rather than only what it is drawn with.
    Write-Studio -Text "$timestamp " -Key "muted" -NoNewline
    Write-Studio -Text "[ " -Key "muted" -NoNewline
    Write-Studio -Text "$rawTag" -Key $color -NoNewline
    Write-Studio -Text " ] " -Key "muted" -NoNewline
    Write-Studio -Text "$scope$Message" -Key "fg"
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
