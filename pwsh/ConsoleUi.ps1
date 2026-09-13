# The review screen: logo, header, per-role summaries, confirmation.
#
# Dot-sourced by Configure-ServerRoles.ps1 - not runnable on its own. Everything
# here lands in that script's scope, so $script: variables and functions are shared
# with every other part. Use $scriptRootPath, never $PSScriptRoot: inside this file
# $PSScriptRoot is the pwsh folder, not the folder the run was started from.

# ===========================[ Console UI ]===========================
# Same shape as the New-Vhdx builder in the HyperV-Scripts repo: a fastfetch-style
# header with the studio's own mark - no vendor logo is drawn anywhere - then the
# then continue or cancel. It is a review screen, not a wizard - the design already
# happened in the studio, and config.json is the answer.

# The studio mark as truecolor pixel art: three role bars of descending length
# docking into the server unit on the right - the same mark the HTML studio draws as
# its brand icon and its favicon. Stored as a plain ASCII mask ('#' paints a cell,
# '.' leaves it bare) and coloured at render time, because the colour is not a
# constant. See Get-MarkAccent below: the mark is one flat accent, and the studio's
# default accent is a blue that lands on the default PowerShell 5.1 console
# background - #012456 - at a perfectly legal 6:1 contrast and still reads as
# background bleed, because the two share a hue. The hue is therefore chosen against
# the console's real background rather than baked in.
#
# 22x10 whole cells rather than the half-block folding the Microsoft mark used,
# because this geometry lands on cell boundaries anyway: bars two cells tall,
# one-cell gaps, a unit eight cells tall. A console cell is roughly 1:2.2, so 22x10
# cells is the square mark of the studio rather than a stretched one.
#
# Every painted cell is a full block (U+2588) written with a **foreground** colour
# only. Never a background fill: that paints the terminal's default foreground into
# the cell as well and draws a grey seam through every gap in the mark.
#
# Ten lines of 22, padded to $script:serverLogoAnsiWidth by Show-MenuHeader.
$script:serverLogoMask = @(
    "......................",
    "..##########..######..",
    "..##########..######..",
    "..............######..",
    "....########..######..",
    "....########..######..",
    "..............######..",
    ".......#####..######..",
    ".......#####..######..",
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
    Write-Host $paddedLabel -NoNewline -ForegroundColor DarkCyan
    Write-Host ": " -NoNewline -ForegroundColor DarkCyan
    Write-Host $Value -ForegroundColor Gray
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
            if ($row.Accent) { Write-Host $row.Value -ForegroundColor White }
            else { Write-FastfetchInfoRow -Label $row.Label -Value $row.Value -LabelWidth $labelWidth }
        }
        else {
            Write-Host ""
        }
    }

    Write-Host ""
    Write-Host ("  " + ("-" * 62)) -ForegroundColor DarkGray
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
            Write-Host "  $Heading" -ForegroundColor White
            if (-not [string]::IsNullOrWhiteSpace($HeadingHint)) {
                Write-Host "  $HeadingHint" -ForegroundColor DarkGray
            }
            Write-Host ""
        }

        for ($i = 0; $i -lt $Items.Count; $i++) {
            $item  = $Items[$i]
            $label = if ($item.Label) { [string]$item.Label } else { [string]$item }

            if ($i -eq $index) {
                Write-Host "  > " -NoNewline -ForegroundColor Cyan
                Write-Host $label -ForegroundColor White
            }
            else {
                Write-Host "    " -NoNewline
                Write-Host $label -ForegroundColor Gray
            }
            foreach ($line in @(Get-MenuDetailLine -Item $item)) {
                Write-Host ("      " + $line) -ForegroundColor DarkGray
            }
        }

        Write-Host ""
        Write-Host ("  " + ("-" * 62)) -ForegroundColor DarkGray
        if ($useRawUi) {
            Write-Host "  Up/Down move   Enter select   Esc/Q cancel" -ForegroundColor DarkGray
        }
        else {
            Write-Host "  Enter number + Enter   (Q to cancel)" -ForegroundColor DarkGray
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

# The same menu, for the questions whose answer is a set rather than one thing - which
# adapters go into the team, which disks go into the pool. Space ticks, Enter confirms.
#
# Asking those one at a time through Show-Menu worked, but it read badly: the list
# reshuffled after every pick and the only way to see what was already chosen was the
# label of the "Done" row. A tick list shows the whole answer at once, which is the point
# when the answer is "these three of the five".
#
# Returns the ids that are ticked - an empty array when nothing is - or $null when the
# operator cancelled, and those two are deliberately different answers.
function Show-MultiSelectMenu {
    param(
        [string]$Title,
        [object[]]$Items,
        [hashtable]$StatusLines,
        [string]$Subtitle,
        [string]$Heading,
        [string]$HeadingHint,
        [scriptblock]$PreItems
    )

    if (-not $Items -or $Items.Count -eq 0) {
        throw "Show-MultiSelectMenu requires at least one item."
    }

    $selected = New-Object System.Collections.Generic.List[string]
    foreach ($item in $Items) {
        if ($item.PSObject.Properties.Name -contains "Selected" -and [bool]$item.Selected) {
            $selected.Add([string]$item.Id) | Out-Null
        }
    }

    $index = 0
    $useRawUi = Test-MenuHostSupported

    while ($true) {
        Show-MenuHeader -Title $Title -StatusLines $StatusLines -Subtitle $Subtitle

        if ($PreItems) { & $PreItems }

        if (-not [string]::IsNullOrWhiteSpace($Heading)) {
            Write-Host "  $Heading" -ForegroundColor White
            if (-not [string]::IsNullOrWhiteSpace($HeadingHint)) {
                Write-Host "  $HeadingHint" -ForegroundColor DarkGray
            }
            Write-Host ""
        }

        for ($i = 0; $i -lt $Items.Count; $i++) {
            $item = $Items[$i]
            $label = if ($item.Label) { [string]$item.Label } else { [string]$item }
            $mark = if ($selected.Contains([string]$item.Id)) { "[x] " } else { "[ ] " }
            $number = ""
            if (-not $useRawUi) { $number = "{0,2}. " -f ($i + 1) }

            if ($i -eq $index) {
                Write-Host "  > " -NoNewline -ForegroundColor Cyan
                Write-Host ($number + $mark + $label) -ForegroundColor White
            }
            else {
                Write-Host "    " -NoNewline
                if ($selected.Contains([string]$item.Id)) {
                    Write-Host ($number + $mark + $label) -ForegroundColor Cyan
                }
                else {
                    Write-Host ($number + $mark + $label) -ForegroundColor Gray
                }
            }
            # Indented past the tick box and the number, so the detail hangs under the
            # label rather than under the margin.
            foreach ($line in @(Get-MenuDetailLine -Item $item)) {
                Write-Host ((" " * (4 + $number.Length + $mark.Length)) + $line) -ForegroundColor DarkGray
            }
        }

        Write-Host ""
        Write-Host ("  " + ("-" * 62)) -ForegroundColor DarkGray
        Write-Host ("  {0} of {1} selected" -f $selected.Count, $Items.Count) -ForegroundColor DarkGray
        if ($useRawUi) {
            Write-Host "  Up/Down move   Space tick   A all/none   Enter confirm   Esc/Q cancel" -ForegroundColor DarkGray
        }
        else {
            Write-Host "  Numbers to tick (1,3,4)   A all/none   Enter confirm   Q cancel" -ForegroundColor DarkGray
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
            if ($virtualKey -eq 32) {
                $id = [string]$Items[$index].Id
                if ($selected.Contains($id)) { $null = $selected.Remove($id) } else { $selected.Add($id) | Out-Null }
                continue
            }
            if ($charKey -eq "a" -or $charKey -eq "A") {
                if ($selected.Count -eq $Items.Count) { $selected.Clear() }
                else {
                    $selected.Clear()
                    foreach ($item in $Items) { $selected.Add([string]$item.Id) | Out-Null }
                }
                continue
            }
            if ($virtualKey -eq 13) { return @($selected.ToArray()) }
            if ($virtualKey -eq 27 -or $charKey -eq "q" -or $charKey -eq "Q") { return $null }
        }
        else {
            $raw = Read-Host "Tick"
            if ([string]::IsNullOrWhiteSpace($raw)) { return @($selected.ToArray()) }
            if ($raw -match "^[Qq]$") { return $null }
            if ($raw -match "^[Aa]$") {
                if ($selected.Count -eq $Items.Count) { $selected.Clear() }
                else {
                    $selected.Clear()
                    foreach ($item in $Items) { $selected.Add([string]$item.Id) | Out-Null }
                }
                continue
            }
            foreach ($part in ($raw -split "[,\s]+")) {
                if ($part -notmatch "^\d+$") { continue }
                $num = [int]$part
                if (($num -lt 1) -or ($num -gt $Items.Count)) { continue }
                $id = [string]$Items[$num - 1].Id
                if ($selected.Contains($id)) { $null = $selected.Remove($id) } else { $selected.Add($id) | Out-Null }
            }
        }
    }
}


# ---------------------------[ Run summary ]---------------------------
# Everything config.json is about to do to this machine, on one screen, before any
# of it happens. It reads the same document the providers read, so what is shown is
# what will run rather than a second description of it that can drift.
function Get-SummaryPeriod {
    param(
        [object]$InputObject,
        [Parameter(Mandatory)][string]$PeriodName,
        [Parameter(Mandatory)][string]$UnitsName,
        [string]$Default = "not set"
    )

    $period = [string](Get-ConfigValue -InputObject $InputObject -Name $PeriodName -Default "")
    $units  = [string](Get-ConfigValue -InputObject $InputObject -Name $UnitsName -Default "")
    if ([string]::IsNullOrWhiteSpace($period) -or [string]::IsNullOrWhiteSpace($units)) { return $Default }
    return "$units $period"
}

function Write-SummarySection {
    param([Parameter(Mandatory)][string]$Title)

    Write-Host ""
    Write-Host "  $Title" -ForegroundColor White
}

function Show-AddsSummary {
    param([object]$ActiveDirectory)

    $mode = [string](Get-ConfigValue -InputObject $ActiveDirectory -Name "mode" -Default "newForest")
    Write-SummarySection -Title "Active Directory Domain Services"

    if ($mode -eq "newForest") {
        $forest = Get-ConfigValue -InputObject $ActiveDirectory -Name "newForest"
        Write-FastfetchInfoRow -Label "operation" -Value "New forest" -LabelWidth 24 -IndentWidth 2
        Write-FastfetchInfoRow -Label "domain" -Value ([string](Get-ConfigValue -InputObject $forest -Name "domainName" -Default "?")) -LabelWidth 24 -IndentWidth 2
        Write-FastfetchInfoRow -Label "netbios" -Value ([string](Get-ConfigValue -InputObject $forest -Name "domainNetbiosName" -Default "?")) -LabelWidth 24 -IndentWidth 2
        Write-FastfetchInfoRow -Label "forest / domain level" -Value ("{0} / {1}" -f (Get-ConfigValue -InputObject $forest -Name "forestMode" -Default "?"), (Get-ConfigValue -InputObject $forest -Name "domainMode" -Default "?")) -LabelWidth 24 -IndentWidth 2
    }
    else {
        $join = Get-ConfigValue -InputObject $ActiveDirectory -Name "joinExisting"
        Write-FastfetchInfoRow -Label "operation" -Value ([string](Get-ConfigValue -InputObject $join -Name "operation" -Default "addDomainController")) -LabelWidth 24 -IndentWidth 2
        $domain = [string](Get-ConfigValue -InputObject $join -Name "domainName" -Default "")
        if ([string]::IsNullOrWhiteSpace($domain)) {
            $domain = "{0} below {1}" -f (Get-ConfigValue -InputObject $join -Name "newDomainName" -Default "?"), (Get-ConfigValue -InputObject $join -Name "parentDomainName" -Default "?")
        }
        Write-FastfetchInfoRow -Label "domain" -Value $domain -LabelWidth 24 -IndentWidth 2
        Write-FastfetchInfoRow -Label "credential" -Value ([string](Get-ConfigValue -InputObject $join -Name "credentialUser" -Default "prompted")) -LabelWidth 24 -IndentWidth 2
    }

    $site = Get-ConfigValue -InputObject $ActiveDirectory -Name "site"
    if ($null -ne $site) {
        $subnets = Get-ConfigArray -InputObject $site -Name "subnets"
        Write-FastfetchInfoRow -Label "site" -Value ("{0} ({1} subnet(s))" -f (Get-ConfigValue -InputObject $site -Name "siteName" -Default "?"), $subnets.Count) -LabelWidth 24 -IndentWidth 2
    }
    $ntp = Get-ConfigValue -InputObject $ActiveDirectory -Name "ntp"
    if ($null -ne $ntp) {
        Write-FastfetchInfoRow -Label "time source" -Value ((Get-ConfigArray -InputObject $ntp -Name "servers") -join ", ") -LabelWidth 24 -IndentWidth 2
    }
    $forest = Get-ConfigValue -InputObject $ActiveDirectory -Name "forest"
    if ($null -ne $forest) {
        $recycleBin = "Left as found"
        if ([bool](Get-ConfigValue -InputObject $forest -Name "enableRecycleBin" -Default $false)) { $recycleBin = "Enabled (forest-wide, irreversible)" }
        Write-FastfetchInfoRow -Label "recycle bin" -Value $recycleBin -LabelWidth 24 -IndentWidth 2
        $suffixes = Get-ConfigArray -InputObject $forest -Name "upnSuffixes"
        if ($suffixes.Count -gt 0) {
            Write-FastfetchInfoRow -Label "upn suffixes" -Value ($suffixes -join ", ") -LabelWidth 24 -IndentWidth 2
        }
    }
    $ipv6 = Get-ConfigValue -InputObject $ActiveDirectory -Name "ipv6"
    if ($null -ne $ipv6) {
        $value = "Left as promotion set it"
        if ([bool](Get-ConfigValue -InputObject $ipv6 -Name "setAutomatic" -Default $false)) { $value = "Reset to automatic" }
        Write-FastfetchInfoRow -Label "ipv6 client" -Value $value -LabelWidth 24 -IndentWidth 2
    }

    Write-Host "    the server restarts when the promotion finishes" -ForegroundColor DarkGray
}

function Show-DnsSummary {
    param([object]$Dns)

    Write-SummarySection -Title "DNS Server"

    $forwarders = Get-ConfigArray -InputObject $Dns -Name "forwarders"
    $value = "Left as found"
    if ($forwarders.Count -gt 0) { $value = $forwarders -join ", " }
    Write-FastfetchInfoRow -Label "forwarders" -Value $value -LabelWidth 24 -IndentWidth 2

    $zones = Get-ConfigArray -InputObject $Dns -Name "reverseLookupZones"
    $zoneText = "None"
    if ($zones.Count -gt 0) {
        $names = @()
        foreach ($zone in $zones) {
            $names += "{0}/{1}" -f (Get-ConfigValue -InputObject $zone -Name "networkId" -Default "?"), (Get-ConfigValue -InputObject $zone -Name "prefixLength" -Default 24)
        }
        $zoneText = $names -join ", "
    }
    Write-FastfetchInfoRow -Label "reverse zones" -Value $zoneText -LabelWidth 24 -IndentWidth 2

    $scavenging = Get-ConfigValue -InputObject $Dns -Name "scavenging"
    $scavengingText = "Disabled"
    if (($null -ne $scavenging) -and [bool](Get-ConfigValue -InputObject $scavenging -Name "enabled" -Default $false)) {
        $scavengingText = "Every {0} day(s)" -f (Get-ConfigValue -InputObject $scavenging -Name "intervalDays" -Default 7)
    }
    Write-FastfetchInfoRow -Label "scavenging" -Value $scavengingText -LabelWidth 24 -IndentWidth 2
}

function Show-AdcsSummary {
    param([object]$CertificateServices)

    $tierName = Resolve-AdcsTier -CertificateServices $CertificateServices
    if ([string]::IsNullOrWhiteSpace($tierName)) { return }

    $tier = Get-ConfigValue -InputObject $CertificateServices -Name $tierName
    $shared = Get-ConfigValue -InputObject $CertificateServices -Name "shared"

    # The directory tier has no CA, no key and no CRL, so the rows below would all read
    # '?'. It gets the two facts it is about instead.
    if ($tierName -eq "directory") {
        Write-SummarySection -Title "Certificate Services"
        Write-FastfetchInfoRow -Label "this server is" -Value "Directory preparation (domain controller)" -LabelWidth 24 -IndentWidth 2
        # Two different sets of groups, and rolling them into one "creates" row hid the
        # fact that the role groups were not being made at all.
        $roleGroups = Get-ConfigValue -InputObject $CertificateServices -Name "roleGroups"
        $roleText = "None - this config has no roleGroups section"
        if ($null -ne $roleGroups) {
            $roleText = "None - group creation is off"
            if ([bool](Get-ConfigValue -InputObject $roleGroups -Name "createGroups" -Default $false)) {
                $roleText = "{0} created or adopted" -f @(Get-ConfigArray -InputObject $roleGroups -Name "groups").Count
            }
        }
        Write-FastfetchInfoRow -Label "role groups" -Value $roleText -LabelWidth 24 -IndentWidth 2

        $access = Get-ConfigValue -InputObject $CertificateServices -Name "access"
        $groups = Get-ConfigArray -InputObject $access -Name "groups"
        $groupText = "None - group creation is off"
        if ([bool](Get-ConfigValue -InputObject $access -Name "createGroups" -Default $false)) {
            # A seeded group is the exception to "created, empty", so it is counted
            # rather than folded into a number that says the opposite of what happens.
            $seeded = 0
            foreach ($group in $groups) {
                if (@(Get-ConfigArray -InputObject $group -Name "members").Count -gt 0) { $seeded++ }
            }
            if ($seeded -gt 0) { $groupText = "{0} created, {1} empty and {2} seeded" -f $groups.Count, ($groups.Count - $seeded), $seeded }
            else { $groupText = "{0} created, empty" -f $groups.Count }
        }
        Write-FastfetchInfoRow -Label "enrollment groups" -Value $groupText -LabelWidth 24 -IndentWidth 2
        Write-FastfetchInfoRow -Label "publication alias" -Value ([string](Get-ConfigText -InputObject $shared -Name "pkiBaseUrl" -Default "None")) -LabelWidth 24 -IndentWidth 2

        $groupPolicy = Get-ConfigValue -InputObject $tier -Name "groupPolicy"
        $policyText = "None - this config has no groupPolicy section"
        if ($null -eq $groupPolicy) { $policyText = "None - this config has no groupPolicy section" }
        elseif (-not [bool](Get-ConfigValue -InputObject $groupPolicy -Name "enabled" -Default $false)) { $policyText = "None - switched off" }
        if (($null -ne $groupPolicy) -and [bool](Get-ConfigValue -InputObject $groupPolicy -Name "enabled" -Default $false)) {
            $policyItems = @(Get-ConfigArray -InputObject $groupPolicy -Name "items")
            # linkTo is a list. Read through the same helper the run uses rather than as
            # text: [string] on a two-element array is the two names with a space between
            # them, which is not false and is not a count either.
            $linked = @($policyItems | Where-Object { (Get-StudioGpoLinkTarget -InputObject $_ -Name "linkTo" -NoExpand).Count -gt 0 })
            $filtered = @($policyItems | Where-Object { -not [string]::IsNullOrWhiteSpace([string](Get-ConfigText -InputObject $_ -Name "wmiFilter" -Default "")) })
            $policyText = "{0} object(s), {1} filtered, {2} linked" -f $policyItems.Count, $filtered.Count, $linked.Count
        }
        Write-FastfetchInfoRow -Label "group policy" -Value $policyText -LabelWidth 24 -IndentWidth 2
        Write-FastfetchInfoRow -Label "installs" -Value "Nothing - no certification authority here" -LabelWidth 24 -IndentWidth 2
        return
    }

    # The SCEP tier is the fourth machine: no CA of its own, so the key and CRL rows
    # would all read '?'. It gets the facts NDES is about instead.
    if ($tierName -eq "scep") {
        Write-SummarySection -Title "Certificate Services"
        Write-FastfetchInfoRow -Label "this server is" -Value "Intune Certificate Connector host (NDES)" -LabelWidth 24 -IndentWidth 2
        $account = Get-ConfigValue -InputObject $tier -Name "serviceAccount"
        Write-FastfetchInfoRow -Label "service account" -Value ([string](Get-ConfigText -InputObject $account -Name "samAccountName" -Default "?")) -LabelWidth 24 -IndentWidth 2
        $issuingTier = Get-ConfigValue -InputObject $CertificateServices -Name "issuing"
        Write-FastfetchInfoRow -Label "enrolls against" -Value ([string](Get-ConfigText -InputObject $issuingTier -Name "caCommonName" -Default "?")) -LabelWidth 24 -IndentWidth 2
        $externalUrl = [string](Get-ConfigText -InputObject $tier -Name "externalUrl" -Default "")
        if (-not [string]::IsNullOrWhiteSpace($externalUrl)) {
            Write-FastfetchInfoRow -Label "published as" -Value $externalUrl -LabelWidth 24 -IndentWidth 2

            # The half of that name nobody thinks about until enrollment from a desk
            # times out: Intune hands out one address, and inside the network it has to
            # answer too. Written on the domain controller run, so this line says which
            # of the two shapes the design asked for.
            $scepDns = Get-ConfigValue -InputObject $tier -Name "dns"
            if ([bool](Get-ConfigValue -InputObject $scepDns -Name "manage" -Default $true)) {
                $zoneMode = [string](Get-ConfigText -InputObject $scepDns -Name "zoneMode" -Default "pinpoint")
                $modeText = switch ($zoneMode) {
                    "full" { "creating the whole parent zone if it is not served here" }
                    "none" { "reported only where the zone is not served here" }
                    default { "one pinpoint zone if it is not served here" }
                }
                Write-FastfetchInfoRow -Label "resolves internally" -Value ("yes, on the domain controller run - {0}" -f $modeText) -LabelWidth 24 -IndentWidth 2
            }
            else {
                Write-FastfetchInfoRow -Label "resolves internally" -Value "no - devices inside must reach it through the proxy" -LabelWidth 24 -IndentWidth 2
            }
        }
        $certificate = Get-ConfigValue -InputObject $tier -Name "certificate"
        Write-FastfetchInfoRow -Label "https certificate" -Value ([string](Get-ConfigText -InputObject $certificate -Name "source" -Default "left alone")) -LabelWidth 24 -IndentWidth 2

        # The three slots, because which template a device is handed is decided here and
        # nowhere the person reading this screen can see - an Intune SCEP profile names a
        # key usage, never a template.
        $slots = Get-AdcsScepSlotTemplate -CertificateServices $CertificateServices
        foreach ($slotName in @($slots.Keys)) {
            $value = [string]$slots[$slotName]
            if ([string]::IsNullOrWhiteSpace($value)) { $value = "left as it is" }
            Write-FastfetchInfoRow -Label $slotName -Value $value -LabelWidth 24 -IndentWidth 4
        }

        Write-FastfetchInfoRow -Label "installs" -Value "AD CS with NDES, IIS and its role services, the .NET features" -LabelWidth 24 -IndentWidth 2
        Write-Host "    the Intune connector itself stays a manual install - an interactive Entra sign-in, no unattended path" -ForegroundColor DarkGray
        return
    }

    Write-SummarySection -Title "Certificate Services"
    $role = "Offline root CA (standalone)"
    if ($tierName -eq "issuing") { $role = "Issuing CA (enterprise subordinate)" }
    Write-FastfetchInfoRow -Label "this server is" -Value $role -LabelWidth 24 -IndentWidth 2
    Write-FastfetchInfoRow -Label "ca name" -Value ([string](Get-ConfigValue -InputObject $tier -Name "caCommonName" -Default "?")) -LabelWidth 24 -IndentWidth 2
    Write-FastfetchInfoRow -Label "key" -Value ("{0} bit, {1}" -f (Get-ConfigValue -InputObject $tier -Name "keyLength" -Default 4096), (Get-ConfigValue -InputObject $tier -Name "hashAlgorithm" -Default "SHA256")) -LabelWidth 24 -IndentWidth 2

    if ($tierName -eq "root") {
        Write-FastfetchInfoRow -Label "own certificate" -Value (Get-SummaryPeriod -InputObject $tier -PeriodName "validityPeriod" -UnitsName "validityUnits") -LabelWidth 24 -IndentWidth 2
    }
    Write-FastfetchInfoRow -Label "issues certs for" -Value (Get-SummaryPeriod -InputObject $tier -PeriodName "issuedValidityPeriod" -UnitsName "issuedValidityUnits") -LabelWidth 24 -IndentWidth 2

    $crl = Get-ConfigValue -InputObject $tier -Name "crl"
    Write-FastfetchInfoRow -Label "crl period" -Value (Get-SummaryPeriod -InputObject $crl -PeriodName "period" -UnitsName "periodUnits") -LabelWidth 24 -IndentWidth 2
    Write-FastfetchInfoRow -Label "publication url" -Value ([string](Get-ConfigValue -InputObject $shared -Name "pkiBaseUrl" -Default "LDAP only")) -LabelWidth 24 -IndentWidth 2

    # Role separation is the one setting on this screen that can leave the operator
    # unable to administer the CA they are about to build, so it gets its own row
    # rather than being folded into a count of mitigations.
    $hardening = Get-ConfigValue -InputObject $shared -Name "hardening"
    $applied = @()
    if ([bool](Get-ConfigValue -InputObject $hardening -Name "disableSanAttribute" -Default $true)) { $applied += "no requester SAN" }
    if ([bool](Get-ConfigValue -InputObject $hardening -Name "enforceEncryptedRequests" -Default $true)) { $applied += "encrypted RPC" }
    if ([bool](Get-ConfigValue -InputObject $hardening -Name "auditSubcategory" -Default $true)) { $applied += "auditing" }
    $appliedText = "none"
    if ($applied.Count -gt 0) { $appliedText = $applied -join ", " }
    Write-FastfetchInfoRow -Label "hardening" -Value $appliedText -LabelWidth 24 -IndentWidth 2

    if ([bool](Get-ConfigValue -InputObject $hardening -Name "enableRoleSeparation" -Default $false)) {
        Write-FastfetchInfoRow -Label "role separation" -Value "ON - an account holding two CA roles loses both" -LabelWidth 24 -IndentWidth 2
    }

    if ($tierName -eq "issuing") {
        $templates = Get-ConfigValue -InputObject $tier -Name "templates"
        $templateText = "None"
        if ([bool](Get-ConfigValue -InputObject $templates -Name "enabled" -Default $false)) {
            $names = @()
            foreach ($item in (Get-ConfigArray -InputObject $templates -Name "items")) {
                $names += [string](Get-ConfigValue -InputObject $item -Name "displayName" -Default "?")
            }
            if ($names.Count -gt 0) { $templateText = $names -join ", " }
        }
        Write-FastfetchInfoRow -Label "templates" -Value $templateText -LabelWidth 24 -IndentWidth 2

        $backup = Get-ConfigValue -InputObject $tier -Name "backup"
        if (($null -ne $backup) -and [bool](Get-ConfigValue -InputObject $backup -Name "enabled" -Default $false)) {
            $backupDirectory = [string](Get-ConfigText -InputObject $backup -Name "directory" -Default "C:\CABackup")
            if ([string]::IsNullOrWhiteSpace($backupDirectory)) { $backupDirectory = "C:\CABackup" }
            $backupText = ("nightly at {0} into {1}, keeps {2} day(s)" -f `
                (Get-ConfigText -InputObject $backup -Name "time" -Default "02:30"), $backupDirectory, `
                [int](Get-ConfigValue -InputObject $backup -Name "retentionDays" -Default 14))
            Write-FastfetchInfoRow -Label "database backup" -Value $backupText -LabelWidth 24 -IndentWidth 2
        }

        # Who may ask for those certificates is at least as consequential as which
        # ones exist, so it belongs on the same screen rather than in the log.
        $access = Get-ConfigValue -InputObject $CertificateServices -Name "access"
        if ($null -ne $access) {
            $groups = Get-ConfigArray -InputObject $access -Name "groups"
            $groupText = "mapped to existing groups"
            if ([bool](Get-ConfigValue -InputObject $access -Name "createGroups" -Default $false) -and $groups.Count -gt 0) {
                $names = @()
                foreach ($group in $groups) { $names += [string](Get-ConfigValue -InputObject $group -Name "name" -Default "?") }
                $groupText = ("creates {0}: {1}" -f (Get-ConfigValue -InputObject $access -Name "scope" -Default "Global"), ($names -join ", "))
            }
            Write-FastfetchInfoRow -Label "enrollment groups" -Value $groupText -LabelWidth 24 -IndentWidth 2
        }
    }
    else {
        Write-Host "    this server should be offline and powered down between ceremonies" -ForegroundColor DarkGray
    }
}

function Show-RdsSummary {
    param([object]$RemoteDesktop)

    $deployment = Get-ConfigValue -InputObject $RemoteDesktop -Name "deployment"
    if ($null -eq $deployment) { return }

    Write-SummarySection -Title "Remote Desktop Services"

    # Counted before the plan is confirmed, so this reads the config rather than the
    # deployment - the same rule the GPO link count follows.
    $broker = [string](Get-ConfigText -InputObject $deployment -Name "connectionBroker" -Default "")
    if ([string]::IsNullOrWhiteSpace($broker)) { $broker = [string](Get-ConfigValue -InputObject $deployment -Name "fqdn" -Default "?") }
    $sessionHosts = @(Get-ConfigArray -InputObject $deployment -Name "sessionHosts")
    $webAccess = Get-ConfigValue -InputObject $deployment -Name "webAccess"
    $webName = [string](Get-ConfigText -InputObject $webAccess -Name "name" -Default "")
    # Not $mode: the licensing block below has its own, and one name for two questions is
    # how "this server" ended up on a summary describing four of them.
    $deploymentMode = [string](Get-ConfigText -InputObject $RemoteDesktop -Name "mode" -Default "singleHost")

    if ($deploymentMode -eq "farm") {
        # Every distinct machine the design names, licence server included - it is a
        # machine of its own the moment it is not the broker, and a count that skipped it
        # would be wrong on exactly the deployments that have one.
        $machines = @($broker)
        $machines += @($sessionHosts | ForEach-Object {
            if ($_ -is [string]) { [string]$_ } else { Get-ConfigText -InputObject $_ -Name "name" }
        })
        if (-not [string]::IsNullOrWhiteSpace($webName)) { $machines += $webName }
        $machines += @(Get-ConfigArray -InputObject (Get-ConfigValue -InputObject $RemoteDesktop -Name "licensing") -Name "servers" |
            ForEach-Object { [string]$_ })
        $machines = @($machines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
        Write-FastfetchInfoRow -Label "deployment" -Value ("Farm - {0} machine(s)" -f $machines.Count) -LabelWidth 24 -IndentWidth 2
    }
    else {
        Write-FastfetchInfoRow -Label "deployment" -Value "Quick session - one server" -LabelWidth 24 -IndentWidth 2
    }
    Write-FastfetchInfoRow -Label "connection broker" -Value $broker -LabelWidth 24 -IndentWidth 2
    if (-not [string]::IsNullOrWhiteSpace($webName)) {
        $webText = $webName
        if ($webName -eq $broker) { $webText = "$webName (on the broker)" }
        Write-FastfetchInfoRow -Label "web access" -Value $webText -LabelWidth 24 -IndentWidth 2
    }
    if ($sessionHosts.Count -gt 0) {
        # The drain state is said out loud: a host parked at 'No' is a host nobody lands
        # on, and a summary that printed it as an ordinary member would hide that.
        $hostText = (($sessionHosts | ForEach-Object {
            if ($_ -is [string]) { [string]$_ }
            else {
                $name = Get-ConfigText -InputObject $_ -Name "name"
                $drain = Get-ConfigText -InputObject $_ -Name "newConnectionAllowed" -Default "Yes"
                if ($drain -eq "Yes") { $name } else { "$name [$drain]" }
            }
        }) -join ", ")
        Write-FastfetchInfoRow -Label "session hosts" -Value $hostText -LabelWidth 24 -IndentWidth 2
    }
    Write-FastfetchInfoRow -Label "collection" -Value ([string](Get-ConfigValue -InputObject $deployment -Name "collectionName" -Default "?")) -LabelWidth 24 -IndentWidth 2

    # Printed either way, and the default is spelled out rather than left blank: a run
    # that says nothing here is a run whose portal says 'Work Resources' and nobody
    # noticed until somebody signed in.
    $workspace = [string](Get-ConfigText -InputObject $deployment -Name "workspaceName" -Default "")
    if ([string]::IsNullOrWhiteSpace($workspace)) {
        Write-FastfetchInfoRow -Label "workspace" -Value "Work Resources (Microsoft's default - not set by this design)" -LabelWidth 24 -IndentWidth 2
    }
    else {
        Write-FastfetchInfoRow -Label "workspace" -Value $workspace -LabelWidth 24 -IndentWidth 2
    }

    $access = Get-ConfigValue -InputObject $RemoteDesktop -Name "access"
    # userGroups carries {name, members} objects - joining those straight into a string
    # prints nothing, which is what this line did after the members were added. The
    # member count comes along, because who fills a group is the other half of the
    # answer and only the domain controller run writes it.
    $groups = Get-StudioGroupDefinition -Entries (Get-ConfigArray -InputObject $access -Name "userGroups")
    $groupText = "nobody"
    if ($groups.Count -gt 0) {
        $groupText = (($groups | ForEach-Object {
            if ($_.Members.Count -gt 0) { "{0} ({1} member(s))" -f $_.Name, $_.Members.Count } else { $_.Name }
        }) -join ", ")
    }
    Write-FastfetchInfoRow -Label "used by" -Value $groupText -LabelWidth 24 -IndentWidth 2

    $licensing = Get-ConfigValue -InputObject $RemoteDesktop -Name "licensing"
    $mode = [string](Get-ConfigValue -InputObject $licensing -Name "mode" -Default "NotConfigured")
    $licenseText = "None - 120 day grace period"
    if ($mode -ne "NotConfigured") {
        $licenseText = "{0} via {1}" -f $mode, ((Get-ConfigArray -InputObject $licensing -Name "servers") -join ", ")
    }
    if ([bool](Get-ConfigValue -InputObject $licensing -Name "installOnThisServer" -Default $false)) {
        # "This server" is the broker in a farm, and the machine reading this in a quick
        # session. Naming it either way beats a pronoun that is wrong on four machines.
        $licenseText = $licenseText + (" ({0}, activation and CALs by hand)" -f $(if ($deploymentMode -eq "farm") { "on the broker" } else { "this server" }))
    }
    Write-FastfetchInfoRow -Label "licensing" -Value $licenseText -LabelWidth 24 -IndentWidth 2

    $certificate = Get-ConfigValue -InputObject $RemoteDesktop -Name "certificate"
    Write-FastfetchInfoRow -Label "certificate" -Value ([string](Get-ConfigValue -InputObject $certificate -Name "source" -Default "leave")) -LabelWidth 24 -IndentWidth 2

    # Its own row, because it is its own certificate on its own machine - and a design
    # that carries two and reports one is a design somebody half checked.
    $webCertificate = Get-ConfigValue -InputObject $RemoteDesktop -Name "webAccessCertificate"
    if ($null -ne $webCertificate) {
        $webCertificateText = [string](Get-ConfigValue -InputObject $webCertificate -Name "source" -Default "leave")
        # Only says where it goes when the design says where that is - "(distributed to )"
        # is the kind of line that reads as a bug in the summary rather than in the config.
        if (-not [string]::IsNullOrWhiteSpace($webName)) {
            $webCertificateText = "{0} (distributed to {1})" -f $webCertificateText, $webName
        }
        Write-FastfetchInfoRow -Label "web certificate" -Value $webCertificateText -LabelWidth 24 -IndentWidth 2
    }

    $published = Get-ConfigValue -InputObject $RemoteDesktop -Name "publishedName"
    if ([bool](Get-ConfigValue -InputObject $published -Name "manage" -Default $false)) {
        Write-FastfetchInfoRow -Label "published as" -Value ([string](Get-ConfigValue -InputObject $published -Name "clientAccessName" -Default "?")) -LabelWidth 24 -IndentWidth 2
    }

    # The records are the domain controller's job from the same config, so the summary
    # says which run writes them rather than leaving the names looking unaccounted for.
    $dns = Get-ConfigValue -InputObject $RemoteDesktop -Name "dns"
    if ([bool](Get-ConfigValue -InputObject $dns -Name "manage" -Default $true)) {
        $zoneMode = [string](Get-ConfigValue -InputObject $dns -Name "zoneMode" -Default "pinpoint")
        Write-FastfetchInfoRow -Label "dns records" -Value "written on the domain controller run ($zoneMode)" -LabelWidth 24 -IndentWidth 2
    }
    else {
        Write-FastfetchInfoRow -Label "dns records" -Value "printed only - create them where their zone is served" -LabelWidth 24 -IndentWidth 2
    }

    Write-FastfetchInfoRow -Label "rdp listener" -Value "Group Policy - Certificate - Remote Desktop Authentication" -LabelWidth 24 -IndentWidth 2

    $fslogix = Get-ConfigValue -InputObject $RemoteDesktop -Name "fslogix"
    if ([bool](Get-ConfigValue -InputObject $fslogix -Name "enabled" -Default $false)) {
        Write-FastfetchInfoRow -Label "fslogix" -Value "agent installed on the session host" -LabelWidth 24 -IndentWidth 2

        # The policy is the domain controller's job from the same config, so the summary
        # says what that run will write rather than leaving the agent looking unconfigured.
        $policy = Get-ConfigValue -InputObject $fslogix -Name "groupPolicy"
        $policyText = "none - this config has no groupPolicy section"
        if ($null -ne $policy) {
            if (-not [bool](Get-ConfigValue -InputObject $policy -Name "enabled" -Default $false)) { $policyText = "none - switched off" }
            else {
                $values = @(Get-ConfigArray -InputObject $policy -Name "values")
                $location = ""
                foreach ($value in $values) {
                    if ([string](Get-ConfigText -InputObject $value -Name "valueName" -Default "") -eq "VHDLocations") {
                        $location = [string](Get-ConfigText -InputObject $value -Name "data" -Default "")
                    }
                }
                $filter = [string](Get-ConfigText -InputObject $policy -Name "wmiFilter" -Default "")
                if ([string]::IsNullOrWhiteSpace($filter)) { $filter = "no WMI filter" }
                $links = @(Get-StudioGpoLinkTarget -InputObject $policy -Name "linkTo" -NoExpand)
                $linkText = if ($links.Count -gt 0) { "linked to {0} OU(s)" -f $links.Count } else { "unlinked" }
                $policyText = "{0} - {1} value(s), {2}, {3}" -f `
                    [string](Get-ConfigText -InputObject $policy -Name "name" -Default ""), $values.Count, $filter, $linkText
                if (-not [string]::IsNullOrWhiteSpace($location)) {
                    Write-FastfetchInfoRow -Label "container location" -Value $location -LabelWidth 24 -IndentWidth 2
                }
            }
        }
        Write-FastfetchInfoRow -Label "fslogix policy" -Value $policyText -LabelWidth 24 -IndentWidth 2
    }

    $remoteApps = Get-ConfigValue -InputObject $RemoteDesktop -Name "remoteApps"
    if ([bool](Get-ConfigValue -InputObject $remoteApps -Name "enabled" -Default $false)) {
        $names = @()
        foreach ($item in (Get-ConfigArray -InputObject $remoteApps -Name "items")) {
            $names += [string](Get-ConfigValue -InputObject $item -Name "displayName" -Default "?")
        }
        Write-FastfetchInfoRow -Label "publishes" -Value ($names -join ", ") -LabelWidth 24 -IndentWidth 2
        if ([bool](Get-ConfigValue -InputObject $remoteApps -Name "showDesktopInPortal" -Default $false)) {
            Write-Host "    the full desktop stays on the portal beside them (ShowInPortal, re-applied every run)" -ForegroundColor DarkGray

            $watchdog = Get-ConfigValue -InputObject $remoteApps -Name "portalWatchdog"
            if ([bool](Get-ConfigValue -InputObject $watchdog -Name "enabled" -Default $false)) {
                $everyMinutes = [int](Get-ConfigValue -InputObject $watchdog -Name "intervalMinutes" -Default 60)
                Write-FastfetchInfoRow -Label "portal watchdog" -Value ("every {0} minute(s) and after every start" -f $everyMinutes) -LabelWidth 24 -IndentWidth 2

                $watchdogMail = Get-ConfigValue -InputObject $watchdog -Name "notification"
                if ([bool](Get-ConfigValue -InputObject $watchdogMail -Name "enabled" -Default $false)) {
                    $sendOn = [string](Get-ConfigText -InputObject $watchdogMail -Name "sendOn" -Default "repairOrFailure")
                    $sendText = switch ($sendOn) {
                        "always"     { "after every check" }
                        "repairOnly" { "when it puts the desktop back" }
                        default      { "when it puts the desktop back, and when it cannot" }
                    }
                    $to = @(Get-ConfigArray -InputObject $watchdogMail -Name "to")
                    Write-FastfetchInfoRow -Label "watchdog mail" -Value ("{0} -> {1}" -f $sendText, ($to -join ", ")) -LabelWidth 24 -IndentWidth 2
                }
            }
            else {
                Write-Host "    nothing re-asserts it between runs - Windows clears it on every broker restart" -ForegroundColor DarkGray
            }
        }
        else {
            Write-Host "    publishing applications takes the full desktop off this collection's feed" -ForegroundColor DarkGray
        }
    }
}

function Show-ArcSummary {
    param([object]$AzureArc)

    $connection = Get-ConfigValue -InputObject $AzureArc -Name "connection"
    if ($null -eq $connection) { return }

    Write-SummarySection -Title "Azure Arc"

    $resourceName = [string](Get-ConfigValue -InputObject $connection -Name "resourceName" -Default "")
    if ([string]::IsNullOrWhiteSpace($resourceName)) { $resourceName = "$env:COMPUTERNAME (this machine's name)" }
    Write-FastfetchInfoRow -Label "resource name" -Value $resourceName -LabelWidth 24 -IndentWidth 2
    Write-FastfetchInfoRow -Label "resource group" -Value ([string](Get-ConfigValue -InputObject $connection -Name "resourceGroup" -Default "?")) -LabelWidth 24 -IndentWidth 2
    Write-FastfetchInfoRow -Label "subscription" -Value ([string](Get-ConfigValue -InputObject $connection -Name "subscriptionId" -Default "?")) -LabelWidth 24 -IndentWidth 2
    Write-FastfetchInfoRow -Label "region" -Value ("{0} ({1})" -f (Get-ConfigValue -InputObject $connection -Name "location" -Default "?"), (Get-ConfigValue -InputObject $connection -Name "cloud" -Default "AzureCloud")) -LabelWidth 24 -IndentWidth 2

    $authMode = [string](Get-ConfigValue -InputObject $connection -Name "authMode" -Default "servicePrincipal")
    $authText = "Interactive sign-in at the console"
    if ($authMode -eq "servicePrincipal") {
        $authText = "Service principal {0}" -f (Get-ConfigValue -InputObject $connection -Name "servicePrincipalAppId" -Default "?")
    }
    Write-FastfetchInfoRow -Label "signs in as" -Value $authText -LabelWidth 24 -IndentWidth 2

    $tagNames = @()
    foreach ($tag in (Get-ConfigArray -InputObject $connection -Name "tags")) {
        $name = [string](Get-ConfigValue -InputObject $tag -Name "name" -Default "")
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $tagNames += ("{0}={1}" -f $name, (Get-ConfigValue -InputObject $tag -Name "value" -Default ""))
        }
    }
    $tagText = "None"
    if ($tagNames.Count -gt 0) { $tagText = $tagNames -join ", " }
    Write-FastfetchInfoRow -Label "tags" -Value $tagText -LabelWidth 24 -IndentWidth 2

    $proxy = Get-ConfigValue -InputObject $AzureArc -Name "proxy"
    $proxyUrl = [string](Get-ConfigValue -InputObject $proxy -Name "url" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($proxyUrl)) {
        Write-FastfetchInfoRow -Label "agent proxy" -Value $proxyUrl -LabelWidth 24 -IndentWidth 2
    }

    Write-Host "    tags are set while connecting - afterwards they belong to the Azure resource" -ForegroundColor DarkGray
}

# The guest cluster half of the file server summary. Silent on a single-host design -
# a run that prints "mode: single host" on every file server in the estate is a run
# that has taught everyone to skip the summary.
function Show-FsClusterSummary {
    param([object]$FileServer)

    if ([string](Get-ConfigText -InputObject $FileServer -Name "mode" -Default "singleHost") -ne "guestCluster") { return }
    $cluster = Get-ConfigValue -InputObject $FileServer -Name "guestCluster"
    if ($null -eq $cluster) { return }

    $nodes = @(Get-ConfigArray -InputObject $cluster -Name "nodes")
    $nodeText = "not named"
    if ($nodes.Count -gt 0) { $nodeText = $nodes -join ", " }
    Write-FastfetchInfoRow -Label "guest cluster" -Value $nodeText -LabelWidth 24 -IndentWidth 2

    $clusterName = [string](Get-ConfigText -InputObject $cluster -Name "clusterName" -Default "cl-files-01")
    $clusterAddress = [string](Get-ConfigText -InputObject $cluster -Name "clusterAddress" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($clusterAddress)) { $clusterName = "{0} ({1})" -f $clusterName, $clusterAddress }
    Write-FastfetchInfoRow -Label "cluster name" -Value $clusterName -LabelWidth 24 -IndentWidth 2

    $roleName = [string](Get-ConfigText -InputObject $cluster -Name "roleName" -Default "files-cl-01")
    $roleAddress = [string](Get-ConfigText -InputObject $cluster -Name "roleAddress" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($roleAddress)) { $roleName = "{0} ({1})" -f $roleName, $roleAddress }
    Write-FastfetchInfoRow -Label "file server role" -Value $roleName -LabelWidth 24 -IndentWidth 2

    $witness = Get-ConfigValue -InputObject $cluster -Name "witness"
    $witnessText = "none - two nodes without one lose quorum"
    if ($null -ne $witness) {
        if ([string](Get-ConfigText -InputObject $witness -Name "type" -Default "cloud") -eq "fileShare") {
            $fileShare = Get-ConfigValue -InputObject $witness -Name "fileShare"
            $witnessText = "\\{0}\{1}" -f [string](Get-ConfigText -InputObject $fileShare -Name "host" -Default "?"),
                [string](Get-ConfigText -InputObject $fileShare -Name "shareName" -Default "?")
        }
        else {
            $cloud = Get-ConfigValue -InputObject $witness -Name "cloud"
            $witnessText = "cloud - {0}" -f [string](Get-ConfigText -InputObject $cloud -Name "accountName" -Default "?")
        }
    }
    Write-FastfetchInfoRow -Label "witness" -Value $witnessText -LabelWidth 24 -IndentWidth 2

    # The setting that decides whether patching a node logs the users off, so it is
    # named rather than left to the share list.
    $continuous = "on - handles survive a planned move"
    if (-not [bool](Get-ConfigValue -InputObject $cluster -Name "continuousAvailability" -Default $true)) {
        $continuous = "OFF - every handle breaks when the role moves"
    }
    Write-FastfetchInfoRow -Label "continuous availability" -Value $continuous -LabelWidth 24 -IndentWidth 2
}

function Show-FsSummary {
    param([object]$FileServer)

    Write-SummarySection -Title "File Server"

    $root = Get-ConfigValue -InputObject $FileServer -Name "root"
    $drive = [string](Get-ConfigValue -InputObject $root -Name "drive" -Default "D:")
    $folder = [string](Get-ConfigValue -InputObject $root -Name "folderName" -Default "shares")
    Write-FastfetchInfoRow -Label "share root" -Value ("{0}\{1}" -f $drive.TrimEnd("\"), $folder) -LabelWidth 24 -IndentWidth 2

    # The mode, and the four names that only exist in one of them. Printed before the
    # shares because it changes what every line below means: in cluster mode the root
    # above is a shared disk that is mounted on one node at a time, and the shares are
    # the role's rather than this machine's.
    Show-FsClusterSummary -FileServer $FileServer

    $shareNames = @()
    foreach ($share in (Get-ConfigArray -InputObject $FileServer -Name "shares")) {
        $name = [string](Get-ConfigValue -InputObject $share -Name "name" -Default "")
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        if ([bool](Get-ConfigValue -InputObject $share -Name "hidden" -Default $true)) { $name += "$" }
        # The permissions model is the one thing about a share that the name does not
        # say and that decides what the run writes on the folder, so it is marked here.
        if ([string](Get-ConfigText -InputObject $share -Name "accessModel" -Default "standard") -eq "fslogixContainer") {
            $name += " (profile containers)"
        }
        # A second group on a share changes who may WRITE what is in it, which the share
        # name says nothing about - so the two-tier shares are marked here rather than
        # left to be discovered from the group list.
        elseif (-not [string]::IsNullOrWhiteSpace((Get-ConfigText -InputObject $share -Name "readGroup"))) {
            $name += " (rw+ro)"
        }
        $shareNames += $name
    }
    $shareText = "None"
    if ($shareNames.Count -gt 0) { $shareText = $shareNames -join ", " }
    Write-FastfetchInfoRow -Label "shares" -Value $shareText -LabelWidth 24 -IndentWidth 2

    # Same reading as the Remote Desktop access groups: the member count is what says
    # whether the domain controller run has anything to write.
    $groupNames = @()
    foreach ($group in (Get-StudioGroupDefinition -Entries (Get-ConfigArray -InputObject $FileServer -Name "groups"))) {
        if ($group.Members.Count -gt 0) { $groupNames += ("{0} ({1} member(s))" -f $group.Name, $group.Members.Count) }
        else { $groupNames += $group.Name }
    }
    $groupText = "None"
    if ($groupNames.Count -gt 0) { $groupText = $groupNames -join ", " }
    Write-FastfetchInfoRow -Label "share groups" -Value $groupText -LabelWidth 24 -IndentWidth 2

    $enumeration = "off"
    if ([bool](Get-ConfigValue -InputObject $FileServer -Name "accessBasedEnumeration" -Default $true)) { $enumeration = "on" }
    Write-FastfetchInfoRow -Label "access-based enum" -Value $enumeration -LabelWidth 24 -IndentWidth 2

    $tiers = "one group per share"
    if ([bool](Get-ConfigValue -InputObject $FileServer -Name "splitAccessGroups" -Default $false)) {
        $tiers = "read/write and read-only groups"
    }
    Write-FastfetchInfoRow -Label "share access" -Value $tiers -LabelWidth 24 -IndentWidth 2

    $shadow = Get-ConfigValue -InputObject $FileServer -Name "shadowCopies"
    $shadowText = "off"
    if ([bool](Get-ConfigValue -InputObject $shadow -Name "enabled" -Default $false)) {
        $times = @(Get-ConfigArray -InputObject $shadow -Name "schedule")
        $shadowText = "daily at {0}" -f ($times -join ", ")
    }
    Write-FastfetchInfoRow -Label "shadow copies" -Value $shadowText -LabelWidth 24 -IndentWidth 2

    $dfs = Get-ConfigValue -InputObject $FileServer -Name "dfs"
    $dfsText = "off"
    if ([bool](Get-ConfigValue -InputObject $dfs -Name "enabled" -Default $false)) {
        $namespaceNames = @()
        foreach ($namespace in (Get-ConfigArray -InputObject $dfs -Name "namespaces")) {
            $name = [string](Get-ConfigValue -InputObject $namespace -Name "name" -Default "")
            if (-not [string]::IsNullOrWhiteSpace($name)) { $namespaceNames += $name }
        }
        $dfsText = "none"
        if ($namespaceNames.Count -gt 0) { $dfsText = $namespaceNames -join ", " }
    }
    Write-FastfetchInfoRow -Label "dfs namespaces" -Value $dfsText -LabelWidth 24 -IndentWidth 2

    # Where the drive-map policies land. One list for all of them, and saying "unlinked"
    # out loud matters more than saying where: an unlinked drive map is a design that
    # writes every object correctly and maps no drive on any machine.
    $fsPolicy = Get-ConfigValue -InputObject $FileServer -Name "groupPolicy"
    $fsLinks = @(Get-StudioGpoLinkTarget -InputObject $fsPolicy -Name "linkTo" -NoExpand)
    $fsLinkText = "unlinked - no drive is mapped until they are"
    if ($fsLinks.Count -gt 0) { $fsLinkText = $fsLinks -join ", " }
    Write-FastfetchInfoRow -Label "drive-map policies" -Value $fsLinkText -LabelWidth 24 -IndentWidth 2

    Write-Host "    on a domain controller this run creates the share groups as domain local security groups, with their members;" -ForegroundColor DarkGray
    Write-Host "    on the file server they are a prerequisite" -ForegroundColor DarkGray
}

function Show-PrintSummary {
    param([object]$PrintServer)

    Write-SummarySection -Title "Print Server"

    $root = Get-ConfigValue -InputObject $PrintServer -Name "root"
    $server = [string](Get-ConfigValue -InputObject $root -Name "computerName" -Default $env:COMPUTERNAME)
    Write-FastfetchInfoRow -Label "print server" -Value $server -LabelWidth 24 -IndentWidth 2

    $driverNames = @()
    foreach ($driver in (Get-PrintDriverDefinition -PrintServer $PrintServer)) {
        if ([string]::IsNullOrWhiteSpace($driver.InfPath)) { $driverNames += $driver.Name }
        else { $driverNames += ($driver.Name + " (staged)") }
    }
    $driverText = "None"
    if ($driverNames.Count -gt 0) { $driverText = $driverNames -join ", " }
    Write-FastfetchInfoRow -Label "drivers" -Value $driverText -LabelWidth 24 -IndentWidth 2

    $portNames = @()
    foreach ($port in (Get-PrintPortDefinition -PrintServer $PrintServer)) {
        $portNames += ("{0}:{1}" -f $port.Address, $port.PortNumber)
    }
    $portText = "None"
    if ($portNames.Count -gt 0) { $portText = $portNames -join ", " }
    Write-FastfetchInfoRow -Label "ports" -Value $portText -LabelWidth 24 -IndentWidth 2

    # The whole-server answer, above the queues that follow it. Every queue below either
    # inherits this or overrides it, and its own row says which it ended up with.
    $serverRights = [string](Get-ConfigText -InputObject $PrintServer -Name "permissions" -Default "authenticated")
    $serverRightsText = switch ($serverRights) {
        "group"     { "the deployment group + Domain Computers" }
        "groupOnly" { "the deployment group only" }
        default     { "Authenticated Users" }
    }
    Write-FastfetchInfoRow -Label "who may print" -Value $serverRightsText -LabelWidth 24 -IndentWidth 2

    $queues = Get-PrintQueue -PrintServer $PrintServer
    Write-FastfetchInfoRow -Label "printers" -Value ("{0} queue(s)" -f $queues.Count) -LabelWidth 24 -IndentWidth 2
    foreach ($queue in $queues) {
        $target = $queue.Group
        if ([string]::IsNullOrWhiteSpace($target)) { $target = "nobody" }
        # Who it is DEPLOYED to, then who may PRINT on it. They are two different
        # questions and the queue row used to answer only the first, which reads as though
        # the group decided both - the thing this role spent a bench day proving wrong.
        # Get-PrintQueue has already resolved 'inherit' against the server-wide answer,
        # so this reports what the queue actually gets rather than what it stated.
        $mayPrint = switch ([string]$queue.Rights) {
            "authenticated" { "Authenticated Users may print" }
            "group"         { "only that group + Domain Computers may print" }
            "groupOnly"     { "only that group may print" }
            default         { "Everyone may print" }
        }
        Write-FastfetchInfoRow -Label $queue.Name -Value ("shared as '{0}' -> {1}, {2}" -f $queue.ShareName, $target, $mayPrint) -LabelWidth 24 -IndentWidth 4
    }

    $groupNames = @()
    foreach ($group in (Get-StudioGroupDefinition -Entries (Get-ConfigArray -InputObject $PrintServer -Name "groups"))) {
        if ($group.Members.Count -gt 0) { $groupNames += ("{0} ({1} member(s))" -f $group.Name, $group.Members.Count) }
        else { $groupNames += $group.Name }
    }
    $groupText = "None"
    if ($groupNames.Count -gt 0) { $groupText = $groupNames -join ", " }
    Write-FastfetchInfoRow -Label "printer groups" -Value $groupText -LabelWidth 24 -IndentWidth 2

    # Same reading as the drive maps: one list for every deployment policy, and an
    # unlinked one hands out no printer however correct the queues behind it are.
    $printPolicy = Get-ConfigValue -InputObject $PrintServer -Name "groupPolicy"
    $printLinks = @(Get-StudioGpoLinkTarget -InputObject $printPolicy -Name "linkTo" -NoExpand)
    $printLinkText = "unlinked - no printer is handed out until they are"
    if ($printLinks.Count -gt 0) { $printLinkText = $printLinks -join ", " }
    Write-FastfetchInfoRow -Label "deployment policies" -Value $printLinkText -LabelWidth 24 -IndentWidth 2

    Write-Host "    on a domain controller this run creates the groups, members and the deployment GPOs; on the print server they are a prerequisite" -ForegroundColor DarkGray
}

function Show-DhcpSummary {
    param([object]$Dhcp)

    Write-SummarySection -Title "DHCP Server"

    $mode = [string](Get-ConfigValue -InputObject $Dhcp -Name "mode" -Default "newDeployment")
    $modeText = "new deployment"
    if ($mode -eq "addServer") { $modeText = "add server to an existing deployment" }
    Write-FastfetchInfoRow -Label "mode" -Value $modeText -LabelWidth 24 -IndentWidth 2

    $authorize = "no"
    if ([bool](Get-ConfigValue -InputObject $Dhcp -Name "authorize" -Default $true)) { $authorize = "yes" }
    Write-FastfetchInfoRow -Label "authorize in AD" -Value $authorize -LabelWidth 24 -IndentWidth 2

    if ($mode -eq "addServer") {
        $failover = Get-ConfigValue -InputObject $Dhcp -Name "failover"
        $partner = [string](Get-ConfigValue -InputObject $failover -Name "partnerServer" -Default "")
        if ([string]::IsNullOrWhiteSpace($partner)) { $partner = "not named" }
        Write-FastfetchInfoRow -Label "partner server" -Value $partner -LabelWidth 24 -IndentWidth 2

        $failoverMode = [string](Get-ConfigValue -InputObject $failover -Name "mode" -Default "LoadBalance")
        $detail = $failoverMode
        if ($failoverMode -eq "LoadBalance") {
            $detail = "load balance {0}/{1}" -f [int](Get-ConfigValue -InputObject $failover -Name "loadBalancePercent" -Default 50),
                (100 - [int](Get-ConfigValue -InputObject $failover -Name "loadBalancePercent" -Default 50))
        }
        else {
            $detail = "hot standby, {0}% reserved" -f [int](Get-ConfigValue -InputObject $failover -Name "reservePercent" -Default 5)
        }
        Write-FastfetchInfoRow -Label "relationship" -Value $detail -LabelWidth 24 -IndentWidth 2
        Write-Host "    the scopes come from the partner - a failover relationship replicates them" -ForegroundColor DarkGray
        return
    }

    $scopes = Get-DhcpScopeDefinition -Dhcp $Dhcp
    Write-FastfetchInfoRow -Label "scopes" -Value ("{0} scope(s)" -f $scopes.Count) -LabelWidth 24 -IndentWidth 2
    foreach ($scope in $scopes) {
        Write-FastfetchInfoRow -Label $scope.Name -Value ("{0} - {1} / {2}, {3} day lease" -f $scope.StartRange, $scope.EndRange, $scope.SubnetMask, $scope.LeaseDays) -LabelWidth 24 -IndentWidth 4
        if ($scope.Reservations.Count -gt 0) {
            Write-FastfetchInfoRow -Label "reservations" -Value ("{0}" -f $scope.Reservations.Count) -LabelWidth 24 -IndentWidth 6
        }
    }

    $dns = Get-ConfigValue -InputObject $Dhcp -Name "dnsUpdate"
    if ($null -ne $dns) {
        Write-FastfetchInfoRow -Label "dns registration" -Value ([string](Get-ConfigValue -InputObject $dns -Name "dynamicUpdates" -Default "OnClientRequest")) -LabelWidth 24 -IndentWidth 2
    }
}

function Show-ConnectorSummary {
    param([object]$EntraConnector)

    Write-SummarySection -Title "Entra Private Network Connector"

    $registration = [string](Get-ConfigValue -InputObject $EntraConnector -Name "registration" -Default "deviceCode")
    $label = "Device code, on this server"
    if ($registration -eq "tokenFile") { $label = "Token minted on another machine" }
    if ($registration -eq "manual") { $label = "Manual - install only" }
    Write-FastfetchInfoRow -Label "registration" -Value $label -LabelWidth 24 -IndentWidth 2

    if ($registration -ne "manual") {
        Write-FastfetchInfoRow -Label "tenant" -Value ([string](Get-ConfigValue -InputObject $EntraConnector -Name "tenantId" -Default "?")) -LabelWidth 24 -IndentWidth 2
        $tokenSource = [string](Get-ConfigValue -InputObject $EntraConnector -Name "tokenFile" -Default "")
        if (-not [string]::IsNullOrWhiteSpace($tokenSource)) {
            Write-FastfetchInfoRow -Label "token file" -Value $tokenSource -LabelWidth 24 -IndentWidth 2
        }
        if ([bool](Get-ConfigValue -InputObject $EntraConnector -Name "forceRegistration" -Default $false)) {
            Write-FastfetchInfoRow -Label "re-register" -Value "Yes - renews the trust certificate" -LabelWidth 24 -IndentWidth 2
        }
        if ($registration -eq "tokenFile") {
            Write-Host "    mint the token with -Task ConnectorToken on a machine with a browser, then copy it here" -ForegroundColor DarkGray
        }
        else {
            Write-Host "    this server prints a URL and a code - sign in on any device to finish the registration" -ForegroundColor DarkGray
        }
    }
    Write-Host "    Conditional Access must allow the device code flow and authentication transfer, or registration fails" -ForegroundColor DarkGray
}

# The two-node S2D mode's half of the summary - its own function because the two modes
# share a blade and nothing else. Dispatched from Show-HypervSummary on the mode string.
function Show-HypervS2dSummary {
    param([object]$Hyperv)

    Write-SummarySection -Title "Hyper-V S2D cluster"

    $s2d = Get-HypervS2dSection -Hyperv $Hyperv
    if ($null -eq $s2d) {
        Write-FastfetchInfoRow -Label "this run" -Value "mode is s2dCluster and the section is missing" -LabelWidth 24 -IndentWidth 2
        return
    }

    $persona = Get-HypervS2dPersona -S2d $s2d
    $names = @(Get-HypervS2dNodeName -S2d $s2d)
    Write-FastfetchInfoRow -Label "this machine" -Value $persona -LabelWidth 24 -IndentWidth 2
    Write-FastfetchInfoRow -Label "cluster" -Value ("{0} across {1}" -f (Get-HypervS2dClusterName -S2d $s2d), ($names -join " + ")) -LabelWidth 24 -IndentWidth 2

    $kind = "workgroup - identical local admin, TrustedHosts, one DNS suffix"
    if (Test-HypervS2dDomainKind -Hyperv $Hyperv) { $kind = "domain - the cluster name becomes a computer object" }
    Write-FastfetchInfoRow -Label "cluster kind" -Value $kind -LabelWidth 24 -IndentWidth 2

    $witness = Get-ConfigValue -InputObject $s2d -Name "witness"
    $witnessLine = "none - NOT viable on two nodes"
    if ($null -ne $witness) {
        $type = [string](Get-ConfigText -InputObject $witness -Name "type" -Default "cloud")
        if ($type -eq "fileShare") {
            $fileShare = Get-ConfigValue -InputObject $witness -Name "fileShare"
            $witnessLine = ("file share \\{0}\{1}" -f
                [string](Get-ConfigText -InputObject $fileShare -Name "host" -Default "?"),
                [string](Get-ConfigText -InputObject $fileShare -Name "shareName" -Default "?"))
        }
        else {
            $cloud = Get-ConfigValue -InputObject $witness -Name "cloud"
            $witnessLine = ("cloud, storage account {0}" -f [string](Get-ConfigText -InputObject $cloud -Name "accountName" -Default "?"))
            if ([bool](Get-ConfigValue -InputObject $cloud -Name "useManagedIdentity" -Default $false)) {
                $witnessLine = $witnessLine + ", managed identity"
            }
            else {
                $witnessLine = $witnessLine + ", key asked at the console"
            }
        }
    }
    Write-FastfetchInfoRow -Label "witness" -Value $witnessLine -LabelWidth 24 -IndentWidth 2

    $storage = Get-ConfigValue -InputObject $s2d -Name "storage"
    # The studio writes no resiliency key - the console interview owns that answer. A key
    # in an older config.json is still shown; absent, the summary says where it is decided.
    $resiliency = [string](Get-ConfigText -InputObject $storage -Name "resiliency" -Default "")
    if ([string]::IsNullOrWhiteSpace($resiliency)) { $resiliency = "resiliency asked at the console" }
    $count = [int](Get-ConfigValue -InputObject $storage -Name "volumeCount" -Default 2)
    if ($count -lt 1) { $count = 1 }
    $prefix = [string](Get-ConfigText -InputObject $storage -Name "csvNamePrefix" -Default "csv")
    Write-FastfetchInfoRow -Label "volumes" -Value ("{0} x {1}-*, {2}, CSVFS_ReFS" -f $count, $prefix, $resiliency) -LabelWidth 24 -IndentWidth 2

    $networking = Get-ConfigValue -InputObject $s2d -Name "networking"
    $lane = [string](Get-ConfigText -InputObject $networking -Name "mode" -Default "atc")
    $frames = "jumbo 9014"
    if (-not [bool](Get-ConfigValue -InputObject $networking -Name "jumboFrames" -Default $true)) { $frames = "standard frames" }
    $pin = "RoCEv2 pinned"
    if (-not [bool](Get-ConfigValue -InputObject $networking -Name "pinRoceV2" -Default $true)) { $pin = "RDMA auto" }
    $networkLine = ("Network ATC - two intents, drift-remediated, {0}, {1}" -f $frames, $pin)
    if ($lane -ne "atc") {
        $rdma = [string](Get-ConfigText -InputObject $networking -Name "rdma" -Default "disabled")
        $networkLine = ("manual - SET switch, direct storage links, RDMA {0}, {1}" -f $rdma, $frames)
    }
    Write-FastfetchInfoRow -Label "networking" -Value $networkLine -LabelWidth 24 -IndentWidth 2

    if ([bool](Get-ConfigValue -InputObject $Hyperv -Name "autoRestart" -Default $true)) {
        Write-FastfetchInfoRow -Label "restart" -Value (("{0}s countdown, then the run continues on its own" -f [int](Get-ConfigValue -InputObject $Hyperv -Name "autoRestartDelaySeconds" -Default 15))) -LabelWidth 24 -IndentWidth 2
    }
}

function Show-HypervSummary {
    param([object]$Hyperv)

    # The mode is the router here exactly as it is in the providers - the two builds
    # share a blade and a section name and nothing else.
    if (Test-HypervS2dMode -Hyperv $Hyperv) {
        Show-HypervS2dSummary -Hyperv $Hyperv
        return
    }

    Write-SummarySection -Title "Hyper-V"

    $state = "Install the role, then a restart"
    if (Test-HypervFeatureInstalled) {
        $state = "Installed - configure only"
        if (Test-HypervRebootPending) { $state = "Installed, restart still owed" }
    }
    Write-FastfetchInfoRow -Label "this run" -Value $state -LabelWidth 24 -IndentWidth 2

    $join = Get-ConfigValue -InputObject $Hyperv -Name "domainJoin"
    if (($null -ne $join) -and [bool](Get-ConfigValue -InputObject $join -Name "enabled" -Default $false)) {
        $ouPath = [string](Get-ConfigText -InputObject $join -Name "ouPath" -Default "")
        if ([string]::IsNullOrWhiteSpace($ouPath)) { $ouPath = "the default computers container" }
        Write-FastfetchInfoRow -Label "domain join" -Value ([string](Get-ConfigText -InputObject $join -Name "domain" -Default "?")) -LabelWidth 24 -IndentWidth 2
        Write-FastfetchInfoRow -Label "computer object" -Value $ouPath -LabelWidth 24 -IndentWidth 2
    }

    $cluster = Get-ConfigValue -InputObject $Hyperv -Name "cluster"
    $clustered = ($null -ne $cluster) -and [bool](Get-ConfigValue -InputObject $cluster -Name "enabled" -Default $false)
    if ($clustered) {
        $count = [int](Get-ConfigValue -InputObject $cluster -Name "csvCount" -Default 2)
        if ($count -lt 1) { $count = 1 }
        $prefix = [string](Get-ConfigText -InputObject $cluster -Name "csvNamePrefix" -Default "csv")
        if ([string]::IsNullOrWhiteSpace($prefix)) { $prefix = "csv" }
        $names = @()
        for ($index = 1; $index -le $count; $index++) { $names += ("{0}-{1:00}" -f $prefix, $index) }

        Write-FastfetchInfoRow -Label "failover cluster" -Value ("{0}, one node" -f (Get-ConfigText -InputObject $cluster -Name "name" -Default "hv-cl-01")) -LabelWidth 24 -IndentWidth 2
        Write-FastfetchInfoRow -Label "shared volumes" -Value (("{0}, {1} {2}" -f ($names -join ", "),
                (Get-ConfigText -InputObject $cluster -Name "fileSystem" -Default "NTFS"),
                (Get-ConfigValue -InputObject $cluster -Name "allocationUnitSize" -Default 65536))) -LabelWidth 24 -IndentWidth 2
        Write-FastfetchInfoRow -Label "virtual machines" -Value ("{0}\ClusterStorage\{1}" -f $env:SystemDrive, $names[0]) -LabelWidth 24 -IndentWidth 2
    }

    $storage = Get-ConfigValue -InputObject $Hyperv -Name "storage"
    if ((-not $clustered) -and ($null -ne $storage) -and [bool](Get-ConfigValue -InputObject $storage -Name "prepareDataVolume" -Default $true)) {
        $letter = ([string](Get-ConfigText -InputObject $storage -Name "driveLetter" -Default "D:")).Trim().TrimEnd(":", "\")
        $fileSystem = [string](Get-ConfigText -InputObject $storage -Name "fileSystem" -Default "ReFS")
        $unit = [int](Get-ConfigValue -InputObject $storage -Name "allocationUnitSize" -Default 4096)
        # The destructive line, on the screen that asks for confirmation.
        Write-FastfetchInfoRow -Label "data volume" -Value ("{0}: {1} {2}, if raw or empty" -f $letter, $fileSystem, $unit) -LabelWidth 24 -IndentWidth 2
        # The letter is taken rather than hoped for, and the occupant of it moves - which
        # belongs on the screen that asks for confirmation rather than in the log after.
        Write-FastfetchInfoRow -Label "drive letter" -Value ("{0}: whatever holds it is moved aside" -f $letter) -LabelWidth 24 -IndentWidth 2
        Write-FastfetchInfoRow -Label "virtual machines" -Value ("{0}:\{1}, disks in {0}:\{2}" -f $letter,
            [string](Get-ConfigText -InputObject $storage -Name "vmFolderName" -Default "vms"),
            [string](Get-ConfigText -InputObject $storage -Name "vhdFolderName" -Default "vhd")) -LabelWidth 24 -IndentWidth 2
    }

    if ([bool](Get-ConfigValue -InputObject $Hyperv -Name "serverCoreAppCompat" -Default $true)) {
        $source = [string](Get-ConfigText -InputObject $Hyperv -Name "appCompatSource" -Default "ask")
        $where = switch ($source) {
            "online" { "Windows Update" }
            "iso"    { "an ISO" }
            default  { "asked at the console, after a connectivity probe" }
        }
        Write-FastfetchInfoRow -Label "app compatibility" -Value ("Server Core only, from {0}" -f $where) -LabelWidth 24 -IndentWidth 2
    }

    $applied = @()
    if ([bool](Get-ConfigValue -InputObject $Hyperv -Name "highPerformancePowerPlan" -Default $true)) { $applied += "High Performance" }
    if ([bool](Get-ConfigValue -InputObject $Hyperv -Name "disableSmb1" -Default $true)) { $applied += "SMB1 off" }
    if ([bool](Get-ConfigValue -InputObject $Hyperv -Name "defenderExclusions" -Default $true)) { $applied += "Defender exclusions" }
    if ($applied.Count -gt 0) {
        Write-FastfetchInfoRow -Label "host settings" -Value ($applied -join ", ") -LabelWidth 24 -IndentWidth 2
    }

    if ([bool](Get-ConfigValue -InputObject $Hyperv -Name "configureSwitches" -Default $true)) {
        $naming = "left as Windows named them"
        if ([bool](Get-ConfigValue -InputObject $Hyperv -Name "renameTeamMembers" -Default $true)) {
            $prefix = Get-HypervAdapterNamePrefix -Prefix ([string](Get-ConfigText -InputObject $Hyperv -Name "adapterNamePrefix" -Default "nic"))
            # Named after the switch they end up under, which is asked for at the console
            # - so the summary shows the shape rather than a name it cannot know yet.
            $naming = "{0}-<switch>-01, {0}-<switch>-02, from one inside each switch" -f $prefix
        }
        Write-FastfetchInfoRow -Label "team members" -Value $naming -LabelWidth 24 -IndentWidth 2
    }

    if ([bool](Get-ConfigValue -InputObject $Hyperv -Name "autoRestart" -Default $true)) {
        Write-FastfetchInfoRow -Label "restart" -Value (("{0}s countdown, then the run continues on its own" -f [int](Get-ConfigValue -InputObject $Hyperv -Name "autoRestartDelaySeconds" -Default 15))) -LabelWidth 24 -IndentWidth 2
    }
}

function Show-ExchangeSummary {
    param([object]$Exchange)

    Write-SummarySection -Title "Exchange Server"
    $state = "Install from ISO, then configure"
    if (Test-ExchangeInstalled) { $state = "Installed - configure only" }
    Write-FastfetchInfoRow -Label "this run" -Value $state -LabelWidth 24 -IndentWidth 2

    Write-FastfetchInfoRow -Label "organization" -Value ([string](Get-ConfigText -InputObject $Exchange -Name "organizationName" -Default "?")) -LabelWidth 24 -IndentWidth 2

    # On the review screen because it is the one line here that can destroy something:
    # an empty volume that misses the specification gets reformatted. Said before the
    # run is confirmed, not after.
    $install = Get-ConfigValue -InputObject $Exchange -Name "install"
    $databasePath = [string](Get-ConfigText -InputObject $install -Name "databasePath" -Default "")
    if ((-not [string]::IsNullOrWhiteSpace($databasePath)) -and (-not (Test-ExchangeInstalled))) {
        $volumeNote = "inspected and reported only"
        if ([bool](Get-ConfigValue -InputObject $install -Name "prepareDatabaseVolume" -Default $true)) {
            $volumeNote = "ReFS 64K 'Database' if raw or empty"
        }
        Write-FastfetchInfoRow -Label "database volume" -Value ("{0} - {1}" -f $databasePath, $volumeNote) -LabelWidth 24 -IndentWidth 2
    }

    $namespace = Get-ConfigValue -InputObject $Exchange -Name "namespace"
    $hostName = [string](Get-ConfigText -InputObject $namespace -Name "hostName" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($hostName)) {
        Write-FastfetchInfoRow -Label "namespace" -Value $hostName -LabelWidth 24 -IndentWidth 2
    }

    $certificate = Get-ConfigValue -InputObject $Exchange -Name "certificate"
    Write-FastfetchInfoRow -Label "certificate" -Value ([string](Get-ConfigText -InputObject $certificate -Name "source" -Default "left alone")) -LabelWidth 24 -IndentWidth 2

    $hardening = Get-ConfigValue -InputObject $Exchange -Name "hardening"
    $applied = @()
    if ([bool](Get-ConfigValue -InputObject $hardening -Name "configureTls" -Default $true)) { $applied += "TLS 1.2 only" }
    if ([bool](Get-ConfigValue -InputObject $hardening -Name "disablePopImap" -Default $true)) { $applied += "POP/IMAP off" }
    if ([bool](Get-ConfigValue -InputObject $hardening -Name "verifyExtendedProtection" -Default $true)) { $applied += "EP verified" }
    if ($applied.Count -gt 0) {
        Write-FastfetchInfoRow -Label "hardening" -Value ($applied -join ", ") -LabelWidth 24 -IndentWidth 2
    }

    $relay = Get-ConfigValue -InputObject $Exchange -Name "relayConnector"
    if (($null -ne $relay) -and [bool](Get-ConfigValue -InputObject $relay -Name "enabled" -Default $false)) {
        $ranges = @(Get-ConfigArray -InputObject $relay -Name "remoteIpRanges")
        Write-FastfetchInfoRow -Label "relay connector" -Value ("{0} address(es), scoped" -f $ranges.Count) -LabelWidth 24 -IndentWidth 2
    }

    # Recipients, because "what will exist on this thing afterwards" is the question the
    # summary is for. Both counts, and the organizational unit sweep said out loud - it
    # is the one line here that acts on accounts the design never named.
    $mailboxes = Get-ConfigValue -InputObject $Exchange -Name "mailboxes"
    if ($null -ne $mailboxes) {
        $listed = @(Get-ConfigArray -InputObject $mailboxes -Name "users")
        $mailboxOu = [string](Get-ConfigText -InputObject $mailboxes -Name "organizationalUnit" -Default "")
        $mailboxText = "none"
        if ($listed.Count -gt 0) { $mailboxText = "{0} account(s)" -f $listed.Count }
        if (-not [string]::IsNullOrWhiteSpace($mailboxOu)) {
            $sweep = "everyone in $mailboxOu"
            $mailboxText = $(if ($listed.Count -gt 0) { "{0}, plus {1}" -f $mailboxText, $sweep } else { $sweep })
        }
        Write-FastfetchInfoRow -Label "user mailboxes" -Value $mailboxText -LabelWidth 24 -IndentWidth 2

        # The created half gets its own row, and counted per type: the two lines answer
        # different questions - one is "who gets enabled", this one is "what gets made".
        $resources = @(Get-ConfigArray -InputObject $mailboxes -Name "resources")
        if ($resources.Count -gt 0) {
            $parts = @()
            foreach ($type in @("Shared", "Room", "Equipment")) {
                $count = @($resources | Where-Object {
                    [string](Get-ConfigText -InputObject $_ -Name "type" -Default "shared") -eq $type.ToLower()
                }).Count
                if ($count -gt 0) { $parts += ("{0} {1}" -f $count, $type) }
            }
            if ($parts.Count -gt 0) {
                Write-FastfetchInfoRow -Label "created mailboxes" -Value ($parts -join ", ") -LabelWidth 24 -IndentWidth 2
            }
        }
    }

    $distribution = @(Get-ConfigArray -InputObject $Exchange -Name "distributionGroups")
    if ($distribution.Count -gt 0) {
        $names = @($distribution | ForEach-Object { [string](Get-ConfigText -InputObject $_ -Name "name" -Default "") } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        Write-FastfetchInfoRow -Label "distribution groups" -Value ($names -join ", ") -LabelWidth 24 -IndentWidth 2
    }

    if (-not (Test-ExchangeInstalled)) {
        Write-Host "    the install runs from the ISO in isos\ and takes the better part of an hour, then one reboot" -ForegroundColor DarkGray
    }
}

function Show-RunSummary {
    param(
        [object]$Config,
        [object[]]$Plan,
        [int]$RunnableStepCount,
        [Parameter(Mandatory)][string]$ConfigFilePath
    )

    Write-Host "  Source" -ForegroundColor White
    Write-FastfetchInfoRow -Label "config" -Value $ConfigFilePath -LabelWidth 24 -IndentWidth 2
    Write-FastfetchInfoRow -Label "this machine" -Value ([string]$env:COMPUTERNAME) -LabelWidth 24 -IndentWidth 2

    foreach ($role in @($script:roleRegistry | Sort-Object -Property Order)) {
        if (-not (Test-ConfigProperty -InputObject $Config -Name $role.Section)) { continue }
        $section = Get-ConfigValue -InputObject $Config -Name $role.Section
        switch ($role.Id) {
            "Hyper-V"            { Show-HypervSummary -Hyperv $section }
            "AD-Domain-Services" { Show-AddsSummary -ActiveDirectory $section }
            "DNS"                { Show-DnsSummary -Dns $section }
            "AD-Certificate"     { Show-AdcsSummary -CertificateServices $section }
            "File-Services"      { Show-FsSummary -FileServer $section }
            "AzureArc"           { Show-ArcSummary -AzureArc $section }
            "EntraPrivateNetworkConnector" { Show-ConnectorSummary -EntraConnector $section }
            "Remote-Desktop-Services" { Show-RdsSummary -RemoteDesktop $section }
            "Exchange-Server"    { Show-ExchangeSummary -Exchange $section }
        }
    }

    Write-SummarySection -Title "Run plan"
    for ($index = 0; $index -lt $Plan.Count; $index++) {
        $step = $Plan[$index]
        $note = "now"
        if ($index -ge $RunnableStepCount) { $note = "after the restart" }
        Write-FastfetchInfoRow -Label ("{0}. {1}" -f ($index + 1), $step.Stage.ToLowerInvariant()) -Value ("{0} ({1})" -f $step.Display, $note) -LabelWidth 24 -IndentWidth 2
    }

    Write-Host ""
    Write-Host ("  " + ("-" * 62)) -ForegroundColor DarkGray
    Write-Host ""
}

# The review screen is for a person about to change a server. A scheduled resume, a
# dry run and a redirected console are none of those things.
function Test-SummaryScreenWanted {
    if ($script:noGui) { return $false }
    if ($script:isResume) { return $false }
    if ($CheckOnly) { return $false }
    if (-not (Test-MenuHostSupported)) { return $false }

    try {
        if (-not [Environment]::UserInteractive) { return $false }
        if ([Console]::IsInputRedirected) { return $false }
    }
    catch {
        return $false
    }
    return $true
}

function Confirm-RunPlan {
    param(
        [object]$Config,
        [object[]]$Plan,
        [int]$RunnableStepCount,
        [Parameter(Mandatory)][string]$ConfigFilePath
    )

    # Deliberately NOT .GetNewClosure(). That binds the scriptblock to a fresh dynamic
    # module, and on Windows PowerShell 5.1 a module scope cannot see functions defined
    # at script scope - Show-RunSummary comes back as CommandNotFoundException. A plain
    # scriptblock keeps this script's session state, so the inputs travel in script
    # scope instead. (Lifting them there also stops PSScriptAnalyzer reporting the
    # parameters as unused, which it does for anything it only sees inside a block.)
    $script:summaryConfig = $Config
    $script:summaryPlan = $Plan
    $script:summaryRunnable = $RunnableStepCount
    $script:summaryPath = $ConfigFilePath

    $summary = {
        Show-RunSummary -Config $script:summaryConfig -Plan $script:summaryPlan `
            -RunnableStepCount $script:summaryRunnable -ConfigFilePath $script:summaryPath
    }

    $roleNames = @()
    foreach ($step in $Plan) {
        if ($roleNames -notcontains $step.Display) { $roleNames += $step.Display }
    }

    $status = [ordered]@{
        roles = ($roleNames -join ", ")
        steps = "$($Plan.Count) step(s), $RunnableStepCount runnable now"
    }

    $items = @(
        [pscustomobject]@{ Id = "continue"; Label = "Continue - apply this configuration" }
        [pscustomobject]@{ Id = "cancel";   Label = "Cancel - change nothing" }
    )

    $decision = Show-Menu -Title "Confirm role configuration" -Subtitle "Review everything below, then continue" `
        -Items $items -SelectedIndex 0 -PreItems $summary -StatusLines $status
    return ($decision -eq "continue")
}
