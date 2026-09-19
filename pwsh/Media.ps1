# Shared installation media handling: the arrow-key ISO picker and the mount/dismount
# tracking, lifted from the sibling HyperV-Scripts project where they were field-proven.
#
# Dot-sourced by Configure-ServerRoles.ps1 - not runnable on its own. Everything
# here lands in that script's scope, so $script: variables and functions are shared
# with every other part. Use $scriptRootPath, never $PSScriptRoot: inside this file
# $PSScriptRoot is the pwsh folder, not the folder the run was started from.
#
# The conventions travel with the code: media lives in isos\ next to the script (the
# picker opens there when the folder holds at least one .iso), a config carries a
# file path rather than a drive letter (mount points move between runs), and only
# ISOs this run mounted itself are dismounted on the way out.

# ISOs this run mounted itself. Anything already attached is somebody else's and is
# left exactly as it is.
$script:mountedIsoPaths = @()

function Get-StudioIsoBrowseRoot {
    $isoFolder = Join-Path -Path $scriptRootPath -ChildPath "isos"
    if (Test-Path -LiteralPath $isoFolder -PathType Container) {
        $found = @(Get-ChildItem -LiteralPath $isoFolder -File -Filter "*.iso" -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1)
        if ($found.Count -gt 0) { return $isoFolder }
    }
    return ":DRIVES"
}

function Get-StudioFilePickerEntry {
    # The current folder listing for the arrow-key browser: drives at the top level,
    # then folders and .iso files.
    param([string]$CurrentPath)

    $entries = @()

    if ([string]::IsNullOrWhiteSpace($CurrentPath) -or $CurrentPath -eq ":DRIVES") {
        $entries += [pscustomobject]@{ Id = ":CANCEL"; Kind = "action"; Label = "[ Cancel ]"; FullPath = "" }

        $drives = @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
            Where-Object { $_.Root -match '^[A-Za-z]:\\$' } |
            Sort-Object -Property Name)
        foreach ($drive in $drives) {
            $root = $drive.Root.TrimEnd('\')
            $labelExtra = ""
            try {
                $volume = Get-Volume -DriveLetter $drive.Name -ErrorAction SilentlyContinue
                if ($volume -and -not [string]::IsNullOrWhiteSpace($volume.FileSystemLabel)) {
                    $labelExtra = "  ($($volume.FileSystemLabel))"
                }
            }
            catch {
                Write-Log "Volume label for '$root' could not be read" -Tag "Debug"
            }
            $entries += [pscustomobject]@{ Id = $root; Kind = "drive"; Label = ("{0}\{1}" -f $root, $labelExtra).TrimEnd(); FullPath = "$root\" }
        }
        return $entries
    }

    if (-not (Test-Path -LiteralPath $CurrentPath -ErrorAction SilentlyContinue)) {
        return @([pscustomobject]@{ Id = ":DRIVES"; Kind = "nav"; Label = "..  (drives)"; FullPath = ":DRIVES" })
    }

    $parent = Split-Path -Path $CurrentPath -Parent
    if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $CurrentPath) {
        $entries += [pscustomobject]@{ Id = ":DRIVES"; Kind = "nav"; Label = "..  (drives)"; FullPath = ":DRIVES" }
    }
    else {
        $entries += [pscustomobject]@{ Id = $parent; Kind = "nav"; Label = ".."; FullPath = $parent }
    }

    try {
        $folders = @(Get-ChildItem -LiteralPath $CurrentPath -Directory -Force -ErrorAction Stop | Sort-Object -Property Name)
        foreach ($folder in $folders) {
            $entries += [pscustomobject]@{ Id = $folder.FullName; Kind = "dir"; Label = "[+] $($folder.Name)"; FullPath = $folder.FullName }
        }
    }
    catch {
        $entries += [pscustomobject]@{ Id = ":ERROR"; Kind = "action"; Label = "(cannot list folders: $($_.Exception.Message))"; FullPath = "" }
    }

    try {
        $isoFiles = @(Get-ChildItem -LiteralPath $CurrentPath -File -Force -ErrorAction Stop |
            Where-Object { $_.Extension -match '^\.iso$' } |
            Sort-Object -Property Name)
        foreach ($isoFile in $isoFiles) {
            $sizeGb = [math]::Round($isoFile.Length / 1GB, 2)
            $entries += [pscustomobject]@{ Id = $isoFile.FullName; Kind = "iso"; Label = "$($isoFile.Name)  (${sizeGb} GB)"; FullPath = $isoFile.FullName }
        }
    }
    catch {
        Write-Log "Files in '$CurrentPath' could not be listed" -Tag "Debug"
    }

    return $entries
}

function Show-StudioIsoPicker {
    # Arrow-key file browser: drives -> folders -> select a .iso file. Falls back to
    # numbered selection where the host has no RawUI (a redirected console).
    param(
        [string]$StartPath = ":DRIVES",
        [string]$Title = "Select ISO file",
        [string]$Subtitle = "Enter opens folder / selects .iso - Esc goes back"
    )

    $currentPath = $StartPath
    $index = 0
    $useRawUi = Test-MenuHostSupported

    while ($true) {
        $entries = @(Get-StudioFilePickerEntry -CurrentPath $currentPath)
        if ($entries.Count -eq 0) {
            $entries = @([pscustomobject]@{ Id = ":DRIVES"; Kind = "nav"; Label = "..  (drives)"; FullPath = ":DRIVES" })
        }
        if ($index -ge $entries.Count) { $index = $entries.Count - 1 }
        if ($index -lt 0) { $index = 0 }

        $displayPath = $currentPath
        if ($displayPath -eq ":DRIVES") { $displayPath = "This PC (drives)" }
        Show-MenuHeader -Title $Title -Subtitle $Subtitle -StatusLines ([ordered]@{ path = $displayPath })

        $maxVisible = 16
        $windowStart = 0
        if ($entries.Count -gt $maxVisible) {
            $windowStart = $index - [math]::Floor($maxVisible / 2)
            if ($windowStart -lt 0) { $windowStart = 0 }
            if (($windowStart + $maxVisible) -gt $entries.Count) { $windowStart = $entries.Count - $maxVisible }
        }
        $windowEnd = [math]::Min(($windowStart + $maxVisible - 1), ($entries.Count - 1))

        if ($windowStart -gt 0) { Write-Studio -Text "    ..." -Key "muted" }
        for ($i = $windowStart; $i -le $windowEnd; $i++) {
            $entry = $entries[$i]
            # Palette keys, not ConsoleColor names - see Write-Studio in Logging.ps1.
            $color = "fg"
            if ($entry.Kind -eq "iso") { $color = "accent" }
            elseif ($entry.Kind -eq "dir" -or $entry.Kind -eq "drive") { $color = "warn" }
            elseif ($entry.Kind -eq "nav") { $color = "muted" }

            if ($i -eq $index) {
                Write-Studio -Text "  > " -Key "accent" -NoNewline
                Write-Studio -Text $entry.Label -Key "fg"
            }
            else {
                Write-Host "    " -NoNewline
                Write-Studio -Text $entry.Label -Key $color
            }
        }
        if ($windowEnd -lt ($entries.Count - 1)) { Write-Studio -Text "    ..." -Key "muted" }

        Write-Host ""
        if (-not $useRawUi) { Write-Studio -Text "  Enter a number, or blank to cancel." -Key "muted" }

        $chosen = $null
        if ($useRawUi) {
            $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            switch ($key.VirtualKeyCode) {
                38 { $index--; continue }              # Up
                40 { $index++; continue }              # Down
                27 { return $null }                    # Esc
                13 { $chosen = $entries[$index] }      # Enter
                default { continue }
            }
        }
        else {
            $raw = Read-Host "Selection"
            if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
            if ($raw -notmatch '^\d+$') { continue }
            $number = [int]$raw
            if ($number -lt 1 -or $number -gt $entries.Count) { continue }
            $chosen = $entries[$number - 1]
        }

        if ($chosen.Kind -eq "action") {
            if ($chosen.Id -eq ":CANCEL") { return $null }
            continue
        }
        if ($chosen.Kind -eq "nav" -or $chosen.Kind -eq "dir" -or $chosen.Kind -eq "drive") {
            $currentPath = $chosen.FullPath
            $index = 0
            continue
        }
        if ($chosen.Kind -eq "iso") { return $chosen.FullPath }
    }
}

function Mount-StudioIso {
    # Mounts an ISO, returns its drive root (e.g. "E:"), and tracks it for dismount
    # at exit. An image already attached is used as it is and never tracked - it was
    # not this run's to dismount.
    param([Parameter(Mandatory)][string]$IsoFilePath)

    if (-not (Test-Path -LiteralPath $IsoFilePath -PathType Leaf)) {
        throw "ISO file not found: $IsoFilePath"
    }

    $existing = Get-DiskImage -ImagePath $IsoFilePath -ErrorAction SilentlyContinue
    if ($existing -and $existing.Attached) {
        Write-Log "ISO already mounted: $IsoFilePath" -Tag "Debug"
    }
    else {
        Write-Log "Mounting ISO '$IsoFilePath'" -Tag "Run"
        Mount-DiskImage -ImagePath $IsoFilePath -ErrorAction Stop | Out-Null
        if ($script:mountedIsoPaths -notcontains $IsoFilePath) {
            $script:mountedIsoPaths += $IsoFilePath
        }
    }

    # The drive letter arrives a beat after the mount - same race as certsvc's RPC
    # interface, same answer: poll briefly rather than fail on the fast machines.
    $volume = $null
    for ($attempt = 1; $attempt -le 10; $attempt++) {
        $diskImage = Get-DiskImage -ImagePath $IsoFilePath -ErrorAction SilentlyContinue
        if ($diskImage) {
            $volume = $diskImage | Get-Volume -ErrorAction SilentlyContinue |
                Where-Object { $_.DriveLetter } | Select-Object -First 1
        }
        if ($volume) { break }
        Start-Sleep -Milliseconds 300
    }

    if (-not $volume -or -not $volume.DriveLetter) {
        throw "ISO mounted but no drive letter was assigned"
    }
    return "$($volume.DriveLetter):"
}

# One image, released as soon as the role that mounted it is done with it - and dropped
# from the tracking list, so the sweep at the end of the run does not try a second time
# and log a failure for something that already worked.
function Dismount-StudioIsoPath {
    param([Parameter(Mandatory)][string]$IsoFilePath)

    if ($script:mountedIsoPaths -notcontains $IsoFilePath) {
        # Not this run's mount. Somebody else attached it, so it stays attached.
        return $false
    }
    try {
        Dismount-DiskImage -ImagePath $IsoFilePath -ErrorAction Stop | Out-Null
        Write-Log "Dismounted ISO '$IsoFilePath'" -Tag "Info"
    }
    catch {
        Write-Log "Could not dismount ISO '$IsoFilePath': $($_.Exception.Message)" -Tag "Info"
        return $false
    }
    $script:mountedIsoPaths = @($script:mountedIsoPaths | Where-Object { $_ -ne $IsoFilePath })
    return $true
}

function Dismount-StudioIso {
    foreach ($isoPath in @($script:mountedIsoPaths)) {
        try {
            Dismount-DiskImage -ImagePath $isoPath -ErrorAction Stop | Out-Null
            Write-Log "Dismounted ISO '$isoPath'" -Tag "Info"
        }
        catch {
            Write-Log "Could not dismount ISO '$isoPath': $($_.Exception.Message)" -Tag "Info"
        }
    }
    $script:mountedIsoPaths = @()
}

# Resolve where the installation media is: an explicit path from the config (a file
# or a glob under isos\), or the interactive picker when there is a console to ask.
# Returns the .iso path, or "" - the caller says what that means for its role.
function Resolve-StudioIsoPath {
    param(
        [string]$ConfiguredPath = "",
        [string]$Title = "Select ISO file",
        [switch]$NoInteraction
    )

    if (-not [string]::IsNullOrWhiteSpace($ConfiguredPath)) {
        $candidate = $ConfiguredPath
        if (-not [System.IO.Path]::IsPathRooted($candidate)) {
            $candidate = Join-Path -Path $scriptRootPath -ChildPath $candidate
        }
        # A glob, so a config can say "isos\ExchangeServer*.iso" and survive a CU
        # bump without an edit. Newest match wins - a folder holding two CUs means
        # the newer one.
        $matched = @(Get-ChildItem -Path $candidate -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -match '^\.iso$' } |
            Sort-Object -Property LastWriteTime -Descending)
        if ($matched.Count -gt 0) { return $matched[0].FullName }
        Write-Log "No .iso matches '$ConfiguredPath'" -Tag "Error"
        return ""
    }

    if ($NoInteraction) {
        Write-Log "No media path in the config and no console to ask - set the ISO path in the design" -Tag "Error"
        return ""
    }

    $picked = Show-StudioIsoPicker -StartPath (Get-StudioIsoBrowseRoot) -Title $Title
    if ($null -eq $picked) { return "" }
    return [string]$picked
}
