#Requires -Version 5.1
# ---------------------------[ Data volumes ]---------------------------
# Preparing a data volume to a stated specification, shared by every role that owns one.
#
# It exists because the check that noticed the problem ran too late to fix it. The
# Exchange role inspected its database volume in the *post-install* pass, correctly
# reported "the allocation unit is 4096, Microsoft's best practice is 65536", and
# correctly added that only a reformat changes it - on a volume that by then held a
# mailbox database. The drive letter was in config.json the whole time, so the one
# moment that could have fixed it was before setup ran.
#
# **There is no default here, on purpose.** Every parameter is mandatory and every role
# states its own numbers in its own file. The two specifications this repo carries are
# not the same and must never converge on a shared default:
#
#   Exchange database volume   ReFS, 64K allocation unit, integrity streams off, label
#                              'Database'. Microsoft's Exchange storage table: "Best
#                              practice: 64 KB for both .edb and log file volumes", and
#                              data integrity features "must be disabled" for the .edb
#                              files or the volume hosting them.
#   Hyper-V virtual machines   ReFS, label 'Hyper-V', its own allocation unit decision -
#                              the ReFS documentation says 4K for most deployments and
#                              64K for large sequential IO, which is a different question
#                              from Exchange's and gets a different answer.
#
# A default in this file is exactly how one role's specification quietly becomes the
# other's, so this file holds none.

# What is on a volume, ignoring the two folders Windows puts there itself. A volume
# holding only these is empty for the purpose of deciding whether a format destroys
# anything - and that decision is the whole safety of this file, so it is written once.
# Single quotes are not a style choice here: "$RECYCLE.BIN" in double quotes is the
# variable $RECYCLE followed by a literal '.BIN', which expands to '.BIN' and matches
# nothing - so a recycle bin would count as data and refuse every format.
$script:storageIgnoredEntry = @("System Volume Information", '$RECYCLE.BIN', '$Recycle.Bin', "RECYCLER")

function Test-StudioVolumeEmpty {
    param([Parameter(Mandatory)][string]$DriveLetter)

    $root = "$($DriveLetter):\"
    $entries = @()
    try {
        $entries = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop |
            Where-Object { $script:storageIgnoredEntry -notcontains $_.Name })
    }
    catch {
        # Unreadable is not empty. Anything that cannot be listed is treated as holding
        # something, which keeps the format on the safe side of the question.
        Write-Log "'$root' could not be listed, so it is treated as holding data: $($_.Exception.Message)" -Tag "Warn"
        return $false
    }
    return ($entries.Count -eq 0)
}

# A volume that reports no file system at all. This is NOT the same question as
# Test-StudioVolumeEmpty and must not be answered by it: that function treats anything it
# cannot list as holding data, which is right for a volume it cannot read and exactly
# wrong for one with no file system, where there is nowhere for data to be. A partition
# somebody created and never formatted came back "it holds data, so it is left exactly as
# it is" and Ready = $true, and the caller then built shares on a drive letter that could
# not be written to at all.
#
# BitLocker is the one case where "no file system visible" means the file system is right
# there, encrypted - a locked volume reports Unknown too. That is checked before anything
# calls this a blank volume, because formatting it would destroy the data it is hiding.
function Test-StudioVolumeUnformatted {
    param([Parameter(Mandatory)][object]$Volume)

    $type = ([string]$Volume.FileSystemType).Trim()
    $name = ([string]$Volume.FileSystem).Trim()
    $blank = @("", "Unknown", "RAW")
    if (($blank -notcontains $type) -or ($blank -notcontains $name)) { return $false }

    $letter = ([string]$Volume.DriveLetter).Trim()
    if ((-not [string]::IsNullOrWhiteSpace($letter)) -and
        (Get-Command -Name "Get-BitLockerVolume" -ErrorAction SilentlyContinue)) {
        try {
            $protected = Get-BitLockerVolume -MountPoint ("{0}:" -f $letter) -ErrorAction Stop
            if ($null -ne $protected) {
                if (([string]$protected.LockStatus -eq "Locked") -or ([string]$protected.ProtectionStatus -ne "Off")) {
                    Write-Log "${letter}: reports no file system because BitLocker holds it - it is never formatted here" -Tag "Warn"
                    return $false
                }
            }
        }
        catch {
            # Not a BitLocker volume, or the service is not running. Either way there is
            # no protector to destroy, and the blank verdict stands.
            Write-Log "BitLocker had nothing to say about ${letter}: $($_.Exception.Message)" -Tag "Debug"
        }
    }
    return $true
}

# The system drive, whatever letter it happens to have. Compared by letter rather than
# by the IsBoot/IsSystem flags alone, because a caller naming C: deserves the refusal
# before any disk enumeration decides anything.
function Test-StudioSystemDriveLetter {
    param([Parameter(Mandatory)][string]$DriveLetter)

    $systemLetter = ([string]$env:SystemDrive).TrimEnd(":", "\")
    if ([string]::IsNullOrWhiteSpace($systemLetter)) { return $false }
    return $DriveLetter.Equals($systemLetter, [System.StringComparison]::OrdinalIgnoreCase)
}

# ---------------------------[ Drive letters ]---------------------------
# The letter the design asked for is the letter the volume gets. Windows hands D: to the
# DVD drive on a default installation, so on a great many servers the letter a design
# names is already taken by something that is not a disk at all - and the old behaviour
# there was the worst possible one: Get-Volume answered with the optical volume, the
# filesystem did not match, the volume "held data", and the run pointed a role's folders
# at a DVD.
#
# So the occupant is moved out of the way rather than worked around. Moving a drive
# letter destroys nothing; it does break paths that were written down against the old
# one, which is why the boot, system and page file volumes are refused outright and
# every move is logged as old -> new.
$script:storageLetterFloor = [int][char]"E"

function Get-StudioUsedDriveLetter {
    $used = @()
    try { $used += @(Get-CimInstance -ClassName "Win32_LogicalDisk" -ErrorAction Stop | ForEach-Object { ([string]$_.DeviceID).TrimEnd(":") }) }
    catch { }
    try { $used += @(Get-Volume -ErrorAction Stop | Where-Object { $_.DriveLetter } | ForEach-Object { [string]$_.DriveLetter }) }
    catch { }
    return @($used | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.ToUpperInvariant() } | Select-Object -Unique)
}

# Somewhere to put whatever was in the way. Counted down from Z so the eviction lands
# far from the letters a design is likely to name next.
function Get-StudioFreeDriveLetter {
    $used = @(Get-StudioUsedDriveLetter)
    for ($code = [int][char]"Z"; $code -ge $script:storageLetterFloor; $code--) {
        $letter = [string][char]$code
        if ($used -notcontains $letter) { return $letter }
    }
    return ""
}

# Whether the page file lives on this letter. A volume carrying one cannot be re-lettered
# without Windows losing its page file at the next boot.
function Test-StudioPageFileLetter {
    param([Parameter(Mandatory)][string]$DriveLetter)

    try {
        $pageFiles = @(Get-CimInstance -ClassName "Win32_PageFileUsage" -ErrorAction Stop)
        foreach ($pageFile in $pageFiles) {
            $name = [string]$pageFile.Name
            if ($name.StartsWith("$($DriveLetter):", [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        }
    }
    catch { }
    return $false
}

# Free the letter, whatever is holding it. Returns $true when the letter is free
# afterwards - including the case where it was free to begin with.
function Clear-StudioDriveLetter {
    param([Parameter(Mandatory)][string]$DriveLetter)

    if (Test-StudioSystemDriveLetter -DriveLetter $DriveLetter) {
        Write-Log "${DriveLetter}: is the system drive and is never moved out of the way" -Tag "Error"
        return $false
    }
    if (Test-StudioPageFileLetter -DriveLetter $DriveLetter) {
        Write-Log "${DriveLetter}: carries the page file, so its letter is left where it is" -Tag "Error"
        return $false
    }

    # A partition first: that is the disk case, and Set-Partition is the cmdlet that
    # knows about it. Win32_Volume below catches everything else - an optical drive, a
    # volume without a partition object - which is exactly where the DVD lands.
    $partition = $null
    try { $partition = Get-Partition -DriveLetter $DriveLetter -ErrorAction Stop } catch { $partition = $null }

    if ($null -ne $partition) {
        $disk = $null
        try { $disk = Get-Disk -Number $partition.DiskNumber -ErrorAction Stop } catch { $disk = $null }
        if (($null -ne $disk) -and ($disk.IsBoot -or $disk.IsSystem) -and ($partition.Type -match "(?i)system|reserved|recovery")) {
            Write-Log "${DriveLetter}: is a system or recovery partition and is never re-lettered" -Tag "Error"
            return $false
        }

        $free = Get-StudioFreeDriveLetter
        if ([string]::IsNullOrWhiteSpace($free)) {
            Write-Log "${DriveLetter}: is taken and there is no free letter to move the occupant to" -Tag "Error"
            return $false
        }
        try {
            Set-Partition -DriveLetter $DriveLetter -NewDriveLetter $free -ErrorAction Stop
            Write-Log "${DriveLetter}: was held by a volume on disk $($partition.DiskNumber) - moved to ${free}: so the design gets its letter" -Tag "Warn"
            return $true
        }
        catch {
            Write-Log "${DriveLetter}: could not be freed: $($_.Exception.Message)" -Tag "Error"
            return $false
        }
    }

    $volume = $null
    try { $volume = @(Get-CimInstance -ClassName "Win32_Volume" -Filter "DriveLetter='$($DriveLetter):'" -ErrorAction Stop)[0] }
    catch { $volume = $null }
    if ($null -eq $volume) { return $true }

    $free = Get-StudioFreeDriveLetter
    if ([string]::IsNullOrWhiteSpace($free)) {
        Write-Log "${DriveLetter}: is taken and there is no free letter to move the occupant to" -Tag "Error"
        return $false
    }
    # DriveType 5 is a CD-ROM, which on a default Windows installation is exactly what is
    # sitting on D: - the letter more designs name than any other.
    $what = if ([int]$volume.DriveType -eq 5) { "the optical drive" } else { "a volume" }
    try {
        $null = Set-CimInstance -InputObject $volume -Property @{ DriveLetter = "$($free):" } -ErrorAction Stop
        Write-Log "${DriveLetter}: was $what - moved to ${free}: so the design gets the letter it asked for" -Tag "Warn"
        return $true
    }
    catch {
        Write-Log "${DriveLetter}: is held by $what and could not be moved: $($_.Exception.Message)" -Tag "Error"
        Write-Log "    By hand: mountvol ${DriveLetter}: /D   then assign it in Disk Management" -Tag "Info"
        return $false
    }
}

function Format-StudioDataVolume {
    param(
        [Parameter(Mandatory)][string]$DriveLetter,
        [Parameter(Mandatory)][string]$FileSystem,
        [Parameter(Mandatory)][int]$AllocationUnitSize,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][bool]$IntegrityStreams,
        # NTFS only, and the mirror image of $IntegrityStreams above: 4 KB file record
        # segments instead of 1 KB. Microsoft names it in one breath with 64K allocation
        # units, for volumes used with Data Deduplication or hosting large .vhdx files -
        # a file whose extents outgrow its record stops being extendable, which on a
        # profile container volume is a container that will not grow.
        [bool]$LargeFileRecordSegments = $false
    )

    $parameters = @{
        DriveLetter        = $DriveLetter
        FileSystem         = $FileSystem
        AllocationUnitSize = $AllocationUnitSize
        NewFileSystemLabel = $Label
        Force              = $true
        Confirm            = $false
        ErrorAction        = "Stop"
    }
    # ReFS only. NTFS has no such thing, and naming the parameter there is a
    # parameter-binding error rather than a setting that is ignored.
    if ($FileSystem -match "(?i)refs") { $parameters["SetIntegrityStreams"] = $IntegrityStreams }
    # And the same rule the other way: -UseLargeFRS is an NTFS switch, and naming it on a
    # ReFS format is a binding error rather than a setting that is ignored.
    elseif ($LargeFileRecordSegments) { $parameters["UseLargeFRS"] = $true }

    Write-Log ("Formatting {0}: as {1}, {2} byte allocation unit, label '{3}'{4}" -f $DriveLetter, $FileSystem,
        $AllocationUnitSize, $Label, $(if ($parameters.ContainsKey("UseLargeFRS")) { ", large file record segments" } else { "" })) -Tag "Run"
    $null = Format-Volume @parameters
    Write-Log "${DriveLetter}: is formatted" -Tag "Ok"
}

# A raw disk this run may claim, or $null. Only ever one: two candidates is a question
# about which disk holds what, and that is not a question a script gets to answer.
function Get-StudioClaimableDisk {
    if (-not (Get-Command -Name "Get-Disk" -ErrorAction SilentlyContinue)) { return $null }

    $candidates = @()
    try {
        $candidates = @(Get-Disk -ErrorAction Stop | Where-Object {
                ($_.PartitionStyle -eq "RAW") -and (-not $_.IsBoot) -and (-not $_.IsSystem) -and (-not $_.IsClustered)
            })
    }
    catch {
        Write-Log "The disks could not be read: $($_.Exception.Message)" -Tag "Warn"
        return $null
    }

    if ($candidates.Count -eq 0) { return $null }
    if ($candidates.Count -gt 1) {
        Write-Log "There is more than one uninitialised disk here, so none is claimed automatically:" -Tag "Warn"
        foreach ($candidate in $candidates) {
            Write-Log ("    disk {0}  {1} GB  {2}  serial {3}" -f $candidate.Number,
                [math]::Round($candidate.Size / 1GB), $candidate.BusType, $candidate.SerialNumber) -Tag "Warn"
        }
        Write-Log "Initialise and format the one you mean, then run this again" -Tag "Warn"
        return $null
    }
    return $candidates[0]
}

# Bring a raw disk up as a single volume at the letter asked for. Separate from the
# format above because the two failures read differently: a disk that cannot be
# partitioned is a hardware answer, a volume that cannot be formatted is a filesystem one.
function New-StudioDataVolume {
    param(
        [Parameter(Mandatory)][object]$Disk,
        [Parameter(Mandatory)][string]$DriveLetter
    )

    Write-Log ("Claiming uninitialised disk {0} - {1} GB, {2}, serial {3}" -f $Disk.Number,
        [math]::Round($Disk.Size / 1GB), $Disk.BusType, $Disk.SerialNumber) -Tag "Run"

    if ($Disk.IsOffline) {
        $null = Set-Disk -Number $Disk.Number -IsOffline $false -ErrorAction Stop
        Write-Log "Disk $($Disk.Number) brought online" -Tag "Info"
    }
    if ($Disk.IsReadOnly) {
        $null = Set-Disk -Number $Disk.Number -IsReadOnly $false -ErrorAction Stop
        Write-Log "Disk $($Disk.Number) cleared of its read-only flag" -Tag "Info"
    }

    # GPT, which is Microsoft's stated best practice for an Exchange volume and the only
    # sane answer above 2 TB anywhere else.
    $null = Initialize-Disk -Number $Disk.Number -PartitionStyle GPT -ErrorAction Stop
    $null = New-Partition -DiskNumber $Disk.Number -UseMaximumSize -DriveLetter $DriveLetter -ErrorAction Stop
    Write-Log "Disk $($Disk.Number) initialised as GPT with one partition at ${DriveLetter}:" -Tag "Ok"
}

# ---------------------------[ Unallocated space ]---------------------------
# The disk that is already initialised and still has room on it, which is the ordinary
# server rather than the exception: two disks in a RAID 1, one array, a 64 GB system
# partition and the rest of it unallocated. Nothing above sees that disk - it is not RAW,
# so it is not claimable, and it carries partitions, so it cannot be pooled - and the run
# used to end at "there is no D: and no uninitialised disk to build it from" on the most
# common layout there is.
#
# The boot disk is allowed here and nowhere else, and the reason is the whole difference
# between this path and the one above it: a partition built in free space initialises
# nothing, clears nothing and moves nothing. It only fills space that was empty.
$script:storageFreeSpaceMinimumBytes = 8GB

# A byte count the way a human reads one off a disk label: GB up to a terabyte, TB above
# it, one decimal either way. 931 GB and 1.0 TB are the same disk and a list that says
# "1000" for one and "931" for the other is a list nobody can check against the hardware.
function Format-StudioCapacity {
    param([long]$Bytes)

    if ($Bytes -le 0) { return "unknown size" }
    if ($Bytes -ge 1TB) { return ("{0:N1} TB" -f ($Bytes / 1TB)) }
    if ($Bytes -ge 1GB) { return ("{0:N0} GB" -f ($Bytes / 1GB)) }
    return ("{0:N0} MB" -f ($Bytes / 1MB))
}

# The Get-PhysicalDisk behind a Get-Disk, which is where the media type, the spindle speed
# and Windows' own poolable/not-poolable answer live. Matched on UniqueId first because it
# is the identity both objects agree on; DeviceId against the disk number is the fallback
# for the adapters that do not report one.
# Read once and kept, because the detail line for every disk on a menu would otherwise
# enumerate every physical disk on the machine once per row. Nothing changes underneath an
# interview; -Refresh is there for the leg that has just cleared a disk.
$script:storagePhysicalDiskCache = $null

function Get-StudioPhysicalDiskList {
    param([switch]$Refresh)

    if ($Refresh) { $script:storagePhysicalDiskCache = $null }
    if ($null -ne $script:storagePhysicalDiskCache) { return @($script:storagePhysicalDiskCache) }
    if (-not (Get-Command -Name "Get-PhysicalDisk" -ErrorAction SilentlyContinue)) { return @() }

    try { $script:storagePhysicalDiskCache = @(Get-PhysicalDisk -ErrorAction Stop) }
    catch { $script:storagePhysicalDiskCache = @() }
    return @($script:storagePhysicalDiskCache)
}

function Get-StudioPhysicalDiskFor {
    param([Parameter(Mandatory)][object]$Disk)

    $physical = @(Get-StudioPhysicalDiskList)
    if ($physical.Count -eq 0) { return $null }

    $unique = [string]$Disk.UniqueId
    if (-not [string]::IsNullOrWhiteSpace($unique)) {
        $match = @($physical | Where-Object { [string]$_.UniqueId -eq $unique })
        if ($match.Count -gt 0) { return $match[0] }
    }
    $match = @($physical | Where-Object { [string]$_.DeviceId -eq [string]$Disk.Number })
    if ($match.Count -gt 0) { return $match[0] }
    return $null
}

# How a disk is addressed at 512 or 4096 bytes a sector, in the two words the industry
# uses for it. It decides what a file system can be laid out on, and a 4Kn disk beside a
# 512e one in the same pool is worth seeing before the pool is built rather than after.
function Get-StudioSectorFormat {
    param([Parameter(Mandatory)][object]$Disk)

    $logical = 0
    $physical = 0
    try { $logical = [int]$Disk.LogicalSectorSize } catch { $logical = 0 }
    try { $physical = [int]$Disk.PhysicalSectorSize } catch { $physical = 0 }
    if (($logical -le 0) -or ($physical -le 0)) { return "" }

    if (($logical -eq 512) -and ($physical -eq 512)) { return "512n" }
    if (($logical -eq 512) -and ($physical -eq 4096)) { return "512e" }
    if (($logical -eq 4096) -and ($physical -eq 4096)) { return "4Kn" }
    return ("{0}/{1} byte sectors" -f $logical, $physical)
}

# Everything needed to tell one disk from the one below it, on the screen that asks which
# one to take. A disk is identified by what is written on it - the model, the serial, the
# bay it sits in - and "disk 3, 512 GB" is not that on a server with four of them.
#
# Two lines, and the split is deliberate: what the disk **is**, then what state it is
# **in**. Anything unreadable is left out rather than printed empty - a virtual disk has no
# serial and no PCIe slot, and a row of "unknown" teaches nobody anything.
function Get-StudioDiskDetail {
    param(
        [object]$Disk = $null,
        [object]$Physical = $null
    )

    if (($null -eq $Disk) -and ($null -eq $Physical)) { return @() }
    if ($null -eq $Physical) { $Physical = Get-StudioPhysicalDiskFor -Disk $Disk }
    if (($null -eq $Disk) -and (Get-Command -Name "Get-Disk" -ErrorAction SilentlyContinue)) {
        # Came in from the pool screen, which enumerates physical disks. The Get-Disk side
        # carries the firmware, the sector format and the partition table.
        try { $Disk = @(Get-Disk -ErrorAction Stop | Where-Object { [string]$_.UniqueId -eq [string]$Physical.UniqueId })[0] }
        catch { $Disk = $null }
        if ($null -eq $Disk) {
            try { $Disk = Get-Disk -Number ([int]$Physical.DeviceId) -ErrorAction Stop } catch { $Disk = $null }
        }
    }

    # What it is. Model first: it is what the invoice and the sticker say.
    $identity = @()
    $model = ""
    foreach ($value in @([string]$Disk.Model, [string]$Physical.Model, [string]$Disk.FriendlyName, [string]$Physical.FriendlyName)) {
        if (-not [string]::IsNullOrWhiteSpace($value)) { $model = $value.Trim(); break }
    }
    $vendor = ""
    foreach ($value in @([string]$Disk.Manufacturer, [string]$Physical.Manufacturer)) {
        if (-not [string]::IsNullOrWhiteSpace($value)) { $vendor = $value.Trim(); break }
    }
    if ((-not [string]::IsNullOrWhiteSpace($vendor)) -and ($model -notlike ("*" + $vendor + "*"))) {
        $model = ($vendor + " " + $model).Trim()
    }
    if ([string]::IsNullOrWhiteSpace($model)) { $model = "unnamed disk" }
    $identity += $model

    $firmware = ""
    foreach ($value in @([string]$Disk.FirmwareVersion, [string]$Physical.FirmwareVersion)) {
        if (-not [string]::IsNullOrWhiteSpace($value)) { $firmware = $value.Trim(); break }
    }
    if (-not [string]::IsNullOrWhiteSpace($firmware)) { $identity += ("firmware " + $firmware) }

    $serial = ""
    foreach ($value in @([string]$Disk.SerialNumber, [string]$Physical.SerialNumber)) {
        if (-not [string]::IsNullOrWhiteSpace($value)) { $serial = $value.Trim(); break }
    }
    if (-not [string]::IsNullOrWhiteSpace($serial)) { $identity += ("serial " + $serial) }

    # Where it sits. The bay, when the enclosure reports one - that is what somebody
    # standing in front of the rack pulls out.
    $location = ""
    foreach ($value in @([string]$Physical.PhysicalLocation, [string]$Disk.Location)) {
        if (-not [string]::IsNullOrWhiteSpace($value)) { $location = $value.Trim(); break }
    }
    if ($location.Length -gt 64) { $location = $location.Substring(0, 61) + "..." }
    if (-not [string]::IsNullOrWhiteSpace($location)) { $identity += $location }

    # What state it is in. The bus type is deliberately not repeated here - every menu
    # this feeds already carries it on the line above.
    $state = @()
    $media = [string]$Physical.MediaType
    if ((-not [string]::IsNullOrWhiteSpace($media)) -and ($media -ne "Unspecified")) {
        $spindle = 0
        try { $spindle = [int]$Physical.SpindleSpeed } catch { $spindle = 0 }
        if (($spindle -gt 0) -and ($spindle -lt 100000)) { $media = ("{0} {1} rpm" -f $media, $spindle) }
        $state += $media
    }

    $sectors = ""
    if ($null -ne $Disk) { $sectors = Get-StudioSectorFormat -Disk $Disk }
    if (-not [string]::IsNullOrWhiteSpace($sectors)) { $state += $sectors }

    $health = [string]$Disk.HealthStatus
    if ([string]::IsNullOrWhiteSpace($health)) { $health = [string]$Physical.HealthStatus }
    if ((-not [string]::IsNullOrWhiteSpace($health)) -and ($health -ne "Healthy")) { $state += ("health " + $health) }

    if ($Disk.IsOffline) {
        $reason = [string]$Disk.OfflineReason
        if ([string]::IsNullOrWhiteSpace($reason)) { $state += "offline" }
        else { $state += ("offline: " + $reason) }
    }
    if ($Disk.IsReadOnly) { $state += "read only" }

    # Windows' own answer to "can this go in a pool", and the reason when it is no. It is
    # the one line that explains a disk being on the list and refused later.
    if ($null -ne $Physical) {
        if ([bool]$Physical.CanPool) { $state += "poolable" }
        else {
            $reason = [string]$Physical.CannotPoolReason
            if ([string]::IsNullOrWhiteSpace($reason)) { $state += "not poolable" }
            else { $state += ("not poolable: " + $reason) }
        }
    }

    $lines = @()
    if ($identity.Count -gt 0) { $lines += ($identity -join "   ") }
    if ($state.Count -gt 0) { $lines += ($state -join "   ") }
    return @($lines)
}

function Get-StudioFreeSpaceDisk {
    param([long]$MinimumBytes = $script:storageFreeSpaceMinimumBytes)

    if (-not (Get-Command -Name "Get-Disk" -ErrorAction SilentlyContinue)) { return @() }
    try {
        return @(Get-Disk -ErrorAction Stop | Where-Object {
                ($_.PartitionStyle -ne "RAW") -and (-not $_.IsClustered) -and
                ($null -ne $_.LargestFreeExtent) -and ([long]$_.LargestFreeExtent -ge $MinimumBytes)
            } | Sort-Object -Property Number)
    }
    catch {
        Write-Log "The disks could not be read: $($_.Exception.Message)" -Tag "Warn"
        return @()
    }
}

# A partition in the free space of a disk that already carries others. Size 0 takes the
# largest free extent whole, which is what "the rest of the disk" means on the layout
# this exists for.
function New-StudioPartitionInFreeSpace {
    param(
        [Parameter(Mandatory)][object]$Disk,
        [Parameter(Mandatory)][string]$DriveLetter,
        [long]$SizeBytes = 0
    )

    if ($Disk.IsOffline) {
        $null = Set-Disk -Number $Disk.Number -IsOffline $false -ErrorAction Stop
        Write-Log "Disk $($Disk.Number) brought online" -Tag "Info"
    }
    if ($Disk.IsReadOnly) {
        $null = Set-Disk -Number $Disk.Number -IsReadOnly $false -ErrorAction Stop
        Write-Log "Disk $($Disk.Number) cleared of its read-only flag" -Tag "Info"
    }

    $free = [long]$Disk.LargestFreeExtent
    if (($SizeBytes -gt 0) -and ($SizeBytes -gt $free)) {
        Write-Log ("{0} GB was asked for and disk {1} has {2} GB free - taking the free space instead" -f
            [math]::Round($SizeBytes / 1GB), $Disk.Number, [math]::Round($free / 1GB)) -Tag "Warn"
        $SizeBytes = 0
    }

    Write-Log ("Creating a partition on disk {0} in {1} GB of unallocated space" -f $Disk.Number,
        [math]::Round($free / 1GB)) -Tag "Run"

    $parameters = @{ DiskNumber = $Disk.Number; DriveLetter = $DriveLetter; ErrorAction = "Stop" }
    if ($SizeBytes -gt 0) { $parameters["Size"] = $SizeBytes } else { $parameters["UseMaximumSize"] = $true }
    $null = New-Partition @parameters

    if ($Disk.IsBoot -or $Disk.IsSystem) {
        # Worth saying out loud rather than discovering at the next feature update: the
        # recovery partition usually sits at the end of the boot disk, so the free space
        # taken here is the space Windows would have used to grow it.
        Write-Log "    This is the boot disk - Windows can no longer grow the recovery partition into this space at a feature update" -Tag "Warn"
    }
    Write-Log "Disk $($Disk.Number) carries a new partition at ${DriveLetter}:" -Tag "Ok"
}

# The one entry point. Returns a result object rather than a boolean, because "the
# volume is not to specification and was left alone" is an outcome the caller reports
# and carries on from, not a failure.
#
#   Ready      the drive letter exists and can be written to
#   ToSpec     it matches the specification asked for
#   Message    what happened, for the caller's own result line
function Initialize-StudioDataVolume {
    param(
        [Parameter(Mandatory)][string]$DriveLetter,
        [Parameter(Mandatory)][ValidateSet("ReFS", "NTFS")][string]$FileSystem,
        [Parameter(Mandatory)][int]$AllocationUnitSize,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][bool]$IntegrityStreams,
        # NTFS only - see Format-StudioDataVolume. Travels with a 64K allocation unit
        # rather than being asked for separately, because the two are one recommendation.
        [bool]$LargeFileRecordSegments = $false,
        # Off, nothing is created or reformatted and the run only reports. On, an
        # uninitialised disk is claimed and an *empty* volume that misses the
        # specification is reformatted. A volume holding anything at all is never
        # touched either way.
        [switch]$AllowPrepare,
        # Which disk to build the volume from, when the caller already knows. Unattended
        # callers leave it at -1 and get the single-candidate rule below; a caller that
        # asked a human - or that just created a virtual disk from a pool - names the
        # number, and "there is more than one uninitialised disk" stops being a refusal.
        [int]$DiskNumber = -1,
        # How much of a named disk's unallocated space to take. 0 is the whole free
        # extent, and it is what an uninitialised disk gets whatever this says - there is
        # no reason to leave part of a disk this run just claimed unused.
        [long]$PartitionSizeBytes = 0
    )

    $letter = ([string]$DriveLetter).Trim().TrimEnd(":", "\")
    if ($letter.Length -ne 1) {
        return [pscustomobject]@{ Ready = $false; ToSpec = $false; Message = "'$DriveLetter' is not a drive letter." }
    }
    $letter = $letter.ToUpperInvariant()

    if (Test-StudioSystemDriveLetter -DriveLetter $letter) {
        Write-Log "${letter}: is the system drive - it is never prepared or reformatted by this run" -Tag "Warn"
        return [pscustomobject]@{ Ready = $true; ToSpec = $false; Message = "${letter}: is the system drive." }
    }

    $volume = $null
    try { $volume = Get-Volume -DriveLetter $letter -ErrorAction Stop }
    catch { $volume = $null }

    # Something is on the letter that cannot be the data volume - on a default Windows
    # installation that is the DVD drive sitting on D:. It is never formatted, and it is
    # not a reason to give up on the letter either: it moves.
    #
    # Named types rather than "anything that is not Fixed", because 'Unknown' is what a
    # partition that exists but was never formatted reports, and that one belongs to the
    # empty-volume path below - which reformats rather than evicts.
    $evictable = @("CD-ROM", "Removable", "Network")
    if (($null -ne $volume) -and ($evictable -contains [string]$volume.DriveType)) {
        if (-not $AllowPrepare) {
            Write-Log "${letter}: is held by $($volume.DriveType), and volume preparation is switched off" -Tag "Error"
            return [pscustomobject]@{ Ready = $false; ToSpec = $false; Message = "${letter}: is held by $($volume.DriveType) and this run was not allowed to move it." }
        }
        if (-not (Clear-StudioDriveLetter -DriveLetter $letter)) {
            return [pscustomobject]@{ Ready = $false; ToSpec = $false; Message = "${letter}: is held by $($volume.DriveType) and could not be freed." }
        }
        $volume = $null
    }

    # A fixed volume on the letter, and this run was told which disk to build the data
    # volume from - and it is a different disk. So the letter is being held by a volume
    # that is not the one the design is describing, and the design's letter wins: the
    # occupant moves and the new volume takes the letter.
    #
    # Only when a disk was named. Without one there is nothing to build afterwards, and
    # evicting the occupant would leave the design's letter belonging to nothing at all,
    # which is worse than the volume the caller can at least see and report on.
    if (($null -ne $volume) -and ($DiskNumber -ge 0)) {
        $holder = $null
        try { $holder = Get-Partition -DriveLetter $letter -ErrorAction Stop } catch { $holder = $null }
        if (($null -ne $holder) -and ([int]$holder.DiskNumber -ne $DiskNumber)) {
            if (-not $AllowPrepare) {
                Write-Log "${letter}: is a volume on disk $($holder.DiskNumber), the design builds on disk $DiskNumber - volume preparation is off, so nothing moved" -Tag "Warn"
            }
            elseif (Clear-StudioDriveLetter -DriveLetter $letter) {
                $volume = $null
            }
            else {
                return [pscustomobject]@{ Ready = $false; ToSpec = $false; Message = "${letter}: is held by a volume on disk $($holder.DiskNumber) and could not be freed." }
            }
        }
    }

    if ($null -eq $volume) {
        # No such volume. Either there is a disk waiting to become one, or the design
        # names a drive letter this server does not have - and those are different
        # conversations.
        if (-not $AllowPrepare) {
            Write-Log "There is no ${letter}: on this server, and volume preparation is switched off" -Tag "Error"
            return [pscustomobject]@{ Ready = $false; ToSpec = $false; Message = "There is no ${letter}: and this run was not allowed to create one." }
        }
        $disk = $null
        $useFreeSpace = $false
        if ($DiskNumber -ge 0) {
            try { $disk = Get-Disk -Number $DiskNumber -ErrorAction Stop } catch { $disk = $null }
            if ($null -eq $disk) {
                Write-Log "Disk $DiskNumber was named for ${letter}: and this server has no such disk" -Tag "Error"
                return [pscustomobject]@{ Ready = $false; ToSpec = $false; Message = "Disk $DiskNumber does not exist." }
            }
            if ($disk.PartitionStyle -eq "RAW") {
                # Claiming a whole disk. Named or not, the boot and system disks are
                # still refused here - a number typed at a console is exactly as capable
                # of being wrong as one guessed, and this path initialises the disk.
                if ($disk.IsBoot -or $disk.IsSystem) {
                    Write-Log "Disk $DiskNumber carries the boot or system volume and is never claimed whole" -Tag "Error"
                    return [pscustomobject]@{ Ready = $false; ToSpec = $false; Message = "Disk $DiskNumber is the boot or system disk." }
                }
            }
            else {
                # Already initialised, so the only thing that can be built on it is a
                # partition in its unallocated space - which is safe on any disk,
                # including the one Windows booted from.
                $free = 0
                try { $free = [long]$disk.LargestFreeExtent } catch { $free = 0 }
                if ($free -lt 1GB) {
                    Write-Log "Disk $DiskNumber is $($disk.PartitionStyle) with no unallocated space to build ${letter}: in" -Tag "Error"
                    Write-Log "Shrink a partition on it, or clear the whole disk by hand: Clear-Disk -Number $DiskNumber -RemoveData" -Tag "Info"
                    return [pscustomobject]@{ Ready = $false; ToSpec = $false; Message = "Disk $DiskNumber is already initialised and full." }
                }
                $useFreeSpace = $true
            }
        }
        else {
            $disk = Get-StudioClaimableDisk
        }
        if ($null -eq $disk) {
            Write-Log "There is no ${letter}: and no single uninitialised disk to make one from" -Tag "Error"
            return [pscustomobject]@{ Ready = $false; ToSpec = $false; Message = "There is no ${letter}: and no uninitialised disk to build it from." }
        }

        # The letter before the partition: New-Partition -DriveLetter fails outright
        # against a letter something else is holding, and the something else is usually
        # the DVD drive.
        if (-not (Clear-StudioDriveLetter -DriveLetter $letter)) {
            return [pscustomobject]@{ Ready = $false; ToSpec = $false; Message = "${letter}: is taken and could not be freed." }
        }

        try {
            if ($useFreeSpace) {
                New-StudioPartitionInFreeSpace -Disk $disk -DriveLetter $letter -SizeBytes $PartitionSizeBytes
            }
            else {
                New-StudioDataVolume -Disk $disk -DriveLetter $letter
            }
            Format-StudioDataVolume -DriveLetter $letter -FileSystem $FileSystem -AllocationUnitSize $AllocationUnitSize `
                -Label $Label -IntegrityStreams $IntegrityStreams -LargeFileRecordSegments $LargeFileRecordSegments
        }
        catch {
            Write-Log "${letter}: could not be prepared: $($_.Exception.Message)" -Tag "Error"
            return [pscustomobject]@{ Ready = $false; ToSpec = $false; Message = "${letter}: could not be prepared: $($_.Exception.Message)" }
        }
        $built = if ($useFreeSpace) { "the unallocated space on disk $($disk.Number)" } else { "an uninitialised disk" }
        return [pscustomobject]@{ Ready = $true; ToSpec = $true; Message = "${letter}: was built from $built, $FileSystem with a $AllocationUnitSize byte allocation unit." }
    }

    $currentFileSystem = [string]$volume.FileSystemType
    $currentUnit = 0
    try { $currentUnit = [int]$volume.AllocationUnitSize } catch { $currentUnit = 0 }

    $fileSystemMatches = $currentFileSystem -match ("(?i)" + [regex]::Escape($FileSystem))
    # A zero reads as "this Windows build did not report it" rather than as a mismatch.
    # Reformatting a volume over a property that was never read would be the worst kind
    # of destructive: correct in theory, unprovoked in practice.
    $unitMatches = ($currentUnit -eq 0) -or ($currentUnit -eq $AllocationUnitSize)

    if ($fileSystemMatches -and $unitMatches) {
        Write-Log "${letter}: is $currentFileSystem with a $currentUnit byte allocation unit - as specified" -Tag "Ok"
        return [pscustomobject]@{ Ready = $true; ToSpec = $true; Message = "${letter}: already matches the specification." }
    }

    # No file system at all: a partition that carries the letter and was never formatted.
    # It reaches here rather than the disk-claiming path above, because a volume DOES
    # exist - and it must not reach the "holds data" branch below, which would report it
    # ready. There is nothing on it to destroy and nothing on it to write to.
    if (Test-StudioVolumeUnformatted -Volume $volume) {
        if (-not $AllowPrepare) {
            Write-Log "${letter}: carries no file system, and volume preparation is switched off" -Tag "Error"
            Write-Log "    Format-Volume -DriveLetter $letter -FileSystem $FileSystem -AllocationUnitSize $AllocationUnitSize -NewFileSystemLabel '$Label'" -Tag "Info"
            return [pscustomobject]@{ Ready = $false; ToSpec = $false; Message = "${letter}: is unformatted and this run was not allowed to format it." }
        }
        Write-Log "${letter}: is an unformatted volume - formatting it to the spec" -Tag "Warn"
        try {
            Format-StudioDataVolume -DriveLetter $letter -FileSystem $FileSystem -AllocationUnitSize $AllocationUnitSize `
                -Label $Label -IntegrityStreams $IntegrityStreams -LargeFileRecordSegments $LargeFileRecordSegments
        }
        catch {
            Write-Log "${letter}: could not be formatted: $($_.Exception.Message)" -Tag "Error"
            return [pscustomobject]@{ Ready = $false; ToSpec = $false; Message = "${letter}: could not be formatted: $($_.Exception.Message)" }
        }
        return [pscustomobject]@{ Ready = $true; ToSpec = $true; Message = "${letter}: was an unformatted volume and is now $FileSystem with a $AllocationUnitSize byte allocation unit." }
    }

    if (-not (Test-StudioVolumeEmpty -DriveLetter $letter)) {
        Write-Log "${letter}: is $currentFileSystem, $currentUnit byte units; the spec is $FileSystem with $AllocationUnitSize" -Tag "Warn"
        Write-Log "It holds data, so it is left exactly as it is - a format is destructive and only the operator gets to decide that:" -Tag "Warn"
        Write-Log "    Format-Volume -DriveLetter $letter -FileSystem $FileSystem -AllocationUnitSize $AllocationUnitSize -NewFileSystemLabel '$Label'" -Tag "Info"
        return [pscustomobject]@{ Ready = $true; ToSpec = $false; Message = "${letter}: holds data and does not match the specification - it was left alone." }
    }

    if (-not $AllowPrepare) {
        Write-Log "${letter}: is empty and does not match the specification, but volume preparation is switched off" -Tag "Warn"
        Write-Log "    Format-Volume -DriveLetter $letter -FileSystem $FileSystem -AllocationUnitSize $AllocationUnitSize -NewFileSystemLabel '$Label'" -Tag "Info"
        return [pscustomobject]@{ Ready = $true; ToSpec = $false; Message = "${letter}: is empty and off specification, and this run was not allowed to reformat it." }
    }

    Write-Log "${letter}: is $currentFileSystem with $currentUnit byte units and holds nothing - reformatting to the spec" -Tag "Warn"
    try {
        Format-StudioDataVolume -DriveLetter $letter -FileSystem $FileSystem -AllocationUnitSize $AllocationUnitSize `
            -Label $Label -IntegrityStreams $IntegrityStreams -LargeFileRecordSegments $LargeFileRecordSegments
    }
    catch {
        Write-Log "${letter}: could not be reformatted: $($_.Exception.Message)" -Tag "Error"
        return [pscustomobject]@{ Ready = $true; ToSpec = $false; Message = "${letter}: could not be reformatted: $($_.Exception.Message)" }
    }
    return [pscustomobject]@{ Ready = $true; ToSpec = $true; Message = "${letter}: was reformatted to $FileSystem with a $AllocationUnitSize byte allocation unit." }
}

# ---------------------------[ Storage pools ]---------------------------
# Storage Spaces, for the host that has no RAID controller behind it. A machine that
# does have one presents its array as a single uninitialised disk, walks straight into
# Initialize-StudioDataVolume above, and never reaches any of this.

function Get-StudioPoolCandidateDisk {
    if (-not (Get-Command -Name "Get-PhysicalDisk" -ErrorAction SilentlyContinue)) { return @() }
    try {
        # CanPool is Windows' own answer, and it already excludes the boot disk and
        # anything carrying a partition. Trusting it beats re-deriving it badly.
        return @(Get-PhysicalDisk -CanPool $true -ErrorAction Stop | Sort-Object -Property DeviceId)
    }
    catch {
        Write-Log "The physical disks could not be read: $($_.Exception.Message)" -Tag "Warn"
        return @()
    }
}

# Columns are how many physical disks one stripe of data is written across, and they are
# where the throughput comes from: "the more columns a storage space is assigned, the more
# disks can be striped across and the higher performance". Storage Spaces picks the count
# itself and "intelligently scales the column count up to eight by default", so this
# function does not set it - it *predicts* it, so the console can say what the layout will
# actually look like before anything is built.
#
# The correlation is Microsoft's: a column costs one disk per data copy, so a two-way
# mirror gets half the disks as columns and a three-way a third of them. A parity space
# stripes across all of them, with one column's worth spent on parity (two for dual).
#
# Setting it by hand is deliberately not done: the guidance is "unless your workload has
# very specific needs and is unlikely to grow significantly, utilize the default column
# count chosen by Spaces at creation time", and mixed virtual machine IO is exactly the
# workload with no specific need. The count is read back after creation and logged,
# because it is fixed for the life of the virtual disk and decides how the pool grows.
$script:storagePoolMaximumColumns = 8

function Get-StudioPoolColumnCount {
    param(
        [Parameter(Mandatory)][int]$DiskCount,
        [Parameter(Mandatory)][int]$Copies
    )

    if ($Copies -lt 1) { $Copies = 1 }
    $columns = [math]::Floor($DiskCount / $Copies)
    if ($columns -lt 1) { $columns = 1 }
    if ($columns -gt $script:storagePoolMaximumColumns) { $columns = $script:storagePoolMaximumColumns }
    return [int]$columns
}

# Every layout this set of disks can actually be built into, best first. The order is the
# answer to one question - what does a host full of running virtual machines want? - and
# it is not the same order a file archive would get:
#
#   Two-way mirror     first, always. Mirror reads come off whichever copy is free and a
#                      write costs two IOs; it is Microsoft's "use for most deployments".
#   Three-way mirror   more tolerance, not more speed: a third write per write and a third
#                      of the raw capacity. Offered from five disks, which is Storage
#                      Spaces' own standalone minimum for it.
#   Parity             offered, and honestly labelled. Microsoft's own best practice list
#                      says "do not use parity spaces for workloads that are predominantly
#                      random in nature" - a host full of virtual machines is the textbook
#                      random workload, and read-modify-write on every write is why.
#   Simple             offered last and never recommended: one disk failure loses every
#                      virtual machine on the host.
#
# Nothing is hidden - the operator sees the whole menu and the reason each one sits where
# it does. What the run *chooses on its own* is the first entry.
function Get-StudioPoolLayout {
    param(
        [Parameter(Mandatory)][int]$DiskCount,
        [long]$RawBytes = 0
    )

    $layouts = @()
    if ($DiskCount -lt 1) { return $layouts }

    # Standalone Storage Spaces minimums, from Microsoft's stand-alone deployment guide:
    # mirror "requires at least two physical disks to protect from single disk failure"
    # and "at least five physical disks to protect from two simultaneous disk failures";
    # parity "requires at least three physical disks"; dual parity needs seven.
    $definitions = @(
        [pscustomobject]@{ Id = "Mirror";         Minimum = 2; Resiliency = "Mirror"; Copies = 2; Redundancy = 1; Name = "Two-way mirror";  Tolerates = "one disk" }
        [pscustomobject]@{ Id = "ThreeWayMirror"; Minimum = 5; Resiliency = "Mirror"; Copies = 3; Redundancy = 2; Name = "Three-way mirror"; Tolerates = "two disks" }
        [pscustomobject]@{ Id = "Parity";         Minimum = 3; Resiliency = "Parity"; Copies = 1; Redundancy = 1; Name = "Parity";           Tolerates = "one disk" }
        [pscustomobject]@{ Id = "DualParity";     Minimum = 7; Resiliency = "Parity"; Copies = 1; Redundancy = 2; Name = "Dual parity";      Tolerates = "two disks" }
        [pscustomobject]@{ Id = "Simple";         Minimum = 1; Resiliency = "Simple"; Copies = 1; Redundancy = 0; Name = "Simple";           Tolerates = "nothing" }
    )

    foreach ($definition in $definitions) {
        if ($DiskCount -lt $definition.Minimum) { continue }

        $columns = Get-StudioPoolColumnCount -DiskCount $DiskCount -Copies $definition.Copies
        # Mirrors lose a whole copy of everything; parity loses one column per parity
        # symbol, which is why parity's efficiency climbs with the disk count and a
        # mirror's never does.
        $usable = 0
        if ($definition.Resiliency -eq "Mirror") { $usable = $RawBytes / $definition.Copies }
        elseif ($definition.Resiliency -eq "Parity") {
            $stripe = [math]::Min($DiskCount, $script:storagePoolMaximumColumns)
            if ($stripe -le $definition.Redundancy) { continue }
            $usable = $RawBytes * (($stripe - $definition.Redundancy) / $stripe)
        }
        else { $usable = $RawBytes }

        $note = ""
        switch ($definition.Id) {
            "Mirror"         { $note = "the fastest layout that survives a disk - what a virtual machine volume wants" }
            "ThreeWayMirror" { $note = "more tolerance, not more speed: a third copy on every write" }
            "Parity"         { $note = "capacity, not speed - Microsoft: not for predominantly random workloads" }
            "DualParity"     { $note = "same, with two parity symbols - archive shaped" }
            "Simple"         { $note = "NO RESILIENCY - one disk failure loses every virtual machine" }
        }

        $capacity = ""
        if ($RawBytes -gt 0) { $capacity = "{0} GB usable   " -f [math]::Round($usable / 1GB) }

        $layouts += [pscustomobject]@{
            Id          = $definition.Id
            Resiliency  = $definition.Resiliency
            Copies      = $definition.Copies
            Redundancy  = $definition.Redundancy
            Columns     = $columns
            UsableBytes = [long]$usable
            Recommended = ($definition.Id -eq "Mirror")
            Label       = ("{0}   {1}{2} column(s)   survives {3}   {4}" -f $definition.Name, $capacity,
                $columns, $definition.Tolerates, $note)
        }
    }
    return $layouts
}

# One pool of SSDs and HDDs together is a pool whose speed is its slowest member, and
# Microsoft's best practice is explicit about it: "when mixing disk types in the same
# storage pool, utilize manual disk selection ... or separate different disk types into
# separate storage pools". Reported rather than refused - the operator picked these disks.
function Test-StudioPoolMediaMix {
    param([Parameter(Mandatory)][object[]]$PhysicalDisk)

    $media = @($PhysicalDisk | ForEach-Object { [string]$_.MediaType } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    if ($media.Count -le 1) { return $false }

    Write-Log ("These disks are not the same media - {0} in one pool" -f ($media -join " and ")) -Tag "Warn"
    Write-Log "A mixed pool performs like its slowest member. Separate pools per media type, or a tiered space, is the faster answer" -Tag "Warn"
    return $true
}

# The next free pool name of a family - 'pool-01', then 'pool-02', and 's2d' in the middle
# when the cluster is building one. Numbered rather than fixed because a second pool on the
# same host is a normal thing to want, and because a name that already exists is adopted
# rather than rebuilt, which would silently give the second pool the first one's disks.
function Get-StudioPoolNameSuggestion {
    param(
        [string]$Base = "pool",
        [string]$Kind = ""
    )

    $family = $Base
    if (-not [string]::IsNullOrWhiteSpace($Kind)) { $family = "$Base-$Kind" }

    $taken = @()
    try { $taken = @(Get-StoragePool -ErrorAction Stop | Where-Object { -not $_.IsPrimordial } | ForEach-Object { [string]$_.FriendlyName }) }
    catch { $taken = @() }

    for ($number = 1; $number -lt 100; $number++) {
        $candidate = "{0}-{1:00}" -f $family, $number
        if ($taken -notcontains $candidate) { return $candidate }
    }
    return "$family-01"
}

# The pool itself, and nothing on top of it. Split out from the virtual disk below
# because a cluster wants two virtual disks out of one pool and a stand-alone host wants
# one - the pool is the same object either way.
function New-StudioPool {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][object[]]$PhysicalDisk
    )

    $existing = $null
    try { $existing = Get-StoragePool -FriendlyName $Name -ErrorAction Stop } catch { $existing = $null }
    if ($null -ne $existing) {
        # Adopted, never rebuilt or extended behind somebody's back - the same rule the
        # rest of this repo follows for objects it did not create.
        Write-Log "The storage pool '$Name' already exists - leaving it exactly as it is" -Tag "Info"
        return $false
    }

    $subsystem = $null
    try { $subsystem = @(Get-StorageSubSystem -ErrorAction Stop | Where-Object { $_.FriendlyName -like "Windows Storage*" })[0] }
    catch { $subsystem = $null }
    if ($null -eq $subsystem) {
        Write-Log "No Windows Storage subsystem was found, so no pool could be created" -Tag "Error"
        return $false
    }

    Write-Log ("Creating the storage pool '{0}' from {1} disk(s)" -f $Name, $PhysicalDisk.Count) -Tag "Run"
    foreach ($disk in $PhysicalDisk) {
        Write-Log ("    {0}  {1} GB  {2}  serial {3}" -f $disk.FriendlyName,
            [math]::Round($disk.Size / 1GB), $disk.MediaType, $disk.SerialNumber) -Tag "Info"
    }
    $null = Test-StudioPoolMediaMix -PhysicalDisk $PhysicalDisk

    try {
        $null = New-StoragePool -FriendlyName $Name -StorageSubSystemFriendlyName $subsystem.FriendlyName `
            -PhysicalDisks $PhysicalDisk -ErrorAction Stop
        Write-Log "The pool '$Name' exists" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "The storage pool could not be created: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

# How much a virtual disk of this layout can still take out of the pool, in bytes. Used
# to cut a pool in half for two cluster volumes - asking Storage Spaces for "half" means
# knowing what the whole is after resiliency has taken its share.
function Get-StudioPoolUsableCapacity {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Copies
    )

    $pool = $null
    try { $pool = Get-StoragePool -FriendlyName $Name -ErrorAction Stop } catch { $pool = $null }
    if ($null -eq $pool) { return 0 }

    $free = 0
    try { $free = [long]$pool.Size - [long]$pool.AllocatedSize } catch { $free = 0 }
    if ($free -le 0) { return 0 }
    if ($Copies -lt 1) { $Copies = 1 }
    return [long]([math]::Floor($free / $Copies))
}

# One virtual disk on an existing pool. Returns the disk number it arrived as - a raw
# disk, and therefore the input the volume preparation above already knows how to handle.
function New-StudioPoolVirtualDisk {
    param(
        [Parameter(Mandatory)][string]$PoolName,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Resiliency,
        [Parameter(Mandatory)][int]$NumberOfDataCopies,
        [int]$PhysicalDiskRedundancy = 0,
        # 0 takes whatever is left of the pool. A number carves out that much and leaves
        # the rest, which is how one pool becomes two cluster volumes.
        [long]$SizeBytes = 0
    )

    $existing = $null
    try { $existing = Get-VirtualDisk -FriendlyName $Name -ErrorAction Stop } catch { $existing = $null }
    if ($null -ne $existing) {
        Write-Log "The virtual disk '$Name' already exists - leaving it exactly as it is" -Tag "Info"
        $disk = $null
        try { $disk = $existing | Get-Disk -ErrorAction Stop } catch { $disk = $null }
        if ($null -ne $disk) { return [int]$disk.Number }
        return -1
    }

    # Fixed rather than thin, and that one is not a preference: a virtual machine that
    # meets a thin space with nothing left behind it does not get an error, it gets a
    # paused-critical virtual machine. Dual parity requires fixed provisioning outright.
    #
    # Columns and interleave are left to Storage Spaces on purpose. It "intelligently
    # scales the column count up to eight by default", the interleave default is 256 KB -
    # already larger than anything a VHDX issues - and Microsoft's own best practice is to
    # take both defaults "unless your workload has very specific needs". Mixed virtual
    # machine IO is random, and the same guidance notes random workloads "do not
    # experience as significant a performance increase" from column tuning anyway. What is
    # read back below is what Spaces actually chose.
    $virtualDiskParameters = @{
        StoragePoolFriendlyName = $PoolName
        FriendlyName            = $Name
        ResiliencySettingName   = $Resiliency
        ProvisioningType        = "Fixed"
        ErrorAction             = "Stop"
    }
    if ($SizeBytes -gt 0) { $virtualDiskParameters["Size"] = [uint64]$SizeBytes }
    else { $virtualDiskParameters["UseMaximumSize"] = $true }
    if ($Resiliency -eq "Mirror") { $virtualDiskParameters["NumberOfDataCopies"] = $NumberOfDataCopies }
    elseif ($Resiliency -eq "Parity") {
        if ($PhysicalDiskRedundancy -lt 1) { $PhysicalDiskRedundancy = 1 }
        $virtualDiskParameters["PhysicalDiskRedundancy"] = $PhysicalDiskRedundancy
    }

    try {
        $null = New-VirtualDisk @virtualDiskParameters
    }
    catch {
        Write-Log "The virtual disk '$Name' could not be created: $($_.Exception.Message)" -Tag "Error"
        return -1
    }

    $virtualDisk = $null
    try { $virtualDisk = Get-VirtualDisk -FriendlyName $Name -ErrorAction Stop }
    catch { $virtualDisk = $null }
    if ($null -eq $virtualDisk) {
        Write-Log "The virtual disk '$Name' was created but could not be read back" -Tag "Error"
        return -1
    }

    $disk = $null
    try { $disk = $virtualDisk | Get-Disk -ErrorAction Stop } catch { $disk = $null }
    if ($null -eq $disk) {
        Write-Log "'$Name' has no disk number yet - initialise and format it by hand" -Tag "Warn"
        return -1
    }

    Write-Log ("'{0}' is {1} GB of {2}, and arrived as disk {3}" -f $Name,
        [math]::Round($virtualDisk.Size / 1GB), $Resiliency, $disk.Number) -Tag "Ok"

    # What Storage Spaces settled on, read back rather than assumed - these two decide
    # the throughput of every virtual machine on this host and neither can be changed
    # afterwards.
    $columns = 0
    $interleave = 0
    try { $columns = [int]$virtualDisk.NumberOfColumns } catch { $columns = 0 }
    try { $interleave = [long]$virtualDisk.Interleave } catch { $interleave = 0 }
    if ($columns -gt 0) {
        $stripe = ""
        if ($interleave -gt 0) {
            $stripe = " with a {0} KB interleave, so one stripe of data is {1} KB" -f
                [math]::Round($interleave / 1KB), [math]::Round(($interleave * $columns) / 1KB)
        }
        Write-Log ("It stripes across {0} column(s){1}" -f $columns, $stripe) -Tag "Info"

        $copies = $NumberOfDataCopies
        if ($Resiliency -ne "Mirror") { $copies = 1 }
        Write-Log ("    Column count is fixed for the life of this virtual disk - growing the pool means adding {0} disk(s) at a time" -f ($columns * $copies)) -Tag "Debug"
    }
    return [int]$disk.Number
}

# The stand-alone host's shape: a pool with one virtual disk across all of it.
function New-StudioStoragePool {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][object[]]$PhysicalDisk,
        [Parameter(Mandatory)][string]$Resiliency,
        [Parameter(Mandatory)][int]$NumberOfDataCopies,
        # How many disks the space survives. Only ever passed for a parity space, where
        # it is the documented way to ask for single or dual parity - a mirror says the
        # same thing with its data copies, and passing both is asking twice.
        [int]$PhysicalDiskRedundancy = 0
    )

    if (-not (New-StudioPool -Name $Name -PhysicalDisk $PhysicalDisk)) { return -1 }
    return (New-StudioPoolVirtualDisk -PoolName $Name -Name "$Name-data" -Resiliency $Resiliency `
            -NumberOfDataCopies $NumberOfDataCopies -PhysicalDiskRedundancy $PhysicalDiskRedundancy)
}

# Integrity streams are inherited from the parent directory, and toggling a directory
# does **not** change files that already exist inside it. So this is worth doing before
# the files exist - a folder cleared now is a folder whose contents are born cleared -
# and the existing files are swept as well for the case where they do not.
#
# Why it is worth doing at all is a narrower claim than it used to be. Microsoft's ReFS
# doc says integrity streams are NOT enabled for file data by default - so on most
# volumes this whole function is asserting a default, and the honest shape of that is to
# READ the state first and say nothing when there is nothing to do. The case it exists
# for is the volume whose root arrives with integrity enabled (mirrored spaces have
# shipped that way), where every VHDX created inside would inherit a checksum on every
# write - a cost a running virtual machine pays forever for protection its mirror
# already provides at the storage layer.
#
# The failure this function used to retry on a timer was never timing (field-decided
# 2026-08-18: the same command failed by hand hours after the volume was made).
# Set-FileIntegrity against a Cluster Shared Volume answers 'One or more parameter
# values passed to the method were invalid' (MI RESULT 4) when this node is not the
# volume's COORDINATOR - a two-node cluster distributes CSV ownership round-robin, which
# is exactly why one of two identically made volumes worked and the other did not. So a
# CSV path that fails locally is retried once on the volume's owner node, and the log
# names it.
function Disable-StudioIntegrityStream {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Get-Command -Name "Set-FileIntegrity" -ErrorAction SilentlyContinue)) { return $false }
    if (-not (Test-Path -LiteralPath $Path)) { return $false }

    # The state first. Already off - the documented default, and what a WS2025 S2D
    # mirror volume was measured to arrive as - means nothing to do and nothing to say
    # above Debug.
    $current = $null
    try { $current = Get-FileIntegrity -FileName $Path -ErrorAction Stop } catch { $current = $null }
    if (($null -ne $current) -and (-not [bool]$current.Enabled)) {
        Write-Log "Integrity streams are already off on '$Path' - the ReFS default, nothing to change" -Tag "Debug"
        return $true
    }

    # Who owns the volume, asked as soon as the LOCAL read could not answer - because
    # the read is a coordinator question exactly like the write (the reader asked how
    # this node would even know, 2026-08-18, and the answer is that from here it
    # cannot). Resolved once, used by whichever of the two paths below needs it.
    $owner = ""
    if ($Path -match '(?i)^[a-z]:\\ClusterStorage\\') {
        try {
            $volumeName = ($Path -split '\\')[2]
            $csv = @(Get-ClusterSharedVolume -ErrorAction Stop | Where-Object {
                @($_.SharedVolumeInfo | ForEach-Object { [string]$_.FriendlyVolumeName }) -contains ("C:\ClusterStorage\" + $volumeName)
            })
            if ($csv.Count -gt 0) { $owner = [string]$csv[0].OwnerNode }
        }
        catch { $owner = "" }
    }
    $ownerIsRemote = ((-not [string]::IsNullOrWhiteSpace($owner)) -and
        (-not $owner.Equals($env:COMPUTERNAME, [System.StringComparison]::OrdinalIgnoreCase)))

    # A CSV this node could not even READ the state of belongs to the other node, so the
    # whole question is asked there in one trip: state, and the write only if the state
    # calls for one. That keeps the ordinary outcome - already off - as quiet on the
    # peer's volume as on our own.
    if (($null -eq $current) -and $ownerIsRemote) {
        try {
            $answer = [string](Invoke-Command -ComputerName $owner -ScriptBlock {
                $state = Get-FileIntegrity -FileName $using:Path -ErrorAction Stop
                if (-not [bool]$state.Enabled) { return "off" }
                Set-FileIntegrity -FileName $using:Path -Enable $false -ErrorAction Stop
                return "cleared"
            } -ErrorAction Stop)
            if ($answer -eq "off") {
                Write-Log "Integrity streams are already off on '$Path' - answered by '$owner', which owns that volume" -Tag "Debug"
                return $true
            }
            Write-Log "Integrity streams cleared on '$Path' by '$owner'" -Tag "Ok"
            return $true
        }
        catch {
            Write-Log "Integrity streams on '$Path' could not be read or cleared via '$owner': $($_.Exception.Message)" -Tag "Warn"
            Write-Log "    On that node:  Set-FileIntegrity -FileName '$Path' -Enable `$false" -Tag "Info"
            return $false
        }
    }

    $cleared = $false
    $detail = ""
    try {
        Set-FileIntegrity -FileName $Path -Enable $false -ErrorAction Stop
        $cleared = $true
    }
    catch {
        $detail = $_.Exception.Message
    }

    # The write refused locally on a volume the other node owns - the read may have
    # answered from here while the write would not, so this second chance stays.
    if ((-not $cleared) -and $ownerIsRemote) {
        Write-Log "'$Path' refused the change from here - '$owner' owns that volume and integrity is a coordinator's write, retrying there" -Tag "Info"
        try {
            Invoke-Command -ComputerName $owner -ScriptBlock {
                Set-FileIntegrity -FileName $using:Path -Enable $false -ErrorAction Stop
            } -ErrorAction Stop
            $cleared = $true
        }
        catch {
            $detail = $_.Exception.Message
        }
    }

    if ($cleared) {
        Write-Log "Integrity streams cleared on '$Path'" -Tag "Ok"
    }
    else {
        Write-Log "Integrity streams could not be cleared on '$Path': $detail" -Tag "Warn"
        Write-Log "    On the node that OWNS the volume (Get-ClusterSharedVolume shows it):  Set-FileIntegrity -FileName '$Path' -Enable `$false" -Tag "Info"
        return $false
    }

    $existing = @()
    try { $existing = @(Get-ChildItem -LiteralPath $Path -File -Force -ErrorAction Stop) }
    catch { $existing = @() }
    foreach ($file in $existing) {
        try { Set-FileIntegrity -FileName $file.FullName -Enable $false -ErrorAction Stop }
        catch { Write-Log "Integrity streams could not be cleared on '$($file.Name)': $($_.Exception.Message)" -Tag "Warn" }
    }
    if ($existing.Count -gt 0) {
        Write-Log "Cleared it on $($existing.Count) file(s) already in there" -Tag "Info"
    }
    return $true
}
