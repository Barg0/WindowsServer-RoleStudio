#Requires -Version 5.1
# ---------------------------[ Hyper-V: the single-node cluster ]---------------------------
# A failover cluster with one node in it. It fails over nowhere, and that is not the point:
# it makes a lab host behave like a cluster - Cluster Shared Volumes under
# C:\ClusterStorage, highly available virtual machines, Failover Cluster Manager - so
# everything built on top is built against the real shape rather than a stand-alone one.
#
# **A local disk cannot be a classic cluster disk, and that is the fact the whole design
# turns on.** Failover Clustering only claims a disk that implements SCSI-3 persistent
# reservations. A VHDX on a guest's own controller has none; neither does an array on a
# machine's own RAID card. Get-ClusterAvailableDisk simply comes back empty, and no amount
# of preparing the volume changes that. This was learned the hard way on the bench, twice.
#
# Storage Spaces Direct does not use SCSI reservations at all. It claims disks through the
# software storage bus, which is what turns a machine's own disks into storage the cluster
# owns - so **S2D is the default here, and it is the only path on which local disks ever
# become a Cluster Shared Volume**.
#
#   storageMode = s2d           every chosen disk goes into **one pool**, and every Cluster
#                               Shared Volume is carved out of that pool. The disks are left
#                               raw until the cluster exists: "before you enable Storage
#                               Spaces Direct, make sure your drives are empty".
#   storageMode = sharedDisks   shared storage presented from outside this host - a SAN LUN, a
#                               an iSCSI target. One disk per volume, formatted NTFS with no
#                               drive letter, handed over with Add-ClusterDisk.
#
# What S2D costs, stated rather than buried: Datacenter edition ("Storage Spaces Direct
# requires Windows Server Datacenter Edition"), empty disks, and a documented minimum of
# two servers - one node is what Azure Local ships as a single-server cluster, but on
# Windows Server it is a lab shape rather than a supported production one. On one node the
# pool's fault domain must be **PhysicalDisk**, or it wants a second server for the second
# copy of a mirror and refuses to build one.
#
# The file system differs by path, and both are Microsoft's: **ReFS** for an S2D volume
# ("Storage Spaces Direct volumes: format with ReFS"), **NTFS** for a classic CSV, because
# a ReFS CSV outside S2D "is placed in redirected mode" and loses Direct IO. The same trap
# as the allocation unit in Storage.ps1 and Role.Exchange.ps1: two right answers.
#
# The shape of a clustered run:
#
#   Apply        install Hyper-V and Failover Clustering; check the chosen disks are empty
#                (S2D) or format them NTFS without a letter (shared disks).
#   (reboot)
#   PostReboot   create the cluster; switch S2D on with -AutoConfig:$false so the pool is
#                built from the disks that were chosen rather than everything lying around;
#                carve the volumes out of it with New-Volume, which creates, formats,
#                shares and mounts each one as C:\ClusterStorage\<name> in a single step;
#                then point Set-VMHost at the first.

# ---------------------------[ Config ]---------------------------
function Get-HypervClusterSection {
    param([Parameter(Mandatory)][object]$Hyperv)
    return (Get-ConfigValue -InputObject $Hyperv -Name "cluster")
}

function Test-HypervClusterWanted {
    param([object]$Hyperv)

    if ($null -eq $Hyperv) { return $false }
    $cluster = Get-HypervClusterSection -Hyperv $Hyperv
    if ($null -eq $cluster) { return $false }
    return [bool](Get-ConfigValue -InputObject $cluster -Name "enabled" -Default $false)
}

function Get-HypervClusterName {
    param([Parameter(Mandatory)][object]$Cluster)

    $name = [string](Get-ConfigText -InputObject $Cluster -Name "name" -Default "hv-cl-01")
    if ([string]::IsNullOrWhiteSpace($name)) { $name = "hv-cl-01" }
    return $name.Trim()
}

# ---------------------------[ The feature ]---------------------------
# The third feature this repo installs rather than demands, and for the same reason as the
# first two: a cluster cannot be configured before the cluster service exists, and unlike
# Hyper-V this one does not even cost a restart of its own - it rides the one Hyper-V
# already owes.
function Test-HypervClusterFeatureInstalled {
    try {
        $feature = Get-WindowsFeature -Name "Failover-Clustering" -ErrorAction Stop
        return ($feature.InstallState -eq "Installed")
    }
    catch {
        return $false
    }
}

function Install-HypervClusterFeature {
    param([Parameter(Mandatory)][object]$Cluster)

    if (Test-HypervClusterFeatureInstalled) {
        Write-Log "Failover Clustering installed" -Tag "Info"
        return $true
    }
    if (-not [bool](Get-ConfigValue -InputObject $Cluster -Name "installFeature" -Default $true)) {
        Write-Log "Failover Clustering is missing and this design does not install it:" -Tag "Error"
        Write-Log "    Install-WindowsFeature -Name Failover-Clustering -IncludeManagementTools" -Tag "Error"
        return $false
    }

    Write-Log "Installing Failover Clustering with its management tools" -Tag "Run"
    $result = $null
    try {
        $result = Install-WindowsFeature -Name "Failover-Clustering" -IncludeManagementTools -ErrorAction Stop
    }
    catch {
        Write-Log "Failover Clustering not installed: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
    if (($null -ne $result) -and (-not $result.Success)) {
        Write-Log "Install-WindowsFeature failed: exit $($result.ExitCode)" -Tag "Error"
        return $false
    }
    Write-Log "Failover Clustering installed" -Tag "Ok"
    return $true
}

# ---------------------------[ Prerequisites ]---------------------------
# Reported rather than refused, with one exception: a cluster needs a name object
# somewhere, and where that goes depends on whether this server is in a domain.
function Test-HypervClusterDomainJoined {
    try {
        $system = Get-CimInstance -ClassName "Win32_ComputerSystem" -ErrorAction Stop
        return [bool]$system.PartOfDomain
    }
    catch {
        return $false
    }
}

function Test-HypervClusterPrerequisite {
    param([Parameter(Mandatory)][object]$Cluster)

    $name = Get-HypervClusterName -Cluster $Cluster
    Write-Log "Single-node failover cluster '$name'" -Tag "Info"
    Write-Log "    One node fails over nowhere - what it buys is the shape: Cluster Shared Volumes and highly available guests" -Tag "Debug"

    if (-not (Test-HypervClusterDomainJoined)) {
        # A workgroup cluster is a supported shape - Microsoft documents it - but it has
        # its own prerequisites, and the one that stops a single node dead is the DNS
        # suffix: the cluster name is registered in DNS instead of Active Directory, and
        # without a primary suffix there is no name to register.
        Write-Log "Not in a domain - the cluster gets a DNS-only access point rather than a computer object" -Tag "Warn"
        Write-Log "    Supported from Windows Server 2025 on" -Tag "Info"

        $suffix = Get-HypervPrimaryDnsSuffix
        $wanted = [string](Get-ConfigText -InputObject $Cluster -Name "dnsSuffix" -Default "")

        if (-not [string]::IsNullOrWhiteSpace($suffix)) {
            Write-Log "Primary DNS suffix '$suffix' - the cluster name registers there" -Tag "Info"
        }
        elseif (-not [string]::IsNullOrWhiteSpace($wanted)) {
            Write-Log "No primary DNS suffix here - this run sets '$wanted' before the restart" -Tag "Info"
        }
        else {
            Write-Log "No primary DNS suffix, and a workgroup cluster needs one - its name has nowhere to register" -Tag "Error"
            Write-Log "    Set it on the Failover cluster card, or: Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'NV Domain' -Value 'lab.invalid'  (needs a restart)" -Tag "Info"
        }
    }
    return $true
}

# The suffix a workgroup node registers under. Read from the registry rather than from
# Win32_ComputerSystem.Domain, which on a workgroup machine answers with the workgroup
# name and would read as a suffix that is not one.
function Get-HypervPrimaryDnsSuffix {
    try {
        $parameters = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ErrorAction Stop
        foreach ($name in @("NV Domain", "Domain")) {
            $value = [string]$parameters.$name
            if (-not [string]::IsNullOrWhiteSpace($value)) { return $value }
        }
    }
    catch { }
    return ""
}

# Give a workgroup node the suffix its cluster name will live under. Written to 'NV
# Domain', which is the value that survives a restart - 'Domain' beside it is the one in
# force right now and is set as well so anything reading it before the reboot agrees.
#
# Only ever on a workgroup machine: a domain member takes its suffix from the domain, and
# writing one there is how a server ends up disagreeing with its own directory.
function Set-HypervPrimaryDnsSuffix {
    param([Parameter(Mandatory)][string]$Suffix)

    $value = $Suffix.Trim().TrimStart(".")
    if ([string]::IsNullOrWhiteSpace($value)) { return $false }

    if (Test-HypervClusterDomainJoined) {
        Write-Log "Domain member - primary DNS suffix left alone" -Tag "Info"
        return $false
    }

    $current = Get-HypervPrimaryDnsSuffix
    if ($current.Equals($value, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Log "Primary DNS suffix is already '$value'" -Tag "Info"
        return $false
    }

    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    try {
        Set-ItemProperty -Path $path -Name "NV Domain" -Value $value -ErrorAction Stop
        Set-ItemProperty -Path $path -Name "Domain" -Value $value -ErrorAction Stop
        Write-Log "Primary DNS suffix '$value' set" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "Primary DNS suffix not set: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

# ---------------------------[ The volumes ]---------------------------
# Two of them, and the number is not arbitrary. Microsoft's own arrangement guidance for
# clustered virtual machines is to mirror how the disks of a physical server would be
# split: "System files, including a page file, in a VHD file on one CSV. Data files in a
# VHD file on another CSV." A second CSV also gives a backup job a second volume to
# snapshot, and a CSV in Backup-in-Progress redirected access is a volume whose IO is
# taking the long way round.
#
# **Nothing here fills a volume to the brim** - but the number, and the reason behind it,
# depend on which of the two paths built the volume, so the note does too. Neither is ever
# subtracted from a volume's size: this is a usage rule, not a size, and it is said at the
# point where it would be acted on.
#
# **On a shared disk formatted NTFS** the published rule applies as written: keep 15% free
# under 1 TB, 10% between 1 and 5 TB, 5% above that. That space is where the software VSS
# snapshot a backup takes has to live - there is nowhere to put it but the volume being
# snapshotted - and under about a gigabyte free VSS fails without saying why. The ladder
# relaxes as the volume grows because a diff area does not grow with the volume.
#
# **On Storage Spaces Direct that rule describes nothing that happens.** A CSVFS_ReFS
# volume holds no software snapshot - Get-StorageSubSystem Clustered* reports
# SupportsSnapshotLocal as False - and Hyper-V backup there runs on resilient change
# tracking and ReFS block cloning instead. Telling an operator to hold 15% of an S2D
# volume back is asking them to reserve space for something that will never land on it.
# What does bite is ReFS itself: a volume 90% full or more loses performance, which is the
# problem ReFS compaction was added to fix, and the destage threshold behind it defaults to
# 85%. So the S2D leg is given a ceiling to stay under rather than a slice to hold back -
# and, on either path, the reminder that a checkpoint and a growing dynamic VHDX come out
# of the volume they sit on.
function Get-HypervCsvFreeSpaceMinimum {
    param([Parameter(Mandatory)][long]$SizeBytes)

    if ($SizeBytes -ge 5TB) { return 5 }
    if ($SizeBytes -ge 1TB) { return 10 }
    return 15
}

function Write-HypervCsvFreeSpaceNote {
    param(
        [Parameter(Mandatory)][string]$Path,
        # The S2D leg formats CSVFS_ReFS and gets the ReFS ceiling. Everything else got
        # here as a shared disk on NTFS and gets the published CSV ladder.
        [switch]$S2d
    )

    $volume = $null
    try { $volume = Get-Volume -FilePath $Path -ErrorAction Stop } catch { $volume = $null }
    if ($null -eq $volume) { return }

    $size = [long]$volume.Size
    if ($size -le 0) { return }

    if ($S2d) {
        Write-Log ("'{0}' is {1} GB - keep it under 90% full" -f $Path, [math]::Round($size / 1GB)) -Tag "Info"
        Write-Log "    ReFS slows above that, and checkpoints and growing dynamic VHDX files come out of the same volume" -Tag "Debug"
        Write-Log "    The 15% a SAN CSV keeps free is snapshot space, and this volume takes no software snapshot" -Tag "Debug"
        return
    }

    $minimum = Get-HypervCsvFreeSpaceMinimum -SizeBytes $size
    Write-Log ("'{0}' is {1} GB - keep at least {2}% free" -f $Path, [math]::Round($size / 1GB), $minimum) -Tag "Info"
    Write-Log "    That headroom is what a VSS snapshot, a checkpoint and a growing dynamic VHDX come out of" -Tag "Debug"
}

# A disk the cluster can take is an **empty** one - no partitions on it - and this is the
# one place that decides what to do about a disk that is not.
#
# Empty means no partitions, not no partition table: a disk initialised as GPT with
# nothing on it is pooled by Storage Spaces Direct exactly as an uninitialised one is, and
# is left alone here. A disk that carries partitions is only ever cleared because the
# console confirmed that disk by number - the caller passes -AllowWipe for those and for
# no others.
function Clear-HypervClusterDisk {
    param(
        [Parameter(Mandatory)][int]$DiskNumber,
        [switch]$AllowWipe
    )

    $disk = $null
    try { $disk = Get-Disk -Number $DiskNumber -ErrorAction Stop } catch { $disk = $null }
    if ($null -eq $disk) {
        Write-Log "Disk $DiskNumber is not on this server any more" -Tag "Warn"
        return $false
    }
    if ($disk.IsBoot -or $disk.IsSystem) {
        Write-Log "Disk $DiskNumber carries the boot or system volume - never claimed" -Tag "Error"
        return $false
    }

    # Offline or read-only answers nothing about its partitions and can hold nothing
    # either. Neither change touches what is on the disk.
    try {
        if ($disk.IsOffline) {
            $null = Set-Disk -Number $DiskNumber -IsOffline $false -ErrorAction Stop
            Write-Log "Disk $DiskNumber was offline, now online" -Tag "Info"
        }
        if ($disk.IsReadOnly) { $null = Set-Disk -Number $DiskNumber -IsReadOnly $false -ErrorAction Stop }
    }
    catch {
        Write-Log "Disk $DiskNumber not brought online: $($_.Exception.Message)" -Tag "Warn"
    }

    $partitions = 0
    if ([string]$disk.PartitionStyle -ne "RAW") {
        try { $partitions = @(Get-Partition -DiskNumber $DiskNumber -ErrorAction Stop).Count }
        catch { $partitions = 0 }
    }
    if ($partitions -eq 0) { return $true }

    if (-not $AllowWipe) {
        Write-Log "Disk $DiskNumber carries $partitions partition(s) and a cluster disk has to be empty" -Tag "Warn"
        Write-Log "    Erasing it was not confirmed at the console, so nothing was done" -Tag "Info"
        Write-Log "    By hand, if it holds nothing you want: Clear-Disk -Number $DiskNumber -RemoveData -RemoveOEM -Confirm:`$false" -Tag "Info"
        return $false
    }

    Write-Log "Erasing disk $DiskNumber - $partitions partition(s), confirmed at the console" -Tag "Run"
    try { $null = Clear-Disk -Number $DiskNumber -RemoveData -RemoveOEM -Confirm:$false -ErrorAction Stop }
    catch {
        Write-Log "Disk $DiskNumber not cleared: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
    Write-Log "Disk $DiskNumber is empty" -Tag "Ok"
    return $true
}

# The disks the console confirmed may be erased, by number. Absent on a design that never
# needed one, which is the normal case and means nothing is ever wiped.
function Get-HypervClusterWipeList {
    param([object]$Plan = $null)

    $wipe = @()
    if (($null -eq $Plan) -or ($null -eq $Plan.storage)) { return @() }
    if ($null -eq $Plan.storage.clusterDiskWipe) { return @() }
    foreach ($number in @($Plan.storage.clusterDiskWipe)) {
        try { $wipe += [int]$number } catch { }
    }
    return @($wipe)
}

# A raw disk brought up as one NTFS volume with **no drive letter**. A CSV is reached
# through C:\ClusterStorage, so a letter would be a second name for the same volume and
# one more thing to collide with the letters the rest of this design hands out.
function New-HypervClusterVolume {
    param(
        [Parameter(Mandatory)][int]$DiskNumber,
        [Parameter(Mandatory)][string]$Label,
        [string]$FileSystem = "NTFS",
        [int]$AllocationUnitSize = 65536,
        # This disk was confirmed for erasing at the console. Without it a disk that
        # carries partitions is left alone and taken as already prepared, below.
        [switch]$AllowWipe
    )

    # Confirmed for erasing: it goes back to empty first, and the rest of this function
    # then sees the disk it would have seen had it always been empty.
    if ($AllowWipe) {
        if (-not (Clear-HypervClusterDisk -DiskNumber $DiskNumber -AllowWipe)) {
            Write-Log "'$Label' not prepared - disk $DiskNumber could not be emptied" -Tag "Error"
            return $false
        }
    }

    $disk = $null
    try { $disk = Get-Disk -Number $DiskNumber -ErrorAction Stop } catch { $disk = $null }
    if ($null -eq $disk) {
        Write-Log "Disk $DiskNumber is gone - '$Label' not prepared" -Tag "Error"
        return $false
    }
    if ($disk.IsBoot -or $disk.IsSystem) {
        Write-Log "Disk $DiskNumber carries the boot or system volume - never claimed" -Tag "Error"
        return $false
    }

    if ($disk.PartitionStyle -eq "RAW") {
        try {
            if ($disk.IsOffline) { $null = Set-Disk -Number $DiskNumber -IsOffline $false -ErrorAction Stop }
            if ($disk.IsReadOnly) { $null = Set-Disk -Number $DiskNumber -IsReadOnly $false -ErrorAction Stop }
            $null = Initialize-Disk -Number $DiskNumber -PartitionStyle GPT -ErrorAction Stop
            Write-Log "Disk $DiskNumber initialised GPT for '$Label'" -Tag "Debug"
        }
        catch {
            Write-Log "Disk $DiskNumber not initialised: $($_.Exception.Message)" -Tag "Error"
            return $false
        }
    }

    # A volume that is already there and already labelled is this run's own work from a
    # previous pass, and is left exactly as it is.
    $existing = @()
    try { $existing = @(Get-Partition -DiskNumber $DiskNumber -ErrorAction Stop | Where-Object { $_.Type -ne "Reserved" }) }
    catch { $existing = @() }
    if ($existing.Count -gt 0) {
        Write-Log "Disk $DiskNumber already carries a partition - '$Label' taken as prepared" -Tag "Info"
        return $true
    }

    try {
        $partition = New-Partition -DiskNumber $DiskNumber -UseMaximumSize -ErrorAction Stop
        Write-Log ("Formatting '{0}': {1}, {2} byte units, no drive letter" -f $Label, $FileSystem, $AllocationUnitSize) -Tag "Run"
        $null = Format-Volume -Partition $partition -FileSystem $FileSystem -AllocationUnitSize $AllocationUnitSize `
            -NewFileSystemLabel $Label -Force -Confirm:$false -ErrorAction Stop
        Write-Log "'$Label' ready for the cluster" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "'$Label' not prepared: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

# The names this design gives its Cluster Shared Volumes, in order.
function Get-HypervCsvLabel {
    param([Parameter(Mandatory)][object]$Cluster)

    $count = [int](Get-ConfigValue -InputObject $Cluster -Name "csvCount" -Default 2)
    if ($count -lt 1) { $count = 1 }
    $prefix = [string](Get-ConfigText -InputObject $Cluster -Name "csvNamePrefix" -Default "csv")
    if ([string]::IsNullOrWhiteSpace($prefix)) { $prefix = "csv" }

    $labels = @()
    for ($index = 1; $index -le $count; $index++) { $labels += ("{0}-{1:00}" -f $prefix, $index) }
    return @($labels)
}

# The disk a prepared volume sits on, found by the label this run gave it. Disk numbers
# move across a restart and volume labels do not, so the label is the durable handle
# between the leg that formats a volume and the leg that hands it to the cluster.
function Get-HypervClusterVolumeDiskNumber {
    param([Parameter(Mandatory)][string]$Label)

    $partitions = @()
    try { $partitions = @(Get-Partition -ErrorAction Stop) } catch { return -1 }
    foreach ($partition in $partitions) {
        $volume = $null
        try { $volume = $partition | Get-Volume -ErrorAction Stop } catch { $volume = $null }
        if ($null -eq $volume) { continue }
        if ([string]$volume.FileSystemLabel -eq $Label) { return [int]$partition.DiskNumber }
    }
    return -1
}

# One whole disk per Cluster Shared Volume - **not** a Storage Spaces pool, and that is a
# hard requirement rather than a simplification.
#
# Clustered Storage Spaces needs every physical disk in the pool to support persistent
# reservations and to sit on SAS cabling reaching every node: "direct attached storage that
# is not connected to all cluster nodes is not usable for clustered pools with Storage
# Spaces". A pool built on a machine's own disks fails that, so the cluster cannot take its
# virtual disks - Add-ClusterDisk answers with "an error was encountered while creating
# storage resources", which is what it did on the bench.
#
# So the pool belongs to the stand-alone host, where nothing is asking the cluster service
# to own it, and a clustered host hands over plain disks instead. Resiliency then comes
# from underneath - the RAID controller, or the array the disks are carved from - which is
# also how a real cluster on SAN or JBOD gets it.
function New-HypervClusterVolumeSet {
    param(
        [Parameter(Mandatory)][object]$Cluster,
        [object]$Plan = $null
    )

    $answer = $null
    if (($null -ne $Plan) -and ($null -ne $Plan.storage)) { $answer = $Plan.storage }

    $labels = @(Get-HypervCsvLabel -Cluster $Cluster)
    $fileSystem = [string](Get-ConfigText -InputObject $Cluster -Name "fileSystem" -Default "NTFS")
    $allocationUnitSize = [int](Get-ConfigValue -InputObject $Cluster -Name "allocationUnitSize" -Default 65536)

    $wanted = @()
    if (($null -ne $answer) -and ($null -ne $answer.clusterDisks)) {
        foreach ($number in @($answer.clusterDisks)) {
            try { $wanted += [int]$number } catch { }
        }
    }
    if ($wanted.Count -eq 0) {
        Write-Log "No disk chosen for the Cluster Shared Volumes" -Tag "Error"
        Write-Log "    Run the interview at the console - a clustered host is asked which disks become its volumes" -Tag "Error"
        return @()
    }

    # Storage Spaces Direct wants the disks **untouched**: "before you enable Storage
    # Spaces Direct, make sure your drives are empty with no old partitions or other
    # data". So on that path this leg formats nothing and only checks.
    if (Test-HypervClusterS2dMode -Cluster $Cluster -Plan $Plan) {
        $wipe = @(Get-HypervClusterWipeList -Plan $Plan)
        $raw = @()
        foreach ($number in $wanted) {
            $allow = ($wipe -contains [int]$number)
            if (Clear-HypervClusterDisk -DiskNumber $number -AllowWipe:$allow) { $raw += $number }
        }
        if ($raw.Count -eq 0) {
            Write-Log "None of the chosen disks is empty - Storage Spaces Direct has nothing to claim" -Tag "Error"
            return @()
        }
        Write-Log ("{0} disk(s) left empty until the cluster exists" -f $raw.Count) -Tag "Info"
        return @($labels)
    }

    $wipe = @(Get-HypervClusterWipeList -Plan $Plan)
    $ready = @()
    for ($index = 0; $index -lt $labels.Count; $index++) {
        $label = $labels[$index]

        # Already prepared by an earlier pass? Then the label is on a disk somewhere and
        # there is nothing to do to it.
        $existingDisk = Get-HypervClusterVolumeDiskNumber -Label $label
        if ($existingDisk -ge 0) {
            Write-Log "'$label' already prepared on disk $existingDisk" -Tag "Info"
            $ready += $label
            continue
        }

        if ($index -ge $wanted.Count) {
            Write-Log "'$label' has no disk behind it - the interview chose $($wanted.Count) disk(s) for $($labels.Count) volume(s)" -Tag "Warn"
            continue
        }
        $allow = ($wipe -contains [int]$wanted[$index])
        if (New-HypervClusterVolume -DiskNumber $wanted[$index] -Label $label -FileSystem $fileSystem `
                -AllocationUnitSize $allocationUnitSize -AllowWipe:$allow) {
            $ready += $label
        }
    }

    if ($ready.Count -gt 0) {
        Write-Log ("{0} volume(s) ready for the cluster: {1}" -f $ready.Count, ($ready -join ", ")) -Tag "Ok"
    }
    return @($ready)
}

# ---------------------------[ Storage Spaces Direct ]---------------------------
# The way a single node actually gets Cluster Shared Volumes, and the reason the earlier
# design could not: a classic cluster disk has to implement SCSI-3 persistent
# reservations, which a local disk does not - not a VHDX on a guest's own controller and
# not an array on a machine's own RAID card. Storage Spaces Direct does not use SCSI
# reservations at all. It claims the disks through the software storage bus, so the
# storage the cluster owns is built out of exactly the disks a cluster otherwise refuses.
#
# What that costs, stated plainly rather than buried:
#
#   Datacenter edition   Microsoft: "Storage Spaces Direct requires Windows Server
#                        Datacenter Edition". Standard cannot do it at all.
#   Two servers, on paper The documented minimum is two, sixteen at most, and guest
#                        clusters are "minimum of two nodes and maximum of three". One
#                        node works and is what Azure Local ships as a single-server
#                        cluster, but on Windows Server it is a lab shape, not a supported
#                        production one.
#   Empty disks          "Before you enable Storage Spaces Direct, make sure your drives
#                        are empty with no old partitions or other data." So the disks are
#                        left raw here rather than formatted, which is the opposite of
#                        what the shared-disk path needs.
#
# And two things it gets right that the old path got wrong: the volumes are **ReFS**,
# which is Microsoft's own instruction for S2D volumes, and New-Volume creates the virtual
# disk, formats it, adds it to Cluster Shared Volumes and mounts it under its own name in
# one step - so C:\ClusterStorage\csv-01 comes out named rather than renamed.
# How many copies the volumes carry: the console's answer when there is one, the design's
# otherwise. Written once because the pool's default resiliency and the volumes themselves
# both have to agree with it.
function Get-HypervClusterCopies {
    param(
        [Parameter(Mandatory)][object]$Cluster,
        [object]$Plan = $null
    )

    $copies = [int](Get-ConfigValue -InputObject $Cluster -Name "mirrorCopies" -Default 2)
    if (($null -ne $Plan) -and ($null -ne $Plan.storage)) {
        $planned = 0
        try { $planned = [int]$Plan.storage.clusterCopies } catch { $planned = 0 }
        if ($planned -ge 1) { $copies = $planned }
    }
    if ($copies -lt 1) { $copies = 1 }
    if ($copies -gt 4) { $copies = 4 }
    return $copies
}

# Where the cluster's shared storage comes from, and the console's answer beats the
# design's. **The Cluster Shared Volumes are always the goal** - this decides what they are
# built out of, never whether they are built at all.
#
#   s2d          This host's own disks become one pool and every Cluster Shared Volume is
#                carved out of it. The only path on which local disks ever become a CSV.
#   sharedDisks  Shared storage presented from outside this host - a SAN LUN, an iSCSI
#                target, a SAS JBOD. One whole disk per volume, handed over with
#                Add-ClusterDisk. It has to implement SCSI-3 persistent reservations, which
#                is what no disk of this host's own does.
#
# The plan carries the answer so that the leg after the restart builds what the leg before it
# prepared, whatever the config file says by then.
function Get-HypervClusterStorageMode {
    param(
        [Parameter(Mandatory)][object]$Cluster,
        [object]$Plan = $null
    )

    if (($null -ne $Plan) -and ($null -ne $Plan.storage)) {
        $answered = [string]$Plan.storage.clusterStorageMode
        if ($answered -eq "sharedDisks") { return "sharedDisks" }
        if ($answered -eq "s2d") { return "s2d" }
    }

    $mode = [string](Get-ConfigText -InputObject $Cluster -Name "storageMode" -Default "s2d")
    if ($mode -eq "sharedDisks") { return "sharedDisks" }
    return "s2d"
}

function Test-HypervClusterS2dMode {
    param(
        [Parameter(Mandatory)][object]$Cluster,
        [object]$Plan = $null
    )

    return ((Get-HypervClusterStorageMode -Cluster $Cluster -Plan $Plan) -eq "s2d")
}

# Whether Windows is running inside a virtual machine. It changes the drive minimum - a
# guest deployment's floor is two virtual disks rather than four flash devices - and it
# brings the guest-cluster rules with it.
function Test-HypervRunningVirtual {
    try {
        $system = Get-CimInstance -ClassName "Win32_ComputerSystem" -ErrorAction Stop
        $model = [string]$system.Model
        $maker = [string]$system.Manufacturer
        if ($model -match "(?i)virtual machine|vmware|kvm|xen|virtualbox") { return $true }
        if (($maker -match "(?i)qemu|xen|innotek|parallels")) { return $true }
        return $false
    }
    catch { return $false }
}

function Test-HypervDatacenterEdition {
    try {
        $edition = [string](Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "EditionID" -ErrorAction Stop).EditionID
        return ($edition -match "(?i)datacenter")
    }
    catch {
        return $true
    }
}

function Get-HypervClusterS2dState {
    if (-not (Get-Command -Name "Get-ClusterStorageSpacesDirect" -ErrorAction SilentlyContinue)) { return "" }
    try { return [string](Get-ClusterStorageSpacesDirect -ErrorAction Stop).State }
    catch { return "" }
}

# The pool Storage Spaces Direct built for this cluster, whatever it decided to call it.
function Get-HypervClusterS2dPool {
    try {
        return @(Get-StoragePool -ErrorAction Stop | Where-Object { $_.IsPrimordial -eq $false -and $_.IsClustered -eq $true })[0]
    }
    catch { return $null }
}

function Enable-HypervClusterS2d {
    param(
        [Parameter(Mandatory)][object]$Cluster,
        [object]$Plan = $null
    )

    $state = Get-HypervClusterS2dState
    if ($state -eq "Enabled") {
        Write-Log "Storage Spaces Direct already on for this cluster" -Tag "Info"
        $poolName = [string](Get-ConfigText -InputObject $Cluster -Name "poolName" -Default "")
        if ([string]::IsNullOrWhiteSpace($poolName)) { $poolName = Get-StudioPoolNameSuggestion -Base "pool" -Kind "s2d" }
        return (New-HypervClusterS2dPool -Name $poolName -Plan $Plan -Copies (Get-HypervClusterCopies -Cluster $Cluster -Plan $Plan))
    }
    if (-not (Get-Command -Name "Enable-ClusterStorageSpacesDirect" -ErrorAction SilentlyContinue)) {
        Write-Log "This Windows has no Enable-ClusterStorageSpacesDirect" -Tag "Error"
        return $false
    }
    if (-not (Test-HypervDatacenterEdition)) {
        Write-Log "Storage Spaces Direct needs Windows Server Datacenter - this server is not running it" -Tag "Error"
        Write-Log "    Standard can still be a single-node cluster, just without a CSV built this way" -Tag "Info"
        return $false
    }

    # A flat design with no cache, which is what Microsoft asks for in a virtual guest -
    # "deploy a flat storage design with no caching devices configured" - and what a set
    # of identical disks wants anyway. A cache tier needs two media types to be worth
    # anything, and one media type with a cache carved out of it is capacity thrown away.
    $poolName = [string](Get-ConfigText -InputObject $Cluster -Name "poolName" -Default "")
    if ([string]::IsNullOrWhiteSpace($poolName)) { $poolName = Get-StudioPoolNameSuggestion -Base "pool" -Kind "s2d" }

    # -AutoConfig:$false, and that is the whole reason this reads the way it does. Left to
    # itself, Enable-ClusterStorageSpacesDirect claims **every** eligible disk on the node
    # and builds its own pool and tiers out of them - which would quietly ignore the disks
    # the interview picked and swallow any other empty disk in the machine. Switched off,
    # the pool below is built from exactly what was chosen.
    Write-Log "Enabling Storage Spaces Direct" -Tag "Run"
    try {
        $null = Enable-ClusterStorageSpacesDirect -AutoConfig:$false -CacheState Disabled -Confirm:$false -ErrorAction Stop
    Write-Log "Storage Spaces Direct on" -Tag "Ok"
    }
    catch {
        Write-Log "Storage Spaces Direct not enabled: $($_.Exception.Message)" -Tag "Error"
        Write-Log "    Usually a disk that is not empty. S2D takes raw disks only - Clear-Disk -RemoveData -RemoveOEM" -Tag "Info"
        return $false
    }

    # Microsoft's guest-cluster guidance, and it matters in a lab: a virtual disk is a
    # file, so the health service replacing one for a fault it 'sees' is the wrong answer.
    try {
        $null = Get-StorageSubSystem -FriendlyName "Clustered*" -ErrorAction Stop |
            Set-StorageHealthSetting -Name "System.Storage.PhysicalDisk.AutoReplace.Enabled" -Value "False" -ErrorAction Stop
        Write-Log "Automatic drive replacement off" -Tag "Info"
    }
    catch {
        Write-Log "The health service kept its automatic drive replacement setting" -Tag "Debug"
    }
    $null = Set-HypervGuestStorageTimeout
    return (New-HypervClusterS2dPool -Name $poolName -Plan $Plan -Copies (Get-HypervClusterCopies -Cluster $Cluster -Plan $Plan))
}

# The other half of Microsoft's guest-cluster guidance, and the half that bites at three in
# the morning rather than on the bench: Storage Spaces waits six seconds for an IO before it
# calls a disk faulty, and a busy parent host can make a guest's IO take longer than that.
# The guidance is 30 seconds inside a virtual machine. Nothing is written on physical
# hardware, where six seconds is the right answer and the disk really has failed.
function Set-HypervGuestStorageTimeout {
    if (-not (Test-HypervRunningVirtual)) { return $true }

    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters"
    $wanted = 30000
    try {
        if (-not (Test-Path -LiteralPath $path)) { $null = New-Item -Path $path -Force -ErrorAction Stop }
        $current = -1
        try { $current = [int](Get-ItemProperty -LiteralPath $path -Name "HwTimeout" -ErrorAction Stop).HwTimeout } catch { $current = -1 }
        if ($current -eq $wanted) {
            Write-Log "Storage Spaces IO timeout is already 30 seconds" -Tag "Info"
            return $true
        }
        $null = New-ItemProperty -Path $path -Name "HwTimeout" -Value $wanted -PropertyType DWord -Force -ErrorAction Stop
        Write-Log "Storage Spaces IO timeout: 30 seconds" -Tag "Ok"
        Write-Log "    Takes effect at the next restart" -Tag "Info"
        return $true
    }
    catch {
        Write-Log "Storage Spaces IO timeout not set: $($_.Exception.Message)" -Tag "Warn"
        return $false
    }
}

# One pool, out of the disks the interview chose - and every Cluster Shared Volume is then
# carved out of that one pool rather than being a disk of its own. That is what S2D is:
# the disks stop being individually meaningful and become capacity the cluster owns.
function New-HypervClusterS2dPool {
    param(
        [Parameter(Mandatory)][string]$Name,
        [object]$Plan = $null,
        # What the volumes on it will be. The pool carries it as its default resiliency,
        # so a one-disk pool is not created with a Mirror default it can never satisfy.
        [int]$Copies = 2
    )

    $existing = Get-HypervClusterS2dPool
    if ($null -ne $existing) {
        Write-Log "Pool '$($existing.FriendlyName)' already exists - left as it is" -Tag "Info"
        return $true
    }

    $subsystem = $null
    try { $subsystem = @(Get-StorageSubSystem -FriendlyName "Clustered*" -ErrorAction Stop)[0] } catch { $subsystem = $null }
    if ($null -eq $subsystem) {
        Write-Log "Clustered storage subsystem unreadable - no pool built" -Tag "Error"
        return $false
    }

    $poolable = @()
    try { $poolable = @($subsystem | Get-PhysicalDisk -ErrorAction Stop | Where-Object { $_.CanPool -eq $true }) }
    catch { $poolable = @() }
    if ($poolable.Count -eq 0) {
        Write-Log "The cluster sees no poolable disk - S2D takes empty disks only" -Tag "Error"
        return $false
    }

    # The interview's choice, matched by serial where there is one. A virtual disk often
    # has no serial at all, so an empty list here means "everything poolable", which is
    # also what a single-node lab wants.
    $wanted = @()
    if (($null -ne $Plan) -and ($null -ne $Plan.storage) -and ($null -ne $Plan.storage.clusterDiskIds)) {
        $wanted = @([string[]]$Plan.storage.clusterDiskIds | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
    $chosen = $poolable
    if ($wanted.Count -gt 0) {
        $matched = @($poolable | Where-Object { $wanted -contains [string]$_.UniqueId -or $wanted -contains [string]$_.SerialNumber })
        if ($matched.Count -gt 0) { $chosen = $matched }
        else { Write-Log "The interview's disks cannot be identified here - every poolable disk goes in" -Tag "Warn" }
    }

    # A pool whose default resiliency is Mirror when it only has one disk is a pool that
    # disagrees with itself. The default follows what the volumes will actually be.
    $default = "Mirror"
    if (($Copies -le 1) -or ($chosen.Count -lt 2)) { $default = "Simple" }

    Write-Log ("Building pool '{0}' from {1} disk(s), default resiliency {2}" -f $Name, $chosen.Count, $default) -Tag "Run"
    # Grouped rather than one line per disk - four identical lines say what one "4 x" says.
    foreach ($shape in ($chosen | Group-Object -Property { "{0}  {1} GB  {2}" -f $_.FriendlyName, [math]::Round($_.Size / 1GB), $_.MediaType })) {
        Write-Log ("    {0} x {1}" -f $shape.Count, $shape.Name) -Tag "Info"
    }
    if ($chosen.Count -lt 2) {
        Write-Log "One disk cannot be mirrored - every volume on this pool would survive nothing" -Tag "Warn"
    }

    # One media type, which on a single server is not a preference but the supported
    # shape: "SBL cache isn't supported in single server configuration. All flat single
    # storage type configurations (for example all-NVMe or all-SSD) are the only supported
    # storage type for single server." A mixed pool asks for a cache tier that cannot
    # exist here, and performs like its slowest member either way.
    $media = @($chosen | ForEach-Object { [string]$_.MediaType } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    if ($media.Count -gt 1) {
        Write-Log ("Pool mixes {0} - a single-server deployment supports one flat storage type" -f ($media -join " and ")) -Tag "Warn"
        Write-Log "    There is no cache tier on one server, so the pool runs at the speed of its slowest disk" -Tag "Warn"
    }

    try {
        # FaultDomainAwarenessDefault PhysicalDisk is the single-node setting: left at its
        # default the pool wants a second *server* for the second copy and refuses to
        # build a mirror at all.
        $null = New-StoragePool -StorageSubSystemFriendlyName $subsystem.FriendlyName -FriendlyName $Name `
            -PhysicalDisks $chosen -ProvisioningTypeDefault Fixed -ResiliencySettingNameDefault $default `
            -FaultDomainAwarenessDefault PhysicalDisk -WriteCacheSizeDefault 0 -ErrorAction Stop
        Write-Log "Pool '$Name' built - mirrored across physical disks" -Tag "Ok"
    }
    catch {
        Write-Log "Pool not built: $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    # Re-asserted on the pool, which is the only object that carries it: the fault domain
    # lives on the pool as its default, and Set-ResiliencySetting has no parameter for it
    # in any Windows Server release.
    $pool = Get-HypervClusterS2dPool
    if ($null -ne $pool) {
        try {
            $null = $pool | Set-StoragePool -FaultDomainAwarenessDefault PhysicalDisk -ErrorAction Stop
        }
        catch {
            Write-Log "The pool kept its own fault domain: $($_.Exception.Message)" -Tag "Debug"
        }
    }

    # Microsoft's guest-cluster guidance, and it matters in a lab: a virtual disk is a
    # file, so the health service replacing one for a fault it 'sees' is the wrong answer,
    # and a busy parent host can make an IO take longer than the six seconds Spaces waits.
    try {
        $null = Get-StorageSubSystem -FriendlyName "Clustered*" -ErrorAction Stop |
            Set-StorageHealthSetting -Name "System.Storage.PhysicalDisk.AutoReplace.Enabled" -Value "False" -ErrorAction Stop
        Write-Log "Automatic drive replacement off" -Tag "Info"
    }
    catch {
        Write-Log "The health service kept its automatic drive replacement setting" -Tag "Debug"
    }
    return $true
}

# One size for every volume, with the pool's repair capacity kept back first.
#
# Two rules, and they pull in opposite directions. **Equal**: two Cluster Shared Volumes
# are meant to be interchangeable - system disks on one, data disks on the other - and a
# 10 GB volume beside a 6 GB one is not that. **Not everything**: Microsoft's reserve
# capacity guidance is to leave the equivalent of one capacity drive per server
# unallocated, so that after a drive fails the pool has somewhere to rebuild the copies
# that were on it, immediately and without anybody being called out.
#
# So: take the free space, put one drive's worth aside, divide the rest by the copies and
# then by the number of volumes, and round down to a whole gigabyte. Every volume gets
# that number. On a pool too small to give each volume a gigabyte, the reserve is dropped
# rather than the volumes - a lab pool that cannot hold both is still a lab pool - and the
# log says which of the two rules it just let go of.
function Get-HypervClusterVolumePlan {
    param(
        [Parameter(Mandatory)][long]$FreeBytes,
        [long]$LargestDiskBytes = 0,
        [int]$DiskCount = 0,
        [Parameter(Mandatory)][int]$Copies,
        [Parameter(Mandatory)][int]$Count
    )

    $result = [pscustomobject]@{
        PerVolume = [long]0
        Reserve   = [long]0
        Usable    = [long]0
        Dropped   = $false
        # What rounding down to whole gigabytes left behind, in pool space rather than
        # volume space. Reported rather than spent: it is the difference between the
        # arithmetic an operator does in their head and the number they end up looking at,
        # and unexplained it reads as capacity that went somewhere it should not have.
        Remainder = [long]0
    }
    if (($Count -lt 1) -or ($FreeBytes -le 0)) { return $result }
    if ($Copies -lt 1) { $Copies = 1 }

    # The reserve, and only when there is somewhere to rebuild onto. With exactly as many
    # drives as copies, a failed drive leaves the survivors unable to hold another copy,
    # so holding space back costs capacity and buys nothing.
    $reserve = 0
    if (($DiskCount -gt $Copies) -and ($LargestDiskBytes -gt 0)) { $reserve = [long]$LargestDiskBytes }

    $each = [long]([math]::Floor((($FreeBytes - $reserve) / $Copies) / $Count / 1GB)) * 1GB
    if ($each -lt 1GB) {
        # Not enough for both rules. The volumes win: a pool with no volume on it is of no
        # use to anybody, and a pool this small was never going to survive a drive anyway.
        $reserve = 0
        $result.Dropped = $true
        $each = [long]([math]::Floor(($FreeBytes / $Copies) / $Count / 1GB)) * 1GB
        if ($each -lt 1GB) { return $result }
    }

    $result.PerVolume = $each
    $result.Reserve = [long]$reserve
    $result.Usable = [long]($each * $Count)
    $result.Remainder = [long](($FreeBytes - $reserve) - ($each * $Count * $Copies))
    if ($result.Remainder -lt 0) { $result.Remainder = [long]0 }
    return $result
}

# The same arithmetic against a pool that exists, with the reasoning logged. Sizes shown
# at the console come from the function above with the same inputs, so what the menu
# promised is what gets built.
function Get-HypervClusterVolumeSize {
    param(
        [Parameter(Mandatory)][object]$Pool,
        [Parameter(Mandatory)][int]$Copies,
        [Parameter(Mandatory)][int]$Count
    )

    $free = 0
    try { $free = [long]$Pool.Size - [long]$Pool.AllocatedSize } catch { $free = 0 }
    if ($free -le 0) {
        Write-Log "Pool reports no free space - Storage Spaces sizes the volumes instead" -Tag "Warn"
        return 0
    }

    $disks = @()
    try { $disks = @($Pool | Get-PhysicalDisk -ErrorAction Stop) } catch { $disks = @() }
    $largest = 0
    if ($disks.Count -gt 0) {
        $maximum = ($disks | Measure-Object -Property Size -Maximum).Maximum
        if ($null -ne $maximum) { $largest = [long]$maximum }
    }
    else {
        Write-Log "Pool drive sizes unreadable - no repair capacity kept back" -Tag "Warn"
    }

    $plan = Get-HypervClusterVolumePlan -FreeBytes $free -LargestDiskBytes $largest -DiskCount $disks.Count -Copies $Copies -Count $Count
    if ($plan.PerVolume -le 0) {
        Write-Log ("The pool holds {0} GB, which does not divide into {1} volume(s) of {2} copies - Storage Spaces sizes them instead" -f
            [math]::Round($free / 1GB), $Count, $Copies) -Tag "Warn"
        return 0
    }

    if ($plan.Reserve -gt 0) {
        Write-Log ("{0} GB stays unallocated as repair capacity - one drive's worth, so the pool can rebuild in place after a failure" -f
            [math]::Round($plan.Reserve / 1GB)) -Tag "Info"
    }
    elseif ($plan.Dropped) {
        Write-Log ("No repair capacity kept back - the pool is too small for both it and {0} volume(s)" -f $Count) -Tag "Warn"
        Write-Log "    A drive failure will need a replacement disk before the pool can rebuild" -Tag "Info"
    }
    elseif (($disks.Count -gt 0) -and ($disks.Count -le $Copies)) {
        Write-Log ("{0} disk(s) for {1} copies - no repair capacity left" -f $disks.Count, $Copies) -Tag "Info"
        Write-Log "    A drive failure here needs a replacement disk either way - reserving space would not change it" -Tag "Debug"
    }

    Write-Log ("Volumes: {0} x {1} GB, {2} copies each" -f $Count, [math]::Round($plan.PerVolume / 1GB), $Copies) -Tag "Info"
    # Said out loud, because it is the gap between the division an operator does in their
    # head and the size they are looking at. Whole gigabytes and equal volumes are worth
    # the scrap; pretending the scrap is not there is not.
    if ($plan.Remainder -ge 1GB) {
        Write-Log ("{0} GB of the pool is left over - the volumes are rounded down to whole gigabytes so they come out the same size" -f
            [math]::Round($plan.Remainder / 1GB)) -Tag "Info"
    }
    return $plan.PerVolume
}

# One volume, created and mounted in a single step. New-Volume makes the virtual disk,
# partitions it, formats it, adds it to Cluster Shared Volumes and mounts it under its own
# friendly name - so the mount point is C:\ClusterStorage\csv-01 without anything being
# renamed afterwards.
function New-HypervClusterS2dVolume {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][object]$Pool,
        [long]$SizeBytes = 0,
        [int]$AllocationUnitSize = 4096,
        # How many copies of everything. Two is the default on one node and the only thing
        # two disks can do; three and four each need a disk more to put a copy on.
        [int]$MirrorCopies = 2
    )

    $existing = $null
    try { $existing = Get-VirtualDisk -FriendlyName $Label -ErrorAction Stop } catch { $existing = $null }
    if ($null -ne $existing) {
        Write-Log "'$Label' already exists - left as it is" -Tag "Info"
        return (Join-Path -Path (Get-HypervClusterStorageFolder) -ChildPath $Label)
    }

    # Two copies is Microsoft's own default - "if your deployment has only one or two
    # servers, Storage Spaces Direct automatically uses two-way mirroring" - and their
    # table counts *servers* as fault domains. This pool counts disks, because one node
    # has nothing else to count, so three and four copies are reachable here from three
    # and four disks. The copies are stated as -PhysicalDiskRedundancy, the failures the
    # volume survives: New-Volume has no -NumberOfDataCopies (New-VirtualDisk and
    # New-StorageTier do, and the two are the same statement said differently), and
    # handing it one fails the call outright. Parity is not offered at all - archive
    # layout, running guests.
    $copies = $MirrorCopies
    if ($copies -lt 1) { $copies = 1 }
    if ($copies -gt 4) { $copies = 4 }

    $parameters = @{
        StoragePoolFriendlyName = $Pool.FriendlyName
        FriendlyName            = $Label
        # ReFS, and this is the one place it is right: Microsoft's own instruction is
        # "Storage Spaces Direct volumes: format with ReFS", for the integrity features,
        # block cloning and the S2D optimisations. It is the opposite of the answer a
        # classic CSV on a SAN gets, which is NTFS for Direct IO.
        FileSystem              = "CSVFS_ReFS"
        AllocationUnitSize      = $AllocationUnitSize
        ErrorAction             = "Stop"
    }
    if ($copies -eq 1) {
        # One copy is a simple space: striped across whatever disks the pool has and
        # protected by nothing. It is the only thing a single-disk pool can hold, and it
        # is never chosen by default - the operator has to ask for it by name.
        $parameters["ResiliencySettingName"] = "Simple"
    }
    else {
        $parameters["ResiliencySettingName"] = "Mirror"
        $parameters["PhysicalDiskRedundancy"] = ($copies - 1)
    }
    if ($SizeBytes -gt 0) { $parameters["Size"] = [uint64]$SizeBytes }
    else { $parameters["UseMaximumSize"] = $true }

    $shape = if ($copies -eq 1) { "simple, no resiliency," } else { "{0}-copy mirrored" -f $copies }
    Write-Log ("Creating '{0}' as a {1} ReFS Cluster Shared Volume" -f $Label, $shape) -Tag "Run"
    if ($copies -eq 1) {
        Write-Log "    Nothing protects this volume - one disk failure loses every guest on it" -Tag "Warn"
    }
    try {
        $null = New-Volume @parameters
    }
    catch {
        Write-Log "'$Label' not created: $($_.Exception.Message)" -Tag "Error"
        return ""
    }

    $path = Join-Path -Path (Get-HypervClusterStorageFolder) -ChildPath $Label
    if (Test-Path -LiteralPath $path) {
        Write-Log "'$Label' is mounted at '$path'" -Tag "Ok"
        # Integrity streams cost a running virtual machine more than they give it, and on
        # a CSV the setting is inherited by whatever is created inside afterwards.
        $null = Disable-StudioIntegrityStream -Path $path
        return $path
    }

    # It exists but somewhere else - the cluster names a volume it was not given a name
    # for as VolumeN. Reported rather than renamed: the caller can still use it.
    Write-Log "'$Label' was created but is not at '$path' - check C:\ClusterStorage for the name it took" -Tag "Warn"
    return ""
}

# ---------------------------[ The cluster ]---------------------------
function Get-HypervClusterHere {
    if (-not (Get-Command -Name "Get-Cluster" -ErrorAction SilentlyContinue)) { return $null }
    try { return (Get-Cluster -ErrorAction Stop) } catch { return $null }
}

function Test-HypervClusterValidation {
    param([Parameter(Mandatory)][object]$Cluster)

    if (-not [bool](Get-ConfigValue -InputObject $Cluster -Name "validate" -Default $true)) {
        Write-Log "Cluster validation off in the design" -Tag "Info"
        return
    }

    Write-Log "Validating - takes a few minutes" -Tag "Run"
    try {
        # Storage is left out on purpose: the storage tests want disks that are free to be
        # taken offline and written to, and on a single node they would be testing the
        # volumes this run just built for the cluster it is about to create.
        $report = Test-Cluster -Node $env:COMPUTERNAME -Ignore "Storage" -ErrorAction Stop
        if ($null -ne $report) {
            Write-Log "Validation report: $($report.FullName)" -Tag "Info"
        }
        Write-Log "Validation finished - a single-node cluster always warns about failover" -Tag "Info"
    }
    catch {
        Write-Log "Cluster validation did not complete: $($_.Exception.Message)" -Tag "Warn"
        Write-Log "    The cluster is created anyway" -Tag "Info"
    }
}

# Whether the cluster name actually reached DNS, and what to do when it did not.
#
# On a workgroup cluster it usually does not, and the event says why in a way that reads
# like a bug: 'failed registration of one or more associated DNS name(s) ... No
# credentials are available in the security package'. There is no computer account here,
# so there is nothing to authenticate a **secure** dynamic update with - the zone would
# have to accept an unsecured one, and a domain's zone is normally set to secure only.
#
# Nothing is broken by it: the cluster runs, and the name is reachable the moment a record
# exists. So this checks, and prints the record to create rather than leaving an event log
# entry to be discovered later.
function Test-HypervClusterNameRegistration {
    param([Parameter(Mandatory)][string]$Name)

    $suffix = Get-HypervPrimaryDnsSuffix
    $fqdn = $Name
    if (-not [string]::IsNullOrWhiteSpace($suffix)) { $fqdn = "$Name.$suffix" }

    $resolved = ""
    try {
        $addresses = @([System.Net.Dns]::GetHostAddresses($fqdn))
        if ($addresses.Count -gt 0) { $resolved = [string]$addresses[0].IPAddressToString }
    }
    catch { $resolved = "" }

    if (-not [string]::IsNullOrWhiteSpace($resolved)) {
        Write-Log "'$fqdn' resolves to $resolved" -Tag "Ok"
        return $true
    }

    # The address the cluster gave its name resource, so the line below is one that can be
    # pasted rather than filled in.
    $address = ""
    try {
        $address = @(Get-ClusterResource -ErrorAction Stop |
            Where-Object { [string]$_.ResourceType -eq "IP Address" } |
            Get-ClusterParameter -Name "Address" -ErrorAction Stop |
            ForEach-Object { [string]$_.Value } | Where-Object { $_ })[0]
    }
    catch { $address = "" }
    if ([string]::IsNullOrWhiteSpace($address)) { $address = "<the cluster's address>" }

    Write-Log "'$fqdn' does not resolve - the cluster could not register its own name" -Tag "Warn"
    if (-not (Test-HypervClusterDomainJoined)) {
        Write-Log "    Expected on a workgroup cluster: secure dynamic update needs a computer account and there is none" -Tag "Info"
    }
    Write-Log "    Create the record by hand on the DNS server:" -Tag "Info"
    Write-Log "        Add-DnsServerResourceRecordA -ZoneName '$suffix' -Name '$Name' -IPv4Address $address" -Tag "Info"
    Write-Log "    Or let the zone take unsecured updates" -Tag "Info"
    return $false
}

function New-HypervClusterHere {
    param([Parameter(Mandatory)][object]$Cluster)

    $existing = Get-HypervClusterHere
    if ($null -ne $existing) {
        Write-Log "Already in the cluster '$($existing.Name)' - left as it is" -Tag "Info"
        return $true
    }

    $name = Get-HypervClusterName -Cluster $Cluster
    Test-HypervClusterValidation -Cluster $Cluster

    $parameters = @{
        Name        = $name
        Node        = $env:COMPUTERNAME
        # The disks are handed over deliberately below rather than swept up at creation,
        # so that what becomes a Cluster Shared Volume is this run's decision.
        NoStorage   = $true
        Force       = $true
        ErrorAction = "Stop"
    }

    $address = [string](Get-ConfigText -InputObject $Cluster -Name "staticAddress" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($address)) { $parameters["StaticAddress"] = $address.Trim() }

    # A workgroup node has no computer object to put a cluster name in, so the name lives in
    # DNS alone. **New-Cluster builds it, and New-WorkgroupCluster is deliberately not used
    # here** - that is a decision rather than an omission, so it does not get "improved"
    # later:
    #
    #   - Microsoft's own workgroup-cluster procedure documents `New-Cluster -Name ...
    #     -AdministrativeAccessPoint DNS` and nothing else. `New-WorkgroupCluster` has a
    #     reference page under the Windows Server 2025 moniker, out of the AD-less module
    #     Microsoft.FailoverClusters.Adless.PowerShell, but no Microsoft procedure uses it.
    #   - Field report from a Lenovo S2D engineer running these clusters: a cluster built
    #     with it breaks things downstream - the Windows Admin Center extension among them.
    #
    # A cluster is created once and lived with for years. The documented path is the one
    # every tool that touches it afterwards expects to find.
    $workgroup = (-not (Test-HypervClusterDomainJoined))
    if ($workgroup) { $parameters["AdministrativeAccessPoint"] = "Dns" }

    Write-Log "Creating single-node cluster '$name'" -Tag "Run"
    try {
        $null = New-Cluster @parameters
        Write-Log "Cluster '$name' exists" -Tag "Ok"
        Test-HypervClusterNameRegistration -Name $name
        # The registration this name will never manage is switched off rather than left
        # to log 'No credentials are available in the security package' at every refresh
        # - see the helper for the whole story. Workgroup only: a domain cluster's
        # registration works and is wanted.
        if ($workgroup) { $null = Disable-HypervWorkgroupDnsRegistration }
        return $true
    }
    catch {
        Write-Log "Cluster not created: $($_.Exception.Message)" -Tag "Error"
        if ($workgroup) {
            Write-Log "    A workgroup cluster needs a primary DNS suffix on this node and a DNS zone its name can live in" -Tag "Info"
        }
        else {
            Write-Log "    In a domain the account running this needs 'Create Computer Objects' where the cluster name object goes" -Tag "Info"
        }
        return $false
    }
}

# ---------------------------[ Cluster Shared Volumes ]---------------------------
# C:\ClusterStorage on every Windows that has not been rebuilt oddly - read from the
# environment rather than hard-coded, with the hard-coded answer as the fallback for the
# case where it cannot be read at all.
function Get-HypervClusterStorageFolder {
    $root = [string]$env:SystemDrive
    if ([string]::IsNullOrWhiteSpace($root)) { $root = "C:" }
    # Built as a string rather than with Join-Path: Join-Path resolves the drive through
    # the provider, and a path is wanted here whether or not that drive can be reached.
    return ($root.TrimEnd("\") + "\ClusterStorage")
}

function Get-HypervClusterStorageEntry {
    $root = Get-HypervClusterStorageFolder
    if (-not (Test-Path -LiteralPath $root)) { return @() }
    try { return @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction Stop | ForEach-Object { $_.Name }) }
    catch { return @() }
}

# Whether a disk the cluster is offering is really a Storage Spaces virtual disk. The bus
# type says so outright - 'Spaces' - and that is the same string this repo logs when it
# claims one for a stand-alone data volume.
function Test-HypervDiskIsStorageSpace {
    param([Parameter(Mandatory)][object]$ClusterDisk)

    $number = -1
    try { $number = [int]$ClusterDisk.Number } catch { $number = -1 }
    if ($number -lt 0) { return $false }

    try {
        $disk = Get-Disk -Number $number -ErrorAction Stop
        return ([string]$disk.BusType -eq "Spaces")
    }
    catch {
        # Unreadable is not a reason to refuse it - Add-ClusterDisk gets its say instead.
        return $false
    }
}

# Every disk the cluster will take, handed over **one at a time**. Piping the whole set
# into Add-ClusterDisk makes one failure the answer for all of them: the bench saw "an
# error was encountered while creating storage resources", one disk claimed anyway, and no
# way to tell which. One call per disk means one line per disk.
function Add-HypervClusterDisk {
    $available = @()
    try { $available = @(Get-ClusterAvailableDisk -ErrorAction Stop) } catch { $available = @() }
    if ($available.Count -eq 0) {
        # The single most misleading moment in this whole role, so it is spelled out.
        # Failover Clustering only claims disks that implement SCSI-3 persistent
        # reservations, and a plain local disk - a VHDX on the guest's own controller, or
        # an array on the machine's own RAID card - does not. It is not that the volumes
        # are wrong: they are formatted, unlettered and sitting right there. The cluster
        # simply cannot own that kind of disk.
        Write-Log "The cluster sees no disk it can take - the volumes this run prepared are not the problem" -Tag "Error"
        Write-Log "    A cluster disk must hold SCSI-3 persistent reservations - a local disk, a VHDX on this guest's own controller and a local RAID array do not" -Tag "Info"
    Write-Log "    What qualifies: iSCSI or FC storage, a SAS JBOD, a shared VHDX or VHD Set from a clustered parent, or S2D - which needs two servers" -Tag "Debug"
        Write-Log "    Get-ClusterAvailableDisk -All shows what the cluster thinks of each disk" -Tag "Info"
        return 0
    }

    $added = 0
    foreach ($disk in $available) {
        $name = [string]$disk.Name
        if ([string]::IsNullOrWhiteSpace($name)) { $name = "disk $($disk.Number)" }

        # Refused before it is offered, rather than after it fails. A Storage Spaces
        # virtual disk can be *added* as a cluster disk and then never comes online:
        # 'Cluster physical disk resource failed to come online ... Reason:
        # AttachSpaceFailure', with a device number of 4294967295 and a null GUID, because
        # the cluster cannot attach a space it does not own.
        if (Test-HypervDiskIsStorageSpace -ClusterDisk $disk) {
            Write-Log "'$name' is a Storage Spaces virtual disk - left where it is" -Tag "Warn"
            Write-Log "    A clustered pool needs shared SAS disks with persistent reservations - anything else comes online as AttachSpaceFailure" -Tag "Info"
            continue
        }

        try {
            $null = $disk | Add-ClusterDisk -ErrorAction Stop
            Write-Log "'$name' is now a cluster disk" -Tag "Ok"
            $added++
        }
        catch {
            Write-Log "'$name' not handed to the cluster: $($_.Exception.Message)" -Tag "Warn"
            Write-Log "    Clustered Storage Spaces needs shared SAS" -Tag "Info"
        }
    }
    if ($added -eq 0) { Write-Log "No disk could be handed to the cluster" -Tag "Error" }
    return $added
}

# The volume label the *cluster* sees on a disk resource. Asked of the cluster's own WMI
# view rather than derived from a disk GUID: MSCluster_Resource leads to MSCluster_Disk
# leads to MSCluster_DiskPartition, which carries VolumeLabel outright. The GUID route
# below it is the fallback, and on the bench it was the one that came back empty.
function Get-HypervClusterResourceLabel {
    param([Parameter(Mandatory)][string]$ResourceName)

    try {
        $resource = @(Get-CimInstance -Namespace "root\MSCluster" -ClassName "MSCluster_Resource" `
                -Filter "Name='$($ResourceName.Replace("'", "''"))'" -ErrorAction Stop)[0]
        if ($null -eq $resource) { return "" }

        $disks = @(Get-CimAssociatedInstance -InputObject $resource -ResultClassName "MSCluster_Disk" -ErrorAction Stop)
        foreach ($disk in $disks) {
            $partitions = @(Get-CimAssociatedInstance -InputObject $disk -ResultClassName "MSCluster_DiskPartition" -ErrorAction Stop)
            foreach ($partition in $partitions) {
                $label = [string]$partition.VolumeLabel
                if (-not [string]::IsNullOrWhiteSpace($label)) { return $label }
            }
        }
    }
    catch { }
    return ""
}

# The cluster's own disk resources that are still in Available Storage, each with the
# volume label of whatever is on it. The label is how a disk is matched back to the name it
# was formatted with - the cluster's own names ('Cluster Disk 1') are assigned in whatever
# order it claimed them.
function Get-HypervClusterAvailableResource {
    $resources = @()
    try {
        $resources = @(Get-ClusterResource -ErrorAction Stop | Where-Object {
                $group = ""
                try { $group = [string]$_.OwnerGroup.Name } catch { $group = "" }
                ([string]$_.ResourceType -eq "Physical Disk") -and ($group -eq "Available Storage")
            })
    }
    catch { return @() }

    $result = @()
    foreach ($resource in $resources) {
        $label = Get-HypervClusterResourceLabel -ResourceName ([string]$resource.Name)
        try {
            if ([string]::IsNullOrWhiteSpace($label)) {
                # The cluster could not say, so ask Windows: the resource records the GPT
                # GUID of its disk, and that is enough to find the volume on it.
                $guid = [string]($resource | Get-ClusterParameter -Name "DiskIdGuid" -ErrorAction Stop).Value
                if (-not [string]::IsNullOrWhiteSpace($guid)) {
                    $disk = @(Get-Disk -ErrorAction Stop | Where-Object { [string]$_.Guid -eq $guid })[0]
                    if ($null -ne $disk) {
                        $volume = @(Get-Partition -DiskNumber $disk.Number -ErrorAction Stop |
                            Get-Volume -ErrorAction SilentlyContinue |
                            Where-Object { -not [string]::IsNullOrWhiteSpace($_.FileSystemLabel) })[0]
                        if ($null -ne $volume) { $label = [string]$volume.FileSystemLabel }
                    }
                }
            }
        }
        catch {
            # No label found is not a failure - it only means the volume is matched by
            # order below instead of by name.
            $label = ""
        }
        $result += [pscustomobject]@{ Resource = $resource; Name = [string]$resource.Name; Label = $label }
    }
    return @($result)
}

# One volume at a time. A CSV arrives as C:\ClusterStorage\VolumeN with a number nobody
# chose, and the cluster is asked where it put it - Get-ClusterSharedVolume answers with
# the mount point for that exact resource. An earlier version diffed the folder listing
# before and after, which is guesswork that fails the moment anything else appears there.
function Add-HypervClusterSharedVolume {
    param([Parameter(Mandatory)][string]$Label)

    $candidates = @(Get-HypervClusterAvailableResource)
    if ($candidates.Count -eq 0) {
        Write-Log "No disk left in Available Storage for '$Label'" -Tag "Warn"
        Write-Log "    A disk qualifies when it is basic, not the boot or system disk, and not already in use" -Tag "Info"
        return ""
    }

    # By label first, so csv-02 is the volume that was formatted csv-02 rather than
    # whichever disk the cluster happened to claim second.
    $match = @($candidates | Where-Object { $_.Label -eq $Label })
    if ($match.Count -eq 0) {
        $match = @($candidates[0])
        Write-Log "No disk in Available Storage carries the label '$Label' - the next one is used and named for its place" -Tag "Warn"
    }
    $resource = $match[0].Resource

    try {
        $null = Add-ClusterSharedVolume -Name $resource.Name -ErrorAction Stop
        Write-Log "'$($resource.Name)' is now a Cluster Shared Volume" -Tag "Ok"
    }
    catch {
        Write-Log "'$($resource.Name)' not converted to a CSV: $($_.Exception.Message)" -Tag "Error"
        return ""
    }

    $current = ""
    try {
        $shared = @(Get-ClusterSharedVolume -Name $resource.Name -ErrorAction Stop)[0]
        if ($null -ne $shared) { $current = [string]$shared.SharedVolumeInfo.FriendlyVolumeName }
    }
    catch { $current = "" }

    $root = Get-HypervClusterStorageFolder
    $wanted = Join-Path -Path $root -ChildPath $Label

    if ([string]::IsNullOrWhiteSpace($current)) {
        # The volume exists either way - the cluster took it a moment ago. Only its name
        # is unknown, so the caller still gets a usable path rather than a failure.
        Write-Log "No mount point reported for '$($resource.Name)' - '$Label' keeps the name it was given" -Tag "Warn"
        return ""
    }
    if ($current.TrimEnd("\") -eq $wanted.TrimEnd("\")) { return $wanted }
    if (Test-Path -LiteralPath $wanted) {
        Write-Log "'$wanted' already exists, so '$current' keeps its name" -Tag "Warn"
        return $current
    }

    try {
        # Renamed now because now is the only cheap moment: a mount point cannot be renamed
        # once anything holds a handle on it, and a running virtual machine is a handle.
        Rename-Item -LiteralPath $current -NewName $Label -ErrorAction Stop
        Write-Log "Mounted at '$wanted'" -Tag "Ok"
        return $wanted
    }
    catch {
        Write-Log "'$current' not renamed to '$Label': $($_.Exception.Message)" -Tag "Warn"
        return $current
    }
}

# When the cluster cannot take the disks, the volumes are still there and still right -
# the right specification, the right label, nothing on them. So rather than leave a host
# with prepared storage it cannot reach, the first one is given the drive letter the
# design would have used on a stand-alone host and the run carries on.
#
# It is a fallback and it says so: a cluster with no shared volume is a cluster in name
# only, and the log says what would make it real.
function Set-HypervClusterVolumeFallback {
    param(
        [Parameter(Mandatory)][object]$Hyperv,
        [Parameter(Mandatory)][string]$Label
    )

    $diskNumber = Get-HypervClusterVolumeDiskNumber -Label $Label
    if ($diskNumber -lt 0) {
        Write-Log "'$Label' is not on this server - nothing to fall back to" -Tag "Warn"
        return ""
    }

    $storage = Get-ConfigValue -InputObject $Hyperv -Name "storage"
    $letter = ([string](Get-ConfigText -InputObject $storage -Name "driveLetter" -Default "D:")).Trim().TrimEnd(":", "\")
    if ([string]::IsNullOrWhiteSpace($letter)) { $letter = "D" }

    if (-not (Clear-StudioDriveLetter -DriveLetter $letter)) {
        Write-Log "${letter}: could not be freed for '$Label'" -Tag "Error"
        return ""
    }

    $partition = $null
    try {
        $partition = @(Get-Partition -DiskNumber $diskNumber -ErrorAction Stop |
            Where-Object { $_.Type -ne "Reserved" })[0]
    }
    catch { $partition = $null }
    if ($null -eq $partition) {
        Write-Log "'$Label' has no partition to give a letter to" -Tag "Error"
        return ""
    }

    try {
        $null = Set-Partition -DiskNumber $diskNumber -PartitionNumber $partition.PartitionNumber -NewDriveLetter $letter -ErrorAction Stop
        Write-Log "'$Label' is at ${letter}: instead - the cluster could not take it, so it serves as an ordinary volume" -Tag "Warn"
        return "$($letter):\"
    }
    catch {
        Write-Log "'$Label' got no drive letter: $($_.Exception.Message)" -Tag "Error"
        return ""
    }
}

# ---------------------------[ Entry points ]---------------------------
# The pre-reboot half: the feature and the volumes. Both need no cluster service and no
# hypervisor, so they happen on the near side of the restart with everything else.
function Invoke-HypervClusterPreparation {
    param(
        [Parameter(Mandatory)][object]$Hyperv,
        [object]$Plan = $null
    )

    $cluster = Get-HypervClusterSection -Hyperv $Hyperv
    if ($null -eq $cluster) { return $false }

    $null = Test-HypervClusterPrerequisite -Cluster $cluster
    if (-not (Install-HypervClusterFeature -Cluster $cluster)) { return $false }

    # Before the restart, because that is the only moment it is free: the suffix needs one
    # and Hyper-V is about to take one anyway.
    $suffix = [string](Get-ConfigText -InputObject $cluster -Name "dnsSuffix" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($suffix)) { $null = Set-HypervPrimaryDnsSuffix -Suffix $suffix }

    $labels = @(New-HypervClusterVolumeSet -Cluster $cluster -Plan $Plan)
    return ($labels.Count -gt 0)
}

# The post-reboot half: the cluster itself, its volumes, and where virtual machines land.
# Returns the first Cluster Shared Volume path, or "" when there is nothing to point at.
function Invoke-HypervClusterConfiguration {
    param(
        [Parameter(Mandatory)][object]$Hyperv,
        [object]$Plan = $null
    )

    $cluster = Get-HypervClusterSection -Hyperv $Hyperv
    if ($null -eq $cluster) { return "" }

    if (-not (Test-HypervClusterFeatureInstalled)) {
        Write-Log "Failover Clustering not installed - no cluster created" -Tag "Error"
        return ""
    }
    if (-not (New-HypervClusterHere -Cluster $cluster)) { return "" }

    $labels = @(Get-HypervCsvLabel -Cluster $cluster)
    # The two paths want different numbers, and both are Microsoft's. On ReFS under
    # Hyper-V the instruction is 4K - "4K cluster sizes offer greater compatibility with
    # Hyper-V IO granularity", and 64K is for large sequential IO, which a VHDX is not. On
    # the NTFS shared-disk path 64K is the usual answer for a volume full of VHDX files.
    $defaultUnit = 65536
    if (Test-HypervClusterS2dMode -Cluster $cluster -Plan $Plan) { $defaultUnit = 4096 }
    $allocationUnitSize = [int](Get-ConfigValue -InputObject $cluster -Name "allocationUnitSize" -Default $defaultUnit)
    $root = Get-HypervClusterStorageFolder
    $paths = @()

    if (Test-HypervClusterS2dMode -Cluster $cluster -Plan $Plan) {
        # Storage Spaces Direct: the cluster builds the pool out of the local disks and
        # every volume is created, formatted, shared and mounted by one cmdlet.
        if (-not (Enable-HypervClusterS2d -Cluster $cluster -Plan $Plan)) { return "" }

        $pool = Get-HypervClusterS2dPool
        if ($null -eq $pool) {
            Write-Log "Storage Spaces Direct is on but its pool cannot be read" -Tag "Error"
            return ""
        }

        # Half each for two volumes, and the last one takes what is left - the same
        # arithmetic the stand-alone pool uses, for the same reason.
        # As many copies as the design asks for, as long as there is a disk to put each
        # one on. A copy per disk is the floor: the fault domain here is the physical
        # disk, so four copies with three disks has nowhere to put the fourth.
        # The console's answer wins over the design's: it was given while looking at the
        # disks that were actually ticked, and the design was written without seeing them.
        $copies = Get-HypervClusterCopies -Cluster $cluster -Plan $Plan

        $poolDisks = 0
        try { $poolDisks = @($pool | Get-PhysicalDisk -ErrorAction Stop).Count } catch { $poolDisks = 0 }
        if (($poolDisks -gt 0) -and ($poolDisks -lt $copies)) {
            # Short of disks for the resiliency that was asked for. Never downgraded
            # silently: a volume with fewer copies than the design asked for looks like
            # storage and survives less than the operator believes it does. A simple
            # space is available - it just has to be chosen by name.
            Write-Log ("A {0}-copy mirror needs {0} disks and the pool has {1} - no volume created" -f $copies, $poolDisks) -Tag "Error"
            if ($poolDisks -ge 2) {
                Write-Log ("    Ask for {0} copies, or add {1} disk(s)" -f $poolDisks, ($copies - $poolDisks)) -Tag "Info"
            }
            else {
                Write-Log "    A one-disk pool holds a simple space only - choose Simple deliberately, or add a disk" -Tag "Info"
            }
            return ""
        }
        Write-Log ("Volumes: {0} copies across physical disks" -f $copies) -Tag "Info"

        $share = Get-HypervClusterVolumeSize -Pool $pool -Copies $copies -Count $labels.Count

        for ($index = 0; $index -lt $labels.Count; $index++) {
            $label = $labels[$index]
            $wanted = Join-Path -Path $root -ChildPath $label
            if (Test-Path -LiteralPath $wanted) {
                Write-Log "'$wanted' is already a Cluster Shared Volume" -Tag "Info"
                $paths += $wanted
                continue
            }
            # Every volume the same size, deliberately. Letting the last one take the
            # remainder is how csv-01 came out 9.94 GB and csv-02 5.94 GB, which makes a
            # nonsense of two volumes meant to be interchangeable.
            $path = New-HypervClusterS2dVolume -Label $label -Pool $pool -SizeBytes $share `
                -AllocationUnitSize $allocationUnitSize -MirrorCopies $copies
            if (-not [string]::IsNullOrWhiteSpace($path)) { $paths += $path }
        }
    }
    else {
        # Shared disks: storage presented from outside this host - a SAN LUN, a SAS JBOD, an
        # iSCSI target - handed over and converted.
        $null = Add-HypervClusterDisk

        foreach ($label in $labels) {
            $wanted = Join-Path -Path $root -ChildPath $label
            if (Test-Path -LiteralPath $wanted) {
                Write-Log "'$wanted' is already a Cluster Shared Volume" -Tag "Info"
                $paths += $wanted
                continue
            }
            $path = Add-HypervClusterSharedVolume -Label $label
            if (-not [string]::IsNullOrWhiteSpace($path)) { $paths += $path }
        }
    }

    if ($paths.Count -eq 0) {
        Write-Log "The cluster exists and has no Cluster Shared Volume" -Tag "Error"
        return ""
    }
    # The advice differs by path, and the wrong half of it is worse than none: the 15% rule
    # is snapshot space, and an S2D volume takes no software snapshot.
    $s2dVolumes = Test-HypervClusterS2dMode -Cluster $cluster -Plan $Plan
    foreach ($path in $paths) { Write-HypervCsvFreeSpaceNote -Path $path -S2d:$s2dVolumes }
    if ($paths.Count -eq 1) {
        Write-Log "One Cluster Shared Volume built. Two is the arrangement Microsoft describes - system disks on one, data on the other - and gives a backup a second volume to snapshot" -Tag "Warn"
    }
    # Every one of them, in order. The caller makes the guest folders on all and points
    # the host at the first.
    return @($paths)
}
