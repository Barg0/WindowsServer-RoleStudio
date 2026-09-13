# Role provider: File Server - shares, their ACLs, DFS namespaces, shadow copies.
#
# Dot-sourced by Configure-ServerRoles.ps1 - not runnable on its own. Everything
# here lands in that script's scope, so $script: variables and functions are shared
# with every other part. Use $scriptRootPath, never $PSScriptRoot: inside this file
# $PSScriptRoot is the pwsh folder, not the folder the run was started from.

# ===========================[ File Server ]===========================
# One config, two machines, same rule as AD CS: the *file server* builds folders,
# ACLs, shares, shadow copies and the DFS namespace; a *domain controller* handed
# the same config builds the share groups and their members, because those live in
# the directory and are the DC's to write. On the file server the groups are a
# prerequisite - the run refuses to start while one is missing, and never creates
# them there (the account driving a file server holds that server's rights, not
# necessarily the right to write groups into AD).
#
# The ACL model is deliberate and fixed, not configurable:
#   - inheritance is disabled on each share folder (nothing above it decides who
#     reads a share),
#   - local Administrators and SYSTEM hold Full control,
#   - the share group holds Full control minus 'Change permissions' and 'Take
#     ownership' - everything a working group needs, nothing that lets a member
#     rewrite who has access.
# Share-level permissions carry the group and local Administrators at Full and rely
# on NTFS for the real decision, which is the long-standing Microsoft guidance.
#
# A share may name a SECOND group - `readGroup` - and that one gets Read & execute on
# the folder and Read on the share. It is the only thing about the model a design
# decides, and it is additive: a share with no readGroup is byte-for-byte the ACL this
# role has always written, which is why the read-only tier is a second rule added to the
# descriptor rather than a second model beside `standard` and `fslogixContainer`. A
# profile container share never has one - a user who cannot write their own container
# cannot sign in - and the studio refuses that design rather than writing it.

$script:fsShareGroupRights = [System.Security.AccessControl.FileSystemRights](
    [System.Security.AccessControl.FileSystemRights]::FullControl -bxor
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bxor
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership)

# The read-only tier. ReadAndExecute already carries Read, ReadData, ReadAttributes,
# ReadExtendedAttributes, ReadPermissions and Traverse; Synchronize is added because
# every right this API grants through a handle needs it and the .NET FileSystemRights
# enum does not fold it in the way the Explorer dialog does - without it a reader can
# list a folder and cannot open a file in it.
$script:fsReadGroupRights = [System.Security.AccessControl.FileSystemRights](
    [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
    [System.Security.AccessControl.FileSystemRights]::Synchronize)

# What the task used to be called before it adopted the console's own convention -
# removed on sight so a server that has been through both is not snapshotting twice.
$script:fsLegacyShadowCopyTaskName = "WSRS-ShadowCopy"

# ---------------------------[ Config readers ]---------------------------
# A design has one volume or two, and the ACL model decides which one a share lands
# on - no per-share volume picker, because the question "is this a profile container"
# has already been answered by the button that created the share. `profileRoot` absent
# or off is exactly the single-volume build this role has always done.
#
# Two volumes rather than two folders on one, and every reason is a per-VOLUME switch:
# deduplication, shadow copies and the antivirus exclusion are all set on a volume, and
# the answer for a share full of documents is the opposite of the answer for a folder
# full of open VHDX. A profile volume that fills stops every sign-in; a share volume
# that fills stops saves. Same folder, one blast radius; two volumes, two.
#
# `folderName` may be empty, and that is a stated design rather than a missing value:
# the shares sit at the volume root and the LABEL carries the name instead. On a volume
# that holds nothing but shares, a containing folder is a level that names what the
# whole volume already is - and it costs a level of MAX_PATH on the one tree where deep
# user paths are normal.
function Get-FsLabelFromFolder {
    # The folder name with a capital first letter. Folders are lower case everywhere in
    # this design; the label is the one place the name is shown to a person, in Explorer
    # and in Disk Management, and there it reads as a name rather than a path component.
    param(
        [string]$Folder,
        [Parameter(Mandatory)][string]$Default
    )

    $trimmed = ([string]$Folder).Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) { return $Default }
    if ($trimmed.Length -eq 1) { return $trimmed.ToUpperInvariant() }
    return ($trimmed.Substring(0, 1).ToUpperInvariant() + $trimmed.Substring(1))
}

function New-FsRoot {
    param(
        [object]$Section,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$DefaultDrive,
        # Empty is a real value here - the profile root defaults to the volume root -
        # and a Mandatory [string] rejects "" outright.
        [Parameter(Mandatory)][AllowEmptyString()][string]$DefaultFolder,
        [Parameter(Mandatory)][string]$DefaultLabel,
        [Parameter(Mandatory)][int]$DefaultUnits,
        [object]$Legacy = $null,
        # Only the profile root offers it, so it is a switch here rather than a read:
        # a share volume holds several shares by definition and can never be one.
        [bool]$AllowWholeVolume = $false
    )

    $drive = ([string](Get-ConfigText -InputObject $Section -Name "drive" -Default $DefaultDrive)).Trim().TrimEnd("\")
    if (-not $drive.EndsWith(":")) { $drive = $drive + ":" }

    # Present-and-empty and absent are different answers here, which is why this is not
    # a -Default read: absent means "this design predates the choice" and gets the
    # folder it has always had; empty means somebody chose the volume root.
    $folder = $DefaultFolder
    if (Test-ConfigProperty -InputObject $Section -Name "folderName") {
        $folder = [string](Get-ConfigText -InputObject $Section -Name "folderName" -Default "")
    }
    $folder = ([string]$folder).Trim().Trim("\")

    $label = ([string](Get-ConfigText -InputObject $Section -Name "label" -Default "")).Trim()
    if ([string]::IsNullOrWhiteSpace($label) -and $null -ne $Legacy) {
        # guestCluster.volumeLabel is where the cluster mode used to state this, and a
        # config written before the roots carried their own is still a valid design.
        $label = ([string](Get-ConfigText -InputObject $Legacy -Name "volumeLabel" -Default "")).Trim()
    }
    if ([string]::IsNullOrWhiteSpace($label)) { $label = Get-FsLabelFromFolder -Folder $folder -Default $DefaultLabel }

    $units = 0
    if (Test-ConfigProperty -InputObject $Section -Name "allocationUnitSize") {
        $units = [int](Get-ConfigValue -InputObject $Section -Name "allocationUnitSize" -Default $DefaultUnits)
    }
    elseif ($null -ne $Legacy -and (Test-ConfigProperty -InputObject $Legacy -Name "allocationUnitSize")) {
        $units = [int](Get-ConfigValue -InputObject $Legacy -Name "allocationUnitSize" -Default $DefaultUnits)
    }
    if ($units -le 0) { $units = $DefaultUnits }

    $path = "{0}\" -f $drive
    if (-not [string]::IsNullOrWhiteSpace($folder)) { $path = "{0}\{1}" -f $drive, $folder }

    # The share IS the volume: no root folder, no per-share folder, the share published
    # straight at the volume root. It is the profile volume's normal shape - a disk given
    # over entirely to containers has nothing to name a folder after that the volume label
    # does not already say - and it is what removes the volume root's default
    # Authenticated Users create-folder right, because the share's own descriptor replaces
    # it. Exactly one share can be the volume, which the caller enforces.
    $wholeVolume = $false
    if ($AllowWholeVolume) {
        $wholeVolume = [bool](Get-ConfigValue -InputObject $Section -Name "wholeVolume" -Default $true)
    }
    if ($wholeVolume) { $folder = ""; $path = "{0}\" -f $drive }

    return [pscustomobject]@{
        Key                     = $Key
        Drive                   = $drive
        Folder                  = $folder
        WholeVolume             = $wholeVolume
        Label                   = $label
        Path                    = $path
        AllocationUnitSize      = $units
        # Large file record segments travel with 64K units rather than being asked for
        # separately: the two are one recommendation, and a volume that wants one and
        # not the other is a spec nobody stated.
        LargeFileRecordSegments = ($units -ge 65536)
    }
}

function Get-FsRootDefinition {
    param(
        [Parameter(Mandatory)][object]$FileServer,
        [object]$Legacy = $null
    )

    $roots = @()
    $roots += (New-FsRoot -Section (Get-ConfigValue -InputObject $FileServer -Name "root") -Key "data" `
            -DefaultDrive "D:" -DefaultFolder "shares" -DefaultLabel "Shares" -DefaultUnits 4096 -Legacy $Legacy)

    # 64K units and large FRS on this one, 4K on the other, and they must never converge
    # on a shared default - the same rule Storage.ps1 states for the Exchange and
    # Hyper-V volume specs. A profile volume holds a handful of GB-scale VHDX per user,
    # where 64K slack is noise and the extent count is what eventually bites; a document
    # share holds many small files, where 64K slack is real and no VHDX reasoning applies.
    $profileSection = Get-ConfigValue -InputObject $FileServer -Name "profileRoot"
    if ($null -ne $profileSection -and [bool](Get-ConfigValue -InputObject $profileSection -Name "enabled" -Default $false)) {
        $roots += (New-FsRoot -Section $profileSection -Key "profile" `
                -DefaultDrive "E:" -DefaultFolder "" -DefaultLabel "Profiles" -DefaultUnits 65536 -AllowWholeVolume $true)
    }
    return ,$roots
}

# Which volume a share lives on. The ACL model is the whole rule.
function Get-FsRootForShare {
    param(
        [Parameter(Mandatory)][object[]]$Roots,
        [Parameter(Mandatory)][object]$Share
    )

    if ($Share.AccessModel -eq "fslogixContainer") {
        $profileRoot = @($Roots | Where-Object { $_.Key -eq "profile" })
        if ($profileRoot.Count -gt 0) { return $profileRoot[0] }
    }
    return (@($Roots | Where-Object { $_.Key -eq "data" })[0])
}

# Where a share's folder is. Normally a child of the root; on a whole-volume root it IS
# the root, and there is nothing to create.
function Get-FsSharePath {
    param(
        [Parameter(Mandatory)][object]$Root,
        [Parameter(Mandatory)][object]$Share
    )

    if ($Root.WholeVolume) { return $Root.Path }
    return (Join-Path -Path $Root.Path -ChildPath $Share.Name)
}

# The volume behind a root, brought to the specification the design states. Preparing it
# is this run's job rather than a list of commands somebody types first - a design that
# says "64K units and large file record segments" and then asks a person to remember that
# at format time has not designed anything.
#
# Every destructive edge is Initialize-StudioDataVolume's, and it is the same contract
# Exchange and Hyper-V already build their volumes under:
#
#   no volume at the letter      a raw disk is claimed, partitioned and formatted
#   volume matches the spec      nothing happens
#   volume with NO file system   formatted to the spec - a partition never formatted is
#                                not "unreadable, so assume data", it is blank
#   off-spec and EMPTY           reformatted to the spec
#   off-spec and HOLDS DATA      left exactly as it is, warned, with the command printed
#   boot or system disk          refused
#
# The fourth row is the one that stays a report and must: reformatting a volume because
# its allocation unit disagrees with a design would destroy the shares the design is
# about. `fileServer.prepareVolumes` turns the whole thing off for somebody who wants the
# old report-only behaviour.
function Confirm-FsVolume {
    param(
        [Parameter(Mandatory)][object]$Root,
        [bool]$Prepare = $true,
        # -1 is "no disk was named", which is the single-candidate rule. A number comes
        # from the picker, and only when more than one volume had to be built.
        [int]$DiskNumber = -1
    )

    $letter = $Root.Drive.TrimEnd(":")

    # Before anything is created, claimed or formatted. A whole-volume share means
    # Set-FsFolderSecurity rebuilds the descriptor of the VOLUME ROOT - inheritance off,
    # and only the rules the design states. That is right on a disk given over to
    # containers and catastrophic on the system drive, so it is a refusal rather than a
    # warning, and it lands before the volume work rather than after it.
    if ($Root.WholeVolume -and (Test-StudioSystemDriveLetter -DriveLetter $letter)) {
        Write-Log "$($Root.Drive) is the system drive, and this root publishes the share at the volume root" -Tag "Error"
        Write-Log "    That rebuilds the root's own ACL from the design - never on the drive Windows is installed on" -Tag "Error"
        return $false
    }

    # NTFS, always. ReFS is the tempting answer for a volume full of VHDX and it is the
    # wrong one here: FSLogix issues none of the operations ReFS accelerates - containers
    # are dynamic, so there is no fixed-disk zeroing, and read-only differencing disks are
    # discarded rather than merged - integrity streams have to be off on a VHDX anyway,
    # and ReFS has no disk quotas, which is the one control a profile share wants.
    # $IntegrityStreams is therefore passed as false and never read.
    $result = Initialize-StudioDataVolume -DriveLetter $letter -FileSystem "NTFS" `
        -AllocationUnitSize $Root.AllocationUnitSize -Label $Root.Label -IntegrityStreams $false `
        -LargeFileRecordSegments $Root.LargeFileRecordSegments -AllowPrepare:$Prepare -DiskNumber $DiskNumber

    if (-not $result.Ready) {
        Write-Log "$($Root.Drive) is not ready for the $($Root.Key) shares: $($result.Message)" -Tag "Error"
        return $false
    }
    if (-not $result.ToSpec) {
        Write-Log $result.Message -Tag "Warn"
        if ($Root.LargeFileRecordSegments) {
            Write-Log "    On a container volume that is not cosmetic: a dynamically expanding VHDX runs out of file record" -Tag "Warn"
            Write-Log "    space for its extents and stops being extendable, which arrives as a profile that will not load" -Tag "Warn"
        }
    }
    else {
        Write-Log $result.Message -Tag "Ok"
    }

    # A volume that already matched the spec was never formatted, so its label is still
    # whatever it was called before. Setting it is reversible and touches no data.
    $volume = $null
    try { $volume = Get-Volume -DriveLetter $letter -ErrorAction Stop } catch { $volume = $null }
    if (($null -ne $volume) -and ([string]$volume.FileSystemLabel -cne $Root.Label)) {
        try {
            $null = Set-Volume -DriveLetter $letter -NewFileSystemLabel $Root.Label -ErrorAction Stop
            Write-Log "$($Root.Drive) labelled '$($Root.Label)'" -Tag "Ok"
        }
        catch {
            Write-Log "$($Root.Drive) could not be labelled '$($Root.Label)': $($_.Exception.Message)" -Tag "Warn"
        }
    }

    return $true
}

# Every volume the design needs, built in one pass. The disk question is asked exactly
# once and only when it is a question: one volume to build is the single-candidate rule
# Initialize-StudioDataVolume already applies, and asking there would be a menu with one
# item. Two is genuinely ambiguous - two blank disks and two volumes, and nothing on
# either disk says which is which - so the picker runs and each volume is built from the
# disk it names.
function Confirm-FsVolumeSet {
    param(
        [Parameter(Mandatory)][object[]]$Roots,
        [bool]$Prepare = $true
    )

    $assigned = @{}
    if ($Prepare) {
        $missing = @($Roots | Where-Object { -not (Test-FsVolumePresent -Drive $_.Drive) })
        if ($missing.Count -gt 1) {
            $candidates = @(Get-FsClaimableDisk)
            if ($candidates.Count -lt $missing.Count) {
                Write-Log ("{0} volume(s) have to be built and {1} uninitialised disk(s) are visible" -f $missing.Count, $candidates.Count) -Tag "Error"
                Write-Log "    One disk per volume - present the missing one, or design a single volume" -Tag "Error"
                return $false
            }
            $pairs = Select-FsDiskForRoot -Roots $missing -Candidate $candidates
            if ($null -eq $pairs) {
                Write-Log "No disk was assigned to a volume - nothing was formatted" -Tag "Error"
                return $false
            }
            foreach ($line in $script:fsDiskChoice) { Write-Log $line -Tag "Info" }
            foreach ($pair in $pairs) { $assigned[$pair.Root.Drive] = [int]$pair.Disk.Number }
        }
    }

    $ok = $true
    foreach ($root in $Roots) {
        $number = -1
        if ($assigned.ContainsKey($root.Drive)) { $number = [int]$assigned[$root.Drive] }
        if (-not (Confirm-FsVolume -Root $root -Prepare $Prepare -DiskNumber $number)) { $ok = $false }
    }
    return $ok
}

function Test-FsVolumePresent {
    param([Parameter(Mandatory)][string]$Drive)
    try { return ($null -ne (Get-Volume -DriveLetter $Drive.TrimEnd(":") -ErrorAction Stop)) } catch { return $false }
}

# Raw, unclaimed, not the disk Windows booted from. The same set Get-StudioClaimableDisk
# picks its single candidate out of - this one returns all of them, because with two
# volumes to build "more than one" is the normal case rather than the ambiguous one.
function Get-FsClaimableDisk {
    if (-not (Get-Command -Name "Get-Disk" -ErrorAction SilentlyContinue)) { return @() }
    try {
        return @(Get-Disk -ErrorAction Stop | Where-Object {
                ($_.PartitionStyle -eq "RAW") -and (-not $_.IsBoot) -and (-not $_.IsSystem) -and (-not $_.IsClustered)
            })
    }
    catch {
        Write-Log "The disks could not be read: $($_.Exception.Message)" -Tag "Warn"
        return @()
    }
}

# The root folder, when the design states one. An empty folder name means the shares sit
# at the volume root, which already exists - creating it is neither possible nor needed.
function New-FsRootFolder {
    param([Parameter(Mandatory)][object]$Root)

    if ($Root.WholeVolume) {
        Write-Log "$($Root.Drive) is given over to one share, published at the volume root and labelled '$($Root.Label)'" -Tag "Info"
        return $true
    }
    if ([string]::IsNullOrWhiteSpace($Root.Folder)) {
        Write-Log "$($Root.Drive) carries its $($Root.Key) shares at the volume root, labelled '$($Root.Label)'" -Tag "Info"
        return $true
    }
    if (Test-Path -LiteralPath $Root.Path) { return $true }
    try {
        $null = New-Item -ItemType Directory -Path $Root.Path -Force -ErrorAction Stop
        Write-Log "Created '$($Root.Path)'" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "'$($Root.Path)' could not be created: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

function Get-FsShare {
    param([Parameter(Mandatory)][object]$FileServer)

    $shares = @()
    foreach ($entry in @(Get-ConfigArray -InputObject $FileServer -Name "shares")) {
        if ($null -eq $entry) { continue }
        $name = Get-ConfigText -InputObject $entry -Name "name"
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        # Anything that is not the one known profile value is the standard model. An
        # unrecognised string read the other way would re-grade a general-purpose share
        # to an ACL under which nobody currently listed can read what is already in it.
        $model = Get-ConfigText -InputObject $entry -Name "accessModel" -Default "standard"
        if ($model -ne "fslogixContainer") { $model = "standard" }

        # Three-valued on purpose: absent means "follow the server-wide setting", which
        # is not the same answer as False and must not be flattened into one.
        $shareAbe = $null
        if (Test-ConfigProperty -InputObject $entry -Name "accessBasedEnumeration") {
            $shareAbe = [bool](Get-ConfigValue -InputObject $entry -Name "accessBasedEnumeration" -Default $true)
        }

        # The read-only tier, empty when the design has none. Never read on a profile
        # container share: the studio refuses to write one there, and acting on a value
        # that reached the file some other way would grant read-only rights on a folder
        # whose whole ACL exists so each user can write their own container.
        $readGroup = Get-ConfigText -InputObject $entry -Name "readGroup"
        if ($model -eq "fslogixContainer" -and -not [string]::IsNullOrWhiteSpace($readGroup)) {
            Write-Log "'$name' is a profile share and names the read-only group '$readGroup' - ignored, a container share has no read-only tier" -Tag "Warn"
            $readGroup = ""
        }

        $shares += [pscustomobject]@{
            Name        = $name
            Hidden      = [bool](Get-ConfigValue -InputObject $entry -Name "hidden" -Default $true)
            Group       = Get-ConfigText -InputObject $entry -Name "group"
            ReadGroup   = $readGroup
            Description = Get-ConfigText -InputObject $entry -Name "description"
            AccessModel = $model
            Abe         = $shareAbe
        }
    }
    return ,$shares
}

# The SMB name is the share name plus $ when the share is hidden - the $ is an SMB
# convention, not part of the folder name.
function Get-FsSmbName {
    param([Parameter(Mandatory)][object]$Share)
    if ($Share.Hidden) { return ($Share.Name + "$") }
    return $Share.Name
}

# ---------------------------[ Which disk is which volume ]---------------------------
# Two raw disks and two volumes is the one question a machine cannot answer, and it is the
# same question on a single host and in the cluster - so it is asked in one place.
# Nothing on a raw disk says which volume it was meant to be - not its size, not its bus,
# not the order Windows enumerated it in - and the consequence of guessing is a profile
# volume formatted 4K where the shares were meant to go, discovered months later as a
# container that will not grow. So it is asked, the same way the Hyper-V host asks which
# disk becomes its data volume, with the same picker and the same disk detail lines.
#
# Gated exactly the way that interview is: never under -NoGui, never in the resume leg,
# never without a real interactive session. A prompt in the resume task is a scheduled
# task that never returns, and that task runs as SYSTEM.
function Test-FsDiskChoiceWanted {
    if ($script:noGui) { return $false }
    if ($script:isResume) { return $false }
    if (-not [Environment]::UserInteractive) { return $false }
    return (Test-MenuHostSupported)
}

# What the picker has settled so far, drawn above every question. The answer is chosen
# against the list rather than against memory - and on the second question the first
# disk is gone from the menu, so the list is the only place it is still visible.
#
# Read out of $script: rather than captured, and the PreItems scriptblock below is a
# plain one for the same reason: .GetNewClosure() binds to a fresh dynamic module, and
# on 5.1 a module scope cannot see a function defined at script scope. Same trap
# Confirm-RunPlan documents.
$script:fsDiskChoice = @()

function Write-FsDiskChoice {
    if ($script:fsDiskChoice.Count -eq 0) { return }
    Write-Host ""
    Write-Host "  Already assigned" -ForegroundColor DarkCyan
    foreach ($line in $script:fsDiskChoice) {
        Write-Host ("    " + $line) -ForegroundColor Gray
    }
    Write-Host ""
}

# One question per volume that still needs a disk, in root order - the share volume
# first, because that is the one somebody is thinking about. A disk that has been chosen
# is gone from the next question, so the same disk cannot be given to both.
#
# Returns one {Root, Disk} pair per root, or $null when the operator cancelled. Cancel is
# a refusal rather than a fall-back to the size order: somebody who pressed Escape at
# "this disk will be formatted and everything on it is lost" has not asked for a guess.
function Select-FsDiskForRoot {
    param(
        [Parameter(Mandatory)][object[]]$Roots,
        [Parameter(Mandatory)][object[]]$Candidate
    )

    $remaining = @($Candidate)
    $pairs = @()
    $script:fsDiskChoice = @()

    # Largest first, which is the order the automatic path hands them out in: a share
    # volume is normally the bigger one. It is also the order the menu lists them in, so
    # the recommended answer is the one already under the cursor.
    $remaining = @($remaining | Sort-Object -Property Size -Descending)

    # Nothing to decide is not a question. One volume and one disk is what this mode has
    # always built, and it has never asked - so it still does not.
    $ask = (Test-FsDiskChoiceWanted) -and (($Roots.Count -gt 1) -or ($remaining.Count -gt 1))
    if (-not $ask) {
        Write-Log "Disks are assigned by size, largest first - the picker needs an interactive session and more than one answer" -Tag "Debug"
    }

    foreach ($root in $Roots) {
        if ($remaining.Count -eq 0) { return $null }
        $disk = $remaining[0]

        if ($ask) {
            $items = @()
            foreach ($entry in $remaining) {
                $items += [pscustomobject]@{
                    Id     = [string]$entry.Number
                    Label  = ("disk {0}   {1}   {2}" -f $entry.Number,
                        (Format-StudioCapacity -Bytes $entry.Size), [string]$entry.BusType)
                    Detail = @(Get-StudioDiskDetail -Disk $entry)
                }
            }

            $hint = "{0} byte allocation unit{1}, 8.3 short names off. The disk is formatted and everything on it is lost." -f `
                $root.AllocationUnitSize, $(if ($root.LargeFileRecordSegments) { ", large file record segments" } else { "" })

            $answer = Show-Menu -Title "File server" -Subtitle "Volumes" `
                -Heading ("Which disk becomes {0}, labelled '{1}'?" -f $root.Drive, $root.Label) `
                -HeadingHint $hint -PreItems { Write-FsDiskChoice } -Items $items

            if ([string]::IsNullOrWhiteSpace($answer)) {
                Write-Log "Cancelled at the shared disk question - nothing was formatted" -Tag "Warn"
                return $null
            }
            $chosen = @($remaining | Where-Object { [string]$_.Number -eq [string]$answer })
            if ($chosen.Count -eq 0) { return $null }
            $disk = $chosen[0]
        }

        $pairs += [pscustomobject]@{ Root = $root; Disk = $disk }
        $script:fsDiskChoice += ("{0}  '{1}'   <-  disk {2}, {3}, {4} byte units" -f $root.Drive, $root.Label,
            $disk.Number, (Format-StudioCapacity -Bytes $disk.Size), $root.AllocationUnitSize)
        $remaining = @($remaining | Where-Object { $_.Number -ne $disk.Number })
    }

    return ,$pairs
}

# ---------------------------[ NTFS security ]---------------------------
# The descriptor is rebuilt from the design on every run rather than patched, so a
# hand-added ACE does not survive and the folder always matches the screen it was
# designed on. Inheritance is disabled without copying: what the parent grants is
# exactly what a share folder must not inherit.
function Set-FsFolderSecurity {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$GroupName,
        # The read-only tier, or empty for the single-group design. Only meaningful on
        # the standard model - see the part header.
        [string]$ReadGroupName = "",
        [ValidateSet("standard", "fslogixContainer")][string]$AccessModel = "standard"
    )

    $everything = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
    $propagate = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow

    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)

    $system = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $admins = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $full   = [System.Security.AccessControl.FileSystemRights]::FullControl

    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, $full, $everything, $propagate, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admins, $full, $everything, $propagate, $allow)))

    $groupSid = Get-FsGroupSid -Name $GroupName
    if ($null -eq $groupSid) {
        Write-Log "Group '$GroupName' does not resolve - ACL keeps Administrators and SYSTEM only" -Tag "Error"
        [System.IO.Directory]::SetAccessControl((Get-Item -LiteralPath $Path).FullName, $acl)
        return $false
    }

    if ($AccessModel -eq "fslogixContainer") {
        # Microsoft's documented profile container permissions, and the three scopes are
        # the whole point - the general-purpose model above cannot express them, because
        # it gives every principal this folder, subfolders and files.
        #
        #   the group      Modify   this folder only          - create your own container
        #                                                       folder, reach into nobody
        #                                                       else's, because the right
        #                                                       is not inherited downward
        #   CREATOR OWNER  Modify   subfolders and files only - the folder a user creates
        #                                                       is theirs by ownership,
        #                                                       rather than by an access
        #                                                       rule written per user
        #
        # CREATOR OWNER is resolved by SID: it is ERSTELLER-BESITZER on a German server,
        # and a name lookup there does not fail, it finds nothing.
        $thisFolderOnly = [System.Security.AccessControl.InheritanceFlags]::None
        $childrenOnly   = [System.Security.AccessControl.PropagationFlags]::InheritOnly
        $modify         = [System.Security.AccessControl.FileSystemRights]::Modify
        $creatorOwner   = New-Object System.Security.Principal.SecurityIdentifier(
            [System.Security.Principal.WellKnownSidType]::CreatorOwnerSid, $null)

        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $groupSid, $modify, $thisFolderOnly, $propagate, $allow)))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $creatorOwner, $modify, $everything, $childrenOnly, $allow)))

        [System.IO.Directory]::SetAccessControl((Get-Item -LiteralPath $Path).FullName, $acl)
        Write-Log "ACL '$Path': profile model - '$GroupName' modify at root, CREATOR OWNER below, Administrators + SYSTEM full" -Tag "Ok"
        return $true
    }

    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($groupSid, $script:fsShareGroupRights, $everything, $propagate, $allow)))

    # The read-only tier, when the design names one. A missing group here is an error
    # rather than a silent omission: the descriptor is rebuilt from scratch on every run,
    # so carrying on would publish a share that reads to its designer as having readers
    # and to everybody in that group as access denied.
    $readDescription = ""
    if (-not [string]::IsNullOrWhiteSpace($ReadGroupName)) {
        $readSid = Get-FsGroupSid -Name $ReadGroupName
        if ($null -eq $readSid) {
            Write-Log "Read-only group '$ReadGroupName' does not resolve - '$Path' has no read-only tier" -Tag "Error"
            [System.IO.Directory]::SetAccessControl((Get-Item -LiteralPath $Path).FullName, $acl)
            return $false
        }
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($readSid, $script:fsReadGroupRights, $everything, $propagate, $allow)))
        $readDescription = ", '$ReadGroupName' read and execute"
    }

    [System.IO.Directory]::SetAccessControl((Get-Item -LiteralPath $Path).FullName, $acl)
    Write-Log "ACL '$Path': inheritance off, Administrators + SYSTEM full, '$GroupName' full minus perms/ownership$readDescription" -Tag "Ok"
    return $true
}

# The SID comes off the directory object rather than through NTAccount.Translate
# first, for the same reason the AD CS grants do it: a name lookup can land on a
# DC that has not replicated the group yet.
function Get-FsGroupSid {
    param([Parameter(Mandatory)][string]$Name)

    try {
        $entry = Find-AdcsGroup -Name $Name
        if ($null -ne $entry) {
            $bytes = [byte[]]$entry.Properties["objectsid"][0]
            return (New-Object System.Security.Principal.SecurityIdentifier($bytes, 0))
        }
    }
    catch {
        Write-Log "Directory lookup for '$Name' failed: $($_.Exception.Message)" -Tag "Debug"
    }
    try {
        $account = New-Object System.Security.Principal.NTAccount($Name)
        return $account.Translate([System.Security.Principal.SecurityIdentifier])
    }
    catch {
        return $null
    }
}

# ---------------------------[ SMB shares ]---------------------------
function Set-FsSmbShare {
    param(
        [Parameter(Mandatory)][object]$Share,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][bool]$AccessBasedEnumeration,
        # Guest cluster mode only. A share on a cluster node with no scope belongs to
        # the NODE and does not move with the role - it looks identical in Get-SmbShare
        # and is gone the moment the file server fails over. The scope is the role's
        # client access point name, which is what makes the share the cluster's.
        [string]$ScopeName = "",
        # SMB Transparent Failover: the handles survive a planned move, which is the
        # entire reason a file server is clustered. Off on a single host, where there is
        # nothing to fail over to and the write-through cost buys nothing.
        [bool]$ContinuouslyAvailable = $false
    )

    $smbName = Get-FsSmbName -Share $Share
    $scoped = @{}
    if (-not [string]::IsNullOrWhiteSpace($ScopeName)) { $scoped["ScopeName"] = $ScopeName }
    $existing = Get-SmbShare -Name $smbName @scoped -ErrorAction SilentlyContinue

    if ($null -ne $existing -and $existing.Path -ne $Path) {
        Write-Log "Share '$smbName' points at '$($existing.Path)' - not repointed" -Tag "Error"
        return $false
    }

    # Share permissions stay coarse on purpose: the group and local Administrators
    # at Full, nothing else - Everyone is never granted, and NTFS above carries the
    # real decision.
    #
    # The read-only group is the one exception and it is granted Read rather than Full.
    # The effective right is identical either way - NTFS already stops it writing - but a
    # share whose permission tab says Full control for a group that cannot create a file
    # is a tab nobody trusts the second time they read it, and the two halves of one
    # design disagreeing on screen is how somebody ends up "fixing" the NTFS side.
    $grantees = @($Share.Group, "BUILTIN\Administrators")
    $readers = @()
    if (-not [string]::IsNullOrWhiteSpace($Share.ReadGroup)) { $readers = @($Share.ReadGroup) }
    if ($null -eq $existing) {
        $parameters = @{ Name = $smbName; Path = $Path; FullAccess = $grantees; Description = $Share.Description; ErrorAction = "Stop" }
        if ($readers.Count -gt 0) { $parameters["ReadAccess"] = $readers }
        foreach ($key in $scoped.Keys) { $parameters[$key] = $scoped[$key] }
        if ($ContinuouslyAvailable) { $parameters["ContinuouslyAvailable"] = $true }
        $null = New-SmbShare @parameters
        Write-Log "Share '$smbName' -> '$Path'$(if ($scoped.Count) { " (scope $ScopeName)" })" -Tag "Ok"
    }
    else {
        # Re-assert the grants; a grant that is already present is a no-op.
        foreach ($grantee in $grantees) {
            $null = Grant-SmbShareAccess -Name $smbName @scoped -AccountName $grantee -AccessRight Full -Force -ErrorAction Stop
        }
        # Revoked first, then granted at Read: Grant-SmbShareAccess adds a second ACE
        # rather than replacing the one that is there, and a group that was Full on an
        # earlier run would keep it. The revoke of a name that is not on the share is a
        # no-op, which is why it is safe to do unconditionally.
        foreach ($reader in $readers) {
            $null = Revoke-SmbShareAccess -Name $smbName @scoped -AccountName $reader -Force -ErrorAction SilentlyContinue
            $null = Grant-SmbShareAccess -Name $smbName @scoped -AccountName $reader -AccessRight Read -Force -ErrorAction Stop
        }
        # By SID, never by the name: "Everyone" is Jeder on a German server, the revoke
        # would match nothing, and SilentlyContinue would swallow it - leaving the
        # default grant on the share with nothing in the log to say so. That is the
        # worst shape a localisation bug can take, because the whole point of this line
        # is taking that grant away.
        $everyone = Get-StudioEveryoneName
        if ([string]::IsNullOrWhiteSpace($everyone)) {
            Write-Log "Everyone did not resolve - its grant on '$smbName' was NOT removed" -Tag "Error"
        }
        else {
            $null = Revoke-SmbShareAccess -Name $smbName @scoped -AccountName $everyone -Force -ErrorAction SilentlyContinue
        }
    }

    $enumeration = "Unrestricted"
    if ($AccessBasedEnumeration) { $enumeration = "AccessBased" }
    $null = Set-SmbShare -Name $smbName @scoped -FolderEnumerationMode $enumeration -Description $Share.Description -Force -ErrorAction Stop

    # One line per share rather than one per setting. Three settings that are each a
    # sentence read as three events; together they are what the share IS.
    $facts = @("enumeration $enumeration")

    # Re-asserted on every run rather than set at creation, for the same reason the
    # caching mode below is: the share may predate this design, and a clustered share
    # that is not continuously available fails over by dropping every handle - which is
    # invisible until the day somebody drains a node.
    if (-not [string]::IsNullOrWhiteSpace($ScopeName)) {
        try {
            $null = Set-SmbShare -Name $smbName @scoped -ContinuouslyAvailable $ContinuouslyAvailable -Force -ErrorAction Stop
            if ($ContinuouslyAvailable) { $facts += "CA on" }
            else {
                $facts += "CA OFF"
                Write-Log "Share '$smbName' is not continuously available - handles break when the role moves" -Tag "Warn"
            }
        }
        catch {
            Write-Log "CA not set on '$smbName': $($_.Exception.Message)" -Tag "Warn"
        }
    }

    # Offline files, on a share holding profile containers. Windows gives a new share
    # 'Manual' caching, so a client can be told to take an offline copy of a VHDX the
    # same client has mounted - which is one of the two classic ways a container is
    # corrupted. Set on every run rather than at creation: the share may predate this
    # design, and the setting is what protects the data rather than the share object.
    if ($Share.AccessModel -eq "fslogixContainer") {
        try {
            $null = Set-SmbShare -Name $smbName @scoped -CachingMode "None" -Force -ErrorAction Stop
            $facts += "caching off"
        }
        catch {
            # Not fatal: the share is published and the ACL is right. Say what is left.
            Write-Log "Offline files still on for '$smbName': $($_.Exception.Message)" -Tag "Warn"
            Write-Log "    Set-SmbShare -Name '$smbName' -CachingMode None -Force" -Tag "Warn"
        }
    }

    Write-Log ("Share '{0}': {1}" -f $smbName, ($facts -join ", ")) -Tag "Info"
    return $true
}

# ---------------------------[ Shadow copies ]---------------------------
# Shadow copies are previous versions, not a backup: they live on the same volume
# they protect. The defaults follow the Explorer UI's own schedule (07:00 and
# 12:00 on weekdays was the classic; here daily at the configured times) and cap
# the diff area, because unbounded shadow storage eats the data volume from the
# inside. vssadmin has no idempotent 'add': add is tried first and resize covers
# the already-configured case.
# The volume as VSS names it: \\?\Volume{GUID}\. Everything below keys off this -
# the storage association, the task name the Shadow Copies tab looks for, and the
# snapshot filter.
function Get-FsVolumeId {
    param([Parameter(Mandatory)][string]$Drive)

    try {
        $volume = Get-CimInstance -ClassName "Win32_Volume" -Filter ("DriveLetter='{0}'" -f $Drive.TrimEnd("\")) -ErrorAction Stop
        if ($null -ne $volume) { return [string]$volume.DeviceID }
    }
    catch {
        Write-Log "No volume id for ${Drive}: $($_.Exception.Message)" -Tag "Error"
    }
    return ""
}

# Shadow copies are previous versions, not a backup: they live on the same volume
# they protect. vssadmin has no idempotent 'add': add is tried first and resize
# covers the already-configured case.
#
# The schedule deliberately copies what the Shadow Copies tab's Enable button
# creates, down to the task name: ShadowCopyVolume{GUID} in the task root, running
# vssadmin Create Shadow /AutoRetry=15. That name is the only thing the tab reads -
# a task called anything else leaves it saying "Disabled" with the storage
# association sitting right under it, which reads as the run not having worked.
# It also takes the first snapshot itself, the way Enable does, so Previous
# Versions answers from now rather than from tonight.
function Set-FsShadowCopy {
    param(
        [Parameter(Mandatory)][string]$Drive,
        [Parameter(Mandatory)][object]$ShadowCopies
    )

    $maxPercent = [int](Get-ConfigValue -InputObject $ShadowCopies -Name "maxSizePercent" -Default 10)
    if ($maxPercent -lt 1) { $maxPercent = 1 }
    $volume = $Drive.TrimEnd("\")

    $sizeArgument = "/maxsize={0}%" -f $maxPercent
    $addOutput = & vssadmin.exe Add ShadowStorage /For=$volume /On=$volume $sizeArgument 2>&1
    if ($LASTEXITCODE -ne 0) {
        $resizeOutput = & vssadmin.exe Resize ShadowStorage /For=$volume /On=$volume $sizeArgument 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Shadow storage ${volume} failed: $(@($resizeOutput) -join ' ')" -Tag "Error"
            return $false
        }
        Write-Log "Shadow storage ${volume}: $maxPercent% (resized)" -Tag "Info"
    }
    else {
        Write-Log "Shadow storage ${volume}: $maxPercent%" -Tag "Ok"
    }
    if ($null -eq $addOutput) { Write-Log "vssadmin returned nothing for $volume" -Tag "Debug" }

    $volumeId = Get-FsVolumeId -Drive $volume
    if ([string]::IsNullOrWhiteSpace($volumeId)) {
        Write-Log "No volume id - shadow copy task not built" -Tag "Error"
        return $false
    }

    $times = @(Get-ConfigArray -InputObject $ShadowCopies -Name "schedule" |
        ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($times.Count -eq 0) { $times = @("07:00", "12:00") }

    if (-not (Get-Command -Name "Register-ScheduledTask" -ErrorAction SilentlyContinue)) {
        Write-Log "ScheduledTasks module unavailable - no snapshot schedule" -Tag "Error"
        return $false
    }

    try {
        # ShadowCopyVolume{GUID} - DeviceID is \\?\Volume{GUID}\, the braces travel.
        $guidPart = $volumeId -replace ".*(\{[0-9a-fA-F-]+\}).*", '$1'
        $taskName = "ShadowCopyVolume" + $guidPart

        $triggers = @()
        foreach ($time in $times) {
            $triggers += New-ScheduledTaskTrigger -Daily -At ([datetime]::Parse($time))
        }
        # The console's own command line, verbatim - /AutoRetry waits out a busy VSS
        # writer instead of skipping that day's snapshot.
        $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\system32\vssadmin.exe" `
            -Argument ("Create Shadow /AutoRetry=15 /For={0}" -f $volumeId)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

        $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
        }
        $null = Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $triggers `
            -Principal $principal -Settings $settings `
            -Description "Windows Server Role Studio - takes the shadow copies previous versions are served from" -ErrorAction Stop
        Write-Log "Task '$taskName': daily $($times -join ', ') as SYSTEM" -Tag "Ok"
    }
    catch {
        Write-Log "Shadow copy task not registered: $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    Remove-FsLegacyShadowCopyTask

    # The first snapshot, the way the console's Enable button takes one - without it
    # Previous Versions stays empty until the first trigger fires, hours away.
    try {
        $snapshots = @(Get-CimInstance -ClassName "Win32_ShadowCopy" -ErrorAction Stop |
            Where-Object { $_.VolumeName -eq $volumeId })
        if ($snapshots.Count -eq 0) {
            Write-Log "First snapshot of $volume" -Tag "Run"
            $reply = Invoke-CimMethod -ClassName "Win32_ShadowCopy" -MethodName "Create" `
                -Arguments @{ Volume = ($volume + "\"); Context = "ClientAccessible" } -ErrorAction Stop
            if ($null -ne $reply -and [int]$reply.ReturnValue -eq 0) {
                Write-Log "First snapshot taken - Previous Versions answers now" -Tag "Ok"
            }
            else {
                Write-Log "First snapshot returned $($reply.ReturnValue) - schedule will retry" -Tag "Warn"
            }
        }
        else {
            Write-Log "$volume already has $($snapshots.Count) snapshot(s)" -Tag "Debug"
        }
    }
    catch {
        Write-Log "First snapshot failed: $($_.Exception.Message) - schedule will retry" -Tag "Warn"
    }
    return $true
}

function Remove-FsLegacyShadowCopyTask {
    if (-not (Get-Command -Name "Unregister-ScheduledTask" -ErrorAction SilentlyContinue)) { return }
    $existing = Get-ScheduledTask -TaskName $script:fsLegacyShadowCopyTaskName -ErrorAction SilentlyContinue
    if ($null -eq $existing) { return }
    try {
        Unregister-ScheduledTask -TaskName $script:fsLegacyShadowCopyTaskName -Confirm:$false -ErrorAction Stop
        Write-Log "Removed legacy task '$($script:fsLegacyShadowCopyTaskName)'" -Tag "Info"
    }
    catch {
        Write-Log "Legacy task not removed: $($_.Exception.Message)" -Tag "Debug"
    }
}

function Remove-FsShadowCopyTask {
    param([string]$Drive = "")

    if (-not (Get-Command -Name "Unregister-ScheduledTask" -ErrorAction SilentlyContinue)) { return }
    Remove-FsLegacyShadowCopyTask
    if ([string]::IsNullOrWhiteSpace($Drive)) { return }
    $volumeId = Get-FsVolumeId -Drive $Drive
    if ([string]::IsNullOrWhiteSpace($volumeId)) { return }
    $guidPart = $volumeId -replace ".*(\{[0-9a-fA-F-]+\}).*", '$1'
    $taskName = "ShadowCopyVolume" + $guidPart
    $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($null -eq $existing) { return }
    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
        Write-Log "Removed task '$taskName' - shadow copies off" -Tag "Info"
    }
    catch {
        Write-Log "Task '$taskName' not removed: $($_.Exception.Message)" -Tag "Debug"
    }
}

# Shadow copies are a per-VOLUME switch, so two volumes get two answers rather than one
# applied twice - and the answer for a profile volume is no.
#
# A snapshot of a container that is open is a crash-consistent image of a mounted file
# system. Nobody can restore a file out of it from the Previous Versions tab, which is
# what shadow copies are for, and the diff area it fills is the same diff area the
# document share's useful snapshots live in when the two share a volume. `enabled`
# therefore means the data volume; `includeProfileVolume` is the separate, off-by-default
# decision to snapshot containers anyway, for somebody who has a reason.
function Set-FsShadowCopyPerRoot {
    param(
        [Parameter(Mandatory)][object]$FileServer,
        [Parameter(Mandatory)][object[]]$Roots
    )

    $shadowCopies = Get-ConfigValue -InputObject $FileServer -Name "shadowCopies"
    $enabled = [bool](Get-ConfigValue -InputObject $shadowCopies -Name "enabled" -Default $false)
    $includeProfiles = [bool](Get-ConfigValue -InputObject $shadowCopies -Name "includeProfileVolume" -Default $false)

    $ok = $true
    foreach ($root in $Roots) {
        $wanted = $enabled
        if ($root.Key -eq "profile" -and -not $includeProfiles) { $wanted = $false }

        if ($wanted) {
            if (-not (Set-FsShadowCopy -Drive $root.Drive -ShadowCopies $shadowCopies)) { $ok = $false }
            continue
        }

        Remove-FsShadowCopyTask -Drive $root.Drive
        if ($enabled -and $root.Key -eq "profile") {
            Write-Log "$($root.Drive) holds profile containers, so it gets no shadow copies" -Tag "Info"
            Write-Log "    A snapshot of a mounted container restores nothing from Previous Versions and fills the diff area" -Tag "Info"
            Write-Log "    shadowCopies.includeProfileVolume turns them on here anyway" -Tag "Info"
        }
    }
    return $ok
}

# ---------------------------[ Antivirus exclusions ]---------------------------
# Scanning a mounted profile container is one of the two classic ways one gets corrupted,
# and the exclusions are needed at BOTH ends - on this file server, where the VHDX live,
# and on every session host, where they are attached. This run sets the half it is
# standing on and prints the other, which is the same boundary the role already draws
# around VHDLocations: a value that belongs to every session host is one policy, not a
# registry write this server makes on their behalf.
#
# Path patterns rather than -ExclusionExtension, deliberately. An extension exclusion is
# global: excluding .vhdx on a file server that also happens to hold a Hyper-V volume
# would switch scanning off for those too. The patterns below reach exactly the container
# tree of exactly the shares this design publishes.
#
# Microsoft's own list is the source of the file names - the container, its lock file and
# the two metadata files.
$script:fsContainerPattern = @("*.VHD", "*.VHDX", "*.VHDX.lock", "*.meta", "*.metadata")

function Get-FsDefenderExclusionPath {
    param([Parameter(Mandatory)][string]$SharePath)

    $root = ([string]$SharePath).TrimEnd("\")
    $paths = @()
    foreach ($pattern in $script:fsContainerPattern) {
        # <share>\<per-user folder>\<file>. FSLogix creates one folder per user under the
        # share, so the wildcard in the middle is the user folder rather than a guess.
        $paths += ("{0}\*\{1}" -f $root, $pattern)
    }
    return ,$paths
}

function Set-FsDefenderExclusion {
    param([Parameter(Mandatory)][string[]]$Path)

    if ($Path.Count -eq 0) { return $true }
    if (-not (Get-Command -Name "Add-MpPreference" -ErrorAction SilentlyContinue)) {
        Write-Log "Defender cmdlets unavailable - no exclusions added, add them in whatever antivirus this server runs" -Tag "Info"
        return $true
    }

    $existing = @()
    try { $existing = @((Get-MpPreference -ErrorAction Stop).ExclusionPath) }
    catch { $existing = @() }

    $added = @()
    foreach ($item in $Path) {
        if ($existing -contains $item) {
            Write-Log "'$item' is already excluded" -Tag "Debug"
            continue
        }
        try {
            Add-MpPreference -ExclusionPath $item -ErrorAction Stop
            $added += $item
        }
        catch {
            # Never a failure of the role. An exclusion that did not land is a performance
            # and corruption risk worth shouting about, and not a reason to leave a share
            # unpublished.
            Write-Log "Defender exclusion for '$item' not added: $($_.Exception.Message)" -Tag "Warn"
        }
    }
    if ($added.Count -gt 0) {
        Write-Log ("Defender exclusions on this server: {0}" -f ($added -join ", ")) -Tag "Ok"
    }
    return $true
}

# ---------------------------[ DFS namespaces ]---------------------------
# Domain-based namespaces are Windows Server 2008 mode - the only domain mode worth
# creating since 2008; standalone puts this server's own name in the path. Either
# way the namespace root is its own small share under C:\DFSRoots, never one of the
# data shares: a root's ACL decides who *sees the namespace*, the folder targets
# keep deciding who reads the data. Which shares appear - and as what - is the
# namespace's list, not the share's.
function Set-FsDfsNamespace {
    param(
        [Parameter(Mandatory)][object]$Namespace,
        [Parameter(Mandatory)][object[]]$Shares,
        # Who holds the DATA, which is not always who holds the namespace. On a single
        # host they are the same machine and this stays empty. In guest cluster mode the
        # root target is this NODE (a domain-based namespace cannot be a cluster
        # resource, so each node hosts its own root out of its own C:\DFSRoots) while
        # every folder target is the CLUSTERED file server - the half that fails over.
        # Two different names in one namespace, and that difference is the design.
        [string]$ShareHostFqdn = ""
    )

    # Read once: it decides the root's own setting and whether each folder below it
    # gets explicit view permissions, which is what makes the setting bite.
    $enumeration = [bool](Get-ConfigValue -InputObject $Namespace -Name "accessBasedEnumeration" -Default $true)

    $namespaceName = Get-ConfigText -InputObject $Namespace -Name "name"
    if ([string]::IsNullOrWhiteSpace($namespaceName)) {
        Write-Log "Namespace entry has no name - skipped" -Tag "Error"
        return $false
    }

    $namespaceType = Get-ConfigText -InputObject $Namespace -Name "type" -Default "domainV2"
    $domain = ([string]$env:USERDNSDOMAIN).ToLowerInvariant()
    if ($namespaceType -ne "standalone" -and [string]::IsNullOrWhiteSpace($domain)) {
        Write-Log "No DNS domain - namespace '$namespaceName' not built" -Tag "Error"
        return $false
    }
    $serverFqdn = $env:COMPUTERNAME.ToLowerInvariant()
    if (-not [string]::IsNullOrWhiteSpace($domain)) { $serverFqdn = "{0}.{1}" -f $serverFqdn, $domain }

    # The root share: a folder of its own, shared read-only for everyone who may
    # browse the namespace. The data never lives here.
    $rootFolder = Join-Path -Path ($env:SystemDrive + "\DFSRoots") -ChildPath $namespaceName
    if (-not (Test-Path -LiteralPath $rootFolder)) {
        $null = New-Item -ItemType Directory -Path $rootFolder -Force
        Write-Log "Created '$rootFolder'" -Tag "Debug"
    }
    if ($null -eq (Get-SmbShare -Name $namespaceName -ErrorAction SilentlyContinue)) {
        # Same rule as above. A DFS namespace root is shared read to everyone by design -
        # the referrals it hands out are not secrets and the targets have their own ACLs -
        # but the principal has to be resolved rather than spelled.
        $everyone = Get-StudioEveryoneName
        if ([string]::IsNullOrWhiteSpace($everyone)) {
            throw "The Everyone group could not be resolved on this machine, so the namespace share could not be created."
        }
        $null = New-SmbShare -Name $namespaceName -Path $rootFolder -ReadAccess $everyone -ErrorAction Stop
        Write-Log "Namespace root share '$namespaceName' -> '$rootFolder' (read: $everyone)" -Tag "Ok"
    }

    $namespaceHost = $domain
    $rootType = "DomainV2"
    if ($namespaceType -eq "standalone") { $namespaceHost = $serverFqdn; $rootType = "Standalone" }
    $namespacePath = "\\{0}\{1}" -f $namespaceHost, $namespaceName
    $rootTarget    = "\\{0}\{1}" -f $serverFqdn, $namespaceName

    # Unstated means "this machine serves its own shares", which is the single host.
    $shareHost = ([string]$ShareHostFqdn).Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($shareHost)) { $shareHost = $serverFqdn }

    $root = Get-DfsnRoot -Path $namespacePath -ErrorAction SilentlyContinue
    if ($null -eq $root) {
        $null = New-DfsnRoot -Path $namespacePath -TargetPath $rootTarget -Type $rootType -ErrorAction Stop
        Write-Log "Namespace $namespacePath created ($rootType), target $rootTarget" -Tag "Ok"
    }
    else {
        Write-Log "Namespace $namespacePath exists - settings re-applied" -Tag "Info"
    }

    # The wizard's page two, as parameters. ABE hides links the reader could not
    # open anyway; site costing hands out the nearest target first; in-site-only
    # and root scalability are the two nobody should turn on without knowing why.
    $rootSettings = @{
        Path                         = $namespacePath
        EnableAccessBasedEnumeration = $enumeration
        EnableSiteCosting            = [bool](Get-ConfigValue -InputObject $Namespace -Name "siteCosting" -Default $true)
        EnableInsiteReferrals        = [bool](Get-ConfigValue -InputObject $Namespace -Name "insiteReferrals" -Default $false)
        EnableRootScalability        = [bool](Get-ConfigValue -InputObject $Namespace -Name "rootScalability" -Default $false)
        TimeToLiveSec                = [int](Get-ConfigValue -InputObject $Namespace -Name "ttlSeconds" -Default 300)
        ErrorAction                  = "Stop"
    }
    $description = Get-ConfigText -InputObject $Namespace -Name "description"
    if (-not [string]::IsNullOrWhiteSpace($description)) { $rootSettings["Description"] = $description }
    $null = Set-DfsnRoot @rootSettings

    $allLinked = $true
    foreach ($link in @(Get-ConfigArray -InputObject $Namespace -Name "links")) {
        $shareName  = Get-ConfigText -InputObject $link -Name "share"
        $folderName = Get-ConfigText -InputObject $link -Name "folder" -Default $shareName
        if ([string]::IsNullOrWhiteSpace($shareName)) { continue }

        $share = $null
        foreach ($candidate in $Shares) {
            if ($candidate.Name -eq $shareName) { $share = $candidate }
        }
        if ($null -eq $share) {
            Write-Log "Namespace '$namespaceName' publishes '$shareName', which this design does not share" -Tag "Error"
            $allLinked = $false
            continue
        }

        $linkPath   = "{0}\{1}" -f $namespacePath, $folderName
        $linkTarget = "\\{0}\{1}" -f $shareHost, (Get-FsSmbName -Share $share)

        # Create-or-extend, then fall through: the view grant below has to run for a
        # folder this pass just created as much as for one it found - the created
        # branch used to end in `continue`, which skipped the grant on exactly the
        # first run, so every fresh namespace folder stayed on inherited permissions
        # and ABE hid nothing. Only a folder that could not be created is skipped.
        $folder = Get-DfsnFolder -Path $linkPath -ErrorAction SilentlyContinue
        if ($null -eq $folder) {
            try {
                $null = New-DfsnFolder -Path $linkPath -TargetPath $linkTarget -ErrorAction Stop
                Write-Log "Namespace folder '$linkPath' -> '$linkTarget'" -Tag "Ok"
            }
            catch {
                Write-Log "Could not create '$linkPath': $($_.Exception.Message)" -Tag "Error"
                $allLinked = $false
                continue
            }
        }
        else {
            $targets = @(Get-DfsnFolderTarget -Path $linkPath -ErrorAction SilentlyContinue)
            $present = $false
            foreach ($target in $targets) {
                if ([string]$target.TargetPath -eq $linkTarget) { $present = $true }
            }
            if (-not $present) {
                try {
                    $null = New-DfsnFolderTarget -Path $linkPath -TargetPath $linkTarget -ErrorAction Stop
                    Write-Log "Added target '$linkTarget' to '$linkPath'" -Tag "Ok"
                }
                catch {
                    Write-Log "Could not add the target to '$linkPath': $($_.Exception.Message)" -Tag "Error"
                    $allLinked = $false
                }
            }
            else {
                Write-Log "Namespace folder '$linkPath' already targets this share" -Tag "Debug"
            }
        }

        # Access-based enumeration on a namespace only hides what the *folder's* own
        # view permissions hide. Left inherited - the default - the namespace server's
        # file system decides, which grants every domain user the right to see every
        # folder, so ABE is on and hides nothing. Granting anybody explicitly is what
        # the console's "Set explicit view permissions on the DFS folder" does, and it
        # is the switch that makes the setting mean something.
        if ($enumeration) {
            if (-not (Grant-FsDfsFolderView -Path $linkPath -GroupName $share.Group -ReadGroupName $share.ReadGroup)) { $allLinked = $false }
        }
    }
    return $allLinked
}

# Grant-DfsnAccess is what flips a folder from inherited to explicit: the first grant
# switches the mode, so the two accounts are the whole ACL afterwards. Local
# Administrators keeps the folder visible to whoever manages it - without it an
# administrator outside the share group stops seeing the link at all.
function Grant-FsDfsFolderView {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$GroupName,
        # The read-only tier sees the link for the same reason the read/write one does:
        # this is a *view* permission on a namespace folder, not access to what is behind
        # it. Leaving it out would hide the folder from exactly the people the share was
        # designed to be readable by.
        [string]$ReadGroupName = ""
    )

    $netbios = [string]$env:USERDOMAIN
    $accounts = @("BUILTIN\Administrators")
    foreach ($name in @($GroupName, $ReadGroupName)) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        if ($name.Contains("\")) { $accounts += $name }
        elseif (-not [string]::IsNullOrWhiteSpace($netbios)) { $accounts += ("{0}\{1}" -f $netbios, $name) }
        else { $accounts += $name }
    }

    $granted = $true
    foreach ($account in $accounts) {
        try {
            $null = Grant-DfsnAccess -Path $Path -AccountName $account -ErrorAction Stop
            Write-Log "'$Path' view permission granted to '$account'" -Tag "Debug"
        }
        catch {
            Write-Log "Could not grant '$account' view on '$Path': $($_.Exception.Message)" -Tag "Error"
            $granted = $false
        }
    }
    if ($granted) {
        $named = @($GroupName, $ReadGroupName) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        Write-Log "$Path view: Administrators + '$($named -join "', '")' only" -Tag "Ok"
    }
    return $granted
}

# ---------------------------[ Drive map GPOs ]---------------------------
# One user GPO per mapped share, written on the domain controller run. Drive maps
# are Group Policy *preferences* - there is no cmdlet family for them, the console
# writes Drives.xml into SYSVOL and registers the Drive Maps client-side extension
# on the GPO, so that is exactly what this does. Two entries per GPO, the pair the
# console screenshots show: an Update targeted at the share group (reconnect,
# label, fixed letter), and a Delete for the same letter targeted at NOT being in
# the group - losing the membership unmounts the drive at the next refresh instead
# of leaving a dead letter behind. Computer settings are disabled: there is nothing
# computer-side in these. Created unlinked, same reasoning as the AD CS policy
# objects - where a policy belongs is an OU-layout decision this design does not
# describe.
$script:fsDriveMapGpoPrefix = "U - USR - Network Drive"
# The Drive Maps preference CSE pair: {2EA1A81B...} is the CSE that processes
# Drives.xml, {5794DAFD...} the editor tool id. Without this attribute the client
# never reads the file and the GPO looks empty in gpresult.
$script:fsDriveMapExtension = "[{00000000-0000-0000-0000-000000000000}{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}][{5794DAFD-BE60-433f-88A2-1A31939AC01F}{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}]"

# The path a mapped drive points at: the DFS path when the share is published in
# an enabled namespace, the file server UNC otherwise. Empty means neither is
# derivable - no DFS link and no computerName in the design.
function Get-FsDriveMapPath {
    param(
        [Parameter(Mandatory)][object]$FileServer,
        [Parameter(Mandatory)][object]$Share
    )

    $dfs = Get-ConfigValue -InputObject $FileServer -Name "dfs"
    if ([bool](Get-ConfigValue -InputObject $dfs -Name "enabled" -Default $false)) {
        $domain = ([string]$env:USERDNSDOMAIN).ToLowerInvariant()
        foreach ($namespace in @(Get-ConfigArray -InputObject $dfs -Name "namespaces")) {
            $nsName = Get-ConfigText -InputObject $namespace -Name "name"
            if ([string]::IsNullOrWhiteSpace($nsName)) { continue }
            foreach ($link in @(Get-ConfigArray -InputObject $namespace -Name "links")) {
                if ((Get-ConfigText -InputObject $link -Name "share") -ne $Share.Name) { continue }
                $folder = Get-ConfigText -InputObject $link -Name "folder" -Default $Share.Name
                return "\\{0}\{1}\{2}" -f $domain, $nsName, $folder
            }
        }
    }

    $root = Get-ConfigValue -InputObject $FileServer -Name "root"
    $computerName = Resolve-StudioServerFqdn -Name (Get-ConfigText -InputObject $root -Name "computerName") -Label "file server"
    if ([string]::IsNullOrWhiteSpace($computerName)) { return "" }
    return "\\{0}\{1}" -f $computerName, (Get-FsSmbName -Share $Share)
}

# The item-level targeting is one FilterGroup per group, and the two entries read the
# pair in opposite directions. The Update entry is an OR - in the read/write group OR in
# the read-only one, because both need the letter and what they may do once it is open is
# the folder's decision rather than the drive's. The Delete entry is an AND of two NOTs -
# in neither - so losing one membership while holding the other leaves the drive alone,
# and losing both unmounts it. A single-group design writes exactly one FilterGroup per
# entry, which is byte-for-byte what this wrote before the second tier existed.
function New-FsDriveMapXml {
    param(
        [Parameter(Mandatory)][string]$Letter,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$GroupName,
        [Parameter(Mandatory)][string]$GroupSid,
        [string]$ReadGroupName = "",
        [string]$ReadGroupSid = ""
    )

    $stamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $updateUid = Get-StudioStableGuid -Seed ("update-" + $Letter + "-" + $Path)
    $deleteUid = Get-StudioStableGuid -Seed ("delete-" + $Letter + "-" + $Path)
    $escapedPath  = [System.Security.SecurityElement]::Escape($Path)
    $escapedLabel = [System.Security.SecurityElement]::Escape($Label)

    $targets = @([pscustomobject]@{ Name = $GroupName; Sid = $GroupSid })
    if ((-not [string]::IsNullOrWhiteSpace($ReadGroupName)) -and (-not [string]::IsNullOrWhiteSpace($ReadGroupSid))) {
        $targets += [pscustomobject]@{ Name = $ReadGroupName; Sid = $ReadGroupSid }
    }

    # The first item's operator is ignored by the client - there is nothing to its left -
    # so the console writes AND there whatever the rest are, and so does this.
    $filterLine = {
        param($target, $operator, $negate)
        '      <FilterGroup bool="' + $operator + '" not="' + $negate + '" name="' +
            [System.Security.SecurityElement]::Escape($target.Name) + '" sid="' + $target.Sid +
            '" userContext="1" primaryGroup="0" localGroup="0"/>'
    }
    $updateFilters = @()
    $deleteFilters = @()
    for ($index = 0; $index -lt $targets.Count; $index++) {
        $updateFilters += (& $filterLine $targets[$index] $(if ($index -eq 0) { "AND" } else { "OR" }) "0")
        $deleteFilters += (& $filterLine $targets[$index] "AND" "1")
    }

    return @(
        '<?xml version="1.0" encoding="utf-8"?>',
        '<Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}">',
        ('  <Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="' + $Letter + ':" status="' + $Letter + ':" image="2" changed="' + $stamp + '" uid="' + $updateUid + '" bypassErrors="1">'),
        ('    <Properties action="U" thisDrive="NOCHANGE" allDrives="NOCHANGE" userName="" path="' + $escapedPath + '" label="' + $escapedLabel + '" persistent="1" useLetter="1" letter="' + $Letter + '"/>'),
        '    <Filters>'
    ) + $updateFilters + @(
        '    </Filters>',
        '  </Drive>',
        ('  <Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="' + $Letter + ':" status="' + $Letter + ':" image="3" changed="' + $stamp + '" uid="' + $deleteUid + '" bypassErrors="1">'),
        ('    <Properties action="D" thisDrive="NOCHANGE" allDrives="NOCHANGE" userName="" path="" label="" persistent="0" useLetter="1" letter="' + $Letter + '"/>'),
        '    <Filters>'
    ) + $deleteFilters + @(
        '    </Filters>',
        '  </Drive>',
        '</Drives>'
    ) -join "`r`n"
}

function Sync-FsDriveMapGpo {
    param([Parameter(Mandatory)][object]$FileServer)

    $mapped = @()
    foreach ($share in (Get-FsShare -FileServer $FileServer)) {
        $entryValue = $null
        foreach ($raw in @(Get-ConfigArray -InputObject $FileServer -Name "shares")) {
            if ((Get-ConfigText -InputObject $raw -Name "name") -eq $share.Name) { $entryValue = $raw }
        }
        $letter = (Get-ConfigText -InputObject $entryValue -Name "driveLetter").ToUpperInvariant()
        if ([string]::IsNullOrWhiteSpace($letter)) { continue }
        # A profile container share is mounted by the FSLogix client at sign-in and is
        # never browsed, so a letter on one is a mistake somewhere upstream - the studio
        # does not even offer the control. Skipped rather than mapped: a drive into the
        # container root invites somebody to open a folder that is being written to.
        if ($share.AccessModel -eq "fslogixContainer") {
            Write-Log "'$($share.Name)' is a profile share with a drive letter - no drive map written" -Tag "Warn"
            continue
        }
        $label = Get-ConfigText -InputObject $entryValue -Name "driveLabel" -Default $share.Name
        $mapped += [pscustomobject]@{ Share = $share; Letter = $letter; Label = $label }
    }
    if ($mapped.Count -eq 0) { return $true }

    if (-not (Get-Command -Name "New-GPO" -ErrorAction SilentlyContinue)) {
        Write-Log "GroupPolicy module unavailable - no drive map GPOs" -Tag "Error"
        Write-Log "    Install-WindowsFeature -Name GPMC" -Tag "Error"
        return $false
    }

    $netbios = [string]$env:USERDOMAIN
    $allCreated = $true

    # One list for every drive-map object this design writes, rather than one per share.
    # These are user policies whose entries already filter on the share's group, so which
    # drive a person gets is decided by membership, not by where the object is linked -
    # the link only decides who *processes* it, and that is the same answer for all of
    # them: wherever the users are. A per-share list would be N copies of one value.
    $groupPolicy = Get-ConfigValue -InputObject $FileServer -Name "groupPolicy"
    $linkTo = @(Get-StudioGpoLinkTarget -InputObject $groupPolicy -Name "linkTo")

    foreach ($map in $mapped) {
        # Named for the drive as people see it, not for the folder behind it: the label
        # is what Explorer shows, so 'U - USR - Network Drive - P - Public' and the P:
        # somebody is asking about are the same word. Get-ConfigText treats a blank
        # label as missing, so an unlabelled drive falls back to the share name.
        $gpoName = "{0} - {1} - {2}" -f $script:fsDriveMapGpoPrefix, $map.Letter, $map.Label
        $path = Get-FsDriveMapPath -FileServer $FileServer -Share $map.Share
        if ([string]::IsNullOrWhiteSpace($path)) {
            Write-Log "'$gpoName' has no path - publish the share in DFS or set fileServer.root.computerName" -Tag "Error"
            $allCreated = $false
            continue
        }

        $groupSid = Get-StudioGroupSid -Name $map.Share.Group
        if ([string]::IsNullOrWhiteSpace($groupSid)) {
            Write-Log "'$gpoName' targets missing group '$($map.Share.Group)' - see the group sync above" -Tag "Error"
            $allCreated = $false
            continue
        }

        # The read-only tier is targeted beside it. A named group whose SID cannot be
        # read stops the object rather than writing half of it: a Drives.xml carrying one
        # filter is a policy that mounts the drive for the writers and silently for
        # nobody else, which is the same file a single-group design writes and therefore
        # gives a reader nothing to notice.
        $readGroupSid = ""
        if (-not [string]::IsNullOrWhiteSpace($map.Share.ReadGroup)) {
            $readGroupSid = Get-StudioGroupSid -Name $map.Share.ReadGroup
            if ([string]::IsNullOrWhiteSpace($readGroupSid)) {
                Write-Log "'$gpoName' targets missing read-only group '$($map.Share.ReadGroup)' - see the group sync above" -Tag "Error"
                $allCreated = $false
                continue
            }
        }

        try {
            $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if ($null -eq $gpo) {
                $gpo = New-GPO -Name $gpoName -ErrorAction Stop
                Write-Log "Created '$gpoName'" -Tag "Ok"
            }
            else {
                Write-Log "GPO '$gpoName' exists - entries re-applied" -Tag "Info"
            }
            # User preferences only; the computer half stays off so nothing ever
            # processes an empty side.
            if ($gpo.GpoStatus -ne "ComputerSettingsDisabled") { $gpo.GpoStatus = "ComputerSettingsDisabled" }

            $policyFolder = Set-StudioGpoUserExtension -Gpo $gpo -Extension $script:fsDriveMapExtension
            $readGroupName = ""
            if (-not [string]::IsNullOrWhiteSpace($readGroupSid)) {
                $readGroupName = "{0}\{1}" -f $netbios, $map.Share.ReadGroup
            }
            $xml = New-FsDriveMapXml -Letter $map.Letter -Path $path -Label $map.Label `
                -GroupName ("{0}\{1}" -f $netbios, $map.Share.Group) -GroupSid $groupSid `
                -ReadGroupName $readGroupName -ReadGroupSid $readGroupSid
            Write-StudioGpoPreferenceFile -PolicyFolder $policyFolder -Folder "Drives" -FileName "Drives.xml" -Content $xml
            $targetText = "'$($map.Share.Group)'"
            if (-not [string]::IsNullOrWhiteSpace($readGroupSid)) { $targetText += " or '$($map.Share.ReadGroup)'" }
            Write-Log "'$gpoName': $($map.Letter): -> $path (update in $targetText, delete outside)" -Tag "Ok"

            if (-not (Set-StudioGpoLink -Name $gpoName -TargetDn $linkTo `
                        -UnlinkedNote "link it to the users' OU when ready")) {
                $allCreated = $false
            }
        }
        catch {
            Write-Log "GPO '$gpoName' failed: $($_.Exception.Message)" -Tag "Error"
            $allCreated = $false
        }
    }
    return $allCreated
}

# The DFSN module ships with the FS-DFS-Namespace role service and works on Server
# Core, where the DFS Management console cannot be installed at all. Loaded on demand
# so a design without DFS never pays for it.
function Import-FsDfsModule {
    if (Get-Command -Name "New-DfsnRoot" -ErrorAction SilentlyContinue) { return $true }
    try {
        Import-Module -Name "DFSN" -ErrorAction Stop
        return $true
    }
    catch {
        Write-Log "DFSN cmdlets unavailable: $($_.Exception.Message)" -Tag "Error"
        Write-Log "    Install-WindowsFeature -Name FS-DFS-Namespace" -Tag "Error"
        return $false
    }
}

# ---------------------------[ Prerequisites ]---------------------------
function Test-FsPrerequisite {
    param([object]$Config)

    $fileServer = Get-ConfigValue -InputObject $Config -Name "fileServer"
    if ($null -eq $fileServer) {
        Write-Log "config.json has no fileServer section" -Tag "Error"
        return $false
    }

    # A domain controller runs the directory half only - groups and members. No
    # file server feature, drive or share belongs on it, so none is checked.
    if (Test-StudioDomainController) {
        Write-Log "Domain controller - share groups and members only" -Tag "Info"
        return $true
    }

    # The mode router, and one of exactly four places the two builds meet. Everything
    # below this line is the single host and is untouched by the cluster mode.
    if (Test-FsClusterMode -FileServer $fileServer) {
        return (Test-FsClusterPrerequisite -FileServer $fileServer -Cluster (Get-FsClusterSection -FileServer $fileServer))
    }

    $passed = $true

    # The registry entry's Feature is empty for the same reason AD CS's is: this
    # role runs on two kinds of machine and only one of them is a file server.
    try {
        $feature = Get-WindowsFeature -Name "FS-FileServer" -ErrorAction Stop
        if (($null -eq $feature) -or (-not $feature.Installed)) {
            Write-Log "FS-FileServer is not installed" -Tag "Error"
            Write-Log "    Install-WindowsFeature -Name FS-FileServer" -Tag "Error"
            $passed = $false
        }
    }
    catch {
        Write-Log "FS-FileServer not queryable: $($_.Exception.Message)" -Tag "Error"
        $passed = $false
    }

    # A missing drive letter is the NORMAL starting state of a fresh file server, and
    # this check used to refuse it - asserting the postcondition of the very step it
    # gates. `prepareVolumes` is on by default and `Confirm-FsVolumeSet` is what claims
    # an uninitialised disk, partitions it and formats it to the design's spec; a server
    # whose data disks are still raw has no D: yet BY DEFINITION, and the run's whole
    # job is to make one. Refusing there meant the one case the volume builder exists
    # for could never reach it.
    #
    # So the question is not "does the drive exist" but "will it, by the time the shares
    # are written". Three answers:
    #
    #   drive is there                  nothing to check
    #   missing, preparation ON         needs an uninitialised disk to build from - and
    #                                   that IS a prerequisite, because no amount of
    #                                   configuring conjures a disk
    #   missing, preparation OFF        nothing will create it, so it is a hard refusal
    #                                   exactly as before
    #
    # Both roots are asked, not just the first: the profile volume is a second drive
    # letter and it was never checked at all.
    $prepareVolumes = [bool](Get-ConfigValue -InputObject $fileServer -Name "prepareVolumes" -Default $true)
    $missingRoots = @()
    foreach ($rootDefinition in (Get-FsRootDefinition -FileServer $fileServer)) {
        $rootDrive = ([string]$rootDefinition.Drive).TrimEnd("\")
        if (Test-Path -LiteralPath ($rootDrive + "\")) { continue }
        if (-not $prepareVolumes) {
            Write-Log "Drive '$rootDrive' does not exist and volume preparation is off - nothing will create it" -Tag "Error"
            Write-Log "    Present the disk and format it, or switch fileServer.prepareVolumes on" -Tag "Error"
            $passed = $false
            continue
        }
        $missingRoots += $rootDefinition
    }
    if ($missingRoots.Count -gt 0) {
        $claimable = @(Get-FsClaimableDisk)
        $missingList = ($missingRoots | ForEach-Object { $_.Drive }) -join ", "
        if ($claimable.Count -lt $missingRoots.Count) {
            Write-Log ("{0} does not exist yet and only {1} uninitialised disk(s) are visible" -f $missingList, $claimable.Count) -Tag "Error"
            Write-Log "    One disk per volume. Present the missing disk - it needs no partition table, the run claims it whole" -Tag "Error"
            $passed = $false
        }
        else {
            Write-Log ("{0} does not exist yet and will be built from {1} uninitialised disk(s) during the run" -f $missingList, $claimable.Count) -Tag "Info"
        }
    }

    # The share groups are a prerequisite here, the same rule as the Remote Desktop
    # access groups: created on the domain controller run (or by hand), never by
    # the file server. DomainLocal in the printed line because that is what this run
    # creates on a domain controller, and the two have to agree - a group made by hand
    # from a line that says Global is adopted as it stands and nothing re-scopes it.
    $groups = Get-StudioGroupDefinition -Entries (Get-ConfigArray -InputObject $fileServer -Name "groups")
    foreach ($group in $groups) {
        $found = $null
        try { $found = Find-AdcsGroup -Name $group.Name } catch { $found = $null }
        if ($null -eq $found) {
            Write-Log "Share group '$($group.Name)' does not exist - run this config on a domain controller first" -Tag "Error"
            Write-Log "    New-ADGroup -Name '$($group.Name)' -GroupScope DomainLocal -GroupCategory Security" -Tag "Error"
            $passed = $false
        }
    }

    # Each share's read-only group, when it names one. It is checked here rather than
    # only through the groups list because a design edited outside the studio can name a
    # group the list does not carry, and the failure that produces is a share published
    # with an ACL that is missing half of what the design says it grants.
    foreach ($share in (Get-FsShare -FileServer $fileServer)) {
        if ([string]::IsNullOrWhiteSpace($share.ReadGroup)) { continue }
        $found = $null
        try { $found = Find-AdcsGroup -Name $share.ReadGroup } catch { $found = $null }
        if ($null -eq $found) {
            Write-Log "Read-only group '$($share.ReadGroup)' for share '$($share.Name)' does not exist - run this config on a domain controller first" -Tag "Error"
            Write-Log "    New-ADGroup -Name '$($share.ReadGroup)' -GroupScope DomainLocal -GroupCategory Security" -Tag "Error"
            $passed = $false
        }
    }

    $dfs = Get-ConfigValue -InputObject $fileServer -Name "dfs"
    if ([bool](Get-ConfigValue -InputObject $dfs -Name "enabled" -Default $false)) {
        # FS-DFS-Namespace is the role service that actually serves a namespace, and
        # the only one this run needs. RSAT-DFS-Mgmt-Con used to be demanded beside it
        # and that was wrong twice over: it is the MMC console, which this script never
        # opens, and it **cannot be installed on Server Core at all** - so the check
        # refused a server that would have worked perfectly. Same lesson as the AD CS
        # web role services: check for the capability, not for a feature name.
        try {
            $feature = Get-WindowsFeature -Name "FS-DFS-Namespace" -ErrorAction Stop
            if (($null -eq $feature) -or (-not $feature.Installed)) {
                Write-Log "DFS is designed but FS-DFS-Namespace is not installed" -Tag "Error"
                Write-Log "    Install-WindowsFeature -Name FS-DFS-Namespace" -Tag "Error"
                $passed = $false
            }
        }
        catch {
            Write-Log "FS-DFS-Namespace not queryable: $($_.Exception.Message)" -Tag "Error"
            $passed = $false
        }

        # The cmdlets are what this run uses, and they arrive with the role service -
        # not with the console. Asking for them by name is the honest check.
        if (-not (Import-FsDfsModule)) { $passed = $false }
    }

    return $passed
}

# ---------------------------[ Entry point ]---------------------------
function Invoke-FsConfiguration {
    param([object]$Config)

    $fileServer = Get-ConfigValue -InputObject $Config -Name "fileServer"
    if ($null -eq $fileServer) {
        return (New-RoleResult -Status "Failed" -Message "config.json has no fileServer section")
    }

    $groups = Get-StudioGroupDefinition -Entries (Get-ConfigArray -InputObject $fileServer -Name "groups")

    # The directory half. Same config, different machine, different job - see the
    # part header. Nothing below this branch runs on a DC.
    if (Test-StudioDomainController) {
        Write-Log "Domain controller: share groups and members" -Tag "Run"
        $allSynced = $true
        # DomainLocal, not Global: these name a RESOURCE - the folders on one file
        # server - and domain local is the scope that may hold accounts and global
        # groups from anywhere in the forest and be written straight into an ACL here.
        # That is the resource half of AGDLP, and it is what a group called
        # 'Share - HR - RW' is. An existing group is adopted with whatever scope it has.
        foreach ($group in $groups) {
            if (-not (Sync-StudioAccessGroup -Name $group.Name -Description "File share access group" -MemberUpn $group.Members -Scope "DomainLocal")) {
                $allSynced = $false
            }
        }
        # After the groups: the drive map GPOs filter on their SIDs, so a group that
        # failed above fails its GPO here with the reason already on screen.
        if (-not (Sync-FsDriveMapGpo -FileServer $fileServer)) { $allSynced = $false }
        if (-not $allSynced) {
            return (New-RoleResult -Status "ManualStepRequired" -Message "Not every group, member or drive map GPO could be written - fix the names above and re-run")
        }
        return (New-RoleResult -Status "Completed" -Message "Share groups and drive map GPOs ready - run the same config on the file server for the shares themselves")
    }

    # The mode router. The directory half above is shared - groups, members and the
    # drive-map GPOs are the same objects whichever way the shares are served, and the
    # GPO's UNC fallback resolves to the clustered name through fileServer.root.
    if (Test-FsClusterMode -FileServer $fileServer) {
        return (Invoke-FsClusterConfiguration -FileServer $fileServer -Cluster (Get-FsClusterSection -FileServer $fileServer))
    }

    $roots = Get-FsRootDefinition -FileServer $fileServer
    $failures = @()
    # On by default: a design that states a file system, an allocation unit and a label
    # and then leaves a person to type Format-Volume has not built anything.
    $prepare = [bool](Get-ConfigValue -InputObject $fileServer -Name "prepareVolumes" -Default $true)
    $defenderExclusions = [bool](Get-ConfigValue -InputObject $fileServer -Name "defenderExclusions" -Default $true)
    if (-not (Confirm-FsVolumeSet -Roots $roots -Prepare $prepare)) {
        $failures += "volumes"
    }
    else {
        foreach ($root in $roots) {
            if (-not (New-FsRootFolder -Root $root)) { $failures += ("{0} root" -f $root.Drive) }
        }
    }
    if ($failures.Count -gt 0) {
        return (New-RoleResult -Status "Failed" -Message ("The share storage is not ready: {0} - see the log" -f (($failures | Select-Object -Unique) -join ", ")))
    }

    $enumeration = [bool](Get-ConfigValue -InputObject $fileServer -Name "accessBasedEnumeration" -Default $true)
    $shares = Get-FsShare -FileServer $fileServer
    if ($shares.Count -eq 0) {
        Write-Log "No share designed - root folder only" -Tag "Info"
    }

    $wholeVolumeTaken = @{}
    foreach ($share in $shares) {
        $shareRoot = Get-FsRootForShare -Roots $roots -Share $share
        # A whole-volume root can hold exactly one share, because the share is the volume.
        # A second one pointed at the same path would publish two names over one folder
        # with two ACL rebuilds fighting over its descriptor - so the first wins and the
        # rest are refused by name rather than silently sharing.
        if ($shareRoot.WholeVolume) {
            if ($wholeVolumeTaken.ContainsKey($shareRoot.Drive)) {
                Write-Log "'$($share.Name)' cannot also be $($shareRoot.Drive) - '$($wholeVolumeTaken[$shareRoot.Drive])' already is that whole volume" -Tag "Error"
                Write-Log "    Give that root a folder name, or design one share per volume" -Tag "Error"
                $failures += $share.Name
                continue
            }
            $wholeVolumeTaken[$shareRoot.Drive] = $share.Name
        }
        $sharePath = Get-FsSharePath -Root $shareRoot -Share $share
        if (-not $shareRoot.WholeVolume -and -not (Test-Path -LiteralPath $sharePath)) {
            $null = New-Item -ItemType Directory -Path $sharePath -Force
            Write-Log "Created '$sharePath'" -Tag "Debug"
        }
        if ([string]::IsNullOrWhiteSpace($share.Group)) {
            Write-Log "Share '$($share.Name)' names no group - folder created, ACL and share skipped" -Tag "Error"
            $failures += $share.Name
            continue
        }
        if (-not (Set-FsFolderSecurity -Path $sharePath -GroupName $share.Group -ReadGroupName $share.ReadGroup -AccessModel $share.AccessModel)) {
            $failures += $share.Name
            continue
        }
        # The share's own answer when it has one, the server-wide setting when it does
        # not. Absent is not False: a share that says nothing follows the design.
        $shareEnumeration = $enumeration
        if ($null -ne $share.Abe) { $shareEnumeration = [bool]$share.Abe }
        try {
            if (-not (Set-FsSmbShare -Share $share -Path $sharePath -AccessBasedEnumeration $shareEnumeration)) { $failures += $share.Name }
        }
        catch {
            Write-Log "Share '$($share.Name)' not published: $($_.Exception.Message)" -Tag "Error"
            $failures += $share.Name
        }
    }

    # A profile share that nothing points at roams nothing, and the pointer is a Group
    # Policy setting covering every session host rather than a value this server sets
    # for itself - so the run prints the path to put in it rather than writing one.
    # Same boundary the Remote Desktop provider states for the agent it installs.
    foreach ($share in $shares) {
        if ($share.AccessModel -ne "fslogixContainer") { continue }
        $domain = ([string]$env:USERDNSDOMAIN).ToLowerInvariant()
        $serverFqdn = $env:COMPUTERNAME.ToLowerInvariant()
        if (-not [string]::IsNullOrWhiteSpace($domain)) { $serverFqdn = "{0}.{1}" -f $serverFqdn, $domain }
        $uncPath = "\\{0}\{1}" -f $serverFqdn, (Get-FsSmbName -Share $share)

        Write-Log "'$($share.Name)': profile container share ready" -Tag "Info"
        Write-Log "    VHDLocations = $uncPath" -Tag "Info"
        Write-Log "    Set on every session host: HKLM\SOFTWARE\FSLogix\Profiles" -Tag "Info"
        Write-Log "    Never in a DFS replication group - a namespace is fine" -Tag "Warn"

        # This server's half of the antivirus exclusions, set rather than printed. The
        # session hosts' half is theirs - the binaries and the drivers live there.
        if ($defenderExclusions) {
            $shareRoot = Get-FsRootForShare -Roots $roots -Share $share
            $null = Set-FsDefenderExclusion -Path (Get-FsDefenderExclusionPath -SharePath (Get-FsSharePath -Root $shareRoot -Share $share))
        }
        else {
            Write-Log "    Antivirus exclusions are switched off in the design - add the container patterns by hand" -Tag "Warn"
        }
        Write-Log "    On every session host as well: the container patterns, plus frxdrv.sys, frxdrvvt.sys, frxccd.sys and the FSLogix binaries" -Tag "Info"
    }

    if (-not (Set-FsShadowCopyPerRoot -FileServer $fileServer -Roots $roots)) { $failures += "shadow copies" }

    $dfs = Get-ConfigValue -InputObject $fileServer -Name "dfs"
    if ([bool](Get-ConfigValue -InputObject $dfs -Name "enabled" -Default $false)) {
        foreach ($namespace in @(Get-ConfigArray -InputObject $dfs -Name "namespaces")) {
            $namespaceName = Get-ConfigText -InputObject $namespace -Name "name" -Default "namespace"
            try {
                if (-not (Set-FsDfsNamespace -Namespace $namespace -Shares $shares)) { $failures += ("namespace " + $namespaceName) }
            }
            catch {
                Write-Log "Namespace '$namespaceName' failed: $($_.Exception.Message)" -Tag "Error"
                $failures += ("namespace " + $namespaceName)
            }
        }
    }

    if ($failures.Count -gt 0) {
        return (New-RoleResult -Status "ManualStepRequired" -Message ("Finished with problems on: {0} - see the log" -f (($failures | Select-Object -Unique) -join ", ")))
    }
    return (New-RoleResult -Status "Completed" -Message "Shares, permissions and namespace match the design")
}
