# Shared failover cluster machinery - cluster creation, the witness, and a shared
# disk claimed from what the hypervisor already presented.
#
# Dot-sourced by Configure-ServerRoles.ps1 - not runnable on its own. Everything
# here lands in that script's scope, so $script: variables and functions are shared
# with every other part. Use $scriptRootPath, never $PSScriptRoot: inside this file
# $PSScriptRoot is the pwsh folder, not the folder the run was started from.

# ===========================[ Why this file exists ]===========================
# A second role now builds a failover cluster, and a cluster is the same object
# whoever asks for it: two nodes, a name in the directory, an address, a witness that
# breaks the tie, and storage. Written twice it would drift within a release - and the
# half that drifts silently is the witness, where a two-node cluster with no quorum
# resource looks healthy right up to the moment a node reboots.
#
# **It is deliberately not a refactor of `Role.Hyperv.S2d.ps1`.** That path is bench
# tested and isolated on purpose - see the header of Role.Hyperv.Cluster.ps1; moving it onto new
# shared code in the same change that introduces the shared code turns one feature into
# two risks. The S2D part keeps its own witness and cluster functions until this one has
# been on a bench, and the migration is its own commit. Read the two side by side before
# changing either: the reasoning in the S2D file - the identity a probe must use, the
# ordering a file share witness needs, why New-WorkgroupCluster is never called - is the
# reasoning here too, and was paid for in bench runs.
#
# What this file assumes and the S2D one cannot: **the machines are domain members**.
# The guest file server cluster hosts a domain-based DFS namespace and hands out domain
# groups, so a workgroup guest cluster is not a design this studio can produce. Every
# workgroup accommodation in the S2D part is therefore absent here rather than copied.

# ---------------------------[ Where am I ]---------------------------
# The cluster this node is already in, or $null. Every step below is idempotent
# against this: a cluster that exists is never rebuilt, only reconciled.
function Get-StudioClusterHere {
    try { return (Get-Cluster -ErrorAction Stop) } catch { return $null }
}

# The node's job in a two-node design, decided by its own name against the config.
# 'Builder' forms the cluster and owns everything that can only be done once;
# 'Joiner' prepares itself and stops. A machine named in neither is 'None' - the
# same config travels to every machine in the design and each finds its own job.
function Get-StudioClusterPersona {
    param(
        [Parameter(Mandatory)][string[]]$Nodes,
        [string]$BuilderNode = ""
    )

    $me = [string]$env:COMPUTERNAME
    $known = @($Nodes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
    if ($known.Count -eq 0) { return "None" }

    $mine = $known | Where-Object { $_.Split(".")[0] -eq $me }
    if (@($mine).Count -eq 0) { return "None" }

    $builder = ([string]$BuilderNode).Trim()
    # Unstated means the last node in the list, not the first: the builder is the node
    # that runs *after* every other one is prepared, and a list is read top to bottom.
    if ([string]::IsNullOrWhiteSpace($builder)) { $builder = $known[$known.Count - 1] }
    if ($builder.Split(".")[0] -eq $me) { return "Builder" }
    return "Joiner"
}

# The physical host this virtual machine is running on, as the host itself reported it
# through the Data Exchange integration service. Empty when the service is off, when
# this is not a guest, or when the host never wrote it - all three are "cannot tell"
# rather than "not co-located", and every caller treats them that way.
function Get-StudioVirtualHostName {
    $path = "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"
    foreach ($name in @("PhysicalHostNameFullyQualified", "PhysicalHostName")) {
        try {
            $value = (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name
            if (-not [string]::IsNullOrWhiteSpace([string]$value)) { return ([string]$value).Trim() }
        }
        catch { }
    }
    return ""
}

# Two guest nodes on one hypervisor is a cluster that survives a node reboot and
# nothing else - the host underneath both is a single point of failure, and patching
# *it* takes down the very sessions the cluster exists to keep. Reported, never
# enforced: co-location is a legitimate temporary state (a host in maintenance, a
# two-VM lab), and refusing to build a working cluster over a placement preference
# would be wrong. The peer's answer arrives over WinRM because only the peer can read
# its own registry.
function Write-StudioClusterPlacementNote {
    param(
        [Parameter(Mandatory)][string]$PeerName,
        [System.Management.Automation.PSCredential]$Credential = $null
    )

    $mine = Get-StudioVirtualHostName
    if ([string]::IsNullOrWhiteSpace($mine)) {
        Write-Log "Could not read this node's physical host - Data Exchange integration service off, or this is not a virtual machine" -Tag "Info"
        Write-Log "    Check by hand that the two nodes do not run on the same hypervisor" -Tag "Warn"
        return
    }

    $theirs = ""
    try {
        $parameters = @{ ComputerName = $PeerName; ErrorAction = "Stop"; ScriptBlock = {
            $path = "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"
            foreach ($name in @("PhysicalHostNameFullyQualified", "PhysicalHostName")) {
                try {
                    $value = (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name
                    if (-not [string]::IsNullOrWhiteSpace([string]$value)) { return ([string]$value).Trim() }
                }
                catch { }
            }
            return ""
        } }
        if ($null -ne $Credential) { $parameters["Credential"] = $Credential }
        $theirs = [string](Invoke-Command @parameters)
    }
    catch {
        Write-Log "Could not ask '$PeerName' which host it runs on: $($_.Exception.Message)" -Tag "Warn"
        return
    }

    if ([string]::IsNullOrWhiteSpace($theirs)) {
        Write-Log "'$PeerName' did not report a physical host - check by hand that the two nodes are not on the same hypervisor" -Tag "Warn"
        return
    }

    if ($mine.Split(".")[0] -eq $theirs.Split(".")[0]) {
        Write-Log "Both nodes are running on '$mine' - this cluster survives a node reboot and nothing else" -Tag "Warn"
        Write-Log "    Separate them, and on a Hyper-V cluster make it stick: Set-ClusterGroup -Name <vm> -AntiAffinityClassNames 'files'" -Tag "Warn"
        Write-Log "    Patching that host takes both file server nodes down at once - the outage this cluster is meant to prevent" -Tag "Warn"
        return
    }

    Write-Log "Nodes are on different hosts: '$mine' and '$theirs'" -Tag "Ok"
}

# ---------------------------[ Who is running this ]---------------------------
# Forming a cluster is remote work: every call reaches the other node, and the other node
# authenticates whoever made it. A SYSTEM token carries no network credential, so those
# calls arrive as this machine's account - which the peer does not accept, in a workgroup
# because it has never heard of it and in a domain because it is not a local
# administrator there. No cluster cmdlet takes a -Credential to work around it: they use
# the caller's token, full stop.
#
# Which makes this a **warning**, not an error. Nothing failed and nothing is broken -
# the node is prepared, its own work is done, and the next step needs a person to be
# signed in. The resume task registered at the reboot is SYSTEM on purpose (it is right
# for every local job and this design deliberately stores no password to make it
# anything else), so it will reach this same point after every boot and stop here again.
# That is not a fault either, and the message says so rather than leaving somebody to
# wonder why the same lines keep appearing in a fresh log.
function Test-StudioClusterIdentity {
    param([string]$Action = "form the cluster")

    $whoami = $env:USERNAME
    try { $whoami = [string][System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $whoami = $env:USERNAME }

    if ($whoami -notmatch '(?i)^(NT AUTHORITY\\SYSTEM|.*\$)$') { return $true }

    Write-Log "Running as '$whoami', which cannot $Action - a machine account has no network credential for the other node" -Tag "Warn"
    Write-Log "    Everything done so far stays done. Sign in at this node's console and run:" -Tag "Warn"
    Write-Log ("        {0} -ConfigPath ""{1}"" -Resume" -f (Get-StudioResumeCommand), $script:configFilePath) -Tag "Warn"
    Write-Log "    The resume task retries at every start and stops here until then" -Tag "Info"
    return $false
}

# The entry script as somebody would type it. The path is the one this run was started
# from, so a copy under C:\role-hv and a copy on a share both print themselves correctly.
function Get-StudioResumeCommand {
    $path = [string]$script:entryScriptPath
    if ([string]::IsNullOrWhiteSpace($path)) { return ".\Configure-ServerRoles.ps1" }
    return $path
}

# ---------------------------[ Features ]---------------------------
# Failover Clustering is a feature this script never installs, the same rule every
# other role follows: which roles a server carries is a decision somebody made. The
# PowerShell half is named separately because a Server Core install can carry the
# feature and not the cmdlets, and every call below is a cmdlet.
function Test-StudioClusterFeature {
    $passed = $true
    foreach ($feature in @("Failover-Clustering", "RSAT-Clustering-PowerShell")) {
        try {
            $found = Get-WindowsFeature -Name $feature -ErrorAction Stop
            if (($null -eq $found) -or (-not $found.Installed)) {
                Write-Log "The '$feature' feature is not installed" -Tag "Error"
                Write-Log "    Install-WindowsFeature -Name $feature" -Tag "Error"
                $passed = $false
            }
        }
        catch {
            Write-Log "Could not query the '$feature' feature: $($_.Exception.Message)" -Tag "Error"
            $passed = $false
        }
    }
    return $passed
}

# ---------------------------[ Validation ]---------------------------
# Test-Cluster before New-Cluster, and the category list is the point. A guest cluster
# on a shared VHD Set or a LUN wants the **legacy "Storage" category**, which is what
# actually exercises SCSI-3 persistent reservations through the virtual disk - the one
# thing that decides whether the disk fails over cleanly or corrupts. That is the exact
# opposite of the S2D path, where the legacy category must never be used because the
# disks are not shared. Do not "align" the two.
#
# The report is written whatever the outcome, and a failure stops the run: a cluster
# built on storage that failed validation is a cluster that works until it moves.
function Test-StudioClusterValidation {
    param(
        [Parameter(Mandatory)][string[]]$Nodes,
        [string[]]$Include = @("Storage", "Inventory", "Network", "System Configuration")
    )

    Write-Log ("Validating {0} - categories: {1}" -f ($Nodes -join " + "), ($Include -join ", ")) -Tag "Run"
    Write-Log "    The Storage category is the one that matters here - it proves the shared disk honours SCSI-3 reservations" -Tag "Debug"
    try {
        $report = Test-Cluster -Node $Nodes -Include $Include -ErrorAction Stop
        if ($null -ne $report) { Write-Log "Validation report: $($report.FullName)" -Tag "Info" }
        return $true
    }
    catch {
        Write-Log "Cluster validation failed: $($_.Exception.Message)" -Tag "Error"
        Write-Log "    Read the report before anything else - a cluster built over a failed storage test moves badly, not never" -Tag "Error"
        return $false
    }
}

# ---------------------------[ The cluster ]---------------------------
# Names, an address and an OU. Two things are deliberate: -NoStorage, so clustering
# does not claim the shared disk before this run has formatted it the way continuous
# availability needs; and the OU carried inside the name, which is how New-Cluster is
# told where to put the cluster name object.
function New-StudioCluster {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$Nodes,
        [string]$StaticAddress = "",
        [string]$OuPath = "",
        [bool]$NoStorage = $true
    )

    $existing = Get-StudioClusterHere
    if ($null -ne $existing) {
        Write-Log "Already in the cluster '$($existing.Name)' - left as it is" -Tag "Info"
        return $true
    }

    $parameters = @{
        Name        = $Name
        Node        = $Nodes
        Force       = $true
        ErrorAction = "Stop"
    }
    if ($NoStorage) { $parameters["NoStorage"] = $true }
    if (-not [string]::IsNullOrWhiteSpace($StaticAddress)) { $parameters["StaticAddress"] = $StaticAddress.Trim() }
    if (-not [string]::IsNullOrWhiteSpace($OuPath)) { $parameters["Name"] = "CN=$Name,$($OuPath.Trim())" }

    Write-Log ("Creating the cluster '{0}' across {1}" -f $Name, ($Nodes -join " + ")) -Tag "Run"
    try {
        $null = New-Cluster @parameters
        Write-Log "The cluster '$Name' exists" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "The cluster could not be created: $($_.Exception.Message)" -Tag "Error"
        Write-Log "    The account running this needs 'Create Computer Objects' where the cluster name object goes" -Tag "Info"
        Write-Log "    A prestaged name object works too - create it disabled and give the account running this Full control on it" -Tag "Debug"
        return $false
    }
}

# The cluster name object has to be able to create the *role's* name object later, and
# that is the failure people meet an hour after the cluster is built: the cluster
# exists, Add-ClusterFileServerRole fails, and the message is about the network name
# resource rather than about a permission. Reported here, while the cluster is being
# built and somebody is still looking.
function Write-StudioClusterVcoNote {
    param(
        [Parameter(Mandatory)][string]$ClusterName,
        [Parameter(Mandatory)][string]$RoleName,
        [string]$OuPath = ""
    )

    Write-Log "The role '$RoleName' gets its own computer object, created by '$ClusterName$'" -Tag "Info"
    if ([string]::IsNullOrWhiteSpace($OuPath)) {
        Write-Log "    That account needs 'Create Computer Objects' in the container the cluster name object lives in" -Tag "Info"
    }
    else {
        Write-Log "    That account needs 'Create Computer Objects' on $OuPath" -Tag "Info"
    }
    Write-Log "    Or prestage '$RoleName' disabled in that container and give '$ClusterName$' Full control on the object" -Tag "Debug"
}

# ---------------------------[ The witness ]---------------------------
# Two nodes without a witness is a coin with no edge: lose either node and the survivor
# holds one vote out of two and stops. Configured immediately after the cluster exists,
# and never rewritten - a cluster that already has a quorum resource is left alone,
# because changing a working witness is a quorum change on a live cluster.
function Test-StudioClusterWitnessConfigured {
    try {
        $quorum = Get-ClusterQuorum -ErrorAction Stop
        if ($null -ne $quorum.QuorumResource) { return $true }
    }
    catch { }
    return $false
}

# Can the share be opened at all, and which of the two causes is it when it cannot?
# New-PSDrive rather than Test-Path because that is the same authenticated SMB session
# the cluster makes, and because its failures separate a refusal (the grants) from a
# path that is not there (name resolution, the firewall, a share never published).
#
# The identity caveat is stated rather than solved: the *cluster* connects to the
# witness as `<cluster>$`, and this probe runs as whoever is driving the script. It is
# therefore evidence about the share existing, not proof the cluster can open it - so a
# failure warns and Set-ClusterQuorum is still attempted, which is the call whose answer
# actually settles it. Three bench runs have been lost to a probe that answered for the
# wrong account; this one says which account it answered for.
function Test-StudioClusterShareReachable {
    param([Parameter(Mandatory)][string]$Path)

    $driveName = "wit" + ([string](Get-Random -Minimum 100 -Maximum 999))
    try {
        $null = New-PSDrive -Name $driveName -PSProvider FileSystem -Root $Path -ErrorAction Stop
        $null = Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
        Write-Log "'$Path' opens as $env:USERDOMAIN\$env:USERNAME" -Tag "Info"
        return $true
    }
    catch {
        Write-Log "'$Path' did not open as $env:USERDOMAIN\$env:USERNAME : $($_.Exception.Message)" -Tag "Warn"
        Write-Log "    That is not the identity the cluster uses - the quorum call below is the one that decides" -Tag "Info"
        return $false
    }
}

function Set-StudioClusterFileShareWitness {
    param(
        [Parameter(Mandatory)][object]$Witness,
        [Parameter(Mandatory)][string]$ClusterName
    )

    $fileShare = Get-ConfigValue -InputObject $Witness -Name "fileShare"
    $witnessHost = ([string](Get-ConfigText -InputObject $fileShare -Name "host" -Default "")).Trim()
    $share = ([string](Get-ConfigText -InputObject $fileShare -Name "shareName" -Default "")).Trim()
    if ([string]::IsNullOrWhiteSpace($witnessHost) -or [string]::IsNullOrWhiteSpace($share)) {
        Write-Log "The file share witness names no host or no share - fill both in on the witness card" -Tag "Error"
        return $false
    }

    $path = "\\{0}\{1}" -f $witnessHost, $share
    $null = Test-StudioClusterShareReachable -Path $path

    Write-Log "Configuring the file share witness on '$path'" -Tag "Run"
    try {
        $null = Set-ClusterQuorum -NodeAndFileShareMajority $path -ErrorAction Stop
        Write-Log "The witness is '$path'" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "The file share witness could not be configured: $($_.Exception.Message)" -Tag "Error"
        # The classic failure is granting one of the two, which reads as a permission
        # error about a path that is plainly there.
        Write-Log "    '$ClusterName$' needs Full control on BOTH the share and the NTFS folder - granting one of the two is the usual cause" -Tag "Info"
        Write-Log "    On the witness host: Grant-SmbShareAccess -Name '$share' -AccountName '$ClusterName$' -AccessRight Full -Force" -Tag "Info"
        Write-Log "    The witness must not live on a node of this cluster" -Tag "Debug"
        return $false
    }
}

function Set-StudioClusterCloudWitness {
    param(
        [Parameter(Mandatory)][object]$Witness,
        [string]$AccessKey = ""
    )

    $cloud = Get-ConfigValue -InputObject $Witness -Name "cloud"
    $account = ([string](Get-ConfigText -InputObject $cloud -Name "accountName" -Default "")).Trim()
    if ([string]::IsNullOrWhiteSpace($account)) {
        Write-Log "The cloud witness names no storage account - fill it in on the witness card" -Tag "Error"
        return $false
    }

    if ([bool](Get-ConfigValue -InputObject $cloud -Name "useManagedIdentity" -Default $false)) {
        Write-Log "Configuring the cloud witness on '$account' with the nodes' managed identities" -Tag "Run"
        try {
            $null = Set-ClusterQuorum -CloudWitness -AccountName $account -UseManagedIdentity -ErrorAction Stop
            Write-Log "Witness: storage account '$account', Arc machine identities" -Tag "Ok"
            return $true
        }
        catch {
            Write-Log "The managed-identity cloud witness could not be configured: $($_.Exception.Message)" -Tag "Error"
            Write-Log "    Needs Windows Server 2025, both nodes Arc-connected, and Storage Blob Data Contributor for each node identity" -Tag "Info"
            return $false
        }
    }

    # The design's own value first, the console's second. A key in config.json is what
    # makes this leg unattended - which is the whole point of carrying the design to the
    # machine - and the console answer exists for a design exported without secrets.
    $key = ([string](Get-ConfigText -InputObject $cloud -Name "accessKey" -Default "")).Trim()
    if (-not [string]::IsNullOrWhiteSpace($key)) {
        Write-Log "Cloud witness key from the design" -Tag "Info"
    }
    else {
        $key = ([string]$AccessKey).Trim()
    }
    if ([string]::IsNullOrWhiteSpace($key)) {
        Write-Log "The cloud witness needs the storage account's access key and neither the design nor this console supplied one" -Tag "Error"
        Write-Log "    By hand: Set-ClusterQuorum -CloudWitness -AccountName $account -AccessKey <key>" -Tag "Info"
        Write-Log "    Or put the key on the witness card and export with secrets included" -Tag "Info"
        return $false
    }

    $endpoint = ([string](Get-ConfigText -InputObject $cloud -Name "endpoint" -Default "core.windows.net")).Trim()
    Write-Log "Configuring the cloud witness on '$account'" -Tag "Run"
    try {
        $parameters = @{ CloudWitness = $true; AccountName = $account; AccessKey = $key; ErrorAction = "Stop" }
        if ((-not [string]::IsNullOrWhiteSpace($endpoint)) -and ($endpoint -ne "core.windows.net")) { $parameters["Endpoint"] = $endpoint }
        $null = Set-ClusterQuorum @parameters
        Write-Log "Witness: storage account '$account'" -Tag "Ok"
        Write-Log "    Rotating the key: point every cluster at the secondary first, then regenerate the primary" -Tag "Debug"
        return $true
    }
    catch {
        Write-Log "The cloud witness could not be configured: $($_.Exception.Message)" -Tag "Error"
        Write-Log "    Both nodes need outbound 443 to $account.blob.$endpoint - the proxy is WinHTTP's, not the browser's" -Tag "Info"
        return $false
    }
}

function Set-StudioClusterWitness {
    param(
        [Parameter(Mandatory)][object]$Witness,
        [Parameter(Mandatory)][string]$ClusterName,
        [string]$AccessKey = ""
    )

    if (Test-StudioClusterWitnessConfigured) {
        Write-Log "The cluster already has a witness - left exactly as it is" -Tag "Info"
        return $true
    }

    $type = [string](Get-ConfigText -InputObject $Witness -Name "type" -Default "cloud")
    if ($type -eq "fileShare") {
        return (Set-StudioClusterFileShareWitness -Witness $Witness -ClusterName $ClusterName)
    }
    return (Set-StudioClusterCloudWitness -Witness $Witness -AccessKey $AccessKey)
}

# ---------------------------[ The shared disk ]---------------------------
# What the hypervisor presented and nothing else. The disk arrives attached to both
# guests and raw; everything from there - initialise, partition, format, hand to the
# cluster - is this run's, because every one of those steps has an answer continuous
# availability depends on and a wizard would let somebody get wrong.
#
# Candidates are RAW and not already clustered. A disk carrying a partition is never
# touched: on a shared disk, "it looked empty from here" is how the other node's data
# is destroyed.
function Get-StudioClusterSharedDiskCandidate {
    $found = @()
    try { $disks = @(Get-Disk -ErrorAction Stop) } catch { return ,$found }

    foreach ($disk in $disks) {
        if ($disk.IsBoot -or $disk.IsSystem) { continue }
        if ($disk.IsClustered) { continue }
        $found += $disk
    }
    return ,$found
}

# The volume flag continuous availability cares about, read back rather than assumed.
# **Returns $true when short name creation is OFF** - the state a continuously available
# share needs - $false when it is on, and $null when the answer could not be read: fsutil
# prints a localised sentence with the state as a digit in it, so a machine in a language
# this parse does not fit reports "could not tell" and the caller warns instead of
# refusing. A wrong refusal here would block a correct build.
#
# The sense of that digit is the whole trap, and it was inverted here until a bench run
# caught it (2026-08-23): `fsutil 8dot3name query D:` answers **`The volume state is: 0
# (8dot3 name creation is enabled)`** - zero means ON, one means OFF, which is the
# opposite of how a boolean named after the feature reads. The function returned
# "digit -eq 0" to a caller that named the result $shortNamesOff, so it failed every
# volume it had just formatted correctly and would have passed an adopted volume that
# really did have short names on. Both directions wrong, and only the first one visible.
function Test-StudioVolumeShortName {
    param([Parameter(Mandatory)][string]$Drive)

    $letter = $Drive.TrimEnd("\").TrimEnd(":")
    try {
        $output = & fsutil.exe 8dot3name query "${letter}:" 2>&1
        $text = ($output | Out-String)
        # State 1 is disabled, which is what this returns $true for.
        if ($text -match "(?m)^\s*.*?:\s*([01])\s") { return ([int]$Matches[1] -eq 1) }
        if ($text -match "([01])\s*\(") { return ([int]$Matches[1] -eq 1) }
        return $null
    }
    catch { return $null }
}

# Whether a drive letter is free on the OTHER node, asked before this one formats
# anything. A cluster disk's letter is mapped persistently across every node, and the
# disk cannot come online on a node where that letter is already taken - so a letter
# that is free here and busy there produces a cluster that passes every check, serves
# every share, and then fails to bring the role online at the first planned move. Which
# is the one moment the whole design exists for.
#
# `D:` is the letter this bites on, because it is the default **DVD** letter in a
# Windows guest: the node that happens to have no optical drive formats it happily and
# the other one refuses it forever.
#
# Answers $true when the letter is free or the question cannot be asked. A peer that
# refuses the session is not evidence that the letter is taken, and a refusal on no
# evidence would block a build that is very probably correct - the same rule the rest
# of this file follows.
function Test-StudioClusterDriveFreeOnPeer {
    param(
        [Parameter(Mandatory)][string]$Drive,
        [string]$PeerName = ""
    )

    if ([string]::IsNullOrWhiteSpace($PeerName)) { return $true }
    $letter = $Drive.TrimEnd("\").TrimEnd(":")

    $holder = $null
    try {
        $holder = Invoke-Command -ComputerName $PeerName -ErrorAction Stop -ScriptBlock {
            $wanted = [string]$using:letter
            $volume = @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { [string]$_.DriveLetter -eq $wanted })
            if ($volume.Count -eq 0) { return "" }
            $label = [string]$volume[0].FileSystemLabel
            $type = [string]$volume[0].DriveType
            if ([string]::IsNullOrWhiteSpace($label)) { return $type }
            return ("{0} '{1}'" -f $type, $label)
        }
    }
    catch {
        Write-Log "Could not check whether ${letter}: is free on '$PeerName': $($_.Exception.Message)" -Tag "Warn"
        Write-Log "    Check it there by hand - a letter taken on one node stops the disk coming online on it" -Tag "Warn"
        return $true
    }

    if ([string]::IsNullOrWhiteSpace([string]$holder)) { return $true }

    Write-Log ("${letter}: is already taken on '{0}' by a {1}" -f $PeerName, [string]$holder) -Tag "Error"
    Write-Log "    A cluster disk's letter is mapped on every node, so the role would not come online there" -Tag "Error"
    if ([string]$holder -match "(?i)cd-?rom|optical") {
        Write-Log ("    Move the optical drive: Get-Volume -DriveLetter {0} | Get-Partition | Set-Partition -NewDriveLetter <free letter>" -f $letter) -Tag "Info"
    }
    Write-Log "    Or give the shared disk a letter that is free on both nodes" -Tag "Info"
    return $false
}

# Initialise, partition, format - with the two settings SMB Transparent Failover
# actually depends on:
#
#   - **8.3 short names off.** A continuously available share on a volume with short
#     name creation enabled does not fail over transparently. Nothing errors; the
#     handles simply break on a planned move, which is the one moment the whole design
#     exists for. Format-Volume -ShortFileNameSupport $false is the only chance to set
#     it, because it is a volume-creation property.
#   - **no compression.** NTFS-compressed files are the other documented incompatibility.
#     Format-Volume never compresses, so this is only checked when adopting.
function Initialize-StudioClusterSharedDisk {
    param(
        [Parameter(Mandatory)][object]$Disk,
        [Parameter(Mandatory)][string]$Drive,
        [string]$Label = "data",
        [int]$AllocationUnitSize = 4096,
        [bool]$LargeFileRecordSegments = $false
    )

    $letter = $Drive.TrimEnd("\").TrimEnd(":")

    if ($Disk.PartitionStyle -ne "RAW") {
        Write-Log "Disk $($Disk.Number) is not raw - it carries a $($Disk.PartitionStyle) layout and is left alone" -Tag "Error"
        Write-Log "    A shared disk that already has a partition on it is somebody's data until a person says otherwise" -Tag "Error"
        return $false
    }

    Write-Log "Preparing disk $($Disk.Number) ($([math]::Round($Disk.Size / 1GB)) GB) as ${letter}:" -Tag "Run"
    try {
        if ($Disk.IsOffline) { $null = Set-Disk -Number $Disk.Number -IsOffline $false -ErrorAction Stop }
        if ($Disk.IsReadOnly) { $null = Set-Disk -Number $Disk.Number -IsReadOnly $false -ErrorAction Stop }
        $null = Initialize-Disk -Number $Disk.Number -PartitionStyle GPT -ErrorAction Stop
        $partition = New-Partition -DiskNumber $Disk.Number -UseMaximumSize -DriveLetter $letter -ErrorAction Stop
        # -UseLargeFRS is 4 KB file record segments instead of 1 KB. It is a volume
        # creation property like the two above, and it is here for the same kind of
        # reason: a dynamically expanding VHDX accumulates extents for months, the
        # retrieval pointers for them live in the file record, and when that record
        # cannot hold any more the file simply stops being extendable -
        # ERROR_FILE_SYSTEM_LIMITATION, which surfaces as a profile container that will
        # not grow and a user who cannot sign in. Microsoft names the pair explicitly:
        # 64 KB allocation units together with large file record segments, for volumes
        # used with Data Deduplication or hosting large .vhdx files.
        $formatParameters = @{
            Partition             = $partition
            FileSystem            = "NTFS"
            NewFileSystemLabel    = $Label
            AllocationUnitSize    = $AllocationUnitSize
            ShortFileNameSupport  = $false
            Confirm               = $false
            ErrorAction           = "Stop"
        }
        if ($LargeFileRecordSegments) { $formatParameters["UseLargeFRS"] = $true }
        $null = Format-Volume @formatParameters
        Write-Log ("{0}: formatted NTFS, {1} byte units, short names off{2}" -f $letter, $AllocationUnitSize,
            $(if ($LargeFileRecordSegments) { ", large FRS" } else { "" })) -Tag "Ok"
    }
    catch {
        Write-Log "The shared disk could not be prepared: $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    return (Test-StudioClusterVolumeReady -Drive $Drive)
}

# The check that stands between "the share exists" and "the share fails over". Run on a
# volume this script formatted and on one it adopted, because the second case is the
# one where the answer can be wrong.
function Test-StudioClusterVolumeReady {
    param([Parameter(Mandatory)][string]$Drive)

    $letter = $Drive.TrimEnd("\").TrimEnd(":")
    $ready = $true

    $shortNamesOff = Test-StudioVolumeShortName -Drive $Drive
    if ($null -eq $shortNamesOff) {
        Write-Log "Could not read the 8.3 short name state of ${letter}: - check it by hand" -Tag "Warn"
        Write-Log "    fsutil 8dot3name query ${letter}:  - state 1 is what a continuously available share needs" -Tag "Warn"
    }
    elseif (-not $shortNamesOff) {
        Write-Log "${letter}: has 8.3 short name creation enabled, which breaks SMB Transparent Failover" -Tag "Error"
        Write-Log "    A continuously available share on this volume looks right and drops every handle when the role moves" -Tag "Error"
        Write-Log "    Volume-creation property: reformat with 'format ${letter}: /FS:NTFS /S:disable', it cannot be changed afterwards" -Tag "Error"
        $ready = $false
    }
    else {
        Write-Log "${letter}: 8.3 short names off" -Tag "Ok"
    }

    try {
        $root = Get-Item -LiteralPath ("${letter}:\") -ErrorAction Stop
        if (($root.Attributes -band [System.IO.FileAttributes]::Compressed) -ne 0) {
            Write-Log "${letter}: is NTFS-compressed, which is the other thing transparent failover cannot carry" -Tag "Error"
            $ready = $false
        }
    }
    catch { }

    return $ready
}

# Available Storage, then the role. Kept separate from the formatting above because a
# re-run finds the disk already clustered and must do neither.
function Add-StudioClusterSharedDisk {
    $added = @()
    try { $available = @(Get-ClusterAvailableDisk -ErrorAction Stop) } catch { $available = @() }
    if ($available.Count -eq 0) {
        Write-Log "No unclaimed shared disk is visible to the cluster" -Tag "Info"
        return ,$added
    }

    foreach ($disk in $available) {
        try {
            $resource = $disk | Add-ClusterDisk -ErrorAction Stop
            Write-Log "'$($resource.Name)' is now cluster storage" -Tag "Ok"
            $added += $resource
        }
        catch {
            Write-Log "Could not add a shared disk to the cluster: $($_.Exception.Message)" -Tag "Error"
        }
    }
    return ,$added
}

# The disk resource holding a given drive letter, whichever node owns it right now.
# Everything downstream - the file server role, the shares, the shadow copies - keys
# off the letter rather than off a resource name, because the letter is what the
# design states and the resource name is what clustering happened to mint.
function Get-StudioClusterDiskForDrive {
    param([Parameter(Mandatory)][string]$Drive)

    $letter = $Drive.TrimEnd("\").TrimEnd(":")

    # The documented mapping, and therefore the first one tried: the cluster's own WMI
    # provider associates a Physical Disk **resource** directly with its partition through
    # MSCluster_ResourceToDiskPartition (GroupComponent = the disk resource, PartComponent
    # = the partition, Windows Server 2012 and later), and MSCluster_DiskPartition.Path is
    # "the path, including the drive letter if present, of the clustered disk partition".
    # That is one association hop and one documented property - no private resource
    # parameter has to be populated for it to answer.
    try {
        $instances = @(Get-CimInstance -Namespace "root\MSCluster" -ClassName "MSCluster_Resource" `
            -Filter "Type='Physical Disk'" -ErrorAction Stop)
        foreach ($instance in $instances) {
            # Two ways to walk the same association, because the field scripts that do
            # this for a living are split between them: by the association class, and by
            # the result class. Either answers on a healthy build; trying both costs one
            # failed call on a build where the first form is not accepted.
            $partitions = @()
            try {
                $partitions = @(Get-CimAssociatedInstance -InputObject $instance `
                    -Association "MSCluster_ResourceToDiskPartition" -ErrorAction Stop)
            }
            catch { $partitions = @() }
            if ($partitions.Count -eq 0) {
                try {
                    $partitions = @(Get-CimAssociatedInstance -InputObject $instance `
                        -ResultClassName "MSCluster_DiskPartition" -ErrorAction Stop)
                }
                catch { continue }
            }

            foreach ($partition in $partitions) {
                if (([string]$partition.Path).TrimEnd("\").TrimEnd(":") -ne $letter) { continue }
                $name = [string]$instance.Name
                try { return (Get-ClusterResource -Name $name -ErrorAction Stop) }
                catch { return $null }
            }
        }
    }
    catch { }

    # Fallbacks for a build where that class cannot be queried. DiskPath is not populated
    # everywhere, which is why the second one scans every parameter for a value that
    # begins with the letter - a guess by comparison with the association above, and kept
    # only because it costs nothing when the documented route has already failed.
    try { $resources = @(Get-ClusterResource -ErrorAction Stop | Where-Object { $_.ResourceType -eq "Physical Disk" }) }
    catch { return $null }

    foreach ($resource in $resources) {
        try {
            $info = $resource | Get-ClusterParameter -Name "DiskPath" -ErrorAction SilentlyContinue
            if (($null -ne $info) -and ([string]$info.Value).TrimEnd("\").TrimEnd(":") -eq $letter) {
                Write-Log "'$([string]$resource.Name)' holds ${letter}: - from the DiskPath parameter, not the disk partition class" -Tag "Debug"
                return $resource
            }
        }
        catch { }
        try {
            $values = @($resource | Get-ClusterParameter -ErrorAction SilentlyContinue)
            foreach ($value in $values) {
                if (([string]$value.Value) -match ("(?i)^" + [regex]::Escape($letter) + ":")) {
                    Write-Log "'$([string]$resource.Name)' holds ${letter}: - matched on the '$([string]$value.Name)' parameter" -Tag "Debug"
                    return $resource
                }
            }
        }
        catch { }
    }
    return $null
}

# The same lookup, waited for. A Physical Disk resource that was added a moment ago is
# **Offline**, and an offline disk resource reports no volume and no DiskPath - the
# cluster reads the partition off the disk when it brings the resource online, not when
# it accepts it into Available Storage. So the bare lookup run in the same second as
# Add-ClusterDisk answers "no cluster disk holds D:" about a disk that plainly exists,
# which is what it did on the bench (2026-08-23: 'Cluster Disk 1' is now cluster storage
# and No cluster disk holds D:, one second apart).
#
# Offline is also worth acting on rather than only waiting through: a disk sitting in
# Available Storage does not come online on its own on every build, and Start-ClusterResource
# is what the console's own right-click does.
function Wait-StudioClusterDiskForDrive {
    param(
        [Parameter(Mandatory)][string]$Drive,
        [int]$TimeoutSeconds = 60
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $started = @()

    while ($true) {
        $disk = Get-StudioClusterDiskForDrive -Drive $Drive
        if ($null -ne $disk) { return $disk }

        # Anything offline is asked to come online once - after which its parameters
        # populate and the next pass of the lookup finds it.
        try {
            foreach ($resource in @(Get-ClusterResource -ErrorAction Stop |
                Where-Object { ([string]$_.ResourceType -eq "Physical Disk") -and ([string]$_.State -ne "Online") })) {
                $name = [string]$resource.Name
                if ($started -contains $name) { continue }
                $started += $name
                Write-Log "'$name' is $([string]$resource.State) - starting it so its volume can be read" -Tag "Debug"
                try { $null = Start-ClusterResource -Name $name -ErrorAction Stop }
                catch { Write-Log "'$name' would not start: $($_.Exception.Message)" -Tag "Debug" }
            }
        }
        catch { }

        if ((Get-Date) -ge $deadline) { return $null }
        Start-Sleep -Seconds 3
    }
}

# Bring a cluster group here, and wait until its volume actually is.
#
# `Add-ClusterFileServerRole` takes the disk out of Available Storage and into the new
# group - and the cluster brings that group online on **whichever node it chooses**,
# which is not necessarily the one running this script. Everything after it here is
# local work on the volume: the folders, the ACLs, the shares, the shadow copies. On the
# node that does not own the group there is no D: at all, and the failure reads
# `Cannot find drive. A drive with the name 'D' does not exist` from whichever cmdlet
# touched it first (bench, 2026-08-23).
#
# Moving rather than reporting, because this is a build: the group has just been created
# by this run, nothing is using it yet, and `Move-ClusterGroup` is the same operation the
# console's own "Move -> Select Node" performs.
function Move-StudioClusterGroupHere {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Drive = "",
        [int]$TimeoutSeconds = 60
    )

    $me = [string]$env:COMPUTERNAME
    $owner = ""
    try { $owner = [string](Get-ClusterGroup -Name $Name -ErrorAction Stop).OwnerNode }
    catch {
        Write-Log "The group '$Name' could not be read: $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    if ($owner -ne $me) {
        Write-Log "'$Name' is online on '$owner' - moving it here" -Tag "Run"
        try { $null = Move-ClusterGroup -Name $Name -Node $me -ErrorAction Stop }
        catch {
            Write-Log "'$Name' could not be moved here: $($_.Exception.Message)" -Tag "Error"
            Write-Log "    Run this config on '$owner', or move it by hand: Move-ClusterGroup -Name '$Name' -Node '$me'" -Tag "Info"
            return $false
        }
    }

    if ([string]::IsNullOrWhiteSpace($Drive)) { return $true }

    # Owning the group and having the volume mounted are two moments, not one.
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        if (Test-StudioClusterOwnsDrive -Drive $Drive) { return $true }
        if ((Get-Date) -ge $deadline) {
            Write-Log "$Drive is still not mounted here after moving '$Name'" -Tag "Error"
            return $false
        }
        Start-Sleep -Seconds 2
    }
}

# Is this node the one currently holding the disk? Shadow copies, folder creation and
# every other job that touches the volume can only run where the volume is mounted -
# and on the other node the same run has to do nothing rather than fail.
function Test-StudioClusterOwnsDrive {
    param([Parameter(Mandatory)][string]$Drive)

    $letter = $Drive.TrimEnd("\").TrimEnd(":")
    try { return [bool](Test-Path -LiteralPath ("${letter}:\")) } catch { return $false }
}
