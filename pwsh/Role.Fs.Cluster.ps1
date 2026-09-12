# Role provider: File Server, guest cluster mode - two virtual machines, one shared
# disk the hypervisor already presented, a general use file server role, and a DFS
# namespace hosted by the nodes rather than by the cluster.
#
# Dot-sourced by Configure-ServerRoles.ps1 - not runnable on its own. Everything
# here lands in that script's scope, so $script: variables and functions are shared
# with every other part. Use $scriptRootPath, never $PSScriptRoot: inside this file
# $PSScriptRoot is the pwsh folder, not the folder the run was started from.

# ===========================[ The shape, and why ]===========================
# `fileServer.mode` is the router and there are exactly two values: `singleHost` and
# `guestCluster`. They are different builds, not two views of one - the same rule
# Hyper-V follows. The single-host path is untouched by this file; the four dispatch
# points in `Role.Fs.ps1` are the only place the two meet.
#
# The design is one specific arrangement, and every part of it is a decision:
#
#   files-01, files-02          two guest VMs, domain members, each with its own address
#   cl-files-01                 the cluster name object, with an address of its own
#   files-cl-01                 the file server role's client access point, another address
#   D:                          the shared disk, presented raw to both guests
#   \\<domain>\<namespace>      a DOMAIN-BASED namespace, hosted by files-01 and files-02
#
# **The namespace is not a cluster role, on purpose and by necessity.** A domain-based
# namespace cannot be a clustered resource at all; redundancy comes from having two
# namespace servers. A namespace server is allowed to be a cluster node as long as its
# namespace uses only local resources - so each node keeps its root under its own
# C:\DFSRoots on the system drive, never on the shared disk. The folder targets inside
# it point at `files-cl-01`, the clustered file server, which is the half that fails
# over. Namespace redundant by having two of it; data redundant by clustering. Neither
# mechanism is asked to do the other's job.
#
# **Why a general use file server rather than a Scale-Out File Server.** SOFS has no
# address of its own (a distributed network name registers the node addresses), and it
# is explicitly the wrong shape for information-worker shares - every metadata change
# synchronises across nodes, and dedup, quotas and DFS-R are not available on it. The
# general use role is the one that carries user shares and profile containers, and it is
# the reason this design needs two addresses rather than one.
#
# **Continuous availability is the point of the whole exercise.** A general use file
# server without it drops every SMB handle when the role moves - so draining a node to
# patch it logs off the very session hosts the cluster was built to protect. With it,
# handles survive a planned move. Two things break that silently and both are checked
# rather than assumed: 8.3 short name creation on the volume, and NTFS compression. See
# Test-StudioClusterVolumeReady in Cluster.ps1.
#
# ---------------------------[ Two personas, three passes ]---------------------------
# One config, carried to both nodes; each finds its own job by name.
#
#   Joiner (pass 1)   features and prerequisites only, then it stops and says
#                     "run the builder" - the cluster is formed FROM the builder,
#                     with both nodes named, so there is nothing else for it to do.
#   Builder           validation, the cluster, the witness, the shared disk, the file
#                     server role, the folders, the ACLs, the shares, its own DFS root.
#   Joiner (pass 2)   adds its own root target to the namespace the builder created,
#                     which is what makes the namespace survive losing a node.
#
# The second joiner pass is not an accident of ordering that could be designed away: a
# root target can only be added to a namespace that exists, and the namespace is the
# builder's to create. The run says which pass it is on rather than leaving somebody to
# work it out.

# ---------------------------[ Config readers ]---------------------------
function Get-FsClusterSection {
    param([object]$FileServer)
    return (Get-ConfigValue -InputObject $FileServer -Name "guestCluster")
}

function Test-FsClusterMode {
    param([object]$FileServer)

    if ($null -eq $FileServer) { return $false }
    $mode = [string](Get-ConfigText -InputObject $FileServer -Name "mode" -Default "singleHost")
    if ($mode -ne "guestCluster") { return $false }
    return ($null -ne (Get-FsClusterSection -FileServer $FileServer))
}

function Get-FsClusterNodeName {
    param([Parameter(Mandatory)][object]$Cluster)

    $names = @()
    foreach ($name in @(Get-ConfigArray -InputObject $Cluster -Name "nodes")) {
        $text = ([string]$name).Trim()
        if (-not [string]::IsNullOrWhiteSpace($text)) { $names += $text }
    }
    return ,$names
}

function Get-FsClusterPersona {
    param([Parameter(Mandatory)][object]$Cluster)

    return (Get-StudioClusterPersona -Nodes (Get-FsClusterNodeName -Cluster $Cluster) `
        -BuilderNode ([string](Get-ConfigText -InputObject $Cluster -Name "builderNode" -Default "")))
}

# The other node, short name. Used for the placement check and for nothing else - the
# cluster is created with both names at once, so there is no remote work to do.
function Get-FsClusterPeerName {
    param([Parameter(Mandatory)][object]$Cluster)

    $me = [string]$env:COMPUTERNAME
    foreach ($name in (Get-FsClusterNodeName -Cluster $Cluster)) {
        if ($name.Split(".")[0] -ne $me) { return $name.Split(".")[0] }
    }
    return ""
}

function Get-FsClusterName {
    param([Parameter(Mandatory)][object]$Cluster)

    $name = ([string](Get-ConfigText -InputObject $Cluster -Name "clusterName" -Default "")).Trim()
    if ([string]::IsNullOrWhiteSpace($name)) { $name = "cl-files-01" }
    return $name
}

function Get-FsClusterRoleName {
    param([Parameter(Mandatory)][object]$Cluster)

    $name = ([string](Get-ConfigText -InputObject $Cluster -Name "roleName" -Default "")).Trim()
    if ([string]::IsNullOrWhiteSpace($name)) { $name = "files-cl-01" }
    return $name
}

# The name every path outside this cluster uses: DFS folder targets, the FSLogix
# location, a mapped drive that is not published in a namespace. Never a node's name -
# a node name in a path is a path that breaks the first time the role moves, which is
# the failure this whole mode exists to prevent.
function Get-FsClusterAccessPointFqdn {
    param([Parameter(Mandatory)][object]$Cluster)

    $name = (Get-FsClusterRoleName -Cluster $Cluster).ToLowerInvariant()
    $domain = ([string]$env:USERDNSDOMAIN).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($domain)) { return $name }
    return ("{0}.{1}" -f $name, $domain)
}

# ---------------------------[ Prerequisites ]---------------------------
function Test-FsClusterPrerequisite {
    param(
        [Parameter(Mandatory)][object]$FileServer,
        [Parameter(Mandatory)][object]$Cluster
    )

    $passed = $true

    $persona = Get-FsClusterPersona -Cluster $Cluster
    if ($persona -eq "None") {
        Write-Log "This machine is named in neither node of the guest cluster design" -Tag "Error"
        Write-Log ("    The design names {0}" -f ((Get-FsClusterNodeName -Cluster $Cluster) -join " and ")) -Tag "Error"
        return $false
    }
    Write-Log "This node's job in the design: $persona" -Tag "Info"

    # A guest cluster that is not in a domain cannot host the domain-based namespace
    # this design is built around, and cannot hand out the domain groups its shares are
    # ACL'd to. Refused here rather than half-built.
    if ([string]::IsNullOrWhiteSpace([string]$env:USERDNSDOMAIN)) {
        Write-Log "This node is not in an Active Directory domain - the guest cluster design needs one" -Tag "Error"
        Write-Log "    The namespace is domain-based and every share ACL names a domain group" -Tag "Error"
        $passed = $false
    }

    if (-not (Test-StudioClusterFeature)) { $passed = $false }

    try {
        $feature = Get-WindowsFeature -Name "FS-FileServer" -ErrorAction Stop
        if (($null -eq $feature) -or (-not $feature.Installed)) {
            Write-Log "The File Server role service is not installed" -Tag "Error"
            Write-Log "    Install-WindowsFeature -Name FS-FileServer" -Tag "Error"
            $passed = $false
        }
    }
    catch {
        Write-Log "Could not query the 'FS-FileServer' feature: $($_.Exception.Message)" -Tag "Error"
        $passed = $false
    }

    # Both nodes are namespace servers, so both need the role service - not just the
    # builder. A joiner missing it produces a namespace with one target and no
    # redundancy, which looks exactly like a working one.
    $dfs = Get-ConfigValue -InputObject $FileServer -Name "dfs"
    if ([bool](Get-ConfigValue -InputObject $dfs -Name "enabled" -Default $false)) {
        try {
            $feature = Get-WindowsFeature -Name "FS-DFS-Namespace" -ErrorAction Stop
            if (($null -eq $feature) -or (-not $feature.Installed)) {
                Write-Log "DFS namespaces are designed but the 'FS-DFS-Namespace' role service is not installed on this node" -Tag "Error"
                Write-Log "    Install-WindowsFeature -Name FS-DFS-Namespace - on BOTH nodes, they are both namespace servers" -Tag "Error"
                $passed = $false
            }
        }
        catch {
            Write-Log "Could not query the 'FS-DFS-Namespace' feature: $($_.Exception.Message)" -Tag "Error"
            $passed = $false
        }
        if (-not (Import-FsDfsModule)) { $passed = $false }
    }

    # The share groups, same rule as the single host: created by the domain controller
    # run, never here.
    $groups = Get-StudioGroupDefinition -Entries (Get-ConfigArray -InputObject $FileServer -Name "groups")
    foreach ($group in $groups) {
        $found = $null
        try { $found = Find-AdcsGroup -Name $group.Name } catch { $found = $null }
        if ($null -eq $found) {
            Write-Log "Share group '$($group.Name)' does not exist - run this config on a domain controller first, or create it by hand" -Tag "Error"
            $passed = $false
        }
    }

    # Deliberately NOT checked: whether the drive exists. In this mode the drive is the
    # shared disk, it is mounted on whichever node owns it, and on the other node its
    # absence is correct. The single-host check would fail half of a healthy cluster.
    return $passed
}

# ---------------------------[ The witness secret ]---------------------------
# The console fallback, and only that. The design carries the key when it was exported
# with secrets included, which is what lets a run finish with nobody watching it; this
# asks only when it did not. Nothing is asked for a domain file share witness (the
# cluster's own computer account is the credential) or for a managed-identity cloud
# witness (the Arc identity is). A headless leg gets an empty string and the witness step
# then stops with the command to run by hand rather than hanging on a prompt nobody can
# answer.
function Get-FsClusterWitnessKey {
    param([Parameter(Mandatory)][object]$Witness)

    $type = [string](Get-ConfigText -InputObject $Witness -Name "type" -Default "cloud")
    if ($type -ne "cloud") { return "" }

    $cloud = Get-ConfigValue -InputObject $Witness -Name "cloud"
    if ([bool](Get-ConfigValue -InputObject $cloud -Name "useManagedIdentity" -Default $false)) {
        Write-Log "The cloud witness uses the nodes' Arc managed identities - no access key needed" -Tag "Info"
        return ""
    }

    # Already answered by the design. Asking again when the value is right there is how
    # two consoles end up holding two different keys for the same account.
    $configured = ([string](Get-ConfigText -InputObject $cloud -Name "accessKey" -Default "")).Trim()
    if (-not [string]::IsNullOrWhiteSpace($configured)) { return $configured }

    if ($script:noGui -or $script:isResume -or (-not [Environment]::UserInteractive)) {
        Write-Log "The cloud witness needs an access key and this leg has no console to ask at" -Tag "Warn"
        return ""
    }

    $account = [string](Get-ConfigText -InputObject $cloud -Name "accountName" -Default "")
    Write-Log "The cloud witness needs the storage account's access key and the design carries none" -Tag "Info"
    $answer = Read-Host -Prompt ("  Access key for storage account '{0}'" -f $account)
    if ([string]::IsNullOrWhiteSpace($answer)) {
        Write-Log "No key was typed - the witness step will stop with the command to run by hand" -Tag "Warn"
        return ""
    }
    return $answer.Trim()
}

# ---------------------------[ The file server role ]---------------------------
# The client access point, which is the object every path outside the cluster names.
# Idempotent against an existing group of the same name, because the second run of the
# builder must not mint a second role beside the first.
# One role, every designed volume. Two cluster disks in ONE role group is the only
# correct shape: they fail over together, mount on whichever node owns the role, and the
# single client access point serves shares off both. In separate groups they could land
# on different nodes and no one UNC name would reach both, which is the mode's whole point.
function New-FsClusterFileServerRole {
    param(
        [Parameter(Mandatory)][object]$Cluster,
        [Parameter(Mandatory)][string[]]$Drive
    )

    $roleName = Get-FsClusterRoleName -Cluster $Cluster
    $existing = $null
    try { $existing = Get-ClusterGroup -Name $roleName -ErrorAction SilentlyContinue } catch { $existing = $null }
    if ($null -ne $existing) {
        Write-Log "The file server role '$roleName' already exists - left exactly as it is" -Tag "Info"
        return $true
    }

    # Waited for, not asked once: this runs seconds after Add-ClusterDisk, and a disk
    # resource reports its volume only once it is online.
    $diskNames = @()
    foreach ($letter in $Drive) {
        $disk = Wait-StudioClusterDiskForDrive -Drive $letter
        if ($null -eq $disk) {
            Write-Log "No cluster disk holds $letter - the role has nothing to serve from" -Tag "Error"
            Write-Log "    Get-ClusterResource | Where-Object ResourceType -eq 'Physical Disk'  - and check the disk came out of Available Storage" -Tag "Error"
            return $false
        }
        $diskNames += $disk.Name
    }

    $parameters = @{
        Name        = $roleName
        Storage     = $diskNames
        ErrorAction = "Stop"
    }
    $address = ([string](Get-ConfigText -InputObject $Cluster -Name "roleAddress" -Default "")).Trim()
    if (-not [string]::IsNullOrWhiteSpace($address)) { $parameters["StaticAddress"] = $address }

    Write-Log ("Creating the file server role '{0}' on {1}" -f $roleName, ($diskNames -join ", ")) -Tag "Run"
    try {
        $null = Add-ClusterFileServerRole @parameters
        Write-Log "The role '$roleName' is online" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "The file server role could not be created: $($_.Exception.Message)" -Tag "Error"
        Write-StudioClusterVcoNote -ClusterName (Get-FsClusterName -Cluster $Cluster) -RoleName $roleName `
            -OuPath ([string](Get-ConfigText -InputObject $Cluster -Name "ouPath" -Default ""))
        return $false
    }
}

# Owning the group and having every one of its volumes mounted are two moments, not one.
# Move-StudioClusterGroupHere already waits for the drive it is given; this waits for the
# rest, and it exists as its own function rather than a second parameter on the shared
# helper because that helper is shared with code this change does not touch.
function Wait-FsClusterVolume {
    param(
        [Parameter(Mandatory)][string]$Drive,
        [int]$TimeoutSeconds = 60
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        if (Test-StudioClusterOwnsDrive -Drive $Drive) { return $true }
        if ((Get-Date) -ge $deadline) {
            Write-Log "$Drive is still not mounted on this node after the role came online here" -Tag "Error"
            Write-Log "    Get-ClusterResource | Where-Object ResourceType -eq 'Physical Disk'  - check every disk in the role group is Online" -Tag "Error"
            return $false
        }
        Start-Sleep -Seconds 2
    }
}

# ---------------------------[ The namespace, second target ]---------------------------
# The joiner's whole job on its second pass. The root folder and its share are local to
# this node - that is the condition under which a namespace server may be a cluster node
# at all - and the target is added to a namespace the builder already created.
function Add-FsClusterNamespaceTarget {
    param([Parameter(Mandatory)][object]$Namespace)

    $namespaceName = Get-ConfigText -InputObject $Namespace -Name "name"
    if ([string]::IsNullOrWhiteSpace($namespaceName)) { return $false }

    $type = Get-ConfigText -InputObject $Namespace -Name "type" -Default "domainV2"
    if ($type -eq "standalone") {
        # A stand-alone namespace has exactly one namespace server. Adding a second root
        # target is not a thing that exists, and saying so is better than failing.
        Write-Log "'$namespaceName' is a stand-alone namespace - it has one namespace server by definition, so this node adds nothing" -Tag "Info"
        Write-Log "    Redundancy for a stand-alone namespace means clustering the namespace itself, which this design does not do" -Tag "Debug"
        return $true
    }

    $domain = ([string]$env:USERDNSDOMAIN).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($domain)) {
        Write-Log "This node has no DNS domain - it cannot become a namespace server for '$namespaceName'" -Tag "Error"
        return $false
    }

    $serverFqdn = "{0}.{1}" -f $env:COMPUTERNAME.ToLowerInvariant(), $domain
    $namespacePath = "\\{0}\{1}" -f $domain, $namespaceName
    $rootTarget = "\\{0}\{1}" -f $serverFqdn, $namespaceName

    $root = $null
    try { $root = Get-DfsnRoot -Path $namespacePath -ErrorAction SilentlyContinue } catch { $root = $null }
    if ($null -eq $root) {
        Write-Log "The namespace '$namespacePath' does not exist yet - the builder creates it" -Tag "Warn"
        Write-Log "    Run this config on the builder node first, then here again" -Tag "Warn"
        return $false
    }

    $existing = @()
    try { $existing = @(Get-DfsnRootTarget -Path $namespacePath -ErrorAction SilentlyContinue) } catch { $existing = @() }
    foreach ($target in $existing) {
        if (([string]$target.TargetPath) -eq $rootTarget) {
            Write-Log "This node is already a namespace server for '$namespacePath'" -Tag "Info"
            return $true
        }
    }

    # The root share is this node's own, on its own system drive. Never the shared disk:
    # a namespace root on clustered storage is a namespace that goes away with the disk.
    $rootFolder = Join-Path -Path ($env:SystemDrive + "\DFSRoots") -ChildPath $namespaceName
    if (-not (Test-Path -LiteralPath $rootFolder)) {
        $null = New-Item -ItemType Directory -Path $rootFolder -Force
        Write-Log "Created '$rootFolder'" -Tag "Info"
    }
    if ($null -eq (Get-SmbShare -Name $namespaceName -ErrorAction SilentlyContinue)) {
        $everyone = Get-StudioEveryoneName
        if ([string]::IsNullOrWhiteSpace($everyone)) {
            Write-Log "The Everyone group could not be resolved on this machine, so the namespace share could not be created" -Tag "Error"
            return $false
        }
        # Unscoped on purpose: this share belongs to the node, not to the clustered file
        # server. Scoping it to the role would make the namespace fail over, which is
        # exactly what a domain-based namespace must not do.
        $null = New-SmbShare -Name $namespaceName -Path $rootFolder -ReadAccess $everyone -ErrorAction Stop
        Write-Log "Shared '$rootFolder' as '$namespaceName' (read for $everyone)" -Tag "Ok"
    }

    try {
        $null = New-DfsnRootTarget -Path $namespacePath -TargetPath $rootTarget -ErrorAction Stop
        Write-Log "This node is now the second namespace server for '$namespacePath'" -Tag "Ok"
        Write-Log "    Losing either node now costs referrals from that node only - the namespace itself stays up" -Tag "Debug"
        return $true
    }
    catch {
        Write-Log "Could not add this node as a namespace server: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

# ---------------------------[ Entry point ]---------------------------
function Invoke-FsClusterConfiguration {
    param(
        [Parameter(Mandatory)][object]$FileServer,
        [Parameter(Mandatory)][object]$Cluster
    )

    $persona = Get-FsClusterPersona -Cluster $Cluster
    $clusterName = Get-FsClusterName -Cluster $Cluster
    $roleName = Get-FsClusterRoleName -Cluster $Cluster
    $nodes = Get-FsClusterNodeName -Cluster $Cluster
    # The same root model the single host uses, with the cluster section as the legacy
    # source for a design written before the roots carried their own label and units.
    $roots = Get-FsRootDefinition -FileServer $FileServer -Legacy $Cluster
    $dfs = Get-ConfigValue -InputObject $FileServer -Name "dfs"
    $dfsOn = [bool](Get-ConfigValue -InputObject $dfs -Name "enabled" -Default $false)

    $here = Get-StudioClusterHere

    # ---- The joiner ----
    if ($persona -eq "Joiner") {
        if ($null -eq $here) {
            Write-Log "This node is prepared and is not in a cluster yet" -Tag "Info"
            Write-Log "    The cluster is formed FROM the builder with both nodes named - run this config on '$(Get-FsClusterPeerName -Cluster $Cluster)' next" -Tag "Info"
            return (New-RoleResult -Status "ManualStepRequired" -Message "Prepared - now run this config on the builder node to form the cluster")
        }

        Write-Log "This node is in the cluster '$($here.Name)'" -Tag "Ok"
        if (-not $dfsOn) {
            return (New-RoleResult -Status "Completed" -Message "Node ready - the shares and their storage belong to the role, which the builder owns")
        }

        $allTargets = $true
        foreach ($namespace in @(Get-ConfigArray -InputObject $dfs -Name "namespaces")) {
            if (-not (Add-FsClusterNamespaceTarget -Namespace $namespace)) { $allTargets = $false }
        }
        if (-not $allTargets) {
            return (New-RoleResult -Status "ManualStepRequired" -Message "This node is not a namespace server for every namespace yet - run the builder first, then this node again")
        }
        return (New-RoleResult -Status "Completed" -Message "Node in the cluster and serving every namespace as its second root target")
    }

    # ---- The builder ----
    if ($null -eq $here) {
        # Before anything remote is attempted. Without this the first failure is
        # New-Cluster reporting a network name resource problem, which names neither the
        # identity nor the fix.
        if (-not (Test-StudioClusterIdentity -Action "form the cluster")) {
            return (New-RoleResult -Status "ManualStepRequired" -Message "The cluster is formed from a signed-in session - the line above has the command. Nothing else is outstanding on this node.")
        }

        Write-StudioClusterPlacementNote -PeerName (Get-FsClusterPeerName -Cluster $Cluster)

        if ([bool](Get-ConfigValue -InputObject $Cluster -Name "validate" -Default $true)) {
            if (-not (Test-StudioClusterValidation -Nodes $nodes)) {
                return (New-RoleResult -Status "Failed" -Message "Cluster validation failed - read the report before building anything on this storage")
            }
        }

        Write-StudioClusterVcoNote -ClusterName $clusterName -RoleName $roleName `
            -OuPath ([string](Get-ConfigText -InputObject $Cluster -Name "ouPath" -Default ""))

        if (-not (New-StudioCluster -Name $clusterName -Nodes $nodes `
                -StaticAddress ([string](Get-ConfigText -InputObject $Cluster -Name "clusterAddress" -Default "")) `
                -OuPath ([string](Get-ConfigText -InputObject $Cluster -Name "ouPath" -Default "")) -NoStorage $true)) {
            return (New-RoleResult -Status "Failed" -Message "The cluster could not be created - see the log")
        }
        $here = Get-StudioClusterHere
    }
    else {
        Write-Log "This node is already in the cluster '$($here.Name)'" -Tag "Info"
    }

    $failures = @()

    # The witness, immediately after the cluster exists. A two-node cluster without one
    # stops the moment either node is lost, and it is the step people postpone.
    $witness = Get-ConfigValue -InputObject $Cluster -Name "witness"
    if ($null -ne $witness) {
        $key = Get-FsClusterWitnessKey -Witness $witness
        if (-not (Set-StudioClusterWitness -Witness $witness -ClusterName $clusterName -AccessKey $key)) {
            $failures += "witness"
        }
    }
    else {
        Write-Log "No witness is designed - two nodes without one lose quorum the moment either is lost" -Tag "Warn"
    }

    # The shared disk. Raw and attached is the state this design starts from; every
    # step from there is this run's, because the formatting carries the two properties
    # transparent failover depends on.
    # Before anything is formatted, because the letter is the one property of this disk
    # that has to be true on BOTH nodes and this run only ever sees one of them.
    $peerName = Get-FsClusterPeerName -Cluster $Cluster
    foreach ($root in $roots) {
        if (-not (Test-StudioClusterDriveFreeOnPeer -Drive $root.Drive -PeerName $peerName)) { $failures += "shared disk" }
    }

    if ($failures -notcontains "shared disk") {
        $alreadyHere = @($roots | Where-Object { Test-StudioClusterOwnsDrive -Drive $_.Drive })
        $toBuild = @($roots | Where-Object { -not (Test-StudioClusterOwnsDrive -Drive $_.Drive) })

        foreach ($root in $alreadyHere) {
            Write-Log "$($root.Drive) is already mounted on this node - its layout is left exactly as it is" -Tag "Info"
            if (-not (Test-StudioClusterVolumeReady -Drive $root.Drive)) { $failures += "shared disk" }
        }

        if ($toBuild.Count -gt 0) {
            $candidates = @(Get-StudioClusterSharedDiskCandidate |
                    Where-Object { $_.PartitionStyle -eq "RAW" } | Sort-Object -Property Size -Descending)
            if ($candidates.Count -lt $toBuild.Count) {
                Write-Log ("{0} raw unclaimed disk(s) visible and this design needs {1} - they have to be presented to both guests first" -f $candidates.Count, $toBuild.Count) -Tag "Error"
                Write-Log "    On Hyper-V that is a VHD Set (.vhds) on a SCSI controller in both VMs, or a LUN masked to both" -Tag "Error"
                Write-Log "    One disk per volume: the data shares and the profile containers are separate volumes by design" -Tag "Error"
                $failures += "shared disk"
            }
            else {
                # Asked at the console when there is genuinely something to decide, taken
                # in size order when there is not - and either way the mapping is PRINTED
                # before a single disk is touched. Getting them the wrong way round is
                # something to notice while it is still a formatting decision, not after
                # the shares are built on top.
                $assignments = Select-FsDiskForRoot -Roots $toBuild -Candidate $candidates
                if ($null -eq $assignments) {
                    Write-Log "No disk was assigned to a volume - nothing was formatted" -Tag "Error"
                    $failures += "shared disk"
                }
                else {
                    foreach ($line in $script:fsDiskChoice) { Write-Log $line -Tag "Info" }
                    foreach ($pair in $assignments) {
                        if (-not (Initialize-StudioClusterSharedDisk -Disk $pair.Disk -Drive $pair.Root.Drive `
                                    -Label $pair.Root.Label -AllocationUnitSize $pair.Root.AllocationUnitSize `
                                    -LargeFileRecordSegments $pair.Root.LargeFileRecordSegments)) {
                            $failures += "shared disk"
                        }
                    }
                }
            }
        }
    }

    if ($failures -contains "shared disk") {
        return (New-RoleResult -Status "Failed" -Message "The shared disk is not in a state a continuously available share can live on - see the log")
    }

    $null = Add-StudioClusterSharedDisk
    if (-not (New-FsClusterFileServerRole -Cluster $Cluster -Drive @($roots | ForEach-Object { $_.Drive }))) {
        return (New-RoleResult -Status "Failed" -Message "The file server role could not be created - see the log")
    }

    # ---- Everything below is the single-host job, aimed at the cluster ----
    # And it can only be done where the volume is. Creating the role moved the disk into
    # its group, and the cluster chose which node to bring that group online on.
    if (-not (Move-StudioClusterGroupHere -Name $roleName -Drive $roots[0].Drive)) {
        return (New-RoleResult -Status "ManualStepRequired" -Message "The role is built, but its volume is not mounted on this node - the shares were not created. The lines above name the move to make.")
    }
    # The move brings the whole group, but the volumes come online one at a time and the
    # wait above only watched the first. A second volume that is not mounted yet fails as
    # 'a drive with the name E does not exist' from whichever cmdlet touches it first.
    foreach ($root in $roots) {
        if ($root.Drive -eq $roots[0].Drive) { continue }
        if (-not (Wait-FsClusterVolume -Drive $root.Drive)) {
            return (New-RoleResult -Status "ManualStepRequired" -Message ("The role owns {0} but it is not mounted on this node - the shares were not created." -f $root.Drive))
        }
    }

    foreach ($root in $roots) {
        # -Prepare $false, always. The cluster builds its own volumes out of the shared
        # disks it claimed, with the spec already applied by Initialize-StudioClusterSharedDisk;
        # letting this call prepare as well would have it hunt for a LOCAL uninitialised
        # disk on whichever node is running, which is never the right disk here.
        $null = Confirm-FsVolume -Root $root -Prepare $false
        if (-not (New-FsRootFolder -Root $root)) {
            return (New-RoleResult -Status "Failed" -Message "The share root could not be created - see the log")
        }
    }

    $enumeration = [bool](Get-ConfigValue -InputObject $FileServer -Name "accessBasedEnumeration" -Default $true)
    $continuous = [bool](Get-ConfigValue -InputObject $Cluster -Name "continuousAvailability" -Default $true)
    $shares = Get-FsShare -FileServer $FileServer

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
            try {
                $null = New-Item -ItemType Directory -Path $sharePath -Force -ErrorAction Stop
                Write-Log "Created '$sharePath'" -Tag "Info"
            }
            catch {
                Write-Log "'$sharePath' could not be created: $($_.Exception.Message)" -Tag "Error"
                $failures += $share.Name
                continue
            }
        }
        if ([string]::IsNullOrWhiteSpace($share.Group)) {
            Write-Log "The share '$($share.Name)' names no group - folder created, ACL and share skipped" -Tag "Error"
            $failures += $share.Name
            continue
        }
        # The ACL model is unchanged from the single host, and that is a finding rather
        # than an omission: a clustered share's NTFS descriptor travels with the volume
        # and its share permissions live in the cluster registry, so every principal in
        # it has to mean the same thing on both nodes. Domain groups and well-known SIDs
        # do; a machine-local group does not - BUILTIN\Administrators is the same
        # S-1-5-32-544 everywhere and resolves against whichever node owns the role,
        # which is exactly the intent.
        if (-not (Set-FsFolderSecurity -Path $sharePath -GroupName $share.Group -AccessModel $share.AccessModel)) {
            $failures += $share.Name
            continue
        }

        $shareEnumeration = $enumeration
        if ($null -ne $share.Abe) { $shareEnumeration = [bool]$share.Abe }
        try {
            if (-not (Set-FsSmbShare -Share $share -Path $sharePath -AccessBasedEnumeration $shareEnumeration `
                    -ScopeName $roleName -ContinuouslyAvailable $continuous)) {
                $failures += $share.Name
            }
        }
        catch {
            Write-Log "Could not publish '$($share.Name)': $($_.Exception.Message)" -Tag "Error"
            $failures += $share.Name
        }
    }

    Write-FsClusterProfileNote -Cluster $Cluster -Shares $shares -ContinuouslyAvailable $continuous `
        -Roots $roots -DefenderExclusions ([bool](Get-ConfigValue -InputObject $FileServer -Name "defenderExclusions" -Default $true))

    # Shadow copies live on the volume they protect, so they are the owning node's job
    # and the owning node is this one - the role was just brought online here. On the
    # other node the same config does nothing, which is correct rather than incomplete.
    if (-not (Set-FsShadowCopyPerRoot -FileServer $FileServer -Roots $roots)) { $failures += "shadow copies" }
    if ([bool](Get-ConfigValue -InputObject (Get-ConfigValue -InputObject $FileServer -Name "shadowCopies") -Name "enabled" -Default $false)) {
        Write-Log "Shadow copies are configured on the node that owns the volumes - after a failover, run this config on the other node too" -Tag "Info"
    }

    if ($dfsOn) {
        $shareHost = Get-FsClusterAccessPointFqdn -Cluster $Cluster
        foreach ($namespace in @(Get-ConfigArray -InputObject $dfs -Name "namespaces")) {
            $namespaceName = Get-ConfigText -InputObject $namespace -Name "name" -Default "namespace"
            try {
                # The root target is THIS node; the folder targets are the clustered
                # role. Two different names in one namespace, and the difference is the
                # whole design.
                if (-not (Set-FsDfsNamespace -Namespace $namespace -Shares $shares -ShareHostFqdn $shareHost)) {
                    $failures += ("namespace " + $namespaceName)
                }
            }
            catch {
                Write-Log "The namespace '$namespaceName' failed: $($_.Exception.Message)" -Tag "Error"
                $failures += ("namespace " + $namespaceName)
            }
        }
        Write-Log "Run this config on '$(Get-FsClusterPeerName -Cluster $Cluster)' once more - that pass makes it the second namespace server" -Tag "Info"
    }

    if ($failures.Count -gt 0) {
        return (New-RoleResult -Status "ManualStepRequired" -Message ("Finished with problems on: {0} - see the log" -f (($failures | Select-Object -Unique) -join ", ")))
    }
    return (New-RoleResult -Status "Completed" -Message ("The cluster '{0}' serves '{1}' - run the config on the other node again for the second namespace target" -f $clusterName, $roleName))
}

# What a profile container share needs that this run does not write. The path is the
# clustered name, never a node's - a container opened through a node name is a container
# that dies with that node, which is the outage the cluster was built to remove.
function Write-FsClusterProfileNote {
    param(
        [Parameter(Mandatory)][object]$Cluster,
        [Parameter(Mandatory)][object[]]$Shares,
        [bool]$ContinuouslyAvailable = $true,
        # The roots, so the container path an exclusion needs is the one the share was
        # actually built at rather than a second guess at it.
        [object[]]$Roots = @(),
        [bool]$DefenderExclusions = $true
    )

    $shareHost = Get-FsClusterAccessPointFqdn -Cluster $Cluster
    foreach ($share in $Shares) {
        if ($share.AccessModel -ne "fslogixContainer") { continue }
        $uncPath = "\\{0}\{1}" -f $shareHost, (Get-FsSmbName -Share $share)

        Write-Log "'$($share.Name)' holds FSLogix profile containers on the clustered file server" -Tag "Info"
        Write-Log "    VHDLocations = $uncPath" -Tag "Info"
        Write-Log "    Set it once, in Group Policy, for every session host - HKLM\SOFTWARE\FSLogix\Profiles" -Tag "Info"
        Write-Log "    Never put this share in a DFS *replication* group - a namespace is fine, replicating an open container is not" -Tag "Warn"

        # Set on THIS node, which is the one that owns the volume right now. The other
        # node needs the same list and cannot get it from here - Defender preferences are
        # per machine, not a cluster resource - so the second pass of this config on the
        # peer sets its own, and the line below says so rather than leaving it implied.
        if ($DefenderExclusions -and $Roots.Count -gt 0) {
            $shareRoot = Get-FsRootForShare -Roots $Roots -Share $share
            $null = Set-FsDefenderExclusion -Path (Get-FsDefenderExclusionPath -SharePath (Get-FsSharePath -Root $shareRoot -Share $share))
            Write-Log "    Defender exclusions are per machine, not a cluster resource - run this config on the other node for its own" -Tag "Info"
        }
        elseif (-not $DefenderExclusions) {
            Write-Log "    Antivirus exclusions are switched off in the design - add the container patterns by hand, both nodes" -Tag "Warn"
        }
        Write-Log "    On every session host as well: the container patterns, plus frxdrv.sys, frxdrvvt.sys, frxccd.sys and the FSLogix binaries" -Tag "Info"

        if ($ContinuouslyAvailable) {
            # The SMB half of surviving a node move is done. The client half is not, and
            # it is a policy on the session hosts rather than anything this server owns:
            # containers have been seen to drop when a clustered role migrates, and the
            # retry settings are what turns that into a pause instead of a lost session.
            Write-Log "    The share is continuously available, so a planned move keeps the handles open" -Tag "Info"
            Write-Log "    Set the retry pair on every session host anyway - a migration is still a stall, and without them a dropped container:" -Tag "Info"
            Write-Log "        ReAttachIntervalSeconds = 15   ReAttachRetryCount = 3   (HKLM\SOFTWARE\FSLogix\Profiles)" -Tag "Info"
        }
        else {
            Write-Log "    This share is NOT continuously available - every profile handle breaks when the role moves, which is the outage this cluster prevents" -Tag "Warn"
        }
    }
}
