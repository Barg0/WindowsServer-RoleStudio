#Requires -Version 5.1
# ---------------------------[ Hyper-V: the two-node S2D cluster ]---------------------------
# The other deployment the Hyper-V blade designs, and a completely separate mode from the
# single host: `hyperV.mode = "s2dCluster"` routes here and nothing below is shared with
# the single-node path in Role.Hyperv.Cluster.ps1. That separation is deliberate and
# load-bearing - the single-node path is field-tested and shipping, and this mode must
# never alter it. What this file does share is the toolbox's primitives: the menus, the
# disk classifiers, the switch builder, the volume arithmetic, the restart machinery.
#
# One config, three personas, decided by computer name:
#
#   member    a node in `nodes` that is not the builder. Prepared only: features, its own
#             networking answers, its own disks emptied, then the restart. It never forms
#             anything.
#   builder   the node named by `builderNode` (the first node when unset). Prepared the
#             same way, and after ITS restart it forms the cluster across both nodes,
#             configures the witness, switches Storage Spaces Direct on and carves the
#             volumes.
#   witness   the machine named by `witness.fileShare.host` when the witness is a file
#             share on a Windows box this toolbox also runs on. It builds the share and
#             grants the cluster account - nothing else, no Hyper-V, no restart.
#
# The documented run order is therefore: every member first, the builder last, and - for a
# domain file-share witness - the witness host after the cluster exists, because the ACL
# names the cluster's computer account and that account is created by New-Cluster. The
# builder says exactly this when it finds the share not ready, and finishes the witness on
# its next run. A workgroup share witness and a cloud witness have no such ordering.
#
# Two cluster kinds, decided by the domain-join card rather than a switch of its own:
#
#   domain     `domainJoin.enabled` on. The cluster name becomes a computer object, the
#              file-share witness ACLs name `<cluster>$`, and the account running the
#              builder needs Create Computer Objects where the name object lands.
#   workgroup  `domainJoin.enabled` off. Windows Server 2025 supports Hyper-V and S2D on a
#              workgroup cluster - the prerequisites are an identical local administrator
#              account on every node, LocalAccountTokenFilterPolicy, the peers in each
#              other's WinRM TrustedHosts and one shared primary DNS suffix, and this run
#              sets what it can of that. The witness is then the cloud, or a share
#              reached with an explicit local credential - there is no computer account
#              to authenticate as.
#
# Storage is Storage Spaces Direct only - two nodes are exactly what S2D is for, and the
# resiliency question gains the two-node-only answers:
#
#   twoWayMirror   one copy per node. 50% efficiency, survives ONE failure - a node OR a
#                  drive. While a node is down for patching, a single drive failure on
#                  the survivor takes the volume with it.
#   nestedMirror   four copies, two per node on different drives. 25% efficiency, and it
#                  survives a node and a drive at the same time - which is why it is the
#                  default whenever the disks allow it. Needs four capacity drives per
#                  node.
#   nestedParity   nested mirror-accelerated parity: a small four-copy mirror tier in
#                  front of per-node single parity mirrored across the nodes. Roughly
#                  35-40% efficiency, needs four drives per node and wants flash - parity
#                  on spinning disks in a two-node cluster is slow by construction.
#
# Networking is Network ATC by default - it is in plain Windows Server 2025 now - with a
# manual lane behind `networking.mode = "manual"`. ATC turns two Add-NetIntent calls into
# the SET switch, the storage VLANs and addresses, DCB and RDMA, and remediates drift; the
# price is symmetric adapters carrying the same names on both nodes, which is why the
# interview renames them before anything is built. On a virtual host the run injects the
# NetworkDirect override itself - a guest NIC has no RDMA to negotiate, and without the
# override the storage intent sits in a failed state forever. RDMA in the manual lane
# (iWARP, RoCEv2) is written from Microsoft's documented sequence and is marked as
# bench-untested in the studio: the lab is nested virtual machines, which expose none of it.

# ---------------------------[ Config ]---------------------------
function Get-HypervS2dSection {
    param([Parameter(Mandatory)][object]$Hyperv)
    return (Get-ConfigValue -InputObject $Hyperv -Name "s2dCluster")
}

# Whether the design is the two-node mode at all. The mode string is the router: the
# single host and this cluster are different builds, not two views of one.
function Test-HypervS2dMode {
    param([object]$Hyperv)

    if ($null -eq $Hyperv) { return $false }
    if ([string](Get-ConfigText -InputObject $Hyperv -Name "mode" -Default "singleHost") -ne "s2dCluster") { return $false }
    return ($null -ne (Get-HypervS2dSection -Hyperv $Hyperv))
}

function Get-HypervS2dNodeName {
    param([Parameter(Mandatory)][object]$S2d)

    $names = @()
    foreach ($name in @(Get-ConfigArray -InputObject $S2d -Name "nodes")) {
        $value = ([string]$name).Trim()
        if (-not [string]::IsNullOrWhiteSpace($value)) { $names += $value }
    }
    return @($names)
}

function Get-HypervS2dBuilderName {
    param([Parameter(Mandatory)][object]$S2d)

    $builder = ([string](Get-ConfigText -InputObject $S2d -Name "builderNode" -Default "")).Trim()
    if (-not [string]::IsNullOrWhiteSpace($builder)) { return $builder }
    $names = @(Get-HypervS2dNodeName -S2d $S2d)
    if ($names.Count -gt 0) { return $names[0] }
    return ""
}

# Which of the three jobs this machine has, by name. "none" means the design does not
# mention this machine and the role is skipped here entirely.
# The NetBIOS half of whatever was written down - 'vm-hv-01' out of 'vm-hv-01.lab.invalid'
# and out of 'vm-hv-01' alike. The one form a machine can compare itself against.
function Get-HypervS2dHostLabel {
    param([string]$Name)

    $value = ([string]$Name).Trim()
    if ([string]::IsNullOrWhiteSpace($value)) { return "" }
    return $value.Split(".")[0]
}

function Get-HypervS2dPersona {
    param([Parameter(Mandatory)][object]$S2d)

    # Matched on the leading label, never on the whole string. A machine knows itself by
    # its NetBIOS name and nothing else, so a design that spells a node or the witness
    # host as an FQDN - which is a reasonable thing to type, and now the form this file
    # hands to every remote call - would otherwise leave that machine unable to recognise
    # itself, take the "none" branch, and skip its own work without an error anywhere.
    $me = Get-HypervS2dHostLabel -Name $env:COMPUTERNAME
    foreach ($name in @(Get-HypervS2dNodeName -S2d $S2d)) {
        if ((Get-HypervS2dHostLabel -Name $name).Equals($me, [System.StringComparison]::OrdinalIgnoreCase)) {
            $builder = Get-HypervS2dHostLabel -Name (Get-HypervS2dBuilderName -S2d $S2d)
            if ((Get-HypervS2dHostLabel -Name $name).Equals($builder, [System.StringComparison]::OrdinalIgnoreCase)) { return "builder" }
            return "member"
        }
    }

    $witness = Get-ConfigValue -InputObject $S2d -Name "witness"
    if ($null -ne $witness) {
        $fileShare = Get-ConfigValue -InputObject $witness -Name "fileShare"
        if ($null -ne $fileShare) {
            $host2 = Get-HypervS2dHostLabel -Name ([string](Get-ConfigText -InputObject $fileShare -Name "host" -Default ""))
            if ((-not [string]::IsNullOrWhiteSpace($host2)) -and $host2.Equals($me, [System.StringComparison]::OrdinalIgnoreCase)) {
                if ([string](Get-ConfigText -InputObject $witness -Name "type" -Default "cloud") -eq "fileShare") { return "witness" }
            }
        }
    }
    return "none"
}

function Test-HypervS2dAppliesHere {
    param([Parameter(Mandatory)][object]$Config)

    $hyperv = Get-HypervSection -Config $Config
    if (-not (Test-HypervS2dMode -Hyperv $hyperv)) { return $true }

    $s2d = Get-HypervS2dSection -Hyperv $hyperv
    $persona = Get-HypervS2dPersona -S2d $s2d
    if ($persona -eq "none") {
        Write-Log ("The S2D cluster design names {0} and this is {1} - skipping" -f
            ((@(Get-HypervS2dNodeName -S2d $s2d)) -join ", "), $env:COMPUTERNAME) -Tag "Info"
        return $false
    }
    Write-Log ("Persona: {0}" -f $persona) -Tag "Info"
    return $true
}

# The kind of cluster follows the domain-join card - there is deliberately no second
# switch to contradict it. Joined (or joining) means a domain cluster.
function Test-HypervS2dDomainKind {
    param([Parameter(Mandatory)][object]$Hyperv)

    if (Test-HypervClusterDomainJoined) { return $true }
    return (Test-HypervDomainJoinWanted -Hyperv $Hyperv)
}

function Get-HypervS2dClusterName {
    param([Parameter(Mandatory)][object]$S2d)

    $cluster = Get-ConfigValue -InputObject $S2d -Name "cluster"
    $name = [string](Get-ConfigText -InputObject $cluster -Name "name" -Default "hvc-01")
    if ([string]::IsNullOrWhiteSpace($name)) { $name = "hvc-01" }
    return $name.Trim()
}

function Get-HypervS2dPeerName {
    param([Parameter(Mandatory)][object]$S2d)

    # Same label rule as the persona: a design that spells its nodes as FQDNs must not
    # leave this node listing itself as its own peer.
    $me = Get-HypervS2dHostLabel -Name $env:COMPUTERNAME
    $peers = @()
    foreach ($name in @(Get-HypervS2dNodeName -S2d $S2d)) {
        if (-not (Get-HypervS2dHostLabel -Name $name).Equals($me, [System.StringComparison]::OrdinalIgnoreCase)) { $peers += $name }
    }
    return @($peers)
}

# The design names its nodes the way `$env:COMPUTERNAME` reports them - short - because
# that is what somebody can check on the machine in front of them. What the cluster
# cmdlets and every remote call want is a name DNS can answer, and on a WORKGROUP cluster
# DNS is the only naming authority there is: there is no directory, the cluster is created
# with -AdministrativeAccessPoint Dns, and a short name then rests on NetBIOS, LLMNR or a
# suffix search list - three things that answer inconsistently and none of which the
# design controls. So the suffix the design already carries is put back on.
#
# It is the suffix this run WROTE, not an invention: on a workgroup design it is
# `cluster.dnsSuffix` (Set-HypervS2dWorkgroupPrerequisite makes it the primary DNS suffix
# of every node before the restart), on a domain design it is the domain being joined.
function Get-HypervS2dNodeSuffix {
    param(
        [Parameter(Mandatory)][object]$S2d,
        [Parameter(Mandatory)][object]$Hyperv
    )

    if (Test-HypervS2dDomainKind -Hyperv $Hyperv) {
        $join = Get-ConfigValue -InputObject $Hyperv -Name "domainJoin"
        $domain = ([string](Get-ConfigText -InputObject $join -Name "domain" -Default "")).Trim()
        if (-not [string]::IsNullOrWhiteSpace($domain)) { return $domain }
    }
    else {
        $cluster = Get-ConfigValue -InputObject $S2d -Name "cluster"
        $suffix = ([string](Get-ConfigText -InputObject $cluster -Name "dnsSuffix" -Default "")).Trim()
        if (-not [string]::IsNullOrWhiteSpace($suffix)) { return $suffix }
    }
    # Whatever this node actually carries, which is what the design set on it last time.
    return ([string](Get-HypervPrimaryDnsSuffix)).Trim()
}

# One node name in the form to hand a cmdlet: the fully qualified one when DNS answers
# for it, the name as written when it does not. Proven rather than assumed - a design
# whose nodes never registered in DNS is a real state, and handing New-Cluster a name
# nothing resolves would trade a working short name for a broken long one.
function Resolve-HypervS2dNodeAddress {
    param(
        [Parameter(Mandatory)][string]$NodeName,
        [string]$Suffix = ""
    )

    $name = $NodeName.Trim()
    if ($name.Contains(".")) { return $name }
    if ([string]::IsNullOrWhiteSpace($Suffix)) { return $name }

    $fqdn = "{0}.{1}" -f $name, $Suffix.Trim().TrimStart(".")
    try {
        $addresses = @([System.Net.Dns]::GetHostAddresses($fqdn))
        if ($addresses.Count -gt 0) { return $fqdn }
    }
    catch {
        Write-Log "'$fqdn' does not resolve - '$name' used as written: $($_.Exception.Message)" -Tag "Debug"
    }
    return $name
}

# Every node, in that form, logged once so a run says which names it is about to use
# rather than leaving somebody to infer it from a failure.
function Get-HypervS2dNodeAddress {
    param(
        [Parameter(Mandatory)][object]$S2d,
        [Parameter(Mandatory)][object]$Hyperv
    )

    $suffix = Get-HypervS2dNodeSuffix -S2d $S2d -Hyperv $Hyperv
    $addresses = @()
    $short = @()
    foreach ($name in @(Get-HypervS2dNodeName -S2d $S2d)) {
        $resolved = Resolve-HypervS2dNodeAddress -NodeName $name -Suffix $suffix
        $addresses += $resolved
        if (-not $resolved.Contains(".")) { $short += $resolved }
    }
    if ($short.Count -gt 0) {
    Write-Log ("Node name(s) not qualified, used as written: {0}" -f ($short -join ", ")) -Tag "Warn"
        if ([string]::IsNullOrWhiteSpace($suffix)) {
            Write-Log "    No DNS suffix in the design - a workgroup cluster needs the cluster card's 'Primary DNS suffix'" -Tag "Warn"
        }
        else {
            Write-Log ("    '<node>.{0}' does not resolve here - resolution falls back to NetBIOS or LLMNR" -f $suffix) -Tag "Warn"
        }
    }
    return @($addresses)
}

# ---------------------------[ The plan file ]---------------------------
# Each node keeps its own answers beside the script, exactly like the single host does -
# but under a different name, because the two modes must never read each other's file.
# The builder's copy may briefly hold a witness secret collected at the console (a cloud
# access key, a share credential); it is deleted the moment the run completes, and the
# log says so when one is written.
function Get-HypervS2dPlanPath {
    return (Join-Path -Path $scriptRootPath -ChildPath "hyperv-s2d-plan.json")
}

function Read-HypervS2dPlan {
    $path = Get-HypervS2dPlanPath
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try {
        return (Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json)
    }
    catch {
        Write-Log "'$path' unreadable - no interview answers this run: $($_.Exception.Message)" -Tag "Warn"
        return $null
    }
}

function Write-HypervS2dPlan {
    param([Parameter(Mandatory)][object]$Plan)

    $path = Get-HypervS2dPlanPath
    try {
        $Plan | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8 -ErrorAction Stop
        Write-Log "Answers written to '$path' - the run after the restart asks nothing" -Tag "Ok"
        if ((-not [string]::IsNullOrWhiteSpace([string]$Plan.witnessKey)) -or (-not [string]::IsNullOrWhiteSpace([string]$Plan.witnessPassword))) {
            Write-Log "    It briefly holds the witness secret typed at the console - removed when the run completes" -Tag "Debug"
        }
        return $true
    }
    catch {
        Write-Log "Plan not written to '$path': $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

function Remove-HypervS2dPlan {
    $path = Get-HypervS2dPlanPath
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        Write-Log "Plan file removed" -Tag "Debug"
    }
}

# ---------------------------[ Features ]---------------------------
# The cluster features beside the Hyper-V role itself, in one call so they ride the one
# restart. Data Center Bridging and the SMB bandwidth limit are only pulled in by the
# lanes that read them - DCB by RoCE and by ATC, FS-SMBBW by ATC, whose prerequisite
# list names both.
function Install-HypervS2dFeature {
    param([Parameter(Mandatory)][object]$S2d)

    $networking = Get-ConfigValue -InputObject $S2d -Name "networking"
    $mode = [string](Get-ConfigText -InputObject $networking -Name "mode" -Default "atc")
    $rdma = [string](Get-ConfigText -InputObject $networking -Name "rdma" -Default "disabled")

    $wanted = @("Failover-Clustering")
    if ($mode -eq "atc") { $wanted += @("NetworkATC", "FS-SMBBW", "Data-Center-Bridging") }
    elseif ($rdma -eq "roce") { $wanted += "Data-Center-Bridging" }

    $missing = @()
    foreach ($name in $wanted) {
        $feature = $null
        try { $feature = Get-WindowsFeature -Name $name -ErrorAction Stop } catch { $feature = $null }
        if ($null -eq $feature) {
            Write-Log "'$name' is not a feature this Windows offers - Network ATC needs Windows Server 2025" -Tag "Error"
            return $false
        }
        if ($feature.InstallState -ne "Installed") { $missing += $name }
    }
    if ($missing.Count -eq 0) {
        Write-Log "Cluster features already installed" -Tag "Info"
        return $true
    }
    if (-not [bool](Get-ConfigValue -InputObject $S2d -Name "installFeatures" -Default $true)) {
        Write-Log "Missing features, and this design does not install them:" -Tag "Error"
        Write-Log ("    Install-WindowsFeature -Name {0} -IncludeManagementTools" -f ($missing -join ", ")) -Tag "Error"
        return $false
    }

    Write-Log ("Installing {0}" -f ($missing -join ", ")) -Tag "Run"
    try {
        $result = Install-WindowsFeature -Name $missing -IncludeManagementTools -ErrorAction Stop
        if (($null -ne $result) -and (-not $result.Success)) {
            Write-Log "Install-WindowsFeature failed: exit $($result.ExitCode)" -Tag "Error"
            return $false
        }
    }
    catch {
        Write-Log "Cluster features not installed: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
    Write-Log "Cluster features installed" -Tag "Ok"
    return $true
}

# ---------------------------[ Workgroup prerequisites ]---------------------------
# Microsoft's list for an AD-less cluster, applied where a registry value or a WinRM
# setting is the answer and said out loud where an identical local account is - this run
# does not create administrator accounts behind anybody's back.
function Set-HypervS2dWorkgroupPrerequisite {
    param(
        [Parameter(Mandatory)][object]$S2d,
        [Parameter(Mandatory)][object]$Hyperv
    )

    if (Test-HypervS2dDomainKind -Hyperv $Hyperv) { return $true }

    Write-Log "Workgroup cluster - applying node prerequisites" -Tag "Info"

    # Remote administration with a named local account needs the full token, which UAC
    # strips from remote logons unless this value says otherwise. The builtin
    # Administrator is exempt, but assuming that account is how a prerequisite hides.
    try {
        $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $current = -1
        try { $current = [int](Get-ItemProperty -LiteralPath $path -Name "LocalAccountTokenFilterPolicy" -ErrorAction Stop).LocalAccountTokenFilterPolicy } catch { $current = -1 }
        if ($current -ne 1) {
            $null = New-ItemProperty -Path $path -Name "LocalAccountTokenFilterPolicy" -Value 1 -PropertyType DWord -Force -ErrorAction Stop
            Write-Log "LocalAccountTokenFilterPolicy set" -Tag "Ok"
        }
    }
    catch {
        Write-Log "LocalAccountTokenFilterPolicy not set: $($_.Exception.Message)" -Tag "Warn"
    }

    # Every node trusts its peers by name. Merged rather than overwritten - a value
    # somebody already put there is somebody's decision.
    #
    # BOTH forms, and that is not belt and braces: TrustedHosts is matched against the
    # string the caller typed, not against the machine it resolves to, so a list holding
    # only 'vm-hv-02' refuses a connection to 'vm-hv-02.lab.invalid' outright. The cluster
    # cmdlets are handed the qualified form wherever DNS answers for it, so a run that
    # trusted only short names would have set up its own refusal.
    $suffix = ([string](Get-ConfigText -InputObject (Get-ConfigValue -InputObject $S2d -Name "cluster") -Name "dnsSuffix" -Default "")).Trim()
    $peers = @()
    foreach ($peer in @(Get-HypervS2dPeerName -S2d $S2d)) {
        $peers += $peer
        if (-not [string]::IsNullOrWhiteSpace($suffix) -and -not $peer.Contains(".")) {
            $peers += ("{0}.{1}" -f $peer, $suffix.TrimStart("."))
        }
    }
    if ($peers.Count -gt 0) {
        try {
            $current = [string](Get-Item -Path "WSMan:\localhost\Client\TrustedHosts" -ErrorAction Stop).Value
            $entries = @()
            if (-not [string]::IsNullOrWhiteSpace($current)) { $entries = @($current -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
            $added = @()
            foreach ($peer in $peers) {
                if ($entries -notcontains $peer) { $entries += $peer; $added += $peer }
            }
            if ($added.Count -gt 0) {
                Set-Item -Path "WSMan:\localhost\Client\TrustedHosts" -Value ($entries -join ",") -Force -ErrorAction Stop
                Write-Log ("WinRM trusts {0}" -f ($added -join ", ")) -Tag "Ok"
            }
            else {
                Write-Log "Peers already in WinRM TrustedHosts" -Tag "Info"
            }
        }
        catch {
            Write-Log "TrustedHosts not updated: $($_.Exception.Message)" -Tag "Warn"
            Write-Log ("    Set-Item WSMan:\localhost\Client\TrustedHosts -Value '{0}' -Force" -f ($peers -join ",")) -Tag "Info"
        }
    }

    # The shared suffix the cluster name lives under. The same function the single-node
    # path uses; a domain member is refused inside it.
    $cluster = Get-ConfigValue -InputObject $S2d -Name "cluster"
    $suffix = [string](Get-ConfigText -InputObject $cluster -Name "dnsSuffix" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($suffix)) { $null = Set-HypervPrimaryDnsSuffix -Suffix $suffix }
    elseif ([string]::IsNullOrWhiteSpace((Get-HypervPrimaryDnsSuffix))) {
        Write-Log "No primary DNS suffix here and none in the design - the cluster name has nowhere to register" -Tag "Error"
        return $false
    }
    return $true
}

# ---------------------------[ The peer ]---------------------------
function Test-HypervS2dPeerReady {
    param([Parameter(Mandatory)][string]$PeerName)

    try {
        $null = Test-WSMan -ComputerName $PeerName -ErrorAction Stop
    }
    catch {
        Write-Log "'$PeerName' does not answer WinRM: $($_.Exception.Message)" -Tag "Warn"
        return $false
    }

    # Test-WSMan alone was this check for one build, and it is the wrong question: the
    # identify request it sends is answered before any authorisation happens, so it
    # succeeds for an identity the peer will refuse everything else to. Field-hit
    # 2026-08-18 - the check passed, and Test-Cluster then failed with a bare "Access is
    # denied" because the caller was this machine's own account. So the peer is asked
    # something that actually needs rights on it, which is the question the cluster
    # cmdlets will ask a moment later.
    # [Environment]::MachineName rather than $env:COMPUTERNAME: the value wanted is the
    # REMOTE machine's, so there is no Using: modifier to add, and the method form says
    # that to the analyzer as well as to the reader.
    try {
        $answered = Invoke-Command -ComputerName $PeerName -ScriptBlock { [System.Environment]::MachineName } -ErrorAction Stop
        Write-Log "'$PeerName' answers this session as '$answered'" -Tag "Debug"
        return $true
    }
    catch {
        $whoami = $env:USERNAME
        try { $whoami = [string][System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $whoami = $env:USERNAME }
        Write-Log "'$PeerName' answers WinRM but refuses this session: $($_.Exception.Message)" -Tag "Warn"
        Write-Log "    Refused identity: '$whoami' - the cluster cmdlets authenticate as it too" -Tag "Warn"
        return $false
    }
}

# Who is running the cluster-forming half, asked before it starts rather than discovered
# through the cmdlet that fails. The post-reboot leg is normally the resume task, which
# the engine registers as SYSTEM - correct for everything a node does to ITSELF (features,
# adapters, its own disks) and useless for everything this half does, because every one of
# those calls is a REMOTE call to the other node and SYSTEM makes them as this machine's
# account. In a workgroup that account means nothing on the peer; in a domain it is not
# the account that was granted Create Computer Objects. Field-hit 2026-08-18: Test-Cluster
# answered "Access is denied" and New-Cluster "There was an error adding node", neither
# naming an identity, on a run whose own header said it was VM-HV-01$.
function Test-HypervS2dBuilderIdentity {
    # One implementation, in Cluster.ps1 - the file server guest cluster meets the same
    # wall for the same reason, and two copies of this reasoning would drift.
    if (Test-StudioClusterIdentity -Action "form the cluster") { return $true }
    Write-Log "    The plan file keeps this node's answers" -Tag "Info"
    return $false
}

# How many disks the peer could pool - colour for the resiliency menu, never a refusal.
# A peer that cannot be asked answers -1 and the menu says so.
function Get-HypervS2dPeerPoolableCount {
    param([Parameter(Mandatory)][string]$PeerName)

    $session = $null
    try {
        $session = New-CimSession -ComputerName $PeerName -ErrorAction Stop
        $disks = @(Get-PhysicalDisk -CimSession $session -ErrorAction Stop | Where-Object { $_.CanPool -eq $true })
        return $disks.Count
    }
    catch {
        Write-Log "Peer disks unreadable over WinRM - the menu shows this node's only: $($_.Exception.Message)" -Tag "Warn"
        return -1
    }
    finally {
        if ($null -ne $session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
    }
}

# ---------------------------[ The interview: this node's hardware ]---------------------------
# Which of this node's disks go into the cluster pool, with the same classification and
# the same spelled-out wipe consent the single-node path uses - reused read-only, because
# a disk is a disk whichever mode ticks it.
function Get-HypervS2dDiskAnswer {
    $all = @(Get-HypervClusterDiskCandidate)
    $candidates = @($all | Where-Object { $_.Usable })
    foreach ($item in @($all | Where-Object { -not $_.Usable })) {
        Write-Log ("Disk {0} not offered: {1}" -f $item.Number, $item.Reason) -Tag "Info"
    }

    $empty = [pscustomobject]@{ Numbers = @(); Ids = @(); Wipe = @() }
    if ($candidates.Count -eq 0) {
        Write-Log "No disk here S2D can claim - it takes whole empty disks" -Tag "Error"
        return $empty
    }

    $candidates = @(@($candidates | Where-Object { -not $_.NeedsWipe }) + @($candidates | Where-Object { $_.NeedsWipe }))
    $items = @()
    foreach ($candidate in $candidates) {
        $items += [pscustomobject]@{
            Id       = [string]$candidate.Number
            Selected = (-not $candidate.NeedsWipe)
            Label    = [string]$candidate.Label
            Detail   = @($candidate.Detail)
        }
    }

    $hint = "Every ticked disk on every node goes into the one cluster pool. Nested resiliency needs four capacity disks per node. A disk marked ERASES is not empty and is confirmed separately."
    $picked = @(Read-HypervMultiChoice -Title "Cluster storage" -Heading "Which of this node's disks join the S2D pool?" -Hint $hint -Items $items)
    $chosen = @()
    foreach ($id in $picked) {
        if ([string]::IsNullOrWhiteSpace([string]$id)) { continue }
        try { $chosen += [int]$id } catch { }
    }
    if ($chosen.Count -eq 0) {
        Write-Log "No disk ticked on this node - the pool gets nothing from it" -Tag "Warn"
        return $empty
    }

    $wipe = @()
    $dirty = @($candidates | Where-Object { $_.NeedsWipe -and (@($chosen) -contains [int]$_.Number) })
    if ($dirty.Count -gt 0) {
        Write-Log ("{0} ticked disk(s) are not empty and would be erased:" -f $dirty.Count) -Tag "Warn"
        foreach ($item in $dirty) {
            Write-Log ("    disk {0}   {1} GB   {2}" -f $item.Number, [math]::Round($item.SizeBytes / 1GB), $item.State) -Tag "Warn"
        }
        Write-Log "    Every partition, volume and file on them is destroyed - no undo, nothing backed up" -Tag "Warn"
        $answered = Read-HypervText -Prompt "Type ERASE to confirm, or press Enter to leave them alone" -Default ""
        if ([string]$answered -ceq "ERASE") {
            $wipe = @($dirty | ForEach-Object { [int]$_.Number })
            Write-Log ("Erase confirmed at the console: disk(s) {0}" -f ($wipe -join ", ")) -Tag "Warn"
        }
        else {
            $dropped = @($dirty | ForEach-Object { [int]$_.Number })
            $chosen = @($chosen | Where-Object { $dropped -notcontains [int]$_ })
            Write-Log ("Disk(s) {0} keep their contents and are not used" -f ($dropped -join ", ")) -Tag "Info"
        }
    }

    $ids = @()
    foreach ($number in $chosen) {
        try {
            $disk = Get-Disk -Number $number -ErrorAction Stop
            foreach ($value in @([string]$disk.UniqueId, [string]$disk.SerialNumber)) {
                if (-not [string]::IsNullOrWhiteSpace($value)) { $ids += $value.Trim() }
            }
        }
        catch { }
    }
    return [pscustomobject]@{ Numbers = @($chosen); Ids = @($ids); Wipe = @($wipe) }
}

# Which two ports are the storage links. Direct-connected between the nodes in the shape
# this mode expects - two cables, two subnets, no switch in between - though nothing here
# breaks if they do run through one.
# The one place a storage address is worked out, because two lanes now derive the same
# one and they must not drift apart. Ten, the VLAN's leading digits, its last digit, then
# the node's position times ten: VLAN 711 on node 2 is 10.71.1.20.
#
# BOTH lanes now (field-decided 2026-08-19, on the Lenovo engineer's recommendation).
# The manual lane has always written these addresses itself; the ATC lane now declares
# its storage intent with EnableAutomaticIPGeneration off - Microsoft's one documented
# lever, set at intent creation - and assigns the same derived addresses afterwards.
# That is NOT the removed replacement pass: nothing takes an address away from ATC,
# because ATC never assigns one in the first place.
#
# Times ten rather than the position itself - .10 and .20 rather than .1 and .2 - purely
# so the addresses read as deliberate in a cluster console. They are equally derived
# either way; one of them just looks like somebody chose it.
#
# -Interim gives the position itself, .1 and .2 - the ATC lane's stopgap between node
# prep and the intents (user's call, 2026-08-19): the links carry an address from the
# start, so the direct cables prove themselves in Test-Cluster before ATC exists, and
# the two shapes tell apart at a glance which state a bench is in - .1/.2 means the
# intent leg has not run yet, .10/.20 means it has.
function Get-HypervS2dStorageAddress {
    param(
        [Parameter(Mandatory)][int]$Vlan,
        [Parameter(Mandatory)][int]$NodeNumber,
        [switch]$Interim
    )

    # Three digits at most - a VLAN of 1000+ would overflow the derived second octet, and
    # the studio validates the field to the same range. Above 25 nodes the host octet
    # would overflow too, which two-node mode can never reach.
    if (($Vlan -lt 10) -or ($Vlan -gt 999)) { return "" }
    if (($NodeNumber -lt 1) -or ($NodeNumber -gt 25)) { return "" }
    $octet = $NodeNumber * 10
    if ($Interim) { $octet = $NodeNumber }
    return ("10.{0}.{1}.{2}" -f [math]::Floor($Vlan / 10), ($Vlan % 10), $octet)
}

# This node's 1-based position in the design's node list, matched on the leading label
# like every other persona decision. Position 1 when the machine is not in the list at
# all - the callers only run on nodes, so that is a fallback, not an answer.
function Get-HypervS2dNodePosition {
    param([Parameter(Mandatory)][object]$S2d)

    $names = @(Get-HypervS2dNodeName -S2d $S2d)
    $me = Get-HypervS2dHostLabel -Name $env:COMPUTERNAME
    for ($index = 0; $index -lt $names.Count; $index++) {
        if ((Get-HypervS2dHostLabel -Name $names[$index]).Equals($me, [System.StringComparison]::OrdinalIgnoreCase)) { return ($index + 1) }
    }
    return 1
}

function Get-HypervS2dStorageLinkAnswer {
    param(
        [Parameter(Mandatory)][object]$S2d,
        [string[]]$UsedAdapterName = @()
    )

    $networking = Get-ConfigValue -InputObject $S2d -Name "networking"
    $free = @(Get-HypervPhysicalAdapter | Where-Object { $UsedAdapterName -notcontains $_.Name })
    if ($free.Count -eq 0) {
        Write-Log "Every physical adapter is spoken for - none left for a storage link" -Tag "Warn"
        return @()
    }

    $items = @()
    foreach ($adapter in $free) {
        $speed = [string]$adapter.LinkSpeed
        if ([string]::IsNullOrWhiteSpace($speed)) { $speed = "speed unknown" }
        $items += [pscustomobject]@{
            Id       = [string]$adapter.Name
            Selected = $false
            Label    = ("{0}   {1}   {2}" -f $adapter.Name, $speed, $adapter.Status)
            Detail   = @(Get-HypervAdapterDetail -Adapter $adapter)
        }
    }

    $picked = @(Read-HypervMultiChoice -Title "Storage links" -Heading "Which adapters are the direct links to the other node?" `
        -Hint "Two, one per cable, each on its own subnet with no gateway - SMB Multichannel uses both at once. Ticking none skips the storage network on this node." `
        -Items $items)
    $chosen = @($free | Where-Object { $picked -contains [string]$_.Name })
    if ($chosen.Count -eq 0) { return @() }
    if ($chosen.Count -gt 2) {
        Write-Log ("{0} adapters ticked for two links - the first two are used" -f $chosen.Count) -Tag "Warn"
        $chosen = @($chosen | Select-Object -First 2)
    }

    # This node's address on each link is DERIVED, never designed: the subnet follows
    # the VLAN by Network ATC's own convention - VLAN 711 is 10.71.1.0/24, VLAN 712 is
    # 10.71.2.0/24, ten then the VLAN's leading digits then its last one - and the host
    # part is this node's position in the nodes list times ten, .10 and .20. The manual
    # lane thereby addresses exactly the subnets ATC would, and the design never states
    # an address the studio could not know.
    $hostNumber = Get-HypervS2dNodePosition -S2d $S2d

    $vlans = @(
        [int](Get-ConfigValue -InputObject $networking -Name "storageVlanA" -Default 711),
        [int](Get-ConfigValue -InputObject $networking -Name "storageVlanB" -Default 712)
    )

    $links = @()
    for ($index = 0; $index -lt $chosen.Count; $index++) {
        $vlan = $vlans[$index]
        $address = ""
        # Three digits at most - a VLAN of 1000+ would overflow the derived second
        # octet, and the studio validates the field to the same range.
        if (($vlan -ge 10) -and ($vlan -le 999)) {
            $address = Get-HypervS2dStorageAddress -Vlan $vlan -NodeNumber $hostNumber
        }
        $links += [pscustomobject]@{
            name         = [string]$chosen[$index].Name
            mac          = [string]$chosen[$index].MacAddress
            address      = $address
            prefixLength = 24
            vlan         = $vlan
        }
    }
    foreach ($link in $links) {
        Write-Log ("Storage link '{0}': {1}/{2}" -f $link.name, $link.address, $link.prefixLength) -Tag "Info"
    }
    return @($links)
}

# ---------------------------[ The interview: cluster-wide answers ]---------------------------
# Asked on the builder only, because they are about the cluster rather than one node's
# hardware. The two-node resiliency menu - the single-node path never sees these shapes.
# The console owns this answer: the studio does not write a resiliency key, because the
# real disk counts exist only here. A key in an older config.json is still honoured as
# the preselected entry; absent, the nested mirror leads.
function Get-HypervS2dResiliencyAnswer {
    param(
        [Parameter(Mandatory)][object]$S2d,
        [int]$LocalDiskCount = 0,
        [int]$PeerDiskCount = -1
    )

    $storage = Get-ConfigValue -InputObject $S2d -Name "storage"
    $wanted = [string](Get-ConfigText -InputObject $storage -Name "resiliency" -Default "nestedMirror")

    $perNode = $LocalDiskCount
    if (($PeerDiskCount -ge 0) -and ($PeerDiskCount -lt $perNode)) { $perNode = $PeerDiskCount }
    $peerLine = "the other node could not be asked - counts assume it matches this one"
    if ($PeerDiskCount -ge 0) { $peerLine = ("{0} poolable disk(s) on the other node" -f $PeerDiskCount) }

    $items = @()
    $items += [pscustomobject]@{
        Id    = "nestedMirror"
        Label = "Nested two-way mirror     survives a node AND a drive at once, 25% usable"
        Detail = @("four copies, two per node on different drives", "the safe two-node answer while one node is down for patching")
    }
    $items += [pscustomobject]@{
        Id    = "twoWayMirror"
        Label = "Two-way mirror            survives ONE failure - a node or a drive, 50% usable"
        Detail = @("one copy per node", "a drive failure while the other node is down takes the volume with it")
    }
    $items += [pscustomobject]@{
        Id    = "nestedParity"
        Label = "Nested mirror-accelerated parity   survives node+drive, roughly 35-40% usable"
        Detail = @("a small four-copy mirror tier in front of per-node parity", "wants flash - parity on spinning disks in a two-node cluster is slow")
    }

    # Nested needs four capacity drives per node; below that only the plain mirror is
    # honest, so the others are not offered rather than offered and refused later.
    if ($perNode -gt 0 -and $perNode -lt 4) {
        Write-Log ("{0} disk(s) per node - below the four nested resiliency needs, so only the plain mirror is offered" -f $perNode) -Tag "Warn"
        $items = @($items | Where-Object { $_.Id -eq "twoWayMirror" })
        $wanted = "twoWayMirror"
    }

    $ordered = @($items | Where-Object { $_.Id -eq $wanted })
    $ordered += @($items | Where-Object { $_.Id -ne $wanted })

    $picked = Read-HypervChoice -Title "Cluster storage" -Heading "How do the two nodes protect the data?" `
        -Hint ("{0} poolable disk(s) on this node, {1}. Every volume is carved from one pool spanning both nodes." -f $LocalDiskCount, $peerLine) `
        -Items $ordered
    if ($null -eq $picked) { $picked = $wanted }
    Write-Log ("Volumes: {0}" -f $picked) -Tag "Info"
    return [string]$picked
}

# The witness secrets, collected while somebody is at the console - the leg that uses
# them runs -NoGui. Nothing is asked for a domain file share (the cluster account is the
# credential) or a managed-identity cloud witness (the Arc identity is).
function Get-HypervS2dWitnessAnswer {
    param(
        [Parameter(Mandatory)][object]$S2d,
        [Parameter(Mandatory)][object]$Hyperv
    )

    $witness = Get-ConfigValue -InputObject $S2d -Name "witness"
    $answer = [pscustomobject]@{ witnessKey = ""; witnessPassword = "" }
    if ($null -eq $witness) { return $answer }

    $type = [string](Get-ConfigText -InputObject $witness -Name "type" -Default "cloud")
    if ($type -eq "cloud") {
        $cloud = Get-ConfigValue -InputObject $witness -Name "cloud"
        if ([bool](Get-ConfigValue -InputObject $cloud -Name "useManagedIdentity" -Default $false)) {
            Write-Log "Cloud witness: managed identities - no access key needed" -Tag "Info"
            return $answer
        }
        # The design's own value first, exactly as the workgroup share password below is
        # handled: asking for a key that is already in the file is how two consoles end
        # up holding two different keys for the same storage account.
        $configured = ([string](Get-ConfigText -InputObject $cloud -Name "accessKey" -Default "")).Trim()
        if (-not [string]::IsNullOrWhiteSpace($configured)) {
            Write-Log "Cloud witness key from the design" -Tag "Info"
            $answer.witnessKey = $configured
            return $answer
        }
        $account = [string](Get-ConfigText -InputObject $cloud -Name "accountName" -Default "")
        Write-Log "Cloud witness key is not in the design" -Tag "Info"
        $answer.witnessKey = Read-HypervText -Prompt ("Access key for storage account '{0}'" -f $account) -Default ""
        if ([string]::IsNullOrWhiteSpace($answer.witnessKey)) {
            Write-Log "No key typed - the witness step stops with the command to run by hand" -Tag "Warn"
        }
        return $answer
    }

    if (-not (Test-HypervS2dDomainKind -Hyperv $Hyperv)) {
        $fileShare = Get-ConfigValue -InputObject $witness -Name "fileShare"
        $account = [string](Get-ConfigText -InputObject $fileShare -Name "localAccount" -Default "clusterwitness")
        Write-Log "Workgroup share witness - explicit local credential" -Tag "Info"
        # The design's own value first: this account is created by this design, so the
        # studio generates its password and the witness host created it with exactly
        # this one. Asking for it again when it is right there is how two consoles end
        # up holding two different passwords for the same account.
        $configured = [string](Get-ConfigText -InputObject $fileShare -Name "password" -Default "")
        if (-not [string]::IsNullOrWhiteSpace($configured)) {
            Write-Log "    Password from the design - the witness host created the account with it" -Tag "Debug"
            $answer.witnessPassword = $configured
            return $answer
        }
        $answer.witnessPassword = Read-HypervText -Prompt ("Password of '{0}' on the witness host (the same one the witness run sets)" -f $account) -Default ""
    }
    return $answer
}

function Write-HypervS2dPlanSummary {
    param(
        [Parameter(Mandatory)][object]$S2d,
        [Parameter(Mandatory)][object]$Plan
    )

    Write-Studio -Text "  Cluster" -Key "fg"
    $names = @(Get-HypervS2dNodeName -S2d $S2d)
    Write-Studio -Text ("    {0}   nodes {1}" -f (Get-HypervS2dClusterName -S2d $S2d), ($names -join " + ")) -Key "accent"
    if (-not [string]::IsNullOrWhiteSpace([string]$Plan.resiliency)) {
        Write-Studio -Text ("    volumes        {0}" -f [string]$Plan.resiliency) -Key "accent"
    }
    Write-Host ""

    Write-Studio -Text "  This node" -Key "fg"
    $disks = @()
    if (($null -ne $Plan.disks) -and ($null -ne $Plan.disks.numbers)) { $disks = @($Plan.disks.numbers) }
    if ($disks.Count -gt 0) {
        Write-Studio -Text ("    pool disks     {0}" -f ($disks -join ", ")) -Key "accent"
        $wipe = @()
        try { $wipe = @($Plan.disks.wipe | Where-Object { $null -ne $_ }) } catch { $wipe = @() }
        if ($wipe.Count -gt 0) {
            Write-Studio -Text ("    erases         disk {0} - every partition and file is destroyed" -f ($wipe -join ", ")) -Key "warn"
        }
    }
    else {
        Write-Studio -Text "    pool disks     none ticked - the pool gets nothing from this node" -Key "muted"
    }
    foreach ($link in @($Plan.storageLinks)) {
        Write-Studio -Text ("    storage link   {0}   {1}/{2}" -f $link.name, $link.address, $link.prefixLength) -Key "accent"
    }
    foreach ($definition in @($Plan.switches)) {
        Write-Studio -Text ("    " + (Get-HypervSwitchLine -Definition $definition)) -Key "accent"
    }
    Write-Host ""
}

# Every question first, one review screen, then the build - the same contract as the
# single host, per node.
function Invoke-HypervS2dInterview {
    param(
        [Parameter(Mandatory)][object]$Hyperv,
        [Parameter(Mandatory)][object]$S2d,
        [Parameter(Mandatory)][string]$Persona
    )

    $networking = Get-ConfigValue -InputObject $S2d -Name "networking"
    $atc = ([string](Get-ConfigText -InputObject $networking -Name "mode" -Default "atc") -eq "atc")

    while ($true) {
        Write-Log "Asking what no config file can answer - which disks, which adapters" -Tag "Run"

        $plan = [pscustomobject]@{
            createdUtc      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            computerName    = [string]$env:COMPUTERNAME
            persona         = $Persona
            disks           = (Get-HypervS2dDiskAnswer)
            switches        = @()
            computeAdapters = @()
            storageLinks    = @()
            resiliency      = ""
            witnessKey      = ""
            witnessPassword = ""
            appCompat       = $null
        }

        # A node that brings no pool disks is not a plan worth reviewing - S2D mirrors
        # per server, so a two-node cluster needs capacity from every node, and letting
        # this through means the volume step fails long after these answers were
        # confirmed (user's call, 2026-08-19). A tick-nothing slip re-asks; a machine
        # with nothing to offer ends the interview instead of looping on a question
        # that has no right answer.
        if (@($plan.disks.Numbers).Count -eq 0) {
            if (@(Get-HypervClusterDiskCandidate | Where-Object { $_.Usable }).Count -eq 0) {
                Write-Log "No disk here the pool could use - attach clean data disks and run this again" -Tag "Error"
                return $null
            }
            Write-Log "No pool disks ticked - a two-node cluster needs capacity from every node, so the question repeats" -Tag "Warn"
            continue
        }

        $used = @()
        if ($atc) {
            # ATC builds the SET switch itself, so the question is only which adapters
            # carry the management and compute intent - and they are renamed to the same
            # names on every node, because ATC matches adapters by name across the cluster.
            $free = @(Get-HypervPhysicalAdapter)
            $items = @()
            foreach ($adapter in $free) {
                $items += [pscustomobject]@{
                    Id       = [string]$adapter.Name
                    Selected = $false
                    Label    = ("{0}   {1}   {2}" -f $adapter.Name, $adapter.LinkSpeed, $adapter.Status)
                    Detail   = @(Get-HypervAdapterDetail -Adapter $adapter)
                }
            }
            $picked = @(Read-HypervMultiChoice -Title "Network ATC" -Heading "Which adapters carry management and virtual machines?" `
                -Hint "Network ATC builds the SET switch out of these itself. They must exist with the same names on both nodes - the run renames them so they do." `
                -Items $items)
            $chosen = @($free | Where-Object { $picked -contains [string]$_.Name })
            $plan.computeAdapters = @($chosen | ForEach-Object { [pscustomobject]@{ name = [string]$_.Name; mac = [string]$_.MacAddress } })
            $used += @($chosen | ForEach-Object { [string]$_.Name })
        }
        else {
            $plan.switches = @(Get-HypervSwitchAnswer -Hyperv $Hyperv)
            foreach ($definition in @($plan.switches)) {
                foreach ($member in @($definition.adapters)) { $used += [string]$member.name }
            }
        }

        $plan.storageLinks = @(Get-HypervS2dStorageLinkAnswer -S2d $S2d -UsedAdapterName $used)

        if ($Persona -eq "builder") {
            $peerCount = -1
            $peerSuffix = Get-HypervS2dNodeSuffix -S2d $S2d -Hyperv $Hyperv
            $peers = @(Get-HypervS2dPeerName -S2d $S2d | ForEach-Object { Resolve-HypervS2dNodeAddress -NodeName $_ -Suffix $peerSuffix })
            if ($peers.Count -gt 0) { $peerCount = Get-HypervS2dPeerPoolableCount -PeerName $peers[0] }
            $plan.resiliency = Get-HypervS2dResiliencyAnswer -S2d $S2d -LocalDiskCount (@($plan.disks.Numbers).Count) -PeerDiskCount $peerCount

            $secrets = Get-HypervS2dWitnessAnswer -S2d $S2d -Hyperv $Hyperv
            $plan.witnessKey = [string]$secrets.witnessKey
            $plan.witnessPassword = [string]$secrets.witnessPassword
        }

        if (Test-HypervAppCompatWanted -Hyperv $Hyperv) {
            $choice = Get-HypervAppCompatChoice -Hyperv $Hyperv
            $plan.appCompat = [pscustomobject]@{ mode = [string]$choice.Mode; isoPath = [string]$choice.IsoPath }
        }

        $script:hypervS2dSummarySection = $S2d
        $script:hypervS2dSummaryPlan = $plan
        # Not .GetNewClosure() - on 5.1 a closure's module scope cannot see script-scope
        # functions. Same note as every PreItems block in this repo.
        $summary = { Write-HypervS2dPlanSummary -S2d $script:hypervS2dSummarySection -Plan $script:hypervS2dSummaryPlan }

        $decision = Show-Menu -Title "Hyper-V S2D cluster" -Subtitle "Review" -Heading "This is what the run will build on this node" `
            -HeadingHint "Nothing above has happened yet. Everything after this point runs without asking." `
            -PreItems $summary -Items @(
            [pscustomobject]@{ Id = "start"; Label = "Start the build" }
            [pscustomobject]@{ Id = "again"; Label = "Answer the questions again" }
            [pscustomobject]@{ Id = "cancel"; Label = "Cancel - change nothing on this server" }
        )

        if ($decision -eq "again") { continue }
        if (($null -eq $decision) -or ($decision -eq "cancel")) {
            Write-Log "Cancelled at the review screen - nothing built, no answers written" -Tag "Warn"
            return $null
        }

        $null = Write-HypervS2dPlan -Plan $plan
        return $plan
    }
}

# ---------------------------[ Networking: the manual lane ]---------------------------
# A storage link is an address and nothing else: no gateway, no DNS registration - a
# crossover cable has neither - and the cluster sees each subnet as its own network.
function Set-HypervS2dStorageLink {
    param([Parameter(Mandatory)][object[]]$Link)

    $done = 0
    foreach ($item in $Link) {
        $adapters = @(Resolve-HypervPlannedAdapter -Member @($item))
        if ($adapters.Count -eq 0) { continue }
        $name = [string]$adapters[0].Name

        try {
            $current = @(Get-NetIPAddress -InterfaceAlias $name -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { [string]$_.IPAddress -eq [string]$item.address })
            if ($current.Count -eq 0) {
                Get-NetIPAddress -InterfaceAlias $name -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
                $null = Set-NetIPInterface -InterfaceAlias $name -Dhcp Disabled -ErrorAction Stop
                $null = New-NetIPAddress -InterfaceAlias $name -IPAddress ([string]$item.address) `
                    -PrefixLength ([int]$item.prefixLength) -ErrorAction Stop
            }
            $null = Set-DnsClient -InterfaceAlias $name -RegisterThisConnectionsAddress $false -ErrorAction Stop
            Write-Log ("'{0}': {1}/{2} - no gateway, no DNS registration" -f $name, $item.address, $item.prefixLength) -Tag "Ok"
            $done++
        }
        catch {
            Write-Log ("Storage address not set on '{0}': {1}" -f $name, $_.Exception.Message) -Tag "Error"
        }
    }
    return ($done -gt 0)
}

# Jumbo frames on the storage links in the manual lane, 9014 - the Lenovo field
# recommendation, on by default; the ATC lane carries the same value as an intent
# override. Host-side only, and the log states the prerequisite instead of assuming it:
# every hop between the nodes has to carry the frame or it is dropped silently. Never
# fatal - a link that stays at 1514 still moves storage traffic, merely in more frames.
function Set-HypervS2dJumboFrame {
    param(
        [Parameter(Mandatory)][object[]]$Link,
        [Parameter(Mandatory)][object]$Networking
    )

    if (-not [bool](Get-ConfigValue -InputObject $Networking -Name "jumboFrames" -Default $true)) {
        Write-Log "Jumbo frames off in this design - storage links stay at 1514" -Tag "Info"
        return $true
    }

    $done = 0
    foreach ($item in $Link) {
        $adapters = @(Resolve-HypervPlannedAdapter -Member @($item))
        if ($adapters.Count -eq 0) { continue }
        $name = [string]$adapters[0].Name
        try {
            $property = @(Get-NetAdapterAdvancedProperty -Name $name -RegistryKeyword "*JumboPacket" -ErrorAction SilentlyContinue)
            if ($property.Count -eq 0) {
                Write-Log "'$name' has no *JumboPacket keyword - jumbo frames stay off on it" -Tag "Warn"
                continue
            }
            $null = Set-NetAdapterAdvancedProperty -Name $name -RegistryKeyword "*JumboPacket" -RegistryValue 9014 -ErrorAction Stop
            Write-Log "'$name': jumbo frames on, *JumboPacket 9014" -Tag "Ok"
            $done++
        }
        catch {
            Write-Log ("Jumbo frames not set on '{0}': {1}" -f $name, $_.Exception.Message) -Tag "Warn"
        }
    }
    if ($done -gt 0) {
        Write-Log "    Every hop must carry 9014, the parent vSwitch included on a virtual host" -Tag "Info"
    }
    return ($done -gt 0)
}

# RDMA in the manual lane. iWARP is one switch per adapter; RoCEv2 needs Priority Flow
# Control end to end even on a direct cable - the pause frames ride the VLAN header,
# which is why the storage links carry a tag at all. Written from Microsoft's documented
# sequence; the studio marks it bench-untested because a nested lab exposes no RDMA.
function Enable-HypervS2dRdma {
    param(
        [Parameter(Mandatory)][object[]]$Link,
        [Parameter(Mandatory)][string]$Flavor
    )

    if ($Flavor -eq "disabled") {
        Write-Log "RDMA off - storage runs TCP SMB multichannel" -Tag "Info"
        return $true
    }
    $names = @()
    foreach ($item in $Link) {
        $adapters = @(Resolve-HypervPlannedAdapter -Member @($item))
        if ($adapters.Count -gt 0) { $names += [string]$adapters[0].Name }
    }
    if ($names.Count -eq 0) { return $false }

    if ($Flavor -eq "roce") {
        Write-Log "DCB for RoCEv2: SMB Direct priority 3, 50% reservation, PFC on it" -Tag "Run"
        try {
            if (@(Get-NetQosPolicy -Name "SMB" -ErrorAction SilentlyContinue).Count -eq 0) {
                $null = New-NetQosPolicy -Name "SMB" -NetDirectPortMatchCondition 445 -PriorityValue8021Action 3 -ErrorAction Stop
            }
            if (@(Get-NetQosPolicy -Name "Cluster" -ErrorAction SilentlyContinue).Count -eq 0) {
                $null = New-NetQosPolicy -Name "Cluster" -Cluster -PriorityValue8021Action 7 -ErrorAction Stop
            }
            $null = Enable-NetQosFlowControl -Priority 3 -ErrorAction Stop
            $null = Disable-NetQosFlowControl -Priority 0, 1, 2, 4, 5, 6, 7 -ErrorAction Stop
            if (@(Get-NetQosTrafficClass -Name "SMB" -ErrorAction SilentlyContinue).Count -eq 0) {
                $null = New-NetQosTrafficClass -Name "SMB" -Priority 3 -BandwidthPercentage 50 -Algorithm ETS -ErrorAction Stop
            }
            $null = Set-NetQosDcbxSetting -Willing $false -Confirm:$false -ErrorAction Stop
            foreach ($name in $names) {
                $null = Enable-NetAdapterQos -Name $name -ErrorAction Stop
            }
        }
        catch {
            Write-Log "DCB configuration failed: $($_.Exception.Message)" -Tag "Error"
            Write-Log "    RoCEv2 without Priority Flow Control drops frames silently under load - fix before trusting the storage network" -Tag "Warn"
            return $false
        }
        # The tag is what the PFC bits ride in, so it stays even back to back.
        foreach ($item in $Link) {
            $vlan = 0
            try { $vlan = [int]$item.vlan } catch { $vlan = 0 }
            if ($vlan -le 0) { continue }
            $adapters = @(Resolve-HypervPlannedAdapter -Member @($item))
            if ($adapters.Count -eq 0) { continue }
            try {
                $null = Set-NetAdapterAdvancedProperty -Name ([string]$adapters[0].Name) -DisplayName "VLAN ID" -DisplayValue ([string]$vlan) -ErrorAction Stop
                Write-Log ("'{0}': VLAN {1}" -f $adapters[0].Name, $vlan) -Tag "Info"
            }
            catch {
                Write-Log ("VLAN tag not set on '{0}': {1}" -f $adapters[0].Name, $_.Exception.Message) -Tag "Warn"
            }
        }
    }

    try {
        $null = Enable-NetAdapterRdma -Name $names -ErrorAction Stop
    }
    catch {
        Write-Log "RDMA not enabled: $($_.Exception.Message)" -Tag "Warn"
    }

    $operational = @()
    try { $operational = @(Get-NetAdapterRdma -Name $names -ErrorAction Stop | Where-Object { $_.Enabled }) } catch { $operational = @() }
    if ($operational.Count -eq 0) {
        Write-Log "No storage adapter reports RDMA - traffic runs plain TCP SMB, which works and is slower" -Tag "Warn"
    }
    else {
        Write-Log ("RDMA on: {0}" -f (($operational | ForEach-Object { $_.Name }) -join ", ")) -Tag "Ok"
    }
    return $true
}

# Host live migration is a DOMAIN feature - Enable-VMMigration refuses on a workgroup
# machine outright ("Live migrations can be enabled only on a domain joined computer"),
# because host-to-host migration authenticates with Kerberos or CredSSP and a workgroup
# has neither. That is not a fault to report on a workgroup design, it is the shape of
# the design: those nodes migrate virtual machines as a CLUSTER, through the cluster's own
# channel, which needs none of this. Asked before the attempt rather than logged as a
# warning after it - a red line about something that was never going to work is how a
# clean run reads as a broken one. Field-hit 2026-08-18.
# Host live migration, on BOTH kinds of cluster.
#
# The workgroup half used to be declined here on the grounds that migration needs
# Kerberos or CredSSP and a workgroup node has neither a domain nor a delegation story.
# Windows Server 2025 ended that: nodes authenticate each other with the self-signing
# PKU2U certificates the cluster already builds, and Microsoft's own workgroup-cluster
# walkthrough is exactly `Enable-VMMigration` plus `Set-VMHost` migration limits - no
# delegation, no SPNs, no domain. The prerequisite is the one the cluster already
# demanded: the identical local administrator, same name and same password, on both.
#
# The authentication TYPE is deliberately left where Windows puts it - CredSSP, the
# default - on both kinds. Kerberos would be the stronger answer in a domain, but it
# only works when constrained delegation for cifs and Microsoft Virtual System Migration
# Service is configured on both computer objects, which this design does not do and must
# not silently half-do. CredSSP's cost is stated instead: a migration has to be STARTED
# from a signed-in session on the source node, because that is where the credential is
# delegated from. The cluster moving a VM itself is not affected by any of this.
$script:hypervS2dMigrationLimit = 10

function Set-HypervS2dLiveMigration {
    param(
        [Parameter(Mandatory)][object]$Hyperv,
        [object]$Plan = $null,
        [string[]]$PeerName = @()
    )

    $domainJoined = Test-HypervS2dDomainKind -Hyperv $Hyperv

    # ORDER, and it is the whole reason this is called twice. On a workgroup host that is
    # not in a cluster yet, Enable-VMMigration answers "Live migrations can be enabled
    # only on a domain joined computer" - bench-seen, and the line that made this design
    # skip workgroup migration entirely. Cluster membership is what lifts it, so the
    # workgroup pass runs from the cluster leg instead, for this node and the peer both.
    if ((-not $domainJoined) -and ($null -eq (Get-StudioClusterHere))) {
        Write-Log "    Live migration waits for the cluster - a workgroup host outside one cannot enable it" -Tag "Debug"
        return $true
    }

    if (-not (Enable-HypervS2dHostMigration -DomainJoined $domainJoined)) { return $false }
    $null = Set-HypervS2dMigrationNetwork -Plan $Plan

    # The peer is configured from here rather than by its own run: on a workgroup cluster
    # the member leg has already finished and stopped by the time a cluster exists.
    $subnets = @(Get-HypervS2dMigrationSubnet -Plan $Plan)
    foreach ($peer in $PeerName) {
        if ([string]::IsNullOrWhiteSpace($peer)) { continue }
        $limit = $script:hypervS2dMigrationLimit
        $remoteSubnets = @($subnets)
        try {
            $applied = Invoke-Command -ComputerName $peer -ErrorAction Stop -ScriptBlock {
                $remoteLimit = [int]$using:limit
                $wanted = @($using:remoteSubnets)
                $null = Enable-VMMigration -ErrorAction Stop
                $null = Set-VMHost -VirtualMachineMigrationPerformanceOption SMB `
                    -MaximumVirtualMachineMigrations $remoteLimit -MaximumStorageMigrations $remoteLimit -ErrorAction Stop
                # Same DAD wait as this node does for itself, then the same three
                # attempts: the peer's storage addresses were assigned seconds ago.
                $pinned = $false
                for ($tries = 1; $tries -le 3; $tries++) {
                    try {
                        $have = @(Get-VMMigrationNetwork -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.Subnet })
                        foreach ($subnet in $wanted) {
                            if ($have -contains $subnet) { continue }
                            $null = Add-VMMigrationNetwork -Subnet $subnet -ErrorAction Stop
                        }
                        if ($wanted.Count -gt 0) { $null = Set-VMHost -UseAnyNetworkForMigration $false -ErrorAction Stop }
                        $pinned = $true
                        break
                    }
                    catch { Start-Sleep -Seconds 5 }
                }
                return $pinned
            }
            if ($applied) { Write-Log "'$peer': live migration on, over SMB" -Tag "Ok" }
            else { Write-Log "'$peer': live migration on, but its migration networks are not pinned" -Tag "Warn" }
        }
        catch {
            Write-Log "'$peer' did not take the live migration settings: $($_.Exception.Message)" -Tag "Warn"
            Write-Log "    Run this config on that node, or set it there: Enable-VMMigration; Set-VMHost -VirtualMachineMigrationPerformanceOption SMB" -Tag "Info"
        }
    }

    if (-not $domainJoined) {
        Write-Log "    The nodes authenticate with PKU2U - Windows Server 2025 is what makes migration work without a domain" -Tag "Debug"
        Write-Log "    Start a migration from a signed-in session on the source node - CredSSP delegates from there, not from a remote console" -Tag "Info"
    }
    return $true
}

function Enable-HypervS2dHostMigration {
    param([bool]$DomainJoined)

    # This runs twice on a domain-joined build - once in the apply leg, once from the
    # cluster leg that the workgroup path needs - so the second pass says nothing rather
    # than repeating a line that was already true.
    try {
        $host_ = Get-VMHost -ErrorAction Stop
        if ([bool]$host_.VirtualMachineMigrationEnabled -and
            ([string]$host_.VirtualMachineMigrationPerformanceOption -eq "SMB") -and
            ([int]$host_.MaximumVirtualMachineMigrations -eq $script:hypervS2dMigrationLimit)) {
            Write-Log "Live migration already on, over SMB" -Tag "Debug"
            return $true
        }
    }
    catch { }

    try {
        $null = Enable-VMMigration -ErrorAction Stop
        $null = Set-VMHost -VirtualMachineMigrationPerformanceOption SMB `
            -MaximumVirtualMachineMigrations $script:hypervS2dMigrationLimit `
            -MaximumStorageMigrations $script:hypervS2dMigrationLimit -ErrorAction Stop
        Write-Log ("Live migration on, over SMB, {0} concurrent" -f $script:hypervS2dMigrationLimit) -Tag "Ok"
        return $true
    }
    catch {
        $message = [string]$_.Exception.Message
        Write-Log "Live migration not configured: $message" -Tag "Warn"
        if ((-not $DomainJoined) -and ($message -match "(?i)domain[ -]?joined")) {
            Write-Log "    A workgroup host takes this only as a cluster node, and only on Windows Server 2025" -Tag "Info"
        }
        Write-Log "    The cluster still moves virtual machines between its own nodes - this is host-to-host migration" -Tag "Info"
        return $false
    }
}

# Migration traffic belongs on the storage links, which are the fast ones and the ones
# nothing else is using. Windows Server 2025 picks a network on its own and picks well,
# but "on its own" includes the management NIC on a node whose storage links are not up
# yet - so the subnets are named, and named from the design rather than from whatever is
# configured at this second.
function Get-HypervS2dMigrationSubnet {
    param([object]$Plan = $null)

    $subnets = @()
    if ($null -eq $Plan) { return $subnets }
    foreach ($item in @($Plan.storageLinks)) {
        $sample = Get-HypervS2dStorageAddress -Vlan ([int]$item.vlan) -NodeNumber 1
        if ([string]::IsNullOrWhiteSpace($sample)) { continue }
        $parts = @($sample -split "\.")
        if ($parts.Count -ne 4) { continue }
        $prefix = [int]$item.prefixLength
        if (($prefix -lt 8) -or ($prefix -gt 30)) { $prefix = 24 }
        $subnets += ("{0}.{1}.{2}.0/{3}" -f $parts[0], $parts[1], $parts[2], $prefix)
    }
    return $subnets
}

function Set-HypervS2dMigrationNetwork {
    param([object]$Plan = $null)

    $subnets = @(Get-HypervS2dMigrationSubnet -Plan $Plan)
    if ($subnets.Count -eq 0) { return $true }

    # DAD again, and this one cost a bench run too (2026-08-22): the storage addresses are
    # assigned one second before this runs, and VMMS binds a listener per migration
    # network. A tentative address cannot be bound, so the whole call fails with
    #
    #   Failed to configure the network listeners for Virtual Machine migrations:
    #   The requested address is not valid in its context. (0x80072741)   [WSAEADDRNOTAVAIL]
    #
    # which reads like the subnet is wrong and is only the address not being awake yet.
    $null = Wait-HypervS2dSubnetAddressReady -Subnet $subnets

    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            $existing = @(Get-VMMigrationNetwork -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.Subnet })
            foreach ($subnet in $subnets) {
                if ($existing -contains $subnet) { continue }
                $null = Add-VMMigrationNetwork -Subnet $subnet -ErrorAction Stop
            }
            # Only after at least one named network exists - clearing this first would
            # leave the host with no path at all if the adds then failed.
            $null = Set-VMHost -UseAnyNetworkForMigration $false -ErrorAction Stop
            Write-Log ("Migration networks: {0}" -f ($subnets -join ", ")) -Tag "Ok"
            return $true
        }
        catch {
            $message = [string]$_.Exception.Message
            if ($attempt -lt 3) {
                Write-Log ("Migration networks not pinned yet (attempt {0}) - waiting for the addresses" -f $attempt) -Tag "Debug"
                Start-Sleep -Seconds 5
                continue
            }
            Write-Log "Migration networks not pinned: $message" -Tag "Warn"
            Write-Log "    Migration still works - Windows picks the network itself, which may be the management link" -Tag "Info"
            Write-Log ("    By hand once the storage links are up: {0}; Set-VMHost -UseAnyNetworkForMigration `$false" -f (($subnets | ForEach-Object { "Add-VMMigrationNetwork -Subnet $_" }) -join "; ")) -Tag "Info"
            return $false
        }
    }
    return $false
}

# Every local address inside one of these subnets has to be Preferred before anything
# binds to it. Nothing to wait for is a pass, not a failure - the peer's addresses are
# not this node's to hold up.
function Wait-HypervS2dSubnetAddressReady {
    param(
        [Parameter(Mandatory)][string[]]$Subnet,
        [int]$TimeoutSeconds = 30
    )

    $prefixes = @()
    foreach ($item in $Subnet) {
        $parts = @(([string]$item -split "/")[0] -split "\.")
        if ($parts.Count -eq 4) { $prefixes += ("{0}.{1}.{2}." -f $parts[0], $parts[1], $parts[2]) }
    }
    if ($prefixes.Count -eq 0) { return $true }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $pending = @()
        $found = 0
        try {
            foreach ($entry in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
                $address = [string]$entry.IPAddress
                foreach ($prefix in $prefixes) {
                    if (-not $address.StartsWith($prefix)) { continue }
                    $found++
                    if ([string]$entry.AddressState -ne "Preferred") { $pending += $address }
                }
            }
        }
        catch { }
        if (($found -eq 0) -or ($pending.Count -eq 0)) { return $true }
        Start-Sleep -Milliseconds 500
    }
    Write-Log ("Storage address(es) still not Preferred: {0}" -f ($pending -join ", ")) -Tag "Debug"
    return $false
}

# ---------------------------[ Networking: the ATC lane ]---------------------------
# Two intents replace everything the manual lane does by hand. Run from the builder with
# -ClusterName once the cluster exists, so ATC applies and remediates cluster-wide.
# One Add-NetIntent call, retried, because the failure that matters here is caused by the
# call before it. Submitting the management intent hands ATC the adapters the cluster is
# currently talking over, and ATC rebuilds them into a SET switch - so for a few seconds
# the local cluster is exactly what this next call cannot open:
#
#   FAILED: Intent request for storage failed to be submitted.
#   Exception calling "ReadIntentRequestFromStore" with "2" argument(s): "Failed to open local cluster"
#
# Field-hit 2026-08-18, and intermittent by nature - the same config had submitted both
# intents cleanly an hour earlier, which is the signature of a race rather than a fault.
# So the cluster is waited for and the submission repeated; anything that is not that
# transient shape fails on the first attempt as before.
function Submit-HypervS2dIntent {
    param(
        [Parameter(Mandatory)][hashtable]$Parameters,
        [Parameter(Mandatory)][string]$Label
    )

    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            $null = Add-NetIntent @Parameters
            return $true
        }
        catch {
            $message = [string]$_.Exception.Message
            $transient = ($message -match "(?i)cluster service|RPC server is unavailable|being restarted")
            # "Failed to open local cluster" is deliberately NOT in that list any more. It
            # was, on the theory that the management intent's SET rebuild had briefly taken
            # the cluster away - and three identical retries, each after the cluster had
            # answered Get-Cluster, disproved it on the bench. It is a NAME failure, fixed
            # by handing ATC the cluster's fully qualified name (see the caller), and
            # retrying it just spends a minute arriving at the same answer.
            if ($message -match "(?i)failed to open (the )?local cluster") {
                Write-Log "$Label intent not declared: $message" -Tag "Error"
                Write-Log "    ATC could not open the cluster's intent store. On a workgroup cluster that is almost always the NAME - it can only be opened by one DNS can answer" -Tag "Error"
                Write-Log ("    This run used '{0}'. Fix DNS or the design's suffix and run again - nothing is half-declared" -f [string]$Parameters["ClusterName"]) -Tag "Error"
                return $false
            }
            if ((-not $transient) -or ($attempt -eq 3)) {
                Write-Log "$Label intent not declared: $message" -Tag "Error"
                return $false
            }
            Write-Log "$Label intent not submitted yet - the cluster service is not answering" -Tag "Warn"
            Write-Log ("    Waiting, then attempt {0} of 3" -f ($attempt + 1)) -Tag "Info"
        }

        # The store ATC itself reads, rather than the cluster in general - a Get-Cluster
        # that answers proved nothing the one time this mattered.
        $deadline = (Get-Date).AddMinutes(3)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 15
            try {
                $null = Get-NetIntent -ClusterName ([string]$Parameters["ClusterName"]) -ErrorAction Stop
                break
            }
            catch {
                Write-Log "    ATC's intent store still does not answer" -Tag "Debug"
            }
        }
    }
    return $false
}

function Add-HypervS2dNetworkIntent {
    param(
        [Parameter(Mandatory)][object]$S2d,
        [Parameter(Mandatory)][object]$Hyperv,
        [Parameter(Mandatory)][object]$Plan,
        [string[]]$PeerName = @()
    )

    if (-not (Get-Command -Name "Add-NetIntent" -ErrorAction SilentlyContinue)) {
        Write-Log "Add-NetIntent not available - Network ATC ships in Windows Server 2025 and the feature has to be installed" -Tag "Error"
        return $false
    }

    # QUALIFIED, and on a workgroup cluster that is what makes these calls work at all.
    # ATC opens the cluster to read and write its intent store, and a workgroup host
    # cannot open a cluster - not even the one it is a member of - by short name: there is
    # no directory to resolve it, so the name has to be one DNS can answer. The symptom
    # when it is not is `Exception calling "ReadIntentRequestFromStore" ... "Failed to open
    # local cluster"`, which names neither the cluster nor the name it tried. Field-hit
    # three times on 2026-08-18, and diagnosed by the user rather than by this code: the
    # storage intent failed at "Checking for existing global intent" while the management
    # intent submitted seconds earlier had succeeded, which sent this file chasing a race
    # that was never there. The same rule the nodes and the witness already follow.
    $clusterName = Resolve-HypervS2dNodeAddress -NodeName (Get-HypervS2dClusterName -S2d $S2d) `
        -Suffix (Get-HypervS2dNodeSuffix -S2d $S2d -Hyperv $Hyperv)
    $networking = Get-ConfigValue -InputObject $S2d -Name "networking"

    $computeNames = @()
    foreach ($member in @($Plan.computeAdapters)) {
        $adapters = @(Resolve-HypervPlannedAdapter -Member @($member))
        if ($adapters.Count -gt 0) { $computeNames += [string]$adapters[0].Name }
    }
    $storageNames = @()
    foreach ($member in @($Plan.storageLinks)) {
        $adapters = @(Resolve-HypervPlannedAdapter -Member @($member))
        if ($adapters.Count -gt 0) { $storageNames += [string]$adapters[0].Name }
    }

    $existing = @()
    try { $existing = @(Get-NetIntent -ClusterName $clusterName -ErrorAction Stop | ForEach-Object { [string]$_.IntentName }) }
    catch { $existing = @() }
    $failed = @()
    $vlans = @(
        [int](Get-ConfigValue -InputObject $networking -Name "storageVlanA" -Default 711),
        [int](Get-ConfigValue -InputObject $networking -Name "storageVlanB" -Default 712)
    )

    # A guest adapter has no RDMA to negotiate, and without this override the storage
    # intent fails and stays failed. Injected by the run rather than designed, so the
    # same config lands unchanged on physical hardware.
    $virtualHost = Test-HypervRunningVirtual
    $override = $null
    if ($virtualHost) {
        try {
            $override = New-NetIntentAdapterPropertyOverrides -ErrorAction Stop
            $override.NetworkDirect = 0
            Write-Log "Virtual host - intents carry NetworkDirect 0" -Tag "Info"
        }
        catch { $override = $null }
    }

    # The storage override that takes addressing back from ATC - the documented lever,
    # asked for before the intent exists because it only applies at creation. A null here
    # (an ATC too old to know the cmdlet) falls back to ATC's own addressing, announced
    # where the intent is declared.
    $storageOverride = $null
    if ($storageNames.Count -gt 0) {
        try {
            $storageOverride = New-NetIntentStorageOverrides -ErrorAction Stop
            $storageOverride.EnableAutomaticIPGeneration = $false
        }
        catch { $storageOverride = $null }
    }

    # The storage intent's own adapter properties, all three Lenovo recommendations in
    # one object: NetworkDirect off on a virtual host (same reason as above), jumbo
    # frames on unless the design says otherwise, and RDMA pinned to RoCEv2 on physical
    # hardware when the design asks (NetworkDirectTechnology 4 - the only protocol a
    # Mellanox/ConnectX card speaks; the pin and the virtual host exclude each other,
    # a guest NIC has no RDMA whichever protocol is named). Storage only, deliberately:
    # management traffic talks to clients and gateways that never negotiated any of it,
    # while the storage links only ever talk to each other.
    $jumbo = [bool](Get-ConfigValue -InputObject $networking -Name "jumboFrames" -Default $true)
    $roce = [bool](Get-ConfigValue -InputObject $networking -Name "pinRoceV2" -Default $true)
    $storageProperty = $null
    if (($storageNames.Count -gt 0) -and ($jumbo -or $virtualHost -or $roce)) {
        try {
            $storageProperty = New-NetIntentAdapterPropertyOverrides -ErrorAction Stop
            if ($virtualHost) { $storageProperty.NetworkDirect = 0 }
            elseif ($roce) { $storageProperty.NetworkDirectTechnology = 4 }
            if ($jumbo) { $storageProperty.JumboPacket = 9014 }
        }
        catch { $storageProperty = $null }
    }

    if ($computeNames.Count -gt 0) {
        if ($existing -contains "management") {
            Write-Log "'management' intent already exists - left as it is" -Tag "Info"
        }
        else {
            Write-Log ("Declaring the management and compute intent over {0}" -f ($computeNames -join ", ")) -Tag "Run"
            $parameters = @{ Name = "management"; Management = $true; Compute = $true; ClusterName = $clusterName; AdapterName = $computeNames; ErrorAction = "Stop" }
            if ($null -ne $override) { $parameters["AdapterPropertyOverrides"] = $override }
            if (-not (Submit-HypervS2dIntent -Parameters $parameters -Label "management")) { $failed += "management" }
        }
    }

    if ($storageNames.Count -gt 0) {
        if ($existing -contains "storage") {
            Write-Log "'storage' intent already exists - left as it is" -Tag "Info"
        }
        else {
            Write-Log ("Declaring the storage intent over {0}, VLANs {1}" -f ($storageNames -join ", "), ($vlans -join "/")) -Tag "Run"
            # Automatic IP generation is off (field-decided 2026-08-19, the Lenovo
            # engineer's recommendation): ATC would pick a random host octet out of the
            # same subnets, which reads as a fault in the cluster console, and Microsoft's
            # one documented lever for that is this override, set at intent creation.
            # The design assigns its own derived addresses once the intent provisions.
            if ($null -ne $storageOverride) {
                Write-Log "    Automatic IP generation off - addresses come from the design" -Tag "Info"
            }
            else {
                Write-Log "    New-NetIntentStorageOverrides not available - ATC keeps its own addressing, expect a host octet it picks" -Tag "Warn"
            }
            if (($null -ne $storageProperty) -and $jumbo) {
                Write-Log "    JumboPacket 9014" -Tag "Info"
            }
            if (($null -ne $storageProperty) -and $roce) {
                if ($virtualHost) {
                    Write-Log "    RoCEv2 pin skipped - guest NICs have no RDMA" -Tag "Info"
                }
                else {
                    Write-Log "    RDMA pinned to RoCEv2 (NetworkDirectTechnology 4) - right for Mellanox/ConnectX, switch it off for iWARP-only cards" -Tag "Debug"
                }
            }
            $parameters = @{ Name = "storage"; Storage = $true; ClusterName = $clusterName; AdapterName = $storageNames; StorageVlans = $vlans; ErrorAction = "Stop" }
            if ($null -ne $storageProperty) { $parameters["AdapterPropertyOverrides"] = $storageProperty }
            if ($null -ne $storageOverride) { $parameters["StorageOverrides"] = $storageOverride }
            if (-not (Submit-HypervS2dIntent -Parameters $parameters -Label "storage")) { $failed += "storage" }
        }
    }

    # Polled even when a submission above failed, and that is the point of collecting
    # them rather than returning early: ATC is a declarative engine with its own retry, so
    # the status of what DID land is the useful answer, and a run that returned on the
    # first failure printed an error and then nothing at all about the intent that had
    # worked. Field-hit 2026-08-18.
    if ($failed.Count -gt 0) {
        Write-Log ("Intent(s) not accepted: {0} - the status below is of whatever did land" -f ($failed -join ", ")) -Tag "Warn"
    }

    # Provisioning takes a few minutes and a brief network blip per node is normal.
    Write-Log "Waiting for Network ATC to provision the intents - takes a few minutes" -Tag "Run"
    $provisioned = $false
    $deadline = (Get-Date).AddMinutes(10)
    $nextReport = (Get-Date).AddMinutes(1)
    while ((Get-Date) -lt $deadline) {
        $status = @(Get-HypervS2dIntentStatus -ClusterName $clusterName)
        if ($status.Count -gt 0) {
            $unfinished = @($status | Where-Object { [string]$_.ConfigurationStatus -ne "Success" })
            if ($unfinished.Count -eq 0) {
                Write-Log "Intents: Success on every node" -Tag "Ok"
                $provisioned = $true
                break
            }
            # A wait that says nothing looks the same as a wait that is stuck, and this
            # one is minutes long. Once a minute, what is actually outstanding.
            if ((Get-Date) -ge $nextReport) {
                $nextReport = (Get-Date).AddMinutes(1)
                $detail = @($unfinished | ForEach-Object { "{0}/{1} {2}" -f [string]$_.IntentName, [string]$_.Host, [string]$_.ConfigurationStatus })
                Write-Log ("    still provisioning: {0}" -f ($detail -join ", ")) -Tag "Info"
            }
        }
        Start-Sleep -Seconds 20
    }
    if (-not $provisioned) {
        Write-Log "Intents did not all reach Success in time - the cluster works on and ATC keeps retrying" -Tag "Warn"
        Write-Log "    Watch it with: Get-NetIntentStatus" -Tag "Info"
        Write-Log "    An intent stuck at Failed can be told to try again: Set-NetIntentRetryState -Name <intent>" -Tag "Info"
    }

    # With automatic IP generation off the addresses are this design's job, on both
    # nodes, and only now - ATC's provisioning is what puts the VLANs on these ports.
    # Skipped when the storage intent never landed (nothing owns those ports yet) and
    # when the override cmdlet was missing (ATC kept the job).
    if (($storageNames.Count -gt 0) -and ($null -ne $storageOverride) -and ($failed -notcontains "storage")) {
        $null = Set-HypervS2dAtcStorageAddress -S2d $S2d -Plan $Plan -PeerName $PeerName
    }
    return $true
}

# Reading the intent status, which is NOT symmetrical with submitting it.
#
# `Add-NetIntent` needs -ClusterName to declare an intent cluster-wide, and on a workgroup
# cluster it needs the FQDN specifically. `Get-NetIntentStatus -ClusterName` with that
# same name then fails outright (bench, 2026-08-22):
#
#   Get-NetworkGoalStatesForAllNodes : Exception calling "ReadExistingGoalStatesForAllNodes"
#   with "2" argument(s): "Failed to open local cluster"
#
# while the BARE call on a cluster member returns every node's rows - it reads the same
# cluster store without asking to open the cluster by name. So the bare call is tried
# first and the scoped ones are the fallback, which is the opposite of the obvious order
# and the reason this is a function rather than one line. The cost of getting it wrong is
# not an error: an empty status reads exactly like "not provisioned yet", so the run waits
# out its whole deadline and then reports a timeout for something that finished minutes
# ago. That is what it did before this existed.
$script:hypervS2dIntentStatusMode = ""

function Get-HypervS2dIntentStatus {
    param([string]$ClusterName = "")

    $shortName = $ClusterName
    if ($shortName -match "\.") { $shortName = ($shortName -split "\.")[0] }

    $attempts = @()
    switch ($script:hypervS2dIntentStatusMode) {
        "local" { $attempts = @(@{ Label = "local"; Name = "" }) }
        "fqdn"  { $attempts = @(@{ Label = "fqdn";  Name = $ClusterName }) }
        "short" { $attempts = @(@{ Label = "short"; Name = $shortName }) }
        default {
            $attempts = @(@{ Label = "local"; Name = "" })
            if (-not [string]::IsNullOrWhiteSpace($ClusterName)) { $attempts += @{ Label = "fqdn"; Name = $ClusterName } }
            if ((-not [string]::IsNullOrWhiteSpace($shortName)) -and ($shortName -ne $ClusterName)) { $attempts += @{ Label = "short"; Name = $shortName } }
        }
    }

    $lastError = ""
    foreach ($attempt in $attempts) {
        try {
            $rows = @()
            if ([string]::IsNullOrWhiteSpace([string]$attempt.Name)) {
                $rows = @(Get-NetIntentStatus -ErrorAction Stop)
            }
            else {
                $rows = @(Get-NetIntentStatus -ClusterName ([string]$attempt.Name) -ErrorAction Stop)
            }
            if ($rows.Count -eq 0) { continue }
            if ($script:hypervS2dIntentStatusMode -ne [string]$attempt.Label) {
                Write-Log ("Intent status read: {0}" -f [string]$attempt.Label) -Tag "Debug"
                $script:hypervS2dIntentStatusMode = [string]$attempt.Label
            }
            return $rows
        }
        catch { $lastError = [string]$_.Exception.Message }
    }

    # Said once per run, not once per poll: the wait below is a loop and this would
    # otherwise print thirty times.
    if (-not [string]::IsNullOrWhiteSpace($lastError) -and ($script:hypervS2dIntentStatusMode -ne "failed")) {
        Write-Log "The intent status cannot be read: $lastError" -Tag "Warn"
        Write-Log "    The wait below can only time out now - the intents may well be provisioning fine" -Tag "Warn"
        $script:hypervS2dIntentStatusMode = "failed"
    }
    return @()
}

# The ATC lane's storage addresses, both nodes, from the builder. The plan already
# carries this node's derived addresses (the interview works them out in both lanes);
# the peer's are the same derivation at its own node position, applied over the same
# adapter names - ATC requires the names to match across nodes and the rename enforced
# it. A peer the session cannot reach gets the paste-ready lines instead of a failure,
# the same contract as the DNS registration step.
function Set-HypervS2dAtcStorageAddress {
    param(
        [Parameter(Mandatory)][object]$S2d,
        [Parameter(Mandatory)][object]$Plan,
        [string[]]$PeerName = @()
    )

    if (@($Plan.storageLinks).Count -eq 0) { return $true }

    Write-Log "Assigning storage addresses - .10 and .20 per node position" -Tag "Run"
    $ok = Set-HypervS2dStorageLink -Link @($Plan.storageLinks)

    $names = @(Get-HypervS2dNodeName -S2d $S2d)
    foreach ($peer in $PeerName) {
        $label = Get-HypervS2dHostLabel -Name $peer
        $position = 0
        for ($index = 0; $index -lt $names.Count; $index++) {
            if ((Get-HypervS2dHostLabel -Name $names[$index]).Equals($label, [System.StringComparison]::OrdinalIgnoreCase)) { $position = $index + 1; break }
        }
        if ($position -eq 0) {
            Write-Log "'$peer' is not in the design's node list - its storage addresses cannot be derived, skipped" -Tag "Warn"
            continue
        }

        $links = @()
        foreach ($item in @($Plan.storageLinks)) {
            $adapters = @(Resolve-HypervPlannedAdapter -Member @($item))
            if ($adapters.Count -eq 0) { continue }
            $address = Get-HypervS2dStorageAddress -Vlan ([int]$item.vlan) -NodeNumber $position
            if ([string]::IsNullOrWhiteSpace($address)) { continue }
            $links += [pscustomobject]@{
                name         = [string]$adapters[0].Name
                address      = $address
                prefixLength = [int]$item.prefixLength
            }
        }
        if ($links.Count -eq 0) { continue }

        try {
            $set = @(Invoke-Command -ComputerName $peer -ErrorAction Stop -ScriptBlock {
                $remoteLinks = @($using:links)
                $done = @()
                foreach ($link in $remoteLinks) {
                    $current = @(Get-NetIPAddress -InterfaceAlias ([string]$link.name) -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                        Where-Object { [string]$_.IPAddress -eq [string]$link.address })
                    if ($current.Count -eq 0) {
                        Get-NetIPAddress -InterfaceAlias ([string]$link.name) -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                            Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
                        $null = Set-NetIPInterface -InterfaceAlias ([string]$link.name) -Dhcp Disabled -ErrorAction Stop
                        $null = New-NetIPAddress -InterfaceAlias ([string]$link.name) -IPAddress ([string]$link.address) `
                            -PrefixLength ([int]$link.prefixLength) -ErrorAction Stop
                    }
                    $null = Set-DnsClient -InterfaceAlias ([string]$link.name) -RegisterThisConnectionsAddress $false -ErrorAction Stop
                    $done += ("{0} = {1}/{2}" -f [string]$link.name, [string]$link.address, [int]$link.prefixLength)
                }
                return $done
            })
            Write-Log ("'{0}': {1} - no gateway, no DNS registration" -f $peer, ($set -join ", ")) -Tag "Ok"
        }
        catch {
            Write-Log "Storage addresses not set on '$peer' from here: $($_.Exception.Message)" -Tag "Warn"
            Write-Log "    Nothing else assigns them with automatic IP generation off. Sign in on '$peer' and run:" -Tag "Warn"
            foreach ($link in $links) {
                Write-Log ("        New-NetIPAddress -InterfaceAlias '{0}' -IPAddress {1} -PrefixLength {2}; Set-DnsClient -InterfaceAlias '{0}' -RegisterThisConnectionsAddress `$false" -f $link.name, $link.address, $link.prefixLength) -Tag "Info"
            }
            $ok = $false
        }
    }
    return $ok
}

# ---------------------------[ The cluster ]---------------------------
function Test-HypervS2dValidation {
    param(
        [Parameter(Mandatory)][object]$S2d,
        [Parameter(Mandatory)][object]$Hyperv
    )

    if (-not [bool](Get-ConfigValue -InputObject $S2d -Name "validate" -Default $true)) {
        Write-Log "Cluster validation off in the design" -Tag "Info"
        return
    }

    $names = @(Get-HypervS2dNodeAddress -S2d $S2d -Hyperv $Hyperv)
    Write-Log ("Validating {0} - takes several minutes" -f ($names -join " + ")) -Tag "Run"
    try {
        # The S2D category instead of the legacy Storage one: the legacy tests arbitrate
        # shared SAS reservations, which is exactly what S2D does not use.
        $report = Test-Cluster -Node $names -Include "Storage Spaces Direct", "Inventory", "Network", "System Configuration" -ErrorAction Stop
        if ($null -ne $report) {
            Write-Log "Validation report: $($report.FullName)" -Tag "Info"
        }
        Write-Log "Validation finished" -Tag "Info"
    }
    catch {
        Write-Log "Cluster validation did not complete: $($_.Exception.Message)" -Tag "Warn"
        # Two very different failures used to share one shrug. Validation that RAN and
        # disliked something is advisory - the cluster is created anyway and the report
        # says what it found. Validation refused outright never reached the peer at all,
        # and New-Cluster is about to make the same call with the same credentials and
        # fail the same way, naming a node instead of a reason. Field-hit 2026-08-18.
        if ($_.Exception.Message -match "(?i)access is denied|0x80070005|unauthorized") {
            Write-Log "    Not a validation finding - the other node refused this session, and every call below authenticates the same way" -Tag "Error"
            $whoami = $env:USERNAME
            try { $whoami = [string][System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $whoami = $env:USERNAME }
            Write-Log "    This run is '$whoami'. A workgroup peer accepts only the identical local administrator - same name AND same password" -Tag "Error"
            return
        }
        Write-Log "The cluster is created anyway" -Tag "Info"
    }
}

# The DNS event every workgroup cluster logs and every reader chases (field-hit
# 2026-08-18): "Cluster network name resource 'Cluster Name' failed registration of one
# or more associated DNS name(s) for the following reason: No credentials are available
# in the security package."
#
# It is expected, and saying so here is the whole point. The network name resource tries
# a dynamic DNS update, the server answers that a secured one is required (or refuses
# outright), and the secure attempt then needs a computer account to authenticate as -
# the exact thing a workgroup cluster does not have. No permission fixes it and nothing
# is broken by it: the resource still comes online, the name works off the STATIC record
# this design requires anyway, and the event just returns on every resource restart and
# periodic refresh, reading as a fault forever.
#
# The run also stops the attempts (the user's call, 2026-08-18, having read the first
# version of this note): the network name resource registers through the node adapters'
# own 'register this connection's addresses' setting, and the builder switches that off
# on every node once the intents are up - Disable-HypervWorkgroupDnsRegistration has the
# whole story, including the one thing given up: a node's own registration against a DNS
# server that accepts nonsecure updates. On a workgroup design the records are static by
# construction, so what is given up is another copy of the same doomed attempt.
#
# The per-adapter half of that does NOT hold on an ATC-managed vNIC: ATC restores it, on
# remediation and at boot, and there is no supported way to ask it not to (2026-08-23 -
# Disable-HypervWorkgroupDnsRegistration records the three levers tried). So on this
# design event 1196 is expected, permanently, and the static record is the thing worth
# checking instead - which is what the rest of this function does.
function Write-HypervS2dWorkgroupDnsNote {
    param(
        [Parameter(Mandatory)][object]$S2d,
        [Parameter(Mandatory)][object]$Hyperv
    )

    $cluster = Get-ConfigValue -InputObject $S2d -Name "cluster"
    $staticAddress = ([string](Get-ConfigText -InputObject $cluster -Name "staticAddress" -Default "")).Trim()
    $suffix = Get-HypervS2dNodeSuffix -S2d $S2d -Hyperv $Hyperv
    $fqdn = Get-HypervS2dClusterName -S2d $S2d
    if (-not [string]::IsNullOrWhiteSpace($suffix)) { $fqdn = "{0}.{1}" -f $fqdn, $suffix.TrimStart(".") }

    Write-Log "A workgroup cluster cannot register '$fqdn' in DNS - the registration event is expected" -Tag "Info"
    Write-Log "    'failed registration ... No credentials are available in the security package' - secure dynamic update needs a computer account. The name resource comes online off the static record, which is why this design requires one" -Tag "Debug"

    # Whether that static record is actually right, which is the half of this worth
    # measuring rather than asserting.
    if (-not [string]::IsNullOrWhiteSpace($staticAddress)) {
        $resolved = @()
        try { $resolved = @([System.Net.Dns]::GetHostAddresses($fqdn) | ForEach-Object { [string]$_.IPAddressToString }) }
        catch { $resolved = @() }
        if ($resolved.Count -eq 0) {
            Write-Log "    '$fqdn' does not resolve yet - create the static record: $fqdn -> $staticAddress" -Tag "Warn"
        }
        elseif ($resolved -contains $staticAddress) {
            Write-Log "    static record correct: '$fqdn' -> $staticAddress" -Tag "Ok"
        }
        else {
            Write-Log ("    '{0}' resolves to {1}, cluster address is {2} - fix the static record or connections land elsewhere" -f $fqdn, ($resolved -join ", "), $staticAddress) -Tag "Warn"
        }
    }

    Write-Log "    DNS registration is switched off on both nodes once the intents are up" -Tag "Debug"
}

function New-HypervS2dCluster {
    param(
        [Parameter(Mandatory)][object]$S2d,
        [Parameter(Mandatory)][object]$Hyperv
    )

    $existing = Get-HypervClusterHere
    if ($null -ne $existing) {
        Write-Log "Already in the cluster '$($existing.Name)' - left as it is" -Tag "Info"
        return $true
    }

    # Qualified where DNS answers: these are remote calls, and on a workgroup cluster
    # DNS is the only naming authority. The cluster's own NAME stays short - it is a
    # name being CREATED rather than one being resolved, and the suffix is put on it by
    # the primary DNS suffix this design already set on both nodes.
    $names = @(Get-HypervS2dNodeAddress -S2d $S2d -Hyperv $Hyperv)
    $name = Get-HypervS2dClusterName -S2d $S2d
    $cluster = Get-ConfigValue -InputObject $S2d -Name "cluster"
    $domainKind = Test-HypervS2dDomainKind -Hyperv $Hyperv

    Test-HypervS2dValidation -S2d $S2d -Hyperv $Hyperv

    # -NoStorage is not optional on an S2D cluster: without it, clustering claims the
    # eligible disks as classic cluster disks and Enable-ClusterStorageSpacesDirect finds
    # nothing left to build the pool from.
    $parameters = @{
        Name        = $name
        Node        = $names
        NoStorage   = $true
        Force       = $true
        ErrorAction = "Stop"
    }
    $address = [string](Get-ConfigText -InputObject $cluster -Name "staticAddress" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($address)) { $parameters["StaticAddress"] = $address.Trim() }

    if ($domainKind) {
        # The OU is carried in the name itself - New-Cluster accepts the distinguished
        # name and creates the computer object there instead of the default container.
        $ouPath = ([string](Get-ConfigText -InputObject $cluster -Name "ouPath" -Default "")).Trim()
        if (-not [string]::IsNullOrWhiteSpace($ouPath)) { $parameters["Name"] = "CN=$name,$ouPath" }
    }
    else {
        # The documented workgroup path, and New-Cluster rather than New-WorkgroupCluster
        # for the same reasons the single-node file records: Microsoft's own procedure
        # uses New-Cluster -AdministrativeAccessPoint DNS, and the field report says the
        # AD-less cmdlet breaks tooling downstream.
        $parameters["AdministrativeAccessPoint"] = "Dns"
    }

    Write-Log ("Creating cluster '{0}' across {1}" -f $name, ($names -join " + ")) -Tag "Run"
    try {
        $null = New-Cluster @parameters
        Write-Log "Cluster '$name' exists" -Tag "Ok"
        Test-HypervClusterNameRegistration -Name $name
        if (-not $domainKind) { Write-HypervS2dWorkgroupDnsNote -S2d $S2d -Hyperv $Hyperv }
        return $true
    }
    catch {
        Write-Log "Cluster not created: $($_.Exception.Message)" -Tag "Error"
        if ($domainKind) {
            Write-Log "    The account running this needs 'Create Computer Objects' where the cluster name object goes" -Tag "Info"
        }
        else {
            Write-Log "    A workgroup cluster needs the identical local administrator on both nodes, TrustedHosts set, and a shared DNS suffix" -Tag "Info"
        }
        return $false
    }
}

# ---------------------------[ The witness ]---------------------------
# Two nodes without a witness is a coin with no edge: lose either node and the survivor
# has no majority and stops. Configured immediately after the cluster exists.
function Test-HypervS2dWitnessConfigured {
    try {
        $quorum = Get-ClusterQuorum -ErrorAction Stop
        if ($null -ne $quorum.QuorumResource) { return $true }
    }
    catch { }
    return $false
}

# Can the SHARE be opened by the identity that will actually open it? That qualifier is
# the whole function. `Test-Path \\host\share` answers for the identity running this
# script, and in a workgroup that account means nothing on the witness host - only
# `clusterwitness` does, which is why the design created it. So the probe said "not
# reachable" about a share whose folder, both grants, firewall rules and account were all
# correct, and returned before Set-ClusterQuorum was ever called. Field-hit 2026-08-18.
#
# This is the THIRD time this shape has cost a bench run - Test-WSMan answering for an
# identity the peer would refuse, `certutil -CAInfo role` answering a different question
# than the one asked - so the rule is worth stating plainly: a probe that gates an
# operation must use the operation's own identity, or it is not evidence about that
# operation at all.
#
# Mapped with New-PSDrive because that is the same authenticated SMB session the cluster
# makes, and its failures separate the two causes that need different fixes: a refusal
# (the account, its password, or the share and NTFS grants) from a path that is not there
# (name resolution, the firewall, or a share that was never published).
function Test-HypervS2dWitnessShareReachable {
    param(
        [Parameter(Mandatory)][string]$Path,
        [System.Management.Automation.PSCredential]$Credential
    )

    $result = [pscustomobject]@{ Reachable = $false; Denied = $false; Detail = "" }
    $name = "s2dwitness"
    try { if (Get-PSDrive -Name $name -ErrorAction SilentlyContinue) { Remove-PSDrive -Name $name -Force -ErrorAction SilentlyContinue } } catch { }

    try {
        $parameters = @{ Name = $name; PSProvider = "FileSystem"; Root = $Path; ErrorAction = "Stop" }
        if ($null -ne $Credential) { $parameters["Credential"] = $Credential }
        $null = New-PSDrive @parameters
        $result.Reachable = $true
    }
    catch {
        $result.Detail = [string]$_.Exception.Message
        # Named refusals only. An earlier version also matched a bare "5)" hoping to catch
        # the Win32 code, which matches any message that happens to contain one.
        $result.Denied = ($result.Detail -match "(?i)access is denied|logon failure|user name or password|is not permitted|0x80070005")
    }
    finally {
        try { Remove-PSDrive -Name $name -Force -ErrorAction SilentlyContinue } catch { }
    }
    return $result
}

function Set-HypervS2dFileShareWitness {
    param(
        [Parameter(Mandatory)][object]$S2d,
        [Parameter(Mandatory)][object]$Hyperv,
        [object]$Plan = $null
    )

    $witness = Get-ConfigValue -InputObject $S2d -Name "witness"
    $fileShare = Get-ConfigValue -InputObject $witness -Name "fileShare"
    $host2 = ([string](Get-ConfigText -InputObject $fileShare -Name "host" -Default "")).Trim()
    $shareName = ([string](Get-ConfigText -InputObject $fileShare -Name "shareName" -Default "")).Trim()
    if ([string]::IsNullOrWhiteSpace($host2) -or [string]::IsNullOrWhiteSpace($shareName)) {
        Write-Log "File share witness names no host or no share - fill both in on the witness card" -Tag "Error"
        return $false
    }
    # The witness host is reached the same way the nodes are, and for the same reason:
    # this is an SMB connection made by the cluster service, on a design where DNS is the
    # only naming authority. A witness is also the one thing here that is often NOT a
    # cluster node - a third box, sometimes not even Windows - so a short name for it
    # leans on NetBIOS harder than anything else in this file does.
    $host2 = Resolve-HypervS2dNodeAddress -NodeName $host2 -Suffix (Get-HypervS2dNodeSuffix -S2d $S2d -Hyperv $Hyperv)
    $path = "\\$host2\$shareName"
    $domainKind = Test-HypervS2dDomainKind -Hyperv $Hyperv
    $clusterName = Get-HypervS2dClusterName -S2d $S2d
    $account = [string](Get-ConfigText -InputObject $fileShare -Name "localAccount" -Default "clusterwitness")
    $hostKind = [string](Get-ConfigText -InputObject $fileShare -Name "hostKind" -Default "windows")

    # The credential is built BEFORE anything is tested, because it is what the test has
    # to be made with.
    $credential = $null
    if (-not $domainKind) {
        $password = ""
        if ($null -ne $Plan) { $password = [string]$Plan.witnessPassword }
        if ([string]::IsNullOrWhiteSpace($password)) {
            $password = [string](Get-ConfigText -InputObject $fileShare -Name "password" -Default "")
        }
        if ([string]::IsNullOrWhiteSpace($password)) {
            Write-Log "Workgroup share witness needs the credential for '$account' - neither the design nor this console supplied one" -Tag "Error"
            Write-Log "    Put a password on the witness card and export with secrets included, or run this at the console" -Tag "Error"
            return $false
        }
        $secure = ConvertTo-SecureString -String $password -AsPlainText -Force
        # The PATH wants the qualified name and the CREDENTIAL does not. This account is
        # LOCAL to the witness host, so the part before the backslash has to be that
        # machine's NetBIOS name - 'vm-hv-witness\clusterwitness'. Handed the fully
        # qualified name instead, Windows reads it as a domain to authenticate against and
        # the logon fails somewhere that reports only access denied.
        $credentialHost = Get-HypervS2dHostLabel -Name $host2
        $credential = New-Object System.Management.Automation.PSCredential("$credentialHost\$account", $secure)
    }

    $reach = Test-HypervS2dWitnessShareReachable -Path $path -Credential $credential
    if (-not $reach.Reachable) {
        if ($domainKind) {
            # NOT a refusal in this shape: the cluster opens the share as the cluster's own
            # computer account, and this test could only be made as the session running the
            # script. So it is reported and Set-ClusterQuorum below is left to be the judge.
            Write-Log "'$path' did not open for this session: $($reach.Detail)" -Tag "Warn"
            Write-Log "    This session's answer, not the cluster's - the cluster opens it as '$clusterName`$'. The attempt below settles it" -Tag "Info"
        }
        elseif ($reach.Denied) {
            Write-Log "'$path' refused '$credentialHost\$account': $($reach.Detail)" -Tag "Error"
            Write-Log "    The share is there and that account cannot open it - so the account, its password, or the grants, not the network" -Tag "Error"
            Write-Log "    On '$host2':  Get-SmbShareAccess -Name '$shareName'    and    (Get-Acl '<the folder>').Access" -Tag "Error"
            Write-Log "    Both halves are needed: Change on the share AND Modify on the folder" -Tag "Error"
            return $false
        }
        else {
            Write-Log "'$path' not reachable: $($reach.Detail)" -Tag "Warn"
            if ($hostKind -eq "windows") {
                Write-Log "    Run this script with this config on '$host2' - it builds the share, account, grants and firewall - then run this node again" -Tag "Info"
            }
            else {
                Write-Log "    Publish an SMB share on '$host2' by hand: SMB 2 or later, dedicated to this cluster, never on DFS" -Tag "Info"
                if ($domainKind) {
                    Write-Log "    Grant '$clusterName`$' Change and Read on the share, Modify on the folder" -Tag "Info"
                }
                else {
                    Write-Log "    Create the local account '$account' on it with full rights on the share" -Tag "Info"
                }
            }
                Write-Log "    Nothing answered at that path - check the name, the firewall, then whether the share exists:" -Tag "Info"
            Write-Log ("        Test-NetConnection {0} -Port 445        then    net view \\{0}" -f (($path -split "\\")[2])) -Tag "Info"
            return $false
        }
    }
    else {
        $who = "this session"
        if ($null -ne $credential) { $who = "'$($credential.UserName)'" }
        Write-Log "'$path' opens for $who" -Tag "Ok"
    }

    Write-Log "Configuring the file share witness at '$path'" -Tag "Run"
    try {
        if ($domainKind) {
            $null = Set-ClusterQuorum -FileShareWitness $path -ErrorAction Stop
        }
        else {
            $null = Set-ClusterQuorum -FileShareWitness $path -Credential $credential -ErrorAction Stop
        }
        Write-Log "Witness: '$path'" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "Witness not configured: $($_.Exception.Message)" -Tag "Error"
        if ($domainKind) {
            Write-Log "    Usually the ACL: '$clusterName`$' needs Change and Read on the share AND Modify on the folder" -Tag "Info"
        }
        else {
            Write-Log "    The share opened for that account a moment ago, so this is the cluster's own attempt - read the cluster events on both nodes" -Tag "Debug"
        }
        return $false
    }
}

function Set-HypervS2dCloudWitness {
    param(
        [Parameter(Mandatory)][object]$S2d,
        [object]$Plan = $null
    )

    $witness = Get-ConfigValue -InputObject $S2d -Name "witness"
    $cloud = Get-ConfigValue -InputObject $witness -Name "cloud"
    $account = ([string](Get-ConfigText -InputObject $cloud -Name "accountName" -Default "")).Trim()
    if ([string]::IsNullOrWhiteSpace($account)) {
        Write-Log "Cloud witness names no storage account - fill it in on the witness card" -Tag "Error"
        return $false
    }

    if ([bool](Get-ConfigValue -InputObject $cloud -Name "useManagedIdentity" -Default $false)) {
        Write-Log "Configuring the cloud witness on '$account' with the nodes' managed identities" -Tag "Run"
        try {
            $null = Set-ClusterQuorum -CloudWitness -AccountName $account -UseManagedIdentity -ErrorAction Stop
            Write-Log "Witness: storage account '$account', as the Arc machine identities" -Tag "Ok"
            return $true
        }
        catch {
            Write-Log "Managed-identity cloud witness not configured: $($_.Exception.Message)" -Tag "Error"
            Write-Log "    Needs Windows Server 2025, both nodes Arc-connected, and Storage Blob Data Contributor for each node identity" -Tag "Info"
            return $false
        }
    }

    # The design's own value first, the plan's (a console answer from the interview leg)
    # second. A key in config.json is what makes the builder finish unattended; the
    # console path stays for a design exported without secrets.
    $key = ([string](Get-ConfigText -InputObject $cloud -Name "accessKey" -Default "")).Trim()
    if (-not [string]::IsNullOrWhiteSpace($key)) {
        Write-Log "Cloud witness key from the design" -Tag "Info"
    }
    elseif ($null -ne $Plan) {
        $key = [string]$Plan.witnessKey
    }
    if ([string]::IsNullOrWhiteSpace($key)) {
        Write-Log "Cloud witness key missing - neither the design nor the interview supplied one" -Tag "Error"
        Write-Log "    By hand: Set-ClusterQuorum -CloudWitness -AccountName $account -AccessKey <key>" -Tag "Info"
        Write-Log "    Or put it on the witness card and export with secrets included" -Tag "Info"
        return $false
    }

    $endpoint = ([string](Get-ConfigText -InputObject $cloud -Name "endpoint" -Default "core.windows.net")).Trim()
    Write-Log "Configuring the cloud witness on '$account'" -Tag "Run"
    try {
        $parameters = @{ CloudWitness = $true; AccountName = $account; AccessKey = $key; ErrorAction = "Stop" }
        if ((-not [string]::IsNullOrWhiteSpace($endpoint)) -and ($endpoint -ne "core.windows.net")) { $parameters["Endpoint"] = $endpoint }
        $null = Set-ClusterQuorum @parameters
        Write-Log "Witness: storage account '$account'" -Tag "Ok"
        # Advice about a future operation, not a statement about this run - Debug is where
        # that belongs, and the docs carry the same sentence.
        Write-Log "    Rotating the key: point every cluster at the secondary first, then regenerate the primary" -Tag "Debug"
        return $true
    }
    catch {
        Write-Log "Cloud witness not configured: $($_.Exception.Message)" -Tag "Error"
        Write-Log "    Both nodes need outbound 443 to $account.blob.$endpoint - the proxy is WinHTTP's, not the browser's" -Tag "Info"
        return $false
    }
}

function Set-HypervS2dWitness {
    param(
        [Parameter(Mandatory)][object]$S2d,
        [Parameter(Mandatory)][object]$Hyperv,
        [object]$Plan = $null
    )

    if (Test-HypervS2dWitnessConfigured) {
        Write-Log "Cluster already has a witness - left as it is" -Tag "Info"
        return $true
    }

    $witness = Get-ConfigValue -InputObject $S2d -Name "witness"
    $type = [string](Get-ConfigText -InputObject $witness -Name "type" -Default "cloud")
    if ($type -eq "fileShare") {
        return (Set-HypervS2dFileShareWitness -S2d $S2d -Hyperv $Hyperv -Plan $Plan)
    }
    return (Set-HypervS2dCloudWitness -S2d $S2d -Plan $Plan)
}

# ---------------------------[ The witness persona ]---------------------------
# The whole job of the third machine: a folder, a share, and the right account granted on
# both the share and the NTFS below it - the classic failure is granting one of the two.
function Invoke-HypervS2dWitnessShare {
    param(
        [Parameter(Mandatory)][object]$S2d,
        [Parameter(Mandatory)][object]$Hyperv
    )

    $witness = Get-ConfigValue -InputObject $S2d -Name "witness"
    $fileShare = Get-ConfigValue -InputObject $witness -Name "fileShare"
    $shareName = ([string](Get-ConfigText -InputObject $fileShare -Name "shareName" -Default "")).Trim()
    $sharePath = ([string](Get-ConfigText -InputObject $fileShare -Name "sharePath" -Default "")).Trim()
    if ([string]::IsNullOrWhiteSpace($shareName) -or [string]::IsNullOrWhiteSpace($sharePath)) {
        return (New-RoleResult -Status "Failed" -Message "The witness design names no share name or no folder - fill both in on the witness card.")
    }

    $clusterName = Get-HypervS2dClusterName -S2d $S2d
    $domainKind = Test-HypervS2dDomainKind -Hyperv $Hyperv

    # DFS is refused outright rather than warned about: a replicated share can answer
    # for both sides of a partition at once, which is the one thing a witness must never do.
    if ($sharePath -match "(?i)^\\\\") {
        return (New-RoleResult -Status "Failed" -Message "The witness folder has to be a local path on this host - a UNC here usually means DFS, which is unsupported for a witness because replication can answer for both sides of a split.")
    }

    if (-not (Test-Path -LiteralPath $sharePath)) {
        try {
            $null = New-Item -ItemType Directory -Path $sharePath -Force -ErrorAction Stop
            Write-Log "Created '$sharePath'" -Tag "Debug"
        }
        catch {
            return (New-RoleResult -Status "Failed" -Message "The witness folder '$sharePath' could not be created: $($_.Exception.Message)")
        }
    }

    # Who gets the rights. Domain: the cluster's computer account, which exists only
    # after New-Cluster - so on a fresh design this run comes after the builder's first
    # pass, and says so instead of failing cryptically. Workgroup: a local account this
    # run creates, password typed at this console and again at the builder's.
    $grantee = ""
    if ($domainKind) {
        $grantee = "$clusterName$"
        $found = $false
        try {
            $account = New-Object System.Security.Principal.NTAccount($grantee)
            $null = $account.Translate([System.Security.Principal.SecurityIdentifier])
            $found = $true
        }
        catch { $found = $false }
        if (-not $found) {
            Write-Log "'$grantee' does not exist yet - it is created when the builder runs New-Cluster" -Tag "Warn"
            return (New-RoleResult -Status "ManualStepRequired" -Message "Run the builder node first so the cluster account exists, then run this host again - the share is granted to '$grantee' and there is nothing to grant yet.")
        }
    }
    else {
        $account = [string](Get-ConfigText -InputObject $fileShare -Name "localAccount" -Default "clusterwitness")
        $grantee = "$env:COMPUTERNAME\$account"
        $exists = $false
        try { $exists = (@(Get-LocalUser -Name $account -ErrorAction Stop).Count -gt 0) } catch { $exists = $false }
        if (-not $exists) {
            # The design's own password when it carries one - this account is created by
            # this design, so it is generated in the studio like every other account it
            # creates, and both the run that CREATES it here and the builder's
            # Set-ClusterQuorum credential read the same field. Absent (secrets not
            # exported), the console is asked and the same value has to be typed twice.
            $password = [string](Get-ConfigText -InputObject $fileShare -Name "password" -Default "")
            if (-not [string]::IsNullOrWhiteSpace($password)) {
                Write-Log "Creating '$account' with the password from the design" -Tag "Run"
            }
            elseif (-not (Test-HypervInterviewWanted)) {
                return (New-RoleResult -Status "ManualStepRequired" -Message "The witness account '$account' does not exist, the design carries no password for it, and this run has no console to ask at - export the design with secrets included, or run this again at the console.")
            }
            else {
                Write-Log "Creating the local account '$account'" -Tag "Run"
                Write-Log "    No password in the design, so it is asked here and must be typed identically at the builder" -Tag "Debug"
                $password = Read-HypervText -Prompt "Password for '$account' (type the same one at the builder's console later)" -Default ""
            }
            if ([string]::IsNullOrWhiteSpace($password)) {
                return (New-RoleResult -Status "ManualStepRequired" -Message "No password was typed, so the witness account was not created and the share was not granted.")
            }
            try {
                $secure = ConvertTo-SecureString -String $password -AsPlainText -Force
                $null = New-LocalUser -Name $account -Password $secure -PasswordNeverExpires -AccountNeverExpires -ErrorAction Stop
                Write-Log "'$account' exists - not an administrator" -Tag "Ok"
            }
            catch {
                return (New-RoleResult -Status "Failed" -Message "The witness account could not be created: $($_.Exception.Message)")
            }
        }
    }

    # The share, made once and adopted after. ~5 MB of quorum data, dedicated to this one
    # cluster - one share per cluster is the documented shape.
    $existing = $null
    try { $existing = Get-SmbShare -Name $shareName -ErrorAction Stop } catch { $existing = $null }
    if ($null -eq $existing) {
        Write-Log "Publishing '$shareName' at '$sharePath'" -Tag "Run"
        try {
            $null = New-SmbShare -Name $shareName -Path $sharePath -ChangeAccess $grantee -ErrorAction Stop
        }
        catch {
            return (New-RoleResult -Status "Failed" -Message "The share could not be created: $($_.Exception.Message)")
        }
    }
    else {
        Write-Log "Share '$shareName' exists - permissions checked, not rebuilt" -Tag "Info"
        try {
            $null = Grant-SmbShareAccess -Name $shareName -AccountName $grantee -AccessRight Change -Force -ErrorAction Stop
        }
        catch {
            Write-Log "Share grant not verified: $($_.Exception.Message)" -Tag "Warn"
        }
    }

    # NTFS as well - the half that gets forgotten, and the witness resource fails with
    # Access Denied when it is.
    try {
        $acl = Get-Acl -LiteralPath $sharePath -ErrorAction Stop
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $grantee, "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $sharePath -AclObject $acl -ErrorAction Stop
        Write-Log "'$grantee': Change on the share, Modify on the folder" -Tag "Ok"
    }
    catch {
        return (New-RoleResult -Status "Failed" -Message "The NTFS grant for '$grantee' failed: $($_.Exception.Message)")
    }

    # A share nothing can reach is not a witness. Windows Server blocks inbound SMB in
    # the profile a freshly built member server usually lands in, so the grants above are
    # correct and the cluster still cannot open the path - which surfaces at the BUILDER
    # as "not reachable from here", a message about a machine that is fine. Enabled here
    # rather than described, because this run is the one standing on the witness host.
    $null = Enable-HypervS2dFileSharingRule

    return (New-RoleResult -Status "Completed" -Message ("The witness share '\\{0}\{1}' is ready for the cluster '{2}'." -f $env:COMPUTERNAME, $shareName, $clusterName))
}

# The inbound half of SMB, which is the only firewall this design opens and the narrowest
# way to open it: the built-in "File and Printer Sharing" rule group, already present and
# merely disabled, rather than a rule of our own invention on port 445. Reported per
# profile so somebody can see it landed on the profile the cluster actually reaches this
# host over - a rule enabled on Domain while the adapter sits in Public is the shape of
# this that looks done and is not.
function Enable-HypervS2dFileSharingRule {
    if (-not (Get-Command -Name "Enable-NetFirewallRule" -ErrorAction SilentlyContinue)) {
        Write-Log "Firewall cmdlets unavailable - allow inbound File and Printer Sharing by hand" -Tag "Warn"
        return $false
    }

    $group = "File and Printer Sharing"
    $rules = @()
    try { $rules = @(Get-NetFirewallRule -DisplayGroup $group -ErrorAction Stop) }
    catch {
        Write-Log "'$group' firewall rules unreadable: $($_.Exception.Message)" -Tag "Warn"
        return $false
    }

    $disabled = @($rules | Where-Object { [string]$_.Enabled -ne "True" })
    if ($disabled.Count -eq 0) {
        Write-Log "Inbound '$group' is already allowed through the firewall" -Tag "Debug"
    }
    else {
        try {
            $null = Enable-NetFirewallRule -DisplayGroup $group -ErrorAction Stop
            Write-Log "Firewall: '$group' enabled - without it the share answers nothing" -Tag "Ok"
        }
        catch {
            Write-Log "'$group' firewall rules not enabled: $($_.Exception.Message)" -Tag "Warn"
            Write-Log "    Enable-NetFirewallRule -DisplayGroup '$group'" -Tag "Info"
            return $false
        }
    }

    # Which profile the cluster arrives on decides whether any of this helped, so it is
    # printed rather than assumed.
    try {
        $connections = @(Get-NetConnectionProfile -ErrorAction Stop)
        if ($connections.Count -gt 0) {
            Write-Log ("    Connections here: {0}" -f ((@($connections | ForEach-Object { "{0} ({1})" -f $_.InterfaceAlias, $_.NetworkCategory })) -join ", ")) -Tag "Info"
            foreach ($connection in @($connections | Where-Object { [string]$_.NetworkCategory -eq "Public" })) {
                # Set, not reported. On a workgroup server Public is an accident rather
                # than a decision - Windows files a network it cannot identify that way,
                # and with no domain here there is nothing to identify it - and it defeats
                # the rules enabled above in a way that is horrible to debug: Windows
                # ships the PUBLIC copy of those rules scoped to the local subnet, so a
                # cluster on another subnet is refused by a rule that reads as enabled.
                #
                # This host was named in the design as the witness and this script was run
                # on it deliberately, which is the same warrant under which the run
                # already created a local account, published a share, wrote two ACLs and
                # opened the firewall. Stopping short of the one setting that makes those
                # four work would be a checklist rather than a deployment.
                $alias = [string]$connection.InterfaceAlias
                try {
                    Set-NetConnectionProfile -InterfaceAlias $alias -NetworkCategory Private -ErrorAction Stop
                    Write-Log "'$alias': Public -> Private" -Tag "Ok"
                    Write-Log "    Revert: Set-NetConnectionProfile -InterfaceAlias '$alias' -NetworkCategory Public" -Tag "Info"
                }
                catch {
                    Write-Log "'$alias' is Public and could not be changed: $($_.Exception.Message)" -Tag "Warn"
                    Write-Log "    On Public the file sharing rules are scoped to the local subnet - a cluster elsewhere is refused by a rule that reads as enabled" -Tag "Warn"
                    Write-Log "    Set-NetConnectionProfile -InterfaceAlias '$alias' -NetworkCategory Private" -Tag "Warn"
                }
            }
        }
    }
    catch { }
    return $true
}

# ---------------------------[ Storage Spaces Direct ]---------------------------
# Switched on with -AutoConfig:$false for the same reason the single-node path does: left
# to itself it claims every eligible disk on both nodes, and the interview chose specific
# ones with wipe consent per disk. The pool and the tiers are then built deliberately.
function Enable-HypervS2dStorage {
    $state = Get-HypervClusterS2dState
    if ($state -eq "Enabled") {
        Write-Log "Storage Spaces Direct already on for this cluster" -Tag "Info"
        return $true
    }
    if (-not (Get-Command -Name "Enable-ClusterStorageSpacesDirect" -ErrorAction SilentlyContinue)) {
        Write-Log "This Windows has no Enable-ClusterStorageSpacesDirect" -Tag "Error"
        return $false
    }
    if (-not (Test-HypervDatacenterEdition)) {
        Write-Log "Storage Spaces Direct needs Windows Server Datacenter - this server is not running it" -Tag "Error"
        return $false
    }

    Write-Log "Enabling Storage Spaces Direct" -Tag "Run"
    try {
        $null = Enable-ClusterStorageSpacesDirect -AutoConfig:$false -Confirm:$false -ErrorAction Stop
    Write-Log "Storage Spaces Direct on" -Tag "Ok"
    }
    catch {
        Write-Log "Storage Spaces Direct not enabled: $($_.Exception.Message)" -Tag "Error"
        Write-Log "    Usually a disk that is not empty on one node" -Tag "Info"
        return $false
    }
    $null = Set-HypervGuestStorageTimeout
    return $true
}

# One pool spanning both nodes. StorageScaleUnit is the two-node fault domain: a copy per
# SERVER, which is the whole point - the single-node path's PhysicalDisk answer would let
# both copies of a mirror land on one machine.
function New-HypervS2dPool {
    param([Parameter(Mandatory)][string]$Name)

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

    # This node's interview named its disks; the peer's run named its own. The pool takes
    # everything poolable across the cluster, which after both interviews is exactly the
    # union of what was ticked - anything not ticked was never emptied and cannot pool.
    Write-Log ("Building the pool '{0}' from {1} disk(s) across both nodes" -f $Name, $poolable.Count) -Tag "Run"
    # Grouped, not one line per disk. Eight identical lines say exactly what one line
    # saying "8 x" says, and bury everything either side of them.
    $shapes = $poolable | Group-Object -Property { "{0}  {1} GB  {2}" -f $_.FriendlyName, [math]::Round($_.Size / 1GB), $_.MediaType }
    foreach ($shape in $shapes) {
        Write-Log ("    {0} x {1}" -f $shape.Count, $shape.Name) -Tag "Info"
    }

    try {
        $null = New-StoragePool -StorageSubSystemFriendlyName $subsystem.FriendlyName -FriendlyName $Name `
            -PhysicalDisks $poolable -ProvisioningTypeDefault Fixed -ResiliencySettingNameDefault Mirror `
            -FaultDomainAwarenessDefault StorageScaleUnit -ErrorAction Stop
        Write-Log "Pool '$Name' built - fault domain StorageScaleUnit" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "Pool not built: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

# The media type the tiers are declared against - one flat type is the shape this mode
# expects, and a mixed pool is reported rather than guessed at. Empty when every disk
# reports Unspecified - a virtual lab's Msft Virtual Disks carry no type - and the
# caller then labels the disks rather than the tier: a tier naming a type the pool does
# not hold makes every volume "insufficient eligible resources" (a resource costume on a
# filter mismatch, field-hit 2026-08-19, when the old fallback here guessed "SSD"), and
# a tier naming no type at all is refused outright - New-StorageTier answered "Invalid
# Parameter", field-hit 2026-08-20. Microsoft's documented templates always carry
# -MediaType, so the disks are brought to where the parameter can be honest.
function Get-HypervS2dPoolMediaType {
    param([Parameter(Mandatory)][object]$Pool)

    $media = @()
    try {
        $media = @($Pool | Get-PhysicalDisk -ErrorAction Stop | ForEach-Object { [string]$_.MediaType } |
            Where-Object { (-not [string]::IsNullOrWhiteSpace($_)) -and ($_ -ne "Unspecified") } | Select-Object -Unique)
    }
    catch { $media = @() }
    if ($media.Count -eq 1) { return $media[0] }
    if ($media.Count -gt 1) {
        Write-Log ("Pool mixes {0} - the nested tiers are declared against {1}" -f ($media -join " and "), $media[0]) -Tag "Warn"
        return $media[0]
    }
    return ""
}

# The nested tier templates. Windows Server 2022 and 2025 create them when
# Enable-ClusterStorageSpacesDirect runs with autoconfig on a two-node cluster - but this
# run switches autoconfig off, so they are created here, from Microsoft's documented
# parameters, and adopted when a template of the name already exists.
function New-HypervS2dTier {
    param(
        [Parameter(Mandatory)][object]$Pool,
        [Parameter(Mandatory)][string]$Resiliency
    )

    if ($Resiliency -eq "twoWayMirror") { return $true }
    $media = Get-HypervS2dPoolMediaType -Pool $Pool
    if ([string]::IsNullOrWhiteSpace($media)) {
        # The virtual lab shape: Hyper-V exposes no flash-or-rotational flag to a guest,
        # so every Msft Virtual Disk reports Unspecified. New-StorageTier refuses a
        # template without -MediaType ("Invalid Parameter", field-hit 2026-08-20), so
        # the pooled disks are labelled SSD - MSLab's own pattern, truthful for a lab
        # backed by host flash, and a label only: Set-PhysicalDisk writes pool metadata,
        # nothing checks the hardware. Pooled disks only - a primordial disk refuses.
    Write-Log "All pool disks report MediaType Unspecified - labelling them SSD" -Tag "Run"
        try {
            $null = $Pool | Get-PhysicalDisk -ErrorAction Stop | Set-PhysicalDisk -MediaType SSD -ErrorAction Stop
        }
        catch {
            Write-Log ("Pool disks not labelled SSD: {0}" -f $_.Exception.Message) -Tag "Error"
            return $false
        }
        $media = "SSD"
    }

    $wanted = @(
        [pscustomobject]@{
            Name = "NestedMirror"
            Parameters = @{
                StoragePoolFriendlyName = $Pool.FriendlyName
                FriendlyName            = "NestedMirror"
                ResiliencySettingName   = "Mirror"
                NumberOfDataCopies      = 4
                ErrorAction             = "Stop"
            }
        }
    )
    if ($Resiliency -eq "nestedParity") {
        $wanted += [pscustomobject]@{
            Name = "NestedParity"
            Parameters = @{
                StoragePoolFriendlyName = $Pool.FriendlyName
                FriendlyName            = "NestedParity"
                ResiliencySettingName   = "Parity"
                NumberOfDataCopies      = 2
                PhysicalDiskRedundancy  = 1
                NumberOfGroups          = 1
                FaultDomainAwareness    = "StorageScaleUnit"
                ColumnIsolation         = "PhysicalDisk"
                ErrorAction             = "Stop"
            }
        }
    }
    foreach ($tier in $wanted) { $tier.Parameters["MediaType"] = $media }

    foreach ($tier in $wanted) {
        $existing = $null
        try { $existing = Get-StorageTier -FriendlyName $tier.Name -ErrorAction Stop } catch { $existing = $null }
        if ($null -ne $existing) {
            # Adopted only when its media filter can be satisfied. A template declaring
            # a type no pool disk reports makes every volume against it fail with
            # "insufficient eligible resources" - the exact bench failure this guards
            # against recurring on a resumed run, where a mistyped template outlived
            # the code that made it.
            $declared = [string]$existing.MediaType
            $mismatch = ($declared -ne "Unspecified") -and (-not [string]::IsNullOrWhiteSpace($declared)) -and ($declared -ne $media)
            if (-not $mismatch) {
                Write-Log ("Tier template '{0}' already exists - left as it is" -f $tier.Name) -Tag "Info"
                continue
            }
            Write-Log ("Tier '{0}' declares MediaType {1}, which no pool disk reports - recreated to match" -f $tier.Name, $declared) -Tag "Warn"
            try { $null = Remove-StorageTier -FriendlyName $tier.Name -Confirm:$false -ErrorAction Stop }
            catch {
                Write-Log ("Tier '{0}' not removed: {1}" -f $tier.Name, $_.Exception.Message) -Tag "Error"
                return $false
            }
        }
        Write-Log ("Creating tier template '{0}'" -f $tier.Name) -Tag "Run"
        try {
            $parameters = $tier.Parameters
            $null = New-StorageTier @parameters
        }
        catch {
            Write-Log ("Tier '{0}' not created: {1}" -f $tier.Name, $_.Exception.Message) -Tag "Error"
            return $false
        }
    }
    return $true
}

# What one volume may hold, sized so every volume comes out equal and one drive's worth
# stays back for repairs - the same two rules the single-node plan states, priced for the
# chosen resiliency. Nested parity prices the mirror slice at four copies and the parity
# slice at two, which is what the nested layout physically writes.
function Get-HypervS2dVolumeShare {
    param(
        [Parameter(Mandatory)][object]$Pool,
        [Parameter(Mandatory)][string]$Resiliency,
        [Parameter(Mandatory)][int]$Count,
        [int]$MirrorPercent = 20
    )

    $free = 0
    try { $free = [long]$Pool.Size - [long]$Pool.AllocatedSize } catch { $free = 0 }
    if (($free -le 0) -or ($Count -lt 1)) { return [pscustomobject]@{ Total = [long]0; Mirror = [long]0; Parity = [long]0 } }

    $disks = @()
    try { $disks = @($Pool | Get-PhysicalDisk -ErrorAction Stop) } catch { $disks = @() }
    $largest = 0
    if ($disks.Count -gt 0) {
        $maximum = ($disks | Measure-Object -Property Size -Maximum).Maximum
        if ($null -ne $maximum) { $largest = [long]$maximum }
    }
    $reserve = 0
    if ($largest -gt 0) { $reserve = [long]$largest }

    $available = $free - $reserve
    if ($available -le 0) { $available = $free; $reserve = 0 }

    if ($Resiliency -eq "twoWayMirror") {
        $each = [long]([math]::Floor(($available / 2) / $Count / 1GB)) * 1GB
        return [pscustomobject]@{ Total = $each; Mirror = [long]0; Parity = [long]0 }
    }
    if ($Resiliency -eq "nestedMirror") {
        $each = [long]([math]::Floor(($available / 4) / $Count / 1GB)) * 1GB
        return [pscustomobject]@{ Total = $each; Mirror = [long]0; Parity = [long]0 }
    }

    # Nested mirror-accelerated parity. Per-node single parity across d disks stores at
    # (d-1)/d, and there are two nested copies of it - so a byte in the parity slice
    # costs 2d/(d-1) bytes of pool, and a byte in the mirror slice costs 4.
    $perNode = 4
    if ($disks.Count -gt 0) { $perNode = [int][math]::Max(4, [math]::Floor($disks.Count / 2)) }
    $parityFactor = (2.0 * $perNode) / ($perNode - 1)
    $fraction = [double]$MirrorPercent / 100.0
    $footprint = (4.0 * $fraction) + ($parityFactor * (1.0 - $fraction))
    $each = [long]([math]::Floor(($available / $footprint) / $Count / 1GB)) * 1GB
    $mirror = [long]([math]::Floor(($each * $fraction) / 1GB)) * 1GB
    if ($mirror -lt 1GB) { $mirror = 1GB }
    $parity = $each - $mirror
    if ($parity -lt 1GB) { $parity = 1GB }
    return [pscustomobject]@{ Total = $each; Mirror = $mirror; Parity = $parity }
}

# One volume, created and mounted in a single step - and the nested shapes have to name
# their tiers, because a default New-Volume on two nodes builds a plain two-way mirror
# however many nested templates exist beside it.
function New-HypervS2dVolume {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][object]$Pool,
        [Parameter(Mandatory)][string]$Resiliency,
        [Parameter(Mandatory)][object]$Share,
        [int]$AllocationUnitSize = 4096
    )

    $existing = $null
    try { $existing = Get-VirtualDisk -FriendlyName $Label -ErrorAction Stop } catch { $existing = $null }
    if ($null -ne $existing) {
        Write-Log "'$Label' already exists - left as it is" -Tag "Info"
        return (Join-Path -Path (Get-HypervClusterStorageFolder) -ChildPath $Label)
    }

    $parameters = @{
        StoragePoolFriendlyName = $Pool.FriendlyName
        FriendlyName            = $Label
        FileSystem              = "CSVFS_ReFS"
        AllocationUnitSize      = $AllocationUnitSize
        ErrorAction             = "Stop"
    }
    $shape = ""
    if ($Resiliency -eq "twoWayMirror") {
        # One failure survived is two copies said the way New-Volume accepts it - the
        # cmdlet has no -NumberOfDataCopies, unlike New-StorageTier below.
        $parameters["ResiliencySettingName"] = "Mirror"
        $parameters["PhysicalDiskRedundancy"] = 1
        if ([long]$Share.Total -gt 0) { $parameters["Size"] = [uint64]$Share.Total } else { $parameters["UseMaximumSize"] = $true }
        $shape = "two-way mirrored (one copy per node)"
    }
    elseif ($Resiliency -eq "nestedMirror") {
        $parameters["StorageTierFriendlyNames"] = @("NestedMirror")
        $parameters["StorageTierSizes"] = @([uint64]$Share.Total)
        $shape = "nested two-way mirrored (four copies, two per node)"
    }
    else {
        $parameters["StorageTierFriendlyNames"] = @("NestedMirror", "NestedParity")
        $parameters["StorageTierSizes"] = @([uint64]$Share.Mirror, [uint64]$Share.Parity)
        $shape = ("nested mirror-accelerated parity ({0} GB mirror in front of {1} GB parity)" -f
            [math]::Round($Share.Mirror / 1GB), [math]::Round($Share.Parity / 1GB))
    }

    Write-Log ("Creating '{0}' as a {1} ReFS Cluster Shared Volume" -f $Label, $shape) -Tag "Run"
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
        $null = Disable-StudioIntegrityStream -Path $path
        return $path
    }
    Write-Log "'$Label' was created but is not at '$path' - check C:\ClusterStorage for the name it took" -Tag "Warn"
    return ""
}

# ---------------------------[ Cluster-Aware Updating ]---------------------------
function Add-HypervS2dClusterUpdating {
    param([Parameter(Mandatory)][object]$S2d)

    if (-not [bool](Get-ConfigValue -InputObject $S2d -Name "cau" -Default $false)) { return $true }
    if (-not (Get-Command -Name "Add-CauClusterRole" -ErrorAction SilentlyContinue)) {
        Write-Log "Cluster-Aware Updating cmdlets missing - they ship with the RSAT-Clustering tools" -Tag "Warn"
        return $true
    }

    $name = Get-HypervS2dClusterName -S2d $S2d
    try {
        $existing = $null
        try { $existing = Get-CauClusterRole -ClusterName $name -ErrorAction Stop } catch { $existing = $null }
        if ($null -ne $existing) {
            Write-Log "Cluster-Aware Updating already configured" -Tag "Info"
            return $true
        }
        Write-Log "Adding Cluster-Aware Updating" -Tag "Run"
        $null = Add-CauClusterRole -ClusterName $name -MaxFailedNodes 0 -MaxRetriesPerNode 3 -EnableFirewallRules -Force -ErrorAction Stop
        Write-Log "Cluster-Aware Updating on - set its schedule in the CAU console" -Tag "Ok"
    }
    catch {
        Write-Log "Cluster-Aware Updating not configured: $($_.Exception.Message)" -Tag "Warn"
        Write-Log "    In a domain its virtual computer object needs the same OU grant the cluster itself needed" -Tag "Info"
    }
    return $true
}

# ---------------------------[ Health ]---------------------------
function Write-HypervS2dHealthReport {
    param([Parameter(Mandatory)][object]$S2d)

    Write-Log "Post-build checks:" -Tag "Info"

    # The core cluster group first, because it is the one failure the rest of this report
    # cannot see. Its IP address and network name are how anything reaches the cluster -
    # cluadmin, Windows Admin Center, a remote Get-Cluster - and the storage, the volumes
    # and the witness can all be perfectly healthy while it sits Offline. A run that ends
    # "the cluster is up" over that is wrong, so this one is not only reported: an offline
    # resource here is brought online.
    #
    # Found by GroupType rather than by name: 'Cluster Group' is the default name, and it
    # is both renameable and localised, while GroupType 'Cluster' is neither. The IP
    # address goes first because the network name depends on it - starting them the other
    # way round asks for a resource whose dependency is still down.
    try {
        $coreGroup = @(Get-ClusterGroup -ErrorAction Stop | Where-Object { [string]$_.GroupType -eq "Cluster" })[0]
        if ($null -ne $coreGroup) {
            $resources = @(Get-ClusterResource -ErrorAction Stop |
                Where-Object { [string]$_.OwnerGroup -eq [string]$coreGroup.Name } |
                Sort-Object -Property @{ Expression = { if ([string]$_.ResourceType -match "Address") { 0 } else { 1 } } }, Name)

            foreach ($resource in $resources) {
                if ([string]$resource.State -eq "Online") {
                    Write-Log ("    {0}: Online" -f [string]$resource.Name) -Tag "Ok"
                    continue
                }

                Write-Log ("    {0}: {1} - starting it" -f [string]$resource.Name, [string]$resource.State) -Tag "Warn"
                try {
                    $started = Start-ClusterResource -Name ([string]$resource.Name) -ErrorAction Stop
                    if ([string]$started.State -eq "Online") {
                        Write-Log ("    {0}: Online" -f [string]$resource.Name) -Tag "Ok"
                    }
                    else {
                        Write-Log ("    {0}: {1} after being started" -f [string]$resource.Name, [string]$started.State) -Tag "Error"
                        Write-Log ("        Get-ClusterResource '{0}' | Get-ClusterParameter, and the System log's FailoverClustering entries, say why" -f [string]$resource.Name) -Tag "Info"
                    }
                }
                catch {
                    Write-Log ("    {0} would not start: {1}" -f [string]$resource.Name, $_.Exception.Message) -Tag "Error"
                    Write-Log ("        Start-ClusterResource -Name '{0}'" -f [string]$resource.Name) -Tag "Info"
                }
            }
        }
    }
    catch {
        Write-Log "The core cluster group could not be read: $($_.Exception.Message)" -Tag "Warn"
    }

    try {
        $quorum = Get-ClusterQuorum -ErrorAction Stop
        $resource = ""
        if ($null -ne $quorum.QuorumResource) { $resource = [string]$quorum.QuorumResource.Name }
        if ([string]::IsNullOrWhiteSpace($resource)) {
            Write-Log "    witness: NONE - losing either node stops the cluster" -Tag "Warn"
        }
        else {
            Write-Log ("    witness: {0}" -f $resource) -Tag "Ok"
        }
    }
    catch { }

    try {
        $jobs = @(Get-StorageJob -ErrorAction Stop | Where-Object { [string]$_.JobState -ne "Completed" })
        if ($jobs.Count -gt 0) {
            Write-Log ("    storage jobs: {0} running" -f $jobs.Count) -Tag "Info"
        }
        else {
            Write-Log "    storage jobs: idle" -Tag "Ok"
        }
    }
    catch { }

    try {
        $unhealthy = @(Get-VirtualDisk -ErrorAction Stop | Where-Object { [string]$_.HealthStatus -ne "Healthy" })
        if ($unhealthy.Count -gt 0) {
            foreach ($disk in $unhealthy) {
                Write-Log ("    volume '{0}': {1}" -f $disk.FriendlyName, $disk.HealthStatus) -Tag "Warn"
            }
        }
        else {
            Write-Log "    volumes: healthy" -Tag "Ok"
        }
    }
    catch { }

    try {
        $networks = @(Get-ClusterNetwork -ErrorAction Stop)
        $partitioned = @()
        foreach ($network in $networks) {
            # State is the whole point of printing these, and it used to be printed at
            # Info whatever it said - so a storage network in Partitioned, which means
            # the nodes cannot reach each other on it at all, read exactly like a healthy
            # one. Field-hit 2026-08-18: both storage networks were Partitioned on a
            # cluster every other line called healthy.
            $state = [string]$network.State
            $tag = "Info"
            if ($state -match "(?i)partitioned|unavailable|down|failed") {
                $tag = "Warn"
                $partitioned += [string]$network.Name
            }
            Write-Log ("    cluster network '{0}': {1}, role {2}" -f $network.Name, $state, $network.Role) -Tag $tag
        }
        if ($partitioned.Count -gt 0) {
            Write-Log ("    {0} network(s) above are NOT carrying traffic between the nodes: {1}" -f $partitioned.Count, ($partitioned -join ", ")) -Tag "Warn"
                Write-Log "        Partitioned: each node has the adapter up and cannot reach the other over it, so S2D falls back to whatever is left, usually management" -Tag "Warn"
                Write-Log "        On a storage network that is nearly always the VLAN - the switch port, or a virtual host's switch, is not carrying the tag to both nodes" -Tag "Warn"
                Write-Log "        Test-NetConnection <peer storage address> -Port 445  from each node settles it" -Tag "Warn"
            # On a nested lab this is not advice, it is the answer - and it is a command
            # for a machine this script is not running on, which is exactly the kind of
            # step worth printing in full rather than describing.
            if (Test-HypervRunningVirtual) {
                $vlans = @(
                    [int](Get-ConfigValue -InputObject (Get-ConfigValue -InputObject $S2d -Name "networking") -Name "storageVlanA" -Default 711),
                    [int](Get-ConfigValue -InputObject (Get-ConfigValue -InputObject $S2d -Name "networking") -Name "storageVlanB" -Default 712)
                )
                Write-Log "        These nodes are virtual machines, so the switch in question is the PARENT host's - its ports are almost certainly untagged" -Tag "Warn"
                # The MAC addresses, because the names do not survive the trip. Inside the
                # guest these adapters are 'nic-storage-01'; on the parent they are VM
                # network adapters with names of the parent's own choosing, and the only
                # thing common to both views is the MAC. Printing it here turns a paragraph
                # of advice into something somebody can match against
                # Get-VMNetworkAdapter on the other machine.
                # The other cause, and it is not a VLAN at all: ATC puts one subnet on
                # the adapter called nic-storage-01 on EVERY node, so if the two nodes
                # renamed different physical adapters to that name - a different tick
                # order at the two interviews is enough - then one subnet lands on two
                # different switches and both storage networks partition with every
                # address, tag and grant looking correct.
                Write-Log "        Two causes look identical here; the MACs below tell them apart:" -Tag "Warn"
                Write-Log "            the parent's ports are untagged and drop the tagged frames, or" -Tag "Warn"
                Write-Log "            the same adapter NAME is on two DIFFERENT switches - ATC puts one subnet on 'nic-storage-01' everywhere, which alone partitions it" -Tag "Warn"
                Write-Log "        The parent knows these adapters by MAC, not by the names they carry here:" -Tag "Warn"
                $shown = 0
                foreach ($vlan in $vlans) {
                    if (($vlan -lt 10) -or ($vlan -gt 999)) { continue }
                    $prefix = "10.{0}.{1}." -f [math]::Floor($vlan / 10), ($vlan % 10)
                    foreach ($ip in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { ([string]$_.IPAddress).StartsWith($prefix) })) {
                        $mac = ""
                        try { $mac = [string](Get-NetAdapter -Name ([string]$ip.InterfaceAlias) -ErrorAction Stop).MacAddress } catch { $mac = "unknown" }
                        Write-Log ("            {0}   {1}   {2}   VLAN {3}" -f $env:COMPUTERNAME, [string]$ip.InterfaceAlias, $mac, $vlan) -Tag "Warn"
                        $shown++
                    }
                }
                if ($shown -eq 0) {
                    Write-Log "            (no address in the storage subnets here - the intent may not have addressed these adapters yet)" -Tag "Warn"
                }
                Write-Log "        On the PARENT host, per node, matching by that MAC - the VM does not need to be off:" -Tag "Warn"
                # -AllowedVlanIdList takes a STRING, not a list, whatever its name says:
                # unquoted, PowerShell binds 711,712 as an array and the cmdlet refuses
                # with "Cannot convert 'System.Object[]' to the type 'System.String'".
                # Printed wrong once, which cost a round trip on the bench.
                Write-Log ("        Get-VMNetworkAdapter -VMName <node> | Where-Object MacAddress -eq '<mac>' | Set-VMNetworkAdapterVlan -Trunk -AllowedVlanIdList '{0}' -NativeVlanId 0" -f ($vlans -join ",")) -Tag "Warn"
                Write-Log "        And check the crossing - same name, same switch, on both nodes:" -Tag "Warn"
                Write-Log "        Get-VMNetworkAdapter -VMName <node1>,<node2> | Format-Table VMName,Name,SwitchName,MacAddress" -Tag "Warn"
                Write-Log "        Then here:  Test-NetConnection <peer storage address> -Port 445" -Tag "Warn"
            }
        }
    }
    catch { }
    Write-Log "    Deeper: Get-StorageSubSystem Cluster* | Get-StorageHealthReport, and Get-SmbMultichannelConnection under load" -Tag "Info"
}

# ---------------------------[ Management certificate ]---------------------------
# WinRM over HTTPS on a workgroup cluster, with a real certificate rather than the
# self-signed one Windows makes for itself.
#
# WHAT THIS IS NOT: the certificate the CLUSTER uses. Windows Server 2025 authenticates
# node to node with self-signing PKU2U certificates it generates and rotates itself -
# that is what makes live migration work on a workgroup cluster without Kerberos, and
# there is nothing to configure, provision or renew for it. A publicly trusted
# certificate cannot take its place.
#
# What this IS: the certificate on the machine's own management endpoint, so remote
# management runs over 5986 with a name and a chain instead of NTLM over 5985. The
# cluster does not need it and does not care. Between two nodes there is no third party
# to convince either - so this is a lab-grade nicety by design, off unless asked for, and
# it exists because the shared certificate machinery was already here: Resolve-
# StudioCertificate hands back a thumbprint from ACME, an internal CA, a PFX or the
# store, and the nightly task already knows how to renew whatever a role holds.
function Get-HypervS2dManagementSection {
    param([object]$S2d)
    return (Get-ConfigValue -InputObject $S2d -Name "management")
}

# The name the certificate is for, and the name the listener answers on. The design's own
# suffix rather than this machine's guess, so it matches the name the other node resolves
# it by - the same reasoning the cluster cmdlets get their qualified names from.
function Get-HypervS2dNodeFqdn {
    param(
        [Parameter(Mandatory)][object]$S2d,
        [Parameter(Mandatory)][object]$Hyperv
    )

    $name = [string]$env:COMPUTERNAME
    $suffix = [string](Get-HypervS2dNodeSuffix -S2d $S2d -Hyperv $Hyperv)
    if ([string]::IsNullOrWhiteSpace($suffix)) { $suffix = [string]$env:USERDNSDOMAIN }
    if ([string]::IsNullOrWhiteSpace($suffix)) { return $name.ToLowerInvariant() }
    return ("{0}.{1}" -f $name, $suffix).ToLowerInvariant()
}

# A certificate this node makes for itself: both EKUs, its own name, and a life the
# design chooses. Microsoft's own workgroup-cluster walkthrough builds exactly this and
# then exchanges the public halves - see Sync-HypervS2dManagementTrust below.
#
# Idempotent by SUBJECT and lifetime rather than by thumbprint: a re-run that minted a
# second certificate for the same name every time would leave the store full of them and
# the listener pointing at whichever one was newest, which is how "it works until it
# doesn't" happens. One that is still good for a month is kept.
function New-HypervS2dSelfSignedCertificate {
    param(
        [Parameter(Mandatory)][object]$Certificate,
        [Parameter(Mandatory)][object]$S2d,
        [Parameter(Mandatory)][string]$Fqdn
    )

    $settings = Get-ConfigValue -InputObject $Certificate -Name "selfSigned"
    $years = [int](Get-ConfigValue -InputObject $settings -Name "years" -Default 5)
    if ($years -lt 1) { $years = 1 }
    if ($years -gt 20) { $years = 20 }

    # The cluster name rides in the SAN so the same certificate answers when somebody
    # reaches the node by the cluster's name - the walkthrough's own suggestion.
    $names = @($Fqdn)
    $clusterName = Get-HypervS2dClusterName -S2d $S2d
    $suffix = ""
    try { $suffix = ($Fqdn -split "\.", 2)[1] } catch { $suffix = "" }
    if (-not [string]::IsNullOrWhiteSpace($clusterName)) {
        if ([string]::IsNullOrWhiteSpace($suffix)) { $names += $clusterName.ToLowerInvariant() }
        else { $names += ("{0}.{1}" -f $clusterName, $suffix).ToLowerInvariant() }
    }

    $subject = "CN=$Fqdn"
    try {
        $existing = @(Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction Stop |
            Where-Object {
                ($_.Subject -eq $subject) -and
                ($_.NotAfter -gt (Get-Date).AddDays(30)) -and
                ($_.HasPrivateKey)
            } | Sort-Object -Property NotAfter -Descending)
        if ($existing.Count -gt 0) {
            Write-Log ("Keeping the certificate already here for '{0}' - valid to {1}" -f $Fqdn, $existing[0].NotAfter.ToString("yyyy-MM-dd")) -Tag "Info"
            return [string]$existing[0].Thumbprint
        }
    }
    catch { }

    Write-Log ("Issuing a self-signed certificate for {0} - {1} year(s)" -f ($names -join ", "), $years) -Tag "Run"
    try {
        # Both EKUs in one extension: server authentication for the listener, client
        # authentication so the same certificate can identify this node to the other one.
        $certificate = New-SelfSignedCertificate -Subject $subject -DnsName $names `
            -CertStoreLocation "Cert:\LocalMachine\My" -KeyAlgorithm RSA -KeyLength 2048 `
            -HashAlgorithm SHA256 -NotAfter ((Get-Date).AddYears($years)) `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2") -ErrorAction Stop
        Write-Log ("Issued {0} - valid to {1}" -f $certificate.Thumbprint, $certificate.NotAfter.ToString("yyyy-MM-dd")) -Tag "Ok"
        return [string]$certificate.Thumbprint
    }
    catch {
        Write-Log "The self-signed certificate could not be issued: $($_.Exception.Message)" -Tag "Error"
        return ""
    }
}

# The other half of a self-signed pair: each node's PUBLIC certificate in the other's
# Trusted Root, so the listener is trusted rather than merely encrypted. Only the public
# half moves - the private key never leaves the machine that made it. Run from the
# builder, because that is the leg that has the peer answering.
function Sync-HypervS2dManagementTrust {
    param(
        [Parameter(Mandatory)][object]$S2d,
        [Parameter(Mandatory)][object]$Hyperv,
        [Parameter(Mandatory)][string]$PeerName
    )

    $management = Get-HypervS2dManagementSection -S2d $S2d
    if ($null -eq $management) { return $true }
    if (-not [bool](Get-ConfigValue -InputObject $management -Name "winRmHttps" -Default $false)) { return $true }
    $certificate = Get-ConfigValue -InputObject $management -Name "certificate"
    if ([string](Get-ConfigText -InputObject $certificate -Name "source" -Default "selfSigned") -ne "selfSigned") { return $true }
    $settings = Get-ConfigValue -InputObject $certificate -Name "selfSigned"
    if (-not [bool](Get-ConfigValue -InputObject $settings -Name "trustPeer" -Default $true)) { return $true }

    $fqdn = Get-HypervS2dNodeFqdn -S2d $S2d -Hyperv $Hyperv
    $mine = @(Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction SilentlyContinue |
        Where-Object { ($_.Subject -eq "CN=$fqdn") -and $_.HasPrivateKey } | Sort-Object -Property NotAfter -Descending)
    if ($mine.Count -eq 0) {
        Write-Log "No management certificate on this node to hand to '$PeerName'" -Tag "Warn"
        return $false
    }

    Write-Log "Exchanging management certificates with '$PeerName' - public halves" -Tag "Run"
    $localBase64 = [Convert]::ToBase64String($mine[0].RawData)

    try {
        # Push ours, and bring theirs back in the same round trip.
        $peerBase64 = [string](Invoke-Command -ComputerName $PeerName -ErrorAction Stop -ScriptBlock {
            $incoming = [Convert]::FromBase64String([string]$using:localBase64)
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
            $store.Open("ReadWrite")
            $imported = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, $incoming)
            if (-not ($store.Certificates | Where-Object { $_.Thumbprint -eq $imported.Thumbprint })) {
                $store.Add($imported)
            }
            $store.Close()

            $own = @(Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction SilentlyContinue |
                Where-Object { ($_.Subject -like "CN=$($env:COMPUTERNAME)*") -and $_.HasPrivateKey } |
                Sort-Object -Property NotAfter -Descending)
            if ($own.Count -eq 0) { return "" }
            return [Convert]::ToBase64String($own[0].RawData)
        })
    }
    catch {
        Write-Log "The certificates could not be exchanged with '$PeerName': $($_.Exception.Message)" -Tag "Warn"
        Write-Log "    Without it -UseSSL needs -SessionOption (New-PSSessionOption -SkipCACheck)" -Tag "Info"
        return $false
    }

    if ([string]::IsNullOrWhiteSpace($peerBase64)) {
        Write-Log "'$PeerName' has no management certificate of its own yet - run this config there first" -Tag "Warn"
        return $false
    }

    try {
        $incoming = [Convert]::FromBase64String($peerBase64)
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
        $store.Open("ReadWrite")
        $peerCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, $incoming)
        if (-not ($store.Certificates | Where-Object { $_.Thumbprint -eq $peerCertificate.Thumbprint })) {
            $store.Add($peerCertificate)
        }
        $store.Close()
        Write-Log ("Peer trust set - {0} here, {1} there" -f $peerCertificate.Thumbprint, $mine[0].Thumbprint) -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "'$PeerName' certificate could not be trusted here: $($_.Exception.Message)" -Tag "Warn"
        return $false
    }
}

# The listener is replaced rather than edited: WSMan exposes it as one instance keyed by
# transport, and a thumbprint change on a live listener is not something it takes kindly.
function Set-HypervS2dWinRmListener {
    param(
        [Parameter(Mandatory)][string]$Thumbprint,
        [Parameter(Mandatory)][string]$Hostname
    )

    $existing = $null
    try { $existing = @(Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop | Where-Object { $_.Keys -contains "Transport=HTTPS" }) }
    catch { $existing = @() }

    foreach ($listener in @($existing)) {
        $current = ""
        try { $current = [string](Get-ChildItem -Path $listener.PSPath -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq "CertificateThumbprint" }).Value }
        catch { $current = "" }
        if ($current.Replace(" ", "").ToUpperInvariant() -eq $Thumbprint.ToUpperInvariant()) {
            Write-Log "WinRM already listens on 5986 with this certificate" -Tag "Info"
            return $true
        }
        try {
            $null = Remove-Item -Path $listener.PSPath -Recurse -Force -ErrorAction Stop
            Write-Log "Replaced the HTTPS listener - it carried $current" -Tag "Debug"
        }
        catch {
            Write-Log "The existing HTTPS listener could not be removed: $($_.Exception.Message)" -Tag "Error"
            return $false
        }
    }

    try {
        $null = New-WSManInstance -ResourceURI "winrm/config/Listener" `
            -SelectorSet @{ Address = "*"; Transport = "HTTPS" } `
            -ValueSet @{ Hostname = $Hostname; CertificateThumbprint = $Thumbprint } -ErrorAction Stop
        Write-Log "WinRM listens on 5986 as '$Hostname' - $Thumbprint" -Tag "Ok"
    }
    catch {
        Write-Log "The HTTPS listener could not be created: $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    # 5986 is not in the default rule set, so the listener would answer nothing.
    try {
        $rule = @(Get-NetFirewallRule -Name "WSRS-WinRM-HTTPS" -ErrorAction SilentlyContinue)
        if ($rule.Count -eq 0) {
            $null = New-NetFirewallRule -Name "WSRS-WinRM-HTTPS" -DisplayName "Windows Remote Management (HTTPS-In)" `
                -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5986 -Profile Any -ErrorAction Stop
            Write-Log "Inbound 5986 allowed" -Tag "Ok"
        }
    }
    catch {
        Write-Log "Inbound 5986 was not opened: $($_.Exception.Message)" -Tag "Warn"
        Write-Log "    New-NetFirewallRule -DisplayName 'WinRM HTTPS' -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow" -Tag "Warn"
    }
    return $true
}

function Set-HypervS2dManagementCertificate {
    param(
        [Parameter(Mandatory)][object]$S2d,
        [Parameter(Mandatory)][object]$Hyperv
    )

    $management = Get-HypervS2dManagementSection -S2d $S2d
    if ($null -eq $management) { return $true }
    if (-not [bool](Get-ConfigValue -InputObject $management -Name "winRmHttps" -Default $false)) { return $true }

    $certificate = Get-ConfigValue -InputObject $management -Name "certificate"
    if ($null -eq $certificate) {
        Write-Log "The management certificate is switched on and the design carries no certificate block" -Tag "Error"
        return $false
    }

    $source = [string](Get-ConfigText -InputObject $certificate -Name "source" -Default "selfSigned")
    $fqdn = Get-HypervS2dNodeFqdn -S2d $S2d -Hyperv $Hyperv
    Write-Log "Management certificate for '$fqdn' - source $source" -Tag "Run"

    $thumbprint = ""
    if ($source -eq "selfSigned") {
        # Not Resolve-StudioCertificate's business: every source it knows either fetches a
        # certificate from somewhere or finds one already in the store, and this one is
        # made here, for this node, out of nothing. Its lifetime is the design's to choose
        # precisely because no CA is involved - which is the opposite of the ACME source,
        # where 90 days is the CA's answer and there is nothing to ask.
        $thumbprint = [string](New-HypervS2dSelfSignedCertificate -Certificate $certificate -S2d $S2d -Fqdn $fqdn)
    }
    else {
        try { $thumbprint = [string](Resolve-StudioCertificate -Certificate $certificate) }
        catch {
            Write-Log "The management certificate could not be obtained: $($_.Exception.Message)" -Tag "Error"
            return $false
        }
    }
    if ([string]::IsNullOrWhiteSpace($thumbprint)) {
        Write-Log "No certificate for the management endpoint - the listener is left as it is" -Tag "Error"
        return $false
    }

    if (-not (Set-HypervS2dWinRmListener -Thumbprint $thumbprint -Hostname $fqdn)) { return $false }

    Write-Log "    Reach this node with: Enter-PSSession -ComputerName $fqdn -UseSSL -Credential (Get-Credential)" -Tag "Info"
    Write-Log "    The cluster's own node-to-node authentication is unaffected - that is PKU2U, which Windows issues and rotates itself" -Tag "Debug"
    return $true
}

# The nightly task's half. Same shape as the other roles': re-resolve, rebind if the
# thumbprint moved, say nothing loudly when nothing changed.
function Invoke-HypervS2dCertificateTask {
    param([object]$Config)

    $hyperv = Get-HypervSection -Config $Config
    $s2d = Get-HypervS2dSection -Hyperv $hyperv
    if ($null -eq $s2d) { return 0 }

    $management = Get-HypervS2dManagementSection -S2d $s2d
    if ($null -eq $management) { return 0 }
    if (-not [bool](Get-ConfigValue -InputObject $management -Name "winRmHttps" -Default $false)) { return 0 }

    if (Set-HypervS2dManagementCertificate -S2d $s2d -Hyperv $hyperv) { return 0 }
    return 1
}

# ---------------------------[ Storage link pairing ]---------------------------
# Which of this node's storage adapters is on the same wire as which of the peer's is a
# fact no node can read off itself. Nothing inside the machine knows: the device
# description ('Microsoft Hyper-V Network Adapter #4') is numbered per machine in arrival
# order, the MAC is random on a virtual NIC, and the interview's own order is whatever
# Get-NetAdapter enumerated on that node. Until now the first storage adapter enumerated
# on each node became VLAN 711, and whether the two 711 links met on the same segment was
# luck. On identical hardware they normally agree; in a lab where the two virtual machines
# were built at different times they need not, and the failure is silent - the cluster
# forms, the pool builds, and every byte of storage traffic quietly runs over the
# management network because that is the only path both nodes share.
#
# So it is measured instead. The only thing a node can observe is which remote MAC answers
# on a given interface, and there are two ways to ask:
#
#   ICMPv6 to ff02::1 - every interface joins all-nodes, so a multicast ping should list
#   every neighbour. It does not: 'File and Printer Sharing (Echo Request - ICMPv6-In)'
#   ships DISABLED on Windows Server, so a freshly built node answers nothing and a good
#   cable reads as no neighbour. Unusable without first changing firewall state on both.
#
#   ARP - not filtered by Windows Firewall at all, because it sits below the IP layer the
#   firewall inspects. Send anything at an address on the interface's subnet and the
#   neighbour cache holds the answering MAC whether or not the packet itself was allowed.
#
# Hence the probe below: link-local addresses, one subnet per LOCAL link so no source
# binding is needed (a subnet that exists on exactly one interface can only be reached
# through it), and BOTH subnets on every PEER link so exactly one candidate answers per
# subnet. Four ARP resolutions, no ICMP, no IPv6, no cluster, and the same behaviour on a
# nested vSwitch and a physical switch.
$script:hypervS2dProbePrefixLength = 24
# How many times the console may ask for the measurement to be run again before the run
# takes the last one. High enough that nobody hits it while re-seating a cable, low enough
# that a headless mistake cannot loop for ever.
$script:hypervS2dPairingAttempts = 10

function Get-HypervS2dProbeAddress {
    param(
        [Parameter(Mandatory)][int]$LinkIndex,
        [Parameter(Mandatory)][int]$HostPart
    )
    # 169.254.7.x for link 1, 169.254.8.x for link 2. Link-local by design: nothing
    # routes it, nothing else in the estate is on it, and a leftover address is harmless.
    return ("169.254.{0}.{1}" -f (6 + $LinkIndex), $HostPart)
}

function Add-HypervS2dProbeAddress {
    param(
        [Parameter(Mandatory)][string]$InterfaceAlias,
        [Parameter(Mandatory)][string]$Address
    )
    try {
        $existing = @(Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { [string]$_.IPAddress -eq $Address })
        if ($existing.Count -gt 0) { return $true }
        $null = New-NetIPAddress -InterfaceAlias $InterfaceAlias -IPAddress $Address `
            -PrefixLength $script:hypervS2dProbePrefixLength -SkipAsSource $true -ErrorAction Stop
        return $true
    }
    catch {
        Write-Log "Probe address $Address not set on '$InterfaceAlias': $($_.Exception.Message)" -Tag "Warn"
        return $false
    }
}

# DAD, and it cost two bench runs (2026-08-22). A freshly added IPv4 address is
# TENTATIVE while Windows ARPs to see whether anyone else owns it: in that state it does
# not answer ARP and cannot be used as a source. The links are measured in order, so link
# 1 was probed milliseconds after both nodes were addressed and came back blank, while
# link 2 - a second or two later, by which time everything was Preferred - measured
# perfectly. A blank first link on hardware that pings fine is this, not a cable.
function Wait-HypervS2dProbeAddressReady {
    param(
        [Parameter(Mandatory)][string[]]$Address,
        [int]$TimeoutSeconds = 10
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $pending = @($Address)
    while ((Get-Date) -lt $deadline) {
        $stillPending = @()
        foreach ($item in $pending) {
            $state = ""
            try {
                $entry = @(Get-NetIPAddress -IPAddress $item -AddressFamily IPv4 -ErrorAction SilentlyContinue)
                if ($entry.Count -gt 0) { $state = [string]$entry[0].AddressState }
            }
            catch { }
            if ($state -ne "Preferred") { $stillPending += $item }
        }
        if ($stillPending.Count -eq 0) { return $true }
        $pending = $stillPending
        Start-Sleep -Milliseconds 300
    }
    Write-Log ("Probe address(es) still not Preferred after {0}s: {1}" -f $TimeoutSeconds, ($pending -join ", ")) -Tag "Warn"
    return $false
}

function Remove-HypervS2dProbeAddress {
    param([Parameter(Mandatory)][string]$Address)
    try {
        $null = Get-NetIPAddress -IPAddress $Address -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    }
    catch { }
}

# What actually puts a packet on the wire, and the part that has to be exactly right.
#
# Two rules this has to satisfy at once, neither of which Test-Connection can:
#
#   The packet must leave through THIS link. Not "the interface the routing table would
#   pick" - the probe subnet exists on one interface, but the probe address carries
#   SkipAsSource, so automatic source selection walks past it. Binding the socket to the
#   source address settles both questions before the stack gets a say.
#
#   Nothing may need to answer at the IP layer. UDP to the discard port is never replied
#   to and is usually dropped by the peer's firewall, which is fine - the ARP exchange
#   that resolves the target's MAC happens underneath it either way, and that resolution
#   IS the measurement.
#
# This replaced `Test-Connection -TargetName` (2026-08-22): -TargetName is PowerShell 7
# only, so on 5.1 the call threw into the empty catch, no packet was sent, and every link
# reported "nothing answered on this wire" - a bench run's worth of a bug that read like
# a cabling fault.
function Send-HypervS2dProbePacket {
    param(
        [Parameter(Mandatory)][string]$SourceAddress,
        [Parameter(Mandatory)][string]$TargetAddress
    )

    $client = $null
    try {
        $endpoint = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($SourceAddress)), 0
        $client = New-Object System.Net.Sockets.UdpClient $endpoint
        $payload = [byte[]](1..8)
        $null = $client.Send($payload, $payload.Length, $TargetAddress, 9)
        return $true
    }
    catch {
        # ping.exe is the fallback rather than the primary: -S binds the source the same
        # way, but it needs the ICMP the peer may refuse, and its exit code says nothing
        # about the ARP that happened regardless.
        try {
            $null = & ping.exe -n 1 -w 500 -S $SourceAddress $TargetAddress 2>&1
            return $true
        }
        catch { return $false }
    }
    finally {
        if ($null -ne $client) { try { $client.Close() } catch { } }
    }
}

# The measurement itself. Anything at all is sent at the address - the reply does not
# matter and is usually refused - and the neighbour cache is then read for the MAC that
# answered the ARP underneath it.
function Get-HypervS2dNeighborMac {
    param(
        [Parameter(Mandatory)][int]$InterfaceIndex,
        [Parameter(Mandatory)][string]$Address,
        [Parameter(Mandatory)][string]$SourceAddress
    )

    $null = Send-HypervS2dProbePacket -SourceAddress $SourceAddress -TargetAddress $Address

    for ($attempt = 1; $attempt -le 5; $attempt++) {
        try {
            $entry = @(Get-NetNeighbor -InterfaceIndex $InterfaceIndex -IPAddress $Address -ErrorAction SilentlyContinue |
                Where-Object { @("Reachable", "Stale", "Delay", "Probe", "Permanent") -contains [string]$_.State })
            if ($entry.Count -gt 0) {
                $mac = ([string]$entry[0].LinkLayerAddress).Replace(":", "-").ToUpperInvariant()
                if (-not [string]::IsNullOrWhiteSpace($mac)) { return $mac }
            }
        }
        catch { }
        Start-Sleep -Milliseconds 400
        # The first ARP on a link that has just been addressed is regularly lost. Sending
        # again between reads costs nothing and is the difference between a measurement
        # and a coin toss.
        $null = Send-HypervS2dProbePacket -SourceAddress $SourceAddress -TargetAddress $Address
    }
    return ""
}

function Get-HypervS2dMacKey {
    param([string]$Mac)
    return (([string]$Mac) -replace "[^0-9A-Fa-f]", "").ToUpperInvariant()
}

# NOTE ON `return ,$array` IN THIS SECTION, because it cost a bench run (2026-08-22):
# that form suppresses unrolling so an empty or single-element result stays an array -
# right for a function whose result is assigned directly, and WRONG for one whose callers
# write @(Get-Thing). `@()` around a COMMAND collects its output stream, and the comma
# made that stream one item, so the caller ends up with a one-element array holding the
# real array. The symptom was a log line reading "Link System.Object[]: 'System.Object[]'
# reaches NO storage adapter". Everything here returns plainly and every caller wraps with
# @(), which is the combination that has one meaning.

# The peer's storage adapters. Read remotely rather than assumed: the member run has
# already applied its names and its plan file is gone.
#
# By name FIRST, then by address. The name is how this design labels them and is the
# reliable answer - but `renameTeamMembers` can be off, and then the peer's links still
# carry their original names and nothing matches the pattern. What they do carry either
# way is an address out of the storage subnets, because the member leg put one there
# before it stopped, so that is the fallback rather than a shrug.
function Get-HypervS2dPeerStorageAdapter {
    param(
        [Parameter(Mandatory)][string]$PeerName,
        [Parameter(Mandatory)][string]$NamePrefix,
        [string[]]$SubnetPrefix = @()
    )

    $pattern = "{0}-storage-*" -f $NamePrefix
    # Lifted into a local before the remote call, which is also what keeps the analyzer
    # from reading the parameter as unused - it cannot see through $using:.
    $subnets = @($SubnetPrefix)
    try {
        $found = @(Invoke-Command -ComputerName $PeerName -ErrorAction Stop -ScriptBlock {
            $namePattern = [string]$using:pattern
            $prefixes = @($using:subnets)
            $adapters = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue)
            $rows = @()
            foreach ($adapter in $adapters) {
                $addresses = @(Get-NetIPAddress -InterfaceIndex ([int]$adapter.ifIndex) -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                    ForEach-Object { [string]$_.IPAddress })
                $byName = ([string]$adapter.Name -like $namePattern)
                $byAddress = $false
                foreach ($address in $addresses) {
                    foreach ($prefix in $prefixes) {
                        if ((-not [string]::IsNullOrWhiteSpace($prefix)) -and $address.StartsWith($prefix)) { $byAddress = $true }
                    }
                }
                if (-not ($byName -or $byAddress)) { continue }
                $rows += [pscustomobject]@{
                    Name      = [string]$adapter.Name
                    Mac       = ([string]$adapter.MacAddress).Replace(":", "-").ToUpperInvariant()
                    IfIndex   = [int]$adapter.ifIndex
                    Status    = [string]$adapter.Status
                    ByName    = $byName
                }
            }
            return $rows
        })
    }
    catch {
        Write-Log "'$PeerName' did not answer with its storage adapters: $($_.Exception.Message)" -Tag "Warn"
        return @()
    }

    $named = @($found | Where-Object { $_.ByName })
    if ($named.Count -ge 2) { return @($named | Sort-Object -Property Name) }
    if ($found.Count -ge 2) {
        Write-Log "'$PeerName' has no adapter named '$pattern' - matched by address" -Tag "Info"
        return @($found | Sort-Object -Property Name)
    }
    return @($found)
}

# Returns one row per local storage link: the local adapter, and the peer adapter that
# answered on the same wire. A row with no peer adapter is a link with no path.
function Resolve-HypervS2dStorageLinkPairing {
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][string]$PeerName,
        [Parameter(Mandatory)][string]$NamePrefix
    )

    $localLinks = @()
    $index = 0
    foreach ($item in @($Plan.storageLinks)) {
        $index++
        $adapters = @(Resolve-HypervPlannedAdapter -Member @($item))
        if ($adapters.Count -eq 0) {
            Write-Log ("The storage link '{0}' from the plan is not on this node any more" -f [string]$item.name) -Tag "Warn"
            continue
        }
        $localLinks += [pscustomobject]@{
            Index   = $index
            Name    = [string]$adapters[0].Name
            Mac     = ([string]$adapters[0].MacAddress).Replace(":", "-").ToUpperInvariant()
            IfIndex = [int]$adapters[0].ifIndex
            Vlan    = [int]$item.vlan
        }
    }
    if ($localLinks.Count -lt 2) { return @() }

    # The subnets the member leg addressed its links out of - the fallback the lookup
    # uses when the peer's adapters were never renamed.
    $subnetPrefix = @()
    foreach ($link in $localLinks) {
        $sample = Get-HypervS2dStorageAddress -Vlan $link.Vlan -NodeNumber 1
        if (-not [string]::IsNullOrWhiteSpace($sample)) {
            $parts = @($sample -split "\.")
            if ($parts.Count -eq 4) { $subnetPrefix += ("{0}.{1}.{2}." -f $parts[0], $parts[1], $parts[2]) }
        }
    }

    $peerLinks = @(Get-HypervS2dPeerStorageAdapter -PeerName $PeerName -NamePrefix $NamePrefix -SubnetPrefix $subnetPrefix)
    if ($peerLinks.Count -lt 2) {
        Write-Log "'$PeerName' reports fewer than two storage adapters - the pairing cannot be measured" -Tag "Warn"
        return @()
    }

    Write-Log "Measuring the storage links - link-local ARP probe on each" -Tag "Run"

    # Every peer link carries an address in BOTH probe subnets, so each local link finds
    # exactly one candidate it can reach and the answer is unambiguous.
    $peerProbes = @()
    for ($j = 0; $j -lt $peerLinks.Count; $j++) {
        foreach ($linkIndex in 1..$localLinks.Count) {
            $peerProbes += [pscustomobject]@{
                Name    = $peerLinks[$j].Name
                Mac     = $peerLinks[$j].Mac
                Address = (Get-HypervS2dProbeAddress -LinkIndex $linkIndex -HostPart (20 + $j + 1))
            }
        }
    }

    $localProbes = @()
    $pairs = @()
    try {
        try {
            $remote = @($peerProbes | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Address = $_.Address } })
            $prefixLength = $script:hypervS2dProbePrefixLength
            # Counted, not assumed: a probe address that never landed on the peer makes
            # every local link look unreachable, which is the same symptom as a dead wire.
            $placed = @(Invoke-Command -ComputerName $PeerName -ErrorAction Stop -ScriptBlock {
                $remoteProbes = @($using:remote)
                $remotePrefix = [int]$using:prefixLength
                $done = @()
                foreach ($probe in $remoteProbes) {
                    $have = @(Get-NetIPAddress -InterfaceAlias ([string]$probe.Name) -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                        Where-Object { [string]$_.IPAddress -eq [string]$probe.Address })
                    if ($have.Count -eq 0) {
                        $null = New-NetIPAddress -InterfaceAlias ([string]$probe.Name) -IPAddress ([string]$probe.Address) `
                            -PrefixLength $remotePrefix -SkipAsSource $true -ErrorAction SilentlyContinue
                        $have = @(Get-NetIPAddress -InterfaceAlias ([string]$probe.Name) -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                            Where-Object { [string]$_.IPAddress -eq [string]$probe.Address })
                    }
                    if ($have.Count -gt 0) { $done += ("{0} {1}" -f [string]$probe.Name, [string]$probe.Address) }
                }
                # Same DAD wait as the local side, on the node that has to ANSWER: a
                # tentative address is silent, and a silent peer reads as a dead wire.
                $deadline = (Get-Date).AddSeconds(10)
                while ((Get-Date) -lt $deadline) {
                    $pending = @()
                    foreach ($probe in $remoteProbes) {
                        $entry = @(Get-NetIPAddress -IPAddress ([string]$probe.Address) -AddressFamily IPv4 -ErrorAction SilentlyContinue)
                        if (($entry.Count -eq 0) -or ([string]$entry[0].AddressState -ne "Preferred")) { $pending += [string]$probe.Address }
                    }
                    if ($pending.Count -eq 0) { break }
                    Start-Sleep -Milliseconds 300
                }
                return $done
            })
            Write-Log ("'{0}': {1} of {2} probe address(es) in place" -f $PeerName, $placed.Count, $remote.Count) -Tag "Debug"
            if ($placed.Count -lt $remote.Count) {
                Write-Log ("'{0}' took {1} of {2} probe addresses - the links it refused cannot answer" -f $PeerName, $placed.Count, $remote.Count) -Tag "Warn"
            }
        }
        catch {
            Write-Log "The probe addresses could not be put on '$PeerName': $($_.Exception.Message)" -Tag "Warn"
            return @()
        }

        foreach ($link in $localLinks) {
            $address = Get-HypervS2dProbeAddress -LinkIndex $link.Index -HostPart 10
            if (Add-HypervS2dProbeAddress -InterfaceAlias $link.Name -Address $address) { $localProbes += $address }
            else { Write-Log "'$($link.Name)' has no probe address - this link cannot be measured" -Tag "Warn" }
        }
        if ($localProbes.Count -gt 0) { $null = Wait-HypervS2dProbeAddressReady -Address $localProbes }

        foreach ($link in $localLinks) {
            $candidates = @($peerProbes | Where-Object { ([string]$_.Address).StartsWith(("169.254.{0}." -f (6 + $link.Index))) })
            $source = Get-HypervS2dProbeAddress -LinkIndex $link.Index -HostPart 10
            $match = $null
            foreach ($candidate in $candidates) {
                $answered = Get-HypervS2dNeighborMac -InterfaceIndex $link.IfIndex -Address $candidate.Address -SourceAddress $source
                if ([string]::IsNullOrWhiteSpace($answered)) { continue }
                if ((Get-HypervS2dMacKey -Mac $answered) -eq (Get-HypervS2dMacKey -Mac $candidate.Mac)) {
                    if ($null -ne $match) {
                        # Both of the peer's links answered on one interface, so the two
                        # "links" share one broadcast domain. That is a cabling or VLAN
                        # fault of its own, and picking one silently would hide it.
                        Write-Log ("'{0}' reaches BOTH of the peer's storage adapters - the two storage networks are one segment" -f $link.Name) -Tag "Warn"
                        $match = $null
                        break
                    }
                    $match = $candidate
                }
            }
            $pairs += [pscustomobject]@{
                Index    = $link.Index
                Vlan     = $link.Vlan
                Local    = $link.Name
                LocalMac = $link.Mac
                Peer     = $(if ($null -ne $match) { [string]$match.Name } else { "" })
                PeerMac  = $(if ($null -ne $match) { [string]$match.Mac } else { "" })
            }
        }
    }
    finally {
        foreach ($address in $localProbes) { Remove-HypervS2dProbeAddress -Address $address }
        try {
            $cleanup = @($peerProbes | ForEach-Object { [string]$_.Address })
            $null = Invoke-Command -ComputerName $PeerName -ErrorAction SilentlyContinue -ScriptBlock {
                $remoteCleanup = @($using:cleanup)
                foreach ($probeAddress in $remoteCleanup) {
                    Get-NetIPAddress -IPAddress $probeAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                        Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
                }
            }
        }
        catch { }
    }

    return $pairs
}

# The measurement drawn on the screen that asks about it. A menu clears what came before
# it, so logging the pairing and then asking is asking somebody to confirm something they
# can no longer see - which is exactly what it did on the bench. PreItems redraws the
# table above the menu on every keypress instead.
#
# Deliberately NOT .GetNewClosure(), for the reason the switch panel records: a closure
# binds the scriptblock to a fresh dynamic module, and on 5.1 a module scope cannot see
# functions defined at script scope. The rows travel in script scope instead.
$script:hypervS2dPairingRows = @()

function Write-HypervS2dPairingPanel {
    $rows = @($script:hypervS2dPairingRows)
    if ($rows.Count -eq 0) { return }

    Write-Host ""
    Write-Studio -Text "  measured pairing" -Key "muted"
    # Two lines per link, the second indented under the first, so the pair reads as one
    # thing and the adapter names line up in a column.
    foreach ($row in $rows) {
        $lead = ("  Link {0}" -f $row.Index).PadRight(11)
        Write-Studio -Text ("{0}{1}{2}  ({3})" -f $lead, "this node ".PadRight(12), $row.Local, $row.LocalMac) -Key "fg"
        if ([string]::IsNullOrWhiteSpace($row.Peer)) {
            Write-Studio -Text ("{0}{1}nothing answered on this wire" -f "".PadRight(11), "other node".PadRight(12)) -Key "danger"
        }
        else {
            Write-Studio -Text ("{0}{1}{2}  ({3})" -f "".PadRight(11), "other node".PadRight(12), $row.Peer, $row.PeerMac) -Key "success"
        }
    }
    Write-Host ""
}

# What was measured, said plainly, and the chance to overrule it where somebody is
# watching. A headless leg accepts the measurement - it is evidence, not a guess.
function Confirm-HypervS2dStorageLinkPairing {
    param([Parameter(Mandatory)][object[]]$Pairing)

    # Belt and braces after the unrolling bug above: a row that is not a row is dropped
    # rather than rendered as its type name.
    $Pairing = @($Pairing | Where-Object { ($null -ne $_) -and ($null -ne $_.Local) })
    if ($Pairing.Count -eq 0) {
        Write-Log "The pairing came back empty - the storage links are left named as they are" -Tag "Warn"
        return @()
    }

    foreach ($pair in $Pairing) {
        if ([string]::IsNullOrWhiteSpace($pair.Peer)) {
            Write-Log ("Link {0}: '{1}' reaches NO storage adapter on the other node" -f $pair.Index, $pair.Local) -Tag "Error"
        }
        else {
            Write-Log ("Link {0}: '{1}' <-> '{2}'" -f $pair.Index, $pair.Local, $pair.Peer) -Tag "Ok"
        }
    }

    if (-not (Test-HypervInterviewWanted)) { return $Pairing }

    $script:hypervS2dPairingRows = @($Pairing)
    $panel = { Write-HypervS2dPairingPanel }

    $answer = Read-HypervChoice -Title "Storage link pairing" -Heading "Is this how the links are cabled?" `
        -Hint "Measured with an ARP probe on each link - the peer adapter named is the one that answered on that wire." `
        -PreItems $panel `
        -Items @(
            [pscustomobject]@{ Id = "accept"; Label = "Accept the measurement"; Detail = @("The peer's adapters are renamed to match if they do not already") },
            [pscustomobject]@{ Id = "again";  Label = "Measure again"; Detail = @("After fixing a cable, a switch port or a VLAN - nothing is changed until you accept") },
            [pscustomobject]@{ Id = "swap";   Label = "Swap the peer's two links"; Detail = @("Use when you know the measurement is wrong") }
        )

    # $null, not an empty array, and the caller tells the two apart: empty means there is
    # nothing to act on, $null means measure the same thing over.
    if ($answer -eq "again") {
        Write-Log "Measuring the links again at the console" -Tag "Info"
        return $null
    }
    if ($answer -ne "swap") { return $Pairing }

    if ($Pairing.Count -ge 2) {
        $first = [string]$Pairing[0].Peer
        $firstMac = [string]$Pairing[0].PeerMac
        $Pairing[0].Peer = [string]$Pairing[1].Peer
        $Pairing[0].PeerMac = [string]$Pairing[1].PeerMac
        $Pairing[1].Peer = $first
        $Pairing[1].PeerMac = $firstMac
        Write-Log "The peer's two links were swapped by hand at the console" -Tag "Warn"
    }
    return $Pairing
}

# The peer's adapter names are made to match the wire: the adapter that answered on this
# node's link 1 becomes the peer's link-1 name. ATC matches adapters across nodes BY NAME
# and checks only that the names exist on both, which is exactly why a crossed pair passes
# its validation - so the names have to carry the truth before an intent is declared.
function Set-HypervS2dPeerStorageLinkOrder {
    param(
        [Parameter(Mandatory)][object[]]$Pairing,
        [Parameter(Mandatory)][string]$PeerName
    )

    $wanted = @()
    foreach ($pair in $Pairing) {
        if ([string]::IsNullOrWhiteSpace($pair.Peer)) { continue }
        $wanted += [pscustomobject]@{ Mac = [string]$pair.PeerMac; Name = [string]$pair.Local }
    }
    if ($wanted.Count -eq 0) { return $false }

    $needsChange = $false
    foreach ($pair in $Pairing) {
        if ((-not [string]::IsNullOrWhiteSpace($pair.Peer)) -and ($pair.Peer -ne $pair.Local)) { $needsChange = $true }
    }
    if (-not $needsChange) {
        Write-Log "Peer storage adapter names already match the wires" -Tag "Info"
        return $true
    }

    Write-Log "Renaming the peer's storage adapters to match the wires" -Tag "Run"
    try {
        # Through a placeholder, because the two names are being exchanged and Windows
        # refuses a rename onto a name another adapter still holds.
        $applied = @(Invoke-Command -ComputerName $PeerName -ErrorAction Stop -ScriptBlock {
            $map = @($using:wanted)
            $done = @()
            $index = 0
            foreach ($item in $map) {
                $index++
                $adapter = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
                    Where-Object { (([string]$_.MacAddress) -replace "[^0-9A-Fa-f]", "").ToUpperInvariant() -eq (([string]$item.Mac) -replace "[^0-9A-Fa-f]", "").ToUpperInvariant() })
                if ($adapter.Count -eq 0) { continue }
                $null = Rename-NetAdapter -Name ([string]$adapter[0].Name) -NewName ("wsrs-pairing-{0}" -f $index) -ErrorAction SilentlyContinue
            }
            $index = 0
            foreach ($item in $map) {
                $index++
                $temporary = "wsrs-pairing-{0}" -f $index
                $adapter = @(Get-NetAdapter -Name $temporary -ErrorAction SilentlyContinue)
                if ($adapter.Count -eq 0) { continue }
                $null = Rename-NetAdapter -Name $temporary -NewName ([string]$item.Name) -ErrorAction SilentlyContinue
                $done += ("{0} = {1}" -f [string]$item.Name, [string]$item.Mac)
            }
            return $done
        })
        if ($applied.Count -gt 0) {
            Write-Log ("'{0}': {1}" -f $PeerName, ($applied -join ", ")) -Tag "Ok"
            Write-Log "    Its addresses are re-applied by name a few steps below, so they follow the rename" -Tag "Debug"
        }
        return $true
    }
    catch {
        Write-Log "The peer's storage adapters could not be renamed: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

# A rename moves the name and leaves the address where it was, so for the moments between
# the two the peer's link carries the wrong subnet for its new name - and Test-Cluster,
# which runs a few steps later, would see exactly that. The interim addresses are
# therefore re-applied by name the instant the rename lands, rather than waiting for the
# addressing step after the intents.
function Set-HypervS2dPeerInterimAddress {
    param(
        [Parameter(Mandatory)][object]$S2d,
        [Parameter(Mandatory)][object[]]$Pairing,
        [Parameter(Mandatory)][string]$PeerName
    )

    $names = @(Get-HypervS2dNodeName -S2d $S2d)
    $label = Get-HypervS2dHostLabel -Name $PeerName
    $position = 0
    for ($index = 0; $index -lt $names.Count; $index++) {
        if ((Get-HypervS2dHostLabel -Name $names[$index]).Equals($label, [System.StringComparison]::OrdinalIgnoreCase)) { $position = $index + 1; break }
    }
    if ($position -eq 0) { return $false }

    $links = @()
    foreach ($pair in $Pairing) {
        if ([string]::IsNullOrWhiteSpace($pair.Peer)) { continue }
        $address = Get-HypervS2dStorageAddress -Vlan ([int]$pair.Vlan) -NodeNumber $position -Interim
        if ([string]::IsNullOrWhiteSpace($address)) { continue }
        $links += [pscustomobject]@{ Name = [string]$pair.Local; Address = $address }
    }
    if ($links.Count -eq 0) { return $false }

    try {
        $applied = @(Invoke-Command -ComputerName $PeerName -ErrorAction Stop -ScriptBlock {
            $remoteLinks = @($using:links)
            $done = @()
            foreach ($link in $remoteLinks) {
                $alias = [string]$link.Name
                $wanted = [string]$link.Address
                $have = @(Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                    Where-Object { [string]$_.IPAddress -eq $wanted })
                if ($have.Count -eq 0) {
                    Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                        Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
                    $null = Set-NetIPInterface -InterfaceAlias $alias -Dhcp Disabled -ErrorAction SilentlyContinue
                    $null = New-NetIPAddress -InterfaceAlias $alias -IPAddress $wanted -PrefixLength 24 -ErrorAction SilentlyContinue
                }
                $null = Set-DnsClient -InterfaceAlias $alias -RegisterThisConnectionsAddress $false -ErrorAction SilentlyContinue
                $done += ("{0} = {1}" -f $alias, $wanted)
            }
            return $done
        })
        if ($applied.Count -gt 0) {
            Write-Log ("'{0}' re-addressed to follow the rename: {1}" -f $PeerName, ($applied -join ", ")) -Tag "Ok"
        }
        return $true
    }
    catch {
        Write-Log "The peer's storage addresses could not be re-applied after the rename: $($_.Exception.Message)" -Tag "Warn"
        Write-Log "    Test-Cluster will report the storage networks as unreachable until they are" -Tag "Warn"
        return $false
    }
}

# Which address this machine would send from to reach a given one, and out of which
# interface. Find-NetRoute answers both: it hands back the source MSFT_NetIPAddress it
# would select together with the route, which is the same decision the socket makes.
#
# This exists because a check that only asks "did it answer" cannot tell a dead storage
# link from a live one being tested over the wrong network. Bench, 2026-08-23: the
# storage probe left the MANAGEMENT address and was seen crossing the firewall on its
# way to the peer's storage address - it can only have been the firewall's problem to
# answer, and the run reported it as "does NOT answer on 445". Traffic on a storage
# subnet that is wired correctly never reaches a router at all.
function Get-HypervS2dPathSource {
    param([Parameter(Mandatory)][string]$Address)

    $result = [pscustomobject]@{ Source = ""; InterfaceAlias = ""; InterfaceIndex = 0 }

    $found = @()
    try { $found = @(Find-NetRoute -RemoteIPAddress $Address -ErrorAction Stop) }
    catch { return $result }

    foreach ($entry in $found) {
        $value = ""
        try { $value = [string]$entry.IPAddress } catch { $value = "" }
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        $result.Source = $value
        try { $result.InterfaceIndex = [int]$entry.InterfaceIndex } catch { }
        break
    }

    if ($result.InterfaceIndex -gt 0) {
        try {
            $result.InterfaceAlias = [string](@(Get-NetIPInterface -InterfaceIndex $result.InterfaceIndex `
                -AddressFamily IPv4 -ErrorAction Stop)[0].InterfaceAlias)
        }
        catch { }
    }
    return $result
}

# An adapter bound into a Hyper-V switch cannot carry a host address of its own: the
# protocol stack is unbound from it and the host talks through a vNIC instead. `vms_pp`
# is the switch protocol binding, and its being enabled is the crisp form of the
# question. This is the shape the ATC lane fails in - ATC rebuilds the storage adapters
# into a SET switch and puts the host's storage addresses on the vSMB vNICs it creates,
# so an address left on the adapter itself is configured, visible in Get-NetIPAddress,
# and inert.
function Test-HypervS2dAdapterInSwitch {
    param([Parameter(Mandatory)][string]$Name)

    try {
        $binding = @(Get-NetAdapterBinding -Name $Name -ComponentID "vms_pp" -ErrorAction Stop)
        if ($binding.Count -eq 0) { return $false }
        return [bool]$binding[0].Enabled
    }
    catch {
        # Silence here reads as "not in a switch", which is a finding rather than a
        # failure to look - and the two sent a bench run down the wrong path once.
        Write-Log ("    The switch binding of '{0}' could not be read: {1}" -f $Name, $_.Exception.Message) -Tag "Debug"
        return $false
    }
}

# The facts that decide why a Preferred address is not the source: whether the interface is
# connected at all (a disconnected one keeps its address and loses its routes), what metric
# it carries, whether the address is marked SkipAsSource, and whether the on-link route for
# its own subnet exists. Printed rather than interpreted - the run does not know which of
# them is the fault, and a log that guesses is worse than one that lists.
# The /24 an address sits in, as a route table would name it. The storage subnets are /24
# by construction - Get-HypervS2dStorageAddress derives them that way.
function Get-HypervS2dSubnetPrefix {
    # Not Mandatory on purpose: PowerShell counts an EMPTY STRING as a missing mandatory
    # argument and prompts for it, which in a headless run is a stall with no output. The
    # callers can legitimately hold "" here.
    param([string]$Address = "")

    if ([string]::IsNullOrWhiteSpace($Address)) { return "" }
    $parts = @($Address -split "\.")
    if ($parts.Count -ne 4) { return "" }
    return ("{0}.{1}.{2}.0/24" -f $parts[0], $parts[1], $parts[2])
}

function Write-HypervS2dInterfaceFact {
    # Same reason as Get-HypervS2dSubnetPrefix: empty is a value here, not an omission.
    param(
        [string]$Address = "",
        [string]$Prefix = ""
    )

    if ([string]::IsNullOrWhiteSpace($Address) -or [string]::IsNullOrWhiteSpace($Prefix)) { return }

    $entry = $null
    try {
        $entry = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { [string]$_.IPAddress -eq $Address })[0]
    }
    catch { $entry = $null }
    if ($null -eq $entry) { return }

    $alias = [string]$entry.InterfaceAlias
    Write-Log ("    {0}: SkipAsSource {1}, prefix /{2}" -f $Address, [bool]$entry.SkipAsSource, [int]$entry.PrefixLength) -Tag "Error"

    try {
        $interface = @(Get-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction Stop)[0]
        Write-Log ("    '{0}': ConnectionState {1}, metric {2}, Dhcp {3}, Forwarding {4}" -f $alias,
            [string]$interface.ConnectionState, [int]$interface.InterfaceMetric,
            [string]$interface.Dhcp, [string]$interface.Forwarding) -Tag "Error"
        if ([string]$interface.ConnectionState -ne "Connected") {
            Write-Log "    A disconnected interface keeps its address and loses its routes - that alone produces this" -Tag "Error"
        }
    }
    catch { }

    try {
        $adapter = @(Get-NetAdapter -Name $alias -ErrorAction Stop)[0]
        Write-Log ("    '{0}': Status {1}, MediaConnectionState {2}, VLAN {3}" -f $alias,
            [string]$adapter.Status, [string]$adapter.MediaConnectionState, [string]$adapter.VlanID) -Tag "Error"
    }
    catch { }

    try {
        $routes = @(Get-NetRoute -DestinationPrefix $Prefix -AddressFamily IPv4 -ErrorAction Stop)
        if ($routes.Count -eq 0) {
            Write-Log ("    No route for {0} at all - which is why the default one is being used" -f $Prefix) -Tag "Error"
        }
        else {
            foreach ($route in $routes) {
                Write-Log ("    Route {0} via '{1}', metric {2}" -f $Prefix, [string]$route.InterfaceAlias, [int]$route.RouteMetric) -Tag "Error"
            }
        }
    }
    catch { }
}

# The other half of the same question, asked on the machine that did not answer. A probe
# that left the right interface and got nothing back is not evidence about this node at
# all: the address may not be up over there, SMB may not be listening on it, or - the one
# that costs the most time - the interface may have landed on the **Public** firewall
# profile, where File and Printer Sharing is blocked and the symptom is exactly this
# silence. A peer that refuses the session gets the paste-ready lines instead.
function Write-HypervS2dPeerStorageFact {
    param(
        [string]$PeerName = "",
        [string]$Address = ""
    )

    if ([string]::IsNullOrWhiteSpace($PeerName) -or [string]::IsNullOrWhiteSpace($Address)) { return }

    try {
        $facts = Invoke-Command -ComputerName $PeerName -ErrorAction Stop -ScriptBlock {
            $wanted = [string]$using:Address
            $result = [pscustomobject]@{
                Held = $false; Alias = ""; State = ""; Profile = ""
                Listening = $false; Blocked = @()
            }
            $entry = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { [string]$_.IPAddress -eq $wanted })
            if ($entry.Count -gt 0) {
                $result.Held = $true
                $result.Alias = [string]$entry[0].InterfaceAlias
                $result.State = [string]$entry[0].AddressState
                try {
                    $result.Profile = [string](Get-NetConnectionProfile -InterfaceAlias $result.Alias -ErrorAction Stop).NetworkCategory
                }
                catch { $result.Profile = "" }
            }
            try {
                $result.Listening = @(Get-NetTCPConnection -State Listen -LocalPort 445 -ErrorAction Stop |
                    Where-Object { ([string]$_.LocalAddress -eq $wanted) -or ([string]$_.LocalAddress -eq "0.0.0.0") }).Count -gt 0
            }
            catch { }
            try {
                $result.Blocked = @(Get-NetFirewallRule -Name "FPS-SMB-In-TCP" -ErrorAction Stop |
                    Where-Object { -not $_.Enabled } | ForEach-Object { [string]$_.Profile })
            }
            catch { }
            return $result
        }
    }
    catch {
        Write-Log ("    '{0}' would not answer a session, so its side is unread: {1}" -f $PeerName, $_.Exception.Message) -Tag "Error"
        Write-Log ("    Sign in there and run: Get-NetIPAddress -IPAddress {0}; Get-NetConnectionProfile; Get-NetTCPConnection -State Listen -LocalPort 445" -f $Address) -Tag "Info"
        return
    }

    if (-not $facts.Held) {
        Write-Log ("    '{0}' does not hold {1} at all - its addressing is the fault, not the wire" -f $PeerName, $Address) -Tag "Error"
        return
    }

    Write-Log ("    '{0}': {1} is on '{2}', state {3}, firewall profile {4}" -f $PeerName, $Address,
        [string]$facts.Alias, [string]$facts.State,
        $(if ([string]::IsNullOrWhiteSpace([string]$facts.Profile)) { "unknown" } else { [string]$facts.Profile })) -Tag "Error"

    if ([string]$facts.Profile -eq "Public") {
        Write-Log "    Public is the answer: File and Printer Sharing is blocked there, so 445 is silent on an interface that is otherwise fine" -Tag "Error"
        Write-Log ("        Set-NetConnectionProfile -InterfaceAlias '{0}' -NetworkCategory Private" -f [string]$facts.Alias) -Tag "Info"
    }
    if (-not $facts.Listening) {
        Write-Log ("    Nothing on '{0}' is listening on 445 for that address" -f $PeerName) -Tag "Error"
    }
    if (@($facts.Blocked).Count -gt 0) {
        Write-Log ("    File and Printer Sharing (SMB-In) is disabled on '{0}' for: {1}" -f $PeerName, (@($facts.Blocked) -join ", ")) -Tag "Error"
    }
}

# One line, and the line is facts: what holds the address, the states that are not the
# normal ones, and whether the route for its own subnet exists. Those three are what turn
# "the probe answered on the wrong interface" into something somebody can act on - a
# storage address on a link that is down, or a subnet with no route of its own.
function Write-HypervS2dInterfaceFact {
    param([string]$Address = "")

    if ([string]::IsNullOrWhiteSpace($Address)) { return }

    $entry = $null
    try {
        $entry = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { [string]$_.IPAddress -eq $Address })[0]
    }
    catch { $entry = $null }
    if ($null -eq $entry) {
        Write-Log ("    {0} is on no interface here" -f $Address) -Tag "Error"
        return
    }

    $alias = [string]$entry.InterfaceAlias
    # Only what is not the normal answer earns a word.
    $facts = @([string]$entry.AddressState)
    if ([bool]$entry.SkipAsSource) { $facts += "SkipAsSource" }
    try {
        $interface = @(Get-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction Stop)[0]
        if ([string]$interface.ConnectionState -ne "Connected") { $facts += [string]$interface.ConnectionState }
    }
    catch { }
    if (Test-HypervS2dAdapterInSwitch -Name $alias) { $facts += "in a vSwitch" }

    $prefix = Get-HypervS2dSubnetPrefix -Address $Address
    if (-not [string]::IsNullOrWhiteSpace($prefix)) {
        $routed = $false
        try { $routed = @(Get-NetRoute -DestinationPrefix $prefix -AddressFamily IPv4 -ErrorAction Stop).Count -gt 0 }
        catch { $routed = $false }
        if (-not $routed) { $facts += ("no route for " + $prefix) }
    }

    Write-Log ("    {0} on '{1}': {2}" -f $Address, $alias, ($facts -join ", ")) -Tag "Error"
}

# The same, asked on the machine that did not answer - a probe that left the right
# interface and got nothing back is not evidence about this node. One line, plus the
# command to run when the answer is Public, because that one the reader has to act on.
function Write-HypervS2dPeerStorageFact {
    param([string]$PeerName = "", [string]$Address = "")

    if ([string]::IsNullOrWhiteSpace($PeerName) -or [string]::IsNullOrWhiteSpace($Address)) { return }

    $facts = $null
    try {
        $facts = Invoke-Command -ComputerName $PeerName -ErrorAction Stop -ScriptBlock {
            $wanted = [string]$using:Address
            $result = [pscustomobject]@{ Held = $false; Alias = ""; State = ""; Profile = ""; Listening = $false }
            $entry = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { [string]$_.IPAddress -eq $wanted })
            if ($entry.Count -gt 0) {
                $result.Held = $true
                $result.Alias = [string]$entry[0].InterfaceAlias
                $result.State = [string]$entry[0].AddressState
                try { $result.Profile = [string](Get-NetConnectionProfile -InterfaceAlias $result.Alias -ErrorAction Stop).NetworkCategory }
                catch { $result.Profile = "" }
            }
            try {
                $result.Listening = @(Get-NetTCPConnection -State Listen -LocalPort 445 -ErrorAction Stop |
                    Where-Object { ([string]$_.LocalAddress -eq $wanted) -or ([string]$_.LocalAddress -eq "0.0.0.0") }).Count -gt 0
            }
            catch { }
            return $result
        }
    }
    catch {
        Write-Log ("    '{0}' would not answer a session, so its side is unread" -f $PeerName) -Tag "Error"
        return
    }

    if (-not $facts.Held) {
        Write-Log ("    '{0}' does not hold {1}" -f $PeerName, $Address) -Tag "Error"
        return
    }

    $parts = @([string]$facts.State)
    if (-not [string]::IsNullOrWhiteSpace([string]$facts.Profile)) { $parts += ("profile " + [string]$facts.Profile) }
    if (-not $facts.Listening) { $parts += "not listening on 445" }
    Write-Log ("    '{0}': {1} on '{2}', {3}" -f $PeerName, $Address, [string]$facts.Alias, ($parts -join ", ")) -Tag "Error"

    # File and Printer Sharing is blocked on Public, so 445 is silent on an interface that
    # is otherwise fine. The one line here the reader acts on.
    if ([string]$facts.Profile -eq "Public") {
        Write-Log ("    Set-NetConnectionProfile -InterfaceAlias '{0}' -NetworkCategory Private" -f [string]$facts.Alias) -Tag "Info"
    }
}

# The last check before the pool exists: every storage subnet has to carry traffic to the
# other node. A crossed pair that got this far produces a healthy-looking cluster whose
# storage runs over management, which is the failure nobody notices until it is slow.
function Test-HypervS2dStoragePathReady {
    param(
        [Parameter(Mandatory)][object]$S2d,
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][string]$PeerName
    )

    $names = @(Get-HypervS2dNodeName -S2d $S2d)
    $label = Get-HypervS2dHostLabel -Name $PeerName
    $position = 0
    for ($index = 0; $index -lt $names.Count; $index++) {
        if ((Get-HypervS2dHostLabel -Name $names[$index]).Equals($label, [System.StringComparison]::OrdinalIgnoreCase)) { $position = $index + 1; break }
    }
    if ($position -eq 0) { return $true }

    $mine = Get-HypervS2dNodePosition -S2d $S2d

    $reachable = 0
    $total = 0
    foreach ($item in @($Plan.storageLinks)) {
        $address = Get-HypervS2dStorageAddress -Vlan ([int]$item.vlan) -NodeNumber $position
        if ([string]::IsNullOrWhiteSpace($address)) { continue }
        $total++

        # This node's own address on the same subnet - the address the traffic this check
        # is about would actually come from.
        $local = Get-HypervS2dStorageAddress -Vlan ([int]$item.vlan) -NodeNumber $mine

        # Freshly added addresses are Tentative until DAD finishes, and a Tentative
        # address is not a source: no on-link route exists yet, so the stack falls back
        # to the default route - out of the management network - and the probe measures
        # the wrong path rather than waiting for the right one.
        if (-not [string]::IsNullOrWhiteSpace($local)) {
            $null = Wait-HypervS2dSubnetAddressReady -Subnet @($local) -TimeoutSeconds 30
        }

        # Which door the traffic would leave by, asked before anything is sent. A probe
        # that answers from the management network is not evidence about this subnet, and
        # a probe that fails there is not evidence about the peer.
        $path = Get-HypervS2dPathSource -Address $address
        if ((-not [string]::IsNullOrWhiteSpace($local)) -and ([string]$path.Source -ne $local)) {
            $door = [string]$path.Source
            if (-not [string]::IsNullOrWhiteSpace([string]$path.InterfaceAlias)) { $door += (" on '" + [string]$path.InterfaceAlias + "'") }
            Write-Log ("Storage path to {0} would leave from {1} instead" -f $address, $door) -Tag "Error"
            Write-HypervS2dInterfaceFact -Address $local
            continue
        }

        # Retried, because this check runs seconds after BOTH nodes were addressed and
        # the first subnet tested is the one most likely to be asked too early - the peer
        # address may still be finishing DAD, and the SMB server binds to it only once it
        # is Preferred. A single probe here reported "does NOT answer on 445" for a link
        # the pairing had measured correctly minutes before (bench, 2026-08-22), which
        # sends somebody looking at cables for a stopwatch problem.
        #
        # Bound to the local storage address rather than left to the stack: with the
        # source pinned, a failure can only be about this subnet. Test-NetConnection has
        # no way to say that, which is why it is not used here any more.
        # Only a timeout is retried. A refusal, a failed bind and an unreachable network
        # are the same in sixty seconds as they are now, and each of the three says
        # something the wait would only delay.
        $probe = $null
        for ($attempt = 1; $attempt -le 6; $attempt++) {
            $probe = Get-HypervTcpProbe -ComputerName $address -Port 445 -TimeoutMilliseconds 5000 -SourceAddress $local
            if ($probe.Open -or (-not $probe.Retryable)) { break }
            if ($attempt -lt 6) {
                Write-Log ("    {0} did not answer on 445 yet - waiting (attempt {1} of 6)" -f $address, $attempt) -Tag "Debug"
                Start-Sleep -Seconds 10
            }
        }
        $open = [bool]$probe.Open
        if ($open) {
            Write-Log ("Storage path to {0} is open on 445" -f $address) -Tag "Ok"
            $reachable++
        }
        else {
            # What is said depends on what came back, because three of the four answers are
            # not about the far end at all. Counting a refusal as reachable is deliberate:
            # the check exists to prove the SUBNET carries traffic to the other node, and a
            # RST is proof that it does. What is not running there is the next question,
            # and Enable-ClusterStorageSpacesDirect is the thing that starts it.
            if ([string]$probe.Error -eq "ConnectionRefused") {
                Write-Log ("Storage path to {0} is open - refused on 445, which is a reply" -f $address) -Tag "Warn"
                $reachable++
            }
            elseif ([string]$probe.Error -eq "AddressNotAvailable") {
                Write-Log ("Storage path to {0} not tested - {1} is not on this machine" -f $address, $local) -Tag "Error"
                Write-HypervS2dInterfaceFact -Address $local
            }
            elseif (([string]$probe.Error -eq "NetworkUnreachable") -or ([string]$probe.Error -eq "HostUnreachable")) {
                Write-Log ("Storage path to {0} does not route from {1}" -f $address, $local) -Tag "Error"
                Write-HypervS2dInterfaceFact -Address $local
            }
            else {
                Write-Log ("Storage path to {0} does NOT answer on 445 - sent from {1}" -f $address, $local) -Tag "Error"
                # The question has moved to the other machine, so it is asked there.
                Write-HypervS2dPeerStorageFact -PeerName $PeerName -Address $address
            }
        }
    }

    if (($total -gt 0) -and ($reachable -eq 0)) {
        Write-Log "No storage subnet reaches the other node - Storage Spaces Direct would run over the management network instead" -Tag "Error"
        Write-Log "    On the parent host, check which switch each adapter is on:" -Tag "Error"
        Write-Log "    Get-VMNetworkAdapter -VMName <node1>,<node2> | Format-Table VMName, Name, SwitchName, MacAddress" -Tag "Error"
        return $false
    }
    if ($reachable -lt $total) {
        Write-Log "One storage subnet does not reach the other node - the cluster works on the one that does, at half the bandwidth" -Tag "Warn"
    }
    return $true
}

# ---------------------------[ Entry points ]---------------------------
# Called from Invoke-HypervConfiguration when the mode routes here - the apply leg.
function Invoke-HypervS2dConfiguration {
    param([Parameter(Mandatory)][object]$Config)

    $hyperv = Get-HypervSection -Config $Config
    $s2d = Get-HypervS2dSection -Hyperv $hyperv
    if ($null -eq $s2d) {
        return (New-RoleResult -Status "Failed" -Message "hyperV.mode is 's2dCluster' and there is no s2dCluster section.")
    }

    $persona = Get-HypervS2dPersona -S2d $s2d
    if ($persona -eq "none") {
        return (New-RoleResult -Status "Completed" -Message "This machine is not part of the S2D cluster design.")
    }

    # The witness host: the share and its grants, nothing else. No Hyper-V, no restart.
    if ($persona -eq "witness") {
        return (Invoke-HypervS2dWitnessShare -S2d $s2d -Hyperv $hyperv)
    }

    # A node. The interview first, before anything is installed - same contract as the
    # single host: every answer is about hardware and the far leg cannot ask.
    $plan = Read-HypervS2dPlan
    if ($null -eq $plan) {
        if (Test-HypervInterviewWanted) {
            $plan = Invoke-HypervS2dInterview -Hyperv $hyperv -S2d $s2d -Persona $persona
            if ($null -eq $plan) {
                return (New-RoleResult -Status "ManualStepRequired" -Message "The review screen was cancelled - nothing was changed. Run the script again to answer the questions afresh.")
            }
        }
        else {
            Write-Log "No console session and no plan file - this run does the declarative parts, the next console run asks the rest" -Tag "Warn"
        }
    }
    else {
        Write-Log "Using the answers from '$(Get-HypervS2dPlanPath)'" -Tag "Info"
    }

    # Domain join or the workgroup prerequisites - the same fork the whole design hangs
    # off, and both ride the restart Hyper-V owes.
    $domainJoined = $false
    if (Test-HypervDomainJoinWanted -Hyperv $hyperv) {
        $domainJoined = Invoke-HypervDomainJoin -Hyperv $hyperv
    }
    else {
        if (-not (Set-HypervS2dWorkgroupPrerequisite -S2d $s2d -Hyperv $hyperv)) {
            return (New-RoleResult -Status "Failed" -Message "The workgroup prerequisites could not be applied - the lines above say why.")
        }
    }

    # This node's disks are emptied on this side of the restart - each node clears its
    # own, with the consent its own console gave.
    if (($null -ne $plan) -and ($null -ne $plan.disks)) {
        $wipe = @()
        try { $wipe = @($plan.disks.wipe | ForEach-Object { [int]$_ }) } catch { $wipe = @() }
        foreach ($number in @($plan.disks.numbers)) {
            $allow = ($wipe -contains [int]$number)
            $null = Clear-HypervClusterDisk -DiskNumber ([int]$number) -AllowWipe:$allow
        }
    }

    if (-not (Install-HypervS2dFeature -S2d $s2d)) {
        return (New-RoleResult -Status "Failed" -Message "The cluster features could not be installed - the lines above say why.")
    }
    if (-not (Test-HypervFeatureInstalled)) {
        if (-not (Install-HypervRole)) {
            return (New-RoleResult -Status "Failed" -Message "The Hyper-V role could not be installed - the lines above say why.")
        }
    }
    else {
        Write-Log "Hyper-V role already installed" -Tag "Info"
    }
    if ([bool](Get-ConfigValue -InputObject $hyperv -Name "serverCoreAppCompat" -Default $true)) {
        $null = Install-HypervAppCompatibility -Hyperv $hyperv -Plan $plan
    }

    if ([bool](Get-ConfigValue -InputObject $hyperv -Name "highPerformancePowerPlan" -Default $true)) {
        $null = Set-HypervPowerPlan
    }
    if ([bool](Get-ConfigValue -InputObject $hyperv -Name "disableSmb1" -Default $true)) {
        $null = Remove-HypervSmb1
    }
    Write-HypervPageFileNote

    if ((Test-HypervRebootPending) -or $domainJoined) {
        $message = "Node prepared - the run after the restart builds its networking"
        if ($persona -eq "builder") {
            # Said here because this is where somebody decides whether to walk away. The
            # resume task will do this node's own networking after the restart and then
            # stop at the cluster, which is remote work no machine account can do.
            $message = $message + ". Sign in here afterwards and run the script again - forming the cluster is remote work."
        }
        else {
            $message = $message + ". Run the builder node once every member is prepared."
        }
        if ($domainJoined) {
            $message = "The domain join is done and " + $message.Substring(0, 1).ToLowerInvariant() + $message.Substring(1)
        }
        return (New-RoleResult -Status "RebootRequired" -Message $message)
    }
    return (New-RoleResult -Status "Completed" -Message "This node was already a hypervisor - the post-reboot leg carries straight on.")
}

# The far side of the restart. Members finish their own networking and stop; the builder
# does the same and then forms everything.
function Invoke-HypervS2dPostReboot {
    param([Parameter(Mandatory)][object]$Config)

    $hyperv = Get-HypervSection -Config $Config
    $s2d = Get-HypervS2dSection -Hyperv $hyperv
    if ($null -eq $s2d) {
        return (New-RoleResult -Status "Failed" -Message "hyperV.mode is 's2dCluster' and there is no s2dCluster section.")
    }

    $persona = Get-HypervS2dPersona -S2d $s2d
    if ($persona -eq "witness") {
        return (New-RoleResult -Status "Completed" -Message "The witness host has no post-reboot work.")
    }
    if ($persona -eq "none") {
        return (New-RoleResult -Status "Completed" -Message "This machine is not part of the S2D cluster design.")
    }

    if (-not (Test-HypervServiceReady)) {
        return (New-RoleResult -Status "RebootRequired" -Message "The Hyper-V management service is not answering yet - this server still owes a restart.")
    }
    $null = Install-HypervManagementTool

    $plan = Read-HypervS2dPlan
    if ($null -eq $plan) {
        return (New-RoleResult -Status "ManualStepRequired" -Message "There is no plan file on this node - run the script at the console so the interview can happen, then let it continue.")
    }

    $networking = Get-ConfigValue -InputObject $s2d -Name "networking"
    $atc = ([string](Get-ConfigText -InputObject $networking -Name "mode" -Default "atc") -eq "atc")

    # This node's own networking. In the manual lane that is the switch and the storage
    # addresses; in the ATC lane the adapters only get their names - the intents build
    # the rest once the cluster exists.
    $renameMembers = [bool](Get-ConfigValue -InputObject $hyperv -Name "renameTeamMembers" -Default $true)
    $namePrefix = Get-HypervAdapterNamePrefix -Prefix ([string](Get-ConfigText -InputObject $hyperv -Name "adapterNamePrefix" -Default "nic"))
    $script:hypervAdapterNameIndex = @{}

    if ($atc) {
        if ($renameMembers -and (@($plan.computeAdapters).Count -gt 0)) {
            $members = @(Resolve-HypervPlannedAdapter -Member @($plan.computeAdapters))
            if ($members.Count -gt 0) { $null = Rename-HypervTeamMember -Adapter $members -Prefix $namePrefix -SwitchName "mgmt" }
        }
    }
    else {
        foreach ($definition in @($plan.switches)) {
            $null = New-HypervVirtualSwitch -Definition $definition -RenameMembers:$renameMembers -NamePrefix $namePrefix
        }
    }

    if (@($plan.storageLinks).Count -gt 0) {
        if ($renameMembers) {
            $members = @(Resolve-HypervPlannedAdapter -Member @($plan.storageLinks))
            if ($members.Count -gt 0) {
                # The plan follows the rename by MAC, so the addresses land on the port
                # that was ticked whatever it is called now.
                $null = Rename-HypervTeamMember -Adapter $members -Prefix $namePrefix -SwitchName "storage"
            }
        }
        if (-not $atc) {
            $null = Set-HypervS2dStorageLink -Link @($plan.storageLinks)
            $null = Set-HypervS2dJumboFrame -Link @($plan.storageLinks) -Networking $networking
            $null = Enable-HypervS2dRdma -Link @($plan.storageLinks) -Flavor ([string](Get-ConfigText -InputObject $networking -Name "rdma" -Default "disabled"))
        }
        else {
            # Interim addresses in the ATC lane (user's call, 2026-08-19): .1 and .2 per
            # node position, on the links from node prep onward, so the direct cables
            # prove themselves in Test-Cluster before ATC exists. The intent leg replaces
            # them with the final .10/.20 once provisioning has put the VLANs on.
            $position = Get-HypervS2dNodePosition -S2d $s2d
            $interim = @()
            foreach ($item in @($plan.storageLinks)) {
                $address = Get-HypervS2dStorageAddress -Vlan ([int]$item.vlan) -NodeNumber $position -Interim
                if ([string]::IsNullOrWhiteSpace($address)) { continue }
                $interim += [pscustomobject]@{
                    name         = [string]$item.name
                    mac          = [string]$item.mac
                    address      = $address
                    prefixLength = [int]$item.prefixLength
                }
            }
            if ($interim.Count -gt 0) {
                Write-Log "Interim storage addresses - .1/.2 per node until ATC provisions" -Tag "Run"
                $null = Set-HypervS2dStorageLink -Link @($interim)
            }
        }
    }

    if ([bool](Get-ConfigValue -InputObject $networking -Name "liveMigrationOverSmb" -Default $true)) {
        $null = Set-HypervS2dLiveMigration -Hyperv $hyperv -Plan $plan
    }

    # Every node holds its own management certificate for its own name, so it is done on
    # both personas and before the member stops. Nothing about the cluster depends on it.
    if (Set-HypervS2dManagementCertificate -S2d $s2d -Hyperv $hyperv) {
        # A certificate that expires needs the nightly task, and the task is registered by
        # whichever role holds one - here, on this node, for this node's own certificate.
        $management = Get-HypervS2dManagementSection -S2d $s2d
        if (($null -ne $management) -and [bool](Get-ConfigValue -InputObject $management -Name "winRmHttps" -Default $false)) {
            $source = [string](Get-ConfigText -InputObject (Get-ConfigValue -InputObject $management -Name "certificate") -Name "source" -Default "generate")
            if (@("acme", "internalCa") -contains $source) {
                $null = Register-StudioCertificateTask -Config $Config -ConfigFilePath $script:configFilePath
            }
        }
    }

    if ($persona -eq "member") {
        Remove-HypervS2dPlan
        return (New-RoleResult -Status "Completed" -Message "This node is ready for the cluster. Run the builder node once every member reports this.")
    }

    # ---- The builder from here on. ----
    # The identity first, because everything below is a remote call and the resume task
    # is not an identity that can make one. Asked before the peer check rather than
    # after: a refusal there would otherwise be read as the peer's fault.
    if (-not (Test-HypervS2dBuilderIdentity)) {
        return (New-RoleResult -Status "ManualStepRequired" -Message ("This node is prepared and its networking is done. Forming the cluster is remote work on '{0}', so it waits for a signed-in session - the line above has the command." -f (@(Get-HypervS2dPeerName -S2d $s2d) -join ", ")))
    }

    # The same qualified form the cluster cmdlets get, for the same reason: every use of
    # $peers below is a remote call.
    $suffix = Get-HypervS2dNodeSuffix -S2d $s2d -Hyperv $hyperv
    $peers = @(Get-HypervS2dPeerName -S2d $s2d | ForEach-Object { Resolve-HypervS2dNodeAddress -NodeName $_ -Suffix $suffix })
    foreach ($peer in $peers) {
        if (-not (Test-HypervS2dPeerReady -PeerName $peer)) {
            return (New-RoleResult -Status "ManualStepRequired" -Message ("'{0}' does not answer this session. Prepare it with this same script and config, let it restart, and check the identical local administrator on a workgroup design - then run this node again, the plan file keeps its answers." -f $peer))
        }
    }

    # The public halves of the self-signed management certificates, once the peer is
    # known to answer. Here rather than in the per-node block above, because the member
    # leg has no peer to hand anything to yet.
    $null = Sync-HypervS2dManagementTrust -S2d $s2d -Hyperv $hyperv -PeerName $peers[0]

    # Which link reaches which, measured before anything is named after it. Before the
    # cluster on purpose: ATC matches adapters across nodes by NAME, so the names have to
    # carry the truth before an intent is declared, and New-Cluster does not care either
    # way. Two nodes, so one peer.
    if (@($plan.storageLinks).Count -gt 1) {
        $namePrefix = Get-HypervAdapterNamePrefix -Prefix ([string](Get-ConfigText -InputObject $hyperv -Name "adapterNamePrefix" -Default "nic"))
        # Measure, show, and measure again as often as the console asks. A link that
        # answered nothing is usually a cable, a switch port or a VLAN tag, and all three
        # are fixed while this menu is open - so the run waits here rather than carrying a
        # known-wrong pairing into the cluster.
        $pairing = @()
        for ($attempt = 1; $attempt -le $script:hypervS2dPairingAttempts; $attempt++) {
            $measured = @(Resolve-HypervS2dStorageLinkPairing -Plan $plan -PeerName $peers[0] -NamePrefix $namePrefix)
            if ($measured.Count -eq 0) { break }
            $answered = Confirm-HypervS2dStorageLinkPairing -Pairing $measured
            if ($null -eq $answered) {
                if ($attempt -eq $script:hypervS2dPairingAttempts) {
                    Write-Log "Measured $attempt time(s) - taking the last measurement" -Tag "Warn"
                    $pairing = @($measured)
                }
                continue
            }
            $pairing = @($answered)
            break
        }
        if ($pairing.Count -gt 0) {
            if (Set-HypervS2dPeerStorageLinkOrder -Pairing $pairing -PeerName $peers[0]) {
                $null = Set-HypervS2dPeerInterimAddress -S2d $s2d -Pairing $pairing -PeerName $peers[0]
            }
        }
        else {
            Write-Log "The storage links could not be paired by measurement - the names are used as they are" -Tag "Warn"
            Write-Log "    If the two nodes' 'nic-storage-01' are on different switches, storage traffic falls back to management" -Tag "Warn"
        }
    }

    if (-not (Test-HypervClusterFeatureInstalled)) {
        return (New-RoleResult -Status "Failed" -Message "Failover Clustering is not installed here - the apply leg should have installed it.")
    }
    if (-not (New-HypervS2dCluster -S2d $s2d -Hyperv $hyperv)) {
        return (New-RoleResult -Status "ManualStepRequired" -Message "The cluster could not be created - the lines above say why. The plan file keeps this node's answers for the next attempt.")
    }

    # The witness before the storage: from here on a node failure is survivable, which is
    # the earliest that is true and therefore the right moment.
    $witnessReady = Set-HypervS2dWitness -S2d $s2d -Hyperv $hyperv -Plan $plan

    if ($atc) {
        $null = Add-HypervS2dNetworkIntent -S2d $s2d -Hyperv $hyperv -Plan $plan -PeerName $peers
    }

    # Live migration, second pass and the one that does the work on a workgroup cluster:
    # the host refuses to enable it outside a cluster, so it could not be done in the
    # apply leg. Both nodes from here, for the same reason the DNS switch below is - the
    # member's own run finished before the cluster existed.
    if ([bool](Get-ConfigValue -InputObject $networking -Name "liveMigrationOverSmb" -Default $true)) {
        $null = Set-HypervS2dLiveMigration -Hyperv $hyperv -Plan $plan -PeerName $peers
    }

    # After the intents on purpose: in the ATC lane the management vNIC this matters
    # most for only exists once provisioning has run. Both nodes, from here, because ATC
    # guarantees nothing about a member ever being run again.
    if (-not (Test-HypervS2dDomainKind -Hyperv $hyperv)) {
        $null = Disable-HypervWorkgroupDnsRegistration
        foreach ($peer in $peers) {
            $null = Disable-HypervWorkgroupDnsRegistration -ComputerName $peer
        }
    }

    $storage = Get-ConfigValue -InputObject $s2d -Name "storage"

    # The last moment this is cheap to fix. After the pool exists, moving storage onto the
    # right network means taking the cluster apart.
    if (@($plan.storageLinks).Count -gt 0) {
        if (-not (Test-HypervS2dStoragePathReady -S2d $s2d -Plan $plan -PeerName $peers[0])) {
            return (New-RoleResult -Status "ManualStepRequired" -Message "No storage network reaches the other node, so the pool was not built - the lines above name the check to run on the parent host.")
        }
    }

    if (-not (Enable-HypervS2dStorage)) {
        return (New-RoleResult -Status "ManualStepRequired" -Message "Storage Spaces Direct could not be switched on - the lines above say why.")
    }

    $poolName = [string](Get-ConfigText -InputObject $storage -Name "poolName" -Default "")
    if ([string]::IsNullOrWhiteSpace($poolName)) { $poolName = Get-StudioPoolNameSuggestion -Base "pool" -Kind "s2d" }
    if (-not (New-HypervS2dPool -Name $poolName)) {
        return (New-RoleResult -Status "ManualStepRequired" -Message "The cluster pool could not be built - the lines above say why.")
    }
    $pool = Get-HypervClusterS2dPool
    if ($null -eq $pool) {
        return (New-RoleResult -Status "ManualStepRequired" -Message "Storage Spaces Direct is on but its pool cannot be read.")
    }

    # The plan carries the console's answer. Without one - a headless run, where the
    # interview never happened - the nested mirror is built (the studio writes no
    # resiliency key; one in an older config.json still applies here).
    $resiliency = [string]$plan.resiliency
    if ([string]::IsNullOrWhiteSpace($resiliency)) {
        $resiliency = [string](Get-ConfigText -InputObject $storage -Name "resiliency" -Default "nestedMirror")
    }
    if (-not (New-HypervS2dTier -Pool $pool -Resiliency $resiliency)) {
        return (New-RoleResult -Status "ManualStepRequired" -Message "The nested tier templates could not be created - the lines above say why.")
    }

    $count = [int](Get-ConfigValue -InputObject $storage -Name "volumeCount" -Default 2)
    if ($count -lt 1) { $count = 1 }
    $prefix = [string](Get-ConfigText -InputObject $storage -Name "csvNamePrefix" -Default "csv")
    if ([string]::IsNullOrWhiteSpace($prefix)) { $prefix = "csv" }
    $allocationUnitSize = [int](Get-ConfigValue -InputObject $storage -Name "allocationUnitSize" -Default 4096)
    $mirrorPercent = [int](Get-ConfigValue -InputObject $storage -Name "nestedParityMirrorPercent" -Default 20)

    $share = Get-HypervS2dVolumeShare -Pool $pool -Resiliency $resiliency -Count $count -MirrorPercent $mirrorPercent
    $root = Get-HypervClusterStorageFolder
    $paths = @()
    for ($index = 1; $index -le $count; $index++) {
        $label = "{0}-{1:00}" -f $prefix, $index
        $wanted = Join-Path -Path $root -ChildPath $label
        if (Test-Path -LiteralPath $wanted) {
            Write-Log "'$wanted' is already a Cluster Shared Volume" -Tag "Info"
            $paths += $wanted
            continue
        }
        $path = New-HypervS2dVolume -Label $label -Pool $pool -Resiliency $resiliency -Share $share -AllocationUnitSize $allocationUnitSize
        if (-not [string]::IsNullOrWhiteSpace($path)) { $paths += $path }
    }
    if ($paths.Count -eq 0) {
        return (New-RoleResult -Status "ManualStepRequired" -Message "The cluster exists but no Cluster Shared Volume could be built - the lines above say why.")
    }
    foreach ($path in $paths) { Write-HypervCsvFreeSpaceNote -Path $path -S2d }

    # The guest folders on every volume, the host pointed at the first - here and on the
    # peer, because Set-VMHost is per node and the peer's own run finished before the
    # volumes existed.
    $folderPaths = @()
    foreach ($extra in @($paths | Select-Object -Skip 1)) {
        $folderPaths += @(Set-HypervHostPath -Hyperv $hyperv -BasePath $extra -FoldersOnly)
    }
    $folderPaths += @(Set-HypervHostPath -Hyperv $hyperv -BasePath $paths[0])
    if ([bool](Get-ConfigValue -InputObject $hyperv -Name "defenderExclusions" -Default $true)) {
        $null = Set-HypervDefenderExclusion -Path $folderPaths
    }
    $null = Set-HypervEnhancedSessionMode -Hyperv $hyperv

    foreach ($peer in $peers) {
        try {
            $storageSection = Get-ConfigValue -InputObject $hyperv -Name "storage"
            $vmFolder = [string](Get-ConfigText -InputObject $storageSection -Name "vmFolderName" -Default "vms")
            $vhdFolder = [string](Get-ConfigText -InputObject $storageSection -Name "vhdFolderName" -Default "vhd")
            $vmPath = Join-Path -Path $paths[0] -ChildPath $vmFolder
            $vhdPath = Join-Path -Path $paths[0] -ChildPath $vhdFolder
            $null = Invoke-Command -ComputerName $peer -ErrorAction Stop -ScriptBlock {
                Set-VMHost -VirtualMachinePath $using:vmPath -VirtualHardDiskPath $using:vhdPath -ErrorAction Stop
            }
            Write-Log ("'{0}' also points new virtual machines at '{1}'" -f $peer, $vmPath) -Tag "Ok"
        }
        catch {
            Write-Log ("Host paths not set on '{0}': {1}" -f $peer, $_.Exception.Message) -Tag "Warn"
            Write-Log ("    By hand there: Set-VMHost -VirtualMachinePath '{0}\vms' -VirtualHardDiskPath '{0}\vhd'" -f $paths[0]) -Tag "Info"
        }
    }

    $null = Add-HypervS2dClusterUpdating -S2d $s2d
    Write-HypervS2dHealthReport -S2d $s2d
    Remove-HypervS2dPlan

    if (-not $witnessReady) {
        return (New-RoleResult -Status "ManualStepRequired" -Message ("The cluster '{0}' runs and its volumes are at {1}, but it has NO WITNESS - losing either node stops it. The lines above say how to finish the witness, then run this node once more." -f (Get-HypervS2dClusterName -S2d $s2d), ($paths -join ", ")))
    }
    return (New-RoleResult -Status "Completed" -Message ("The two-node cluster '{0}' is up - virtual machines land in '{1}'." -f (Get-HypervS2dClusterName -S2d $s2d), $paths[0]))
}
