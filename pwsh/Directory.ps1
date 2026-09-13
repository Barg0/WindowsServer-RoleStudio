# Shared directory helpers - who runs where, and the groups that cross that line.
#
# Dot-sourced by Configure-ServerRoles.ps1 - not runnable on its own. Everything
# here lands in that script's scope, so $script: variables and functions are shared
# with every other part. Use $scriptRootPath, never $PSScriptRoot: inside this file
# $PSScriptRoot is the pwsh folder, not the folder the run was started from.

# ===========================[ Directory helpers ]===========================
# The File Server and Remote Desktop roles both name domain groups they never
# create: the account driving a member-server run holds that server's rights, not
# necessarily the right to write groups into AD. The directory half of both roles
# runs when the same config is carried to a domain controller - the machine whose
# job that is - using the same ADSI machinery the AD CS enrollment groups use
# (New-AdcsAccessGroup, Find-AdcsGroup; shared scope makes them callable here).

# Which installation option this is, which decides what may run here at all: RD Web
# Access, RD Session Host and RD Gateway are not on Server Core, and the Hyper-V role
# reads the same value to know whether a console is available. Shared rather than one
# copy per provider, the same reason the GPO plumbing is here.
function Test-StudioServerCore {
    try {
        $installationType = [string](Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" `
            -Name "InstallationType" -ErrorAction Stop).InstallationType
        return ($installationType -eq "Server Core")
    }
    catch {
        # Unreadable is not "Core": a probe nobody can answer must not refuse a run.
        return $false
    }
}

# 4 = backup domain controller, 5 = primary. Anything less is a member server or
# workgroup machine. Same reading Test-AdcsDomainController uses.
function Test-StudioDomainController {
    try {
        $computer = Get-CimInstance -ClassName "Win32_ComputerSystem" -ErrorAction Stop
        return ([int]$computer.DomainRole -ge 4)
    }
    catch {
        Write-Log "Could not determine the domain role: $($_.Exception.Message)" -Tag "Debug"
        return $false
    }
}

# A UPN is looked up as itself, never split into name parts - the left half of a
# UPN and sAMAccountName are two attributes that agree only by convention.
function Find-StudioUpn {
    param([Parameter(Mandatory)][string]$Upn)

    $domainDn = Get-AdcsDefaultNamingContext
    $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDn")
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
    $searcher.Filter = "(&(objectCategory=person)(userPrincipalName=$(ConvertTo-AdcsLdapFilterValue -Value $Upn)))"
    $null = $searcher.PropertiesToLoad.Add("distinguishedName")
    return $searcher.FindOne()
}

# A member value with an @ is a user's UPN; without one it is a group's name -
# the same reading the studio's field applies. Returns the DN, or empty.
function Resolve-StudioMemberDn {
    param([Parameter(Mandatory)][string]$Value)

    if ($Value.Contains("@")) {
        $person = $null
        try { $person = Find-StudioUpn -Upn $Value } catch { $person = $null }
        if ($null -eq $person) { return "" }
        return [string]$person.Properties["distinguishedname"][0]
    }

    $nested = $null
    try { $nested = Find-AdcsGroup -Name $Value } catch { $nested = $null }
    if ($null -eq $nested) { return "" }
    return [string]$nested.Properties["distinguishedname"][0]
}

# Create-or-adopt the group, then bring the listed members in. One commit per
# member, the same rule the AD CS role groups follow: the directory refuses an
# entire write for one illegal value, so a single unresolvable member must not
# take the resolvable ones with it. Members are only ever added - removing one is
# a decision this script does not make.
function Sync-StudioAccessGroup {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Description = "",
        [string[]]$MemberUpn = @(),
        # Global by default, because that is what every caller but one wants: a group
        # naming *people* - the Remote Desktop users, the NDES service account - is a
        # global group, and nesting one into a resource group later is how AGDLP is
        # meant to go. A group naming a *resource* on one server asks for DomainLocal
        # instead. Only ever applied to a group this run creates; an existing group's
        # scope is left exactly as somebody set it.
        [ValidateSet("Global", "DomainLocal", "Universal")][string]$Scope = "Global"
    )

    $null = New-AdcsAccessGroup -Name $Name -Description $Description -Scope $Scope

    $entry = Find-AdcsGroup -Name $Name
    if ($null -eq $entry) {
        Write-Log "The group '$Name' could not be read back after creation" -Tag "Error"
        return $false
    }
    $group = $entry.GetDirectoryEntry()
    $existing = @()
    try { $existing = @($group.Properties["member"]) } catch { $existing = @() }

    $allAdded = $true
    foreach ($upn in @($MemberUpn | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        $personDn = Resolve-StudioMemberDn -Value $upn
        if ([string]::IsNullOrWhiteSpace($personDn)) {
            if ($upn.Contains("@")) {
                Write-Log "'$upn' does not resolve to an account in this domain - not added to '$Name'" -Tag "Error"
            }
            else {
                Write-Log "'$upn' does not resolve to a group here (a member without an @ is read as a group name) - not added to '$Name'" -Tag "Error"
            }
            $allAdded = $false
            continue
        }
        if ($existing -contains $personDn) {
            Write-Log "'$upn' is already a member of '$Name'" -Tag "Debug"
            continue
        }

        try {
            $null = $group.Properties["member"].Add($personDn)
            $group.CommitChanges()
            Write-Log "Added '$upn' to '$Name'" -Tag "Ok"
        }
        catch {
            Write-Log "Could not add '$upn' to '$Name': $($_.Exception.Message)" -Tag "Error"
            $allAdded = $false
            # The failed value stays in the cached property list and would ride into
            # the next member's commit - reload so each member is its own write.
            $group = ($entry.GetDirectoryEntry())
        }
    }
    return $allAdded
}

# ---------------------------[ Well-known accounts, by SID ]---------------------------
# **Never match a Windows principal on its name.** Every built-in account and group is
# translated: Administrators is Administratoren, Everyone is Jeder, CREATOR OWNER is
# ERSTELLER-BESITZER. A script that hard-codes the English name does not fail loudly on a
# German server - it fails in whichever direction the caller's -ErrorAction points, which
# for a *Revoke* is silently leaving the permission in place.
#
# The SID is the identity; the name is a label on it. So the SID is what this states, and
# the localised name is looked up from it at run time - which also means the value handed
# to a cmdlet is the one that machine actually uses, rather than a SID string the cmdlet
# may or may not accept.
#
# IIS_IUSRS is deliberately absent: IIS 7 and later guarantee their built-in account and
# group names are never localised, so that one is safe as a literal and is used as one.
function Get-StudioWellKnownAccountName {
    param(
        [Parameter(Mandatory)][System.Security.Principal.WellKnownSidType]$WellKnown,
        # Only for the log line when translation fails - never used as a lookup value.
        [string]$Label = ""
    )

    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($WellKnown, $null)
        return ($sid.Translate([System.Security.Principal.NTAccount])).Value
    }
    catch {
        $what = $Label
        if ([string]::IsNullOrWhiteSpace($what)) { $what = [string]$WellKnown }
        Write-Log "Could not resolve the well-known account '$what' to a name on this machine: $($_.Exception.Message)" -Tag "Warn"
        return ""
    }
}

# The three this project actually needs, named once so a call site reads as intent
# rather than as an enumeration member.
function Get-StudioEveryoneName {
    return (Get-StudioWellKnownAccountName -WellKnown ([System.Security.Principal.WellKnownSidType]::WorldSid) -Label "Everyone")
}

# ---------------------------[ Server names in UNC paths ]---------------------------
# **A server name that ends up inside a UNC path has to be fully qualified**, and this is
# the one place that decides it. A single label is resolved through the *client's* DNS
# suffix search list - a per-client setting nobody writing a design controls - so a mapped
# drive or a printer connection works on the machines that happen to carry the right
# suffix and fails on a laptop on a VPN, on a client in another domain of the forest, and
# on anything with its suffixes in a different order. It costs Kerberos too: a short name
# has no service principal name of its own to match, so the connection falls back to NTLM
# where that is still allowed and simply fails where it is not. Every symptom is per
# client, which is the worst kind to be told about.
#
# The studio makes this a validation error. This is the safety net for a hand-written
# config: a short name is completed from this machine's own domain when there is one, and
# reported either way rather than quietly written into a policy every client reads.
function Resolve-StudioServerFqdn {
    param(
        [string]$Name = "",
        [string]$Label = "server"
    )

    $trimmed = ([string]$Name).Trim().TrimEnd(".")
    if ([string]::IsNullOrWhiteSpace($trimmed)) { return "" }
    if ($trimmed.Contains(".")) { return $trimmed }

    $domain = ([string]$env:USERDNSDOMAIN).Trim()
    if ([string]::IsNullOrWhiteSpace($domain)) {
        Write-Log "The $Label name '$trimmed' is a single label and this machine has no DNS domain to complete it with" -Tag "Warn"
        Write-Log "    Clients resolve it through their own DNS suffix list, so it works on some and not others - set the FQDN in the design" -Tag "Warn"
        return $trimmed
    }

    $qualified = "{0}.{1}" -f $trimmed, $domain.ToLowerInvariant()
    Write-Log "The $Label name '$trimmed' is a single label - using '$qualified'" -Tag "Warn"
    Write-Log "    Set the fully qualified name in the design - a short name resolves per client and has no Kerberos name to match" -Tag "Warn"
    return $qualified
}

# ---------------------------[ Group Policy preferences ]---------------------------
# Two roles now write preference items straight into SYSVOL - drive maps and printers -
# because no cmdlet family exists for them: the console writes the XML itself. The three
# things that make such a file real are the same for both and are load-bearing enough that
# there is one copy of them here rather than one per provider.

# Stable per seed, so a re-run rewrites the same entries instead of minting new uids every
# night - the console then shows one item, not a history of them.
function Get-StudioStableGuid {
    param([Parameter(Mandatory)][string]$Seed)

    $md5 = [System.Security.Cryptography.MD5]::Create()
    try {
        $hash = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Seed))
        return ([guid]::new($hash)).ToString("B").ToUpperInvariant()
    }
    finally { $md5.Dispose() }
}

# Registering the client-side extension and bumping the version are what make the file
# real. AD's versionNumber and GPT.ini must move together (the user half is the high 16
# bits, so +65536), or clients read the GPO as unchanged and never look at SYSVOL again.
#
# The extension list is **merged**, not overwritten. A GPO this run created carries nothing
# else, but the attribute is a list for a reason, and a helper that clobbers it is one
# accident away from switching another extension off on a GPO somebody else built.
function Set-StudioGpoUserExtension {
    param(
        [Parameter(Mandatory)][object]$Gpo,
        [Parameter(Mandatory)][string]$Extension
    )

    $domainDn = Get-AdcsDefaultNamingContext
    $policyDn = "CN={{{0}}},CN=Policies,CN=System,{1}" -f $Gpo.Id.ToString().ToUpperInvariant(), $domainDn
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$policyDn")

    $version = 0
    try { $version = [int]$entry.Properties["versionNumber"].Value } catch { $version = 0 }
    $version = $version + 65536

    $current = ""
    try { $current = [string]$entry.Properties["gPCUserExtensionNames"].Value } catch { $current = "" }

    $merged = $Extension
    if (-not [string]::IsNullOrWhiteSpace($current)) {
        # Each pair is "[{cse}{tool}]". Anything already there that this extension does not
        # name is kept, in the order it was found; the pairs this run needs go on the end.
        $wanted  = @([regex]::Matches($Extension, "\[[^\]]+\]") | ForEach-Object { $_.Value })
        $existing = @([regex]::Matches($current, "\[[^\]]+\]") | ForEach-Object { $_.Value })
        $keep = @($existing | Where-Object { $wanted -notcontains $_ })
        $merged = (@($keep) + @($wanted)) -join ""
    }

    $entry.Properties["gPCUserExtensionNames"].Value = $merged
    $entry.Properties["versionNumber"].Value = $version
    $entry.CommitChanges()

    $domain = ([string]$env:USERDNSDOMAIN).ToLowerInvariant()
    $policyFolder = "\\{0}\SYSVOL\{0}\Policies\{{{1}}}" -f $domain, $Gpo.Id.ToString().ToUpperInvariant()
    $gptPath = Join-Path -Path $policyFolder -ChildPath "GPT.ini"
    $lines = @("[General]", ("Version={0}" -f $version))
    [System.IO.File]::WriteAllLines($gptPath, $lines)
    return $policyFolder
}

# One writer for every preference file: the folder under the policy's User half, the XML,
# and no BOM - the client-side extension parses the file itself and a BOM is one more thing
# for it to be unhappy about.
function Write-StudioGpoPreferenceFile {
    param(
        [Parameter(Mandatory)][string]$PolicyFolder,
        [Parameter(Mandatory)][string]$Folder,
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][string]$Content
    )

    $target = Join-Path -Path $PolicyFolder -ChildPath ("User\Preferences\" + $Folder)
    if (-not (Test-Path -LiteralPath $target)) {
        $null = New-Item -ItemType Directory -Path $target -Force
    }
    [System.IO.File]::WriteAllText((Join-Path -Path $target -ChildPath $FileName), $Content,
        (New-Object System.Text.UTF8Encoding($false)))
}

# The SID a preference item's item-level targeting filter needs, read off the group object
# rather than through NTAccount.Translate - a name lookup can land on a DC that has not
# seen a group this run just created.
function Get-StudioGroupSid {
    param([Parameter(Mandatory)][string]$Name)

    $entry = $null
    try { $entry = Find-AdcsGroup -Name $Name } catch { $entry = $null }
    if ($null -eq $entry) { return "" }

    try {
        $sidBytes = [byte[]]$entry.Properties["objectsid"][0]
        return (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
    }
    catch {
        Write-Log "Could not read the SID of '$Name': $($_.Exception.Message)" -Tag "Debug"
        return ""
    }
}

# ---------------------------[ The account domain's own SID ]---------------------------
# Every group AD creates with a domain is the domain's SID plus a fixed RID - Domain
# Computers is 515, Domain Users 513, Domain Admins 512 - so the domain SID is the one
# value needed to name any of them without ever typing the name.
#
# **Their names are not reliable and their RIDs are.** `Domain Computers` is
# `Domänencomputer` on a German domain and `Ordinateurs du domaine` on a French one: the
# names are written in the language the forest was created in and they stay that way
# forever. That is the same rule the well-known-account lookup above already follows for
# the BUILTIN principals, applied one level down - BUILTIN\Administrators is a constant
# SID everywhere, while a *domain* group's SID is constant only relative to its domain.
#
# The domain object itself carries the SID, so one read answers it. Empty when this
# machine cannot reach a domain at all, which is a workgroup server and a caller's
# problem to report rather than this function's to guess at.
function Get-StudioAccountDomainSid {
    try {
        $context = Get-AdcsDefaultNamingContext
        if ([string]::IsNullOrWhiteSpace($context)) { return $null }
        $domain = Get-AdcsDirectoryEntry -DistinguishedName $context
        $bytes = [byte[]]$domain.Properties["objectSid"].Value
        return (New-Object System.Security.Principal.SecurityIdentifier($bytes, 0))
    }
    catch {
        Write-Log "Could not read the domain's own SID: $($_.Exception.Message)" -Tag "Debug"
        return $null
    }
}

# One of those domain groups, by the RID .NET already has a name for. `AccountComputersSid`
# is 515 - Domain Computers - and the second argument is what makes the result this
# domain's copy of it rather than a constant.
function Get-StudioDomainGroupSid {
    param([Parameter(Mandatory)][System.Security.Principal.WellKnownSidType]$WellKnown)

    $domainSid = Get-StudioAccountDomainSid
    if ($null -eq $domainSid) { return $null }
    try {
        return (New-Object System.Security.Principal.SecurityIdentifier($WellKnown, $domainSid))
    }
    catch {
        Write-Log "Could not build the '$WellKnown' SID from the domain SID: $($_.Exception.Message)" -Tag "Debug"
        return $null
    }
}

# The shared "groups with members" shape both roles carry: an array of strings (a
# config written before members existed) or of {name, members} objects. Returned
# as objects either way, so callers read one shape.
function Get-StudioGroupDefinition {
    param([object[]]$Entries = @())

    $definitions = @()
    foreach ($entry in @($Entries)) {
        if ($null -eq $entry) { continue }
        if ($entry -is [string]) {
            if (-not [string]::IsNullOrWhiteSpace($entry)) {
                $definitions += [pscustomobject]@{ Name = [string]$entry; Members = @() }
            }
            continue
        }
        $name = Get-ConfigText -InputObject $entry -Name "name"
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $members = @(Get-ConfigArray -InputObject $entry -Name "members" |
            ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $definitions += [pscustomobject]@{ Name = $name; Members = $members }
    }
    return ,$definitions
}

# ---------------------------[ WMI filters on a policy object ]---------------------------
# Shared, because two roles now attach one: the PKI policy objects and the FSLogix policy
# the Remote Desktop design creates. It lived in Role.Adcs.ps1 while there was one caller.
#
# A WMI filter decides which machines a linked policy actually applies to, and none of
# them is created here. They are domain-wide objects under CN=SOM,CN=WMIPolicy,CN=System,
# written by the sibling ActiveDirectory-ToolKit from its own config/WmiFilters.json - and
# that toolkit no longer skips one it finds: it compares msWMI-Parm2 and corrects the
# drift. Two tools both correcting the same attribute is a flip-flop that rewrites itself
# on every run of either, on an object every filtered policy in the domain shares. So this
# looks a filter up and attaches it, and says which one is missing when it is not there.
#
# The lookup takes the aliases with it because the toolkit renames a filter *in place* -
# the msWMI-ID is kept, so every existing gPCWQLFilter link survives - and a design
# written against the older short name is still naming the same object.
function ConvertTo-StudioDomainDnsName {
    param([Parameter(Mandatory)][string]$DistinguishedName)

    $labels = @()
    foreach ($piece in ($DistinguishedName -split ",")) {
        $trimmed = $piece.Trim()
        if ($trimmed -match '^(?i)DC=(.+)$') { $labels += $Matches[1] }
    }
    return ($labels -join ".")
}

function Find-StudioWmiFilter {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string[]]$Alias = @(),
        [Parameter(Mandatory)][string]$DomainDn
    )

    $containerDn = "CN=SOM,CN=WMIPolicy,CN=System,$DomainDn"
    if (-not (Test-StudioDirectoryObject -DistinguishedName $containerDn)) {
        Write-Log "There is no '$containerDn' - this domain holds no WMI filters at all" -Tag "Warn"
        return $null
    }

    $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$containerDn")
    foreach ($candidate in (@($Name) + @($Alias | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }))) {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
        $searcher.Filter = "(&(objectClass=msWMI-Som)(msWMI-Name=$(ConvertTo-AdcsLdapFilterValue -Value $candidate)))"
        $null = $searcher.PropertiesToLoad.Add("msWMI-ID")
        $null = $searcher.PropertiesToLoad.Add("msWMI-Name")
        $hit = $null
        try { $hit = $searcher.FindOne() }
        catch {
            Write-Log "Could not search for the WMI filter '$candidate': $($_.Exception.Message)" -Tag "Debug"
            continue
        }
        if ($null -ne $hit) {
            return [pscustomobject]@{
                Id         = [string]$hit.Properties["mswmi-id"][0]
                Name       = [string]$hit.Properties["mswmi-name"][0]
                FoundUnder = $candidate
            }
        }
    }
    return $null
}

function Set-StudioGpoWmiFilter {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$FilterName,
        [string[]]$Alias = @(),
        [Parameter(Mandatory)][string]$DomainDn
    )

    $gpo = $null
    try { $gpo = Get-GPO -Name $Name -ErrorAction Stop }
    catch {
        Write-Log "Could not read '$Name' back to attach a WMI filter: $($_.Exception.Message)" -Tag "Warn"
        return
    }

    $filter = Find-StudioWmiFilter -Name $FilterName -Alias $Alias -DomainDn $DomainDn
    if ($null -eq $filter) {
        # Never fatal, and never created here. An unfiltered object is not a broken one:
        # nothing in this design links it, so it applies to nobody until somebody does.
        Write-Log "The WMI filter '$FilterName' does not exist in this domain - '$Name' is left unfiltered" -Tag "Warn"
        Write-Log "    Create it with the ActiveDirectory-ToolKit (config\WmiFilters.json), then run this again" -Tag "Warn"
        return
    }
    if ($filter.FoundUnder -ne $filter.Name) {
        Write-Log "Found '$FilterName' under its earlier name '$($filter.FoundUnder)' - same object, same id" -Tag "Info"
    }

    $wanted = "[$(ConvertTo-StudioDomainDnsName -DistinguishedName $DomainDn);$($filter.Id);0]"
    $gpoDn  = "CN={$($gpo.Id)},CN=Policies,CN=System,$DomainDn"

    try {
        $entry = Get-AdcsDirectoryEntry -DistinguishedName $gpoDn
        $current = [string]$entry.Properties["gPCWQLFilter"].Value
        if ($current -eq $wanted) {
            Write-Log "'$Name' already carries the '$($filter.Name)' filter" -Tag "Info"
            return
        }
        if (-not [string]::IsNullOrWhiteSpace($current)) {
            # Same rule as the object's own settings: something is already here, so
            # somebody chose it, and a run that quietly swaps a filter changes which
            # machines a linked policy reaches without saying so anywhere.
            Write-Log "'$Name' already carries a different WMI filter ($current) - leaving it alone" -Tag "Warn"
            return
        }
        Set-AdcsDirectoryProperty -Entry $entry -Name "gPCWQLFilter" -Value $wanted
        $entry.CommitChanges()
        Write-Log "'$Name' now filtered by '$($filter.Name)'" -Tag "Ok"
    }
    catch {
        Write-Log "Could not attach '$FilterName' to '$Name': $($_.Exception.Message)" -Tag "Warn"
    }
}

# ---------------------------[ Links on a policy object ]---------------------------
# A group policy object that exists changes nothing until it is linked, and every role
# in this studio that creates one now says where it belongs. That used to be an AD CS
# detail (Add-AdcsGroupPolicyLink, one target, no way to ask for it from the studio);
# it is shared here because the drive maps, the printer deployment and the FSLogix
# policy all end the same way - an object sitting in the domain applying to nobody.
#
# Nothing here creates an organizational unit. A link needs a container that already
# exists, and where a policy belongs is a statement about somebody's OU layout - the
# design names it, the run attaches to it, and a name that is not there is reported
# rather than invented.

# The targets a policy asks for, read out of the config in whatever shape it arrives.
#
# The studio writes a list of distinguished names. Three older or hand-written shapes
# still have to read: a bare string (what the AD CS contract carried when there was one
# target and no UI for it), an absent property, and the 'domainControllers' keyword -
# the one OU whose DN this script can build without being told, kept because the AD CS
# contract has always documented it. The domain DN behind that keyword is resolved only
# if the keyword is actually used: reading it up front made a directory hiccup fail a
# step before a single object was touched.
#
# -NoExpand is for the run summary, which counts these before anybody has confirmed the
# plan: expanding the keyword means an LDAP call, and a display path must not reach the
# directory to print a number. The keyword counts as one target either way.
function Get-StudioGpoLinkTarget {
    param(
        [object]$InputObject,
        [string]$Name = "linkTo",
        [string]$DomainDn = "",
        [switch]$NoExpand
    )

    $targets = @()
    foreach ($raw in @(Get-ConfigArray -InputObject $InputObject -Name $Name)) {
        $value = ([string]$raw).Trim()
        if ([string]::IsNullOrWhiteSpace($value)) { continue }

        if (($value -eq "domainControllers") -and -not $NoExpand) {
            if ([string]::IsNullOrWhiteSpace($DomainDn)) { $DomainDn = Get-AdcsDefaultNamingContext }
            if ([string]::IsNullOrWhiteSpace($DomainDn)) {
                Write-Log "'domainControllers' cannot be expanded - this machine's domain could not be read" -Tag "Error"
                continue
            }
            $value = "OU=Domain Controllers,$DomainDn"
        }

        # A design carried to more than one machine, or edited twice, can name the same
        # container twice. Linking it twice is not an error worth reporting - the second
        # attempt would find its own link and say so - but it is noise.
        if ($targets -notcontains $value) { $targets += $value }
    }
    # Returned plain, **not** as `,$targets`. Every caller wraps this in @(), and the
    # comma idiom double-wraps there: the function emits one object that is the array,
    # @() collects it as a single element, and an object with no links comes back with
    # Count 1. That reads as "linked" to anything counting, which is the wrong way for
    # this particular mistake to fall.
    return $targets
}

# `[DirectoryEntry]::Exists` does not answer false for a DN it cannot parse - it THROWS
# "An invalid dn syntax has been specified", and that exception escapes whatever called
# it. On the bench a mistyped GPO link target took the entire Remote Desktop role down
# after the policy had already been created, populated and WMI-filtered (2026-09-05):
#
#     Remote Desktop Services - Apply failed: Exception calling "Exists" with "1"
#     argument(s): "An invalid dn syntax has been specified."
#
# Everything downstream of that call was already written to carry on - one failing link
# does not stop the others, and the role reports ManualStepRequired rather than dying -
# and none of it ran, because the exception went straight past it.
#
# Every one of these paths is handed a distinguished name somebody typed: a link target,
# an organizational unit for a group, a template container. The studio's own check is a
# shape test and cannot know what AD will parse, so the question is asked here, and a DN
# that cannot be parsed is answered exactly like one that is not there - false. The two
# are worth different words: "there is no such OU" sends somebody into the directory,
# "that is not a DN" sends them back to the design.
function Test-StudioDirectoryObject {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$DistinguishedName,
        [string]$What = "object"
    )

    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) { return $false }

    try {
        return [System.DirectoryServices.DirectoryEntry]::Exists("LDAP://$DistinguishedName")
    }
    catch {
        Write-Log "'$DistinguishedName' is not a distinguished name AD can parse, so the $What cannot be looked up" -Tag "Error"
        Write-Log "    $($_.Exception.Message.Trim())" -Tag "Error"
        Write-Log "    Expected: OU=Name,OU=Parent,DC=example,DC=invalid - commas between parts, no trailing comma" -Tag "Error"
        return $false
    }
}

# Links are checked against what the target already has rather than blindly added:
# New-GPLink on an existing link is an error, and a second link to the same object at
# the same place is not something to create anyway. Moved here from Role.Adcs.ps1,
# unchanged - it was already the careful version.
function Add-StudioGpoLink {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$TargetDn
    )

    if (-not (Test-StudioDirectoryObject -DistinguishedName $TargetDn -What "link target")) {
        Write-Log "Cannot link '$Name': there is no '$TargetDn'" -Tag "Error"
        Write-Log "    The organizational unit has to exist first - this run does not create one" -Tag "Error"
        return $false
    }

    try {
        $inheritance = Get-GPInheritance -Target $TargetDn -ErrorAction Stop
        foreach ($link in @($inheritance.GpoLinks)) {
            if ([string]$link.DisplayName -eq $Name) {
                Write-Log "'$Name' is already linked to $TargetDn" -Tag "Info"
                return $true
            }
        }
    }
    catch {
        Write-Log "Could not read the existing links on '$TargetDn': $($_.Exception.Message)" -Tag "Warn"
    }

    try {
        $null = New-GPLink -Name $Name -Target $TargetDn -LinkEnabled "Yes" -ErrorAction Stop
    }
    catch {
        Write-Log "Could not link '$Name' to '$TargetDn': $($_.Exception.Message)" -Tag "Error"
        return $false
    }
    Write-Log "Linked '$Name' to $TargetDn" -Tag "Ok"
    return $true
}

# Every target one object asks for. One failing link does not stop the others: each is
# a separate container and a typo in one is no reason to leave the rest unlinked.
# Returns false if any of them failed, so the role can report ManualStepRequired - the
# object is fine, it just does not apply where the design said it would.
#
# An object with no targets is not a failure. Saying so out loud is the point: an
# unlinked policy is the state this studio shipped in for every role, and a run that
# went quiet about it would read as one that had linked something.
function Set-StudioGpoLink {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string[]]$TargetDn = @(),
        [string]$UnlinkedNote = "it changes nothing until you link it where it belongs"
    )

    $targets = @($TargetDn | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($targets.Count -eq 0) {
        Write-Log "'$Name' is not linked - $UnlinkedNote" -Tag "Info"
        return $true
    }

    $allLinked = $true
    foreach ($target in $targets) {
        if (-not (Add-StudioGpoLink -Name $Name -TargetDn $target)) { $allLinked = $false }
    }
    return $allLinked
}
