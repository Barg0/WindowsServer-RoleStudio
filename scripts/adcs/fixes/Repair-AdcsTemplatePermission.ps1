#Requires -Version 5.1
<#
.SYNOPSIS
    Retrofits three certificate template permission fixes onto an AD CS deployment
    built by Windows Server Role Studio before 2026-09-19.

.DESCRIPTION
    Standalone by design. It dot-sources nothing, needs no modules beyond what Windows
    ships, and talks to the directory through System.DirectoryServices - so it runs from
    a folder of its own on the CA, on a domain controller, or on any domain member. The
    logging below is a deliberate copy of pwsh\Logging.ps1 rather than a reference to it,
    for the same reason: a retrofit that only works inside a full checkout is not one.

    Three changes, each skippable:

    1. The template managers group holds GenericAll on CN=Certificate Templates and
       CN=OID, inherited by every template. On a template object the only two extended
       rights that exist are Enroll and Autoenroll, so that grant quietly made the group
       an autoenrolling principal on every template in the forest - and a member signing
       in anywhere had its autoenrollment client submit for every template flagged
       CT_FLAG_AUTO_ENROLLMENT, the domain controller one included, which the CA then
       denied one by one. Replaced with the same mask minus ExtendedRight - 983295,
       CCDCLCSWRPWPDTLOSDRCWDWO - which is what Microsoft grants Domain Admins on their
       own CN=KerberosAuthentication.

    2. Every template the studio created carries an explicit NT AUTHORITY\SYSTEM full
       control ACE. It comes from the pKICertificateTemplate class defaultSecurityDescriptor,
       which an object created without an explicit descriptor inherits, and it carries CR -
       Enroll and Autoenroll again. Microsoft's own templates have no SYSTEM entry at all.
       Removed per template, because the ACE is explicit and is not inherited from the
       container: clearing it at CN=Certificate Templates would change nothing below.

    3. The Domain Controller Authentication (Kerberos) template is missing Enterprise
       Read-only Domain Controllers, which the built-in Kerberos Authentication grants.
       An RODC is not a member of Domain Controllers, so without it the first read-only
       domain controller promoted into the forest silently never enrolls.

    Every change is idempotent and supports -WhatIf. Nothing is deleted, no template is
    rebuilt, and no enrollment grant this design did not write is touched.

    Order matters on the first pass, which is why the skip switches default to off. Step
    one restores the inheritance that a hand edit of the container usually drops, and
    steps two and three reach the templates through it.

.PARAMETER TemplateManagerGroup
    sAMAccountName of the template managers group. Default is the studio's name.

.PARAMETER KerberosTemplateName
    CN of the domain controller template. Default is the studio's sanitized name.

.PARAMETER LogRoot
    Folder to write logs under. Defaults to the toolbox root when this script sits in its
    scripts folder, so the run lands in logs\adcs\ beside the role's own runs, and to the
    script's own folder when it has been copied out on its own.

.PARAMETER LogDebug
    Turns the Debug tag on - the reasoning behind each decision rather than just what
    happened. Same switch, same meaning, as the entry script.

.EXAMPLE
    .\Repair-AdcsTemplatePermission.ps1 -WhatIf
    .\Repair-AdcsTemplatePermission.ps1 -LogDebug
#>
# ConfirmImpact is deliberately Medium. At High every one of the forty template objects
# would stop and ask, which turns a retrofit into forty keystrokes and trains the operator
# to hold Enter. -WhatIf is the dry run; -Confirm is there for anyone who wants prompts.
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string]$TemplateManagerGroup = 'AD CS - Template Managers',
    [string]$KerberosTemplateName = 'DomainControllerAuthenticationKerberos',
    [string]$LogRoot,
    [switch]$LogDebug,
    [switch]$SkipContainerAcl,
    [switch]$SkipSystemAce,
    [switch]$SkipReadOnlyDomainControllers
)

$ErrorActionPreference = 'Stop'

# =================================================================================
# Logging. A copy of pwsh\Logging.ps1's behaviour, not a reference to it - see the
# note in the description. Same line format, same tag spellings, same five-wide
# column, same colours, same two log files, so a retrofit reads identically to a run
# and lands in the folder somebody already opens to ask what happened to this CA.
# =================================================================================
$scriptStartTime = Get-Date
$script:logEnabled = $true
$script:logDebug   = [bool]$LogDebug
# Empty on purpose. The bracket after the tag names the ROLE a line was written
# under, and this script is not running one - a [AD-Certificate] on every line of a
# hand-run tool claims a run that never happened. The log still lands in logs\adcs\,
# because that is where somebody looks for what happened to this CA.
$script:currentRole = ''

if ([string]::IsNullOrWhiteSpace($LogRoot)) {
    # Beside the role's own runs when this is still in the toolbox, beside the
    # script when it has been copied out alone.
    # Walk up looking for the toolbox root rather than checking one level. The scripts
    # folder is nested by area now - scripts\adcs\fixes - so the sibling pwsh folder
    # that marks the root is three levels above this file, not one. Four levels is
    # plenty and stops dead at the drive root; finding nothing means this script has
    # been copied out on its own, and then its own folder is the right answer.
    $LogRoot = $PSScriptRoot
    $probe = $PSScriptRoot
    for ($up = 0; $up -lt 4; $up++) {
        if ([string]::IsNullOrWhiteSpace($probe)) { break }
        if (Test-Path -LiteralPath (Join-Path -Path $probe -ChildPath 'pwsh')) { $LogRoot = $probe; break }
        $probe = Split-Path -Path $probe -Parent
    }
}

$script:logFileName = (Get-Date -Format 'yyyyMMdd-HHmm') + '.log'
$script:logTargets  = @()
foreach ($folder in @('run', 'adcs')) {
    $directory = Join-Path -Path (Join-Path -Path $LogRoot -ChildPath 'logs') -ChildPath $folder
    try {
        if (-not (Test-Path -LiteralPath $directory)) {
            $null = New-Item -ItemType Directory -Path $directory -Force
        }
        $script:logTargets += (Join-Path -Path $directory -ChildPath $script:logFileName)
    }
    catch {
        # Logging must never block execution. A folder that cannot be created costs
        # that copy of the line, not the line and not the run.
    }
}

function Write-Log {
    [CmdletBinding()]
    param(
        [string]$Message,
        [string]$Tag = 'Info'
    )

    if (-not $script:logEnabled) { return }
    if (($Tag -eq 'Debug') -and (-not $script:logDebug)) { return }

    # InvariantCulture, not -Format. In a .NET custom format string ':' is the TIME
    # SEPARATOR placeholder, not a literal, so on a Finnish-locale server 'HH:mm:ss'
    # renders as 10.44.39 and the log stops being greppable by the shape everything
    # else in this repo writes. The date is safe either way - '-' is a literal - but
    # both are pinned here so the line is the same on every server in the estate.
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)

    # Lower case and five characters wide, so the message column starts in the same
    # place on every line and the eye reads down the text rather than down a ragged
    # edge. Both old spellings still map, exactly as in the toolbox.
    $tagMap = @{
        'start'   = 'start'
        'get'     = 'get'
        'run'     = 'run'
        'info'    = 'info'
        'warn'    = 'warn'
        'warning' = 'warn'
        'ok'      = 'o.k.'
        'success' = 'o.k.'
        'error'   = 'error'
        'debug'   = 'debug'
        'end'     = 'end'
    }

    $key = $Tag.Trim().ToLowerInvariant()
    # A tag outside the map renders as an error rather than being dropped, so a typo
    # is loud instead of invisible.
    $shown = $tagMap[$key]
    if ([string]::IsNullOrWhiteSpace($shown)) { $shown = 'error' }
    $rawTag = $shown.PadRight(5)

    $color = switch ($shown) {
        'start' { 'Cyan' }
        'get'   { 'Blue' }
        'run'   { 'Magenta' }
        'info'  { 'Yellow' }
        # There is no orange in ConsoleColor. DarkYellow is ANSI 3, which every current
        # scheme renders orange-brown, against info's Yellow = ANSI 11, the pale bright
        # one - so warn reads as the louder of the two, not the dimmer.
        'warn'  { 'DarkYellow' }
        'o.k.'  { 'Green' }
        'error' { 'Red' }
        'debug' { 'DarkGray' }
        'end'   { 'Cyan' }
        default { 'White' }
    }

    $scope = ''
    if (-not [string]::IsNullOrWhiteSpace($script:currentRole)) {
        $scope = '[' + $script:currentRole + '] '
    }
    $logMessage = "$timestamp [ $rawTag ] $scope$Message"

    foreach ($target in $script:logTargets) {
        # -ErrorAction Stop is what makes the catch a catch: without it Add-Content
        # reports a locked file as a NON-TERMINATING error, which walks straight past
        # try/catch and prints the whole red block mid-run. A lock on a log file is
        # transient by nature, so it is retried rather than swallowed; after three
        # attempts the line is lost and the run carries on.
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

    Write-Host "$timestamp " -NoNewline
    Write-Host '[ ' -NoNewline -ForegroundColor White
    Write-Host "$rawTag" -NoNewline -ForegroundColor $color
    Write-Host ' ] ' -NoNewline -ForegroundColor White
    Write-Host "$scope$Message"
}

function Complete-Script {
    param([int]$ExitCode)

    $script:currentRole = ''
    $duration = (Get-Date) - $scriptStartTime

    Write-Log "Runtime $($duration.ToString('hh\:mm\:ss\.ff'))" -Tag 'Info'
    Write-Log "Exit $ExitCode" -Tag 'Info'
    Write-Log '==================== End ====================' -Tag 'End'

    exit $ExitCode
}

# =================================================================================
# Directory helpers
# =================================================================================
$enrollRight     = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$autoEnrollRight = [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

# GenericAll minus ExtendedRight. Spelled out rather than computed so the value is
# readable next to the SDDL it produces: CCDCLCSWRPWPDTLOSDRCWDWO, mask 983295.
$managerRights = [System.DirectoryServices.ActiveDirectoryRights]'CreateChild, DeleteChild, ListChildren, Self, ReadProperty, WriteProperty, DeleteTree, ListObject, Delete, ReadControl, WriteDacl, WriteOwner'

function Get-RootDseValue {
    param([Parameter(Mandatory)][string]$Name)
    $rootDse = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE')
    return [string]$rootDse.Properties[$Name].Value
}

function Get-DomainSid {
    param([Parameter(Mandatory)][string]$NamingContext)
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$NamingContext")
    return New-Object System.Security.Principal.SecurityIdentifier($entry.Properties['objectSid'].Value, 0)
}

# Name to SID. The directory search is tried first rather than NTAccount.Translate,
# because a group this design created minutes ago may not have reached the LSA cache,
# and because a name is the one thing written in the language the forest was installed in.
function Get-GroupSid {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$NamingContext)

    $escaped = $Name -replace '([\\()*\x00])', '\$1'
    $searcher = New-Object System.DirectoryServices.DirectorySearcher(
        (New-Object System.DirectoryServices.DirectoryEntry("LDAP://$NamingContext")),
        "(&(objectClass=group)(sAMAccountName=$escaped))")
    $null = $searcher.PropertiesToLoad.Add('objectSid')
    $found = $searcher.FindOne()
    if ($null -ne $found) {
        return New-Object System.Security.Principal.SecurityIdentifier($found.Properties['objectsid'][0], 0)
    }
    try {
        return (New-Object System.Security.Principal.NTAccount($Name)).Translate([System.Security.Principal.SecurityIdentifier])
    }
    catch {
        return $null
    }
}

# The SID an access rule names, whatever form it arrived in. Names are never compared
# here: a localised name is not the one in the catalogue, and on a German domain every
# ACE a run had just written came back looking like somebody else's.
function Get-AceSid {
    param([Parameter(Mandatory)][object]$Rule)
    if ($Rule.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
        return [string]$Rule.IdentityReference.Value
    }
    try { return [string]$Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
    catch { return '' }
}

# The name this machine prints for a SID - what the certificates console shows, so a
# log line matches what somebody is looking at.
function Get-SidDisplayName {
    param([Parameter(Mandatory)][object]$Sid)
    try { return [string]$Sid.Translate([System.Security.Principal.NTAccount]).Value }
    catch { return [string]$Sid.Value }
}

# =================================================================================
$failures = 0

Write-Log '==================== Start ====================' -Tag 'Start'
Write-Log 'Repairing certificate template permissions' -Tag 'Info'

try {
    $configurationNc = Get-RootDseValue -Name 'configurationNamingContext'
    $defaultNc       = Get-RootDseValue -Name 'defaultNamingContext'
    $rootNc          = Get-RootDseValue -Name 'rootDomainNamingContext'
}
catch {
    Write-Log "No directory answered: $($_.Exception.Message)" -Tag 'Error'
    Complete-Script -ExitCode 1
}

$templatesDn = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configurationNc"
$oidDn       = "CN=OID,CN=Public Key Services,CN=Services,$configurationNc"

Write-Log "Templates container: $templatesDn" -Tag 'Debug'
Write-Log "Logs: $(Join-Path -Path $LogRoot -ChildPath 'logs')" -Tag 'Debug'
if ($WhatIfPreference) { Write-Log 'WhatIf was requested - nothing will be written' -Tag 'Warn' }

# ---------------------------------------------------------------------------------
# 1. The template managers grant on the two containers.
# ---------------------------------------------------------------------------------
if ($SkipContainerAcl) {
    Write-Log 'Container grant skipped by request' -Tag 'Info'
}
else {
    Write-Log 'Template managers grant on the containers' -Tag 'Info'
    Write-Log '    GenericAll carries ExtendedRight, and on a template that is Enroll and Autoenroll' -Tag 'Debug'

    $managerSid = Get-GroupSid -Name $TemplateManagerGroup -NamingContext $defaultNc
    if ($null -eq $managerSid) {
        Write-Log "'$TemplateManagerGroup' could not be resolved - the container grant was left alone" -Tag 'Error'
        $failures++
    }
    else {
        Write-Log "'$TemplateManagerGroup' is $($managerSid.Value)" -Tag 'Debug'
        foreach ($containerDn in @($templatesDn, $oidDn)) {
            try {
                $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$containerDn")
                $entry.RefreshCache(@('nTSecurityDescriptor'))
                $security = $entry.ObjectSecurity

                $existing = @($security.Access | Where-Object {
                    (-not $_.IsInherited) -and ((Get-AceSid -Rule $_) -eq $managerSid.Value)
                })

                $alreadyRight = ($existing.Count -eq 1) -and
                    ($existing[0].ActiveDirectoryRights -eq $managerRights) -and
                    ($existing[0].InheritanceType -eq [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All) -and
                    ($existing[0].AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow)

                if ($alreadyRight) {
                    Write-Log "Already correct on $containerDn" -Tag 'Ok'
                    continue
                }

                Write-Log "$($existing.Count) explicit entry/entries to replace on $containerDn" -Tag 'Debug'
                if ($PSCmdlet.ShouldProcess($containerDn, "replace '$TemplateManagerGroup' with read and write, inherited, no extended rights")) {
                    # Purge, not add: AddAccessRule MERGES, so a narrower rule added beside
                    # the old GenericAll leaves the extended rights exactly where they were,
                    # and the step would report a fix that changed nothing.
                    $null = $security.PurgeAccessRules($managerSid)
                    $security.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $managerSid, $managerRights,
                        [System.Security.AccessControl.AccessControlType]::Allow,
                        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)))
                    $entry.ObjectSecurity = $security
                    $entry.CommitChanges()
                    Write-Log "Granted read and write on $containerDn, inherited by the objects in it" -Tag 'Ok'
                }
            }
            catch {
                Write-Log "Could not write the permissions on $($containerDn): $($_.Exception.Message)" -Tag 'Error'
                $failures++
            }
        }
    }
}

# ---------------------------------------------------------------------------------
# 2. The explicit SYSTEM ACE on each template.
# ---------------------------------------------------------------------------------
if ($SkipSystemAce) {
    Write-Log 'SYSTEM removal skipped by request' -Tag 'Info'
}
else {
    Write-Log 'Explicit SYSTEM entries on the templates' -Tag 'Info'
    Write-Log '    It arrives from the pKICertificateTemplate defaultSecurityDescriptor, not from this design' -Tag 'Debug'

    $systemSid = New-Object System.Security.Principal.SecurityIdentifier(
        [System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)

    $cleared = 0
    $clean   = 0
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher(
            (New-Object System.DirectoryServices.DirectoryEntry("LDAP://$templatesDn")),
            '(objectClass=pKICertificateTemplate)')
        $searcher.PageSize = 200
        $null = $searcher.PropertiesToLoad.Add('distinguishedName')
        $null = $searcher.PropertiesToLoad.Add('cn')
        $results = $searcher.FindAll()
    }
    catch {
        Write-Log "Could not read the templates container: $($_.Exception.Message)" -Tag 'Error'
        $results = @()
        $failures++
    }

    foreach ($result in $results) {
        $templateDn = [string]$result.Properties['distinguishedname'][0]
        $templateCn = [string]$result.Properties['cn'][0]
        try {
            $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$templateDn")
            $entry.RefreshCache(@('nTSecurityDescriptor'))
            $security = $entry.ObjectSecurity

            # Explicit only. An inherited SYSTEM entry would belong to a decision made
            # further up the tree and cannot be removed from the object that inherited it.
            $explicit = @($security.Access | Where-Object {
                (-not $_.IsInherited) -and ((Get-AceSid -Rule $_) -eq $systemSid.Value)
            })
            if ($explicit.Count -eq 0) { $clean++; continue }

            if ($PSCmdlet.ShouldProcess($templateCn, 'remove the explicit SYSTEM entry')) {
                # PurgeAccessRules, not RemoveAccessRuleSpecific: the specific form matches
                # on the whole rule and leaves the descriptor untouched when it matches none.
                $null = $security.PurgeAccessRules($systemSid)
                $entry.ObjectSecurity = $security
                $entry.CommitChanges()
                Write-Log "SYSTEM removed from $templateCn" -Tag 'Ok'
                $cleared++
            }
        }
        catch {
            Write-Log "Could not remove SYSTEM from $($templateCn): $($_.Exception.Message)" -Tag 'Error'
            $failures++
        }
    }
    Write-Log "$cleared template(s) cleared, $clean already without one" -Tag 'Info'
}

# ---------------------------------------------------------------------------------
# 3. Enterprise Read-only Domain Controllers on the Kerberos template.
# ---------------------------------------------------------------------------------
if ($SkipReadOnlyDomainControllers) {
    Write-Log 'Read-only domain controller grant skipped by request' -Tag 'Info'
}
else {
    Write-Log 'Enterprise Read-only Domain Controllers on the Kerberos template' -Tag 'Info'
    Write-Log '    An RODC is not a member of Domain Controllers, so the template grants it nothing today' -Tag 'Debug'

    $templateDn = "CN=$KerberosTemplateName,$templatesDn"
    $exists = $false
    try { $exists = [System.DirectoryServices.DirectoryEntry]::Exists("LDAP://$templateDn") } catch { $exists = $false }

    if (-not $exists) {
        Write-Log "$templateDn does not exist - nothing was granted. Pass -KerberosTemplateName if yours is named differently." -Tag 'Warn'
    }
    else {
        try {
            # RID 498 on the FOREST ROOT domain's SID. The group is universal and lives in
            # the root domain, the same shape as Enterprise Admins - reading the account
            # domain from a child would mint the SID of a group that does not exist, and
            # .NET has no WellKnownSidType that names this one.
            $rootSid = Get-DomainSid -NamingContext $rootNc
            $rodcSid = New-Object System.Security.Principal.SecurityIdentifier("$($rootSid.Value)-498")
            Write-Log "$(Get-SidDisplayName -Sid $rodcSid) is $($rodcSid.Value)" -Tag 'Debug'

            $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$templateDn")
            $entry.RefreshCache(@('nTSecurityDescriptor'))
            $security = $entry.ObjectSecurity

            $held = @($security.Access | Where-Object { (Get-AceSid -Rule $_) -eq $rodcSid.Value })
            $hasAuto = @($held | Where-Object {
                ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -and
                ([string]$_.ObjectType -eq [string]$autoEnrollRight)
            }).Count -gt 0

            if ($hasAuto) {
                Write-Log "Already holds enroll and autoenroll on $KerberosTemplateName" -Tag 'Ok'
            }
            elseif ($PSCmdlet.ShouldProcess($KerberosTemplateName, 'grant Enterprise Read-only Domain Controllers read, enroll and autoenroll')) {
                $security.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $rodcSid, [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
                    [System.Security.AccessControl.AccessControlType]::Allow)))
                $security.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $rodcSid, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                    [System.Security.AccessControl.AccessControlType]::Allow, $enrollRight)))
                $security.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $rodcSid, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                    [System.Security.AccessControl.AccessControlType]::Allow, $autoEnrollRight)))
                $entry.ObjectSecurity = $security
                $entry.CommitChanges()
                Write-Log "Granted enroll and autoenroll on $KerberosTemplateName" -Tag 'Ok'
            }
        }
        catch {
            Write-Log "Could not grant the read-only domain controllers: $($_.Exception.Message)" -Tag 'Error'
            $failures++
        }
    }
}

# ---------------------------------------------------------------------------------
if ($WhatIfPreference) {
    Write-Log 'WhatIf - nothing was written. Run again without -WhatIf to apply.' -Tag 'Warn'
}
else {
    Write-Log "Verify with: dsacls `"$templatesDn`"" -Tag 'Info'
    Write-Log "        and: dsacls `"CN=$KerberosTemplateName,$templatesDn`"" -Tag 'Info'
    Write-Log 'Then restart certsvc on the CA, and run certutil -policycache -f followed by certutil -pulse on a client.' -Tag 'Info'
}

if ($failures -gt 0) {
    Write-Log "$failures step(s) failed - the directory was not fully updated" -Tag 'Error'
    Complete-Script -ExitCode 1
}
Complete-Script -ExitCode 0
