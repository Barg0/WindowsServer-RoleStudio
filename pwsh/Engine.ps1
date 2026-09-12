# The run engine: role registry, plan, prerequisites, resume state, dispatch.
#
# Dot-sourced by Configure-ServerRoles.ps1 - not runnable on its own. Everything
# here lands in that script's scope, so $script: variables and functions are shared
# with every other part. Use $scriptRootPath, never $PSScriptRoot: inside this file
# $PSScriptRoot is the pwsh folder, not the folder the run was started from.

# ---------------------------[ Role Registry ]---------------------------
# Generated from tools/make-script.py. Order is deployment order.
$script:supportedSchemaVersion = 3

$script:roleRegistry = @(
    [pscustomobject]@{
        Id         = 'Hyper-V'
        Prefix     = 'Hyperv'
        Section    = 'hyperV'
        # Empty for the Exchange reason, and a stronger one: this role installs the
        # feature itself, because a host cannot be configured before it is a hypervisor.
        # A feature named here would refuse the run over the very thing it is here to do.
        Feature    = ''
        Display    = 'Hyper-V'
        # First. A hypervisor sits underneath everything else a design might put on this
        # machine, and its install owes a restart that everything behind it would wait on.
        Order      = 5
        MayReboot  = $true
        PostReboot = $true
    }
    [pscustomobject]@{
        Id         = 'AD-Domain-Services'
        Prefix     = 'Adds'
        Section    = 'activeDirectory'
        Feature    = 'AD-Domain-Services'
        Display    = 'Active Directory Domain Services'
        Order      = 10
        MayReboot  = $true
        PostReboot = $true
    }
    [pscustomobject]@{
        Id         = 'DNS'
        Prefix     = 'Dns'
        Section    = 'dnsServer'
        Feature    = 'DNS'
        Display    = 'DNS Server'
        Order      = 20
        MayReboot  = $false
        PostReboot = $false
    }
    [pscustomobject]@{
        Id         = 'File-Services'
        Prefix     = 'Fs'
        Section    = 'fileServer'
        # Empty for the AD CS reason, not the Windows Admin Center one: this role
        # runs on two kinds of machine - the file server, which needs FS-FileServer,
        # and a domain controller running the directory half (share groups and
        # members), which does not. Test-FsPrerequisite asks per machine.
        Feature    = ''
        Display    = 'File Server'
        Order      = 35
        MayReboot  = $false
        PostReboot = $false
    }
    [pscustomobject]@{
        Id         = 'Print-Services'
        Prefix     = 'Print'
        Section    = 'printServer'
        # Empty for the File Server reason: this role runs on two kinds of machine - the
        # print server, which needs Print-Services, and a domain controller running the
        # directory half (printer groups, members and the deployment GPOs), which does
        # not. Test-PrintPrerequisite asks per machine.
        Feature    = ''
        Display    = 'Print Server'
        Order      = 36
        MayReboot  = $false
        PostReboot = $false
    }
    [pscustomobject]@{
        Id         = 'DHCP'
        Prefix     = 'Dhcp'
        Section    = 'dhcp'
        # Empty for the File Server reason: this role runs on two kinds of machine - the
        # DHCP server, which needs the DHCP feature, and a domain controller creating the
        # DNS registration account, which does not. Test-DhcpPrerequisite asks per machine.
        Feature    = ''
        Display    = 'DHCP Server'
        # Behind DNS and AD DS: a scope hands out DNS servers, and authorizing the
        # server is a write into a directory that has to exist first.
        Order      = 25
        MayReboot  = $false
        PostReboot = $false
    }
    [pscustomobject]@{
        Id         = 'WindowsAdminCenter'
        Prefix     = 'Wac'
        Section    = 'windowsAdminCenter'
        # No Windows feature to check: on Server 2025 the Server Manager entry is a
        # downloader, not a payload, so there is no Install-WindowsFeature line to
        # print. This provider runs the vendor installer instead - the one place
        # in this script where that is true.
        Feature    = ''
        Display    = 'Windows Admin Center'
        Order      = 40
        MayReboot  = $false
        PostReboot = $false
    }
    [pscustomobject]@{
        Id         = 'Remote-Desktop-Services'
        Prefix     = 'Rds'
        Section    = 'remoteDesktop'
        # Empty for the same reason File Server, Print Server and DHCP are: this config
        # is also carried to a **domain controller**, where the provider creates the
        # access groups and the FSLogix policy and installs nothing. A feature named here
        # is demanded on every machine the config reaches, so the engine would refuse the
        # directory trip with "Feature 'RDS-RD-Server' is unknown on this operating
        # system" before the provider ever got to say what it was there for.
        # Test-RdsPrerequisite asserts the session host role services itself, per machine,
        # and prints them as one Install-WindowsFeature line.
        Feature    = ''
        Display    = 'Remote Desktop Services'
        Order      = 45
        MayReboot  = $true
        PostReboot = $false
    }
    [pscustomobject]@{
        Id         = 'AzureArc'
        Prefix     = 'Arc'
        Section    = 'azureArc'
        # Same as Windows Admin Center: the Connected Machine agent is a vendor MSI,
        # not a Windows feature, so there is no Install-WindowsFeature line to print.
        Feature    = ''
        Display    = 'Azure Arc'
        Order      = 50
        MayReboot  = $false
        PostReboot = $false
    }
    [pscustomobject]@{
        Id         = 'EntraPrivateNetworkConnector'
        Prefix     = 'Connector'
        Section    = 'entraConnector'
        # The third vendor installer, same rule as Windows Admin Center and Arc.
        Feature    = ''
        Display    = 'Entra Private Network Connector'
        Order      = 55
        MayReboot  = $false
        PostReboot = $false
    }
    [pscustomobject]@{
        Id         = 'AD-Certificate'
        Prefix     = 'Adcs'
        Section    = 'certificateServices'
        # Empty, and checked by the provider instead - which is not the Windows Admin
        # Center reason. This role runs on three kinds of machine: the two CAs, which
        # do need ADCS-Cert-Authority, and the domain controller running the directory
        # tier, which must not have it. Asserting it here would demand a CA feature on
        # a DC. Test-AdcsPrerequisite asks for it per tier, with the same message.
        Feature    = ''
        Display    = 'Active Directory Certificate Services'
        Order      = 30
        # The SCEP tier ends in a reboot when the MSCEP slots or the http.sys limits
        # changed - values read at driver start, where iisreset is explicitly not
        # enough. Test-AdcsRebootPending answers $false so the planner never holds
        # the other tiers hostage; the reboot is signalled by the RebootRequired
        # result itself, and the PostReboot stage is what verifies the endpoint
        # after the restart.
        MayReboot  = $true
        PostReboot = $true
    }
    [pscustomobject]@{
        Id         = 'Exchange-Server'
        Prefix     = 'Exchange'
        Section    = 'exchange'
        # A vendor installer from an ISO, the Windows Admin Center reason - and the
        # one role whose setup installs its own Windows features, because Microsoft's
        # supported path is /InstallWindowsComponents and second-guessing an
        # installer that takes an hour to say so is worse.
        Feature    = ''
        Display    = 'Exchange Server'
        # Last: it needs the directory, DNS and usually the PKI before it means
        # anything, and its install is the longest thing this script ever starts.
        Order      = 60
        MayReboot  = $true
        PostReboot = $true
    }
    [pscustomobject]@{
        Id         = 'AcmeRenewal'
        Prefix     = 'Acme'
        Section    = 'acmeRenewal'
        # Nothing to install and nothing to check for: this role adds a certificate to
        # a service somebody else already built, so what it needs is that service to be
        # present - which is Test-AcmePrerequisite's whole job.
        Feature    = ''
        Display    = "Let's Encrypt certificate and renewal"
        # Alone in its own design (the catalogue marks it standalone), so the order only
        # decides where it sits in a one-step plan.
        Order      = 70
        MayReboot  = $false
        PostReboot = $false
    }
)

# ---------------------------[ Role Result ]---------------------------
# What every provider function hands back to the engine.
# The restart the run has been asking a person to perform - when the role that asked
# wants it done for them.
#
# Deliberately not a global setting. It lived in `general` for about an hour and that was
# wrong: "restart this server automatically" is not a property of a run, it is a property
# of the one role that finishes by needing a restart and cannot continue without it.
# Exchange is that role - setup completes, the server has to come back before the
# namespace, the certificate and the hardening can be applied. A domain controller
# reboots itself during promotion and never asks. So the engine holds no opinion and no
# switch: it asks the role, through an optional `Get-<Prefix>AutoRestartDelay` hook,
# and a role without one never restarts anything.
#
# Two refusals stay here, because they are the engine's business rather than the role's:
#
#   the resume task has to exist  A restart with nothing scheduled to continue leaves a
#                                 half-configured server that no longer knows it was
#                                 mid-run. Checked against the task actually being
#                                 registered, not the intention to.
#   shutdown.exe has to be there  Nothing else in this repo assumes a Windows binary is
#                                 present without looking.
#
# The delay is the third safety and the reason this uses shutdown.exe rather than
# Restart-Computer: somebody watching the console gets a window, the message says why,
# and 'shutdown /a' is a real answer for as long as it lasts.
function Start-StudioRestart {
    param(
        [Parameter(Mandatory)][object]$Config,
        [Parameter(Mandatory)][object]$Role,
        [Parameter(Mandatory)][bool]$TaskOwned
    )

    $hook = "Get-" + $Role.Prefix + "AutoRestartDelay"
    if (-not (Get-Command -Name $hook -ErrorAction SilentlyContinue)) { return $false }

    $delaySeconds = [int](& $hook -Config $Config)
    if ($delaySeconds -le 0) {
        Write-Log "$($Role.Display): restart left to you" -Tag "Info"
        return $false
    }
    if ($delaySeconds -lt 15) { $delaySeconds = 15 }
    if ($delaySeconds -gt 3600) { $delaySeconds = 3600 }

    if (-not $TaskOwned) {
        Write-Log "$($Role.Display) wants a restart but no resume task is registered - not restarting" -Tag "Warn"
        return $false
    }

    if (-not (Get-Command -Name "shutdown.exe" -ErrorAction SilentlyContinue)) {
        Write-Log "shutdown.exe not found - restart this server by hand" -Tag "Warn"
        return $false
    }

    Write-Log "Restarting in $delaySeconds s - the resume task carries the plan on" -Tag "Run"
    Write-Log "    shutdown /a  within $delaySeconds s to stop it" -Tag "Info"

    try {
        $arguments = @("/r", "/t", [string]$delaySeconds, "/c", "`"Windows Server Role Studio: restarting to continue the run`"")
        $process = Start-Process -FilePath "shutdown.exe" -ArgumentList $arguments -Wait -PassThru -NoNewWindow -ErrorAction Stop
        if ([int]$process.ExitCode -ne 0) {
            Write-Log "shutdown.exe exit $([int]$process.ExitCode) - not scheduled, restart by hand" -Tag "Warn"
            return $false
        }
    }
    catch {
        Write-Log "Restart not scheduled: $($_.Exception.Message)" -Tag "Warn"
        return $false
    }

    Write-Log "Restart scheduled - this log ends here, a new one starts after the reboot" -Tag "Ok"
    return $true
}

function New-RoleResult {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Completed", "RebootRequired", "ManualStepRequired", "Failed")]
        [string]$Status,
        [string]$Message = ""
    )

    return [pscustomobject]@{
        Status  = $Status
        Message = $Message
    }
}

# ---------------------------[ Environment Checks ]---------------------------
function Test-ElevatedSession {
    try {
        $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        Write-Log "Elevation unknown: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

function Test-ServerOperatingSystem {
    try {
        $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        # ProductType 1 is a workstation; 2 is a domain controller; 3 is a member server.
        return ($operatingSystem.ProductType -ne 1)
    }
    catch {
        Write-Log "OS product type unknown: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
}

function Test-MachinePrerequisite {
    param([object]$Config)

    $problems = @()

    if (-not (Test-ElevatedSession)) {
        $problems += "This script must run in an elevated session."
    }
    if (-not (Test-ServerOperatingSystem)) {
        $problems += "This machine is not running a Windows Server edition."
    }

    # There is deliberately no global "this config is for computer X" check. Which
    # server a design is for is named by the role that cares - each PKI tier, the
    # Remote Desktop deployment - and one config is meant to be carried across three
    # machines that each apply their own part of it.
    $schemaVersion = [int](Get-ConfigValue -InputObject $Config -Name "schemaVersion" -Default 0)
    if ($schemaVersion -ne $script:supportedSchemaVersion) {
        $problems += "Unsupported config schemaVersion '$schemaVersion'. This script understands version $($script:supportedSchemaVersion)."
    }

    foreach ($problem in $problems) {
        Write-Log $problem -Tag "Error"
    }
    return ($problems.Count -eq 0)
}

# Installation is out of scope for this repository. The most this script does
# about a missing role is tell you exactly how to add it.
function Test-RoleInstalled {
    param(
        [Parameter(Mandatory)][string]$FeatureName,
        [Parameter(Mandatory)][string]$DisplayName
    )

    try {
        $feature = Get-WindowsFeature -Name $FeatureName -ErrorAction Stop
    }
    catch {
        Write-Log "Feature query failed: $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    if ($null -eq $feature) {
        Write-Log "Feature '$FeatureName' unknown on this OS" -Tag "Error"
        return $false
    }
    if (-not $feature.Installed) {
        Write-Log "$DisplayName is not installed" -Tag "Error"
        return $false
    }
    return $true
}

# Only the roles that actually run in this phase are checked. A role deferred
# past the reboot is checked in the resumed run instead, because the reboot is
# often what installs it - promotion pulls in DNS on its own.
function Test-RolePrerequisite {
    param(
        [object]$Config,
        [object[]]$Roles
    )

    $allPassed = $true
    $missing   = @()

    foreach ($role in $Roles) {
        # A role with no Feature is one Windows does not install - Windows Admin
        # Center ships as its own installer, not a role - nothing to look up.
        if (-not [string]::IsNullOrWhiteSpace([string]$role.Feature)) {
            if (-not (Test-RoleInstalled -FeatureName $role.Feature -DisplayName $role.Display)) {
                $missing  += $role
                $allPassed = $false
                continue
            }
        }

        $hookName = "Test-" + $role.Prefix + "Prerequisite"
        if (-not (Get-Command -Name $hookName -ErrorAction SilentlyContinue)) { continue }

        $script:currentRole = $role.Id
        $hookPassed = [bool](& $hookName -Config $Config)
        $script:currentRole = ""
        if (-not $hookPassed) { $allPassed = $false }
    }

    if ($missing.Count -gt 0) {
        $featureList = @($missing | ForEach-Object { $_.Feature }) -join ", "
        Write-Log "Install the missing role(s), then run again:" -Tag "Error"
        Write-Log "    Install-WindowsFeature -Name $featureList -IncludeManagementTools" -Tag "Error"
    }

    return $allPassed
}

# ---------------------------[ Role Selection ]---------------------------
function Get-SelectedRole {
    param([object]$Config)

    $requested = @()
    foreach ($entry in (Get-ConfigArray -InputObject $Config -Name "roles")) {
        $roleId = [string](Get-ConfigValue -InputObject $entry -Name "id" -Default "")
        if (-not [string]::IsNullOrWhiteSpace($roleId)) { $requested += $roleId }
    }

    if ($requested.Count -eq 0) {
        Write-Log "config.json selects no roles" -Tag "Error"
        return @()
    }

    $known    = @($script:roleRegistry | ForEach-Object { $_.Id })
    $selected = @()

    foreach ($role in @($script:roleRegistry | Sort-Object -Property Order)) {
        if ($requested -notcontains $role.Id) { continue }
        if (($script:roleFilter.Count -gt 0) -and ($script:roleFilter -notcontains $role.Id)) {
            Write-Log "Skipping '$($role.Display)' - not in -Role" -Tag "Info"
            continue
        }
        if (-not (Test-ConfigProperty -InputObject $Config -Name $role.Section)) {
            Write-Log "Skipping '$($role.Display)' - no '$($role.Section)' section in config.json" -Tag "Info"
            continue
        }
        # "Is this role for this machine?", asked of the role rather than assumed.
        #
        # One config describes a whole design, and the same file is carried to every
        # server in it - so a role being in `roles` means the *design* has it, not that
        # this machine is the one that gets it. The tiered roles already answer this
        # themselves by computer name; the flat ones used to answer it in their
        # prerequisite check, which is the wrong place: a prerequisite that returns false
        # fails the whole run, so the domain controller carrying an Exchange design
        # exited 1 without ever reaching the DNS records it was there to write.
        #
        # The hook is optional. A role without one is a role that runs wherever it lands,
        # which is the right default for every role that has no opinion about it.
        $appliesHook = "Test-" + $role.Prefix + "AppliesHere"
        if (Get-Command -Name $appliesHook -ErrorAction SilentlyContinue) {
            if (-not [bool](& $appliesHook -Config $Config)) {
                Write-Log "Skipping '$($role.Display)' - designed for another machine" -Tag "Info"
                continue
            }
        }
        $selected += $role
    }

    # Roles the studio can select but this script has no provider for. They are
    # installed by hand; saying so beats silence.
    foreach ($roleId in $requested) {
        if ($known -notcontains $roleId) {
            Write-Log "Skipping '$roleId' - no provider in this script" -Tag "Info"
        }
    }

    return $selected
}

# ---------------------------[ Run Plan ]---------------------------
# A flat list of steps in deployment order: every role's Apply, followed by its
# PostReboot stage when it declares one.
function New-RunPlan {
    param([object[]]$Roles)

    $plan = @()
    foreach ($role in $Roles) {
        $plan += [pscustomobject]@{
            RoleId   = $role.Id
            # Carried on the step so the run loop can reach a role's optional hooks
            # without going back to the registry for the name it already had.
            Prefix   = $role.Prefix
            Display  = $role.Display
            Stage    = "Apply"
            Function = "Invoke-" + $role.Prefix + "Configuration"
            Key      = $role.Id + ":Apply"
        }

        if ($role.PostReboot) {
            $plan += [pscustomobject]@{
                RoleId   = $role.Id
                Prefix   = $role.Prefix
                Display  = $role.Display
                Stage    = "PostReboot"
                Function = "Invoke-" + $role.Prefix + "PostReboot"
                Key      = $role.Id + ":PostReboot"
            }
        }
    }
    return $plan
}

# Which roles still owe the machine a restart. A role without the hook is taken
# at its word: if it can reboot, assume it has not yet.
function Get-PendingRebootRole {
    param([object[]]$Roles)

    $pending = @()
    foreach ($role in $Roles) {
        if (-not $role.MayReboot) { continue }

        $hookName = "Test-" + $role.Prefix + "RebootPending"
        if (-not (Get-Command -Name $hookName -ErrorAction SilentlyContinue)) {
            $pending += $role.Id
            continue
        }

        $script:currentRole = $role.Id
        $isPending = [bool](& $hookName)
        $script:currentRole = ""
        if ($isPending) { $pending += $role.Id }
    }
    return $pending
}

# The run stops right after the Apply stage of the first role that still owes a
# restart - that stage is what triggers it, and nothing behind it can run yet.
function Get-RunnableStepCount {
    param(
        [object[]]$Plan,
        [string[]]$PendingRebootRole
    )

    if (@($PendingRebootRole).Count -eq 0) { return $Plan.Count }

    for ($index = 0; $index -lt $Plan.Count; $index++) {
        $step = $Plan[$index]
        if (($step.Stage -eq "Apply") -and (@($PendingRebootRole) -contains $step.RoleId)) {
            return ($index + 1)
        }
    }
    return $Plan.Count
}

function Write-RunPlan {
    param(
        [object[]]$Plan,
        [string[]]$CompletedStep,
        [int]$RunnableStepCount
    )

    Write-Log "Run plan:" -Tag "Info"
    for ($index = 0; $index -lt $Plan.Count; $index++) {
        $step = $Plan[$index]
        $note = "now"
        if ($index -ge $RunnableStepCount) { $note = "after the restart" }
        if (@($CompletedStep) -contains $step.Key) { $note = "already done" }
        Write-Log "    $($step.Display) - $($step.Stage) ($note)" -Tag "Info"
    }
}

# ---------------------------[ Run State ]---------------------------
# The state file is a shortcut, never the truth. Every provider stays idempotent,
# so a lost or stale state file costs a re-run, not a broken server.
$script:stateFilePath  = Join-Path -Path $scriptRootPath -ChildPath ".wsrs-run.json"
$script:resumeTaskName = "WSRS-Resume"

function Get-RunState {
    if (-not (Test-Path -LiteralPath $script:stateFilePath)) { return $null }
    try {
        return (Get-Content -LiteralPath $script:stateFilePath -Raw -Encoding UTF8 | ConvertFrom-Json)
    }
    catch {
        Write-Log "Run state unreadable - starting from the top" -Tag "Warn"
        return $null
    }
}

function Save-RunState {
    param(
        [Parameter(Mandatory)][string]$ConfigFilePath,
        [string[]]$CompletedStep
    )

    $state = [pscustomobject]@{
        schemaVersion  = 1
        configPath     = $ConfigFilePath
        completedSteps = @($CompletedStep)
    }

    try {
        $state | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $script:stateFilePath -Encoding UTF8
    }
    catch {
        Write-Log "Run state not written: $($_.Exception.Message)" -Tag "Error"
    }
}

function Remove-RunState {
    if (-not (Test-Path -LiteralPath $script:stateFilePath)) { return }
    try {
        Remove-Item -LiteralPath $script:stateFilePath -Force -ErrorAction Stop
    }
    catch {
        Write-Log "Run state not removed: $($_.Exception.Message)" -Tag "Debug"
    }
}

# ---------------------------[ Follow-up Task ]---------------------------
# A role that reboots takes the session with it, so the rest of the plan is
# handed to the task scheduler: one task, at startup, as SYSTEM, that runs this
# same script with -Resume and removes itself once the plan is finished.
function Register-ResumeTask {
    param([Parameter(Mandatory)][string]$ConfigFilePath)

    if (-not (Get-Command -Name "Register-ScheduledTask" -ErrorAction SilentlyContinue)) {
        Write-Log "ScheduledTasks module unavailable - run this script again by hand after the restart" -Tag "Warn"
        return $false
    }

    $configFullPath = $ConfigFilePath
    try {
        $configFullPath = (Resolve-Path -Path $ConfigFilePath -ErrorAction Stop).Path
    }
    catch {
        Write-Log "'$ConfigFilePath' not resolved - the task uses it as given" -Tag "Debug"
    }

    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -ConfigPath "{1}" -Resume -NoGui' -f $script:entryScriptPath, $configFullPath

    try {
        $existing = Get-ScheduledTask -TaskName $script:resumeTaskName -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Unregister-ScheduledTask -TaskName $script:resumeTaskName -Confirm:$false -ErrorAction Stop
        }

        $action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arguments -WorkingDirectory $scriptRootPath
        $trigger = New-ScheduledTaskTrigger -AtStartup
        # Services need a moment after boot; the providers also wait on their own.
        $trigger.Delay = "PT2M"
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)

        $null = Register-ScheduledTask -TaskName $script:resumeTaskName -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings `
            -Description "Windows Server Role Studio - finishes the role configuration after a restart" -ErrorAction Stop
    }
    catch {
        Write-Log "Resume task not registered: $($_.Exception.Message)" -Tag "Error"
        return $false
    }

    Write-Log "Resume task '$($script:resumeTaskName)': 2 min after the next start" -Tag "Ok"
    return $true
}

function Unregister-ResumeTask {
    if (-not (Get-Command -Name "Unregister-ScheduledTask" -ErrorAction SilentlyContinue)) { return }
    $existing = Get-ScheduledTask -TaskName $script:resumeTaskName -ErrorAction SilentlyContinue
    if ($null -eq $existing) { return }

    try {
        Unregister-ScheduledTask -TaskName $script:resumeTaskName -Confirm:$false -ErrorAction Stop
        Write-Log "Resume task '$($script:resumeTaskName)' removed" -Tag "Ok"
    }
    catch {
        Write-Log "Resume task not removed: $($_.Exception.Message)" -Tag "Debug"
    }
}

# ---------------------------[ Dispatcher ]---------------------------
# Only the roles with a step that can run in this pass are checked. A role behind
# the restart is checked once the machine comes back, because the restart is
# often what installs it - promotion pulls in DNS on its own.
function Get-PhaseRole {
    param(
        [object[]]$Roles,
        [object[]]$Plan,
        [string[]]$CompletedStep,
        [int]$RunnableStepCount
    )

    $phaseRoleIds = @()
    for ($index = 0; $index -lt $RunnableStepCount; $index++) {
        $step = $Plan[$index]
        if (@($CompletedStep) -contains $step.Key) { continue }
        if ($phaseRoleIds -notcontains $step.RoleId) { $phaseRoleIds += $step.RoleId }
    }

    return @($Roles | Where-Object { $phaseRoleIds -contains $_.Id })
}

function Invoke-RunPlan {
    param(
        [object]$Config,
        [object[]]$Plan,
        [string[]]$CompletedStep,
        [int]$RunnableStepCount,
        [Parameter(Mandatory)][string]$ConfigFilePath
    )

    # Same reason as -Role above: keep a stray $null out of the array, or it lands in
    # the state file and comes back as a completed step called nothing.
    $completed = @($CompletedStep | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $waiting   = @()
    for ($index = $RunnableStepCount; $index -lt $Plan.Count; $index++) {
        if ($completed -contains $Plan[$index].Key) { continue }
        $waiting += $Plan[$index]
    }

    $script:restartTriggered = $false

    $needsResume = ($waiting.Count -gt 0)
    $taskOwned   = $false

    $general    = Get-ConfigValue -InputObject $Config -Name "general"
    $autoResume = [bool](Get-ConfigValue -InputObject $general -Name "autoResumeAfterReboot" -Default $true)

    # Registered before the first step, because the role that restarts the server
    # does not come back to register anything.
    if ($needsResume) {
        Save-RunState -ConfigFilePath $ConfigFilePath -CompletedStep $completed
        if ($autoResume) {
            $taskOwned = [bool](Register-ResumeTask -ConfigFilePath $ConfigFilePath)
        }
        else {
            Write-Log "autoResumeAfterReboot off - no resume task" -Tag "Info"
        }
        if (-not $taskOwned) {
            Write-Log "    Run this script again after the restart to finish the plan" -Tag "Info"
        }
    }

    for ($index = 0; $index -lt $RunnableStepCount; $index++) {
        $step = $Plan[$index]
        if ($completed -contains $step.Key) { continue }

        $script:currentRole = $step.RoleId
        Write-Log "$($step.Display) - $($step.Stage)" -Tag "Run"

        $result = $null
        try {
            $result = & $step.Function -Config $Config
        }
        catch {
            $result = New-RoleResult -Status "Failed" -Message $_.Exception.Message
        }

        if ($null -eq $result) { $result = New-RoleResult -Status "Completed" }

        # The scope is cleared AFTER the verdict is written, in every branch below, so a
        # role's own log file ends with that role's own outcome. Cleared here instead -
        # which it was - and "this node is ready for the cluster" went to the run log
        # alone, leaving logs\<role>\ trailing off after whatever the provider happened to
        # write last. What stays unscoped is what belongs to the run rather than to a
        # role: the resume task, the restart, the closing summary.
        if ($result.Status -eq "Completed") {
            if (-not [string]::IsNullOrWhiteSpace($result.Message)) {
                Write-Log $result.Message -Tag "Ok"
            }
            $script:currentRole = ""
            $completed += $step.Key
            if ($needsResume) { Save-RunState -ConfigFilePath $ConfigFilePath -CompletedStep $completed }
            continue
        }

        if ($result.Status -eq "RebootRequired") {
            # The message first, while the role still owns the scope; the task and the
            # restart after it, because those are the run's business and not this role's.
            if (-not [string]::IsNullOrWhiteSpace($result.Message)) {
                Write-Log $result.Message -Tag "Info"
            }
            $script:currentRole = ""
            $completed += $step.Key
            Save-RunState -ConfigFilePath $ConfigFilePath -CompletedStep $completed
            if ($autoResume -and (-not $taskOwned)) {
                $taskOwned = [bool](Register-ResumeTask -ConfigFilePath $ConfigFilePath)
            }
            if (Start-StudioRestart -Config $Config -Role $step -TaskOwned $taskOwned) { return 0 }
            Write-Log "    Restart this server to continue the plan" -Tag "Info"
            return 0
        }

        if ($result.Status -eq "ManualStepRequired") {
            Write-Log "$($step.Display): manual step needed" -Tag "Warn"
            if (-not [string]::IsNullOrWhiteSpace($result.Message)) {
                Write-Log $result.Message -Tag "Info"
            }
            $script:currentRole = ""
            Save-RunState -ConfigFilePath $ConfigFilePath -CompletedStep $completed
            return 0
        }

        # Failed. The state file and the task stay behind on purpose - the next
        # start retries this step instead of losing the run.
        $failureMessage = $result.Message
        if ([string]::IsNullOrWhiteSpace($failureMessage)) { $failureMessage = "no reason given" }
        Write-Log "$($step.Display) - $($step.Stage) failed: $failureMessage" -Tag "Error"
        $script:currentRole = ""
        Save-RunState -ConfigFilePath $ConfigFilePath -CompletedStep $completed
        return 1
    }

    if ($waiting.Count -gt 0) {
        foreach ($step in $waiting) {
            Write-Log "$($step.Display) - $($step.Stage): waiting for the restart" -Tag "Info"
        }
        if ($taskOwned) {
            Write-Log "Nothing left by hand - the resume task finishes the plan after the next start" -Tag "Info"
        }
        return 0
    }

    Unregister-ResumeTask
    Remove-RunState
    Write-Log "Every selected role is configured" -Tag "Ok"
    return 0
}
