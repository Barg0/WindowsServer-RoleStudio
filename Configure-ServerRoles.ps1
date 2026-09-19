#Requires -Version 5.1
<#
.SYNOPSIS
    Configures the Windows Server roles described in config.json.

.DESCRIPTION
    One script for every role the studio supports. The 'roles' array in
    config.json selects what runs; each role reads only its own section.

    This script configures already installed roles. It never installs one.
    If a selected role is missing it stops and prints the Install-WindowsFeature
    command you need, then exits.

    When a role reboots the server - a domain controller promotion does - the
    script registers a follow-up task, and everything that has to wait for the
    restart continues on its own after the next start.

    config.json is produced by ServerRoleConfigurator.html (Windows Server Role
    Studio).

.PARAMETER ConfigPath
    Path to config.json. Optional: without it the script looks for config.json
    next to itself, then in the current directory, then one folder deeper, and
    accepts any single file that looks like a studio export.

.PARAMETER CheckOnly
    Validate the config and the local machine, print the run plan, then exit
    without changing anything.

.PARAMETER Role
    Configure only these role ids out of config.json. Useful to retry one role.

.PARAMETER Resume
    Continue an interrupted run from the state file. The follow-up task passes
    this after a reboot; there is rarely a reason to pass it by hand.

.PARAMETER Task
    Run a single job rather than the role plan, and exit. Registered tasks pass
    this; there is no reason to pass it by hand - except 'ConnectorToken', which
    is run by a person on a machine with a browser and a connector installed. It
    signs in interactively and writes the Entra connector's registration token to
    a file to carry to the server that is being registered.

.PARAMETER NoGui
    Skip the review screen and apply the configuration straight away. From a
    script, a scheduled task or a redirected console this is already the default -
    the screen only appears for a person at a keyboard.

.PARAMETER LogDebug
    Show the Debug tag as well. A normal run logs what happened; the reasoning
    behind it - why a default is the default, what a setting protects against, the
    detail behind a decision - is written at Debug and appears only with this.

.NOTES
    Target shell : Windows PowerShell 5.1 and PowerShell 7
    Encoding     : UTF-8 with BOM, ASCII content only
    Layout       : this script is the entry point; the engine, the console UI and
                   one file per role provider are dot-sourced from the 'pwsh'
                   folder beside it. Copy both to the server, not the script alone.
#>

[CmdletBinding()]
param (
    [Parameter(HelpMessage = "Path to config.json. Optional - the script finds it when omitted.")]
    [string]$ConfigPath,

    [Parameter(HelpMessage = "Validate only; change nothing on this machine.")]
    [switch]$CheckOnly,

    [Parameter(HelpMessage = "Configure only these role ids from config.json.")]
    [string[]]$Role,

    [Parameter(HelpMessage = "Continue an interrupted run. Set by the follow-up task.")]
    [switch]$Resume,

    [Parameter(HelpMessage = "Skip the review screen and apply the configuration straight away.")]
    [switch]$NoGui,
    # Turns the Debug tag on. The reasoning behind a decision - why a default is the
    # default, what a setting protects against - is written at Debug rather than Info, so
    # a normal run reads as what happened and this switch is where the rest of it went.
    [switch]$LogDebug,

    [Parameter(HelpMessage = "Run one job instead of the role plan. Set by a registered task, except ConnectorToken.")]
    # 'Certificate' is the one nightly job: it renews whatever certificates this server
    # holds. 'WacCertificate' is what that task was called while it belonged to Windows
    # Admin Center alone, and is still accepted so a task registered by an older run
    # keeps working until it is re-registered. 'CaBackup' is the issuing CA's nightly
    # database backup. 'ExchangeLogs' prunes the Exchange and IIS logging trees, which
    # Exchange itself does not. 'RdsPortal' is the only one that runs hourly: it keeps
    # the full desktop on the Remote Desktop web feed, a single registry value that
    # Windows clears on every broker restart and every collection change. Two are run by
    # a person rather than by a task: 'ConnectorToken' signs in on a machine with a
    # browser to mint the Entra connector's registration token, because that token cannot
    # be acquired on the server itself, and 'AdcsAssess' reads an existing CA and writes
    # what it found into the transfer folder for the studio's adopt mode.
    #
    # **A task name missing from this list is a task that cannot be run at all** - the
    # parameter binder refuses it before the switch below is ever reached, and the
    # failure looks like the task name being wrong rather than unlisted.
    [ValidateSet("Certificate", "WacCertificate", "CaBackup", "ExchangeLogs", "RdsPortal", "ConnectorToken", "AdcsAssess")]
    [string]$Task,

    # For '-Task Certificate' only, and for a person rather than a schedule. The nightly
    # task asks Posh-ACME to renew and Posh-ACME declines while the certificate is still
    # comfortably inside its window - which is correct every night of the year and
    # useless when the thing being tested is the renewal itself. This adds -Force to
    # that call, so the order is renewed now and every step after it - the binding, the
    # back-end check, the mail report - runs against a certificate that really did
    # change. It spends a Let's Encrypt issuance, so it is a switch and not a default.
    [Parameter(HelpMessage = "With -Task Certificate: renew now even though the certificate is not due.")]
    [switch]$ForceRenewal,

    # What a registered task carries so it does not need the whole project beside it.
    # A nightly renewal on a Windows Admin Center gateway reaches four of the parts
    # below; staging all twenty-seven of them - 2.1 MB, every role this studio can
    # configure - so that one of them can be dot-sourced was bloat with nothing behind
    # it. The task's own action now names its parts, which means the scheduled action
    # is also the honest documentation of what the job loads: read the task in Task
    # Scheduler and you can see it.
    #
    # Named on the command line rather than in a file beside the parts, deliberately.
    # Two tasks can share one deploy folder and need different parts of it, and a file
    # would have to belong to one of them; an argument belongs to whichever task is
    # running. The order is ignored - the list below is what decides load order, always,
    # because Logging and Config must be first and nothing else may depend on the shape
    # of an argument somebody hand-edits.
    # ONE comma-separated string and not a [string[]]: powershell.exe -File hands every
    # argument to the script as a literal string, so '-Part a.ps1,b.ps1' binds as the
    # single name 'a.ps1,b.ps1' and every task would refuse itself. Split here instead.
    [Parameter(HelpMessage = "Load only these parts, comma separated. Set by a registered task; an unknown name is refused.")]
    [string]$Part = ""
)

# Lifted here, at top level, where PSScriptAnalyzer can see the parameters being
# used - it does not follow a parameter into a function body.
# @($null) is an array of length one holding $null, not an empty array, so an
# unsupplied -Role would otherwise read as "a filter that matches nothing" and skip
# every role in the config. Strip the empties instead of trusting the count.
$script:roleFilter = @($Role | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$script:isResume   = [bool]$Resume
$script:noGui      = [bool]$NoGui
$script:logDebugRequested = [bool]$LogDebug
$script:taskName   = [string]$Task
$script:forceRenewal = [bool]$ForceRenewal
# Providers are handed the config object, not the file it came from. The one that
# registers a task needs the path as well, so it is published here.
$script:configFilePath = ""

# ---------------------------[ Script Name and Root ]---------------------------
$scriptName = "Configure-ServerRoles"

# The one thing that cannot move into a part: inside a dot-sourced file $PSScriptRoot
# is the pwsh folder, not the folder the run was started from. Everything else reads
# this variable instead.
$scriptRootPath = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# Every progress bar this run would draw, silenced. Get-WindowsFeature paints
# "Collecting data..." across the console for the tens of seconds it spends walking the
# component store, which is most of what a prerequisite check looks like from outside;
# the downloads in the agent providers already did this locally for the same reason.
$ProgressPreference = "SilentlyContinue"

# ---------------------------[ Script Parts ]---------------------------
# The engine, the console UI and one file per role provider live in 'pwsh' beside this
# script and are dot-sourced into this scope, so they share $script: state and
# $scriptRootPath and a function defined in one is callable from any other. This file
# stays the only entry point: the parameter block, the log setup and the run itself.
#
# A missing part is a broken run, not a degraded one, so the load stops at the first
# gap - and it stops with Write-Host and a bare exit, because Write-Log and
# Complete-Script are themselves in one of these files. That is the only place in this
# repo where a bare exit is correct.
$script:moduleDirectory = Join-Path -Path $scriptRootPath -ChildPath "pwsh"

# $PSCommandPath means "this file" only while this file is the one being run - inside a
# dot-sourced part it is that part. The task registrations need the entry point, so it
# is published here rather than read where it would already be wrong.
$script:entryScriptPath = $PSCommandPath
if ([string]::IsNullOrWhiteSpace($script:entryScriptPath)) {
    $script:entryScriptPath = Join-Path -Path $scriptRootPath -ChildPath "Configure-ServerRoles.ps1"
}

# Order matters for the statements a part runs as it loads - logging before anything
# that logs, the engine's registry before the providers it names. Function definitions
# do not care; the top-level assignments do.
$script:scriptParts = @(
    "Logging.ps1",
    "Config.ps1",
    "Engine.ps1",
    "Mail.ps1",
    "Acme.ps1",
    "Media.ps1",
    "Storage.ps1",
    "Cluster.ps1",
    "Role.Hyperv.ps1",
    "Role.Hyperv.Cluster.ps1",
    "Role.Hyperv.S2d.ps1",
    "Role.Adds.ps1",
    "Role.Dns.ps1",
    "Role.Adcs.ps1",
    "Role.Adcs.Ndes.ps1",
    "Role.Adcs.Pkcs.ps1",
    "Directory.ps1",
    "Role.Fs.ps1",
    "Role.Fs.Cluster.ps1",
    "Role.Print.ps1",
    "Role.Dhcp.ps1",
    "Role.Wac.ps1",
    "Role.Rds.ps1",
    "Role.Arc.ps1",
    "Role.Connector.ps1",
    "Role.Exchange.ps1",
    "Role.Acme.ps1",
    "ConsoleUi.ps1"
)

# A part named that this project does not have is refused here rather than skipped: a
# task carrying a typo would otherwise run with one part quietly absent and fail later
# inside a function that is simply not defined.
$script:requestedPart = @()
if (-not [string]::IsNullOrWhiteSpace($Part)) {
    $script:requestedPart = @($Part -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}
if ($script:requestedPart.Count -gt 0) {
    $unknownPart = @($script:requestedPart | Where-Object { $script:scriptParts -notcontains $_ })
    if ($unknownPart.Count -gt 0) {
        Write-Host "Not a part of this script: $($unknownPart -join ', ')" -ForegroundColor Red
        exit 1
    }
    $script:scriptParts = @($script:scriptParts | Where-Object { $script:requestedPart -contains $_ })
}

foreach ($scriptPart in $script:scriptParts) {
    $scriptPartPath = Join-Path -Path $script:moduleDirectory -ChildPath $scriptPart
    if (-not (Test-Path -LiteralPath $scriptPartPath)) {
        Write-Host "Missing '$scriptPartPath' - copy the whole folder to this server, not just this script." -ForegroundColor Red
        # The folder a task was staged into holds that task's parts and no others, so
        # this is also what a full run started from a deploy folder looks like.
        if ($script:requestedPart.Count -eq 0) {
            Write-Host "If this is a task deployment folder it holds only what its tasks load - run the script from a full copy." -ForegroundColor Red
        }
        exit 1
    }
    . $scriptPartPath
}

# After Logging.ps1 has set its own default, because that is the variable this flips.
if ($script:logDebugRequested) { $logDebug = $true }

# ---------------------------[ Script Start ]---------------------------
Write-Log "==================== Start ====================" -Tag "Start"
Write-Log "$env:COMPUTERNAME | $env:USERNAME | $scriptName" -Tag "Info"

$runState     = Get-RunState
$completedRun = @()

if ($script:isResume) {
    Write-Log "Resuming an interrupted run" -Tag "Info"
    if ($null -eq $runState) {
        Write-Log "No run state file found - every step of the plan runs again" -Tag "Info"
    }
    else {
        $completedRun = @(Get-ConfigArray -InputObject $runState -Name "completedSteps")
        if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
            $ConfigPath = [string](Get-ConfigValue -InputObject $runState -Name "configPath" -Default "")
        }
    }
}

# The assessment reads a CA that already exists and writes down what it found. It is
# the one task with nothing to apply, so demanding the design it is meant to help write
# is backwards - a config is honoured when there is one and its absence is not an error.
$script:configOptional = ($script:taskName -eq "AdcsAssess")
$config = $null

try {
    if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        $ConfigPath = Find-ConfigFile
        Write-Log "Found config '$ConfigPath'" -Tag "Get"
    }
    else {
        Write-Log "Loading config '$ConfigPath'" -Tag "Get"
    }
    $config = Get-ConfigObject -Path $ConfigPath
}
catch {
    if (-not $script:configOptional) {
        Write-Log $_.Exception.Message -Tag "Error"
        Write-Log "Export config.json from ServerRoleConfigurator.html and place it next to this script" -Tag "Error"
        Complete-Script -ExitCode 1
    }
    Write-Log "No config.json, and the '$($script:taskName)' task does not need one - reading this server as it is" -Tag "Info"
    $config = $null
}

# Nothing to check a machine against without a config, and the assessment writes to no
# machine anyway.
if ($null -ne $config -and -not (Test-MachinePrerequisite -Config $config)) {
    Complete-Script -ExitCode 1
}

$script:configFilePath = $ConfigPath

# A registered task asks for one job, not for the role plan. It runs, it reports,
# it exits - no plan, no state file, no review screen.
if (-not [string]::IsNullOrWhiteSpace($script:taskName)) {
    Write-Log "Running the '$($script:taskName)' task" -Tag "Info"
    $script:currentRole = $script:taskName
    $taskExit = 1
    try {
        switch ($script:taskName) {
            "Certificate"    { $taskExit = [int](Invoke-CertificateTask -Config $config) }
            "WacCertificate" { $taskExit = [int](Invoke-CertificateTask -Config $config) }
            "CaBackup"       { $taskExit = [int](Invoke-AdcsCaBackupTask -Config $config) }
            "AdcsAssess"     { $taskExit = [int](Invoke-AdcsAssessment -Config $config) }
            "ExchangeLogs"   { $taskExit = [int](Invoke-ExchangeLogCleanupTask -Config $config) }
            "RdsPortal"      { $taskExit = [int](Invoke-RdsPortalTask -Config $config) }
            "ConnectorToken" { $taskExit = [int](Invoke-ConnectorTokenTask -Config $config) }
            default          { Write-Log "No handler for task '$($script:taskName)'" -Tag "Error" }
        }
    }
    catch {
        Write-Log "The task failed: $($_.Exception.Message)" -Tag "Error"
        $taskExit = 1
    }
    $script:currentRole = ""
    Complete-Script -ExitCode $taskExit
}

$selectedRoles = @(Get-SelectedRole -Config $config)
if ($selectedRoles.Count -eq 0) {
    Write-Log "No configurable role is selected in config.json" -Tag "Error"
    Complete-Script -ExitCode 1
}

$runPlan      = @(New-RunPlan -Roles $selectedRoles)
$pendingRoles = @(Get-PendingRebootRole -Roles $selectedRoles)
$runnableSteps = [int](Get-RunnableStepCount -Plan $runPlan -PendingRebootRole $pendingRoles)

Write-RunPlan -Plan $runPlan -CompletedStep $completedRun -RunnableStepCount $runnableSteps

$phaseRoles = @(Get-PhaseRole -Roles $selectedRoles -Plan $runPlan -CompletedStep $completedRun -RunnableStepCount $runnableSteps)
if (-not (Test-RolePrerequisite -Config $config -Roles $phaseRoles)) {
    Complete-Script -ExitCode 1
}
Write-Log "Prerequisite checks passed" -Tag "Ok"

if ($CheckOnly) {
    Write-Log "CheckOnly was requested - no changes were made" -Tag "Info"
    Complete-Script -ExitCode 0
}

if (Test-SummaryScreenWanted) {
    if (-not (Confirm-RunPlan -Config $config -Plan $runPlan -RunnableStepCount $runnableSteps -ConfigFilePath $ConfigPath)) {
        Write-Log "Cancelled at the review screen - nothing was changed" -Tag "Info"
        Complete-Script -ExitCode 0
    }
    Write-Log "Confirmed at the review screen" -Tag "Info"
}

$exitCode = Invoke-RunPlan -Config $config -Plan $runPlan -CompletedStep $completedRun `
    -RunnableStepCount $runnableSteps -ConfigFilePath $ConfigPath
Complete-Script -ExitCode $exitCode
