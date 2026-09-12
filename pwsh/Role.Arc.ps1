# Role provider: Azure Arc (Connected Machine agent).
#
# Dot-sourced by Configure-ServerRoles.ps1 - not runnable on its own. Everything
# here lands in that script's scope, so $script: variables and functions are shared
# with every other part. Use $scriptRootPath, never $PSScriptRoot: inside this file
# $PSScriptRoot is the pwsh folder, not the folder the run was started from.

# ===========================[ Azure Arc ]===========================

# Like Windows Admin Center and unlike every other role here, there is no Windows
# feature to install: the Connected Machine agent is a vendor MSI. The registry entry
# for this role therefore carries an empty Feature, and the run fetches the installer
# itself rather than printing an Install-WindowsFeature line nobody could run.
$script:arcDefaultDownloadUrl = "https://aka.ms/AzureConnectedMachineAgent"

# ---------------------------[ Agent ]---------------------------
# Built when they are needed rather than as this part loads: a part is dot-sourced on
# whatever machine the load check runs on, and Join-Path against a Windows drive is an
# error where that drive does not exist.
function Get-ArcAgentPath {
    return (Join-Path -Path $env:ProgramFiles -ChildPath "AzureConnectedMachineAgent\azcmagent.exe")
}

# Written by the agent itself, and the only place the connection state is readable
# without calling Azure.
function Get-ArcAgentConfigPath {
    return (Join-Path -Path $env:ProgramData -ChildPath "AzureConnectedMachineAgent\Config\agentconfig.json")
}

function Test-ArcAgentInstalled {
    return (Test-Path -LiteralPath (Get-ArcAgentPath))
}

# Same reasoning as the Windows Admin Center download: on Windows PowerShell 5.1
# Invoke-WebRequest redraws its progress bar for every chunk it reads, and 5.1 offers
# TLS 1.0 by default - aka.ms refuses that with what looks like a connection reset.
function Invoke-ArcDownload {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Destination
    )

    $previousProgress = $ProgressPreference
    $ProgressPreference = "SilentlyContinue"
    $client = $null

    try {
        [System.Net.ServicePointManager]::SecurityProtocol =
            [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

        Write-Log "Downloading $Url" -Tag "Run"
        $client = New-Object System.Net.WebClient
        $client.Headers.Add("User-Agent", "WindowsServerRoleStudio")
        $client.DownloadFile($Url, $Destination)
    }
    finally {
        $ProgressPreference = $previousProgress
        if ($null -ne $client) { $client.Dispose() }
    }

    if (-not (Test-Path -LiteralPath $Destination)) {
        throw "The download reported success but '$Destination' is not there."
    }

    # An error page is a few kilobytes of HTML and installs as cleanly as a corrupt
    # MSI does - which is to say not at all, several minutes later.
    $length = (Get-Item -LiteralPath $Destination).Length
    if ($length -lt 1MB) {
        throw "'$Destination' is only $length bytes - that is an error page, not the agent installer."
    }

    Write-Log "Downloaded $([math]::Round(($length / 1MB), 1)) MB to '$Destination'" -Tag "Ok"
}

function Get-ArcInstallerPath {
    param([Parameter(Mandatory)][object]$Agent)

    $source = [string](Get-ConfigText -InputObject $Agent -Name "source" -Default "download")

    if ($source -eq "localPath") {
        $stagedPath = [string](Get-ConfigText -InputObject $Agent -Name "installerPath" -Default "")
        if ([string]::IsNullOrWhiteSpace($stagedPath)) {
            throw "The agent source is 'localPath' but no installerPath is set."
        }
        if (-not (Test-Path -LiteralPath $stagedPath)) {
            throw "The Connected Machine agent installer '$stagedPath' does not exist."
        }
        Write-Log "Using the staged installer '$stagedPath'" -Tag "Info"
        return $stagedPath
    }

    $url = [string](Get-ConfigText -InputObject $Agent -Name "downloadUrl" -Default $script:arcDefaultDownloadUrl)

    # Beside the script, where the logs and the run state already live - $env:TEMP is
    # per account, and the resume task runs as SYSTEM. A script root that cannot be
    # written to falls back to the temp folder.
    $downloadDirectory = Join-Path -Path $scriptRootPath -ChildPath "downloads"
    try {
        if (-not (Test-Path -LiteralPath $downloadDirectory)) {
            $null = New-Item -Path $downloadDirectory -ItemType Directory -Force -ErrorAction Stop
        }
    }
    catch {
        Write-Log "Could not use '$downloadDirectory' ($($_.Exception.Message)) - downloading to '$env:TEMP' instead" -Tag "Info"
        $downloadDirectory = $env:TEMP
    }

    # aka.ms/AzureConnectedMachineAgent has served an MSI for every version of the
    # agent so far, and msiexec refuses a package not named .msi - so the name is
    # ours, not the redirector's.
    $target = Join-Path -Path $downloadDirectory -ChildPath "AzureConnectedMachineAgent.msi"
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue
    }
    Invoke-ArcDownload -Url $url -Destination $target
    return $target
}

function Install-ArcAgent {
    param([Parameter(Mandatory)][object]$Agent)

    $installerPath = Get-ArcInstallerPath -Agent $Agent
    $installLog    = Join-Path -Path (Get-LogRoleDirectory) -ChildPath "azureconnectedmachineagent.log"
    $arguments     = @("/i", "`"$installerPath`"", "/qn", "/norestart", "/L*v", "`"$installLog`"")

    Write-Log "Installing the Connected Machine agent: msiexec.exe $($arguments -join ' ')" -Tag "Run"
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru
    $exitCode = [int]$process.ExitCode

    # 3010 is "installed, wants a restart" - the agent does not need one to connect.
    if (($exitCode -ne 0) -and ($exitCode -ne 3010)) {
        throw "msiexec exited with code $exitCode - see '$installLog'."
    }

    if (-not (Test-ArcAgentInstalled)) {
        throw "The installer reported success but '$(Get-ArcAgentPath)' is not there."
    }
    Write-Log "Connected Machine agent installed" -Tag "Ok"
}

# ---------------------------[ Connection state ]---------------------------
# Every run looks at what is already there and does the next possible thing, so
# re-running is safe and the same command covers a fresh server and a connected one.
function Get-ArcConnectionState {
    $state = [pscustomobject]@{
        Connected      = $false
        SubscriptionId = ""
        ResourceGroup  = ""
        ResourceName   = ""
        TenantId       = ""
        Location       = ""
    }

    if (Test-Path -LiteralPath (Get-ArcAgentConfigPath)) {
        try {
            $document = Get-Content -LiteralPath (Get-ArcAgentConfigPath) -Raw -Encoding UTF8 | ConvertFrom-Json
            $state.SubscriptionId = [string](Get-ConfigText -InputObject $document -Name "subscriptionId" -Default "")
            $state.ResourceGroup  = [string](Get-ConfigText -InputObject $document -Name "resourceGroup" -Default "")
            $state.ResourceName   = [string](Get-ConfigText -InputObject $document -Name "resourceName" -Default "")
            $state.TenantId       = [string](Get-ConfigText -InputObject $document -Name "tenantId" -Default "")
            $state.Location       = [string](Get-ConfigText -InputObject $document -Name "location" -Default "")
        }
        catch {
            Write-Log "Could not read '$(Get-ArcAgentConfigPath)': $($_.Exception.Message)" -Tag "Info"
        }
    }

    # A machine that has never been connected still has the file, with the fields
    # empty - the subscription is what tells the two apart.
    $state.Connected = (-not [string]::IsNullOrWhiteSpace($state.SubscriptionId)) -and
                       (-not [string]::IsNullOrWhiteSpace($state.ResourceGroup))
    return $state
}

# ---------------------------[ Proxy ]---------------------------
# Written into the agent's own configuration rather than the machine's: the agent is a
# service and never sees a per-user WinINET proxy.
function Set-ArcProxyConfiguration {
    param([object]$Proxy)

    if ($null -eq $Proxy) { return }

    $url = [string](Get-ConfigText -InputObject $Proxy -Name "url" -Default "")
    if ([string]::IsNullOrWhiteSpace($url)) { return }

    Write-Log "Setting the agent proxy to '$url'" -Tag "Run"
    $output = & (Get-ArcAgentPath) "config" "set" "proxy.url" $url 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "azcmagent config set proxy.url failed (exit $LASTEXITCODE): $(@($output) -join ' ')"
    }

    $bypass = @(Get-ConfigArray -InputObject $Proxy -Name "bypass" | ForEach-Object { [string]$_ } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($bypass.Count -gt 0) {
        $bypassList = $bypass -join ","
        Write-Log "Setting the agent proxy bypass list to '$bypassList'" -Tag "Run"
        $output = & (Get-ArcAgentPath) "config" "set" "proxy.bypass" $bypassList 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "azcmagent config set proxy.bypass failed (exit $LASTEXITCODE): $(@($output) -join ' ')"
        }
    }
    Write-Log "Agent proxy configured" -Tag "Ok"
}

# ---------------------------[ Connect ]---------------------------
# Tags are only settable while connecting - afterwards they belong to the Azure
# resource, not to the agent - so a tag added later is an Azure change, not a re-run.
function Get-ArcTagArgument {
    param([object]$Connection)

    $pairs = @()
    foreach ($tag in (Get-ConfigArray -InputObject $Connection -Name "tags")) {
        $name = [string](Get-ConfigText -InputObject $tag -Name "name" -Default "")
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $value = [string](Get-ConfigText -InputObject $tag -Name "value" -Default "")
        $pairs += ("{0}={1}" -f $name, $value)
    }
    if ($pairs.Count -eq 0) { return "" }
    return ($pairs -join ",")
}

# The secret is exported into config.json only when the design says so. Without it a
# person at the console is asked; an unattended run says which setting is missing
# rather than failing inside azcmagent with an authentication error.
function Read-ArcServicePrincipalSecret {
    param([object]$Connection)

    $secret = [string](Get-ConfigText -InputObject $Connection -Name "servicePrincipalSecret" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($secret)) { return $secret }

    if ($script:noGui -or $script:isResume -or (-not [Environment]::UserInteractive)) {
        throw "azureArc.connection.servicePrincipalSecret is empty and this run cannot ask for one."
    }

    $entry = Read-Host -Prompt "Azure Arc service principal secret" -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($entry)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Get-ArcConnectArgument {
    param([Parameter(Mandatory)][object]$Connection)

    $arguments = @(
        "connect",
        "--subscription-id", [string](Get-ConfigText -InputObject $Connection -Name "subscriptionId" -Default ""),
        "--resource-group",  [string](Get-ConfigText -InputObject $Connection -Name "resourceGroup" -Default ""),
        "--tenant-id",       [string](Get-ConfigText -InputObject $Connection -Name "tenantId" -Default ""),
        "--location",        [string](Get-ConfigText -InputObject $Connection -Name "location" -Default "")
    )

    $cloud = [string](Get-ConfigText -InputObject $Connection -Name "cloud" -Default "AzureCloud")
    $arguments += @("--cloud", $cloud)

    # Blank means the machine's own name, which is what the agent defaults to - there
    # is no reason to repeat it into the command line.
    $resourceName = [string](Get-ConfigText -InputObject $Connection -Name "resourceName" -Default "")
    if (-not [string]::IsNullOrWhiteSpace($resourceName)) {
        $arguments += @("--resource-name", $resourceName)
    }

    $tags = Get-ArcTagArgument -Connection $Connection
    if (-not [string]::IsNullOrWhiteSpace($tags)) {
        $arguments += @("--tags", $tags)
    }

    return $arguments
}

# Everything except the secret, which is the one thing that must not reach a log file
# that gets mailed, copied or pasted into a ticket.
function Get-ArcSafeCommandLine {
    param([string[]]$Argument)

    $safe = @()
    $maskNext = $false
    foreach ($item in $Argument) {
        if ($maskNext) {
            $safe += "***"
            $maskNext = $false
            continue
        }
        $safe += $item
        if ($item -eq "--service-principal-secret") { $maskNext = $true }
    }
    return ("azcmagent " + ($safe -join " "))
}

function Connect-ArcMachine {
    param(
        [Parameter(Mandatory)][object]$Connection,
        [int]$RetryCount = 3,
        [int]$RetryDelaySeconds = 60
    )

    $arguments = Get-ArcConnectArgument -Connection $Connection
    $authMode  = [string](Get-ConfigText -InputObject $Connection -Name "authMode" -Default "servicePrincipal")

    if ($authMode -eq "servicePrincipal") {
        $appId = [string](Get-ConfigText -InputObject $Connection -Name "servicePrincipalAppId" -Default "")
        $arguments += @("--service-principal-id", $appId)
        $arguments += @("--service-principal-secret", (Read-ArcServicePrincipalSecret -Connection $Connection))
    }
    else {
        Write-Log "No service principal in the design - azcmagent will ask for an interactive sign-in" -Tag "Info"
    }

    if ($RetryCount -lt 1) { $RetryCount = 1 }
    $delay = $RetryDelaySeconds
    if ($delay -lt 0) { $delay = 0 }

    Write-Log (Get-ArcSafeCommandLine -Argument $arguments) -Tag "Run"

    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
        Write-Log "Connecting this machine to Azure Arc - attempt $attempt of $RetryCount" -Tag "Run"

        $output   = $null
        $exitCode = 1
        try {
            $output   = & (Get-ArcAgentPath) @arguments 2>&1
            $exitCode = $LASTEXITCODE
        }
        catch {
            Write-Log "azcmagent connect threw: $($_.Exception.Message)" -Tag "Error"
        }

        foreach ($line in @($output)) {
            if ([string]::IsNullOrWhiteSpace([string]$line)) { continue }
            Write-Log "azcmagent: $line" -Tag "Info"
        }

        if ($exitCode -eq 0) {
            Write-Log "Connected to Azure Arc" -Tag "Ok"
            return $true
        }

        # Exit 42 is "failed to create resource", which in practice is a role
        # assignment or a resource provider registration that has not finished
        # propagating - a race a freshly built server always loses. Every other
        # failure is retried too; azcmagent is idempotent enough for that.
        Write-Log "azcmagent connect failed with exit code $exitCode" -Tag "Error"
        if ($attempt -lt $RetryCount) {
            Write-Log "Retrying in $delay second(s)" -Tag "Info"
            if ($delay -gt 0) { Start-Sleep -Seconds $delay }
            $delay = $delay * 2
        }
    }

    return $false
}

# ---------------------------[ Prerequisites ]---------------------------
# Called by the engine before anything is applied, and before -CheckOnly exits.
function Test-ArcPrerequisite {
    param([object]$Config)

    $passed = $true
    $arc    = Get-ConfigValue -InputObject $Config -Name "azureArc"

    if ($null -eq $arc) {
        Write-Log "config.json has no azureArc section" -Tag "Error"
        return $false
    }

    $connection = Get-ConfigValue -InputObject $arc -Name "connection"
    if ($null -eq $connection) {
        Write-Log "azureArc has no connection section - there is no landing zone to connect to" -Tag "Error"
        return $false
    }

    foreach ($field in @("subscriptionId", "tenantId", "resourceGroup", "location")) {
        if ([string]::IsNullOrWhiteSpace([string](Get-ConfigText -InputObject $connection -Name $field -Default ""))) {
            Write-Log "azureArc.connection.$field is empty - the landing zone is incomplete" -Tag "Error"
            $passed = $false
        }
    }

    $authMode = [string](Get-ConfigText -InputObject $connection -Name "authMode" -Default "servicePrincipal")
    if (($authMode -eq "servicePrincipal") -and
        [string]::IsNullOrWhiteSpace([string](Get-ConfigText -InputObject $connection -Name "servicePrincipalAppId" -Default ""))) {
        Write-Log "azureArc.connection.servicePrincipalAppId is empty" -Tag "Error"
        $passed = $false
    }

    # There is no Install-WindowsFeature line to print for this one: the agent is a
    # vendor MSI. If the design forbids installing it, it has to be there already.
    $agent = Get-ConfigValue -InputObject $arc -Name "agent"
    $install = [bool](Get-ConfigValue -InputObject $agent -Name "install" -Default $true)
    if ((-not $install) -and (-not (Test-ArcAgentInstalled))) {
        Write-Log "The Connected Machine agent is not installed and the design does not allow installing it" -Tag "Error"
        Write-Log "    Install it by hand, or turn the agent install back on in the studio:" -Tag "Error"
        Write-Log "    $($script:arcDefaultDownloadUrl)" -Tag "Error"
        $passed = $false
    }

    return $passed
}

# ---------------------------[ Entry Point ]---------------------------
function Invoke-ArcConfiguration {
    param([object]$Config)

    $arc = Get-ConfigValue -InputObject $Config -Name "azureArc"
    if ($null -eq $arc) {
        return (New-RoleResult -Status "Failed" -Message "config.json has no azureArc section.")
    }

    # An absent agent section means "all defaults", not "nothing to do" - the download
    # URL and the install switch both have one.
    $agent = Get-ConfigValue -InputObject $arc -Name "agent"
    if ($null -eq $agent) { $agent = [pscustomobject]@{} }

    $connection = Get-ConfigValue -InputObject $arc -Name "connection"
    if ($null -eq $connection) {
        return (New-RoleResult -Status "Failed" -Message "azureArc has no connection section.")
    }

    if (-not (Test-ArcAgentInstalled)) {
        if (-not [bool](Get-ConfigValue -InputObject $agent -Name "install" -Default $true)) {
            return (New-RoleResult -Status "ManualStepRequired" -Message "The Connected Machine agent is missing and this design does not install it.")
        }
        Install-ArcAgent -Agent $agent
    }
    else {
        Write-Log "The Connected Machine agent is already installed" -Tag "Info"
    }

    Set-ArcProxyConfiguration -Proxy (Get-ConfigValue -InputObject $arc -Name "proxy")

    $wantedSubscription = [string](Get-ConfigText -InputObject $connection -Name "subscriptionId" -Default "")
    $wantedGroup        = [string](Get-ConfigText -InputObject $connection -Name "resourceGroup" -Default "")
    $current            = Get-ArcConnectionState

    if ($current.Connected) {
        # Disconnecting deletes the Azure resource and everything hanging off it -
        # extensions, policy assignments, machine configuration. That is a decision,
        # not a step, so a machine pointing somewhere else is reported rather than
        # moved.
        if (($current.SubscriptionId -eq $wantedSubscription) -and ($current.ResourceGroup -eq $wantedGroup)) {
            Write-Log "Already connected as '$($current.ResourceName)' in '$($current.ResourceGroup)'" -Tag "Info"
            Write-Log "Tags are set while connecting - change them on the Azure resource, not here" -Tag "Info"
            return (New-RoleResult -Status "Completed" -Message "This machine is already connected to Azure Arc.")
        }

        $message = "This machine is connected to '{0}' in subscription '{1}', not to the design's '{2}' / '{3}'. Run 'azcmagent disconnect' first if that is what you want - it deletes the Azure resource and its extensions." -f `
            $current.ResourceGroup, $current.SubscriptionId, $wantedGroup, $wantedSubscription
        Write-Log $message -Tag "Error"
        return (New-RoleResult -Status "ManualStepRequired" -Message $message)
    }

    $retryCount = [int](Get-ConfigValue -InputObject $connection -Name "retryCount" -Default 3)
    $retryDelay = [int](Get-ConfigValue -InputObject $connection -Name "retryDelaySeconds" -Default 60)

    if (-not (Connect-ArcMachine -Connection $connection -RetryCount $retryCount -RetryDelaySeconds $retryDelay)) {
        return (New-RoleResult -Status "Failed" -Message "azcmagent connect did not succeed after $retryCount attempt(s).")
    }

    $now = Get-ArcConnectionState
    if (-not $now.Connected) {
        return (New-RoleResult -Status "Failed" -Message "azcmagent reported success but the agent configuration still holds no resource.")
    }

    Write-Log "Arc resource '$($now.ResourceName)' in '$($now.ResourceGroup)' ($($now.Location))" -Tag "Ok"
    return (New-RoleResult -Status "Completed" -Message "This machine is connected to Azure Arc as '$($now.ResourceName)'.")
}
