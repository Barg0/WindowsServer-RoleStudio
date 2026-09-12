# Finding, reading and reading out of config.json.
#
# Dot-sourced by Configure-ServerRoles.ps1 - not runnable on its own. Everything
# here lands in that script's scope, so $script: variables and functions are shared
# with every other part. Use $scriptRootPath, never $PSScriptRoot: inside this file
# $PSScriptRoot is the pwsh folder, not the folder the run was started from.

# ---------------------------[ Configuration Loading ]---------------------------
function Get-ConfigObject {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Config file not found: $Path"
    }

    try {
        $rawJson = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
        return ($rawJson | ConvertFrom-Json)
    }
    catch {
        throw "Config file is not valid JSON: $($_.Exception.Message)"
    }
}

# A studio export carries both of these, which is what tells it apart from any
# other .json sitting in the folder.
function Test-StudioConfigFile {
    param([Parameter(Mandatory)][string]$Path)

    try {
        $candidate = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        return $false
    }
    if (-not (Test-ConfigProperty -InputObject $candidate -Name "schemaVersion")) { return $false }
    return (Test-ConfigProperty -InputObject $candidate -Name "roles")
}

# -ConfigPath is optional: look next to the script first, then in the working
# directory, then one level down, and only accept files that look like an export.
function Find-ConfigFile {
    $searchRoots = @($scriptRootPath)
    $currentPath = (Get-Location).Path
    if ($currentPath -ne $scriptRootPath) { $searchRoots += $currentPath }

    foreach ($root in $searchRoots) {
        $preferred = Join-Path -Path $root -ChildPath "config.json"
        if (Test-Path -LiteralPath $preferred) { return $preferred }
    }

    $candidates = @()
    foreach ($root in $searchRoots) {
        # -Depth needs -Recurse on Windows PowerShell 5.1.
        $found = @(Get-ChildItem -Path $root -Filter "*.json" -File -Recurse -Depth 1 -ErrorAction SilentlyContinue)
        foreach ($file in $found) {
            if (Test-StudioConfigFile -Path $file.FullName) { $candidates += $file.FullName }
        }
    }
    $candidates = @($candidates | Select-Object -Unique)

    if ($candidates.Count -eq 1) { return $candidates[0] }
    if ($candidates.Count -gt 1) {
        Write-Log "Several exported configs were found - pass -ConfigPath to pick one:" -Tag "Error"
        foreach ($candidate in $candidates) { Write-Log "    $candidate" -Tag "Error" }
        throw "More than one config.json candidate."
    }

    throw "No config.json found next to the script or in the current directory."
}

function Test-ConfigProperty {
    param(
        [object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) { return $false }
    return ($InputObject.PSObject.Properties.Name -contains $Name)
}

function Get-ConfigValue {
    param(
        [object]$InputObject,
        [Parameter(Mandatory)][string]$Name,
        [object]$Default = $null
    )

    if (-not (Test-ConfigProperty -InputObject $InputObject -Name $Name)) { return $Default }

    $value = $InputObject.$Name
    if ($null -eq $value) { return $Default }
    return $value
}

# ConvertFrom-Json on Windows PowerShell 5.1 unwraps single-element arrays into
# a bare object, so every list has to be normalised before it is enumerated.
function Get-ConfigArray {
    param(
        [object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if (-not (Test-ConfigProperty -InputObject $InputObject -Name $Name)) { return @() }

    $value = $InputObject.$Name
    if ($null -eq $value) { return @() }

    if (($value -is [System.Collections.IEnumerable]) -and -not ($value -is [string])) {
        return @(foreach ($item in $value) { $item })
    }
    return @($value)
}

# Get-ConfigValue falls back only when the property is absent, and the studio exports
# an untouched field as an empty string - which means the same thing to everyone who
# reads it. Without this, a blank pfxPassword reaches ConvertTo-SecureString as "" and
# the run dies on "Cannot bind argument to parameter 'String' because it is an empty
# string", naming neither the setting nor the file it came from.
# $InputObject is deliberately NOT Mandatory, and that is a fix rather than an oversight.
# A mandatory [object] parameter rejects $null at binding time, which threw before the
# body - so every `Get-ConfigText -InputObject (Get-ConfigValue ... -Name "acme")` blew
# up on a certificate that has no acme block, which is every certificate from an internal
# CA. That is the nightly renewal task in four roles (Windows Admin Center, Remote
# Desktop, Exchange, NDES) failing with "Cannot bind argument to parameter 'InputObject'"
# before it could send the report saying so. Get-ConfigValue and Get-ConfigArray have
# always taken $null and returned the default; this now agrees with them, which is what
# every caller already assumed by passing -Default.
function Get-ConfigText {
    param(
        [object]$InputObject,
        [Parameter(Mandatory)][string]$Name,
        [string]$Default = ""
    )

    $value = [string](Get-ConfigValue -InputObject $InputObject -Name $Name -Default $Default)
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value
}
