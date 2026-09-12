# Role provider: Let's Encrypt for something that already exists.
#
# Dot-sourced by Configure-ServerRoles.ps1 - not runnable on its own. Everything
# here lands in that script's scope, so $script: variables and functions are shared
# with every other part. Use $scriptRootPath, never $PSScriptRoot: inside this file
# $PSScriptRoot is the pwsh folder, not the folder the run was started from.
#
# ===========================[ Let's Encrypt, standalone ]===========================
# The role that configures nothing and installs nothing. It exists for the case the
# rest of this toolbox cannot express: a gateway, a Remote Desktop deployment, an
# Exchange server or an NDES box that **somebody else already built**, which now wants
# a real certificate and something to renew it.
#
# It is deliberately thin, and the reason is worth stating: every piece of work it
# needs is already written. `Resolve-StudioCertificate` gets a certificate from ACME,
# each role's own `Invoke-*CertificateTask` binds one and reports on it, and
# `Register-StudioCertificateTask` schedules the lot. So this provider:
#
#   1. checks the named service is actually on this machine
#   2. calls Invoke-CertificateTask once, now, to get and bind the certificate
#   3. registers the nightly task so it keeps happening
#
# There is no fourth step and there should never be one. Anything else this role
# learned to do would be a second implementation of a provider that already exists.
#
# The trick that makes it work: the studio emits **only the certificate half** of the
# target's section - `windowsAdminCenter.certificate` and its port, say - and does not
# select that role. The section is enough for the renewal to dispatch; the role being
# absent is what keeps the gateway installer, the deployment builder and the Exchange
# setup from running. One flag in the catalogue (`standalone`) stops the two being
# selected together, because a design that both builds Exchange and "adds Let's
# Encrypt to an existing Exchange" is two answers to one question.

# The targets, and what proves each one is here. Order matters only for the message.
$script:acmeTargets = @(
    [pscustomobject]@{
        Id      = "windowsAdminCenter"
        Display = "Windows Admin Center"
        Section = "windowsAdminCenter"
        Test    = { Test-WacInstalled }
        Missing = "The Windows Admin Center gateway is not installed on this server."
    }
    [pscustomobject]@{
        Id      = "remoteDesktop"
        Display = "Remote Desktop Services"
        Section = "remoteDesktop"
        Test    = { (Get-Command -Name "Get-RDServer" -ErrorAction SilentlyContinue) -ne $null }
        Missing = "The RemoteDesktop module is not on this server, so there is no deployment to bind a certificate to."
    }
    [pscustomobject]@{
        Id      = "exchange"
        Display = "Exchange Server"
        Section = "exchange"
        Test    = { Test-ExchangeInstalled }
        Missing = "Exchange is not installed on this server."
    }
    [pscustomobject]@{
        Id      = "certificateConnector"
        Display = "Intune Certificate Connector"
        Section = "certificateServices"
        Test    = { Test-Path -LiteralPath $script:adcsScepMscepBinary }
        Missing = "The NDES role service is not installed on this server, so there is nothing serving HTTPS to rebind."
    }
)

function Get-AcmeTarget {
    param([object]$Acme)

    $id = [string](Get-ConfigText -InputObject $Acme -Name "target" -Default "")
    foreach ($target in $script:acmeTargets) {
        if ($target.Id -eq $id) { return $target }
    }
    return $null
}

function Test-AcmePrerequisite {
    param([object]$Config)

    $acme = Get-ConfigValue -InputObject $Config -Name "acmeRenewal"
    if ($null -eq $acme) {
        Write-Log "config.json has no acmeRenewal section" -Tag "Error"
        return $false
    }

    $target = Get-AcmeTarget -Acme $acme
    if ($null -eq $target) {
        Write-Log "acmeRenewal.target names no service this role knows: $(($script:acmeTargets | ForEach-Object { $_.Id }) -join ', ')" -Tag "Error"
        return $false
    }

    Write-Log "This run adds a certificate and a renewal to an existing $($target.Display)" -Tag "Info"

    # The section the renewal reads has to be in the file, or Invoke-CertificateTask
    # has nothing to dispatch on and the run would report success having done nothing.
    if ($null -eq (Get-ConfigValue -InputObject $Config -Name $target.Section)) {
        Write-Log "The design names $($target.Display) but carries no '$($target.Section)' section - re-export it from the studio" -Tag "Error"
        return $false
    }

    # And the service itself has to be here. This is the whole prerequisite: everything
    # else this role does is already proven by the code it calls.
    if (-not (& $target.Test)) {
        Write-Log $target.Missing -Tag "Error"
        Write-Log "This role adds a certificate to something that already exists - it does not configure the service" -Tag "Debug"
        return $false
    }

    $certificateTask = Get-CertificateTaskSection -Config $Config
    if ($null -eq $certificateTask) {
        Write-Log "The design carries no certificateTask section, so nothing would renew the certificate this run obtains" -Tag "Warn"
    }
    return $true
}

function Invoke-AcmeConfiguration {
    param([object]$Config)

    $acme = Get-ConfigValue -InputObject $Config -Name "acmeRenewal"
    $target = Get-AcmeTarget -Acme $acme
    if ($null -eq $target) {
        return (New-RoleResult -Status "Failed" -Message "acmeRenewal.target names no service this role knows.")
    }
    $script:currentConfig = $Config

    # One call, and it is the same code the nightly task runs - which is the point:
    # whatever happens tonight has already happened once, in front of somebody, with
    # the log on screen. A failure here is the real failure rather than a surprise at
    # 03:00 in a mail nobody reads.
    Write-Log "Obtaining the certificate now, through the same path the nightly task uses" -Tag "Run"
    $outcome = [int](Invoke-CertificateTask -Config $Config)

    $taskRegistered = Register-StudioCertificateTask -Config $Config -ConfigFilePath $script:configFilePath

    if ($outcome -ne 0) {
        return (New-RoleResult -Status "ManualStepRequired" -Message ("The certificate for {0} could not be obtained or bound - the log above says why. The nightly task {1}." -f $target.Display, $(if ($taskRegistered) { "is registered and will try again" } else { "could not be registered either" })))
    }
    if (-not $taskRegistered) {
        return (New-RoleResult -Status "ManualStepRequired" -Message ("{0} has its certificate, but the nightly renewal task could not be registered - it expires in 90 days with nothing watching." -f $target.Display))
    }

    Write-Log "$($target.Display) serves a Let's Encrypt certificate, kept by the nightly task" -Tag "Ok"
    return (New-RoleResult -Status "Completed" -Message ("{0} has a certificate and a renewal task." -f $target.Display))
}
