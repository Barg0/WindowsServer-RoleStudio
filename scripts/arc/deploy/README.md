<div align="center">

<h1>Connect-ArcServer.ps1</h1>

<p><b>Onboard every server a GPO reaches into Azure Arc, and keep checking that each one stays there.</b></p>

<p>
<img src="https://img.shields.io/badge/PowerShell-5.1%20%7C%207-7aa2f7?style=flat-square" alt="PowerShell 5.1 or 7">
<img src="https://img.shields.io/badge/runs%20as-SYSTEM%2C%20hourly-9ece6a?style=flat-square" alt="Runs as SYSTEM, hourly">
<img src="https://img.shields.io/badge/bench-not%20yet%20proven-e0af68?style=flat-square" alt="Not yet bench-proven">
</p>

</div>
<div align="justify">

One file. You fill in its defaults once, drop it into a GPO, and a scheduled task runs it every
hour as SYSTEM on every server the GPO applies to. It has nothing to do with the studio or
`config.json` - it does not need the rest of this repository and does not read from it.

</div>

## <picture><source media="(prefers-color-scheme: dark)" srcset="../../../.github/assets/icons/overview-dark.png"><img src="../../../.github/assets/icons/overview-light.png" width="22" alt=""></picture> What a run does
<div align="justify">

Every run looks at what is already there and does the next possible thing. On a healthy server
that is one log line and nothing else.

</div>

| The server is | The run | Exit |
|---|---|---|
| Without the agent | Downloads it from `aka.ms`, checks its Microsoft signature, installs it, connects | 0 / 1 |
| Not connected | `azcmagent connect`, up to three attempts | 0 / 1 |
| Connected, healthy | Nothing | 0 |
| Connected, a service stopped | Starts it once - never one set to Disabled, never `arcproxy` | 0 |
| **Disconnected** (no heartbeat, under 45 days) | Reports what it cannot reach - the agent comes back on its own once it can | 1 |
| **Expired** (over 45 days) | Reports only - the way back deletes the Azure resource | 2 |
| Connected to another resource group | Reports only - moving it deletes the Azure resource | 2 |
| An Azure VM | Nothing - Arc does not onboard those | 3 |

<div align="justify">

"Healthy" is five checks, each depending on the one before: agent installed, connected to this
resource group, agent status Connected, services running, and a managed identity token issued by
Azure through the agent's local endpoint. The last one is the proof the machine actually works in
Azure, not just that a service is up.

</div>

## <picture><source media="(prefers-color-scheme: dark)" srcset="../../../.github/assets/icons/certificate-dark.png"><img src="../../../.github/assets/icons/certificate-light.png" width="22" alt=""></picture> 1. Azure, once
<div align="justify">

A resource group for the servers, a service principal that may onboard into it and nothing else,
and the resource providers Arc needs. In Cloud Shell or anywhere the Azure CLI is signed in:

</div>

```bash
az group create --name rg-arc-servers --location westeurope

# A service principal for onboarding only. Note appId, password and tenant -
# the password is shown this once. One year, then rotate it.
az ad sp create-for-rbac --name "arc-gpo-onboarding" --years 1

az role assignment create \
  --assignee <appId> \
  --role "Azure Connected Machine Onboarding" \
  --scope "/subscriptions/<subscriptionId>/resourceGroups/rg-arc-servers"

# Once per subscription - skipping this is the #1 cause of "azcmagent connect failed (exit 42)"
az provider register --namespace Microsoft.HybridCompute
az provider register --namespace Microsoft.GuestConfiguration
az provider register --namespace Microsoft.HybridConnectivity
```

<details>
<summary><b>The same in Azure PowerShell</b></summary>

```powershell
New-AzResourceGroup -Name rg-arc-servers -Location westeurope

$sp = New-AzADServicePrincipal -DisplayName "arc-gpo-onboarding" -EndDate (Get-Date).AddYears(1)
$sp.AppId                          # ServicePrincipalAppId
$sp.PasswordCredentials.SecretText # ServicePrincipalSecret - shown this once
(Get-AzContext).Tenant.Id          # TenantId

New-AzRoleAssignment -ApplicationId $sp.AppId `
  -RoleDefinitionName "Azure Connected Machine Onboarding" `
  -Scope "/subscriptions/<subscriptionId>/resourceGroups/rg-arc-servers"

"Microsoft.HybridCompute", "Microsoft.GuestConfiguration", "Microsoft.HybridConnectivity" |
  ForEach-Object { Register-AzResourceProvider -ProviderNamespace $_ }
```

</details>

> <picture><source media="(prefers-color-scheme: dark)" srcset="../../../.github/assets/icons/security-dark.png"><img src="../../../.github/assets/icons/security-light.png" width="16" alt=""></picture> Keep the role exactly this narrow. The secret will sit in a file in SYSVOL;
> with *Azure Connected Machine Onboarding* on one resource group, the worst anyone can do with it
> is register machines into that group. Anything wider - Contributor, *Resource Administrator* -
> and the same secret can delete every Arc server you have.

## <picture><source media="(prefers-color-scheme: dark)" srcset="../../../.github/assets/icons/settings-dark.png"><img src="../../../.github/assets/icons/settings-light.png" width="22" alt=""></picture> 2. Fill in the script
<div align="justify">

The `param` block at the top **is** the configuration. Fill in the defaults:

</div>

```powershell
param(
    # Required - an empty one stops the run with "configuration incomplete"
    [string]$SubscriptionId         = "<subscriptionId>",
    [string]$TenantId               = "<tenant>",
    [string]$ResourceGroup          = "rg-arc-servers",
    [string]$Location               = "westeurope",
    [string]$ServicePrincipalAppId  = "<appId>",
    [string]$ServicePrincipalSecret = "<password>",

    # Optional
    [string]$ProxyUrl      = "",                           # empty = direct
    [string[]]$ProxyBypass = @(),
    [string[]]$Tags        = @("Environment=Production"),  # empty = no tags

    # Optional - an empty smart host means no mail at all
    [string]$MailSmartHost       = "smtp.ad.lab.invalid",
    [int]$MailPort               = 25,
    [bool]$MailUseSsl            = $false,                         # STARTTLS, usually with port 587
    [string]$MailFrom            = "arc-onboarding@ad.lab.invalid",   # needed once a smart host is set
    [string]$MailFromDisplayName = "Azure Arc Onboarding",
    [string[]]$MailTo            = @("it-ops@ad.lab.invalid"),        # needed once a smart host is set
    [string]$MailOrganization    = "AD Lab",                          # top right of every mail
    ...
)
```

<div align="justify">

Everything goes into the defaults, not onto the task's command line: `powershell.exe -File`
cannot pass a list, and a secret on a command line ends up in event 4688, Sysmon and every EDR
log. One copy of the script per resource group, if you have more than one.

Tags are set when a machine connects and belong to its Azure resource afterwards - changing them
here does not change a server that is already connected.

</div>

## <picture><source media="(prefers-color-scheme: dark)" srcset="../../../.github/assets/icons/run-plan-dark.png"><img src="../../../.github/assets/icons/run-plan-light.png" width="22" alt=""></picture> 3. Try it before the GPO

```powershell
# The five mails with sample data. Changes nothing on the server.
# Without a smart host they land as HTML files in the log folder instead.
.\Connect-ArcServer.ps1 -TestMail

# One real run on a test server, from an elevated console
.\Connect-ArcServer.ps1
.\Connect-ArcServer.ps1 -LogDebug     # the same, with every azcmagent line in the log
```

## <picture><source media="(prefers-color-scheme: dark)" srcset="../../../.github/assets/icons/servers-dark.png"><img src="../../../.github/assets/icons/servers-light.png" width="22" alt=""></picture> 4. Group Policy
<div align="justify">

**A group.** Create a security group, e.g. `Azure Arc Servers`, and put the **computer accounts**
in it.

**A GPO, closed to that group.** Create the GPO and link it where the servers live. On its
**Delegation** tab - *Security Filtering* on the Scope tab - remove *Authenticated Users* and add
the group from above with *Read* and *Apply group policy*. GPMC copies that onto the GPO's folder in
SYSVOL, and that is the only thing keeping the secret away from users. If GPMC says the SYSVOL
permissions are inconsistent, the protection is not in place. The script checks its own file on
every run and warns in the log when Everyone, Authenticated Users, Users or Domain Users can read it.

**The script, inside the GPO.** Copy it into

```text
\\ad.lab.invalid\SYSVOL\ad.lab.invalid\Policies\{<GPO GUID>}\Machine\Scripts\
```

**The task.** *Computer Configuration > Preferences > Control Panel Settings > Scheduled Tasks >
New > Scheduled Task (At least Windows 7)*:

</div>

| Tab | Setting |
|---|---|
| General | Action **Replace**. User `NT AUTHORITY\System`. Run whether user is logged on or not. Run with highest privileges |
| Triggers | **At startup**, delay task for 5 minutes |
| | **Daily**, repeat task every **1 hour** for a duration of **Indefinitely** |
| Actions | Start a program - `powershell.exe` |
| | Arguments: `-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "\\ad.lab.invalid\SYSVOL\ad.lab.invalid\Policies\{<GPO GUID>}\Machine\Scripts\Connect-ArcServer.ps1"` |
| Settings | Stop the task if it runs longer than **30 minutes** |
| | If the task is already running: **Do not start a new instance** |

> <picture><source media="(prefers-color-scheme: dark)" srcset="../../../.github/assets/icons/help-dark.png"><img src="../../../.github/assets/icons/help-light.png" width="16" alt=""></picture> `-ExecutionPolicy Bypass` is not optional here. A script on a UNC path with dots
> in the name is in the Internet zone, and `RemoteSigned` refuses it.

## <picture><source media="(prefers-color-scheme: dark)" srcset="../../../.github/assets/icons/install-media-dark.png"><img src="../../../.github/assets/icons/install-media-light.png" width="22" alt=""></picture> Mails
<div align="justify">

One mail per **change**, never one per run - a server that stays healthy is quiet. The subject
starts with the status word, so it survives a narrow inbox column and one Outlook rule per word
sorts them:

</div>

| Mail | When | Example subject |
|---|---|---|
| Onboarded | The first healthy run | `[Azure Arc] Onboarded: SRV-FS01 - rg-arc-servers` |
| Repaired | A stopped agent service had to be started | `[Azure Arc] Repaired: SRV-SQL02 - service started: himds` |
| Failed | The first failed run after anything else | `[Azure Arc] Failed: SRV-APP07 - 2 Arc endpoint(s) unreachable` |
| Recovered | Healthy again after Failed or Action needed | `[Azure Arc] Recovered: SRV-APP07 - connected again after 26 h` |
| Action needed | Expired, another resource group, `himds` disabled | `[Azure Arc] Action needed: SRV-DC01 - connected to rg-legacy-servers` |

<div align="justify">

A mail that cannot be sent is a warning in the log and changes nothing else. The mail uses
`System.Net.Mail.SmtpClient` rather than `Send-MailMessage`, because only that can carry the
icons as inline images every mail client shows. Anonymous relay to an internal smart host is
the expected case; there is no SMTP login. `$MailUseSsl = $true` means STARTTLS (usually port
587) - implicit TLS on port 465 is something `SmtpClient` cannot do.

</div>

## <picture><source media="(prefers-color-scheme: dark)" srcset="../../../.github/assets/icons/files-dark.png"><img src="../../../.github/assets/icons/files-light.png" width="22" alt=""></picture> On each server
<pre>
<picture><source media="(prefers-color-scheme: dark)" srcset="../../../.github/assets/icons/files-dark.png"><img src="../../../.github/assets/icons/files-light.png" width="16" alt=""></picture> %ProgramData%\AzureArcOnboarding         SYSTEM and Administrators only
├─ <picture><source media="(prefers-color-scheme: dark)" srcset="../../../.github/assets/icons/files-dark.png"><img src="../../../.github/assets/icons/files-light.png" width="16" alt=""></picture> logs\                               20261102.log, 20261102-msiexec.log - the last 14 of each
├─ <picture><source media="(prefers-color-scheme: dark)" srcset="../../../.github/assets/icons/install-media-dark.png"><img src="../../../.github/assets/icons/install-media-light.png" width="16" alt=""></picture> download\                           the agent installer, only while it installs
├─ <picture><source media="(prefers-color-scheme: dark)" srcset="../../../.github/assets/icons/security-dark.png"><img src="../../../.github/assets/icons/security-light.png" width="16" alt=""></picture> temp\                               the secret for azcmagent, only while it connects
└─ <picture><source media="(prefers-color-scheme: dark)" srcset="../../../.github/assets/icons/settings-dark.png"><img src="../../../.github/assets/icons/settings-light.png" width="16" alt=""></picture> state.json                          the last state - what decides whether a mail goes out
</pre>
<div align="justify">

Every run makes sure that folder is closed to everyone but SYSTEM and Administrators, and stops
before downloading or connecting if it cannot. Ordinary users can create files anywhere under
ProgramData; without this one of them could swap the installer SYSTEM is about to run.

</div>

## <picture><source media="(prefers-color-scheme: dark)" srcset="../../../.github/assets/icons/help-dark.png"><img src="../../../.github/assets/icons/help-light.png" width="22" alt=""></picture> When something is off
<div align="justify">

The task's *Last Run Result* is the exit code: **0** healthy or nothing to do, **1** failed, **2**
needs a person, **3** skipped (Azure VM). The day's log has the detail; run once by hand with
`-LogDebug` for every line `azcmagent` printed.

</div>

| You see | It means |
|---|---|
| `configuration incomplete` | A required default is empty - the log lists every one |
| Exit 42 after three attempts | Resource providers not registered, or the role assignment is still propagating. Check the providers above; otherwise it usually works on the next run |
| Exit 41 on the first attempt | Wrong app ID, wrong secret, expired secret, or a tenant mismatch |
| `N Arc endpoint(s) unreachable` | Firewall or proxy. The mail lists which ones |
| `Agent status Disconnected` | The server cannot reach Azure. Nothing to do on the server - fix the network and it comes back by itself |
| Action needed: expired | Off for more than 45 days. The only way back is `azcmagent disconnect` - which deletes the Azure resource, extensions and all - and the next run connects it again |
| Action needed: another resource group | Connected somewhere else before. Disconnect it there if it should move, or take it out of the GPO |
| A warning that the script is readable by users | The GPO's security filtering still contains Authenticated Users |

> <picture><source media="(prefers-color-scheme: dark)" srcset="../../../.github/assets/icons/security-dark.png"><img src="../../../.github/assets/icons/security-light.png" width="16" alt=""></picture> Built and checked on Linux - parse, analyzer, the mails, the mail state machine.
> Nothing on the Windows or Azure side has run yet. Try it on one server before the GPO
> reaches the rest.
