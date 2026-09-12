# Mail reporting for the nightly certificate task.
#
# Dot-sourced by Configure-ServerRoles.ps1 - not runnable on its own. Everything
# here lands in that script's scope, so $script: variables and functions are shared
# with every other part. Use $scriptRootPath, never $PSScriptRoot: inside this file
# $PSScriptRoot is the pwsh folder, not the folder the run was started from.
#
# Only the daily certificate task reports. A configuration run has a console and a
# person in front of it; the task runs at 03:00 as SYSTEM, and a renewal that failed
# there is otherwise a line in a log file nobody opens until the certificate expires.
#
# The transport is System.Net.Mail.SmtpClient rather than Send-MailMessage: the cmdlet
# is marked obsolete in PowerShell 7 and writes a warning on every call, which a task
# would repeat every morning. Anonymous relay is the assumed case - port and TLS are
# the design's to choose, credentials are deliberately not part of the contract.

# ---------------------------[ Template pieces ]---------------------------
# The mail is the studio's own design language rendered in what mail clients accept:
# tables and inline styles. Outlook draws HTML with the Word engine - no flexbox, no
# <style> block, no border-radius, and **no SVG at all** - so the studio's components
# cannot be reused and its icons cannot travel. What does travel is the rest of the
# system: the azure_default palette token for token, the topbar, the cards, the section
# heads, the pills, and the label/value/why fact rows. Only the drawing changes.
$script:mailFontFamily = "font-family:'Segoe UI','Segoe UI Web (West European)',-apple-system,BlinkMacSystemFont,Roboto,'Helvetica Neue',Arial,sans-serif"
$script:mailMonoFamily = "font-family:Consolas,'Courier New','Liberation Mono',monospace"

# THEMES['kaido_dark'] in the studio, token for token - its default theme and the one
# every screenshot of it shows. It used to be azure_default, a theme the studio has not
# had since it went to three families, so a report and the page that designed it no
# longer looked like the same product. Keep these in step with that theme rather than
# inventing a second palette that drifts, and remember that the icons below carry the
# same hues baked in: changing one without the other is half a restyle.
#
# The three tokens with no counterpart in the studio are derived here rather than
# invented: the *Soft* backgrounds are the status hue over the card at low weight (a
# mail client has no rgba on a table cell, so they are flattened), and *Text* is the hue
# itself, which is already legible on this card - the studio's own pills do the same.
#
# TopbarText does double duty as the ink on a status chip (the watched-certificate
# grades), which is right in this family and worth knowing before another one is tried:
# every Kaido status hue is a light one, so dark ink reads on all four. A family whose
# danger colour is dark would need that second use split out.
$script:mailPalette = @{
    Background   = "#16171e"
    Card         = "#1d1f28"
    Subtle       = "#1a1c24"
    Border       = "#2b2f3d"
    BorderStrong = "#3d4356"
    Divider      = "#23262f"
    Text         = "#d7dbec"
    Muted        = "#8b93ad"
    Accent       = "#7aa2f7"
    AccentSoft   = "#22304f"
    AccentText   = "#93b3fa"
    Danger       = "#f7768e"
    DangerSoft   = "#3a222c"
    DangerText   = "#f7768e"
    Success      = "#9ece6a"
    SuccessSoft  = "#28321f"
    SuccessText  = "#9ece6a"
    Warn         = "#e0af68"
    WarnSoft     = "#352d1e"
    Topbar       = "#7aa2f7"
    TopbarText   = "#11141c"
    TopbarMuted  = "#22304f"
}

# The studio's own icons, rasterised to 64px PNG and carried here as base64.
# They are attached to the mail as linked resources and referenced as cid:, which is
# the one image mechanism every client renders - Outlook has no SVG at all, and both
# Outlook and Gmail block data: URIs in <img>. Base64 in the script rather than files
# beside it keeps the part self-contained and the repository free of binaries.
$script:mailIcons = @{
    wac = @(
        "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAABmJLR0QA/wD/AP+gvaeTAAADw0lEQVR4nO2a7UsUQRzHvzOz5+pp",
        "2hmapSaSvdEIClTEFwX1onpZ1IsCKXuCXtQ/EBHR+6gXPZhoCPWi8rUQ9TauKKwgCSJMu1Asq7vuuqfdnV6U4XVz597e7U7lfN7d",
        "/GZ2v7/vzszO3A6gUCgUCoViuULyBTkHwfCxHsDaAkIrvRJVErgVA+fP0D8UJAQ8V7WcBvDBI22g5DaATlcEegXBExB6gBwaeCsO",
        "C+A3jq4GwzMAja6K844QYG4h/cMf/wxQYXVGzuD/SR4AmgB2RhQQGwC+x001khDmlGUAP3dOA7DGdTne0/grtwyye0D7K4ol3g7/",
        "KORXbhnkGALLB2WAbAGyyRjrlw/uqtb1dP+mppUXZQlyC0KAF9OR08kUu3nq1lhkofz3rMgBcrXMuG9y0j3+PixHpftc0sqMAxzo",
        "Ifi5PP7dA6737VhnMjIlT5t3MJO3nBh5MA0smgMC8cAsOGbkyfIIjplAPDC78DNjDrjSt30T0djZxpryvd4rc58P4cQoN8zzJ0ce",
        "vlwoy1rw8Dv7yhCtSXorzSOqwjrZfze1uGjZvwaVAbIFyEYZIFuAbLL2x3YZD0XwZi6GtGnZblOpM3S3BLCmRhfGZ8JJPJ76gljS",
        "tH1NH6PYUF+JzU3VttssxpEBU5/jCE5+KbhdJGFgbGIOfV2N0Fhm5zNMC2MTc0ga9g1dYH4yhVq/Dy21FQW3dTQEPsVSS1fKQdKw",
        "EBU84YTBHSVfrKa/Zg6o0hmaV5Z7fl/Hc8Biqss1bG6uEcaSaRPBd19tXWd3x2pMzn9H0sa8Mv4+jEjCKEiniJIYUOFjaG+oEsai",
        "KfsGUAqsr/Pbqvt6NloSA/6aISALZYBsAbJRBsgWIBtlgGwBslEGyBYgm5KsBA2L4+M38WYkbtjf2gJANGEgnl56KWxYOY/9FERJ",
        "DJiPpXDvefGfFILvvsLrr1LOhkBpzM8gnrbwvJjkHWpyZECV7rzjUApUlLHscgKQImYkp5oc3bKt3o/WVf6Cz5FolKC3tRa6ln1b",
        "XaPoba2FRgu8KAFaV/nRVm9vF5mlyUkjRgh2ttchbVmwCpjjfIyC5rF849oVaG9YUdD/jJQBvnwXXYJsAyY6LKwLcdh4vj5KS/4i",
        "pRTQi0goDxwTHRZwN6NQfFBy6OgHAGvdUCGREOkfbP6zUGw1x6jrcjyHC3MSG+DTLgAIuSnHY6aRZhdEAaEBpO/aHGBtBRB0VZY3",
        "PIKJbeTEwCdR0MZx+eNdgNn5zx2Xt3gUhD7F4YEn+Y7LKxQKhUKhWL78AD2TDOFU9V4IAAAAAElFTkSuQmCC"
    )
    certificate = @(
        "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"
    )
    rds = @(
        "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"
    )
    web = @(
        "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"
    )
    security = @(
        "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",
        "T4oUKVI8tPwLIibv3HRi4hoAAAAASUVORK5CYII="
    )
    letsencrypt = @(
        "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAABmJLR0QA/wD/AP+gvaeTAAAE8UlEQVR4nO2aW2wUVRjHf9/Mbrul",
        "a1toS0ulGIJpRW3SGCGiiQkYTXxQqAlGEi9taWt8NxqND0188Mk3E8VeUBJvQCIaDYkSL1hUNAqmKFJFrr0A29rbdtu9zPGhRHfZ",
        "6e5sd6Yd7P7e9syZ7/+d/57bnrOQI0eOHDly5MixRJG5Hqi923UmSh5D2Apq+UImZUIMpBfDeE1aus7ZGdjUALV3ex6TRQdAHrRT",
        "zAYmQRqkueOQXQE109KJ4hdd2HgAP6j31K62YrsCmhsgNNkl4ABleI2H7AqWZIBqb/cA1XYJOIKwzq5QyT3g1l81UkyOLkG3K5D5",
        "EFhCLHkDPJlU7h2Y4PiFMSJKOZXPv5QX5rO5thR/nm293RTLBgwHw/ScHnEylwQujob49vTfPLC+zFEdy0NgKhxzMo9F07RsQFWJ",
        "j3J/npO5JKAh1N14g+M6loeALkJDfSX9o9NEos7PAWV+L8UFXsd1MpoEdRHWLC9wKpdFYckvg0vegIyGQCSmODs8RcSY/xygIawu",
        "ycfvy0jaMSxnEY0Z7D82yGgomrWoVxceqV/FimXOT3LpsDwEBsZnbGk8zPakvstBW2Jli2UDivI9tv5ELMp3dotrFctDoGSZl801",
        "ZfzSP04kZsxbUERYu6KA9ZXOb3KskNFMVFtRSG1FoVO5LApLfhlMGtazJ8LFM4uRjHXUCIgPiAEXgX5EDmHEDsjO7lOZRLpODUiB",
        "4gi6el4au45Yqf7/GwLCPRjSo7pb3lV7nkg7YSUZII/uCwMTjiS3sOwgmt+j9rStSVVprh5w0IGEbCMwGeazkwG+6AswMZ1yc1ZP",
        "zPhK7Wqb81hpDgOMF4DhrLJ0iKih+OTEJU4Hgpy6FOTgb1dSv6BYi8d4/+p9RxKmBkhz91+IvgmRTwF79r82MToVIRT5byM2HAwT",
        "TndAI9zHTf3PmD9Kg9rd6COmV6ApZ/euUVWNrn+OkPIX0pWJMPuPDyaUNd9VTb437XweIC+0Th5/Zzy+MO1OUJremgZsvZI2Q3W3",
        "PAupG58lZcwUtAKvxhe6YhlU7e0awrYFkGq4tsAVBrBmYAOKVY7rCJtUd1N5fJE7DJDYbQukpGFo6xML3ICSrL79PwJBsHpKp2tV",
        "8R9dYoBaYbWqZrJuffPnCB/2DjESjKQPYKjShHhWhR1FxPKlY0mh1/RAdWhshn3HBjl6bpRoqgMbIRD/0R0GwIDViroIW29fSVWx",
        "L+mZoRQ/nx9j77EhxkNz9AZJ1HKHAcLJTKoXFXjZWlfB5ppSfCYboLFQhB/Pj5m9aqB7Es4L3GHAudU/IAymrxiHwC0VfnbcWUXt",
        "Sn/SnjZqdrGs+E6efONyfJErDJD2dgMlH8/nXZ9HZ0ttKQ/XVVJy9Z7B59W4o7rIREgdSCqaj6gTqI6Wtej8Dsz7Dl4pGJkKU1zg",
        "xZO8XASIaDfL028mjA1X9AAAae08g9CRVQyB0sI8s8YDvHxt48FFBswSfQnI6FDTGvIlEe110yf2i2WHeru1hpj6HrDpD9rqLBgb",
        "pXm36cmJy3oAyFMdfWjcz+xxd7b0EpMtczUeXGgAgDR2/kRE2wh8nUWYDwjl3S2tnWdSamUhsCCortYGRL0C1Fp84ygGz0lL12Er",
        "tV1vAIBSCF07N6Bp21DqXoRqoJLZm6EB4AJwCEN9JC1dJxY12Rw5cuS4nvgHCjtrLe1XTXsAAAAASUVORK5CYII="
    )
    intune = @(
        "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAABmJLR0QA/wD/AP+gvaeTAAAERElEQVR4nO2ZX2hbVRzHv7+bNPcm",
        "M+2qKawLjJpVNxVxRV9klGlNHfhUmOuTblrSdkw37HCKb/dloDIUXFdsUzpEYRCRCb6MUhU2HyfIJljGHK1aN9bI2mVdbtPm/nxI",
        "lTS5Nz335qYTez5v95zf+f2758/v3AtIJBKJRCKRSCQSiUQi2WhQpc7xkeweYuoCuJkUUtwaYfASgN8Iytl4r3rZrZ7zo0ar3+RX",
        "wYhBIbWiTZNNEP1pmvz13kPBC3ZylgnQdVZ2bzWSAHrcOmuDSczvxftDHzodOD6SfY2AEQB1TscSYfSFhNZHRFzaZ/lWd0ezR+F9",
        "8ACgMNH748PGi04Gnf809xQBSbgIHgCYkZhILr5p6ZD1CDrsxpAgRGQ60u9TlvsA+KuyyvyGVXNZAlIp9gHYXpWxNZ2hnY7kiXZU",
        "bZPwyEpsq7CaAT6bdi9xNpW5yrdfQEEhtrLGDc2GT4Dw1Lp7bw6T05dg5BZsZXyKHw9vfQJbHmpx5IS+PxW4q03Xnfz8uL3yGiGc",
        "gB8nv8NCdm5NubnMLexp24dQsF5I77GDp/bNY/YMENp07MDg6fpY+i1d101Rv6pFaAkwM+4Z80IKmRkLgrIAYEL5BEAYhRrhyJ3r",
        "TUld19dtaQoZIiJEm8ROxqAWRmP9FmEHqGRnZkLPeiZBeAk82dqOpsZtyBoZWxk1oKHpwW3w+xycckzvgvgMisrylSRA1/XeWi8H",
        "4QQQEZojLcKKF5eyyOeXLftMM1830DMUW3m8iGU6CeLjxTL/JGGgZ+iEsZgJaGpY2LYTyi5DqRQHGueMRbcKmRk/Xf0eN9JTVTlW",
        "SnOkBbsefR5EFS+wFbm9WVO7uylX3Ob5OkvPz3gePADcSE8hPT/jud4NXwh5noBIQ9TRXiFKc6QFkYao53q9uGSsgojQtqMDj8cq",
        "boK/X7h87rl/G5ZxqHQTBABijLGfTnS0vfyFpoaf9dpXwEECmBk3/5oWOgYDfhVqXdD+zsdY+njs8HUAGDgwdBDEb5eKEGOsPjbb",
        "q+u6+dLI67lyJd4gnIAr1y7ij1vX1pQLamG07+oSrwWIP0DJaVQcvKh/bhEuhWdmfxVSmDUyuH3nprADDOSLn9czeMBBKRzSGoQU",
        "EhE2CcoWHDCPAsig8MH01HoGDzhYAk/v7BC+DoveBAHgo8+OfKXvT33zn78OPxDajGcei9fECf3L7hyAmm10lZCF0P124H5jlYA8",
        "gFpvQkuOpAnWFZUzTJScOIBFArq7KQ9g7QO/Goh+cSRu8qQHVq+uxLYKmyVAgx4YtIMJOO1oAHzDcDpryoxax2SZgHivOkiE0WoM",
        "2mAC/E68T5twMqizX70CQgIuTwoGhjsT6pBVX8WvCxPJbLvJ1EXM0Wp/j5OJqbxPObs3of7sVs+3w8Z2U+FXyESryO9xJpoh5nOd",
        "/cEf3NqUSCQSiUQikUgkEolE8v/jbyinbaI/ejkHAAAAAElFTkSuQmCC"
    )
    exchange = @(
        "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"
    )
    mark = @(
        "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAABmJLR0QA/wD/AP+gvaeTAAAEN0lEQVR4nO2bTWgjZRjH/887kzbb",
        "mnSTznSXNGVTYW/CHqoHL37hCh5EED34gaL0IorgXvayoOBFxINe9KIuHjwIiizeXBVERAS9KaK0Ndo2bTZNmqRfSTszjwe70E2m",
        "SWbmnY/Y+UEuM+88zz//ZN73ed5JgJiYmJgTDIUtwAm5XG5s90C5U8A6028sM7cE80K1uvZ7r3FDY0BWm7nE4NcBpBxe+pNg8/nj",
        "jBgKA07rM1eI+Q0PISpkWXO1Wmm584TiIWggaNpMjsGfA1A9hBknILO3t3Wt84TwEDQQDLYuAhj1GocFPWJ3PPIGENGUlECMSWAu",
        "0Xm419eKsvr04wy6B4wRKSJuFbR0kDA+2l5fr/QZJ+TNVK2uSLYGFAqFZGPHuMaMh2Sl7oKAEUO9lJnKPbZ5o/SDb3n6YHsLNHaM",
        "1+Dnmz+EgSlY4hNd12/zO9dx2M8BjPkANZw7sJIPBpjvFmwMmEsA0IIUQcB0kPmOYmNA90ThPxxaQRb5ZdBvImIAcViZbQz4bR9A",
        "I0gRJKzetYCPHPcN+DQwBYSq0aavA8vXga0BbKiXQfg1gPwttmi+2VypBZDLFttKsF4v1guFwl2NLeMVEO5lkPRSmIBFwca7/TYs",
        "/ObYXqBYLLYAvHX4+t8SkVUgPE68Aa53WTRNS5mcfAnEFwDhfGeJeAmG9d7mZukftxpk4MqAiTPnZk3T/AaE2f+2FV3UMQxAES9m",
        "szNP1GrLX7nRIQNXt4AwzQ8BzErIn2bBH2cyt09IiOUKxwZks9N5APdL1HCW1PZFifEc4dgAU7CcPbojsCX6PujwCxe3gOpD6xq3",
        "w6HhwgDDh9Y1Uu1wb1QWZdkiSOF12TEHxbEB1erKKgHfStSwBiN5XWI8R7iaA0xFmQewJCF/kyzxXK220JQQyxWuKsFG+e+/dF2/",
        "YFijL3sohRdhWO/XNleGrxQGgEqlsg3gTYlaQiFeBsMWEDZefnTQk7SeP68wv8oQ5+3OE3hJsPlOZLfEvJDR8w+D8RlAY9SjVbZI",
        "efb0ZP6penXlCz90DIL0W0DTtBQzXwUwNsDwJBE+SKWmJ2XrGBTpBpgYuY9ATrq7bCIpovR02BtMiuNPk61gn0YfxY9VwEVrG7fD",
        "oeGHAS5a2yFqh/sGNFFyeg0Dq7J1DIp0A2rZ0e8Y+HPgC5iLo+r+cLXDPVlYaDPoaQBr/YYScAMKP1Mul3ek6xgQXyrBxsbyz+l0",
        "/g51hF5gsG0pDMbifsK42veHkj7jWy9w+Mz/bc+BCJZ3NTdJdk22kV8GmVnWHuQG8MtB58HIG6CSeh1A22scYv7S7njk/y+wu9vY",
        "PjU+wQAe8BCmQsxP7u1tde09Rt4AAGjtNr9PjqfrBNwNIOnoYsKPCqxHq9WS7SbuUPxl5ib5fP7UTlvMEcyz6KOdmVsK6I+NjdXB",
        "a5KYmJiYk8a/qM1Hu8LwXRYAAAAASUVORK5CYII="
    )
}
# Only the icons a mail actually references are attached: an unused linked resource shows
# up as a stray attachment in some clients.
function Get-MailUsedIcon {
    param([Parameter(Mandatory)][string]$BodyHtml)

    $used = @()
    foreach ($name in $script:mailIcons.Keys) {
        if ($BodyHtml -match ("cid:icon-" + [regex]::Escape($name))) { $used += $name }
    }
    return $used
}

function New-MailIcon {
    param(
        [Parameter(Mandatory)][string]$Name,
        [int]$Size = 16,
        [string]$Alt = ""
    )

    if (-not $script:mailIcons.ContainsKey($Name)) { return "" }
    return '<img src="cid:icon-' + $Name + '" width="' + $Size + '" height="' + $Size +
        '" alt="' + (ConvertTo-MailText -Value $Alt) + '" style="display:block;border:0;outline:none;text-decoration:none;">'
}

function Get-MailDividerRow {
    param([string]$Padding = "0")

    return '<tr><td style="padding:' + $Padding + ';"><div style="height:1px;line-height:1px;font-size:0;background:' +
        $script:mailPalette.Divider + ';">&nbsp;</div></td></tr>'
}

# Everything interpolated into the templates goes through this. A DNS name or an
# exception message is not markup, and an unescaped '<' silently eats the rest of a row.
function ConvertTo-MailText {
    param([string]$Value)

    if ([string]::IsNullOrEmpty($Value)) { return "" }
    $text = $Value -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;'
    return ($text -replace "(`r`n|`r|`n)", '<br>')
}

# The studio's own mark for the top of a report - the same glyph the page wears in its
# header and its favicon, and the same shape the console header paints.
#
# It is an image, and a mail client with images blocked shows nothing where an image is,
# so there is a second drawing of the same mark in table cells underneath. That fallback
# used to be a two-by-two grid of coloured squares, which is somebody else's logo
# whatever the four colours are - and recolouring a logo to a palette makes it a modified
# logo rather than a different one. Both drawings are this project's mark now.
function New-MailLogo {
    $mark = New-MailIcon -Name "mark" -Size 20 -Alt "Windows Server Role Studio"
    if (-not [string]::IsNullOrWhiteSpace($mark)) { return $mark }

    # The mark drawn in table cells, for the client that blocked the image. It is the
    # studio's own shape - three stepped bars and one block, the same mask the console
    # header paints - in ONE colour.
    #
    # It used to be a 2x2 grid of orange, green, blue and purple squares. Four coloured
    # squares in a two-by-two grid is somebody else's logo whatever the four colours are,
    # and recolouring a logo to match a palette makes it a modified logo rather than a
    # different one - which is the one thing this project's own icon rule forbids. Nobody
    # would have called it deliberate; that is exactly why it had to go before release.
    # TopbarText, not Accent: this only ever draws on the topbar, and the topbar IS the
    # accent - an accent-coloured mark on it is an invisible one, which is exactly how
    # the first version of this shipped.
    $ink  = $script:mailPalette.TopbarText
    $bar  = "height:4px;line-height:4px;font-size:0;mso-line-height-rule:exactly;background:" + $ink + ";"
    $gap  = "height:3px;line-height:3px;font-size:0;mso-line-height-rule:exactly;"
    return '<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">' +
        '<tr>' +
          '<td style="padding:0;vertical-align:top;">' +
            '<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">' +
              '<tr><td style="' + $bar + 'width:14px;">&nbsp;</td></tr>' +
              '<tr><td style="' + $gap + '">&nbsp;</td></tr>' +
              '<tr><td style="' + $bar + 'width:11px;">&nbsp;</td></tr>' +
              '<tr><td style="' + $gap + '">&nbsp;</td></tr>' +
              '<tr><td style="' + $bar + 'width:7px;">&nbsp;</td></tr>' +
            '</table>' +
          '</td>' +
          '<td style="padding:0 0 0 3px;vertical-align:top;">' +
            '<div style="width:6px;height:18px;line-height:18px;font-size:0;mso-line-height-rule:exactly;background:' +
              $ink + ';">&nbsp;</div>' +
          '</td>' +
        '</tr></table>'
}

# The studio's section head: a small accent chip, then an uppercase letterspaced label.
# The chip stands in for the glyph the page shows in that position and a mail client
# will not render as an SVG.
# Which mark a report wears. Keyed off the role label the task set, because that is
# already the one thing every consumer of the shared machinery hands in - a fifth
# consumer needs a line here and nothing else. Falls back to the certificate mark,
# which is never wrong for a report about a certificate.
function Get-MailRoleIcon {
    param([string]$RoleLabel)

    $label = [string]$RoleLabel
    if ($label -like "*Remote Desktop*") { return "rds" }
    if ($label -like "*Exchange*") { return "exchange" }
    if ($label -like "*Connector*" -or $label -like "*Intune*") { return "intune" }
    if ($label -like "*Admin Center*") { return "wac" }
    return "certificate"
}

function New-MailSectionHead {
    param(
        [Parameter(Mandatory)][string]$Label,
        [string]$Icon = ""
    )

    $palette = $script:mailPalette

    # The studio's section head is an icon and an uppercase label. With images blocked the
    # accent chip is what remains, which is why the fallback is a coloured square rather
    # than a broken-image box.
    $mark = ""
    if (-not [string]::IsNullOrWhiteSpace($Icon)) { $mark = New-MailIcon -Name $Icon -Size 16 -Alt $Label }
    if ([string]::IsNullOrWhiteSpace($mark)) {
        $mark = '<div style="width:10px;height:10px;line-height:10px;font-size:0;background:' + $palette.Accent + ';">&nbsp;</div>'
    }

    return '<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>' +
        '<td width="16" valign="middle" style="width:16px;padding-right:10px;">' + $mark + '</td>' +
        '<td valign="middle" style="' + $script:mailFontFamily + ';font-size:11px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:' +
            $palette.Muted + ';">' + (ConvertTo-MailText -Value $Label) + '</td>' +
        '</tr></table>'
}

# .pill.status, as far as a mail client can carry it. 4px and not the 999px it used to
# be: the studio's radius tokens are 2 and 4, a pill in it is a rounded rectangle, and a
# lozenge in the mail was the last of the old round design left anywhere. Outlook draws
# neither - see below - so this is for the clients that do.
# lands as a small bordered tag rather than a lozenge. The tone names match the studio's.
function New-MailPill {
    param(
        [string]$Label = "",
        [string]$Value = "",
        [ValidateSet("on", "off", "warn", "danger")][string]$Tone = "off"
    )

    $palette = $script:mailPalette
    $colour     = $palette.Muted
    $background = $palette.Subtle
    $border     = $palette.Border

    if ($Tone -eq "on")          { $colour = $palette.AccentText; $background = $palette.AccentSoft; $border = $palette.Accent }
    elseif ($Tone -eq "warn")    { $colour = $palette.Warn;       $background = $palette.WarnSoft;   $border = $palette.Warn }
    elseif ($Tone -eq "danger")  { $colour = $palette.DangerText; $background = $palette.DangerSoft; $border = $palette.Danger }

    $text = ""
    if (-not [string]::IsNullOrWhiteSpace($Label)) {
        $text = '<span style="color:' + $palette.Muted + ';">' + (ConvertTo-MailText -Value $Label) + '</span>&nbsp;&nbsp;'
    }
    $text = $text + '<b>' + (ConvertTo-MailText -Value $Value) + '</b>'

    return '<td style="padding:0 8px 8px 0;"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>' +
        '<td style="' + $script:mailFontFamily + ';font-size:10px;letter-spacing:1px;text-transform:uppercase;padding:5px 10px;' +
        'color:' + $colour + ';background:' + $background + ';border:1px solid ' + $border + ';border-radius:4px;white-space:nowrap;">' +
        $text + '</td></tr></table></td>'
}

# factRow(): a name, a value, and the line underneath saying why it matters. Same shape as
# the studio's, because somebody reading the mail has read the page.
function New-MailFactRow {
    param(
        [Parameter(Mandatory)][string]$Label,
        [string]$Value = "",
        [string]$Why = "",
        [string]$ValueColor = "",
        [switch]$Monospace
    )

    $palette = $script:mailPalette
    $colour  = $ValueColor
    if ([string]::IsNullOrWhiteSpace($colour)) { $colour = $palette.Text }

    $face = $script:mailFontFamily
    $size = "13px"
    if ($Monospace) { $face = $script:mailMonoFamily; $size = "12px" }

    $text = $Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        $text   = "&mdash;"
        $colour = $palette.Muted
    }

    # break-all belongs to a thumbprint or a URL, never to a sentence: applied to prose it
    # breaks words mid-syllable, which is how "the first of them" became "the first of th em".
    $wrap = "word-break:break-word;"
    if ($Monospace) { $wrap = "word-break:break-all;" }

    $row = '<tr>' +
        '<td width="150" valign="top" style="width:150px;' + $script:mailFontFamily +
            ';font-size:11px;letter-spacing:.6px;text-transform:uppercase;color:' + $palette.Muted +
            ';padding:9px 20px 3px 0;white-space:nowrap;">' + (ConvertTo-MailText -Value $Label) + '</td>' +
        '<td valign="top" style="' + $face + ';font-size:' + $size + ';color:' + $colour +
            ';padding:8px 0 3px 0;line-height:1.5;' + $wrap + '">' + $text

    if (-not [string]::IsNullOrWhiteSpace($Why)) {
        $row = $row + '<div style="' + $script:mailFontFamily + ';font-size:11.5px;color:' + $palette.Muted +
            ';padding-top:3px;line-height:1.5;">' + (ConvertTo-MailText -Value $Why) + '</div>'
    }

    return ($row + '</td></tr>')
}

# warnBox() / infoBox(): a soft panel with an accent edge, which is the studio's way of
# saying "read this bit" without an icon font.
function New-MailNotice {
    # Not Mandatory. A mandatory [string] cannot bind "" - a failure with no message would
    # throw inside the code that exists to report failures, which is the worst place for it.
    param(
        [string]$Text = "",
        [ValidateSet("info", "warn", "danger", "success")][string]$Tone = "info",
        [string]$Title = ""
    )

    if ([string]::IsNullOrWhiteSpace($Text)) { $Text = "No detail was reported." }

    $palette = $script:mailPalette
    $edge = $palette.Accent
    $back = $palette.AccentSoft
    $head = $palette.AccentText

    if ($Tone -eq "warn")         { $edge = $palette.Warn;    $back = $palette.WarnSoft;    $head = $palette.Warn }
    elseif ($Tone -eq "danger")   { $edge = $palette.Danger;  $back = $palette.DangerSoft;  $head = $palette.DangerText }
    elseif ($Tone -eq "success")  { $edge = $palette.Success; $back = $palette.SuccessSoft; $head = $palette.SuccessText }

    $body = '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:' + $back +
        ';border-left:3px solid ' + $edge + ';"><tr><td style="padding:14px 18px;">'

    if (-not [string]::IsNullOrWhiteSpace($Title)) {
        $body = $body + '<div style="' + $script:mailFontFamily + ';font-size:11px;font-weight:600;letter-spacing:1px;' +
            'text-transform:uppercase;color:' + $head + ';padding-bottom:6px;">' + (ConvertTo-MailText -Value $Title) + '</div>'
    }

    return ($body + '<div style="' + $script:mailFontFamily + ';font-size:12.5px;line-height:1.6;color:' + $palette.Text + ';">' +
        $Text + '</div></td></tr></table>')
}

# ---------------------------[ The report itself ]---------------------------
# Built from what the task actually did, not from a second reading of the machine -
# a mail that re-queries the gateway can disagree with the run it is reporting on.
function New-WacCertificateReport {
    param(
        [Parameter(Mandatory)][string]$Status,
        # Which certificate this run was about. One task renews whatever the server
        # holds, so the report has to say which one it is reporting on.
        [string]$RoleLabel          = "Windows Admin Center",
        [string]$PrimaryName        = "",
        [string[]]$Names            = @(),
        [string]$Source             = "",
        [string]$PluginName         = "",
        [int]$Port                  = 443,
        [string]$Thumbprint         = "",
        [string]$NotAfter           = "",
        [string]$PreviousThumbprint = "",
        [string]$PreviousNotAfter   = "",
        [string]$ErrorMessage       = "",
        [string]$ErrorStackTrace         = "",
        [object[]]$Endpoints        = @(),
        # Certificates this run does NOT renew but whose expiry would take the role down
        # anyway - the NDES registration authority pair above all. Reported so nobody
        # learns about a two-year certificate from a helpdesk ticket.
        [object[]]$WatchedCertificates = @()
    )

    return [pscustomobject]@{
        Status             = $Status
        RoleLabel          = $RoleLabel
        PrimaryName        = $PrimaryName
        Names              = @($Names)
        Source             = $Source
        PluginName         = $PluginName
        Port               = $Port
        Thumbprint         = $Thumbprint
        NotAfter           = $NotAfter
        PreviousThumbprint = $PreviousThumbprint
        PreviousNotAfter   = $PreviousNotAfter
        ErrorMessage       = $ErrorMessage
        ErrorStackTrace    = $ErrorStackTrace
        Endpoints          = @($Endpoints)
        WatchedCertificates = @($WatchedCertificates)
    }
}

function New-WacCertificateMailHtml {
    param(
        [Parameter(Mandatory)][object]$Report,
        [string]$Organization = ""
    )

    $palette    = $script:mailPalette
    $font       = $script:mailFontFamily
    $mono       = $script:mailMonoFamily
    $failed     = ($Report.Status -eq "Failed")
    $serverName = [string]$env:COMPUTERNAME
    $runTime    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # The status pill carries the whole outcome, so it gets the studio's tones: accent for
    # a renewal, neutral for a day when nothing had to happen, danger when it did not work.
    $statusTone = "off"
    if ($Report.Status -eq "Renewed") { $statusTone = "on" }
    elseif ($failed) { $statusTone = "danger" }

    $pills = New-MailPill -Label "Status" -Value ($Report.Status.ToUpperInvariant()) -Tone $statusTone
    if (-not [string]::IsNullOrWhiteSpace($Report.Source)) {
        $pills = $pills + (New-MailPill -Label "Source" -Value $Report.Source -Tone "off")
    }
    if (-not [string]::IsNullOrWhiteSpace($Report.PluginName)) {
        $pills = $pills + (New-MailPill -Label "Plugin" -Value $Report.PluginName -Tone "off")
    }
    $pills = $pills + (New-MailPill -Label "Port" -Value ([string]$Report.Port) -Tone "off")

    $nameList = ""
    foreach ($name in @($Report.Names)) {
        $nameList = $nameList + '<div style="' + $mono + ';font-size:12px;color:' + $palette.Text + ';line-height:1.7;">' +
            (ConvertTo-MailText -Value ([string]$name)) + '</div>'
    }

    # ---- the certificate card
    $certificateRows = ""
    if (-not $failed) {
        if (($Report.Status -eq "Renewed") -and (-not [string]::IsNullOrWhiteSpace($Report.PreviousThumbprint))) {
            $certificateRows = $certificateRows + (New-MailFactRow -Label "Replaced" -Value $Report.PreviousThumbprint `
                -Why ("Valid until " + $Report.PreviousNotAfter + " - what the gateway served until this run") `
                -ValueColor $palette.Muted -Monospace)
        }

        $thumbprintColour = $palette.Text
        if ($Report.Status -eq "Renewed") { $thumbprintColour = $palette.AccentText }

        $certificateRows = $certificateRows + (New-MailFactRow -Label "Thumbprint" -Value $Report.Thumbprint `
            -ValueColor $thumbprintColour -Monospace)
        $certificateRows = $certificateRows + (New-MailFactRow -Label "Valid until" -Value $Report.NotAfter `
            -Why "The daily task renews inside this window; nothing waits for the last day." -ValueColor $thumbprintColour)
    }

    $certificateBlock = ""
    if (-not [string]::IsNullOrWhiteSpace($certificateRows)) {
        # The issuer's own mark on the section about its certificate: Let's Encrypt when
        # that is where it came from, the generic certificate mark otherwise. The report
        # is mostly about a 90-day certificate, so saying who issued it is not decoration.
        $certificateIcon = "certificate"
        if ([string]$Report.Source -eq "acme") { $certificateIcon = "letsencrypt" }
        $certificateBlock = '<tr><td style="padding:18px 26px 6px;">' + (New-MailSectionHead -Label "Certificate" -Icon $certificateIcon) + '</td></tr>' +
            '<tr><td style="padding:2px 26px 20px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">' +
            $certificateRows + '</table>'

        if ($Report.Status -eq "Current") {
            $certificateBlock = $certificateBlock + '<div style="height:12px;line-height:12px;font-size:0;">&nbsp;</div>' +
                (New-MailNotice -Tone "info" -Text "The gateway already serves this certificate, so nothing was changed. The task compares before it acts.")
        }
        $certificateBlock = $certificateBlock + '</td></tr>'
    }

    # ---- the failure card
    $errorBlock = ""
    if ($failed) {
        # A run can fail with nothing to say - a provider that returned false rather than
        # throwing. The section still belongs in the mail; it just says so plainly.
        $errorText = ConvertTo-MailText -Value $Report.ErrorMessage
        if ([string]::IsNullOrWhiteSpace($errorText)) {
            $errorText = "The run reported a failure without a message. The log has the detail."
        }

        $errorBlock = '<tr><td style="padding:18px 26px 6px;">' + (New-MailSectionHead -Label "What went wrong" -Icon "security") + '</td></tr>' +
            '<tr><td style="padding:2px 26px 14px;">' +
            (New-MailNotice -Tone "danger" -Title "Error" -Text $errorText) + '</td></tr>'

        if (-not [string]::IsNullOrWhiteSpace($Report.ErrorStackTrace)) {
            $errorBlock = $errorBlock + '<tr><td style="padding:0 26px 20px;">' +
                '<div style="' + $mono + ';font-size:11px;color:' + $palette.Muted + ';line-height:1.6;background:' + $palette.Subtle +
                ';border:1px solid ' + $palette.Border + ';padding:12px 14px;word-break:break-all;">' +
                (ConvertTo-MailText -Value $Report.ErrorStackTrace) + '</div></td></tr>'
        }
    }

    # ---- HTTPS validation, the same list the run prints
    $validationBlock = ""
    if (@($Report.Endpoints).Count -gt 0) {
        $rows = ""
        foreach ($endpoint in @($Report.Endpoints)) {
            $chip  = $palette.Danger
            $label = "FAIL"
            if ($endpoint.Ok) { $chip = $palette.Success; $label = "OK" }

            $rows = $rows + '<tr>' +
                '<td width="56" valign="top" style="width:56px;padding:6px 12px 6px 0;">' +
                    '<div style="' + $font + ';font-size:10px;font-weight:600;letter-spacing:1px;text-align:center;color:' + $palette.TopbarText +
                    ';background:' + $chip + ';padding:3px 0;">' + $label + '</div></td>' +
                '<td valign="top" style="' + $mono + ';font-size:12px;color:' + $palette.Text + ';padding:6px 12px 6px 0;word-break:break-all;">' +
                    (ConvertTo-MailText -Value ([string]$endpoint.Url)) + '</td>' +
                '<td valign="top" align="right" style="' + $font + ';font-size:11.5px;color:' + $palette.Muted +
                    ';padding:6px 0;white-space:nowrap;">' + (ConvertTo-MailText -Value ([string]$endpoint.Detail)) + '</td>' +
                '</tr>'
        }

        $validationBlock = '<tr><td style="padding:18px 26px 6px;">' + (New-MailSectionHead -Label "HTTPS validation" -Icon "web") + '</td></tr>' +
            '<tr><td style="padding:2px 26px 22px;">' +
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="table-layout:fixed;">' +
            $rows + '</table></td></tr>'
    }

    # ---- certificates this task watches but never renews
    # Same shape as the validation rows above, deliberately: they are the same kind of
    # fact - something checked rather than something done - and a second visual language
    # for them would read as a second kind of thing.
    $watchedBlock = ""
    if (@($Report.WatchedCertificates).Count -gt 0) {
        $watchedRows = ""
        foreach ($watched in @($Report.WatchedCertificates)) {
            $chip  = $palette.Success
            $label = "OK"
            switch ([string]$watched.Grade) {
                "Expired"  { $chip = $palette.Danger;  $label = "EXPIRED" }
                "Critical" { $chip = $palette.Danger;  $label = "DAYS" }
                "Warning"  { $chip = $palette.Warn;    $label = "SOON" }
                "Notice"   { $chip = $palette.Warn;    $label = "DUE" }
                "Missing"  { $chip = $palette.Danger;  $label = "GONE" }
            }
            $when = [string]$watched.NotAfter
            if ([string]::IsNullOrWhiteSpace($when)) { $when = "not found" }
            else { $when = "{0} - {1} day(s)" -f $when, [int]$watched.DaysLeft }

            $watchedRows = $watchedRows + '<tr>' +
                '<td width="72" valign="top" style="width:72px;padding:6px 12px 6px 0;">' +
                    '<div style="' + $font + ';font-size:10px;font-weight:600;letter-spacing:1px;text-align:center;color:' + $palette.TopbarText +
                    ';background:' + $chip + ';padding:3px 0;">' + $label + '</div></td>' +
                '<td valign="top" style="' + $font + ';font-size:12px;color:' + $palette.Text + ';padding:6px 12px 6px 0;">' +
                    (ConvertTo-MailText -Value ([string]$watched.Label)) +
                    '<div style="' + $font + ';font-size:11px;color:' + $palette.Muted + ';padding-top:2px;">' +
                    (ConvertTo-MailText -Value ([string]$watched.Detail)) + '</div></td>' +
                '<td valign="top" align="right" style="' + $font + ';font-size:11.5px;color:' + $palette.Muted +
                    ';padding:6px 0;white-space:nowrap;">' + (ConvertTo-MailText -Value $when) + '</td>' +
                '</tr>'
        }

        $watchedBlock = '<tr><td style="padding:18px 26px 6px;">' +
            (New-MailSectionHead -Label "Watched, not renewed" -Icon "certificate") + '</td></tr>' +
            '<tr><td style="padding:2px 26px 6px;">' +
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="table-layout:fixed;">' +
            $watchedRows + '</table></td></tr>' +
            '<tr><td style="padding:0 26px 22px;' + $font + ';font-size:11.5px;color:' + $palette.Muted + ';line-height:1.5;">' +
            'These do not renew themselves and this task deliberately does not renew them. The two registration authority ' +
            'certificates come from version 1 templates - a fixed two-year life that cannot be changed - and the enrollment agent ' +
            'one cannot be renewed from the computer store at all, because its template&#39;s subject type is User. When SCEP stops ' +
            'working for no apparent reason, this is almost always why.' +
            '</td></tr>'
    }

    # ---- the run's own facts
    $runRows = New-MailFactRow -Label "Gateway" -Value ("https://" + $Report.PrimaryName + ":" + $Report.Port) -Monospace
    $runRows = $runRows + (New-MailFactRow -Label "Names" -Value $nameList `
        -Why "The gateway presents these, and reaches its own service endpoints by the first of them.")
    $runRows = $runRows + (New-MailFactRow -Label "Run at" -Value $runTime)

    $organizationLabel = ConvertTo-MailText -Value $Organization
    $logLine = ConvertTo-MailText -Value $logFile

    return @"
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="$($palette.Background)" style="background:$($palette.Background);margin:0;padding:0;">
<tr><td align="center" style="padding:32px 16px;">
<table role="presentation" width="640" cellpadding="0" cellspacing="0" border="0" bgcolor="$($palette.Card)" style="width:640px;max-width:640px;background:$($palette.Card);border:1px solid $($palette.Border);">

  <tr><td style="background:$($palette.Topbar);padding:14px 26px;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
      <td width="24" style="width:24px;padding-right:12px;">$(New-MailLogo)</td>
      <td style="$font;font-size:13px;font-weight:600;color:$($palette.TopbarText);">Windows Server Role Studio</td>
      <td align="right" style="$font;font-size:11.5px;color:$($palette.TopbarMuted);">$organizationLabel</td>
    </tr></table>
  </td></tr>

  <tr><td style="padding:26px 26px 0;">
    <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
      <td width="28" valign="top" style="width:28px;padding:2px 14px 0 0;">$(New-MailIcon -Name (Get-MailRoleIcon -RoleLabel ([string]$Report.RoleLabel)) -Size 28 -Alt ([string]$Report.RoleLabel))</td>
      <td valign="top">
        <div style="$font;font-size:20px;font-weight:600;color:$($palette.Text);line-height:1.3;">$(ConvertTo-MailText -Value ([string]$Report.RoleLabel)) certificate</div>
        <div style="$font;font-size:12.5px;color:$($palette.Muted);padding-top:6px;">Daily renewal and rebind on <b style="color:$($palette.Text);">$serverName</b></div>
      </td>
    </tr></table>
  </td></tr>

  <tr><td style="padding:20px 26px 0;">
    <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>$pills</tr></table>
  </td></tr>

  <tr><td style="padding:10px 26px 22px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">$runRows</table></td></tr>

  $(Get-MailDividerRow -Padding "0 26px")

  $certificateBlock
  $errorBlock
  $validationBlock
  $watchedBlock

  <tr><td style="padding:20px 26px 24px;background:$($palette.Subtle);border-top:1px solid $($palette.Divider);">
    <div style="$font;font-size:11.5px;color:$($palette.Muted);line-height:1.7;">
      $scriptName &middot; task <span style="$mono;color:$($palette.Text);">WSRS-WacCertificate</span><br>
      Log: <span style="$mono;">$logLine</span><br>
      <span style="color:$($palette.BorderStrong);">Automated notification &mdash; nobody reads replies to it.</span>
    </div>
  </td></tr>

</table>
</td></tr>
</table>
"@
}

# ---------------------------[ Transport ]---------------------------
# A copy is attached rather than the live log: the run is still writing to it, and a
# file opened for reading by the mail client is a file the logger cannot append to.
function Copy-MailAttachment {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return "" }

    try {
        $target = Join-Path -Path $env:TEMP -ChildPath ("wsrs-mail-" + [System.IO.Path]::GetFileName($Path))
        Copy-Item -LiteralPath $Path -Destination $target -Force -ErrorAction Stop
        return $target
    }
    catch {
        Write-Log "Could not copy '$Path' for the mail: $($_.Exception.Message)" -Tag "Debug"
        return ""
    }
}

# Never throws. A report that cannot be sent must not turn a successful renewal into a
# failed task - the certificate is on the gateway either way, and the log says so.
function Send-StudioMail {
    param(
        [Parameter(Mandatory)][object]$Notification,
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$BodyHtml,
        [string[]]$Attachment = @()
    )

    $server = Get-ConfigText -InputObject $Notification -Name "smtpServer"
    if ([string]::IsNullOrWhiteSpace($server)) {
        Write-Log "No SMTP server is configured - no report was sent" -Tag "Error"
        return $false
    }

    $from = Get-ConfigText -InputObject $Notification -Name "from"
    if ([string]::IsNullOrWhiteSpace($from)) {
        Write-Log "notification.from is empty - no report was sent" -Tag "Error"
        return $false
    }

    $recipients = @(Get-ConfigArray -InputObject $Notification -Name "to" |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($recipients.Count -eq 0) {
        Write-Log "notification.to is empty - no report was sent" -Tag "Error"
        return $false
    }

    $port    = [int](Get-ConfigValue -InputObject $Notification -Name "port" -Default 25)
    $useSsl  = [bool](Get-ConfigValue -InputObject $Notification -Name "useSsl" -Default $false)
    $timeout = [int](Get-ConfigValue -InputObject $Notification -Name "timeoutSeconds" -Default 30)
    if ($timeout -le 0) { $timeout = 30 }

    $message         = $null
    $client          = $null
    $tempAttachments = @()

    try {
        # UTF8 without a BOM: a leading byte-order mark inside a MIME part shows up as
        # stray characters at the top of the mail in more clients than it does not.
        $encoding = New-Object System.Text.UTF8Encoding($false)

        $message                 = New-Object System.Net.Mail.MailMessage
        $message.From            = New-Object System.Net.Mail.MailAddress($from)
        $message.Subject         = $Subject
        $message.Body            = $BodyHtml.TrimStart([char]0xFEFF).TrimStart()
        $message.IsBodyHtml      = $true
        $message.BodyEncoding    = $encoding
        $message.SubjectEncoding = $encoding

        # Icons ride along as linked resources rather than as <img src> to anywhere: a
        # cid: reference is the only image mechanism Outlook, Outlook Web and Gmail all
        # render. An AlternateView replaces Body, so the same HTML goes in once more here.
        $icons = @(Get-MailUsedIcon -BodyHtml $message.Body)
        if ($icons.Count -gt 0) {
            $view = [System.Net.Mail.AlternateView]::CreateAlternateViewFromString(
                $message.Body, $encoding, [System.Net.Mime.MediaTypeNames+Text]::Html)

            foreach ($icon in $icons) {
                $bytes    = [System.Convert]::FromBase64String($script:mailIcons[$icon])
                $stream   = New-Object System.IO.MemoryStream(, $bytes)
                $resource = New-Object System.Net.Mail.LinkedResource($stream, "image/png")
                $resource.ContentId        = "icon-" + $icon
                $resource.TransferEncoding = [System.Net.Mime.TransferEncoding]::Base64
                $view.LinkedResources.Add($resource)
            }

            $message.AlternateViews.Add($view)
            Write-Log "Attached $($icons.Count) inline icon(s): $($icons -join ', ')" -Tag "Debug"
        }

        foreach ($recipient in $recipients) { $message.To.Add([string]$recipient) }

        foreach ($file in @($Attachment | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
            $copy = Copy-MailAttachment -Path $file
            if ([string]::IsNullOrWhiteSpace($copy)) { continue }
            $tempAttachments += $copy
            $message.Attachments.Add((New-Object System.Net.Mail.Attachment($copy)))
        }

        [System.Net.ServicePointManager]::SecurityProtocol =
            [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

        $client           = New-Object System.Net.Mail.SmtpClient($server, $port)
        $client.Timeout   = $timeout * 1000
        $client.EnableSsl = $useSsl

        Write-Log "Sending the report to $($recipients -join ', ') via $server`:$port" -Tag "Run"
        $client.Send($message)
        Write-Log "Report mail sent" -Tag "Ok"
        return $true
    }
    catch {
        Write-Log "The report mail could not be sent: $($_.Exception.Message)" -Tag "Error"
        return $false
    }
    finally {
        if ($null -ne $message) { $message.Dispose() }
        if ($null -ne $client)  { $client.Dispose() }
        foreach ($copy in $tempAttachments) {
            Remove-Item -LiteralPath $copy -Force -ErrorAction SilentlyContinue
        }
    }
}

# The task belongs to the server rather than to one role, so the report is addressed
# from the shared certificateTask section - with the old windowsAdminCenter.notification
# read as a fallback, which Get-CertificateNotificationSection handles.
function Send-CertificateReport {
    param(
        [Parameter(Mandatory)][object]$Config,
        [Parameter(Mandatory)][object]$Report
    )

    $notification = Get-CertificateNotificationSection -Config $Config
    if ($null -eq $notification) { return $false }
    if (-not [bool](Get-ConfigValue -InputObject $notification -Name "enabled" -Default $false)) { return $false }

    # "Only when something went wrong" is a real choice: a mail that arrives every
    # morning saying nothing happened is a mail people filter away, taking the one that
    # matters with it.
    $sendOn = Get-ConfigText -InputObject $notification -Name "sendOn" -Default "always"
    if (($sendOn -eq "failureOnly") -and ($Report.Status -ne "Failed")) {
        Write-Log "Nothing failed and notification.sendOn is 'failureOnly' - no report was sent" -Tag "Info"
        return $false
    }

    # The prefix is stored trimmed, so the separator lives here rather than depending on
    # somebody having typed a trailing space into the studio.
    $prefix  = Get-ConfigText -InputObject $notification -Name "subjectPrefix" -Default "Certificate maintenance -"
    $label   = [string]$Report.RoleLabel
    if ([string]::IsNullOrWhiteSpace($label)) { $label = "Certificate" }
    $subject = ("{0} {1} - {2} on {3}" -f $prefix, $label, $Report.Status, $env:COMPUTERNAME).Trim()

    $body = New-WacCertificateMailHtml -Report $Report `
        -Organization (Get-ConfigText -InputObject $notification -Name "organization")

    $attachments = @()
    if ([bool](Get-ConfigValue -InputObject $notification -Name "attachLog" -Default $true)) {
        $attachments = @($logFile)
    }

    return (Send-StudioMail -Notification $notification -Subject $subject -BodyHtml $body -Attachment $attachments)
}

# ---------------------------[ The portal watchdog's report ]---------------------------
# A separate report rather than a RoleLabel on the certificate one. They share the
# transport and every template piece above, and nothing else: that report is built
# around a thumbprint, a validity window and a rebind, and a watchdog over one registry
# DWORD has none of those. Bending it to fit would have meant a body full of empty
# certificate rows on a mail that is about something else entirely.
function New-RdsPortalReport {
    param(
        [Parameter(Mandatory)][ValidateSet("Repaired", "Current", "Failed")][string]$Status,
        [string]$CollectionName = "",
        [string]$Alias          = "",
        [int]$Attempts          = 1,
        [string]$Detail         = ""
    )

    return [pscustomobject]@{
        Status         = $Status
        CollectionName = $CollectionName
        Alias          = $Alias
        Attempts       = $Attempts
        Detail         = $Detail
    }
}

function New-RdsPortalMailHtml {
    param(
        [Parameter(Mandatory)][object]$Report,
        [string]$Organization = ""
    )

    $palette    = $script:mailPalette
    $font       = $script:mailFontFamily
    $mono       = $script:mailMonoFamily
    $failed     = ([string]$Report.Status -eq "Failed")
    $repaired   = ([string]$Report.Status -eq "Repaired")
    $serverName = [string]$env:COMPUTERNAME
    $runTime    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Repaired is the accent tone rather than a success green on purpose: a repair means
    # the desktop had been off the feed for up to an interval, which is a thing that
    # happened rather than a thing that went well.
    $statusTone = "off"
    if ($repaired)   { $statusTone = "on" }
    elseif ($failed) { $statusTone = "danger" }

    $pills = New-MailPill -Label "Status" -Value ([string]$Report.Status).ToUpperInvariant() -Tone $statusTone
    if (-not [string]::IsNullOrWhiteSpace($Report.Alias)) {
        $pills = $pills + (New-MailPill -Label "Alias" -Value ([string]$Report.Alias) -Tone "off")
    }
    if ([int]$Report.Attempts -gt 1) {
        $pills = $pills + (New-MailPill -Label "Attempts" -Value ([string]$Report.Attempts) -Tone "warn")
    }

    # ---- what was checked
    $aliasValue = [string]$Report.Alias
    $keyPath    = "not resolved"
    if (-not [string]::IsNullOrWhiteSpace($aliasValue)) {
        $keyPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\CentralPublishedResources\" +
            "PublishedFarms\" + $aliasValue + "\RemoteDesktops\" + $aliasValue
    }

    $factRows = New-MailFactRow -Label "Collection" -Value ([string]$Report.CollectionName)
    $factRows = $factRows + (New-MailFactRow -Label "Value" -Value "ShowInPortal = 1" -Monospace `
        -Why "The collection's alias is the key name, not the collection's name - it is read from the deployment, never derived.")
    $factRows = $factRows + (New-MailFactRow -Label "Key" -Value $keyPath -Monospace)
    $factRows = $factRows + (New-MailFactRow -Label "Checked at" -Value $runTime)

    # ---- what happened
    $outcomeBlock = ""
    if ($failed) {
        $outcomeText = ConvertTo-MailText -Value ([string]$Report.Detail)
        if ([string]::IsNullOrWhiteSpace($outcomeText)) {
            $outcomeText = "The check failed without a message. The log has the detail."
        }
        $outcomeBlock = '<tr><td style="padding:18px 26px 6px;">' + (New-MailSectionHead -Label "What went wrong" -Icon "security") + '</td></tr>' +
            '<tr><td style="padding:2px 26px 14px;">' + (New-MailNotice -Tone "danger" -Title "Not repaired" -Text $outcomeText) + '</td></tr>' +
            '<tr><td style="padding:0 26px 20px;' + $font + ';font-size:11.5px;color:' + $palette.Muted + ';line-height:1.6;">' +
            'The full desktop is off the RD Web feed until this succeeds. Published applications are unaffected - it is only the ' +
            'desktop tile that this value carries.</td></tr>'
    }
    elseif ($repaired) {
        $outcomeBlock = '<tr><td style="padding:18px 26px 6px;">' + (New-MailSectionHead -Label "What happened" -Icon "web") + '</td></tr>' +
            '<tr><td style="padding:2px 26px 14px;">' +
            (New-MailNotice -Tone "success" -Title "Repaired" -Text (
                'The value had been cleared and this run wrote it back. The full desktop is on the feed again beside the ' +
                'published applications.')) + '</td></tr>' +
            '<tr><td style="padding:0 26px 20px;' + $font + ';font-size:11.5px;color:' + $palette.Muted + ';line-height:1.6;">' +
            'Windows clears this on a broker restart, on a RemoteApp change and on any collection settings change, so a mail after ' +
            'a reboot or a deployment edit is expected. One arriving every interval with nothing else changing means something is ' +
            'writing it back - a second broker in the deployment does exactly that.</td></tr>'
    }
    else {
        $outcomeBlock = '<tr><td style="padding:18px 26px 20px;">' +
            (New-MailNotice -Tone "info" -Text (
                'The value was already set, so nothing was changed. This report is only in your inbox because the design asks ' +
                'for one after every check.')) + '</td></tr>'
    }

    $organizationLabel = ConvertTo-MailText -Value $Organization
    $logLine  = ConvertTo-MailText -Value $logFile
    $taskName = ConvertTo-MailText -Value $script:rdsPortalTaskName

    return @"
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="$($palette.Background)" style="background:$($palette.Background);margin:0;padding:0;">
<tr><td align="center" style="padding:32px 16px;">
<table role="presentation" width="640" cellpadding="0" cellspacing="0" border="0" bgcolor="$($palette.Card)" style="width:640px;max-width:640px;background:$($palette.Card);border:1px solid $($palette.Border);">

  <tr><td style="background:$($palette.Topbar);padding:14px 26px;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
      <td width="24" style="width:24px;padding-right:12px;">$(New-MailLogo)</td>
      <td style="$font;font-size:13px;font-weight:600;color:$($palette.TopbarText);">Windows Server Role Studio</td>
      <td align="right" style="$font;font-size:11.5px;color:$($palette.TopbarMuted);">$organizationLabel</td>
    </tr></table>
  </td></tr>

  <tr><td style="padding:26px 26px 0;">
    <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
      <td width="28" valign="top" style="width:28px;padding:2px 14px 0 0;">$(New-MailIcon -Name "rds" -Size 28 -Alt "Remote Desktop Services")</td>
      <td valign="top">
        <div style="$font;font-size:20px;font-weight:600;color:$($palette.Text);line-height:1.3;">Desktop on the Remote Desktop portal</div>
        <div style="$font;font-size:12.5px;color:$($palette.Muted);padding-top:6px;">Publication check on <b style="color:$($palette.Text);">$serverName</b></div>
      </td>
    </tr></table>
  </td></tr>

  <tr><td style="padding:20px 26px 0;">
    <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>$pills</tr></table>
  </td></tr>

  <tr><td style="padding:10px 26px 22px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">$factRows</table></td></tr>

  $(Get-MailDividerRow -Padding "0 26px")

  $outcomeBlock

  <tr><td style="padding:20px 26px 24px;background:$($palette.Subtle);border-top:1px solid $($palette.Divider);">
    <div style="$font;font-size:11.5px;color:$($palette.Muted);line-height:1.7;">
      $scriptName &middot; task <span style="$mono;color:$($palette.Text);">$taskName</span><br>
      Log: <span style="$mono;">$logLine</span><br>
      <span style="color:$($palette.BorderStrong);">Automated notification &mdash; nobody reads replies to it.</span>
    </div>
  </td></tr>

</table>
</td></tr>
</table>
"@
}

# Its own notification block, unlike the certificate report's, and its own relay: the
# certificate task is one job for the whole server, this one is a property of one
# collection on one broker. They shared a sender while the studio filled this block from
# the certificate mail card, which meant every report from the server arrived from the
# same address about a different subject - so the studio types this one separately now.
# Nothing changed on this side: the block was always read from remoteDesktop.
function Send-RdsPortalReport {
    param(
        [Parameter(Mandatory)][object]$RemoteDesktop,
        [Parameter(Mandatory)][object]$Report
    )

    $watchdog = Get-RdsPortalWatchdog -RemoteDesktop $RemoteDesktop
    if ($null -eq $watchdog) { return $false }

    $notification = Get-ConfigValue -InputObject $watchdog -Name "notification"
    if ($null -eq $notification) { return $false }
    if (-not [bool](Get-ConfigValue -InputObject $notification -Name "enabled" -Default $false)) { return $false }

    # Three answers, and the default is the middle one. An hourly task that mails on
    # every check is a task whose mail gets filtered into a folder, taking the repair
    # notice with it; one that mails on repairs alone can fail silently for a month.
    $status = [string]$Report.Status
    $sendOn = Get-ConfigText -InputObject $notification -Name "sendOn" -Default "repairOrFailure"
    if (($sendOn -eq "repairOnly") -and ($status -ne "Repaired")) {
        Write-Log "Nothing was repaired and notification.sendOn is 'repairOnly' - no report was sent" -Tag "Info"
        return $false
    }
    if (($sendOn -eq "repairOrFailure") -and ($status -eq "Current")) {
        Write-Log "Nothing was repaired and notification.sendOn is 'repairOrFailure' - no report was sent" -Tag "Info"
        return $false
    }

    $prefix  = Get-ConfigText -InputObject $notification -Name "subjectPrefix" -Default "Remote Desktop portal -"
    $subject = ("{0} desktop publication {1} on {2}" -f $prefix, $status.ToLowerInvariant(), $env:COMPUTERNAME).Trim()

    $body = New-RdsPortalMailHtml -Report $Report `
        -Organization (Get-ConfigText -InputObject $notification -Name "organization")

    # Off by default here, unlike the certificate report: this task runs hourly, and a
    # log file an hour is a mailbox rather than a record. The body already carries the
    # alias, the status and the error.
    $attachments = @()
    if ([bool](Get-ConfigValue -InputObject $notification -Name "attachLog" -Default $false)) {
        $attachments = @($logFile)
    }

    return (Send-StudioMail -Notification $notification -Subject $subject -BodyHtml $body -Attachment $attachments)
}
