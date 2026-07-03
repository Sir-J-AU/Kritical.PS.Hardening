function Get-KriticalHardenModuleStatus {
    <#
    .SYNOPSIS
        Read-only inventory of the OSS hardening modules Kritical.PS.Hardening orchestrates.
    .NOTES
        Author: Joshua Finley - Kritical Pty Ltd
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()
    $names = @(
        'Harden-Windows-Security-Module',  # HotCakeX - Confirm-SystemCompliance / Protect-WindowsSecurity
        'HardeningKitty',                  # scipag - Invoke-HardeningKitty STIG/CIS audit + HailMary apply
        'AuditPolicyDsc',                  # DSC AuditPolicy resource
        'SecurityPolicyDsc',               # DSC SecurityPolicy (LSA / Kerberos / user-rights)
        'PSDscResources',                  # Modern DSC base resources
        'NetworkingDsc',                   # DSC firewall + IPSec
        'PSScriptAnalyzer'                 # PS-side static analysis (anti-pattern hardening)
    )
    $rows = foreach ($n in $names) {
        $have = Get-Module -ListAvailable -Name $n -ErrorAction SilentlyContinue |
                Sort-Object Version -Descending | Select-Object -First 1
        [pscustomobject]@{
            Module    = $n
            Installed = [bool]$have
            Version   = if ($have) { $have.Version } else { $null }
            Loaded    = [bool](Get-Module -Name $n -ErrorAction SilentlyContinue)
        }
    }
    [pscustomobject]@{ Modules = @($rows); Timestamp = (Get-Date).ToUniversalTime() }
}

function Install-KriticalHardenModules {
    <#
    .SYNOPSIS
        Idempotent installer for the OSS hardening giants that Kritical.PS.Hardening orchestrates.

    .DESCRIPTION
        Installs (CurrentUser scope) any missing module from the canonical hardening set:
          - HotCakeX/Harden-Windows-Security-Module
          - scipag/HardeningKitty
          - AuditPolicyDsc / SecurityPolicyDsc / PSDscResources / NetworkingDsc
          - PSScriptAnalyzer
        Honours -NoInstall (CI prebake). Honours -OnlyCore (HotCakeX + HardeningKitty only;
        skip DSC family for minimal install).

    .EXAMPLE
        Install-KriticalHardenModules                           # full set
        Install-KriticalHardenModules -OnlyCore                 # just HotCakeX + HardeningKitty
        Install-KriticalHardenModules -NoInstall                # report-only

    .NOTES
        Author: Joshua Finley - Kritical Pty Ltd
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [switch] $OnlyCore,
        [switch] $NoInstall,
        [switch] $NoBanner,
        [switch] $Quiet
    )
    if (-not $NoBanner.IsPresent -and -not $Quiet.IsPresent) {
        Write-KriticalHardenBanner -Title 'Install-KriticalHardenModules' -Compact
    }

    $core = @('Harden-Windows-Security-Module','HardeningKitty')
    $extras = @('AuditPolicyDsc','SecurityPolicyDsc','PSDscResources','NetworkingDsc','PSScriptAnalyzer')
    $targets = if ($OnlyCore.IsPresent) { $core } else { $core + $extras }

    $rows = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($n in $targets) {
        $have = Get-Module -ListAvailable -Name $n -ErrorAction SilentlyContinue |
                Sort-Object Version -Descending | Select-Object -First 1
        if (-not $have -and -not $NoInstall.IsPresent) {
            try {
                if (-not $Quiet.IsPresent) { Write-Host ("Installing $n (CurrentUser)") -ForegroundColor DarkCyan }
                Install-Module -Name $n -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                $have = Get-Module -ListAvailable -Name $n -ErrorAction SilentlyContinue |
                        Sort-Object Version -Descending | Select-Object -First 1
            } catch {
                $rows.Add([pscustomobject]@{ Module=$n; Status='INSTALL-FAILED'; Version=$null; Detail=$_.Exception.Message })
                continue
            }
        }
        if (-not $have) { $rows.Add([pscustomobject]@{ Module=$n; Status='MISSING'; Version=$null; Detail='not installed' }); continue }
        $rows.Add([pscustomobject]@{ Module=$n; Status='READY'; Version=$have.Version; Detail='installed (not auto-imported)' })
    }
    if (-not $Quiet.IsPresent) {
        $rows | Format-Table -AutoSize | Out-String | Write-Host
    }
    $bad = @($rows | Where-Object { $_.Status -in @('MISSING','INSTALL-FAILED') })
    [pscustomobject]@{
        Ok       = ($bad.Count -eq 0)
        Failures = $bad.Count
        Modules  = @($rows)
    }
}
