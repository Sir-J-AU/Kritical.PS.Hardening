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
    $pins = $null
    try { $pins = Get-KriticalHardenUpstreamPin } catch { $pins = $null }
    $rows = foreach ($n in $names) {
        $have = Get-Module -ListAvailable -Name $n -ErrorAction SilentlyContinue |
                Sort-Object Version -Descending | Select-Object -First 1
        $pinned = Get-KriticalHardenPinnedVersion -Pins $pins -ModuleName $n
        [pscustomobject]@{
            Module        = $n
            Installed     = [bool]$have
            Version       = if ($have) { $have.Version } else { $null }
            Loaded        = [bool](Get-Module -Name $n -ErrorAction SilentlyContinue)
            PinnedVersion = $pinned
            PinMatch      = if ($pinned -and $have) { ([string]$have.Version -eq [string]$pinned) } elseif ($pinned) { $false } else { $null }
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
          - HotCakeX/Harden-Windows-Security-Module   (PSGallery, pinned -RequiredVersion)
          - scipag/HardeningKitty   (NOT on PSGallery: pinned GitHub release archive, SHA-256
            verified against src\Data\UpstreamPins.json, fail closed on mismatch, installed to
            the user module path)
          - AuditPolicyDsc / SecurityPolicyDsc / PSDscResources / NetworkingDsc
          - PSScriptAnalyzer
        Pins are read from src\Data\UpstreamPins.json (written by
        tools\Update-KriticalHardenUpstreamPins.ps1). An already-installed module is never
        replaced; a version that differs from its pin is reported (PinMatch = $false).
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
        [switch] $Quiet,
        # Override the install root for the GitHub-release module (default: the user module path).
        [string] $ModulesRoot
    )
    if (-not $NoBanner.IsPresent -and -not $Quiet.IsPresent) {
        Write-KriticalHardenBanner -Title 'Install-KriticalHardenModules' -Compact
    }

    $core = @('Harden-Windows-Security-Module','HardeningKitty')
    $extras = @('AuditPolicyDsc','SecurityPolicyDsc','PSDscResources','NetworkingDsc','PSScriptAnalyzer')
    $targets = if ($OnlyCore.IsPresent) { $core } else { $core + $extras }

    # Pins live in src\Data\UpstreamPins.json. A missing/empty/unparseable pin file is a hard
    # error: installing "whatever is latest" silently is exactly what the pins exist to prevent.
    $pins = Get-KriticalHardenUpstreamPin

    $rows = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($n in $targets) {
        $pin = if ($pins.tools.PSObject.Properties[$n]) { $pins.tools.$n } else { $null }
        $pinned = Get-KriticalHardenPinnedVersion -Pins $pins -ModuleName $n
        $have = Get-Module -ListAvailable -Name $n -ErrorAction SilentlyContinue |
                Sort-Object Version -Descending | Select-Object -First 1
        $relInstall = $null
        if (-not $have -and -not $NoInstall.IsPresent) {
            try {
                if (-not $Quiet.IsPresent) { Write-Host ("Installing $n (CurrentUser)") -ForegroundColor DarkCyan }
                if ($pin -and $pin.source -eq 'github-release') {
                    # NOT on PSGallery: pinned GitHub release, SHA-256 verified, fail closed.
                    $relInstall = Install-KriticalHardenGitHubReleaseModule -ModuleName $n -Pin $pin -ModulesRoot $ModulesRoot
                    if ($relInstall.Status -ne 'INSTALLED') {
                        $rows.Add([pscustomobject]@{ Module=$n; Status='INSTALL-FAILED'; Version=$null; Detail=("{0}: {1}" -f $relInstall.Status, $relInstall.Detail); PinnedVersion=$pinned; PinMatch=$false })
                        continue
                    }
                } else {
                    $im = @{ Name = $n; Scope = 'CurrentUser'; Force = $true; AllowClobber = $true; ErrorAction = 'Stop' }
                    if ($pin -and $pin.source -eq 'psgallery' -and $pin.requiredVersion) { $im.RequiredVersion = [string]$pin.requiredVersion }
                    Install-Module @im
                }
                $have = Get-Module -ListAvailable -Name $n -ErrorAction SilentlyContinue |
                        Sort-Object Version -Descending | Select-Object -First 1
            } catch {
                $rows.Add([pscustomobject]@{ Module=$n; Status='INSTALL-FAILED'; Version=$null; Detail=$_.Exception.Message; PinnedVersion=$pinned; PinMatch=$false })
                continue
            }
        }
        if (-not $have -and $relInstall -and $relInstall.Status -eq 'INSTALLED') {
            # Installed to a custom -ModulesRoot that is not on PSModulePath.
            $rows.Add([pscustomobject]@{ Module=$n; Status='READY'; Version=$relInstall.Version; Detail=("installed to {0} (not on PSModulePath)" -f $relInstall.InstallPath); PinnedVersion=$pinned; PinMatch=([string]$relInstall.Version -eq [string]$pinned) })
            continue
        }
        if (-not $have) { $rows.Add([pscustomobject]@{ Module=$n; Status='MISSING'; Version=$null; Detail='not installed'; PinnedVersion=$pinned; PinMatch=$(if ($pinned) { $false } else { $null }) }); continue }
        $match = if ($pinned) { ([string]$have.Version -eq [string]$pinned) } else { $null }
        $detail = 'installed (not auto-imported)'
        if ($pinned -and -not $match) { $detail = "installed $($have.Version) differs from pinned $pinned (not replaced; remove it and re-run to install the pin)" }
        $rows.Add([pscustomobject]@{ Module=$n; Status='READY'; Version=$have.Version; Detail=$detail; PinnedVersion=$pinned; PinMatch=$match })
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
