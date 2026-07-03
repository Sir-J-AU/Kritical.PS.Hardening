<#
.SYNOPSIS
    Kritical.PS.Hardening - Kritical Hardening toolkit (audit-only in v1.0.0).
.AUTHOR
    Joshua Finley - Kritical Pty Ltd - https://kritical.net
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# 1.0.1 - soft-import Kritical.PS.OmniFramework. Never fail hard at import time even
# if Omni is missing or AppDomain-locked at an older version. Consuming
# functions probe for OmniFramework at use time and degrade gracefully.
function Import-KriticalHardenOmniSoft {
    [CmdletBinding()]
    param([switch] $Quiet)
    $already = Get-Module -Name Kritical.PS.OmniFramework -ErrorAction SilentlyContinue
    if ($already) { return @{ Ok=$true; Version=$already.Version; Source='already-loaded' } }
    $have = Get-Module -ListAvailable -Name Kritical.PS.OmniFramework -ErrorAction SilentlyContinue |
            Sort-Object Version -Descending | Select-Object -First 1
    if (-not $have) { return @{ Ok=$false; Version=$null; Source='not-installed' } }
    try {
        Import-Module -Name Kritical.PS.OmniFramework -ErrorAction Stop
        $loaded = Get-Module -Name Kritical.PS.OmniFramework | Select-Object -First 1
        return @{ Ok=$true; Version=$loaded.Version; Source='imported' }
    } catch {
        if (-not $Quiet.IsPresent) { Write-Warning ("Kritical.PS.OmniFramework soft-import failed: " + $_.Exception.Message) }
        return @{ Ok=$false; Version=$have.Version; Source='import-failed'; Error=$_.Exception.Message }
    }
}

try { Import-KriticalHardenOmniSoft -Quiet | Out-Null } catch { }

$here = Split-Path -Parent $PSCommandPath
foreach ($dir in 'Private','Public') {
    $folder = Join-Path $here $dir
    if (Test-Path -LiteralPath $folder) {
        Get-ChildItem -LiteralPath $folder -Filter '*.ps1' -File | Sort-Object Name | ForEach-Object {
            . $_.FullName
        }
    }
}

Export-ModuleMember -Function @(
    'Test-KriticalHardenPrereqs',
    'Install-KriticalHardenModules',
    'Get-KriticalHardenModuleStatus',
    'Test-KriticalHardenCompliance',
    'New-KriticalHardenReport',
    'Get-KriticalHardenBanner'
)
