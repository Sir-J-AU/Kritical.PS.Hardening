<#
.SYNOPSIS
    Kritical.PS.Hardening full test runner. Pester 5+. Output OUT of repo by default.
.AUTHOR
    Joshua Finley - Kritical Pty Ltd
#>
[CmdletBinding()]
param([switch] $NoBanner, [string] $OutputDir)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $PSCommandPath
$repo = Split-Path -Parent $here
Import-Module (Join-Path $repo 'src\Kritical.PS.Hardening.psm1') -Force

if (-not $NoBanner.IsPresent) {
    # Write-KriticalHardenBanner is private (not exported): call it in module scope.
    & (Get-Module Kritical.PS.Hardening) { Write-KriticalHardenBanner -Title 'Test Runner' }
}

# The suite is written for Pester 5.x (tested on 5.7.1). Pester 6 is installed on some machines and
# breaks every test here, so select the highest 5.x explicitly instead of "highest installed".
$pester = Get-Module Pester -ListAvailable | Where-Object { $_.Version.Major -eq 5 -and $_.Version -ge [version]'5.5.0' } |
          Sort-Object Version -Descending | Select-Object -First 1
if (-not $pester) {
    Install-Module Pester -MinimumVersion 5.5.0 -MaximumVersion 5.99.99 -Force -SkipPublisherCheck -Scope CurrentUser
    $pester = Get-Module Pester -ListAvailable | Where-Object { $_.Version.Major -eq 5 } | Sort-Object Version -Descending | Select-Object -First 1
}
Import-Module Pester -RequiredVersion $pester.Version -Force

if (-not $OutputDir) { $OutputDir = Join-Path $env:LOCALAPPDATA 'Kritical\Kritical.PS.Hardening\test-output' }
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$utc = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmssZ')

$conf = New-PesterConfiguration
$conf.Run.Path = @((Join-Path $here 'Unit'))
$conf.Output.Verbosity = 'Detailed'
$conf.TestResult.Enabled = $true
$conf.TestResult.OutputPath = (Join-Path $OutputDir "results-$utc.xml")
$conf.TestResult.OutputFormat = 'NUnitXml'
$conf.Run.PassThru = $true

$r = Invoke-Pester -Configuration $conf
[pscustomobject]@{
    UtcStamp=$utc; Total=$r.TotalCount; Passed=$r.PassedCount; Failed=$r.FailedCount
    Skipped=$r.SkippedCount; Duration=$r.Duration; Result=$r.Result
} | Format-List | Out-String | Write-Host

if ($r.Result -ne 'Passed') { Write-Host "FAIL - $($r.FailedCount) failed." -ForegroundColor Red; exit 1 }
Write-Host "PASS - $($r.PassedCount) tests." -ForegroundColor Green
exit 0
