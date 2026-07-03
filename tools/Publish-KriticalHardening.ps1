<#
.SYNOPSIS
    Publish Kritical.PS.Hardening to PSGallery with gated tests + doc check + manifest validation.
.NOTES
    Author: Joshua Finley - Kritical Pty Ltd
#>
[CmdletBinding(SupportsShouldProcess)]
[OutputType([pscustomobject])]
param(
    [string] $ApiKeyFile,
    [string] $ModuleName = 'Kritical.PS.Hardening',
    [string] $RepoRoot,
    [switch] $SkipManifestTest,
    [switch] $SkipTests,
    [switch] $SkipDocCheck,
    [switch] $NoBanner
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath) }
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$srcDir = Join-Path $RepoRoot 'src'
if (-not (Test-Path -LiteralPath $srcDir)) { throw "src folder not found at $srcDir" }

if (-not $ApiKeyFile) {
    $ApiKeyFile = Join-Path $env:USERPROFILE 'OneDrive - Kritical Pty Ltd\Github-SecretsOutsideOfGitRepos\psgallery-api-key.txt'
}

if (-not $NoBanner.IsPresent) {
    $logo = Join-Path $env:USERPROFILE 'OneDrive - Kritical Pty Ltd\Kritical-Branding\public\KriticalLogo.txt'
    if (-not (Test-Path -LiteralPath $logo)) { $logo = Join-Path $srcDir 'Assets\kritical-logo.txt' }
    if (Test-Path -LiteralPath $logo) {
        Write-Host (Get-Content -LiteralPath $logo -Raw) -ForegroundColor DarkCyan
        Write-Host "--- Publish $ModuleName to PSGallery ---" -ForegroundColor Yellow
    }
}

if (-not (Test-Path -LiteralPath $ApiKeyFile)) { throw "PSGallery API key file not found at $ApiKeyFile" }
$apiKey = (Get-Content -LiteralPath $ApiKeyFile -Raw).Trim()
if ($apiKey.Length -lt 30) { throw "API key suspiciously short" }
Write-Host ("API key loaded (length=" + $apiKey.Length + ")") -ForegroundColor Green

if (-not $SkipDocCheck.IsPresent) {
    Write-Host 'Validating doc set...' -ForegroundColor DarkCyan
    $required = @{
        'README.md'             = 'README'
        'LICENSE'               = 'License'
        'CONTRIBUTING.md'       = 'Contributing'
        'docs\USAGE.md'         = 'Usage'
        'docs\ARCHITECTURE.md'  = 'Architecture'
        'docs\PUBLISHING.md'    = 'Publishing'
    }
    $bad = @()
    foreach ($rel in $required.Keys) {
        $full = Join-Path $RepoRoot $rel
        if (-not (Test-Path -LiteralPath $full)) { $bad += "MISSING: $rel"; continue }
        $c = Get-Content -LiteralPath $full -Raw -ErrorAction SilentlyContinue
        if ($rel -ne 'LICENSE' -and $c -and ($c -notmatch 'Kritical|SirJ')) { $bad += "NO-BRAND: $rel" }
        if ($c -and $c -notmatch 'Joshua Finley') { $bad += "NO-AUTHOR: $rel" }
    }
    if ($bad.Count -gt 0) { $bad | ForEach-Object { Write-Host ("  [FAIL] $_") -ForegroundColor Red }; throw "Doc gate failed ($($bad.Count))" }
    Write-Host ("  All $($required.Count) docs present + branded + authored.") -ForegroundColor Green
}

if (-not $SkipTests.IsPresent) {
    Write-Host 'Running Pester suite...' -ForegroundColor DarkCyan
    $runner = Join-Path $RepoRoot 'tests\Invoke-AllTests.ps1'
    if (-not (Test-Path -LiteralPath $runner)) { throw "Test runner missing at $runner" }
    $savedWhatIf = $WhatIfPreference
    $WhatIfPreference = $false
    try { & $runner -NoBanner } finally { $WhatIfPreference = $savedWhatIf }
    if ($LASTEXITCODE -ne 0) { throw "Tests FAILED (exit $LASTEXITCODE). Refusing red publish." }
    Write-Host '  Tests GREEN.' -ForegroundColor Green
}

$stagingBase = Join-Path $env:LOCALAPPDATA "Kritical\$ModuleName\publish-staging"
$stagingMod  = Join-Path $stagingBase $ModuleName
if (Test-Path -LiteralPath $stagingMod) { Remove-Item -LiteralPath $stagingMod -Recurse -Force }
New-Item -ItemType Directory -Path $stagingMod -Force | Out-Null
Copy-Item -Recurse -Force "$srcDir\*" $stagingMod
Write-Host ("Staged module -> " + $stagingMod) -ForegroundColor Green

if (-not $SkipManifestTest.IsPresent) {
    $stagedPsd1 = Join-Path $stagingMod "$ModuleName.psd1"
    $mi = Test-ModuleManifest -Path $stagedPsd1
    Write-Host ("  Manifest: $($mi.Name) v$($mi.Version) | Author=$($mi.Author) | Company=$($mi.CompanyName)") -ForegroundColor Green
    if ($mi.Author -ne 'Joshua Finley') { Write-Warning "Author mismatch: '$($mi.Author)'" }
}

Push-Location -LiteralPath $stagingBase
try {
    if ($PSCmdlet.ShouldProcess($stagingMod, "Publish-Module to PSGallery")) {
        Publish-Module -Path $stagingMod -NuGetApiKey $apiKey -Verbose -ErrorAction Stop
        $published = $true
        Write-Host ("Published OK -> https://www.powershellgallery.com/packages/$ModuleName") -ForegroundColor Green
    } else { $published = $false }
} finally { Pop-Location }

[pscustomobject]@{
    Module       = $ModuleName
    StagedAt     = $stagingMod
    Published    = $published
    PSGalleryUrl = "https://www.powershellgallery.com/packages/$ModuleName"
}
