# Kritical.PS.Hardening — Publishing

Author: Joshua Finley — Kritical Pty Ltd

## Pre-flight

1. Pester green: `tools\Publish-KriticalHardening.ps1` runs this automatically; or `tests\Invoke-AllTests.ps1` manually.
2. `Test-ModuleManifest src\Kritical.PS.Hardening.psd1` passes (Krit.OmniFramework must be installed locally).
3. No AI-agent name leaks (Manifest.Tests.ps1 enforces).
4. Author/Company stamp in manifest: Joshua Finley / Kritical Pty Ltd.
5. Version bumped + ReleaseNotes added.

## One-button publish

```powershell
& "$env:USERPROFILE\OneDrive - Kritical Pty Ltd\Github\Kritical.PS.Hardening\tools\Publish-KriticalHardening.ps1"
```

Runs the gated flow: doc check → Pester suite → stage → manifest validate → PSGallery push. Reads API key from `Github-SecretsOutsideOfGitRepos\psgallery-api-key.txt`.

## Manual fallback

```powershell
$apiKey = (Get-Content "$env:USERPROFILE\OneDrive - Kritical Pty Ltd\Github-SecretsOutsideOfGitRepos\psgallery-api-key.txt" -Raw).Trim()
$repo = "$env:USERPROFILE\OneDrive - Kritical Pty Ltd\Github\Kritical.PS.Hardening"
$stage = "$env:LOCALAPPDATA\Kritical\Kritical.PS.Hardening\publish-staging\Kritical.PS.Hardening"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null
Copy-Item -Recurse -Force "$repo\src\*" $stage
Publish-Module -Path $stage -NuGetApiKey $apiKey -Verbose
```

## GitHub release zip

```powershell
$out = "$env:LOCALAPPDATA\Kritical\Kritical.PS.Hardening\release\Kritical.PS.Hardening-1.0.0.zip"
$stage = "$env:LOCALAPPDATA\Kritical\Kritical.PS.Hardening\zip-staging"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null
Copy-Item -Recurse -Force "$repo\src\*" $stage
Copy-Item -Force "$repo\README.md","$repo\LICENSE","$repo\CONTRIBUTING.md" $stage
Copy-Item -Recurse -Force "$repo\docs" $stage
Push-Location $stage; try { Compress-Archive -Path .\* -DestinationPath $out -Force } finally { Pop-Location }
gh release create v1.0.0 $out -t 'Kritical.PS.Hardening 1.0.0' -n 'Audit-only Kritical Hardening toolkit. Author: Joshua Finley.'
```

## Rollback

`Unpublish-Module -Name Kritical.PS.Hardening -RequiredVersion 1.0.0 -NuGetApiKey $apiKey` (within 90 days), or publish a patch.
