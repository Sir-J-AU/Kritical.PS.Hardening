# Shared helpers for the Kritical.PS.Hardening Pester suites (dot-sourced; not a test file).
# KRIT_HARDEN_SRC lets tests\Invoke-PlantedDefectProofs.ps1 point the suites at a mutated copy of src.

function Get-HardenTestSrcRoot {
    if ($env:KRIT_HARDEN_SRC) { return $env:KRIT_HARDEN_SRC }
    Join-Path $PSScriptRoot '..\..\src'
}

function Build-HardenFakeReleaseZip {
    <# Builds a tiny archive shaped like the HardeningKitty release (one top folder with the manifest). #>
    param([Parameter(Mandatory)][string] $Directory, [string] $Version = '0.9.4', [switch] $NoManifest)
    $stage = Join-Path $Directory ('stage-' + [guid]::NewGuid().ToString('N'))
    $top = Join-Path $stage 'scipag-HardeningKitty-abc1234'
    New-Item -ItemType Directory -Path (Join-Path $top 'lists') -Force | Out-Null
    if (-not $NoManifest) {
        Set-Content -LiteralPath (Join-Path $top 'HardeningKitty.psd1') -Value "@{ ModuleVersion = '$Version'; RootModule = 'HardeningKitty.psm1' }"
        Set-Content -LiteralPath (Join-Path $top 'HardeningKitty.psm1') -Value 'function Invoke-HardeningKitty { }'
    }
    Set-Content -LiteralPath (Join-Path $top 'LICENSE') -Value 'MIT License (fake test fixture)'
    Set-Content -LiteralPath (Join-Path $top 'lists\fixture.csv') -Value 'ID,Name'
    $zip = Join-Path $Directory ('fake-' + [guid]::NewGuid().ToString('N') + '.zip')
    Compress-Archive -Path $top -DestinationPath $zip
    Remove-Item -LiteralPath $stage -Recurse -Force
    $zip
}

function Build-HardenTestPin {
    param([Parameter(Mandatory)][string] $ArchiveSha256, [string] $Url = 'https://api.github.com/repos/scipag/HardeningKitty/zipball/v.0.9.4')
    [pscustomobject]@{
        source = 'github-release'; repo = 'scipag/HardeningKitty'; releaseTag = 'v.0.9.4'
        archiveUrl = $Url; archiveSha256 = $ArchiveSha256; moduleVersion = '0.9.4'
    }
}
