<#
.SYNOPSIS
    Build-time tool: records the pinned upstream versions and hashes for Kritical.PS.Hardening.

.DESCRIPTION
    Reads the latest scipag/HardeningKitty release from the GitHub API, downloads the release
    archive, computes its SHA-256, reads the repository LICENSE, and writes:
      - src\Data\UpstreamPins.json   (pins: tag, commit, archive URL, SHA-256, licence)
      - THIRD-PARTY-NOTICES.md       (licence texts for the upstream tools)
    It also records the pinned PSGallery version of Harden-Windows-Security-Module.

    This is NOT part of the module's runtime or its tests. Tests mock the network. Run it only
    when deliberately re-pinning, review the diff, and commit the result.

    Fails closed: any API, download, hash or licence failure throws before anything is written.
    Writes via temp file + move so a failure never leaves a half-written pin file.

    NOTE: GitHub generates source archives on demand and does not promise byte-stable archives
    forever. The installer verifies the recorded hash and refuses on mismatch; if GitHub ever
    changes archive bytes, re-run this tool deliberately and review the new hash.

.PARAMETER HardeningKittyRepo   owner/name of the HardeningKitty repository.
.PARAMETER HardenWindowsRepo    owner/name of the HotCakeX repository (licence notice only).
.PARAMETER GalleryVersion       Pin for Harden-Windows-Security-Module. Default: highest on PSGallery.
.PARAMETER DataPath             Output pin file. Default: src\Data\UpstreamPins.json beside this tool.
.PARAMETER NoticesPath          Output notices file. Default: THIRD-PARTY-NOTICES.md at repo root.

.NOTES
    Author: Joshua Finley - Kritical Pty Ltd
#>
[CmdletBinding()]
param(
    [string] $HardeningKittyRepo = 'scipag/HardeningKitty',
    [string] $HardenWindowsRepo  = 'HotCakeX/Harden-Windows-Security',
    [string] $GalleryVersion,
    [string] $DataPath,
    [string] $NoticesPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $DataPath)    { $DataPath    = Join-Path $repoRoot 'src\Data\UpstreamPins.json' }
if (-not $NoticesPath) { $NoticesPath = Join-Path $repoRoot 'THIRD-PARTY-NOTICES.md' }
$hdr = @{ 'User-Agent' = 'Kritical.PS.Hardening-pin-tool'; 'Accept' = 'application/vnd.github+json' }

function Get-GitHubJson([string] $Path) { Invoke-RestMethod -Uri "https://api.github.com/$Path" -Headers $hdr -ErrorAction Stop }
function Get-RepoLicence([string] $Repo) {
    $l = Get-GitHubJson "repos/$Repo/license"
    $text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($l.content -replace '\s', '')))
    if (-not $text.Trim()) { throw "LICENSE for $Repo was empty" }
    [pscustomobject]@{ Spdx = $l.license.spdx_id; File = $l.path; Text = $text.TrimEnd() }
}

# --- HardeningKitty: latest release ---
$rel = Get-GitHubJson "repos/$HardeningKittyRepo/releases/latest"
if ($rel.draft -or $rel.prerelease) { throw "latest release $($rel.tag_name) is a draft/prerelease; refusing to pin" }
$assets = @($rel.assets | Where-Object { $_.name -like '*.zip' })
if ($assets.Count -gt 0) {
    $assetKind = 'release-asset'; $assetName = $assets[0].name; $url = $assets[0].browser_download_url
    $apiDigest = if ($assets[0].PSObject.Properties['digest']) { [string]$assets[0].digest } else { $null }
} else {
    $assetKind = 'source-archive'; $assetName = "$($rel.tag_name).zip (source archive)"; $url = $rel.zipball_url; $apiDigest = $null
}
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('krit-pin-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $zip = Join-Path $tmp 'a.zip'
    Invoke-WebRequest -Uri $url -OutFile $zip -Headers @{ 'User-Agent' = $hdr['User-Agent'] } -ErrorAction Stop
    $size = (Get-Item -LiteralPath $zip).Length
    if ($size -le 0) { throw 'downloaded archive is empty' }
    $sha = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
    if ($apiDigest -and $apiDigest -match '^sha256:(?<h>[0-9a-fA-F]{64})$' -and $Matches.h -ine $sha) {
        throw "API digest $($Matches.h) does not match downloaded archive hash $sha"
    }
    # Second download must reproduce the same bytes, else the hash is not a usable pin.
    $zip2 = Join-Path $tmp 'b.zip'
    Invoke-WebRequest -Uri $url -OutFile $zip2 -Headers @{ 'User-Agent' = $hdr['User-Agent'] } -ErrorAction Stop
    $sha2 = (Get-FileHash -LiteralPath $zip2 -Algorithm SHA256).Hash
    if ($sha2 -ine $sha) { throw "archive is not byte-stable across two downloads ($sha vs $sha2); cannot pin" }
    $x = Join-Path $tmp 'x'
    Expand-Archive -LiteralPath $zip -DestinationPath $x
    $manifestFile = Get-ChildItem -LiteralPath $x -Recurse -File -Filter 'HardeningKitty.psd1' | Select-Object -First 1
    if (-not $manifestFile) { throw 'HardeningKitty.psd1 not found in archive' }
    $moduleVersion = (Import-PowerShellDataFile -LiteralPath $manifestFile.FullName).ModuleVersion
    $licFile = Get-ChildItem -LiteralPath $manifestFile.Directory.FullName -File -Filter 'LICENSE*' | Select-Object -First 1
    if (-not $licFile) { throw 'LICENSE not found in archive root' }
    $archiveLicence = (Get-Content -LiteralPath $licFile.FullName -Raw).TrimEnd()
} finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }

$commit = (Get-GitHubJson "repos/$HardeningKittyRepo/commits/$([uri]::EscapeDataString($rel.tag_name))").sha
$hkLic  = Get-RepoLicence $HardeningKittyRepo
if ($hkLic.Spdx -ne 'MIT' -or $archiveLicence -notmatch '^MIT License') { throw "unexpected HardeningKitty licence (api=$($hkLic.Spdx)); review before pinning" }
$hwLic  = Get-RepoLicence $HardenWindowsRepo

# --- HotCakeX PSGallery version ---
$gallery = Find-Module -Name 'Harden-Windows-Security-Module' -Repository PSGallery -AllVersions -ErrorAction Stop |
           Sort-Object { [version]($_.Version -replace '-.*$', '') } -Descending
if (-not $gallery) { throw 'Harden-Windows-Security-Module not found on PSGallery' }
$pick = if ($GalleryVersion) { $gallery | Where-Object { $_.Version -eq $GalleryVersion } | Select-Object -First 1 } else { $gallery | Select-Object -First 1 }
if (-not $pick) { throw "PSGallery has no Harden-Windows-Security-Module $GalleryVersion" }

$nowUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$pins = [ordered]@{
    schema      = 'kritical-ps-hardening/upstream-pins/v1'
    recordedUtc = $nowUtc
    recordedBy  = 'tools/Update-KriticalHardenUpstreamPins.ps1'
    tools       = [ordered]@{
        'HardeningKitty' = [ordered]@{
            source         = 'github-release'
            repo           = $HardeningKittyRepo
            releaseTag     = $rel.tag_name
            releasePublishedUtc = ([datetime]$rel.published_at).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            releaseUrl     = $rel.html_url
            commitSha      = $commit
            assetKind      = $assetKind
            assetName      = $assetName
            archiveUrl     = $url
            archiveSizeBytes = $size
            archiveSha256  = $sha
            moduleVersion  = [string]$moduleVersion
            licence        = [ordered]@{ spdx = $hkLic.Spdx; file = $licFile.Name; holder = (($hkLic.Text -split "`n" | Where-Object { $_ -match '^Copyright' } | Select-Object -First 1)) }
            establishedBy  = [ordered]@{
                tag = 'VERIFIED-FROM-API (GitHub REST releases/latest)'
                archiveSha256 = 'VERIFIED-BY-EXECUTION (downloaded twice, identical bytes, hashed locally)'
                licence = 'VERIFIED-FROM-REPO (LICENSE file in the archive and licence API agree)'
            }
            notAvailableOnPSGallery = $true
        }
        'Harden-Windows-Security-Module' = [ordered]@{
            source          = 'psgallery'
            requiredVersion = [string]$pick.Version
            publishedUtc    = if ($pick.PublishedDate) { ([datetime]$pick.PublishedDate).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
            licence         = [ordered]@{ spdx = $hwLic.Spdx; repo = $HardenWindowsRepo }
            establishedBy   = [ordered]@{ version = 'VERIFIED-FROM-API (Find-Module PSGallery)' }
            notes           = 'The PowerShell module is a frozen artefact: the upstream repository now ships Microsoft Store apps, not this module. Pinned, not endorsed as the maintained product.'
        }
    }
}
$json = $pins | ConvertTo-Json -Depth 8

$notices = @"
# Third-party notices

Kritical.PS.Hardening orchestrates the open-source tools below. It does not bundle or redistribute
their code; the installer fetches them at install time (HardeningKitty from a pinned, hash-verified
GitHub release; the HotCakeX module from PSGallery). Their licences are reproduced here as read from
the upstream repositories on $nowUtc.

The mapping data in src\Data\FrameworkMapping.json refers to HardeningKitty finding-list IDs and
finding titles. Those identifiers belong to HardeningKitty (MIT, below).

---

## HardeningKitty ($($rel.tag_name))

Source: https://github.com/$HardeningKittyRepo  (commit $commit)
Licence: $($hkLic.Spdx)

``````text
$($hkLic.Text)
``````

---

## Harden-Windows-Security-Module (HotCakeX) $($pick.Version)

Source: https://github.com/$HardenWindowsRepo
Licence: $($hwLic.Spdx)

``````text
$($hwLic.Text)
``````
"@

New-Item -ItemType Directory -Path (Split-Path -Parent $DataPath) -Force | Out-Null
$t1 = "$DataPath.tmp"; $t2 = "$NoticesPath.tmp"
try {
    Set-Content -LiteralPath $t1 -Value $json -Encoding utf8
    Set-Content -LiteralPath $t2 -Value $notices -Encoding utf8
    Move-Item -LiteralPath $t1 -Destination $DataPath -Force
    Move-Item -LiteralPath $t2 -Destination $NoticesPath -Force
} finally { Remove-Item -LiteralPath $t1, $t2 -Force -ErrorAction SilentlyContinue }

"PINNED HardeningKitty $($rel.tag_name) sha256=$sha size=$size commit=$commit; Harden-Windows-Security-Module $($pick.Version)"
