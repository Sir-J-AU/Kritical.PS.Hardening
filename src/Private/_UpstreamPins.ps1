<#
.SYNOPSIS
    Internal helpers: pinned upstream versions and the verified GitHub-release installer.
.NOTES
    Author: Joshua Finley - Kritical Pty Ltd

    The pins live in src\Data\UpstreamPins.json (never as literals in code). The HardeningKitty
    entry is written by tools\Update-KriticalHardenUpstreamPins.ps1, which reads the latest
    release from the GitHub API, downloads the archive, computes its SHA-256 and records it.
    The installer below re-computes the hash of whatever it downloads and FAILS CLOSED on any
    mismatch: nothing is extracted, nothing is copied into a module path.
#>

Set-StrictMode -Version Latest

$script:KriticalHardenDataRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'Data'

function Get-KriticalHardenDataPath {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string] $Name)
    Join-Path $script:KriticalHardenDataRoot $Name
}

function Get-KriticalHardenUpstreamPin {
    <#
    .SYNOPSIS
        Reads and validates the upstream pin file. Throws on a missing, unparseable or empty file.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([string] $Path)
    if (-not $Path) { $Path = Get-KriticalHardenDataPath -Name 'UpstreamPins.json' }
    if (-not (Test-Path -LiteralPath $Path)) { throw "Upstream pin file not found: $Path" }
    try { $pins = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Upstream pin file is not valid JSON ($Path): $($_.Exception.Message)" }
    if (-not $pins.PSObject.Properties['tools'] -or @($pins.tools.PSObject.Properties).Count -eq 0) {
        throw "Upstream pin file measured zero tools ($Path); refusing to continue."
    }
    $pins
}

function Get-KriticalHardenPinnedVersion {
    <#
    .SYNOPSIS
        The pinned version string for a module, or $null when the module has no pin.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param($Pins, [Parameter(Mandatory)][string] $ModuleName)
    if (-not $Pins -or -not $Pins.PSObject.Properties['tools']) { return $null }
    $p = $Pins.tools.PSObject.Properties[$ModuleName]
    if (-not $p) { return $null }
    $t = $p.Value
    if ($t.PSObject.Properties['requiredVersion'] -and $t.requiredVersion) { return [string]$t.requiredVersion }
    if ($t.PSObject.Properties['moduleVersion'] -and $t.moduleVersion) { return [string]$t.moduleVersion }
    $null
}

function Test-KriticalHardenSha256Format {
    [CmdletBinding()]
    [OutputType([bool])]
    param([string] $Value)
    [bool]($Value -and $Value -match '^[0-9A-Fa-f]{64}$')
}

function Get-KriticalHardenUserModulePath {
    <#
    .SYNOPSIS
        The CurrentUser module root (the path Install-Module -Scope CurrentUser uses).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $docs = [Environment]::GetFolderPath('MyDocuments')
    $leaf = if ($PSVersionTable.PSEdition -eq 'Core') { 'PowerShell\Modules' } else { 'WindowsPowerShell\Modules' }
    Join-Path $docs $leaf
}

function Install-KriticalHardenGitHubReleaseModule {
    <#
    .SYNOPSIS
        Installs a module from a pinned GitHub release archive into the user module path,
        verifying the archive SHA-256 against the recorded pin first. Fails closed.

    .OUTPUTS
        pscustomobject: Status (INSTALLED | HASH-MISMATCH | PIN-INVALID | DOWNLOAD-FAILED |
        ARCHIVE-INVALID), Module, Version, Detail, ExpectedSha256, ActualSha256, InstallPath.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string] $ModuleName,
        [Parameter(Mandatory)][pscustomobject] $Pin,
        [string] $ModulesRoot
    )
    $row = [ordered]@{
        Status = $null; Module = $ModuleName; Version = $null; Detail = $null
        ExpectedSha256 = $null; ActualSha256 = $null; InstallPath = $null
    }
    $fail = { param($status, $detail) $row.Status = $status; $row.Detail = $detail; [pscustomobject]$row }

    $expected = if ($Pin.PSObject.Properties['archiveSha256']) { [string]$Pin.archiveSha256 } else { '' }
    $url      = if ($Pin.PSObject.Properties['archiveUrl'])    { [string]$Pin.archiveUrl }    else { '' }
    $row.ExpectedSha256 = $expected
    if (-not (Test-KriticalHardenSha256Format -Value $expected)) {
        return (& $fail 'PIN-INVALID' 'pin has no valid 64-hex archiveSha256; refusing to download')
    }
    if ($url -notmatch '^https://(api\.github\.com|github\.com|codeload\.github\.com)/') {
        return (& $fail 'PIN-INVALID' "pin archiveUrl is not an https GitHub URL: $url")
    }
    if (-not $ModulesRoot) { $ModulesRoot = Get-KriticalHardenUserModulePath }

    $work = Join-Path ([System.IO.Path]::GetTempPath()) ('krit-harden-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    try {
        $zip = Join-Path $work 'archive.zip'
        try {
            Invoke-WebRequest -Uri $url -OutFile $zip -Headers @{ 'User-Agent' = 'Kritical.PS.Hardening' } -ErrorAction Stop
        } catch {
            return (& $fail 'DOWNLOAD-FAILED' $_.Exception.Message)
        }
        if (-not (Test-Path -LiteralPath $zip)) { return (& $fail 'DOWNLOAD-FAILED' 'download produced no file') }
        $actual = (Get-FileHash -LiteralPath $zip -Algorithm SHA256 -ErrorAction Stop).Hash
        $row.ActualSha256 = $actual
        if ($actual -ine $expected) {
            return (& $fail 'HASH-MISMATCH' "archive SHA-256 $actual does not match pinned $expected; nothing extracted or installed")
        }
        $extract = Join-Path $work 'x'
        try { Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force -ErrorAction Stop }
        catch { return (& $fail 'ARCHIVE-INVALID' $_.Exception.Message) }

        $manifest = Get-ChildItem -LiteralPath $extract -Recurse -File -Filter "$ModuleName.psd1" -ErrorAction Stop |
                    Select-Object -First 1
        if (-not $manifest) { return (& $fail 'ARCHIVE-INVALID' "$ModuleName.psd1 not found in the verified archive") }
        $workFull = [System.IO.Path]::GetFullPath($work)
        if (-not ([System.IO.Path]::GetFullPath($manifest.FullName)).StartsWith($workFull, [System.StringComparison]::OrdinalIgnoreCase)) {
            return (& $fail 'ARCHIVE-INVALID' 'extracted path escaped the work directory')
        }
        $moduleVersion = $null
        try { $moduleVersion = (Import-PowerShellDataFile -LiteralPath $manifest.FullName).ModuleVersion } catch { $moduleVersion = $null }
        if (-not $moduleVersion) { return (& $fail 'ARCHIVE-INVALID' "$ModuleName.psd1 has no readable ModuleVersion") }

        $dest = Join-Path (Join-Path $ModulesRoot $ModuleName) ([string]$moduleVersion)
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        Copy-Item -Path (Join-Path $manifest.Directory.FullName '*') -Destination $dest -Recurse -Force -ErrorAction Stop
        $row.Status = 'INSTALLED'; $row.Version = [string]$moduleVersion; $row.InstallPath = $dest
        $row.Detail = "verified SHA-256 $actual; installed from release $($Pin.releaseTag)"
        [pscustomobject]$row
    } finally {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}
