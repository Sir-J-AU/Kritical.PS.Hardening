function Get-KriticalHardenBannerCanonicalPath {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $candidates = @(
        (Join-Path $env:USERPROFILE 'OneDrive - Kritical Pty Ltd\Kritical-Branding\public\KriticalLogo.txt'),
        (Join-Path $env:USERPROFILE 'OneDrive - Kritical Pty Ltd\Github-SecretsOutsideOfGitRepos\KriticalLogo.txt'),
        (Join-Path (Split-Path -Parent (Split-Path -Parent $PSCommandPath)) 'Assets/kritical-logo.txt')
    )
    foreach ($p in $candidates) { if (Test-Path -LiteralPath $p) { return $p } }
    return $null
}

function Get-KriticalHardenBanner {
    <#
    .SYNOPSIS
        Returns the canonical Kritical banner. Prefers Krit.OmniFramework's Get-KritBanner
        if the foundation is loaded; falls back to a local copy.
    .NOTES
        Author: Joshua Finley - Kritical Pty Ltd
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string] $Title, [switch] $Compact)
    if (Get-Command Get-KritBanner -Module Krit.OmniFramework -ErrorAction SilentlyContinue) {
        return Get-KritBanner -Title $Title -Compact:$Compact
    }
    $path = Get-KriticalHardenBannerCanonicalPath
    if ($Compact -or -not $path -or -not (Test-Path -LiteralPath $path)) {
        $line = '[Kritical(TM)] Hardening | +61 1300 274 655 | sales at kritical dot net'
        if ($Title) { $line += " - $Title" }
        return $line
    }
    $logo = Get-Content -LiteralPath $path -Raw
    if ($Title) { return ($logo.TrimEnd() + "`n`n--- $Title ---`n") }
    return $logo
}

function Write-KriticalHardenBanner {
    [CmdletBinding()]
    param([string] $Title, [switch] $Compact, [switch] $NoColor)
    if (Get-Command Write-KritBanner -Module Krit.OmniFramework -ErrorAction SilentlyContinue) {
        Write-KritBanner -Title $Title -Compact:$Compact -NoColor:$NoColor
        return
    }
    Write-Host (Get-KriticalHardenBanner -Title $Title -Compact:$Compact) -ForegroundColor DarkCyan
}
