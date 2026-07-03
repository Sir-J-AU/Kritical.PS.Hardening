#requires -Version 7.0
<#
.SYNOPSIS
    Renames Krit.Hardening -> Kritical.PS.Hardening (module name), KritHarden ->
    KriticalHarden (function prefix), across contents and filenames.
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [ValidateSet('Content','Filenames','Both')][string]$Phase = 'Both'
)
$ErrorActionPreference = 'Stop'
$repo = $PSScriptRoot

$replacements = @(
    @{ Pattern = 'Krit\.Hardening';   Replacement = 'Kritical.PS.Hardening' },
    @{ Pattern = 'KritHarden';        Replacement = 'KriticalHarden' }
)

$textExtensions = @('.ps1','.psm1','.psd1','.md','.json','.yml','.yaml','.txt','.gitignore')

$stats = [ordered]@{
    Apply=[bool]$Apply; Phase=$Phase; Scanned=0; ContentEdited=0; ContentHits=0
    FilesRenamed=0; PerPattern=@{}; SampleContent=@(); SampleRename=@(); Errors=@()
}
foreach ($r in $replacements) { $stats.PerPattern[$r.Pattern] = 0 }

function Get-RepoFiles {
    Get-ChildItem -Path $repo -Recurse -File -Force | Where-Object {
        $_.FullName -notmatch '\\\.git\\' -and
        $_.FullName -notlike '*.bak.*' -and
        $_.Name -ne 'Rename-KritHardeningToKriticalPSHardening.ps1'
    }
}

if ($Phase -in @('Content','Both')) {
    Write-Host "== Content ==" -ForegroundColor Cyan
    foreach ($f in Get-RepoFiles) {
        $stats.Scanned++
        if ($textExtensions -notcontains $f.Extension.ToLower()) { continue }
        try {
            $orig = [System.IO.File]::ReadAllText($f.FullName)
            $cur = $orig
            $hits = 0
            foreach ($r in $replacements) {
                $m = [regex]::Matches($cur, $r.Pattern)
                if ($m.Count -gt 0) {
                    $stats.PerPattern[$r.Pattern] += $m.Count
                    $hits += $m.Count
                    $cur = [regex]::Replace($cur, $r.Pattern, $r.Replacement)
                }
            }
            if ($cur -ne $orig) {
                $stats.ContentEdited++
                $stats.ContentHits += $hits
                if ($stats.SampleContent.Count -lt 5) {
                    $stats.SampleContent += $f.FullName.Substring($repo.Length + 1)
                }
                if ($Apply) { [System.IO.File]::WriteAllText($f.FullName, $cur) }
            }
        } catch { $stats.Errors += "$($f.FullName): $_" }
    }
    Write-Host ("  Scanned: {0}  Edited: {1}  Total hits: {2}" -f $stats.Scanned, $stats.ContentEdited, $stats.ContentHits)
    foreach ($k in $stats.PerPattern.Keys) { Write-Host ("    {0,-30} {1}" -f $k, $stats.PerPattern[$k]) }
}

if ($Phase -in @('Filenames','Both')) {
    Write-Host "== Filenames ==" -ForegroundColor Cyan
    $files = Get-RepoFiles | Where-Object { $_.Name -match 'Krit\.Hardening|KritHarden' } |
        Sort-Object { $_.FullName.Length } -Descending
    foreach ($f in $files) {
        $newName = $f.Name
        foreach ($r in $replacements) {
            $newName = [regex]::Replace($newName, $r.Pattern, $r.Replacement)
        }
        if ($newName -ne $f.Name) {
            $stats.FilesRenamed++
            if ($stats.SampleRename.Count -lt 5) {
                $stats.SampleRename += "$($f.Name)  ->  $newName"
            }
            if ($Apply) {
                try {
                    $rel = $f.FullName.Substring($repo.Length + 1).Replace('\','/')
                    $newRel = (Join-Path (Split-Path $rel -Parent) $newName).Replace('\','/')
                    Push-Location $repo
                    try {
                        $null = git mv -- $rel $newRel 2>&1
                        if ($LASTEXITCODE -ne 0) {
                            Move-Item -LiteralPath $f.FullName -Destination (Join-Path $f.Directory.FullName $newName) -Force
                        }
                    } finally { Pop-Location }
                } catch { $stats.Errors += "$($f.FullName): $_" }
            }
        }
    }
    Write-Host ("  Renamed: {0}" -f $stats.FilesRenamed)
    $stats.SampleRename | ForEach-Object { Write-Host "    $_" }
}

if ($stats.Errors.Count -gt 0) {
    Write-Warning ("{0} errors:" -f $stats.Errors.Count)
    $stats.Errors | Select-Object -First 5 | ForEach-Object { Write-Host "  $_" }
}
