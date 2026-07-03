#requires -Modules Pester
BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
    $script:Psd1     = Join-Path $script:RepoRoot 'src\Kritical.PS.Hardening.psd1'
    Import-Module (Join-Path $script:RepoRoot 'src\Kritical.PS.Hardening.psm1') -Force
}

Describe 'Manifest integrity' {
    It 'Test-ModuleManifest passes' {
        $mi = Test-ModuleManifest -Path $script:Psd1
        $mi.Name        | Should -Be 'Kritical.PS.Hardening'
        $mi.Author      | Should -Be 'Joshua Finley'
        $mi.CompanyName | Should -Be 'Kritical Pty Ltd'
        $mi.Copyright   | Should -Match 'Kritical'
    }
    It 'Every FunctionsToExport exists in loaded module' {
        $mi = Test-ModuleManifest -Path $script:Psd1
        $exported = (Get-Command -Module Kritical.PS.Hardening | Select-Object -ExpandProperty Name) | Sort-Object
        foreach ($f in $mi.ExportedFunctions.Keys) { $exported | Should -Contain $f }
    }
}

Describe 'Banner asset bundled' {
    It 'src/Assets/kritical-logo.txt contains the canonical SirJ banner' {
        $asset = Join-Path $script:RepoRoot 'src/Assets/kritical-logo.txt'
        Test-Path -LiteralPath $asset | Should -BeTrue
        $body = Get-Content -LiteralPath $asset -Raw
        $body | Should -Match 'SirJ'
        $body | Should -Match 'Kritical'
    }
}

Describe 'No AI-agent strings in published source' {
    It 'no Claude / Hermes / Codex / Copilot / ChatGPT / Anthropic / OpenAI strings under src/' {
        $srcDir = Join-Path $script:RepoRoot 'src'
        $files = Get-ChildItem -LiteralPath $srcDir -Recurse -File -Include *.ps1,*.psm1,*.psd1
        $bad = foreach ($f in $files) {
            $c = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
            if ($c -and $c -match '(?i)\b(Claude|Hermes|Codex|Copilot|ChatGPT|Anthropic|OpenAI)\b') {
                [pscustomobject]@{ File=$f.FullName; Match=$matches[1] }
            }
        }
        $bad | Should -BeNullOrEmpty -Because ("found AI-agent names in: " + (($bad | ForEach-Object { $_.File }) -join ', '))
    }
}
