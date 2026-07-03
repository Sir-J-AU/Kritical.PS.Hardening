#requires -Modules Pester
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\..\src\Kritical.PS.Hardening.psm1') -Force
}
Describe 'Get-KriticalHardenBanner' {
    It 'returns a string with Kritical brand' {
        $b = Get-KriticalHardenBanner
        $b | Should -Match 'Kritical'
    }
    It '-Compact returns one-line summary' {
        $b = Get-KriticalHardenBanner -Compact
        $b | Should -Match 'Kritical'
    }
    It '-Title appends title block when not Compact' {
        (Get-KriticalHardenBanner -Title 'UnitTest') | Should -Match 'UnitTest'
    }
}
