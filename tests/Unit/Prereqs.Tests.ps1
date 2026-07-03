#requires -Modules Pester
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\..\src\Kritical.PS.Hardening.psm1') -Force
}
Describe 'Test-KriticalHardenPrereqs' {
    It 'returns a structured result' {
        $r = Test-KriticalHardenPrereqs -Quiet -NoBanner
        $r        | Should -Not -BeNullOrEmpty
        $r.Gates  | Should -Not -BeNullOrEmpty
        $r.Ok     | Should -BeOfType [bool]
        $r.CriticalFails | Should -BeOfType [int]
    }
    It 'reports all 7 gates' {
        $r = Test-KriticalHardenPrereqs -Quiet -NoBanner
        $names = ($r.Gates | Select-Object -ExpandProperty Gate)
        $names | Should -Contain 'P1.Windows'
        $names | Should -Contain 'P2.PSVersion'
        $names | Should -Contain 'P3.Admin'
        $names | Should -Contain 'P4.Defender'
        $names | Should -Contain 'P5.Tpm'
        $names | Should -Contain 'P6.SecureBoot'
        $names | Should -Contain 'P7.WinRM'
    }
    It 'every gate has Severity in Critical/Warning/Info' {
        $r = Test-KriticalHardenPrereqs -Quiet -NoBanner
        foreach ($g in $r.Gates) {
            $g.Severity | Should -BeIn @('Critical','Warning','Info')
        }
    }
}
