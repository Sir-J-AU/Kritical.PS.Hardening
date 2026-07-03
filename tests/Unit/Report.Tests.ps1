#requires -Modules Pester
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\..\src\Kritical.PS.Hardening.psm1') -Force
    $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("krit-harden-rpt-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $script:Tmp | Out-Null
    # Synthetic compliance result for report rendering
    $script:Synth = [pscustomobject]@{
        Timestamp     = (Get-Date).ToUniversalTime()
        FindingCount  = 2
        ByOutcome     = @([pscustomobject]@{Outcome='Pass';Count=1}, [pscustomobject]@{Outcome='Fail';Count=1})
        SourceSummary = @([pscustomobject]@{Source='Synthetic';Tool='unit-test';Version='0.0';Findings=2})
        Findings      = @(
            [pscustomobject]@{ Source='Synthetic'; Category='Defender'; Control='RealTimeProtection'; Outcome='Pass';  Detail='RTP enabled'; Recommendation=''; Severity='Info' }
            [pscustomobject]@{ Source='Synthetic'; Category='Defender'; Control='SignatureAge';      Outcome='Fail'; Detail='5 days'; Recommendation='Run Update-MpSignature'; Severity='Warning' }
        )
        Platform      = $null
    }
}
AfterAll {
    Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'New-KriticalHardenReport' {
    It 'always writes a JSON snapshot of the compliance result' {
        $r = New-KriticalHardenReport -ComplianceResult $script:Synth -OutDir $script:Tmp -NoOpen -NoBanner
        Test-Path -LiteralPath $r.JsonPath | Should -BeTrue
        (Get-Content -LiteralPath $r.JsonPath -Raw) | Should -Match 'RealTimeProtection'
    }
    It 'returns an object with OutDir/JsonPath/HtmlPath/XlsxPath' {
        $r = New-KriticalHardenReport -ComplianceResult $script:Synth -OutDir $script:Tmp -NoOpen -NoBanner
        $r          | Should -Not -BeNullOrEmpty
        $r.OutDir   | Should -Be $script:Tmp
        $r.JsonPath | Should -Not -BeNullOrEmpty
    }
}
