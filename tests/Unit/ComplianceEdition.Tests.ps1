#requires -Modules Pester
BeforeAll {
    . (Join-Path $PSScriptRoot '_TestHelpers.ps1')
    $script:SrcRoot = Get-HardenTestSrcRoot
    Import-Module (Join-Path $script:SrcRoot 'Kritical.PS.Hardening.psm1') -Force
    $script:Cis24 = 'finding_list_cis_microsoft_windows_11_enterprise_24h2_machine'
    $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('krit-harden-ed-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Tmp | Out-Null
}
AfterAll { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }

Describe 'Resolve-KriticalHardenEditionStatus + enrichment' {
    BeforeAll {
        $script:Rules = InModuleScope Kritical.PS.Hardening { Get-KriticalHardenEditionRule }
        $script:Data  = InModuleScope Kritical.PS.Hardening { Get-KriticalHardenMappingData }
        function script:New-F($control, $outcome) {
            [pscustomobject]@{ Source = 'HardeningKitty'; Category = 'Administrative Templates: System'; Control = $control; Outcome = $outcome
                Detail = 'd'; Recommendation = 'r'; Severity = 'Medium'; FindingId = '18.9.5.5'; FindingList = $script:Cis24 }
        }
        function script:Enrich($f, $edition) {
            InModuleScope Kritical.PS.Hardening -Parameters @{ F = $f; D = $script:Data; R = $script:Rules; E = $edition } {
                Add-KriticalHardenFindingEnrichment -Finding $F -MappingData $D -EditionRules $R -TargetEdition $E
            }
        }
    }
    It 'an Enterprise-only finding (Credential Guard) FAILING on a Pro target is NOT-APPLICABLE-EDITION and never Fail' {
        $r = Enrich (New-F 'Device Guard: Credential Guard Configuration (Policy)' 'Fail') 'Pro'
        $r.EditionStatus | Should -Be 'NOT-APPLICABLE-EDITION'
        $r.Outcome       | Should -Be 'NotApplicable'
        $r.Outcome       | Should -Not -Be 'Fail'
        $r.RawOutcome    | Should -Be 'Fail'
        $r.EditionRule   | Should -Be 'ED-CREDENTIAL-GUARD'
    }
    It 'the same finding on an Enterprise target stays a real Fail' {
        $r = Enrich (New-F 'Device Guard: Credential Guard Configuration (Policy)' 'Fail') 'Enterprise'
        $r.EditionStatus | Should -Be 'APPLICABLE'
        $r.Outcome       | Should -Be 'Fail'
    }
    It 'a PASSING Enterprise-only finding on Pro is left as Pass (Learn: Pro devices can retain it)' {
        $r = Enrich (New-F 'Device Guard: Credential Guard Configuration (Policy)' 'Pass') 'Pro'
        $r.EditionStatus | Should -Be 'NOT-APPLICABLE-EDITION'
        $r.Outcome       | Should -Be 'Pass'
    }
    It 'a CONTESTED fact (AppLocker on Pro) keeps its label and the Outcome is NOT changed' {
        $r = Enrich (New-F 'AppLocker: Configure rule collection' 'Fail') 'Pro'
        $r.EditionStatus | Should -Be 'CONTESTED'
        $r.Outcome       | Should -Be 'Fail'
        $r.EditionNote   | Should -Match 'contradicts itself'
    }
    It 'an UNKNOWN fact keeps its UNKNOWN label and the Outcome is NOT changed' {
        $rules = [pscustomobject]@{ rules = @([pscustomobject]@{ ruleId = 'ED-TEST-UNKNOWN'; namePatterns = @('*Mystery Feature*'); proStatus = 'UNKNOWN'; note = 'n' }) }
        $f = New-F 'Mystery Feature enablement' 'Fail'
        $r = InModuleScope Kritical.PS.Hardening -Parameters @{ F = $f; D = $script:Data; R = $rules } { Add-KriticalHardenFindingEnrichment -Finding $F -MappingData $D -EditionRules $R -TargetEdition 'Pro' }
        $r.EditionStatus | Should -Be 'UNKNOWN'
        $r.Outcome       | Should -Be 'Fail'
    }
    It 'an unrecognised proStatus is treated as UNKNOWN, never as applicable or not-applicable' {
        $rules = [pscustomobject]@{ rules = @([pscustomobject]@{ ruleId = 'ED-TEST-ODD'; namePatterns = @('*Odd Feature*'); proStatus = 'MAYBE'; note = 'n' }) }
        $f = New-F 'Odd Feature' 'Fail'
        $r = InModuleScope Kritical.PS.Hardening -Parameters @{ F = $f; D = $script:Data; R = $rules } { Add-KriticalHardenFindingEnrichment -Finding $F -MappingData $D -EditionRules $R -TargetEdition 'Pro' }
        $r.EditionStatus | Should -Be 'UNKNOWN'
        $r.Outcome       | Should -Be 'Fail'
    }
    It 'a finding with no edition fact on a Pro target is UNASSESSED and stays Fail' {
        $r = Enrich (New-F 'Account lockout threshold' 'Fail') 'Pro'
        $r.EditionStatus | Should -Be 'UNASSESSED'
        $r.Outcome       | Should -Be 'Fail'
    }
    It 'without -TargetEdition nothing is relabelled (backward compatible) and EditionStatus is NOT-EVALUATED' {
        $r = Enrich (New-F 'Device Guard: Credential Guard Configuration (Policy)' 'Fail') $null
        $r.EditionStatus | Should -Be 'NOT-EVALUATED'
        $r.Outcome       | Should -Be 'Fail'
    }
    It 'the Learn-sourced rules each cite evidence and a basis' {
        foreach ($rule in $script:Rules.rules) {
            $rule.evidenceUrl | Should -Match '^https://learn\.microsoft\.com/'
            $rule.basis       | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Test-KriticalHardenCompliance end to end (HardeningKitty + HotCakeX mocked)' {
    BeforeAll {
        $realHeader = 'ID,Category,Name,Severity,Result,Recommended,TestResult,SeverityFinding,DefaultValue,Filter'
        $script:RealCsvLines = @(
            $realHeader
            '18.9.5.5,"Administrative Templates: System","Device Guard: Credential Guard Configuration (Policy)",Medium,,1,Failed,Medium,,L1'
            '1.2.2,"Account Policies","Account lockout threshold",Low,5,5,Passed,Low,,L1'
            '1.1.1,"Account Policies","Length of password history maintained",Low,0,24,Failed,Low,,L1'
            '99.9.9,"Administrative Templates: Windows Components","AppLocker: Configure rule collection",Medium,0,1,Failed,Medium,,L1'
        )
        $script:ListFile = "hardeningkitty_report_stacktrace_${script:Cis24}-20261008-120000.csv"

        # Pester copies a cmdlet's parameter types into its mock, so a fake job object cannot be passed to a
        # mocked Wait-Job. Permissive global stubs (functions beat cmdlets in command resolution) get mocked instead.
        function global:Start-Job   { [CmdletBinding()] param($ScriptBlock, $ArgumentList) $null = $PSBoundParameters }
        function global:Wait-Job    { [CmdletBinding()] param($Job, $Timeout) $null = $PSBoundParameters }
        function global:Receive-Job { [CmdletBinding()] param($Job) $null = $PSBoundParameters }
        function global:Remove-Job  { [CmdletBinding()] param($Job, [switch] $Force) $null = $PSBoundParameters }
        function global:Stop-Job    { [CmdletBinding()] param($Job) $null = $PSBoundParameters }
    }
    AfterAll {
        foreach ($n in 'Start-Job', 'Wait-Job', 'Receive-Job', 'Remove-Job', 'Stop-Job') { Remove-Item "Function:\global:$n" -ErrorAction SilentlyContinue }
    }
    BeforeEach {
        $script:Work = Join-Path $script:Tmp ('w-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Work | Out-Null
        Push-Location -LiteralPath $script:Work
        Mock -ModuleName Kritical.PS.Hardening Get-Module { [pscustomobject]@{ Name = 'HardeningKitty'; Version = [version]'0.9.4' } } -ParameterFilter { $ListAvailable -and $Name -eq 'HardeningKitty' }
        Mock -ModuleName Kritical.PS.Hardening Import-Module { } -ParameterFilter { $Name -eq 'HardeningKitty' }
        Mock -ModuleName Kritical.PS.Hardening Get-Command { [pscustomobject]@{ Name = 'Invoke-HardeningKitty' } } -ParameterFilter { $Name -eq 'Invoke-HardeningKitty' }
        Mock -ModuleName Kritical.PS.Hardening Start-Job { [pscustomobject]@{ Id = 1 } }
        Mock -ModuleName Kritical.PS.Hardening Wait-Job { $true }
        Mock -ModuleName Kritical.PS.Hardening Receive-Job { $null }
        Mock -ModuleName Kritical.PS.Hardening Remove-Job { }
        Mock -ModuleName Kritical.PS.Hardening Stop-Job { }
    }
    AfterEach { Pop-Location }

    It 'parses the REAL HardeningKitty report columns: TestResult drives the outcome (not Information)' {
        Set-Content -LiteralPath (Join-Path $script:Work $script:ListFile) -Value $script:RealCsvLines
        $r = Test-KriticalHardenCompliance -SkipHotCakeX -Quiet -NoBanner
        $r.FindingCount | Should -Be 4
        ($r.Findings | Where-Object Control -eq 'Account lockout threshold').Outcome | Should -Be 'Pass'
        ($r.Findings | Where-Object Control -eq 'Length of password history maintained').Outcome | Should -Be 'Fail'
        @($r.Findings | Where-Object Outcome -eq 'Information').Count | Should -Be 0
    }
    It 'still parses the legacy column shape (Result = Passed/Failed, RecommendedValue)' {
        Set-Content -LiteralPath (Join-Path $script:Work $script:ListFile) -Value @(
            'Category,Name,Result,RecommendedValue,Severity'
            '"Account Policies","Account lockout threshold",Passed,5,Low'
            '"Account Policies","Length of password history maintained",Failed,24,Low')
        $r = Test-KriticalHardenCompliance -SkipHotCakeX -Quiet -NoBanner
        $r.FindingCount | Should -Be 2
        @($r.Findings.Outcome | Sort-Object) | Should -Be @('Fail', 'Pass')
        ($r.Findings | Where-Object Outcome -eq 'Fail').Detail | Should -Match 'Failed / Expected=24'
    }
    It 'keeps every legacy field and adds FrameworkIds and EditionStatus' {
        Set-Content -LiteralPath (Join-Path $script:Work $script:ListFile) -Value $script:RealCsvLines
        $r = Test-KriticalHardenCompliance -SkipHotCakeX -Quiet -NoBanner
        $f = $r.Findings | Select-Object -First 1
        foreach ($p in 'Source', 'Category', 'Control', 'Outcome', 'Detail', 'Recommendation', 'Severity') { $f.PSObject.Properties.Name | Should -Contain $p }
        foreach ($p in 'FrameworkIds', 'EditionStatus', 'RawOutcome', 'MappingStatus', 'FindingId', 'FindingList') { $f.PSObject.Properties.Name | Should -Contain $p }
        foreach ($p in 'Timestamp', 'FindingCount', 'ByOutcome', 'SourceSummary', 'Findings', 'Platform') { $r.PSObject.Properties.Name | Should -Contain $p }
        $f.FindingList | Should -Be $script:Cis24
    }
    It 'maps a titled finding and shows UNMAPPED (never a guess) for the rest' {
        Set-Content -LiteralPath (Join-Path $script:Work $script:ListFile) -Value $script:RealCsvLines
        $r = Test-KriticalHardenCompliance -SkipHotCakeX -Quiet -NoBanner
        ($r.Findings | Where-Object Control -eq 'Account lockout threshold').FrameworkIds | Should -Be @('CISWIN11-L1-03')
        ($r.Findings | Where-Object Control -eq 'Length of password history maintained').FrameworkIds | Should -Be @('UNMAPPED')
        ($r.Findings | Where-Object Control -like '*Credential Guard*').FrameworkIds | Should -Be @('UNMAPPED')
        $r.Mapping.DataStatus | Should -Be 'OK'
        $r.Mapping.Mapped   | Should -Be 1
        $r.Mapping.Unmapped | Should -Be 3
    }
    It '-TargetEdition Pro: the Enterprise-only Credential Guard FAIL becomes NOT-APPLICABLE-EDITION, and no Fail is left for it' {
        Set-Content -LiteralPath (Join-Path $script:Work $script:ListFile) -Value $script:RealCsvLines
        $r = Test-KriticalHardenCompliance -SkipHotCakeX -Quiet -NoBanner -TargetEdition Pro
        $cg = $r.Findings | Where-Object Control -like '*Credential Guard*'
        $cg.EditionStatus | Should -Be 'NOT-APPLICABLE-EDITION'
        $cg.Outcome       | Should -Be 'NotApplicable'
        $r.TargetEdition  | Should -Be 'Pro'
        # AppLocker on Pro stays the contested label and stays a Fail.
        $al = $r.Findings | Where-Object Control -like '*AppLocker*'
        $al.EditionStatus | Should -Be 'CONTESTED'
        $al.Outcome       | Should -Be 'Fail'
        # The remaining real Fail is untouched.
        ($r.Findings | Where-Object Control -eq 'Length of password history maintained').Outcome | Should -Be 'Fail'
        ($r.ByOutcome | Where-Object Outcome -eq 'NotApplicable').Count | Should -Be 1
    }
    It '-TargetEdition Enterprise: the same finding is a real Fail' {
        Set-Content -LiteralPath (Join-Path $script:Work $script:ListFile) -Value $script:RealCsvLines
        $r = Test-KriticalHardenCompliance -SkipHotCakeX -Quiet -NoBanner -TargetEdition Enterprise
        ($r.Findings | Where-Object Control -like '*Credential Guard*').Outcome | Should -Be 'Fail'
    }
    It 'no -TargetEdition: nothing is relabelled and every finding is NOT-EVALUATED' {
        Set-Content -LiteralPath (Join-Path $script:Work $script:ListFile) -Value $script:RealCsvLines
        $r = Test-KriticalHardenCompliance -SkipHotCakeX -Quiet -NoBanner
        @($r.Findings | Where-Object EditionStatus -ne 'NOT-EVALUATED').Count | Should -Be 0
        @($r.Findings | Where-Object Outcome -eq 'NotApplicable').Count | Should -Be 0
        $r.TargetEdition | Should -BeNullOrEmpty
    }
    It 'an explicit -HardeningKittyList decides the finding list (default list is not covered -> UNMAPPED)' {
        $odd = 'hardeningkitty_report_stacktrace_finding_list_0x6d69636b_machine-20261008-120000.csv'
        Set-Content -LiteralPath (Join-Path $script:Work $odd) -Value $script:RealCsvLines
        $r = Test-KriticalHardenCompliance -SkipHotCakeX -Quiet -NoBanner
        ($r.Findings | Select-Object -First 1).FindingList | Should -Be 'finding_list_0x6d69636b_machine'
        @($r.Findings | Where-Object MappingStatus -eq 'MAPPED').Count | Should -Be 0
        $r2 = Test-KriticalHardenCompliance -SkipHotCakeX -Quiet -NoBanner -HardeningKittyList "C:\x\lists\$($script:Cis24).csv"
        ($r2.Findings | Select-Object -First 1).FindingList | Should -Be $script:Cis24
    }
    It 'a missing edition rule file with -TargetEdition is an error, not "no edition issues"' {
        Set-Content -LiteralPath (Join-Path $script:Work $script:ListFile) -Value $script:RealCsvLines
        Mock -ModuleName Kritical.PS.Hardening Get-KriticalHardenEditionRule { throw 'Edition rule file not found' }
        { Test-KriticalHardenCompliance -SkipHotCakeX -Quiet -NoBanner -TargetEdition Pro } | Should -Throw '*Edition rule file*'
    }
    It 'reports mapping data trouble loudly and returns every finding UNMAPPED' {
        Set-Content -LiteralPath (Join-Path $script:Work $script:ListFile) -Value $script:RealCsvLines
        Mock -ModuleName Kritical.PS.Hardening Get-KriticalHardenMappingData { [pscustomobject]@{ DataStatus = 'UNAVAILABLE'; Detail = 'gone'; Mapping = $null; ValidIds = $null; CatalogCommit = $null; RuleCount = 0 } }
        $r = Test-KriticalHardenCompliance -SkipHotCakeX -Quiet -NoBanner -WarningAction SilentlyContinue
        $r.Mapping.DataStatus | Should -Be 'UNAVAILABLE'
        @($r.Findings | Where-Object { $_.FrameworkIds -ne 'UNMAPPED' }).Count | Should -Be 0
    }
    It 'parses HotCakeX output (both CSV file names) and maps by category + title' {
        Mock -ModuleName Kritical.PS.Hardening Get-Module { [pscustomobject]@{ Name = 'Harden-Windows-Security-Module'; Version = [version]'0.7.6' } } -ParameterFilter { $ListAvailable -and $Name -eq 'Harden-Windows-Security-Module' }
        Mock -ModuleName Kritical.PS.Hardening Import-Module { } -ParameterFilter { $Name -eq 'Harden-Windows-Security-Module' }
        Mock -ModuleName Kritical.PS.Hardening Get-Command { [pscustomobject]@{ Name = 'Confirm-SystemCompliance' } } -ParameterFilter { $Name -eq 'Confirm-SystemCompliance' }
        Set-Content -LiteralPath (Join-Path $script:Work 'Compliance Check Output 10-08-2026 at 12-00-00.CSV') -Value @(
            'FriendlyName,Compliant,Value,Name,Category,Method'
            'x,True,True,"Enable Windows Firewall for Public profile",WindowsFirewall,Registry'
            'y,False,0,"Credential Guard Configuration - UEFI Lock",DeviceGuard,Registry')
        $r = Test-KriticalHardenCompliance -SkipHardeningKitty -Quiet -NoBanner -TargetEdition Pro
        $r.FindingCount | Should -Be 2
        ($r.Findings | Where-Object Control -like 'Enable Windows Firewall*').FrameworkIds | Should -Be @('CISWIN11-L1-05')
        $cg = $r.Findings | Where-Object Control -like '*Credential Guard*'
        $cg.EditionStatus | Should -Be 'NOT-APPLICABLE-EDITION'
        $cg.Outcome | Should -Be 'NotApplicable'
        $cg.FrameworkIds | Should -Be @('UNMAPPED')
    }
    It 'measured something: both probes skipped yields zero findings and says so (not a pass)' {
        $r = Test-KriticalHardenCompliance -SkipHotCakeX -SkipHardeningKitty -Quiet -NoBanner
        $r.FindingCount | Should -Be 0
        $r.Mapping.Mapped | Should -Be 0
    }
    It 'the report generator still renders the enriched result' {
        Set-Content -LiteralPath (Join-Path $script:Work $script:ListFile) -Value $script:RealCsvLines
        $r = Test-KriticalHardenCompliance -SkipHotCakeX -Quiet -NoBanner -TargetEdition Pro
        $out = New-KriticalHardenReport -ComplianceResult $r -OutDir (Join-Path $script:Work 'rpt') -NoOpen -NoBanner
        Test-Path -LiteralPath $out.JsonPath | Should -BeTrue
        (Get-Content -LiteralPath $out.JsonPath -Raw) | Should -Match 'CISWIN11-L1-03'
    }
}
