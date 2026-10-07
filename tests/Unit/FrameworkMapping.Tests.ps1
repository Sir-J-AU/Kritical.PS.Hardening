#requires -Modules Pester
BeforeAll {
    . (Join-Path $PSScriptRoot '_TestHelpers.ps1')
    $script:SrcRoot = Get-HardenTestSrcRoot
    Import-Module (Join-Path $script:SrcRoot 'Kritical.PS.Hardening.psm1') -Force
    $script:Map  = Get-Content -LiteralPath (Join-Path $script:SrcRoot 'Data\FrameworkMapping.json') -Raw | ConvertFrom-Json
    $script:Snap = Get-Content -LiteralPath (Join-Path $script:SrcRoot 'Data\FrameworkRequirementIds.json') -Raw | ConvertFrom-Json
    $script:Cis24 = 'finding_list_cis_microsoft_windows_11_enterprise_24h2_machine'
    $script:Msft25 = 'finding_list_msft_security_baseline_windows_11_25h2_machine'
}

Describe 'Mapping data invariants (data files)' {
    It 'the catalog snapshot is anchored to a commit and holds IDs for every framework' {
        $script:Snap.catalog.commit | Should -Match '^[0-9a-f]{40}$'
        @($script:Snap.frameworks.PSObject.Properties).Count | Should -BeGreaterOrEqual 8
        @($script:Snap.frameworks.'CIS-WIN11-L1'.requirements).Count | Should -Be 16
    }
    It 'every framework ID used by any rule exists, exactly, in the catalog snapshot' {
        $valid = @{}
        foreach ($fw in $script:Snap.frameworks.PSObject.Properties) { foreach ($r in $fw.Value.requirements) { $valid[$r.requirementId] = $true } }
        $valid.Count | Should -BeGreaterThan 100
        $used = @($script:Map.hardeningKittyRules) + @($script:Map.hotCakeXRules) | ForEach-Object { $_.frameworkIds } | Sort-Object -Unique
        @($used).Count | Should -BeGreaterThan 5
        foreach ($u in $used) { $valid.ContainsKey($u) | Should -BeTrue -Because "$u must be a published requirement ID" }
    }
    It 'every rule carries a justification and at least one framework ID' {
        foreach ($r in @($script:Map.hardeningKittyRules) + @($script:Map.hotCakeXRules)) {
            $r.justification | Should -Not -BeNullOrEmpty -Because $r.ruleId
            @($r.frameworkIds).Count | Should -BeGreaterThan 0 -Because $r.ruleId
        }
    }
    It 'every HardeningKitty rule recorded at least one list+ID, and only in scanned lists' {
        $scanned = @($script:Map.hardeningKitty.listsScanned | ForEach-Object { $_.list })
        $scanned.Count | Should -BeGreaterThan 0
        foreach ($r in @($script:Map.hardeningKittyRules)) {
            @($r.ids.PSObject.Properties).Count | Should -BeGreaterThan 0 -Because $r.ruleId
            foreach ($l in $r.ids.PSObject.Properties.Name) { $scanned | Should -Contain $l }
        }
    }
    It 'no AI-agent or placeholder text in the data' {
        (Get-Content -LiteralPath (Join-Path $script:SrcRoot 'Data\FrameworkMapping.json') -Raw) | Should -Not -Match '(?i)\b(TODO|TBD|guess)\b'
    }
}

Describe 'Resolve-KriticalHardenFrameworkId' {
    BeforeAll {
        $script:Data = InModuleScope Kritical.PS.Hardening { Get-KriticalHardenMappingData }
    }
    It 'loads the shipped mapping data (positive control: not vacuous)' {
        $script:Data.DataStatus | Should -Be 'OK'
        $script:Data.RuleCount  | Should -BeGreaterThan 10
    }
    It 'maps a finding whose own title names the requirement topic (lockout threshold -> CISWIN11-L1-03)' {
        $f = [pscustomobject]@{ Source = 'HardeningKitty'; Category = 'Account Policies'; Control = 'Account lockout threshold'; FindingId = '1.2.2'; FindingList = $script:Cis24 }
        $r = InModuleScope Kritical.PS.Hardening -Parameters @{ F = $f; D = $script:Data } { Resolve-KriticalHardenFrameworkId -Finding $F -MappingData $D }
        $r.MappingStatus | Should -Be 'MAPPED'
        $r.FrameworkIds  | Should -Be @('CISWIN11-L1-03')
    }
    It 'maps the same setting on the Microsoft baseline list by its own list ID' {
        $f = [pscustomobject]@{ Source = 'HardeningKitty'; Category = 'Account Policies'; Control = 'Account lockout threshold'; FindingId = '10001'; FindingList = $script:Msft25 }
        $r = InModuleScope Kritical.PS.Hardening -Parameters @{ F = $f; D = $script:Data } { Resolve-KriticalHardenFrameworkId -Finding $F -MappingData $D }
        $r.FrameworkIds | Should -Be @('CISWIN11-L1-03')
    }
    It 'returns both IDs when the title supports two requirement topics (inactivity limit)' {
        $f = [pscustomobject]@{ Source = 'HardeningKitty'; Category = 'Security Options'; Control = 'Interactive logon: Machine inactivity limit'; FindingId = '2.3.7.4'; FindingList = $script:Cis24 }
        $r = InModuleScope Kritical.PS.Hardening -Parameters @{ F = $f; D = $script:Data } { Resolve-KriticalHardenFrameworkId -Finding $F -MappingData $D }
        $r.FrameworkIds | Should -Be @('CISWIN11-L1-07', 'CISV8-4.3')
    }
    It 'an UNMAPPED finding shows UNMAPPED and never a guessed ID (Credential Guard has no requirement topic)' {
        $f = [pscustomobject]@{ Source = 'HardeningKitty'; Category = 'Administrative Templates: System'; Control = 'Device Guard: Credential Guard Configuration (Policy)'; FindingId = '18.9.5.5'; FindingList = $script:Cis24 }
        $r = InModuleScope Kritical.PS.Hardening -Parameters @{ F = $f; D = $script:Data } { Resolve-KriticalHardenFrameworkId -Finding $F -MappingData $D }
        $r.MappingStatus | Should -Be 'UNMAPPED'
        $r.FrameworkIds  | Should -Be @('UNMAPPED')
        $r.MappingReason | Should -Not -BeNullOrEmpty
    }
    It 'is precise: a firewall LOGGING row in the same category as a mapped EnableFirewall row stays UNMAPPED' {
        $on  = [pscustomobject]@{ Source = 'HardeningKitty'; Category = 'Windows Firewall'; Control = 'EnableFirewall (Domain Profile, Policy)'; FindingId = '9.1.1'; FindingList = $script:Cis24 }
        $log = [pscustomobject]@{ Source = 'HardeningKitty'; Category = 'Windows Firewall'; Control = 'Name of log file (Domain Profile, Policy)'; FindingId = '9.1.4'; FindingList = $script:Cis24 }
        $a = InModuleScope Kritical.PS.Hardening -Parameters @{ F = $on;  D = $script:Data } { Resolve-KriticalHardenFrameworkId -Finding $F -MappingData $D }
        $b = InModuleScope Kritical.PS.Hardening -Parameters @{ F = $log; D = $script:Data } { Resolve-KriticalHardenFrameworkId -Finding $F -MappingData $D }
        $a.FrameworkIds | Should -Be @('CISWIN11-L1-05')
        $b.FrameworkIds | Should -Be @('UNMAPPED')
    }
    It 'does not trust a bare ID: the right ID with a different title (renumbered list) is UNMAPPED' {
        $f = [pscustomobject]@{ Source = 'HardeningKitty'; Category = 'Account Policies'; Control = 'Some other setting entirely'; FindingId = '1.2.2'; FindingList = $script:Cis24 }
        $r = InModuleScope Kritical.PS.Hardening -Parameters @{ F = $f; D = $script:Data } { Resolve-KriticalHardenFrameworkId -Finding $F -MappingData $D }
        $r.FrameworkIds | Should -Be @('UNMAPPED')
    }
    It 'a finding list the mapping does not cover is UNMAPPED and says so (HardeningKitty default list)' {
        $f = [pscustomobject]@{ Source = 'HardeningKitty'; Category = 'Account Policies'; Control = 'Account lockout threshold'; FindingId = '1.2.2'; FindingList = 'finding_list_0x6d69636b_machine' }
        $r = InModuleScope Kritical.PS.Hardening -Parameters @{ F = $f; D = $script:Data } { Resolve-KriticalHardenFrameworkId -Finding $F -MappingData $D }
        $r.FrameworkIds  | Should -Be @('UNMAPPED')
        $r.MappingReason | Should -Match 'not covered'
    }
    It 'an unknown finding list or missing finding ID is UNMAPPED' {
        $a = [pscustomobject]@{ Source = 'HardeningKitty'; Category = 'x'; Control = 'Account lockout threshold'; FindingId = '1.2.2'; FindingList = $null }
        $b = [pscustomobject]@{ Source = 'HardeningKitty'; Category = 'x'; Control = 'Account lockout threshold'; FindingId = $null; FindingList = $script:Cis24 }
        foreach ($f in $a, $b) {
            $r = InModuleScope Kritical.PS.Hardening -Parameters @{ F = $f; D = $script:Data } { Resolve-KriticalHardenFrameworkId -Finding $F -MappingData $D }
            $r.FrameworkIds | Should -Be @('UNMAPPED')
        }
    }
    It 'FAILS CLOSED when mapping data is unavailable or empty: every finding is UNMAPPED' {
        $f = [pscustomobject]@{ Source = 'HardeningKitty'; Category = 'Account Policies'; Control = 'Account lockout threshold'; FindingId = '1.2.2'; FindingList = $script:Cis24 }
        foreach ($status in 'UNAVAILABLE', 'EMPTY') {
            $d = [pscustomobject]@{ DataStatus = $status; Detail = 'test'; Mapping = $null; ValidIds = $null; RuleCount = 0 }
            $r = InModuleScope Kritical.PS.Hardening -Parameters @{ F = $f; D = $d } { Resolve-KriticalHardenFrameworkId -Finding $F -MappingData $D }
            $r.FrameworkIds | Should -Be @('UNMAPPED')
        }
    }
    It 'FAILS CLOSED when a rule points at an ID that is not in the catalog snapshot' {
        $f = [pscustomobject]@{ Source = 'HardeningKitty'; Category = 'Account Policies'; Control = 'Account lockout threshold'; FindingId = '1.2.2'; FindingList = $script:Cis24 }
        $r = InModuleScope Kritical.PS.Hardening -Parameters @{ F = $f; D = $script:Data } {
            $rules = $D.Mapping.hardeningKittyRules | ForEach-Object { $_ | ConvertTo-Json -Depth 10 | ConvertFrom-Json }
            ($rules | Where-Object ruleId -eq 'HK-LOCKOUT').frameworkIds = @('CISWIN11-L1-99')
            $bad = [pscustomobject]@{ DataStatus = 'OK'; Detail = $null; RuleCount = 1; CatalogCommit = 'x'; ValidIds = $D.ValidIds
                Mapping = [pscustomobject]@{ hardeningKitty = $D.Mapping.hardeningKitty; hardeningKittyRules = $rules; hotCakeXRules = @() } }
            Resolve-KriticalHardenFrameworkId -Finding $F -MappingData $bad
        }
        $r.FrameworkIds  | Should -Be @('UNMAPPED')
        $r.MappingReason | Should -Match 'not in the catalog'
    }
    It 'maps a HotCakeX finding by category + title, and leaves other HotCakeX findings UNMAPPED' {
        $fw = [pscustomobject]@{ Source = 'HotCakeX'; Category = 'WindowsFirewall'; Control = 'Enable Windows Firewall for Public profile'; FindingId = $null; FindingList = $null }
        $dg = [pscustomobject]@{ Source = 'HotCakeX'; Category = 'DeviceGuard'; Control = 'Credential Guard Configuration - UEFI Lock'; FindingId = $null; FindingList = $null }
        $a = InModuleScope Kritical.PS.Hardening -Parameters @{ F = $fw; D = $script:Data } { Resolve-KriticalHardenFrameworkId -Finding $F -MappingData $D }
        $b = InModuleScope Kritical.PS.Hardening -Parameters @{ F = $dg; D = $script:Data } { Resolve-KriticalHardenFrameworkId -Finding $F -MappingData $D }
        $a.FrameworkIds | Should -Be @('CISWIN11-L1-05')
        $b.FrameworkIds | Should -Be @('UNMAPPED')
    }
    It 'an unknown source is UNMAPPED' {
        $f = [pscustomobject]@{ Source = 'MicrosoftSCT'; Category = 'x'; Control = 'y'; FindingId = $null; FindingList = $null }
        $r = InModuleScope Kritical.PS.Hardening -Parameters @{ F = $f; D = $script:Data } { Resolve-KriticalHardenFrameworkId -Finding $F -MappingData $D }
        $r.FrameworkIds | Should -Be @('UNMAPPED')
    }
}
