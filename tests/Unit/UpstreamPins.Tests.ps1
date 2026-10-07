#requires -Modules Pester
BeforeAll {
    . (Join-Path $PSScriptRoot '_TestHelpers.ps1')
    $script:SrcRoot = Get-HardenTestSrcRoot
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
    Import-Module (Join-Path $script:SrcRoot 'Kritical.PS.Hardening.psm1') -Force
    $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('krit-harden-pins-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Tmp | Out-Null
    $script:Zip = Build-HardenFakeReleaseZip -Directory $script:Tmp
    $script:ZipSha = (Get-FileHash -LiteralPath $script:Zip -Algorithm SHA256).Hash
    $script:BadSha = ('0' * 64)
    # Pester can only mock a command it can resolve. Load PowerShellGet, or stub Install-Module (never called for real).
    Import-Module PowerShellGet -ErrorAction SilentlyContinue 2>$null
    $script:StubbedInstallModule = $false
    if (-not (Get-Command Install-Module -ErrorAction SilentlyContinue)) {
        function global:Install-Module { [CmdletBinding()] param($Name, $Scope, $RequiredVersion, [switch] $Force, [switch] $AllowClobber) $null = $PSBoundParameters }
        $script:StubbedInstallModule = $true
    }
}
AfterAll {
    Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item Env:\KRIT_TEST_FAKEZIP -ErrorAction SilentlyContinue
    Remove-Item Env:\KRIT_TEST_PINS -ErrorAction SilentlyContinue
    if ($script:StubbedInstallModule) { Remove-Item Function:\global:Install-Module -ErrorAction SilentlyContinue }
}

Describe 'Pin data file (src\Data\UpstreamPins.json)' {
    BeforeAll { $script:Pins = Get-Content -LiteralPath (Join-Path $script:SrcRoot 'Data\UpstreamPins.json') -Raw | ConvertFrom-Json }
    It 'pins HardeningKitty to a release tag, a 40-hex commit and a 64-hex SHA-256' {
        $hk = $script:Pins.tools.HardeningKitty
        $hk.source        | Should -Be 'github-release'
        $hk.releaseTag    | Should -Not -BeNullOrEmpty
        $hk.commitSha     | Should -Match '^[0-9a-f]{40}$'
        $hk.archiveSha256 | Should -Match '^[0-9A-Fa-f]{64}$'
        $hk.archiveUrl    | Should -Match '^https://(api\.)?github\.com/scipag/HardeningKitty|^https://api\.github\.com/repos/scipag/HardeningKitty/'
        $hk.moduleVersion | Should -Match '^\d+\.\d+\.\d+'
        $hk.licence.spdx  | Should -Be 'MIT'
    }
    It 'records how each HardeningKitty fact was established' {
        $script:Pins.tools.HardeningKitty.establishedBy.archiveSha256 | Should -Match 'VERIFIED-BY-EXECUTION'
        $script:Pins.tools.HardeningKitty.establishedBy.tag           | Should -Match 'VERIFIED-FROM-API'
    }
    It 'pins HotCakeX Harden-Windows-Security-Module to an exact PSGallery version' {
        $script:Pins.tools.'Harden-Windows-Security-Module'.source          | Should -Be 'psgallery'
        $script:Pins.tools.'Harden-Windows-Security-Module'.requiredVersion | Should -Match '^\d+\.\d+\.\d+'
    }
    It 'THIRD-PARTY-NOTICES.md carries the MIT licence text for both upstream tools' {
        $n = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'THIRD-PARTY-NOTICES.md') -Raw
        $n | Should -Match 'MIT License'
        $n | Should -Match 'scip ag'
        $n | Should -Match 'HotCakeX'
        $n | Should -Match 'Permission is hereby granted, free of charge'
    }
}

Describe 'Get-KriticalHardenUpstreamPin fails closed' {
    It 'throws on a missing file' {
        InModuleScope Kritical.PS.Hardening -Parameters @{ P = (Join-Path $script:Tmp 'nope.json') } {
            { Get-KriticalHardenUpstreamPin -Path $P } | Should -Throw '*not found*'
        }
    }
    It 'throws on malformed JSON' {
        $p = Join-Path $script:Tmp 'bad.json'; Set-Content -LiteralPath $p -Value '{ not json'
        InModuleScope Kritical.PS.Hardening -Parameters @{ P = $p } {
            { Get-KriticalHardenUpstreamPin -Path $P } | Should -Throw '*not valid JSON*'
        }
    }
    It 'throws when the file measured zero tools (an empty pin file is not "no pins needed")' {
        $p = Join-Path $script:Tmp 'empty.json'; Set-Content -LiteralPath $p -Value '{ "schema": "x", "tools": { } }'
        InModuleScope Kritical.PS.Hardening -Parameters @{ P = $p } {
            { Get-KriticalHardenUpstreamPin -Path $P } | Should -Throw '*zero tools*'
        }
    }
    It 'positive control: the shipped pin file loads and holds both tools' {
        InModuleScope Kritical.PS.Hardening {
            $p = Get-KriticalHardenUpstreamPin
            @($p.tools.PSObject.Properties).Count | Should -BeGreaterOrEqual 2
        }
    }
}

Describe 'Install-KriticalHardenGitHubReleaseModule (download mocked)' {
    BeforeEach {
        $env:KRIT_TEST_FAKEZIP = $script:Zip
        Mock -ModuleName Kritical.PS.Hardening Invoke-WebRequest { param($Uri, $OutFile) $null = $Uri; Copy-Item -LiteralPath $env:KRIT_TEST_FAKEZIP -Destination $OutFile }
        $script:Root = Join-Path $script:Tmp ('mods-' + [guid]::NewGuid().ToString('N'))
    }
    It 'installs to root\HardeningKitty\version when the SHA-256 matches the pin' {
        $pin = Build-HardenTestPin -ArchiveSha256 $script:ZipSha
        $r = InModuleScope Kritical.PS.Hardening -Parameters @{ Pin = $pin; Root = $script:Root } { Install-KriticalHardenGitHubReleaseModule -ModuleName HardeningKitty -Pin $Pin -ModulesRoot $Root }
        $r.Status | Should -Be 'INSTALLED'
        $r.Version | Should -Be '0.9.4'
        Test-Path -LiteralPath (Join-Path $script:Root 'HardeningKitty\0.9.4\HardeningKitty.psd1') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:Root 'HardeningKitty\0.9.4\lists\fixture.csv') | Should -BeTrue
        Should -Invoke -ModuleName Kritical.PS.Hardening Invoke-WebRequest -Times 1 -Exactly
    }
    It 'FAILS CLOSED on a hash mismatch: HASH-MISMATCH, nothing extracted, nothing installed' {
        $pin = Build-HardenTestPin -ArchiveSha256 $script:BadSha
        $r = InModuleScope Kritical.PS.Hardening -Parameters @{ Pin = $pin; Root = $script:Root } { Install-KriticalHardenGitHubReleaseModule -ModuleName HardeningKitty -Pin $Pin -ModulesRoot $Root }
        $r.Status | Should -Be 'HASH-MISMATCH'
        $r.ActualSha256 | Should -Be $script:ZipSha
        $r.ExpectedSha256 | Should -Be $script:BadSha
        Test-Path -LiteralPath (Join-Path $script:Root 'HardeningKitty') | Should -BeFalse
    }
    It 'refuses a pin with no valid SHA-256 before any download' {
        $pin = Build-HardenTestPin -ArchiveSha256 'not-a-hash'
        $r = InModuleScope Kritical.PS.Hardening -Parameters @{ Pin = $pin; Root = $script:Root } { Install-KriticalHardenGitHubReleaseModule -ModuleName HardeningKitty -Pin $Pin -ModulesRoot $Root }
        $r.Status | Should -Be 'PIN-INVALID'
        Should -Invoke -ModuleName Kritical.PS.Hardening Invoke-WebRequest -Times 0 -Exactly
    }
    It 'refuses a non-GitHub or non-https archive URL before any download' {
        foreach ($u in 'http://api.github.com/x.zip', 'https://evil.example.com/HardeningKitty.zip') {
            $pin = Build-HardenTestPin -ArchiveSha256 $script:ZipSha -Url $u
            $r = InModuleScope Kritical.PS.Hardening -Parameters @{ Pin = $pin; Root = $script:Root } { Install-KriticalHardenGitHubReleaseModule -ModuleName HardeningKitty -Pin $Pin -ModulesRoot $Root }
            $r.Status | Should -Be 'PIN-INVALID'
        }
        Should -Invoke -ModuleName Kritical.PS.Hardening Invoke-WebRequest -Times 0 -Exactly
    }
    It 'reports DOWNLOAD-FAILED when the download throws' {
        Mock -ModuleName Kritical.PS.Hardening Invoke-WebRequest { throw 'network down' }
        $pin = Build-HardenTestPin -ArchiveSha256 $script:ZipSha
        $r = InModuleScope Kritical.PS.Hardening -Parameters @{ Pin = $pin; Root = $script:Root } { Install-KriticalHardenGitHubReleaseModule -ModuleName HardeningKitty -Pin $Pin -ModulesRoot $Root }
        $r.Status | Should -Be 'DOWNLOAD-FAILED'
        Test-Path -LiteralPath (Join-Path $script:Root 'HardeningKitty') | Should -BeFalse
    }
    It 'reports ARCHIVE-INVALID when the verified archive has no module manifest' {
        $noManifest = Build-HardenFakeReleaseZip -Directory $script:Tmp -NoManifest
        $env:KRIT_TEST_FAKEZIP = $noManifest
        $pin = Build-HardenTestPin -ArchiveSha256 ((Get-FileHash -LiteralPath $noManifest -Algorithm SHA256).Hash)
        $r = InModuleScope Kritical.PS.Hardening -Parameters @{ Pin = $pin; Root = $script:Root } { Install-KriticalHardenGitHubReleaseModule -ModuleName HardeningKitty -Pin $Pin -ModulesRoot $Root }
        $r.Status | Should -Be 'ARCHIVE-INVALID'
        Test-Path -LiteralPath (Join-Path $script:Root 'HardeningKitty') | Should -BeFalse
    }
}

Describe 'Install-KriticalHardenModules uses the pins' {
    BeforeEach {
        $env:KRIT_TEST_FAKEZIP = $script:Zip
        Mock -ModuleName Kritical.PS.Hardening Get-Module { $null } -ParameterFilter { $ListAvailable }
        Mock -ModuleName Kritical.PS.Hardening Install-Module { }
        Mock -ModuleName Kritical.PS.Hardening Invoke-WebRequest { param($Uri, $OutFile) $null = $Uri; Copy-Item -LiteralPath $env:KRIT_TEST_FAKEZIP -Destination $OutFile }
        $script:Root = Join-Path $script:Tmp ('mods-' + [guid]::NewGuid().ToString('N'))
    }
    It 'installs HardeningKitty from the pinned release and never through Install-Module' {
        $pins = [pscustomobject]@{ tools = [pscustomobject]@{
            HardeningKitty = (Build-HardenTestPin -ArchiveSha256 $script:ZipSha)
            'Harden-Windows-Security-Module' = [pscustomobject]@{ source = 'psgallery'; requiredVersion = '0.7.6' } } }
        $env:KRIT_TEST_PINS = ($pins | ConvertTo-Json -Depth 6)
        Mock -ModuleName Kritical.PS.Hardening Get-KriticalHardenUpstreamPin { $env:KRIT_TEST_PINS | ConvertFrom-Json }
        $r = Install-KriticalHardenModules -OnlyCore -Quiet -NoBanner -ModulesRoot $script:Root
        $hk = $r.Modules | Where-Object Module -eq 'HardeningKitty'
        $hk.Status  | Should -Be 'READY'
        $hk.Version | Should -Be '0.9.4'
        $hk.PinMatch | Should -BeTrue
        Should -Invoke -ModuleName Kritical.PS.Hardening Install-Module -Times 0 -Exactly -ParameterFilter { $Name -eq 'HardeningKitty' }
        Should -Invoke -ModuleName Kritical.PS.Hardening Invoke-WebRequest -Times 1 -Exactly
    }
    It 'installs HotCakeX with -RequiredVersion from the pin' {
        $pins = [pscustomobject]@{ tools = [pscustomobject]@{
            HardeningKitty = (Build-HardenTestPin -ArchiveSha256 $script:ZipSha)
            'Harden-Windows-Security-Module' = [pscustomobject]@{ source = 'psgallery'; requiredVersion = '0.7.6' } } }
        $env:KRIT_TEST_PINS = ($pins | ConvertTo-Json -Depth 6)
        Mock -ModuleName Kritical.PS.Hardening Get-KriticalHardenUpstreamPin { $env:KRIT_TEST_PINS | ConvertFrom-Json }
        $null = Install-KriticalHardenModules -OnlyCore -Quiet -NoBanner -ModulesRoot $script:Root
        Should -Invoke -ModuleName Kritical.PS.Hardening Install-Module -Times 1 -Exactly -ParameterFilter { $Name -eq 'Harden-Windows-Security-Module' -and $RequiredVersion -eq '0.7.6' }
    }
    It 'a hash mismatch surfaces as INSTALL-FAILED with HASH-MISMATCH and Ok = false' {
        $pins = [pscustomobject]@{ tools = [pscustomobject]@{
            HardeningKitty = (Build-HardenTestPin -ArchiveSha256 $script:BadSha)
            'Harden-Windows-Security-Module' = [pscustomobject]@{ source = 'psgallery'; requiredVersion = '0.7.6' } } }
        $env:KRIT_TEST_PINS = ($pins | ConvertTo-Json -Depth 6)
        Mock -ModuleName Kritical.PS.Hardening Get-KriticalHardenUpstreamPin { $env:KRIT_TEST_PINS | ConvertFrom-Json }
        $r = Install-KriticalHardenModules -OnlyCore -Quiet -NoBanner -ModulesRoot $script:Root
        $hk = $r.Modules | Where-Object Module -eq 'HardeningKitty'
        $hk.Status | Should -Be 'INSTALL-FAILED'
        $hk.Detail | Should -Match 'HASH-MISMATCH'
        $r.Ok | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $script:Root 'HardeningKitty') | Should -BeFalse
    }
    It '-NoInstall downloads nothing and installs nothing' {
        $r = Install-KriticalHardenModules -OnlyCore -NoInstall -Quiet -NoBanner -ModulesRoot $script:Root
        Should -Invoke -ModuleName Kritical.PS.Hardening Invoke-WebRequest -Times 0 -Exactly
        Should -Invoke -ModuleName Kritical.PS.Hardening Install-Module -Times 0 -Exactly
        ($r.Modules | Where-Object Module -eq 'HardeningKitty').Status | Should -Be 'MISSING'
    }
    It 'refuses to run when the pin file cannot be read (no silent "install latest")' {
        Mock -ModuleName Kritical.PS.Hardening Get-KriticalHardenUpstreamPin { throw 'pin file gone' }
        { Install-KriticalHardenModules -OnlyCore -Quiet -NoBanner } | Should -Throw '*pin file gone*'
        Should -Invoke -ModuleName Kritical.PS.Hardening Install-Module -Times 0 -Exactly
    }
    It 'reports a version that differs from its pin (PinMatch = false) without replacing it' {
        Mock -ModuleName Kritical.PS.Hardening Get-Module { [pscustomobject]@{ Name = 'HardeningKitty'; Version = [version]'0.9.1' } } -ParameterFilter { $ListAvailable -and $Name -eq 'HardeningKitty' }
        $r = Install-KriticalHardenModules -OnlyCore -NoInstall -Quiet -NoBanner
        $hk = $r.Modules | Where-Object Module -eq 'HardeningKitty'
        $hk.Status   | Should -Be 'READY'
        $hk.PinMatch | Should -BeFalse
        $hk.Detail   | Should -Match 'differs from pinned'
    }
}
