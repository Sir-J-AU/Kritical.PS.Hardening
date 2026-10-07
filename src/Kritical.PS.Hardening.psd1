@{
    RootModule        = 'Kritical.PS.Hardening.psm1'
    ModuleVersion     = '1.2.0'
    GUID              = 'd4e5f6a7-8b9c-4d1e-9f2a-3b4c5d6e7f80'
    Author            = 'Joshua Finley'
    CompanyName       = 'Kritical Pty Ltd'
    Copyright         = '(c) 2026 Kritical Pty Ltd. All rights reserved.'
    Description       = 'Kritical Hardening toolkit. Stands on the shoulders of HotCakeX/Harden-Windows-Security-Module, scipag/HardeningKitty, Microsoft Security Compliance Toolkit, and the DSC AuditPolicy/SecurityPolicy resources. v1.0.0 is audit-only: a single call runs every installed compliance probe and emits a Kritical-branded HTML + Excel report. Apply-side functions (Invoke-KriticalHardenApply / Restore-KriticalHardenSnapshot / Start-KriticalHardenWatcher) ship in v1.1.0 once the snapshot/rollback chain is bulletproof. Built on Kritical.PS.OmniFramework.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop','Core')

    # 1.0.1 — Kritical.PS.OmniFramework moved from RequiredModules to
    # ExternalModuleDependencies (PSData) for the same reason
    # Kritical.PS.OmniFramework 1.0.2 removed its own RequiredModules: PowerShell
    # hard-imports RequiredModules BEFORE the psm1 runs, so any AppDomain
    # collision (stale PSFramework loaded at an older version) cascaded into
    # Kritical.PS.Hardening import failure. Install-Module STILL pulls Kritical.PS.OmniFramework
    # on PSGallery install via ExternalModuleDependencies. Soft-imported at use
    # time by the consuming functions instead.

    FunctionsToExport = @(
        'Test-KriticalHardenPrereqs',
        'Install-KriticalHardenModules',
        'Get-KriticalHardenModuleStatus',
        'Test-KriticalHardenCompliance',
        'New-KriticalHardenReport',
        'Get-KriticalHardenBanner',
        'Set-KritCredential',
        'Get-KritCredential',
        'Remove-KritCredential',
        'Get-KritCredentialList'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('Kritical','Hardening','Security','HotCakeX','HardeningKitty','MicrosoftSecurityComplianceToolkit','LGPO','DSC','CIS','STIG','Windows','MSP','Automation','DPAPI','CredentialStore')
            LicenseUri   = 'https://kritical.net/legal/license'
            ProjectUri   = 'https://github.com/Sir-J-AU/Kritical.PS.Hardening'
            IconUri      = 'https://kritical.net/assets/horizontal_logo.png'
            ExternalModuleDependencies = @('Kritical.PS.OmniFramework')
            ReleaseNotes = @'
1.2.0 - Pins, verified HardeningKitty install, framework IDs, edition awareness (still audit-only).
  * HardeningKitty is NOT on PSGallery: Install-KriticalHardenModules now installs it from a pinned
    scipag/HardeningKitty GitHub release, verifying the archive SHA-256 against src\Data\UpstreamPins.json
    and failing closed on a mismatch. HotCakeX is pinned to an exact PSGallery version.
  * THIRD-PARTY-NOTICES.md added (MIT licences of the upstream tools).
  * Test-KriticalHardenCompliance: findings gain FrameworkIds (or UNMAPPED), MappingStatus, FindingId,
    FindingList, RawOutcome, EditionStatus; new -TargetEdition Pro|Enterprise. Existing fields unchanged.
  * Fixed: HardeningKitty report parsing read non-existent columns (outcome could never be Pass/Fail);
    HotCakeX CSV file-name glob widened.

1.1.0 - Reusable encrypted credential store.
  * Set-KritCredential / Get-KritCredential / Remove-KritCredential / Get-KritCredentialList
    - a per-user, DPAPI(CurrentUser)-encrypted secret store keyed by Name. No separate AES
    key to protect: DPAPI's OS-managed per-user master key IS the protection. Defence-in-
    depth NTFS ACL lockdown on the store folder (current identity + SYSTEM only). Fails
    closed on an absent/corrupted/wrong-account entry rather than ever returning a
    fabricated credential. See README-HUMAN.md ("Credential store") for the full,
    honest threat model.

1.0.1 - Resilience fix (matches Kritical.PS.OmniFramework 1.0.2 pattern).
  * Moved Kritical.PS.OmniFramework out of RequiredModules into
    PSData.ExternalModuleDependencies. PowerShell hard-imports
    RequiredModules BEFORE the consuming module's psm1 runs, so any
    AppDomain collision in a transitive dep (e.g. stale PSFramework)
    used to cascade into Kritical.PS.Hardening import failure.
    Install-Module Kritical.PS.Hardening STILL pulls Kritical.PS.OmniFramework
    transitively from PSGallery via ExternalModuleDependencies.
  * Consuming functions (New-KriticalHardenReport, etc.) soft-import
    Kritical.PS.OmniFramework at use time and degrade gracefully when an
    older version is AppDomain-locked.
  * Recommended: Update-Module Kritical.PS.OmniFramework -Force to land 1.0.2
    in the same step, then restart pwsh.

1.0.0 - Initial release (audit-only).
  * Test-KriticalHardenPrereqs        - 7-gate prereq check (OS / PS / admin / Defender / TPM / SecureBoot / WinRM)
  * Install-KriticalHardenModules     - wraps Install-Module for HotCakeX Harden-Windows-Security-Module + scipag HardeningKitty; honours the operator's existing module versions
  * Test-KriticalHardenCompliance     - runs every installed audit tool, normalises findings into a single PSCustomObject set + JSON
  * New-KriticalHardenReport          - Kritical-branded HTML + Excel via Kritical.PS.OmniFramework (sister module)
  * Pester unit tests, brand discipline, no destructive apply path in this version
  * Stands on Kritical.PS.OmniFramework 1.0.1+
  * Joshua Finley, Kritical Pty Ltd
'@
        }
    }
}
