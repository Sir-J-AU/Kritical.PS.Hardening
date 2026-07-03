@{
    RootModule        = 'Kritical.PS.Hardening.psm1'
    ModuleVersion     = '1.0.1'
    GUID              = 'd4e5f6a7-8b9c-4d1e-9f2a-3b4c5d6e7f80'
    Author            = 'Joshua Finley'
    CompanyName       = 'Kritical Pty Ltd'
    Copyright         = '(c) 2026 Kritical Pty Ltd. All rights reserved.'
    Description       = 'Kritical Hardening toolkit. Stands on the shoulders of HotCakeX/Harden-Windows-Security-Module, scipag/HardeningKitty, Microsoft Security Compliance Toolkit, and the DSC AuditPolicy/SecurityPolicy resources. v1.0.0 is audit-only: a single call runs every installed compliance probe and emits a Kritical-branded HTML + Excel report. Apply-side functions (Invoke-KriticalHardenApply / Restore-KriticalHardenSnapshot / Start-KriticalHardenWatcher) ship in v1.1.0 once the snapshot/rollback chain is bulletproof. Built on Krit.OmniFramework.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop','Core')

    # 1.0.1 — Krit.OmniFramework moved from RequiredModules to
    # ExternalModuleDependencies (PSData) for the same reason
    # Krit.OmniFramework 1.0.2 removed its own RequiredModules: PowerShell
    # hard-imports RequiredModules BEFORE the psm1 runs, so any AppDomain
    # collision (stale PSFramework loaded at an older version) cascaded into
    # Kritical.PS.Hardening import failure. Install-Module STILL pulls Krit.OmniFramework
    # on PSGallery install via ExternalModuleDependencies. Soft-imported at use
    # time by the consuming functions instead.

    FunctionsToExport = @(
        'Test-KriticalHardenPrereqs',
        'Install-KriticalHardenModules',
        'Get-KriticalHardenModuleStatus',
        'Test-KriticalHardenCompliance',
        'New-KriticalHardenReport',
        'Get-KriticalHardenBanner'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('Kritical','Hardening','Security','HotCakeX','HardeningKitty','MicrosoftSecurityComplianceToolkit','LGPO','DSC','CIS','STIG','Windows','MSP','Automation')
            LicenseUri   = 'https://kritical.net/legal/license'
            ProjectUri   = 'https://github.com/Sir-J-AU/Kritical.PS.Hardening'
            IconUri      = 'https://kritical.net/assets/horizontal_logo.png'
            ExternalModuleDependencies = @('Krit.OmniFramework')
            ReleaseNotes = @'
1.0.1 - Resilience fix (matches Krit.OmniFramework 1.0.2 pattern).
  * Moved Krit.OmniFramework out of RequiredModules into
    PSData.ExternalModuleDependencies. PowerShell hard-imports
    RequiredModules BEFORE the consuming module's psm1 runs, so any
    AppDomain collision in a transitive dep (e.g. stale PSFramework)
    used to cascade into Kritical.PS.Hardening import failure.
    Install-Module Kritical.PS.Hardening STILL pulls Krit.OmniFramework
    transitively from PSGallery via ExternalModuleDependencies.
  * Consuming functions (New-KriticalHardenReport, etc.) soft-import
    Krit.OmniFramework at use time and degrade gracefully when an
    older version is AppDomain-locked.
  * Recommended: Update-Module Krit.OmniFramework -Force to land 1.0.2
    in the same step, then restart pwsh.

1.0.0 - Initial release (audit-only).
  * Test-KriticalHardenPrereqs        - 7-gate prereq check (OS / PS / admin / Defender / TPM / SecureBoot / WinRM)
  * Install-KriticalHardenModules     - wraps Install-Module for HotCakeX Harden-Windows-Security-Module + scipag HardeningKitty; honours the operator's existing module versions
  * Test-KriticalHardenCompliance     - runs every installed audit tool, normalises findings into a single PSCustomObject set + JSON
  * New-KriticalHardenReport          - Kritical-branded HTML + Excel via Krit.OmniFramework (sister module)
  * Pester unit tests, brand discipline, no destructive apply path in this version
  * Stands on Krit.OmniFramework 1.0.1+
  * Joshua Finley, Kritical Pty Ltd
'@
        }
    }
}
