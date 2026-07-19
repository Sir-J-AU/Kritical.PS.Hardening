{
  "schema": "kritical-readme-ai/v1",
  "generatedUtc": "2026-07-16",
  "generatedFrom": ["src/Kritical.PS.Hardening.psd1 (incl ReleaseNotes)", "src/Public/*.ps1", "src/Private/_Banner.ps1"],
  "repo": {
    "name": "Kritical.PS.Hardening",
    "version": "1.0.1",
    "guid": "d4e5f6a7-8b9c-4d1e-9f2a-3b4c5d6e7f80",
    "family": "Kritical.PS",
    "author": "Joshua Finley",
    "company": "Kritical Pty Ltd",
    "requiresPowerShell": "5.1",
    "compatibleEditions": ["Desktop", "Core"],
    "posture": "audit-only in v1.0.x — no destructive apply path ships yet",
    "purpose": "Windows security-hardening toolkit: orchestrates + normalises + brand-reports over HotCakeX Harden-Windows-Security-Module, scipag HardeningKitty, MS Security Compliance Toolkit, and DSC AuditPolicy/SecurityPolicy. One call runs every installed compliance probe and emits a Kritical-branded HTML + Excel report.",
    "builtOn": "Kritical.PS.OmniFramework",
    "wrapsExternal": ["HotCakeX/Harden-Windows-Security-Module", "scipag/HardeningKitty", "Microsoft Security Compliance Toolkit", "DSC AuditPolicy/SecurityPolicy"],
    "externalModuleDependencies": ["Kritical.PS.OmniFramework"],
    "tags": ["Kritical", "Hardening", "Security", "HotCakeX", "HardeningKitty", "MicrosoftSecurityComplianceToolkit", "LGPO", "DSC", "CIS", "STIG", "Windows", "MSP", "Automation"]
  },
  "keyDesignDecisions": {
    "auditOnly": {
      "statement": "v1.0.x runs probes and reports only; no machine changes.",
      "deferredToV110": ["Invoke-KriticalHardenApply", "Restore-KriticalHardenSnapshot", "Start-KriticalHardenWatcher"],
      "gate": "ships only once snapshot/rollback chain is bulletproof"
    },
    "loadOrderFix": {
      "statement": "v1.0.1 moved Kritical.PS.OmniFramework out of RequiredModules into ExternalModuleDependencies (mirrors OmniFramework 1.0.2).",
      "why": "PowerShell hard-imports RequiredModules before the psm1 runs; a stale-PSFramework AppDomain collision in a transitive dep cascaded into import failure.",
      "how": "consuming functions soft-import OmniFramework at use time, degrade when older version AppDomain-locked; Install-Module still pulls it transitively."
    }
  },
  "publicApi": [
    { "name": "Test-KriticalHardenPrereqs", "does": "7-gate prereq check: OS / PS / admin / Defender / TPM / SecureBoot / WinRM" },
    { "name": "Install-KriticalHardenModules", "does": "wrap Install-Module for HotCakeX + HardeningKitty, honouring operator's existing versions" },
    { "name": "Get-KriticalHardenModuleStatus", "does": "report which underlying hardening tools/modules installed + versions" },
    { "name": "Test-KriticalHardenCompliance", "does": "run every installed audit tool, normalise findings into single PSCustomObject set + JSON" },
    { "name": "New-KriticalHardenReport", "does": "Kritical-branded HTML + Excel report via OmniFramework" },
    { "name": "Get-KriticalHardenBanner", "does": "canonical Kritical brand banner (hardening-tagged)" }
  ],
  "privateApi": [
    { "name": "_Banner", "file": "src/Private/_Banner.ps1", "role": "banner internals" }
  ],
  "exportCount": 6,
  "publicFileCount": 4,
  "typicalFlow": ["Test-KriticalHardenPrereqs", "Install-KriticalHardenModules", "Test-KriticalHardenCompliance", "New-KriticalHardenReport"],
  "standards": ["CIS", "STIG", "LGPO", "DSC"],
  "roadmap": {
    "v1.1.0": "apply-side (Invoke-KriticalHardenApply / Restore-KriticalHardenSnapshot / Start-KriticalHardenWatcher), gated on bulletproof snapshot/rollback"
  },
  "estateRole": {
    "standsOn": "Kritical.PS.OmniFramework",
    "consumesForReporting": "OmniFramework New-Kritical*Report"
  },
  "testCoverage": {
    "l6Rank": "Tier 1 zero-first-party-test target (security module = worst kind of gap)",
    "firstTargets": ["Test-KriticalHardenPrereqs (7 mockable gates)", "finding-normalisation in Test-KriticalHardenCompliance"],
    "caveat": "repo ships tests/ dir; confirm live Pester before assuming coverage (file-presence != line-coverage)"
  },
  "provenance": {
    "note": "Generated from live manifest (incl release notes) + public source tree. New files only (README-HUMAN.md + README-AI.md); README.md not touched.",
    "lane": "L4 (NIGHT-SHIFT-WORKLIST)",
    "repoOrdinal": "8th repo in L4 sweep; also L6 Tier-1 test-gap target"
  }
}
