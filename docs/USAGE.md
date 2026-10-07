# Kritical.PS.Hardening — Detailed Usage

```text
·· × × × ···  SirJ's Deaddrop  ··· × × × ···
---------------- A Seriously Kritical™ Production ----------------
```

Author: Joshua Finley — Kritical Pty Ltd

Audit-only v1.0.0. Every function below is read-only against the OS; nothing in this module mutates Windows configuration.

---

## Prereq probe

`Test-KriticalHardenPrereqs` runs seven gates and returns a structured result. Use it as a hard gate before running anything else.

```powershell
$r = Test-KriticalHardenPrereqs -Quiet
if (-not $r.Ok) {
    Write-Host "Critical prereqs failed: $($r.CriticalFails)" -ForegroundColor Red
    $r.Gates | Where-Object { -not $_.Pass } | Format-Table
    return
}
```

Gates:

| Gate | Severity | What it checks |
| --- | --- | --- |
| P1 Windows | Critical | OS is Windows (v1.0.0 is Windows-only; macOS + Linux land in v1.1.0) |
| P2 PSVersion | Warning | PowerShell ≥ 7.4 recommended for HotCakeX compatibility |
| P3 Admin | Critical | Process is elevated |
| P4 Defender | Warning | WinDefend service running + signature age ≤ 7 days |
| P5 Tpm | Warning | TPM 2.0 present + ready |
| P6 SecureBoot | Warning | SecureBoot enabled |
| P7 WinRM | Info | Test-WSMan localhost reachable |

---

## Install the OSS giants

```powershell
# Full canonical set
Install-KriticalHardenModules

# Minimal (just HotCakeX + HardeningKitty; skip DSC family)
Install-KriticalHardenModules -OnlyCore

# Report-only (CI prebake; report what's missing without installing)
Install-KriticalHardenModules -NoInstall
```

Status check any time:

```powershell
Get-KriticalHardenModuleStatus | Format-Table
```

Pinned upstreams (1.2.0). The versions are not literals in the code; they live in
`src\Data\UpstreamPins.json`, written by `tools\Update-KriticalHardenUpstreamPins.ps1`:

- **HardeningKitty is not on PSGallery.** The installer downloads the pinned scipag/HardeningKitty
  GitHub release archive, recomputes its SHA-256, and compares it with the recorded hash. A mismatch
  fails closed (`INSTALL-FAILED`, detail `HASH-MISMATCH`): nothing is extracted or installed. On a match it
  is copied to `<user module path>\HardeningKitty\<version>`.
- **HotCakeX Harden-Windows-Security-Module** is installed from PSGallery with `-RequiredVersion` from the pin
  (0.7.6, a frozen artefact: the upstream repository now ships Store apps instead).
- An already-installed module is never replaced. `Get-KriticalHardenModuleStatus` and the installer rows show
  `PinnedVersion` and `PinMatch` so drift is visible.
- Licences are in `THIRD-PARTY-NOTICES.md`. To re-pin, run the tool, review the diff, commit.

---

## Run the compliance probe

```powershell
$r = Test-KriticalHardenCompliance

# Default: runs every installed source, 300-second per-probe timeout
# Skip specific sources:
$r = Test-KriticalHardenCompliance -SkipHotCakeX
$r = Test-KriticalHardenCompliance -SkipHardeningKitty

# Use a specific HardeningKitty finding list:
$r = Test-KriticalHardenCompliance -HardeningKittyList 'finding_list_0x6d69636b_machine.csv'
```

Result shape:

```text
Timestamp     : 2026-06-24 12:34:56Z
FindingCount  : 247
ByOutcome     : @( @{Outcome=Pass; Count=189}, @{Outcome=Fail; Count=42}, @{Outcome=Warning; Count=16} )
SourceSummary : @( @{Source=HotCakeX; Tool=Harden-Windows-Security-Module; Version=...; Findings=87},
                   @{Source=HardeningKitty; Tool=HardeningKitty; Version=...; Findings=160} )
Findings      : @( ...247 PSCustomObjects with Source/Category/Control/Outcome/Detail/Recommendation/Severity )
Platform      : @{Family=Windows; DistroId=windows; Version=10.0.26200; Architecture=Arm64; IsAdmin=True; ...}
```

Framework IDs and edition (1.2.0). Every finding now also carries:

| Field | Meaning |
| --- | --- |
| `FrameworkIds` | Requirement IDs exactly as published in the Kritical-MSShowcase `catalog\framework-mappings\*.json` (for example `CISWIN11-L1-03`). `UNMAPPED` when no curated rule justifies a mapping: never a guess. |
| `MappingStatus` / `MappingRule` / `MappingReason` | `MAPPED` or `UNMAPPED`, the rule that fired, and why a finding is unmapped. |
| `FindingId` / `FindingList` | HardeningKitty finding-list ID and the list it belongs to. |
| `EditionStatus` | See `-TargetEdition` below. |
| `RawOutcome` | The tool's own verdict before any edition relabelling. |

The mapping covers the HardeningKitty Windows 11 CIS (21H2-24H2) and Microsoft baseline (21H2-25H2) machine
lists, plus a handful of HotCakeX categories. HardeningKitty's own default list
(`finding_list_0x6d69636b_machine`) is not covered, so pass `-HardeningKittyList` with a full path to one of the
Windows 11 lists to get framework IDs. Mapping rules and their justifications are in
`src\Data\FrameworkMapping.json` (regenerate with `tools\New-KriticalHardenFrameworkMapping.ps1`).

```powershell
# EES runs Windows 11 Pro; the CIS Windows 11 lists are the Enterprise benchmark.
$r = Test-KriticalHardenCompliance -TargetEdition Pro -HardeningKittyList 'C:\...\lists\finding_list_cis_microsoft_windows_11_enterprise_24h2_machine.csv'
$r.Findings | Where-Object EditionStatus -eq 'NOT-APPLICABLE-EDITION'   # e.g. Credential Guard: not on Pro
```

`-TargetEdition Pro|Enterprise`: `NOT-APPLICABLE-EDITION` is used only where Microsoft Learn says the feature is not
on Pro, and only a failing finding is relabelled (`Outcome = NotApplicable`); a passing one stays `Pass`.
`CONTESTED` (for example AppLocker on Pro, where Learn contradicts itself) and `UNKNOWN` are carried through and the
outcome is not changed. `UNASSESSED` means no edition fact is recorded. Without `-TargetEdition` every finding is
`NOT-EVALUATED` and nothing is relabelled. Rules and evidence URLs: `src\Data\EditionRules.json`.
---

## Render branded report

```powershell
# Default: %LOCALAPPDATA%\Kritical\Kritical.PS.Hardening\reports\<utc>\
New-KriticalHardenReport -ComplianceResult $r

# Custom out:
New-KriticalHardenReport -ComplianceResult $r -OutDir C:\drop\harden-2026-06

# Or pipeline:
Test-KriticalHardenCompliance -Quiet | New-KriticalHardenReport -OutDir C:\drop\harden
```

Output:

- `compliance-report.html` — Kritical-branded via PSWriteHTML (sections: Source summary, Outcome counts, All findings)
- `compliance-report.xlsx` — multi-sheet via ImportExcel (Kritical banner sheet + SourceSummary + OutcomeCounts + Findings)
- `compliance-result.json` — raw findings for any downstream consumer (Power BI / Splunk / ELK / Sentinel)

---

## End-to-end one-shot

```powershell
Import-Module Kritical.PS.OmniFramework -Force
Import-Module Kritical.PS.Hardening -Force
$pre = Test-KriticalHardenPrereqs -Quiet
if (-not $pre.Ok) { throw "Prereqs failed - run elevated PS 7.4+" }
Install-KriticalHardenModules -OnlyCore
$r = Test-KriticalHardenCompliance -SkipHardeningKitty   # HotCakeX-only for speed
$report = New-KriticalHardenReport -ComplianceResult $r
"Report: $($report.OutDir)"
```

---

## References

| # | Title | URL |
| --- | --- | --- |
| 1 | HotCakeX / Harden-Windows-Security | <https://github.com/HotCakeX/Harden-Windows-Security> |
| 2 | scipag / HardeningKitty | <https://github.com/scipag/HardeningKitty> |
| 3 | Microsoft Security Compliance Toolkit | <https://learn.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10> |
| 4 | AuditPolicyDsc | <https://www.powershellgallery.com/packages/AuditPolicyDsc> |
| 5 | SecurityPolicyDsc | <https://www.powershellgallery.com/packages/SecurityPolicyDsc> |
| 6 | PSDscResources | <https://www.powershellgallery.com/packages/PSDscResources> |
| 7 | NetworkingDsc | <https://www.powershellgallery.com/packages/NetworkingDsc> |
| 8 | PSScriptAnalyzer | <https://github.com/PowerShell/PSScriptAnalyzer> |
| 9 | Kritical.PS.OmniFramework (foundation) | <https://github.com/Sir-J-AU/Kritical.PS.OmniFramework> |
