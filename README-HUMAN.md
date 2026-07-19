# [PS-MODULE] Kritical.PS.Hardening — README (human)

> Kritical's **Windows security-hardening toolkit** — an audit-first wrapper that stands
> on the shoulders of HotCakeX/Harden-Windows-Security-Module, scipag/HardeningKitty, the
> Microsoft Security Compliance Toolkit, and the DSC AuditPolicy/SecurityPolicy resources.
> One call runs every installed compliance probe and emits a Kritical-branded HTML + Excel
> report. Built on [`Kritical.PS.OmniFramework`](../Kritical.PS.OmniFramework).

| | |
|---|---|
| **Module** | `Kritical.PS.Hardening` |
| **Version** | 1.0.1 |
| **Requires** | PowerShell **5.1+** — `Desktop` **and** `Core` |
| **Public surface** | **6 functions** |
| **Posture** | **Audit-only** in v1.0.x — no destructive apply path ships yet |
| **Built on** | `Kritical.PS.OmniFramework` (sister/foundation module) |
| **Wraps** | HotCakeX Harden-Windows-Security-Module · scipag HardeningKitty · MS Security Compliance Toolkit · DSC AuditPolicy/SecurityPolicy |
| **Author** | Joshua Finley · (c) 2026 Kritical Pty Ltd |

---

## Posture: audit-only by design (for now)

**v1.0.x runs probes and reports — it does not change your machine.** That's deliberate:
the apply-side functions (`Invoke-KriticalHardenApply` / `Restore-KriticalHardenSnapshot` /
`Start-KriticalHardenWatcher`) are held for **v1.1.0**, to ship only once the
snapshot/rollback chain is bulletproof. Until then there is **no destructive path** in the
module — a safety choice that fits the estate's "reversible or not at all" discipline.

## The load-order inheritance (same fix as OmniFramework)

v1.0.1 moved `Kritical.PS.OmniFramework` **out of `RequiredModules`** into
`PSData.ExternalModuleDependencies` — the exact pattern OmniFramework 1.0.2 adopted for
itself. PowerShell hard-imports `RequiredModules` *before* the consuming `.psm1` runs, so a
stale PSFramework AppDomain collision in a transitive dep used to cascade into a
`Kritical.PS.Hardening` import failure. Now OmniFramework is **soft-imported at use time**
by the consuming functions (degrading gracefully when an older version is AppDomain-locked),
while `Install-Module` still pulls it transitively from PSGallery.

## Function map (6 public)

| Function | Does |
|---|---|
| `Test-KriticalHardenPrereqs` | **7-gate prereq check** — OS / PS / admin / Defender / TPM / SecureBoot / WinRM. |
| `Install-KriticalHardenModules` | Wraps `Install-Module` for HotCakeX Harden-Windows-Security-Module + scipag HardeningKitty; **honours the operator's existing module versions** (no forced upgrade). |
| `Get-KriticalHardenModuleStatus` | Reports which underlying hardening tools/modules are installed and at what version. |
| `Test-KriticalHardenCompliance` | Runs **every installed audit tool**, normalises findings into a single `PSCustomObject` set + JSON. |
| `New-KriticalHardenReport` | Kritical-branded **HTML + Excel** report via OmniFramework. |
| `Get-KriticalHardenBanner` | Canonical Kritical brand banner (hardening-tagged). |

### Typical flow

```powershell
Import-Module Kritical.PS.Hardening
Test-KriticalHardenPrereqs                  # 7 gates — bail early if the box can't be assessed
Install-KriticalHardenModules               # ensure HotCakeX + HardeningKitty present (version-respecting)
$findings = Test-KriticalHardenCompliance   # run every probe → normalised object set + JSON
New-KriticalHardenReport -Findings $findings -OutFile .\reports\harden.html
```

## Standards / provenance

Findings map to recognised baselines — the tags declare **CIS**, **STIG**, **LGPO**, and
**DSC** lineage. The module is an *orchestrator + normaliser + brand-reporter* over
established community/Microsoft tooling, not a reimplementation of their rulesets.

## Estate role & test-coverage flag

- **Depends on** `Kritical.PS.OmniFramework` (branded reporting, logging, platform detection).
- The **L6 PS-TEST-COVERAGE-MAP flagged this as a Tier-1 zero-first-party-test target** —
  a security module with no tests is the worst kind of gap. First test targets:
  `Test-KriticalHardenPrereqs` (the 7 gates, each mockable) and the finding-normalisation in
  `Test-KriticalHardenCompliance`. *(Note: the repo ships a `tests/` dir; confirm live Pester
  contents before assuming coverage — file-presence ≠ line-coverage.)*

## Repo layout

```
src/Kritical.PS.Hardening.psd1   manifest v1.0.1 (6 exports; OmniFramework in ExternalModuleDependencies)
src/Kritical.PS.Hardening.psm1   loader
src/Public/*.ps1                 4 files → 6 exported functions (banner + module-status grouped)
src/Private/_Banner.ps1          banner internals
src/Assets/kritical-logo.txt     ASCII banner asset
tests/ · tools/ · scripts/ · docs/
Kritical.PS.Hardening-1.0.0.zip / -1.0.1.zip   packaged releases
```

## Roadmap (from release notes)

- **v1.1.0** — apply-side: `Invoke-KriticalHardenApply`, `Restore-KriticalHardenSnapshot`,
  `Start-KriticalHardenWatcher` — gated on a bulletproof snapshot/rollback chain.

## Family relationships

- **Stands on:** `Kritical.PS.OmniFramework` (foundation).
- **Wraps (external):** HotCakeX Harden-Windows-Security-Module, scipag HardeningKitty, MS Security Compliance Toolkit, DSC AuditPolicy/SecurityPolicy.

---

*Companion machine doc: `README-AI.md` (schema `kritical-readme-ai/v1`). Generated from
live manifest (incl. release notes) + public source tree — new file, does not touch `README.md`.*
