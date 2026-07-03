# Kritical.PS.Hardening — Kritical Hardening Toolkit (audit-only v1.0.0)

```text
·· × × × ···  SirJ's Deaddrop  ··· × × × ···
      — If you found this, you were meant to —

---------------- A Seriously Kritical™ Production ----------------

                                   [] →
                 (¯`·.¸¸.·´¯)
               .·´            `·.        [] →
               `·.______________.·´
              |   +------------------+   |
              |   |     Kritical™     |  |
              |   |   []      []      |  |
              |   |                  |  |
              |   |   []  []  []     |  |
              |   +------------------+   |
                  (._.·´¯`·.¸_)

                     Your last call.
                   And your first move.

                         ★  ☆  ★

                     +61 1300 274 655
                 sales at kritical dot net

-----------------------------------------------------------------
```

**Author**: Joshua Finley — Kritical Pty Ltd — <https://kritical.net>
**License**: see [LICENSE](./LICENSE)
**Version**: 1.0.0
**Depends on**: [Kritical.PS.OmniFramework](https://www.powershellgallery.com/packages/Kritical.PS.OmniFramework) ≥ 1.0.1

---

## What this is

One PowerShell module that runs every well-known OSS Windows-hardening compliance probe in one call, normalises the findings into a single PSCustomObject set, and emits a Kritical-branded HTML + Excel + JSON report.

### Giants we stand on

| Giant | What we use it for |
| --- | --- |
| **HotCakeX / Harden-Windows-Security-Module** | `Confirm-SystemCompliance` baseline check across Defender / Firewall / SmartScreen / BitLocker / ASR / TLS / UAC / etc. |
| **scipag / HardeningKitty** | `Invoke-HardeningKitty -Mode Audit` — STIG + CIS + Microsoft baseline lists |
| **AuditPolicyDsc / SecurityPolicyDsc / PSDscResources / NetworkingDsc** | DSC-side audit (LSA / Kerberos / user-rights / firewall rules) |
| **PSScriptAnalyzer** | PS-side static analysis for any PowerShell hardening scripts |
| **Kritical.PS.OmniFramework** | Foundation: PSFramework logging + PSSharedGoods + PSWriteHTML + ImportExcel + multi-OS detection + Kritical-branded reports |

### v1.0.0 = audit-only

- ✅ `Test-KriticalHardenPrereqs` — 7-gate prereq check
- ✅ `Install-KriticalHardenModules` — installs HotCakeX + HardeningKitty + DSC family (idempotent)
- ✅ `Get-KriticalHardenModuleStatus` — read-only inventory
- ✅ `Test-KriticalHardenCompliance` — runs every installed audit tool, returns normalised result
- ✅ `New-KriticalHardenReport` — Kritical-branded HTML + Excel + JSON via Kritical.PS.OmniFramework

### v1.1.0 (deferred — destructive apply lands here once snapshot/rollback is bulletproof)

- 🚧 `Invoke-KriticalHardenApply` — gated `-Apply -IUnderstandThisCanBreakProduction`; per-area selection
- 🚧 `Restore-KriticalHardenSnapshot` — rollback to pre-apply registry + secedit + DSC state
- 🚧 `Start-KriticalHardenWatcher` — scheduled-task watcher; re-runs compliance daily/weekly; alerts on drift

---

## Install

### PSGallery

```powershell
Install-Module Kritical.PS.OmniFramework -Scope CurrentUser   # foundation dependency
Install-Module Kritical.PS.Hardening     -Scope CurrentUser
Import-Module  Kritical.PS.Hardening -Force
```

### GitHub release zip

```powershell
gh release download v1.0.0 -R Sir-J-AU/Kritical.PS.Hardening -p '*.zip' -D $env:TEMP --clobber
$psMod = ($env:PSModulePath -split ';' | Where-Object { $_ -match 'Documents\\PowerShell\\Modules$' } | Select-Object -First 1)
$instDir = Join-Path $psMod 'Kritical.PS.Hardening\1.0.0'
Expand-Archive -LiteralPath "$env:TEMP\Kritical.PS.Hardening-1.0.0.zip" -DestinationPath $instDir -Force
Import-Module Kritical.PS.Hardening -Force
```

---

## Quickstart (audit-only)

```powershell
# 1. Verify the machine is ready for a compliance probe (admin / Defender / TPM / SecureBoot / etc.)
Test-KriticalHardenPrereqs

# 2. Install the OSS hardening modules
Install-KriticalHardenModules                # full set: HotCakeX + HardeningKitty + DSC family
Install-KriticalHardenModules -OnlyCore      # smaller: HotCakeX + HardeningKitty only

# 3. Read-only inventory (which giants are installed)
Get-KriticalHardenModuleStatus | Format-Table

# 4. Run every installed audit tool (read-only; takes a few minutes)
$r = Test-KriticalHardenCompliance

# 5. Render Kritical-branded HTML + Excel + JSON report
New-KriticalHardenReport -ComplianceResult $r
```

Output lands at `%LOCALAPPDATA%\Kritical\Kritical.PS.Hardening\reports\<utc>\` with:
- `compliance-report.html` (Kritical-branded; from PSWriteHTML)
- `compliance-report.xlsx` (multi-sheet with Kritical banner sheet; from ImportExcel)
- `compliance-result.json` (raw findings for any downstream consumer)

---

## Exported functions

| Function | Purpose |
| --- | --- |
| `Test-KriticalHardenPrereqs` | 7-gate prereq probe (P1 Windows / P2 PSVersion ≥ 7.4 / P3 Admin / P4 Defender / P5 TPM / P6 SecureBoot / P7 WinRM) |
| `Get-KriticalHardenModuleStatus` | Read-only: which OSS hardening modules are installed + loaded |
| `Install-KriticalHardenModules` | Idempotent installer for HotCakeX + HardeningKitty + DSC family + PSScriptAnalyzer; `-OnlyCore` / `-NoInstall` |
| `Test-KriticalHardenCompliance` | Runs every installed probe (HotCakeX `Confirm-SystemCompliance` + HardeningKitty `Invoke-HardeningKitty -Mode Audit`); normalises findings into a single PSCustomObject set with `Source / Category / Control / Outcome / Detail / Recommendation / Severity` |
| `New-KriticalHardenReport` | Renders HTML + Excel + JSON via Kritical.PS.OmniFramework; falls back to minimal-HTML / JSON-only when OmniFramework not loaded |
| `Get-KriticalHardenBanner` | Brand banner reader (prefers Kritical.PS.OmniFramework's Get-KritBanner) |

---

## Tests

```powershell
cd "$env:USERPROFILE\OneDrive - Kritical Pty Ltd\Github\Kritical.PS.Hardening"
.\tests\Invoke-AllTests.ps1
```

16 Pester unit tests across Banner / Manifest / Modules / Prereqs / Report. Test artefacts to `%LOCALAPPDATA%\Kritical\Kritical.PS.Hardening\test-output\` (out of repo).

---

## Brand discipline

- Every published source file scanned for AI-agent strings (Claude / Hermes / Codex / Copilot / ChatGPT / Anthropic / OpenAI); Pester `Manifest.Tests.ps1` blocks the publish if any leak.
- Canonical Kritical banner verbatim from `Kritical-Branding\public\KriticalLogo.txt` (with bundled fallback).
- Author = Joshua Finley, Company = Kritical Pty Ltd, every manifest, every report.

---

## Related Kritical packages

- [`Kritical.PS.OmniFramework`](https://github.com/Sir-J-AU/Kritical.PS.OmniFramework) — foundation (this module's required dependency)
- [`Kritical.Pax8Mcp`](https://github.com/Sir-J-AU/Kritical.Pax8Mcp) — multi-agent Pax8 MCP wiring for Claude Code / Codex / Cursor / VS Code

---

## Support

- Hotline: +61 1300 274 655
- Email: sales at kritical dot net
- Web: <https://kritical.net>
