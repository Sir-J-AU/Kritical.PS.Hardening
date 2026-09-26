# [PS-MODULE] Kritical.PS.Hardening — README (human)

> Kritical's **Windows security-hardening toolkit** — an audit-first wrapper that stands
> on the shoulders of HotCakeX/Harden-Windows-Security-Module, scipag/HardeningKitty, the
> Microsoft Security Compliance Toolkit, and the DSC AuditPolicy/SecurityPolicy resources.
> One call runs every installed compliance probe and emits a Kritical-branded HTML + Excel
> report. Built on [`Kritical.PS.OmniFramework`](../Kritical.PS.OmniFramework).

| | |
|---|---|
| **Module** | `Kritical.PS.Hardening` |
| **Version** | 1.1.0 |
| **Requires** | PowerShell **5.1+** — `Desktop` **and** `Core` |
| **Public surface** | **10 functions** |
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

## Function map (10 public)

| Function | Does |
|---|---|
| `Test-KriticalHardenPrereqs` | **7-gate prereq check** — OS / PS / admin / Defender / TPM / SecureBoot / WinRM. |
| `Install-KriticalHardenModules` | Wraps `Install-Module` for HotCakeX Harden-Windows-Security-Module + scipag HardeningKitty; **honours the operator's existing module versions** (no forced upgrade). |
| `Get-KriticalHardenModuleStatus` | Reports which underlying hardening tools/modules are installed and at what version. |
| `Test-KriticalHardenCompliance` | Runs **every installed audit tool**, normalises findings into a single `PSCustomObject` set + JSON. |
| `New-KriticalHardenReport` | Kritical-branded **HTML + Excel** report via OmniFramework. |
| `Get-KriticalHardenBanner` | Canonical Kritical brand banner (hardening-tagged). |
| `Set-KritCredential` | Store a secret (PSCredential or SecureString) under a Name, DPAPI(CurrentUser)-encrypted. |
| `Get-KritCredential` | Retrieve a stored secret as a PSCredential or SecureString. Fails closed. |
| `Remove-KritCredential` | Delete a stored secret. Idempotent. |
| `Get-KritCredentialList` | List stored Names/metadata without decrypting anything. |

### Typical flow

```powershell
Import-Module Kritical.PS.Hardening
Test-KriticalHardenPrereqs                  # 7 gates — bail early if the box can't be assessed
Install-KriticalHardenModules               # ensure HotCakeX + HardeningKitty present (version-respecting)
$findings = Test-KriticalHardenCompliance   # run every probe → normalised object set + JSON
New-KriticalHardenReport -Findings $findings -OutFile .\reports\harden.html
```

## Credential store (reusable, DPAPI-encrypted)

A small, general-purpose secret store, independent of the hardening/reporting functions above.
Any script or service on the box can call it to stop hitting "how do I not hardcode this
password" every time a new unattended task needs a credential.

```powershell
# Store once (interactively, by a human — never by an agent typing a secret into chat)
Set-KritCredential -Name 'w365-portal' -Credential (Get-Credential)
Set-KritCredential -Name 'es-mcp-git-push-pat' -SecureString (Read-Host -AsSecureString 'PAT') -UserName 'es-mcp-system'

# Retrieve later, non-interactively, by the SAME Windows account on the SAME machine
$cred  = Get-KritCredential -Name 'w365-portal'                 # -> PSCredential (UserName was stored)
$token = Get-KritCredential -Name 'es-mcp-git-push-pat'         # -> SecureString (no UserName forced with -AsSecureString)

Get-KritCredentialList                                          # what's stored, no decryption
Remove-KritCredential -Name 'w365-portal' -WhatIf                # idempotent; -WhatIf supported everywhere it writes
```

**How it's protected.** Windows DPAPI
(`System.Security.Cryptography.ProtectedData`, `DataProtectionScope.CurrentUser`) — there is
**no separate AES key** sitting anywhere; the OS-managed, per-user DPAPI master key *is* the
protection, which is deliberate (an AES key stored beside its own ciphertext is not
encryption). Entries live at `%LOCALAPPDATA%\Kritical\CredentialStore\<Name>.kritcred.json` as
`{ name, userName (not secret), protectedBase64 (DPAPI ciphertext), createdUtc, updatedUtc,
createdBy, machine }` — the JSON never contains the plaintext secret. As defence-in-depth on
top of DPAPI, the store folder's NTFS ACL is reset (inheritance broken, inherited ACEs
stripped) and rebuilt with `FullControl` granted **only** to the calling Windows identity plus
the built-in `SYSTEM` principal (`S-1-5-18`) — never `Everyone`, `Users`, or `Authenticated
Users`. `Name` is restricted to `[A-Za-z0-9][A-Za-z0-9_.-]{0,127}` to block path traversal.

**Honest threat model — what this does NOT protect against:**

- **Same-user-same-machine is the whole boundary.** DPAPI `CurrentUser` scope ties the
  decryption key to *that Windows account on that machine*. Any other process running **as
  that same account** — a scheduled task, another script, malware, another interactive
  session — can call `Get-KritCredential` itself and get the plaintext back. This store does
  not, and cannot, distinguish "this legitimate caller" from "anything else running as you."
- **Not portable.** Copy the `.kritcred.json` file to another machine, or a different user
  profile on the same machine, and it is permanently undecryptable there — DPAPI intentionally
  will not unwrap it. That is a confidentiality feature, not a bug, but it means: no
  cross-machine backup/restore of secrets without re-entering them.
- **A local Administrator (or SYSTEM, with sufficient rights) can, with known offline
  techniques, extract another user's DPAPI master key material.** The NTFS ACL lockdown above
  raises the bar (an admin has to go around the file ACL, not just read the file) but does not
  make this impossible for someone who already has that level of access to the box.
- **The plaintext exists briefly in process memory** during `Set-KritCredential` /
  `Get-KritCredential` (an unmanaged buffer, explicitly zeroed and freed immediately after
  use — see `src/Private/_KritCredentialStore.ps1`). A live memory-scraper running as the same
  user during that narrow window is not defended against.
- **DPAPI is Windows-only.** There is no macOS/Linux fallback; this is scoped to the estate's
  Windows boxes, matching the module's existing Windows-only posture.

**Tests** (`tests/Unit/CredentialStore.Tests.ps1`, all synthetic fixture values, isolated to a
temp `%LOCALAPPDATA%` for the run): round-trip for both `PSCredential` and bare `SecureString`;
an absent Name fails closed (errors, returns nothing); the on-disk JSON is grepped for the
plaintext secret and asserted absent; a **planted RED case** — deliberately corrupting the
stored ciphertext — is asserted to fail closed rather than decrypt into a plausible wrong
secret; path-traversal Names are rejected; `-WhatIf` performs no write; `Remove-KritCredential`
is idempotent; and the store directory's ACL is asserted to exclude `Everyone`/`Users`/
`Authenticated Users` and include only the calling identity.

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
