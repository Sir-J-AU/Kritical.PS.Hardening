# Contributing to Kritical.PS.Hardening

```text
·· × × × ···  SirJ's Deaddrop  ··· × × × ···
---------------- A Seriously Kritical™ Production ----------------
```

Author: Joshua Finley — Kritical Pty Ltd — <https://kritical.net>

Outside contributions require a Contributor License Agreement; reach Kritical at +61 1300 274 655 or `sales at kritical dot net` before opening a PR.

## Local dev

- PowerShell 7.4+ required (Pester 5.5+, ImportExcel, PSWriteHTML via Kritical.PS.OmniFramework).
- Install foundation dep first: `Install-Module Kritical.PS.OmniFramework -Scope CurrentUser -Force`
- Install Pester: `Install-Module Pester -MinimumVersion 5.5.0 -Force -SkipPublisherCheck -Scope CurrentUser`

## Code standards

- `Set-StrictMode -Version Latest` at the top of every file.
- Comment-based help on every public function (`.SYNOPSIS`, `.DESCRIPTION`, `.EXAMPLE`, `.NOTES Author: Joshua Finley - Kritical Pty Ltd`).
- Private helpers go in `src/Private/`; public in `src/Public/`; all dot-sourced by the root `.psm1`.
- Every operator-facing path emits the Kritical banner via `Write-KriticalHardenBanner` (which delegates to Kritical.PS.OmniFramework's `Write-KritBanner` when available).
- No `Claude` / `Hermes` / `Codex` / `Copilot` / `ChatGPT` / `Anthropic` / `OpenAI` strings anywhere in published output — the Manifest.Tests.ps1 brand-leak scan blocks the publish if any leak.
- v1.0.0 is audit-only. Destructive `Invoke-KriticalHardenApply` lands in v1.1.0 only after the snapshot/rollback chain is bulletproof.

## Tests

```powershell
.\tests\Invoke-AllTests.ps1
```

Output to `%LOCALAPPDATA%\Kritical\Kritical.PS.Hardening\test-output\`. Exit 0 = all pass.

## Publish

See [docs/PUBLISHING.md](docs/PUBLISHING.md).
