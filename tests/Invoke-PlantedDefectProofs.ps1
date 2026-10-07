<#
.SYNOPSIS
    RED-proof harness: plants one defect at a time in a COPY of src and requires the named test to FAIL.

.DESCRIPTION
    A test that has never been seen to fail is decoration. For each mutant this script:
      1. copies src to a temp directory and applies one textual defect (it errors if the text to
         replace is not found, so a stale mutation can never pass silently);
      2. points the Pester suites at that copy (KRIT_HARDEN_SRC) and runs them in a child process;
      3. requires the expected test to be among the FAILED tests.
    It also runs the PRISTINE src first and requires zero failures over a non-trivial test count
    (positive control: a harness that always reports RED would otherwise pass every mutant).

    Output ends with one line starting GREEN or RED. Exit code 0 only on GREEN.
    The repo is never modified; mutants live in %TEMP% and are removed.

.NOTES
    Author: Joshua Finley - Kritical Pty Ltd
    Run:  pwsh -NoProfile -File tests\Invoke-PlantedDefectProofs.ps1
#>
[CmdletBinding()]
param([int] $MinimumPristineTests = 50)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $PSCommandPath
$repo = Split-Path -Parent $here
$srcRoot = Join-Path $repo 'src'
$unit = Join-Path $here 'Unit'

$pesterVersion = (Get-Module Pester -ListAvailable | Where-Object { $_.Version.Major -eq 5 } | Sort-Object Version -Descending | Select-Object -First 1).Version
if (-not $pesterVersion) { throw 'Pester 5.x is required' }

$runner = Join-Path ([IO.Path]::GetTempPath()) ('krit-harden-runner-' + [guid]::NewGuid().ToString('N') + '.ps1')
@'
param([string]$Src, [string]$Out, [string]$Version, [string]$Path)
Import-Module Pester -RequiredVersion $Version
if ($Src) { $env:KRIT_HARDEN_SRC = $Src }
$c = New-PesterConfiguration
$c.Run.Path = @($Path -split ';')
$c.Output.Verbosity = 'None'
$c.Run.PassThru = $true
$r = Invoke-Pester -Configuration $c
$failed = @($r.Failed | ForEach-Object { $_.ExpandedPath })
[pscustomobject]@{ Total = $r.TotalCount; Passed = $r.PassedCount; Failed = $r.FailedCount; FailedNames = $failed } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Out -Encoding utf8
'@ | Set-Content -LiteralPath $runner -Encoding utf8

function Invoke-Suite([string] $Src, [string[]] $Paths) {
    $out = Join-Path ([IO.Path]::GetTempPath()) ('krit-harden-out-' + [guid]::NewGuid().ToString('N') + '.json')
    try {
        & pwsh -NoProfile -File $runner -Src $Src -Out $out -Version $pesterVersion -Path ($Paths -join ';') *> $null
        if (-not (Test-Path -LiteralPath $out)) { throw 'test child process produced no result file (treated as RED)' }
        Get-Content -LiteralPath $out -Raw | ConvertFrom-Json
    } finally { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
}

# file (under src), text to find, replacement, expected failing test-name fragment
$mutants = @(
    @{ Id='M01'; Why='archive hash mismatch is accepted'; File='Private\_UpstreamPins.ps1'; Find='if ($actual -ine $expected) {'; Replace='if ($false) {'; Expect='FAILS CLOSED on a hash mismatch' }
    @{ Id='M02'; Why='HardeningKitty goes back through Install-Module (PSGallery)'; File='Public\Install-KriticalHardenModules.ps1'; Find="`$pin.source -eq 'github-release'"; Replace='$false'; Expect='never through Install-Module' }
    @{ Id='M03'; Why='the HotCakeX version pin is ignored'; File='Public\Install-KriticalHardenModules.ps1'; Find='$im.RequiredVersion = [string]$pin.requiredVersion'; Replace='$null = 1'; Expect='-RequiredVersion from the pin' }
    @{ Id='M04'; Why='an empty pin file is accepted'; File='Private\_UpstreamPins.ps1'; Find='@($pins.tools.PSObject.Properties).Count -eq 0'; Replace='$false'; Expect='zero tools' }
    @{ Id='M05'; Why='Enterprise-only FAIL on Pro is left as Fail'; File='Private\_Findings.ps1'; Find="`$outcome = 'NotApplicable'"; Replace='$outcome = $Finding.Outcome'; Expect='never Fail' }
    @{ Id='M06'; Why='NOT-AVAILABLE on Pro is not labelled NOT-APPLICABLE-EDITION'; File='Private\_Findings.ps1'; Find="'NOT-AVAILABLE' { 'NOT-APPLICABLE-EDITION' }"; Replace="'NOT-AVAILABLE' { 'UNASSESSED' }"; Expect='never Fail' }
    @{ Id='M07'; Why='a PASSING finding is relabelled NotApplicable'; File='Private\_Findings.ps1'; Find="-and `$Finding.Outcome -eq 'Fail') { `$outcome = 'NotApplicable' }"; Replace=") { `$outcome = 'NotApplicable' }"; Expect='PASSING Enterprise-only' }
    @{ Id='M08'; Why='a CONTESTED fact is decided (turned into NOT-APPLICABLE-EDITION)'; File='Private\_Findings.ps1'; Find="'CONTESTED'     { 'CONTESTED' }"; Replace="'CONTESTED'     { 'NOT-APPLICABLE-EDITION' }"; Expect='CONTESTED fact' }
    @{ Id='M09'; Why='an unmapped finding gets a guessed ID'; File='Private\_Findings.ps1'; Find='return (& $unmapped $why)'; Replace="return [pscustomobject]@{ FrameworkIds = @('CISWIN11-L1-12'); MappingStatus = 'MAPPED'; MappingRule = 'guess'; MappingReason = `$null }"; Expect='never a guessed ID' }
    @{ Id='M10'; Why='the finding title guard is dropped (bare ID trusted)'; File='Private\_Findings.ps1'; Find='if (-not (Test-KriticalHardenRuleNameMatch -Match $rule.match -Control $control -Category $category)) { continue }'; Replace='$null = 1'; Expect='does not trust a bare ID' }
    @{ Id='M11'; Why='the catalog-snapshot check is dropped'; File='Private\_Findings.ps1'; Find='if (-not $MappingData.ValidIds.Contains($i)) {'; Replace='if ($false) {'; Expect='not in the catalog snapshot' }
    @{ Id='M12'; Why='unavailable mapping data does not fail closed'; File='Private\_Findings.ps1'; Find="if (`$MappingData.DataStatus -ne 'OK') {"; Replace='if ($false) {'; Expect='FAILS CLOSED when mapping data is unavailable' }
    @{ Id='M13'; Why='HardeningKitty TestResult column ignored (the original parser defect)'; File='Private\_Findings.ps1'; Find="`$verdict     = Get-KriticalHardenRowValue -Row `$Row -Name 'TestResult'"; Replace='$verdict = $null'; Expect='REAL HardeningKitty report columns' }
    @{ Id='M14'; Why='no -TargetEdition silently behaves as Pro'; File='Private\_Findings.ps1'; Find="if (-not `$TargetEdition) { return (& `$res 'NOT-EVALUATED' `$null 'no -TargetEdition given') }"; Replace="if (-not `$TargetEdition) { `$TargetEdition = 'Pro' }"; Expect='without -TargetEdition nothing is relabelled' }
)

# Only suites that load the module through KRIT_HARDEN_SRC can run against a mutant copy (the older suites import the repo src directly and would collide on module name).
$newSuites = @('UpstreamPins', 'FrameworkMapping', 'ComplianceEdition') | ForEach-Object { Join-Path $unit "$_.Tests.ps1" }
$lines = [System.Collections.Generic.List[string]]::new()
$bad = 0
try {
    $pristine = Invoke-Suite -Src $null -Paths @($unit)
    if ($pristine.Total -lt $MinimumPristineTests) { $bad++; $lines.Add("RED  pristine: measured only $($pristine.Total) tests (< $MinimumPristineTests); a harness that measured nothing is not a pass") }
    elseif ($pristine.Failed -ne 0) { $bad++; $lines.Add("RED  pristine: $($pristine.Failed) test(s) fail on the unmodified source: $(@($pristine.FailedNames) -join '; ')") }
    else { $lines.Add("ok   pristine src: $($pristine.Passed)/$($pristine.Total) tests pass (positive control)") }

    foreach ($m in $mutants) {
        $copy = Join-Path ([IO.Path]::GetTempPath()) ('krit-harden-mut-' + $m.Id + '-' + [guid]::NewGuid().ToString('N'))
        try {
            Copy-Item -LiteralPath $srcRoot -Destination $copy -Recurse
            $target = Join-Path $copy $m.File
            $text = [IO.File]::ReadAllText($target)
            if (-not $text.Contains($m.Find)) { $bad++; $lines.Add("RED  $($m.Id): mutation text not found in $($m.File) (stale mutant)"); continue }
            [IO.File]::WriteAllText($target, $text.Replace($m.Find, $m.Replace))
            $res = Invoke-Suite -Src $copy -Paths $newSuites
            $hit = @($res.FailedNames | Where-Object { $_ -like "*$($m.Expect)*" })
            if ($res.Failed -gt 0 -and $hit.Count -gt 0) { $lines.Add("ok   $($m.Id) caught ($($res.Failed) failing): $($m.Why) -> '$($hit[0])'") }
            else { $bad++; $lines.Add("RED  $($m.Id) NOT caught: $($m.Why) (failed=$($res.Failed); expected a failure matching '$($m.Expect)')") }
        } finally { Remove-Item -LiteralPath $copy -Recurse -Force -ErrorAction SilentlyContinue }
    }
} finally { Remove-Item -LiteralPath $runner -Force -ErrorAction SilentlyContinue }

$lines | ForEach-Object { $_ }
if ($bad -eq 0) { "GREEN planted-defect proofs: measured $($mutants.Count) planted defects, $($mutants.Count) caught, pristine $($pristine.Passed)/$($pristine.Total) pass; not measured: defects outside these $($mutants.Count) mutants"; exit 0 }
"RED planted-defect proofs: $bad problem(s) of $($mutants.Count + 1) checks"
exit 1
