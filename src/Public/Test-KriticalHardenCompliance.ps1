function Test-KriticalHardenCompliance {
    <#
    .SYNOPSIS
        Runs every installed compliance probe (HotCakeX Confirm-SystemCompliance + scipag
        Invoke-HardeningKitty in Audit mode) and emits a normalised result set.

    .DESCRIPTION
        Audit-only - never mutates system state. Probes run sequentially with timeouts
        so a hung tool doesn't lock up the whole pass. Result rows carry:
          - Source         (HotCakeX | HardeningKitty | MicrosoftSCT | DSC)
          - Category       (Defender / Firewall / SmartScreen / BitLocker / etc.)
          - Control        (specific check name)
          - Outcome        (Pass | Fail | Warning | Information | NotApplicable)
          - Detail         (free-form)
          - Recommendation (short text)
          - Severity       (Critical | Warning | Info)
        added in 1.2.0 (the fields above are unchanged):
          - FindingId      (HardeningKitty finding-list ID; $null for HotCakeX)
          - FindingList    (HardeningKitty finding list the ID belongs to)
          - RawOutcome     (the tool's own verdict, before any edition relabelling)
          - FrameworkIds   (framework requirement IDs from src\Data\FrameworkMapping.json,
                            exactly as published in the Kritical-MSShowcase catalog; the single
                            value 'UNMAPPED' when no curated rule justifies a mapping)
          - MappingStatus  (MAPPED | UNMAPPED), MappingRule, MappingReason
          - EditionStatus  (see -TargetEdition), EditionRule, EditionNote

        Plus an aggregate score per source.

    .PARAMETER MaxProbeSeconds
        Per-probe timeout. Default 300 (5 min).

    .PARAMETER HardeningKittyList
        Which HardeningKitty finding list to apply. When omitted HardeningKitty uses its own default
        list (finding_list_0x6d69636b_machine.csv), which the framework mapping does NOT cover, so those
        findings come back UNMAPPED. Pass the full path of a Windows 11 list (CIS or Microsoft baseline)
        to get framework IDs. Pass 'all' to run every shipped list (much longer).

    .PARAMETER TargetEdition
        Pro | Enterprise. When given, each finding gets an EditionStatus:
          APPLICABLE              - target is Enterprise, or a rule says Pro has the feature
          NOT-APPLICABLE-EDITION  - Microsoft Learn says the feature is not on Pro (for example
                                    Credential Guard). A FAILING finding is relabelled Outcome =
                                    'NotApplicable' (never Fail); RawOutcome keeps the tool's verdict.
                                    A passing finding is left as Pass.
          CONTESTED / UNKNOWN     - the evidence is contested or missing (for example AppLocker on
                                    Pro). The label is carried; the Outcome is NOT changed.
          UNASSESSED              - Pro target and no edition fact recorded for this finding.
        Without -TargetEdition every finding is NOT-EVALUATED and no Outcome is changed.
        The CIS Windows 11 finding lists are the Enterprise benchmark; EES runs Windows 11 Pro.

    .EXAMPLE
        Test-KriticalHardenCompliance
        $r = Test-KriticalHardenCompliance -Quiet -TargetEdition Pro
        New-KriticalHardenReport -ComplianceResult $r -OutDir C:\drop\harden

    .NOTES
        Author: Joshua Finley - Kritical Pty Ltd
        Audit-only. Apply path lands in a later version.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [int]    $MaxProbeSeconds = 300,
        [string] $HardeningKittyList,
        [ValidateSet('Pro', 'Enterprise')]
        [string] $TargetEdition,
        [switch] $SkipHotCakeX,
        [switch] $SkipHardeningKitty,
        [switch] $Quiet,
        [switch] $NoBanner
    )
    if (-not $NoBanner.IsPresent -and -not $Quiet.IsPresent) {
        Write-KriticalHardenBanner -Title 'Compliance Probe (audit-only)' -Compact
    }

    $raw = [System.Collections.Generic.List[pscustomobject]]::new()
    $sourceSummary = [System.Collections.Generic.List[pscustomobject]]::new()
    $pins = $null
    try { $pins = Get-KriticalHardenUpstreamPin } catch { Write-Verbose "pin file unavailable: $($_.Exception.Message)" }

    # ---- Source 1: HotCakeX Confirm-SystemCompliance ----
    if (-not $SkipHotCakeX.IsPresent) {
        $hc = Get-Module -ListAvailable -Name 'Harden-Windows-Security-Module' -ErrorAction SilentlyContinue |
              Sort-Object Version -Descending | Select-Object -First 1
        if ($hc) {
            try {
                Import-Module 'Harden-Windows-Security-Module' -Force -ErrorAction Stop
                if (Get-Command -Name 'Confirm-SystemCompliance' -ErrorAction SilentlyContinue) {
                    if (-not $Quiet.IsPresent) { Write-Host 'Running HotCakeX Confirm-SystemCompliance...' -ForegroundColor DarkCyan }
                    $job = Start-Job -ScriptBlock {
                        Import-Module 'Harden-Windows-Security-Module' -Force
                        Confirm-SystemCompliance -ExportToCSV -DetailedDisplay 2>&1
                    }
                    if (Wait-Job -Job $job -Timeout $MaxProbeSeconds) {
                        # .5231 (lens-hunt): capture job output instead of discarding to Out-Null so
                        # probe warnings/errors survive in the audit trail (surfaced via -Verbose).
                        $jobOutput = Receive-Job -Job $job -ErrorAction SilentlyContinue 2>&1
                        if ($jobOutput) { $jobOutput | ForEach-Object { Write-Verbose "HotCakeX job: $_" } }
                        # HotCakeX writes a CSV alongside; parse if present. Module source (tag 0.7.5.1)
                        # names it "Compliance Check Output <date>.CSV"; older notes said Compliance-Check-*.csv.
                        $csv = Get-ChildItem -LiteralPath (Get-Location) -File -ErrorAction SilentlyContinue |
                               Where-Object { $_.Name -like 'Compliance-Check-*.csv' -or $_.Name -like 'Compliance Check Output*.csv' } |
                               Sort-Object LastWriteTime -Descending | Select-Object -First 1
                        if ($csv) {
                            $rows = @(Import-Csv -LiteralPath $csv.FullName)
                            foreach ($r in $rows) { $raw.Add((ConvertFrom-KriticalHardenHotCakeXRow -Row $r)) }
                            $sourceSummary.Add([pscustomobject]@{ Source='HotCakeX'; Tool=$hc.Name; Version=$hc.Version; Findings=$rows.Count; CsvPath=$csv.FullName; PinnedVersion=(Get-KriticalHardenPinnedVersion -Pins $pins -ModuleName 'Harden-Windows-Security-Module'); PinMatch=([string]$hc.Version -eq [string](Get-KriticalHardenPinnedVersion -Pins $pins -ModuleName 'Harden-Windows-Security-Module')) })
                        } else {
                            $sourceSummary.Add([pscustomobject]@{ Source='HotCakeX'; Tool=$hc.Name; Version=$hc.Version; Findings=0; CsvPath=$null; Note='no CSV emitted' })
                        }
                    } else {
                        Stop-Job -Job $job -ErrorAction SilentlyContinue
                        $sourceSummary.Add([pscustomobject]@{ Source='HotCakeX'; Status='TIMEOUT'; Note="exceeded $MaxProbeSeconds sec" })
                    }
                    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                } else {
                    $sourceSummary.Add([pscustomobject]@{ Source='HotCakeX'; Status='SKIPPED'; Note='Confirm-SystemCompliance not exported by installed module version' })
                }
            } catch {
                $sourceSummary.Add([pscustomobject]@{ Source='HotCakeX'; Status='ERROR'; Note=$_.Exception.Message })
            }
        } else {
            $sourceSummary.Add([pscustomobject]@{ Source='HotCakeX'; Status='NOT-INSTALLED'; Note='Install-KriticalHardenModules to install' })
        }
    }

    # ---- Source 2: scipag/HardeningKitty (Audit mode) ----
    if (-not $SkipHardeningKitty.IsPresent) {
        $hk = Get-Module -ListAvailable -Name 'HardeningKitty' -ErrorAction SilentlyContinue |
              Sort-Object Version -Descending | Select-Object -First 1
        if ($hk) {
            try {
                Import-Module 'HardeningKitty' -Force -ErrorAction Stop
                if (Get-Command -Name 'Invoke-HardeningKitty' -ErrorAction SilentlyContinue) {
                    if (-not $Quiet.IsPresent) { Write-Host 'Running HardeningKitty in Audit mode...' -ForegroundColor DarkCyan }
                    $hkArgs = @{ Mode = 'Audit'; Log = $true; Report = $true }
                    if ($HardeningKittyList) { $hkArgs.FileFindingList = $HardeningKittyList }
                    $job = Start-Job -ArgumentList $hkArgs -ScriptBlock {
                        param($a)
                        Import-Module 'HardeningKitty' -Force
                        Invoke-HardeningKitty @a
                    }
                    if (Wait-Job -Job $job -Timeout $MaxProbeSeconds) {
                        # .5231 (lens-hunt): capture job output instead of discarding to Out-Null so
                        # HardeningKitty warnings/errors survive in the audit trail (surfaced via -Verbose).
                        $jobOutput = Receive-Job -Job $job -ErrorAction SilentlyContinue 2>&1
                        if ($jobOutput) { $jobOutput | ForEach-Object { Write-Verbose "HardeningKitty job: $_" } }
                        # HardeningKitty writes a CSV report alongside; parse newest
                        $csv = Get-ChildItem -LiteralPath (Get-Location) -Filter 'hardeningkitty_report_*.csv' -ErrorAction SilentlyContinue |
                               Sort-Object LastWriteTime -Descending | Select-Object -First 1
                        if ($csv) {
                            $listName = Get-KriticalHardenHardeningKittyListName -RequestedList $HardeningKittyList -ReportFileName $csv.Name
                            $rows = @(Import-Csv -LiteralPath $csv.FullName)
                            foreach ($r in $rows) { $raw.Add((ConvertFrom-KriticalHardenHardeningKittyRow -Row $r -ListName $listName)) }
                            $hkPinned = Get-KriticalHardenPinnedVersion -Pins $pins -ModuleName 'HardeningKitty'
                            $sourceSummary.Add([pscustomobject]@{ Source='HardeningKitty'; Tool=$hk.Name; Version=$hk.Version; Findings=$rows.Count; CsvPath=$csv.FullName; FindingList=$listName; PinnedVersion=$hkPinned; PinMatch=([string]$hk.Version -eq [string]$hkPinned) })
                        } else {
                            $sourceSummary.Add([pscustomobject]@{ Source='HardeningKitty'; Tool=$hk.Name; Version=$hk.Version; Findings=0; CsvPath=$null; Note='no CSV emitted' })
                        }
                    } else {
                        Stop-Job -Job $job -ErrorAction SilentlyContinue
                        $sourceSummary.Add([pscustomobject]@{ Source='HardeningKitty'; Status='TIMEOUT'; Note="exceeded $MaxProbeSeconds sec" })
                    }
                    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                } else {
                    $sourceSummary.Add([pscustomobject]@{ Source='HardeningKitty'; Status='SKIPPED'; Note='Invoke-HardeningKitty not exported by installed version' })
                }
            } catch {
                $sourceSummary.Add([pscustomobject]@{ Source='HardeningKitty'; Status='ERROR'; Note=$_.Exception.Message })
            }
        } else {
            $sourceSummary.Add([pscustomobject]@{ Source='HardeningKitty'; Status='NOT-INSTALLED'; Note='Install-KriticalHardenModules to install' })
        }
    }

    # ---- Enrichment: framework IDs + edition status ----
    $mappingData = Get-KriticalHardenMappingData
    if ($mappingData.DataStatus -ne 'OK') { Write-Warning ("Framework mapping data {0}: {1}. Every finding will be UNMAPPED." -f $mappingData.DataStatus, $mappingData.Detail) }
    $editionRules = $null
    if ($TargetEdition) { $editionRules = Get-KriticalHardenEditionRule }   # throws: a missing rule file must not look like "no edition issues"
    $findings = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($f in $raw) {
        $findings.Add((Add-KriticalHardenFindingEnrichment -Finding $f -MappingData $mappingData -EditionRules $editionRules -TargetEdition $TargetEdition))
    }

    # Aggregate
    $byOutcome = $findings | Group-Object Outcome | ForEach-Object {
        [pscustomobject]@{ Outcome=$_.Name; Count=$_.Count }
    }
    $byEdition = $findings | Group-Object EditionStatus | ForEach-Object {
        [pscustomobject]@{ EditionStatus=$_.Name; Count=$_.Count }
    }
    $mappedCount = @($findings | Where-Object { $_.MappingStatus -eq 'MAPPED' }).Count

    $platform = $null
    if (Get-Command Get-KritPlatform -ErrorAction SilentlyContinue) { $platform = Get-KritPlatform }
    $result = [pscustomobject]@{
        Timestamp       = (Get-Date).ToUniversalTime()
        FindingCount    = $findings.Count
        ByOutcome       = @($byOutcome)
        SourceSummary   = @($sourceSummary)
        Findings        = @($findings)
        Platform        = $platform
        TargetEdition   = $(if ($TargetEdition) { $TargetEdition } else { $null })
        ByEditionStatus = @($byEdition)
        Mapping         = [pscustomobject]@{
            DataStatus    = $mappingData.DataStatus
            RuleCount     = $mappingData.RuleCount
            CatalogCommit = $mappingData.CatalogCommit
            Mapped        = $mappedCount
            Unmapped      = ($findings.Count - $mappedCount)
        }
    }

    if (-not $Quiet.IsPresent) {
        Write-Host ''
        Write-Host "=== Compliance probe complete ===" -ForegroundColor Yellow
        Write-Host ("Findings: $($findings.Count)  (framework-mapped: $mappedCount, unmapped: $($findings.Count - $mappedCount))")
        $byOutcome | Format-Table -AutoSize | Out-String | Write-Host
        $sourceSummary | Format-Table -AutoSize | Out-String | Write-Host
    }
    $result
}
