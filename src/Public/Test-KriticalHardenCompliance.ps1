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

        Plus an aggregate score per source.

    .PARAMETER MaxProbeSeconds
        Per-probe timeout. Default 300 (5 min).

    .PARAMETER HardeningKittyList
        Which HardeningKitty finding list to apply. Default: 'finding_list_0x6d69636b_machine.csv' (Windows 11 23H2 baseline).
        Pass 'all' to run every shipped list (much longer).

    .EXAMPLE
        Test-KriticalHardenCompliance
        $r = Test-KriticalHardenCompliance -Quiet
        New-KriticalHardenReport -ComplianceResult $r -OutDir C:\drop\harden

    .NOTES
        Author: Joshua Finley - Kritical Pty Ltd
        Audit-only in v1.0.0. Apply path lands in v1.1.0.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [int]    $MaxProbeSeconds = 300,
        [string] $HardeningKittyList,
        [switch] $SkipHotCakeX,
        [switch] $SkipHardeningKitty,
        [switch] $Quiet,
        [switch] $NoBanner
    )
    if (-not $NoBanner.IsPresent -and -not $Quiet.IsPresent) {
        Write-KriticalHardenBanner -Title 'Compliance Probe (audit-only)' -Compact
    }

    $findings = [System.Collections.Generic.List[pscustomobject]]::new()
    $sourceSummary = [System.Collections.Generic.List[pscustomobject]]::new()

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
                        Receive-Job -Job $job | Out-Null
                        # HotCakeX writes a CSV alongside; parse if present
                        $csv = Get-ChildItem -LiteralPath (Get-Location) -Filter 'Compliance-Check-*.csv' -ErrorAction SilentlyContinue |
                               Sort-Object LastWriteTime -Descending | Select-Object -First 1
                        if ($csv) {
                            $rows = Import-Csv -LiteralPath $csv.FullName
                            foreach ($r in $rows) {
                                $findings.Add([pscustomobject]@{
                                    Source         = 'HotCakeX'
                                    Category       = ($r.PSObject.Properties['Category'].Value)
                                    Control        = ($r.PSObject.Properties['Name'].Value)
                                    Outcome        = if ($r.PSObject.Properties['Compliant'].Value -eq 'True') { 'Pass' } else { 'Fail' }
                                    Detail         = ($r.PSObject.Properties['Value'].Value)
                                    Recommendation = ''
                                    Severity       = if ($r.PSObject.Properties['Compliant'].Value -eq 'True') { 'Info' } else { 'Warning' }
                                })
                            }
                            $sourceSummary.Add([pscustomobject]@{ Source='HotCakeX'; Tool=$hc.Name; Version=$hc.Version; Findings=$rows.Count; CsvPath=$csv.FullName })
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
                        Receive-Job -Job $job | Out-Null
                        # HardeningKitty writes a CSV report alongside; parse newest
                        $csv = Get-ChildItem -LiteralPath (Get-Location) -Filter 'hardeningkitty_report_*.csv' -ErrorAction SilentlyContinue |
                               Sort-Object LastWriteTime -Descending | Select-Object -First 1
                        if ($csv) {
                            $rows = Import-Csv -LiteralPath $csv.FullName
                            foreach ($r in $rows) {
                                $outcome = switch (($r.PSObject.Properties['Result'].Value)) {
                                    'Passed'  { 'Pass' }
                                    'Failed'  { 'Fail' }
                                    default   { 'Information' }
                                }
                                $findings.Add([pscustomobject]@{
                                    Source         = 'HardeningKitty'
                                    Category       = ($r.PSObject.Properties['Category'].Value)
                                    Control        = ($r.PSObject.Properties['Name'].Value)
                                    Outcome        = $outcome
                                    Detail         = ($r.PSObject.Properties['Result'].Value) + ' / Expected=' + ($r.PSObject.Properties['RecommendedValue'].Value)
                                    Recommendation = ($r.PSObject.Properties['RecommendedValue'].Value)
                                    Severity       = ($r.PSObject.Properties['Severity'].Value)
                                })
                            }
                            $sourceSummary.Add([pscustomobject]@{ Source='HardeningKitty'; Tool=$hk.Name; Version=$hk.Version; Findings=$rows.Count; CsvPath=$csv.FullName })
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

    # Aggregate
    $byOutcome = $findings | Group-Object Outcome | ForEach-Object {
        [pscustomobject]@{ Outcome=$_.Name; Count=$_.Count }
    }

    $platform = $null
    if (Get-Command Get-KritPlatform -ErrorAction SilentlyContinue) { $platform = Get-KritPlatform }
    $result = [pscustomobject]@{
        Timestamp       = (Get-Date).ToUniversalTime()
        FindingCount    = $findings.Count
        ByOutcome       = @($byOutcome)
        SourceSummary   = @($sourceSummary)
        Findings        = @($findings)
        Platform        = $platform
    }

    if (-not $Quiet.IsPresent) {
        Write-Host ''
        Write-Host "=== Compliance probe complete ===" -ForegroundColor Yellow
        Write-Host ("Findings: $($findings.Count)")
        $byOutcome | Format-Table -AutoSize | Out-String | Write-Host
        $sourceSummary | Format-Table -AutoSize | Out-String | Write-Host
    }
    $result
}
