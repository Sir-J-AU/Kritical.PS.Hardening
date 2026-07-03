function New-KriticalHardenReport {
    <#
    .SYNOPSIS
        Renders a Kritical-branded HTML + Excel report from a Test-KriticalHardenCompliance
        result. Uses Kritical.PS.OmniFramework's New-KritHtmlReport + New-KritExcelReport.

    .PARAMETER ComplianceResult
        The object returned by Test-KriticalHardenCompliance.

    .PARAMETER OutDir
        Where to drop the two files. Default: %LOCALAPPDATA%\Kritical\Kritical.PS.Hardening\reports\<utc>\

    .EXAMPLE
        $r = Test-KriticalHardenCompliance -Quiet
        New-KriticalHardenReport -ComplianceResult $r

    .EXAMPLE
        Test-KriticalHardenCompliance -Quiet | New-KriticalHardenReport -OutDir C:\drop\harden

    .NOTES
        Author: Joshua Finley - Kritical Pty Ltd
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [pscustomobject] $ComplianceResult,
        [string] $OutDir,
        [switch] $NoOpen,
        [switch] $NoBanner
    )
    if (-not $NoBanner.IsPresent) { Write-KriticalHardenBanner -Title 'Render Compliance Report' -Compact }

    if (-not $OutDir) {
        $utc = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmssZ')
        $OutDir = Join-Path $env:LOCALAPPDATA "Kritical\Kritical.PS.Hardening\reports\$utc"
    }
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

    $htmlOut  = Join-Path $OutDir 'compliance-report.html'
    $xlsxOut  = Join-Path $OutDir 'compliance-report.xlsx'
    $jsonOut  = Join-Path $OutDir 'compliance-result.json'

    # Always emit the JSON regardless of whether OmniFramework is loaded
    $ComplianceResult | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $jsonOut -Encoding UTF8

    $htmlOk = $false
    $xlsxOk = $false
    if (Get-Command New-KritHtmlReport -ErrorAction SilentlyContinue) {
        try {
            New-KritHtmlReport `
                -Title 'Kritical.PS.Hardening - Compliance Probe' `
                -Subtitle ("Captured " + $ComplianceResult.Timestamp + ", " + $ComplianceResult.FindingCount + " findings") `
                -Section @{
                    'Source summary'        = $ComplianceResult.SourceSummary
                    'Outcome counts'        = $ComplianceResult.ByOutcome
                    'All findings'          = $ComplianceResult.Findings
                } `
                -OutFile $htmlOut -NoOpen:$NoOpen | Out-Null
            $htmlOk = $true
        } catch { Write-Warning "HTML report failed: $($_.Exception.Message)" }
    } else {
        Write-Warning 'Kritical.PS.OmniFramework not loaded - HTML report skipped. Import-Module Kritical.PS.OmniFramework first.'
    }

    if (Get-Command New-KritExcelReport -ErrorAction SilentlyContinue) {
        try {
            New-KritExcelReport `
                -Title 'Kritical.PS.Hardening - Compliance Probe' `
                -Sheet @{
                    'SourceSummary' = $ComplianceResult.SourceSummary
                    'OutcomeCounts' = $ComplianceResult.ByOutcome
                    'Findings'      = $ComplianceResult.Findings
                } `
                -OutFile $xlsxOut | Out-Null
            $xlsxOk = $true
        } catch { Write-Warning "Excel report failed: $($_.Exception.Message)" }
    } else {
        Write-Warning 'Kritical.PS.OmniFramework not loaded - Excel report skipped.'
    }

    [pscustomobject]@{
        OutDir   = $OutDir
        JsonPath = $jsonOut
        HtmlPath = if ($htmlOk) { $htmlOut } else { $null }
        XlsxPath = if ($xlsxOk) { $xlsxOut } else { $null }
    }
}
