<#
.SYNOPSIS
    Internal helpers: normalise probe rows, attach framework requirement IDs and edition status.
.NOTES
    Author: Joshua Finley - Kritical Pty Ltd

    Policy (enforced here and by tests):
      * A finding is mapped to a framework requirement ONLY by a rule in src\Data\FrameworkMapping.json.
        No rule, unknown finding list, unreadable mapping data, or a mapped ID that is not in the
        catalog snapshot -> FrameworkIds = @('UNMAPPED') and MappingStatus = 'UNMAPPED'. Never a guess.
      * Edition handling never decides a contested or unknown fact: those labels are carried through
        and the outcome is left exactly as the tool reported it.
#>

Set-StrictMode -Version Latest

function Get-KriticalHardenRowValue {
    [CmdletBinding()]
    param($Row, [Parameter(Mandatory)][string[]] $Name)
    foreach ($n in $Name) {
        $p = $Row.PSObject.Properties[$n]
        if ($p -and $null -ne $p.Value -and "$($p.Value)" -ne '') { return $p.Value }
    }
    $null
}

function ConvertFrom-KriticalHardenHardeningKittyRow {
    <#
    .SYNOPSIS
        One HardeningKitty report row -> normalised finding.
    .DESCRIPTION
        Real report columns (HardeningKitty v.0.9.4): ID, Category, Name, Severity, Result (the
        observed value), Recommended, TestResult (Passed|Failed), SeverityFinding, DefaultValue,
        Filter. Legacy column names (Result as Passed/Failed, RecommendedValue) are still honoured.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] $Row, [string] $ListName)
    $result      = Get-KriticalHardenRowValue -Row $Row -Name 'Result'
    $recommended = Get-KriticalHardenRowValue -Row $Row -Name 'Recommended', 'RecommendedValue'
    $verdict     = Get-KriticalHardenRowValue -Row $Row -Name 'TestResult'
    if (-not $verdict -and $result -in @('Passed', 'Failed')) { $verdict = $result }   # legacy shape
    $outcome = switch ([string]$verdict) {
        'Passed' { 'Pass' }
        'Failed' { 'Fail' }
        default  { 'Information' }
    }
    [pscustomobject]@{
        Source         = 'HardeningKitty'
        Category       = Get-KriticalHardenRowValue -Row $Row -Name 'Category'
        Control        = Get-KriticalHardenRowValue -Row $Row -Name 'Name'
        Outcome        = $outcome
        Detail         = ("{0} / Expected={1}" -f $result, $recommended)
        Recommendation = $recommended
        Severity       = Get-KriticalHardenRowValue -Row $Row -Name 'Severity', 'SeverityFinding'
        FindingId      = Get-KriticalHardenRowValue -Row $Row -Name 'ID'
        FindingList    = $ListName
    }
}

function ConvertFrom-KriticalHardenHotCakeXRow {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] $Row)
    $compliant = Get-KriticalHardenRowValue -Row $Row -Name 'Compliant'
    $ok = ([string]$compliant -eq 'True')
    [pscustomobject]@{
        Source         = 'HotCakeX'
        Category       = Get-KriticalHardenRowValue -Row $Row -Name 'Category'
        Control        = Get-KriticalHardenRowValue -Row $Row -Name 'Name'
        Outcome        = if ($ok) { 'Pass' } else { 'Fail' }
        Detail         = Get-KriticalHardenRowValue -Row $Row -Name 'Value'
        Recommendation = ''
        Severity       = if ($ok) { 'Info' } else { 'Warning' }
        FindingId      = $null
        FindingList    = $null
    }
}

function Get-KriticalHardenHardeningKittyListName {
    <#
    .SYNOPSIS
        The finding list a HardeningKitty run used: the explicit -FileFindingList basename, else the
        name embedded in the report file name (hardeningkitty_report_<host>_<list>-<yyyyMMdd-HHmmss>.csv).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string] $RequestedList, [string] $ReportFileName)
    if ($RequestedList -and $RequestedList -ne 'all') {
        return [System.IO.Path]::GetFileNameWithoutExtension($RequestedList)
    }
    if ($ReportFileName -and $ReportFileName -match '_(finding_list_[A-Za-z0-9_.]+)-\d{8}-\d{6}\.csv$') { return $Matches[1] }
    $null
}

function Get-KriticalHardenMappingData {
    <#
    .SYNOPSIS
        Loads FrameworkMapping.json + the catalog ID snapshot. Never throws: reports DataStatus.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([string] $MappingPath, [string] $SnapshotPath)
    if (-not $MappingPath)  { $MappingPath  = Get-KriticalHardenDataPath -Name 'FrameworkMapping.json' }
    if (-not $SnapshotPath) { $SnapshotPath = Get-KriticalHardenDataPath -Name 'FrameworkRequirementIds.json' }
    $out = [ordered]@{ DataStatus = 'UNAVAILABLE'; Detail = $null; Mapping = $null; ValidIds = $null; CatalogCommit = $null; RuleCount = 0 }
    try {
        if (-not (Test-Path -LiteralPath $MappingPath))  { throw "mapping file not found: $MappingPath" }
        if (-not (Test-Path -LiteralPath $SnapshotPath)) { throw "catalog snapshot not found: $SnapshotPath" }
        $map  = Get-Content -LiteralPath $MappingPath  -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $snap = Get-Content -LiteralPath $SnapshotPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $valid = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        foreach ($fw in $snap.frameworks.PSObject.Properties) { foreach ($r in $fw.Value.requirements) { [void]$valid.Add([string]$r.requirementId) } }
        $count = @($map.hardeningKittyRules).Count + @($map.hotCakeXRules).Count
        $out.Mapping = $map; $out.ValidIds = $valid; $out.RuleCount = $count
        $out.CatalogCommit = [string]$snap.catalog.commit
        if ($valid.Count -eq 0) { $out.DataStatus = 'EMPTY'; $out.Detail = 'catalog snapshot holds zero requirement IDs' }
        elseif ($count -eq 0)   { $out.DataStatus = 'EMPTY'; $out.Detail = 'mapping holds zero rules' }
        else { $out.DataStatus = 'OK' }
    } catch {
        $out.DataStatus = 'UNAVAILABLE'; $out.Detail = $_.Exception.Message
    }
    [pscustomobject]$out
}

function Test-KriticalHardenRuleNameMatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param($Match, [string] $Control, [string] $Category)
    $type = [string]$Match.type
    switch ($type) {
        'name'       { return [bool](@($Match.value) | Where-Object { $Control -ceq [string]$_ }) }
        'namePrefix' { return [bool]($Control -and $Control.StartsWith([string]$Match.value, [System.StringComparison]::Ordinal)) }
        'category'   { return ($Category -ceq [string]$Match.value) }
    }
    $false
}

function Resolve-KriticalHardenFrameworkId {
    <#
    .SYNOPSIS
        FrameworkIds / MappingStatus for one finding. UNMAPPED unless a curated rule justifies it.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] $Finding, [Parameter(Mandatory)] $MappingData)
    $unmapped = {
        param($reason)
        [pscustomobject]@{ FrameworkIds = @('UNMAPPED'); MappingStatus = 'UNMAPPED'; MappingRule = $null; MappingReason = $reason }
    }
    if ($MappingData.DataStatus -ne 'OK') {
        return (& $unmapped ("mapping data {0}: {1}" -f $MappingData.DataStatus, $MappingData.Detail))
    }
    $ids = New-Object 'System.Collections.Generic.List[string]'
    $ruleIds = New-Object 'System.Collections.Generic.List[string]'
    $control = [string]$Finding.Control; $category = [string]$Finding.Category

    if ($Finding.Source -eq 'HardeningKitty') {
        if (-not $Finding.FindingList) { return (& $unmapped 'finding list unknown') }
        if (-not $Finding.FindingId)   { return (& $unmapped 'finding ID missing') }
        $scanned = @($MappingData.Mapping.hardeningKitty.listsScanned | ForEach-Object { $_.list })
        foreach ($rule in @($MappingData.Mapping.hardeningKittyRules)) {
            $listIds = $rule.ids.PSObject.Properties[[string]$Finding.FindingList]
            if (-not $listIds) { continue }
            if (@($listIds.Value) -notcontains [string]$Finding.FindingId) { continue }
            if (-not (Test-KriticalHardenRuleNameMatch -Match $rule.match -Control $control -Category $category)) { continue }
            foreach ($i in @($rule.frameworkIds)) { if (-not $ids.Contains([string]$i)) { $ids.Add([string]$i) } }
            $ruleIds.Add([string]$rule.ruleId)
        }
        if ($ids.Count -eq 0) {
            $why = if ($scanned -notcontains [string]$Finding.FindingList) { "finding list '$($Finding.FindingList)' is not covered by the mapping" } else { 'no mapping rule justifies this finding' }
            return (& $unmapped $why)
        }
    }
    elseif ($Finding.Source -eq 'HotCakeX') {
        $normCat = ($category -replace '\s', '')
        foreach ($rule in @($MappingData.Mapping.hotCakeXRules)) {
            $m = $rule.match
            if (($normCat -ine ([string]$m.category -replace '\s', ''))) { continue }
            if ($m.PSObject.Properties['name'] -and ($control -cne [string]$m.name)) { continue }
            if ($m.PSObject.Properties['namePrefix'] -and -not $control.StartsWith([string]$m.namePrefix, [System.StringComparison]::Ordinal)) { continue }
            foreach ($i in @($rule.frameworkIds)) { if (-not $ids.Contains([string]$i)) { $ids.Add([string]$i) } }
            $ruleIds.Add([string]$rule.ruleId)
        }
        if ($ids.Count -eq 0) { return (& $unmapped 'no mapping rule justifies this finding') }
    }
    else { return (& $unmapped ("no mapping rules for source '{0}'" -f $Finding.Source)) }

    # Fail closed: every mapped ID must exist in the catalog snapshot.
    foreach ($i in $ids) {
        if (-not $MappingData.ValidIds.Contains($i)) { return (& $unmapped "mapped ID '$i' is not in the catalog snapshot") }
    }
    [pscustomobject]@{ FrameworkIds = @($ids); MappingStatus = 'MAPPED'; MappingRule = ($ruleIds -join ','); MappingReason = $null }
}

function Get-KriticalHardenEditionRule {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([string] $Path)
    if (-not $Path) { $Path = Get-KriticalHardenDataPath -Name 'EditionRules.json' }
    if (-not (Test-Path -LiteralPath $Path)) { throw "Edition rule file not found: $Path" }
    try { $j = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Edition rule file is not valid JSON ($Path): $($_.Exception.Message)" }
    if (-not $j.PSObject.Properties['rules']) { throw "Edition rule file has no rules property ($Path)" }
    $j
}

function Resolve-KriticalHardenEditionStatus {
    <#
    .SYNOPSIS
        EditionStatus for one finding against a target edition.
    .OUTPUTS
        EditionStatus: NOT-EVALUATED (no -TargetEdition) | APPLICABLE | NOT-APPLICABLE-EDITION |
        CONTESTED | UNKNOWN | UNASSESSED (Pro target, no rule recorded).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] $Finding, [string] $TargetEdition, $EditionRules)
    $res = { param($s, $r, $n) [pscustomobject]@{ EditionStatus = $s; EditionRule = $r; EditionNote = $n } }
    if (-not $TargetEdition) { return (& $res 'NOT-EVALUATED' $null 'no -TargetEdition given') }
    if ($TargetEdition -eq 'Enterprise') { return (& $res 'APPLICABLE' $null 'target edition is Enterprise') }
    $rank = @{ 'NOT-AVAILABLE' = 4; 'CONTESTED' = 3; 'UNKNOWN' = 2; 'AVAILABLE' = 1 }
    $best = $null
    foreach ($rule in @($EditionRules.rules)) {
        $hit = $false
        foreach ($pat in @($rule.namePatterns)) {
            if (([string]$Finding.Control -like [string]$pat) -or ([string]$Finding.Category -like [string]$pat)) { $hit = $true; break }
        }
        if (-not $hit) { continue }
        $r = $rank[[string]$rule.proStatus]
        if (-not $r) { $r = 2 }   # an unrecognised status is treated as UNKNOWN, never as a pass
        if (-not $best -or $r -gt $best.Rank) { $best = [pscustomobject]@{ Rank = $r; Rule = $rule } }
    }
    if (-not $best) { return (& $res 'UNASSESSED' $null 'no edition fact recorded for this finding') }
    $status = switch ([string]$best.Rule.proStatus) {
        'NOT-AVAILABLE' { 'NOT-APPLICABLE-EDITION' }
        'CONTESTED'     { 'CONTESTED' }
        'AVAILABLE'     { 'APPLICABLE' }
        default         { 'UNKNOWN' }
    }
    & $res $status ([string]$best.Rule.ruleId) ([string]$best.Rule.note)
}

function Add-KriticalHardenFindingEnrichment {
    <#
    .SYNOPSIS
        Adds FrameworkIds, MappingStatus, EditionStatus (and RawOutcome) to a normalised finding.
        Existing fields keep their names and meaning. Outcome changes ONLY when the finding is a
        Fail on a feature the target edition does not have; the tool's own verdict is in RawOutcome.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] $Finding,
        [Parameter(Mandatory)] $MappingData,
        $EditionRules,
        [string] $TargetEdition
    )
    $map = Resolve-KriticalHardenFrameworkId -Finding $Finding -MappingData $MappingData
    $ed  = Resolve-KriticalHardenEditionStatus -Finding $Finding -TargetEdition $TargetEdition -EditionRules $EditionRules
    $outcome = $Finding.Outcome
    if ($ed.EditionStatus -eq 'NOT-APPLICABLE-EDITION' -and $Finding.Outcome -eq 'Fail') { $outcome = 'NotApplicable' }
    [pscustomobject]@{
        Source         = $Finding.Source
        Category       = $Finding.Category
        Control        = $Finding.Control
        Outcome        = $outcome
        Detail         = $Finding.Detail
        Recommendation = $Finding.Recommendation
        Severity       = $Finding.Severity
        FindingId      = $Finding.FindingId
        FindingList    = $Finding.FindingList
        RawOutcome     = $Finding.Outcome
        FrameworkIds   = @($map.FrameworkIds)
        MappingStatus  = $map.MappingStatus
        MappingRule    = $map.MappingRule
        MappingReason  = $map.MappingReason
        EditionStatus  = $ed.EditionStatus
        EditionRule    = $ed.EditionRule
        EditionNote    = $ed.EditionNote
    }
}
