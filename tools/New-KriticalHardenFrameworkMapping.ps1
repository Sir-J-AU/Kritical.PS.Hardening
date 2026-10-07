<#
.SYNOPSIS
    Build-time tool: generates src\Data\FrameworkMapping.json and src\Data\FrameworkRequirementIds.json.

.DESCRIPTION
    Maps HardeningKitty finding-list IDs and HotCakeX categories/titles to framework requirement
    IDs, using the requirement IDs EXACTLY as published in Kritical-MSShowcase
    catalog\framework-mappings\*.json (read-only; pass the path of a checkout).

    THE RULES BELOW ARE CURATED BY HAND AND ARE THE ONLY SOURCE OF MAPPINGS. A finding is mapped
    only when its own title (or, for a category rule, its category title) names the same setting
    family as the requirement's title. Everything else stays UNMAPPED at run time. Never add a
    rule on a hunch: write the justification, and if you cannot, leave the finding unmapped.

    The HardeningKitty IDs are NOT typed by hand: this tool scans the Windows 11 finding lists in
    the PINNED, hash-verified release archive and records every list+ID that satisfies a rule.
    It FAILS CLOSED when a rule matches nothing (a typo would otherwise silently map nothing), when
    a mapped requirement ID is not in the catalog, or when the archive hash does not match the pin.

.PARAMETER ArchivePath   The HardeningKitty release archive (verified against src\Data\UpstreamPins.json).
.PARAMETER CatalogRoot   Directory holding the framework-mappings *.json files (read-only).
.PARAMETER CatalogCommit Commit the catalog was read at (recorded; resolved with git when omitted).

.NOTES
    Author: Joshua Finley - Kritical Pty Ltd
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $ArchivePath,
    [Parameter(Mandatory)][string] $CatalogRoot,
    [string] $CatalogCommit
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repoRoot 'src\Private\_UpstreamPins.ps1')
$pins = Get-KriticalHardenUpstreamPin
$hkPin = $pins.tools.HardeningKitty
$actual = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash
if ($actual -ine $hkPin.archiveSha256) { throw "Archive hash $actual does not match the pinned $($hkPin.archiveSha256); refusing to read finding lists from an unverified archive." }

# ---------------- catalog snapshot (exact IDs) ----------------
$catalog = [ordered]@{}
$validIds = @{}
foreach ($f in Get-ChildItem -LiteralPath $CatalogRoot -Filter '*.json' -File | Sort-Object Name) {
    $j = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json
    if (-not $j.requirements -or @($j.requirements).Count -eq 0) { throw "catalog file $($f.Name) has no requirements" }
    $catalog[$j.framework] = [ordered]@{
        file = $f.Name; frameworkName = $j.frameworkName
        requirements = @($j.requirements | ForEach-Object { [ordered]@{ requirementId = $_.requirementId; shortTitle = $_.shortTitle } })
    }
    foreach ($r in $j.requirements) { $validIds[$r.requirementId] = $f.Name }
}
if (-not $CatalogCommit) { $CatalogCommit = (git -C (Split-Path -Parent (Split-Path -Parent $CatalogRoot)) rev-parse HEAD) }

# ---------------- curated rules ----------------
# type: name (exact title) | namePrefix | category.   Every rule needs a justification.
$hkRules = @(
    @{ id='HK-BITLOCKER'; type='namePrefix'; value='BitLocker Drive Encryption:'; ids=@('CISWIN11-L1-01')
       why='Finding titles are BitLocker Drive Encryption policy settings; requirement title is "BitLocker drive encryption".' }
    @{ id='HK-PWD-LENGTH-COMPLEXITY'; type='name'; value=@('Minimum password length','Password must meet complexity requirements'); ids=@('CISWIN11-L1-02')
       why='Finding titles are the minimum password length and password complexity policies; requirement title is "Password length and complexity".' }
    @{ id='HK-LOCKOUT'; type='name'; value=@('Account lockout duration','Account lockout threshold','Reset account lockout counter','Allow Administrator account lockout'); ids=@('CISWIN11-L1-03')
       why='Finding titles are account lockout policy settings; requirement title is "Account lockout policy".' }
    @{ id='HK-DEFENDER-RTP'; type='namePrefix'; value='Microsoft Defender Antivirus: Real-time Protection:'; ids=@('CISWIN11-L1-04')
       why='Finding titles sit under Microsoft Defender Antivirus Real-time Protection; requirement title is "Defender antivirus real-time protection".' }
    @{ id='HK-FIREWALL-ENABLE'; type='namePrefix'; value='EnableFirewall ('; ids=@('CISWIN11-L1-05')
       why='Finding titles are the per-profile EnableFirewall state; requirement title is "Windows Firewall on for all profiles". Logging, notification and inbound/outbound rows are deliberately NOT mapped.' }
    @{ id='HK-SMARTSCREEN'; type='name'; value=@('File Explorer: Configure Windows Defender SmartScreen','File Explorer: Configure Windows Defender SmartScreen to warn and prevent bypass','Windows Defender SmartScreen: Service Enabled'); ids=@('CISWIN11-L1-06')
       why='Finding titles enable Windows Defender SmartScreen; requirement title is "SmartScreen enabled".' }
    @{ id='HK-SCREEN-LOCK'; type='name'; value=@('Interactive logon: Machine inactivity limit'); ids=@('CISWIN11-L1-07','CISV8-4.3')
       why='Finding title is the machine inactivity (lock) limit; requirement titles are "Screen lock inactivity limit" and "Automatic session locking".' }
    @{ id='HK-UAC'; type='namePrefix'; value='User Account Control:'; ids=@('CISWIN11-L1-08')
       why='Finding titles are User Account Control policy settings; requirement title is "User Account Control enforced".' }
    @{ id='HK-AUTOPLAY'; type='namePrefix'; value='AutoPlay Policies:'; ids=@('CISWIN11-L1-09','CISV8-10.3')
       why='Finding titles are AutoPlay/AutoRun policies; requirement titles are "Autorun/autoplay disabled" and "Disable autorun for removable media".' }
    @{ id='HK-SMB1'; type='name'; value=@('Configure SMB v1 client driver','Configure SMB v1 server'); ids=@('CISWIN11-L1-10')
       why='Finding titles configure SMB v1; requirement title is "SMBv1 disabled".' }
    @{ id='HK-GUEST'; type='name'; value=@('Accounts: Guest account status'); ids=@('CISWIN11-L1-11','CISV8-4.7')
       why='Finding title is the built-in Guest account status; requirement titles are "Guest account disabled" and "Manage default accounts" (Guest is a default account).' }
    @{ id='HK-AUDIT-POLICY'; type='category'; value='Advanced Audit Policy Configuration'; ids=@('CISWIN11-L1-12')
       why='Category title is Advanced Audit Policy Configuration; requirement title is "Security audit policy configured".' }
    @{ id='HK-AUTO-UPDATES'; type='name'; value=@('Windows Update: Manage end user experience: Configure Automatic Updates'); ids=@('CISWIN11-L1-13')
       why='Finding title is Configure Automatic Updates; requirement title is "Automatic Windows updates".' }
    @{ id='HK-RDP-NLA'; type='name'; value=@('Remote Desktop Session Host: Security: Require user authentication for remote connections by using Network Level Authentication'); ids=@('CISWIN11-L1-14')
       why='Finding title requires Network Level Authentication for remote connections; requirement title is "Remote Desktop requires NLA".' }
    @{ id='HK-LLMNR-NETBIOS'; type='name'; value=@('DNS Client: Turn off multicast name resolution (LLMNR)','DNS Client: Configure NetBIOS settings','NetBT NodeType configuration'); ids=@('CISWIN11-L1-15')
       why='Finding titles control LLMNR and NetBIOS name resolution; requirement title is "LLMNR and NetBIOS name resolution disabled".' }
    @{ id='HK-PS-SCRIPTBLOCK'; type='name'; value=@('Windows PowerShell: Turn on PowerShell Script Block Logging','Windows PowerShell: Turn on PowerShell Script Block Logging (Invocation)'); ids=@('CISWIN11-L1-16')
       why='Finding titles turn on PowerShell Script Block Logging; requirement title is "PowerShell script block logging".' }
)
# HotCakeX: Category is the module's ComplianceCategories enum name (read from the module source,
# tag Hardening-Module-v.0.7.5.1; 0.7.6 has no tag, so the 0.7.6 names are UNKNOWN-but-assumed-stable).
$hcRules = @(
    @{ id='HC-FIREWALL-ENABLE'; category='WindowsFirewall'; namePrefix='Enable Windows Firewall for'; ids=@('CISWIN11-L1-05')
       why='Finding titles are "Enable Windows Firewall for <profile> profile"; requirement title is "Windows Firewall on for all profiles".' }
    @{ id='HC-BITLOCKER-OS'; category='BitLockerSettings'; name='Secure OS Drive encryption'; ids=@('CISWIN11-L1-01')
       why='Finding title is OS drive encryption; requirement title is "BitLocker drive encryption".' }
    @{ id='HC-UAC'; category='UserAccountControl'; ids=@('CISWIN11-L1-08')
       why='Category title is User Account Control; requirement title is "User Account Control enforced".' }
    @{ id='HC-AUTO-UPDATES'; category='WindowsUpdateConfigurations'; name='Automatically download updates and install them on maintenance day'; ids=@('CISWIN11-L1-13')
       why='Finding title is automatic update install; requirement title is "Automatic Windows updates".' }
)
foreach ($r in @($hkRules + $hcRules)) { foreach ($i in $r.ids) { if (-not $validIds.ContainsKey($i)) { throw "rule $($r.id) maps to $i which is NOT in the catalog at $CatalogRoot" } } }

# ---------------- scan the pinned archive's finding lists ----------------
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('krit-map-' + [guid]::NewGuid().ToString('N'))
try {
    Expand-Archive -LiteralPath $ArchivePath -DestinationPath $tmp
    $listDir = Get-ChildItem -LiteralPath $tmp -Recurse -Directory -Filter lists | Select-Object -First 1
    if (-not $listDir) { throw 'lists directory not found in archive' }
    $listFiles = Get-ChildItem -LiteralPath $listDir.FullName -File -Filter 'finding_list_*.csv' |
        Where-Object { $_.BaseName -match '^finding_list_(cis_microsoft_windows_11_enterprise_\w+|msft_security_baseline_windows_11_\w+)_machine$' } | Sort-Object Name
    if ($listFiles.Count -eq 0) { throw 'scan measured zero Windows 11 machine finding lists' }
    $scanned = @(); $outRules = @()
    $tables = @{}
    foreach ($lf in $listFiles) { $tables[$lf.BaseName] = @(Import-Csv -LiteralPath $lf.FullName); $scanned += [ordered]@{ list = $lf.BaseName; rows = $tables[$lf.BaseName].Count } }
    foreach ($r in $hkRules) {
        $idMap = [ordered]@{}; $total = 0
        foreach ($lf in $listFiles) {
            $hits = foreach ($row in $tables[$lf.BaseName]) {
                $ok = switch ($r.type) {
                    'name'       { @($r.value) -contains $row.Name }
                    'namePrefix' { $row.Name.StartsWith([string]$r.value, [StringComparison]::Ordinal) }
                    'category'   { $row.Category -eq $r.value }
                }
                if ($ok) { $row.ID }
            }
            $hits = @($hits)
            if ($hits.Count -gt 0) { $idMap[$lf.BaseName] = $hits; $total += $hits.Count }
        }
        if ($total -eq 0) { throw "rule $($r.id) matched zero findings in every scanned list (typo or upstream rename)" }
        $outRules += [ordered]@{
            ruleId = $r.id; match = [ordered]@{ type = $r.type; value = $r.value }
            frameworkIds = @($r.ids); justification = $r.why; ids = $idMap
        }
    }
} finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }

$hcOut = foreach ($r in $hcRules) {
    $m = [ordered]@{ category = $r.category }
    if ($r.ContainsKey('name')) { $m.name = $r.name }
    if ($r.ContainsKey('namePrefix')) { $m.namePrefix = $r.namePrefix }
    [ordered]@{ ruleId = $r.id; match = $m; frameworkIds = @($r.ids); justification = $r.why }
}

$map = [ordered]@{
    schema = 'kritical-ps-hardening/framework-mapping/v1'
    generatedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    generatedBy = 'tools/New-KriticalHardenFrameworkMapping.ps1'
    policy = 'A finding is mapped ONLY when its own title (or category title) names the same setting family as the requirement title. Everything else is UNMAPPED at run time. Requirement IDs are copied exactly from the catalog snapshot in FrameworkRequirementIds.json.'
    hardeningKitty = [ordered]@{ pinnedTag = $hkPin.releaseTag; archiveSha256 = $hkPin.archiveSha256; listsScanned = $scanned }
    hotCakeX = [ordered]@{ categorySource = 'ComplianceCategories enum, module source tag Hardening-Module-v.0.7.5.1 (READ-FROM-SOURCE)' }
    hardeningKittyRules = @($outRules)
    hotCakeXRules = @($hcOut)
}
$snap = [ordered]@{
    schema = 'kritical-ps-hardening/framework-requirement-ids/v1'
    note = 'Snapshot of requirementId + shortTitle from Kritical-MSShowcase catalog\framework-mappings\*.json. Used to prove a mapped ID exists; never edit by hand.'
    catalog = [ordered]@{ repo = 'Sir-J-AU/Kritical-MSShowcase'; commit = $CatalogCommit; readOnlyCheckout = $CatalogRoot }
    frameworks = $catalog
}
$dataDir = Join-Path $repoRoot 'src\Data'
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
Set-Content -LiteralPath (Join-Path $dataDir 'FrameworkMapping.json') -Value ($map | ConvertTo-Json -Depth 10) -Encoding utf8
Set-Content -LiteralPath (Join-Path $dataDir 'FrameworkRequirementIds.json') -Value ($snap | ConvertTo-Json -Depth 10) -Encoding utf8
"MAPPING hk-rules=$($outRules.Count) hc-rules=$(@($hcOut).Count) lists-scanned=$($listFiles.Count) catalog-ids=$($validIds.Count) catalog-commit=$CatalogCommit"
foreach ($o in $outRules) { "{0}: {1} list(s), {2} id(s)" -f $o.ruleId, $o.ids.Count, (($o.ids.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum) }
