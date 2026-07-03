function Test-KriticalHardenPrereqs {
    <#
    .SYNOPSIS
        7-gate prereq check for the Kritical Hardening toolkit. Read-only.

    .DESCRIPTION
        Gates:
          P1 OS family supported (Windows for v1; macOS/Linux deferred to v1.1)
          P2 PowerShell version >= 7.4 (recommended for HotCakeX module compatibility)
          P3 Process is elevated / running as Administrator
          P4 Microsoft Defender service Running + signature recent
          P5 TPM 2.0 present + ready (warning only; not a hard fail)
          P6 SecureBoot enabled (warning only)
          P7 WinRM / PSRemoting reachable (info only)

        Returns a structured object so a supervisor / scheduled task / CI runner
        can branch on .Ok and per-gate detail.

    .EXAMPLE
        Test-KriticalHardenPrereqs

    .EXAMPLE
        $r = Test-KriticalHardenPrereqs -Quiet
        if (-not $r.Ok) { throw "Hardening prereqs failed" }

    .NOTES
        Author: Joshua Finley - Kritical Pty Ltd
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([switch] $Quiet, [switch] $NoBanner)

    if (-not $NoBanner.IsPresent -and -not $Quiet.IsPresent) {
        Write-KriticalHardenBanner -Title 'Hardening Prereq Probe' -Compact
    }

    $gates = [System.Collections.Generic.List[pscustomobject]]::new()
    $add = { param($n,$p,$severity,$d) $gates.Add([pscustomobject]@{ Gate=$n; Pass=[bool]$p; Severity=$severity; Detail=$d }) }

    # P1 Windows (v1 only)
    $rti = [System.Runtime.InteropServices.RuntimeInformation]
    $os  = [System.Runtime.InteropServices.OSPlatform]
    $isWindows = $rti::IsOSPlatform($os::Windows)
    $p1Detail = if ($isWindows) { 'Windows detected' } else { 'macOS/Linux deferred to v1.1' }
    & $add 'P1.Windows' $isWindows 'Critical' $p1Detail

    # P2 PS version >= 7.4 recommended
    $psv = $PSVersionTable.PSVersion
    $psOk = ($psv.Major -gt 7) -or ($psv.Major -eq 7 -and $psv.Minor -ge 4)
    & $add 'P2.PSVersion' $psOk 'Warning' ("PS $psv (>= 7.4 recommended for HotCakeX module)")

    # P3 Admin
    $admin = $false
    if ($isWindows) {
        try {
            $cur = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
            $admin = $cur.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
        } catch { }
    }
    $p3Detail = if ($admin) { 'elevated' } else { 'not elevated - hardening probes need admin' }
    & $add 'P3.Admin' $admin 'Critical' $p3Detail

    # P4 Defender running + recent sigs
    $defOk = $false; $defDetail = 'not probed (non-Windows)'
    if ($isWindows) {
        try {
            $svc = Get-Service -Name 'WinDefend' -ErrorAction Stop
            $sigAge = $null
            try {
                $mp = Get-MpComputerStatus -ErrorAction Stop
                $sigAge = if ($mp.AntivirusSignatureAge) { [int]$mp.AntivirusSignatureAge } else { $null }
            } catch { }
            $defOk = ($svc.Status -eq 'Running') -and ($sigAge -ne $null -and $sigAge -le 7)
            $defDetail = "WinDefend=$($svc.Status); signature age days=$sigAge"
        } catch { $defDetail = "Defender probe failed: $($_.Exception.Message)" }
    }
    & $add 'P4.Defender' $defOk 'Warning' $defDetail

    # P5 TPM 2.0 (warning)
    $tpmOk = $false; $tpmDetail = 'not probed'
    if ($isWindows) {
        try {
            $tpm = Get-Tpm -ErrorAction Stop
            $tpmOk = ($tpm.TpmPresent -and $tpm.TpmReady -and ($tpm.ManufacturerVersionInfo -or $tpm.LockoutCount -ne $null))
            $tpmDetail = "Present=$($tpm.TpmPresent); Ready=$($tpm.TpmReady)"
        } catch { $tpmDetail = "Get-Tpm failed: $($_.Exception.Message)" }
    }
    & $add 'P5.Tpm' $tpmOk 'Warning' $tpmDetail

    # P6 SecureBoot (warning)
    $sbOk = $false; $sbDetail = 'not probed'
    if ($isWindows) {
        try {
            $sb = Confirm-SecureBootUEFI -ErrorAction Stop
            $sbOk = [bool]$sb; $sbDetail = "SecureBoot=$sb"
        } catch { $sbDetail = "Confirm-SecureBootUEFI failed: $($_.Exception.Message)" }
    }
    & $add 'P6.SecureBoot' $sbOk 'Warning' $sbDetail

    # P7 WinRM (info only)
    $wsOk = $false; $wsDetail = 'not probed'
    if ($isWindows) {
        try { Test-WSMan -ComputerName localhost -ErrorAction Stop | Out-Null; $wsOk = $true; $wsDetail = 'WinRM reachable' }
        catch { $wsDetail = "Test-WSMan failed: $($_.Exception.Message)" }
    }
    & $add 'P7.WinRM' $wsOk 'Info' $wsDetail

    $criticalFails = @($gates | Where-Object { $_.Severity -eq 'Critical' -and -not $_.Pass })
    $warningFails  = @($gates | Where-Object { $_.Severity -eq 'Warning'  -and -not $_.Pass })
    $ok = ($criticalFails.Count -eq 0)

    if (-not $Quiet.IsPresent) {
        $gates | Format-Table -AutoSize | Out-String | Write-Host
        if ($ok) {
            Write-Host ("Prereqs OK (Critical=0 fail, Warning=$($warningFails.Count) fail, Info-only items as reported).") -ForegroundColor Green
        } else {
            Write-Host ("Prereqs FAILED ($($criticalFails.Count) critical gate(s) failed).") -ForegroundColor Red
        }
    }
    $platform = $null
    if (Get-Command Get-KritPlatform -ErrorAction SilentlyContinue) { $platform = Get-KritPlatform }
    [pscustomobject]@{
        Ok            = $ok
        CriticalFails = $criticalFails.Count
        WarningFails  = $warningFails.Count
        Gates         = @($gates)
        Platform      = $platform
    }
}
