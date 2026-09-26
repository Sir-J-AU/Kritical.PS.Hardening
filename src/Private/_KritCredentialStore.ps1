<#
.SYNOPSIS
    Internal helpers for the Kritical reusable encrypted credential store
    (Set-KritCredential / Get-KritCredential / Remove-KritCredential / Get-KritCredentialList).
.NOTES
    Author: Joshua Finley - Kritical Pty Ltd

    DPAPI (System.Security.Cryptography.ProtectedData, DataProtectionScope.CurrentUser) is the
    ONLY thing that actually protects the secret at rest -- there is no separate AES key to
    manage, which is deliberate: an AES key sitting next to its own ciphertext is not
    encryption. The NTFS ACL lockdown below is a second, defence-in-depth layer, not the
    primary control. See README-HUMAN.md ("Credential store") for the full, honest threat
    model, including what this does NOT protect against.
#>

Set-StrictMode -Version Latest

$script:KritCredentialStoreSchema  = 'kritical-credential-store/v1'
# Only safe path-segment characters -- blocks path traversal (../, absolute paths, UNC, etc.)
$script:KritCredentialNamePattern  = '^[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}$'

function Get-KritCredentialStoreRoot {
    <#
    .SYNOPSIS
        Per-user store directory (under %LOCALAPPDATA%, itself user-profile-scoped), created
        on demand with a locked-down ACL. Re-evaluates $env:LOCALAPPDATA on every call
        (never cached) so tests can redirect it cleanly.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $root = Join-Path $env:LOCALAPPDATA 'Kritical\CredentialStore'
    if (-not (Test-Path -LiteralPath $root)) {
        New-Item -ItemType Directory -Path $root -Force | Out-Null
    }
    Protect-KritCredentialStoreAcl -Path $root
    return $root
}

function Protect-KritCredentialStoreAcl {
    <#
    .SYNOPSIS
        Defence-in-depth only: strips inherited ACEs on the store directory and grants
        FullControl to ONLY the current Windows identity (+ the built-in SYSTEM principal,
        S-1-5-18, so a service that runs its OWN store AS SYSTEM still works -- SYSTEM is a
        distinct security principal from every interactive/service user account; adding it
        here does not grant any other user account access to this identity's store).
        Best-effort and silent on failure -- DPAPI CurrentUser scope is the real protection
        even if this ACL step fails (e.g. non-NTFS volume, restricted environment).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    try {
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetAccessRuleProtection($true, $false)   # disable inheritance, drop inherited ACEs
        foreach ($rule in @($acl.Access)) { $acl.RemoveAccessRule($rule) | Out-Null }

        $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $ruleMe = New-Object Security.AccessControl.FileSystemAccessRule(
            $me, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($ruleMe)

        $sys = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')  # NT AUTHORITY\SYSTEM
        $ruleSys = New-Object Security.AccessControl.FileSystemAccessRule(
            $sys, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($ruleSys)

        Set-Acl -LiteralPath $Path -AclObject $acl
    } catch {
        Write-Verbose "Protect-KritCredentialStoreAcl: best-effort ACL lockdown failed for '$Path': $($_.Exception.Message)"
    }
}

function Test-KritCredentialName {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Name)
    return ($Name -match $script:KritCredentialNamePattern)
}

function Get-KritCredentialFilePath {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Name)
    if (-not (Test-KritCredentialName -Name $Name)) {
        throw "Invalid credential Name '$Name'. Allowed: letters, digits, '.', '_', '-' (1-128 chars, must start with a letter/digit)."
    }
    $root = Get-KritCredentialStoreRoot
    return (Join-Path $root ($Name + '.kritcred.json'))
}

function Protect-KritCredentialSecureString {
    <#
    .SYNOPSIS
        SecureString -> DPAPI(CurrentUser)-protected bytes, base64. Never materialises the
        plaintext as a managed System.String (which cannot be reliably zeroed); copies the
        secret into an unmanaged Unicode buffer, protects it, then explicitly zeroes and frees
        every buffer involved.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][securestring]$SecureString)

    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($SecureString)
    try {
        $byteCount  = $SecureString.Length * 2
        $plainBytes = New-Object byte[] $byteCount
        try {
            [Runtime.InteropServices.Marshal]::Copy($ptr, $plainBytes, 0, $byteCount)
            $cipher = [Security.Cryptography.ProtectedData]::Protect(
                $plainBytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
            return [Convert]::ToBase64String($cipher)
        } finally {
            [Array]::Clear($plainBytes, 0, $plainBytes.Length)
        }
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr)
    }
}

function Unprotect-KritCredentialSecureString {
    <#
    .SYNOPSIS
        base64 DPAPI(CurrentUser) ciphertext -> SecureString. FAILS CLOSED: any
        FormatException (bad base64) or CryptographicException (wrong user, wrong machine
        profile, tampered/corrupted blob) propagates as a terminating error. Callers MUST NOT
        treat a caught failure here as "empty secret" -- only as "could not recover secret".
    #>
    [CmdletBinding()]
    [OutputType([securestring])]
    param([Parameter(Mandatory)][string]$Base64CipherText)

    $cipher     = [Convert]::FromBase64String($Base64CipherText)
    $plainBytes = [Security.Cryptography.ProtectedData]::Unprotect(
        $cipher, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    try {
        $secure = New-Object Security.SecureString
        for ($i = 0; $i -lt $plainBytes.Length; $i += 2) {
            $ch = [BitConverter]::ToChar($plainBytes, $i)
            $secure.AppendChar($ch)
        }
        $secure.MakeReadOnly()
        return $secure
    } finally {
        [Array]::Clear($plainBytes, 0, $plainBytes.Length)
    }
}
