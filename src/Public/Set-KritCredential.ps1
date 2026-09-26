function Set-KritCredential {
    <#
    .SYNOPSIS
        Stores a reusable secret, DPAPI(CurrentUser)-encrypted, under a Name, for later
        retrieval by Get-KritCredential -- by THIS SAME Windows account, on THIS SAME machine.

    .DESCRIPTION
        Encrypts with Windows DPAPI (System.Security.Cryptography.ProtectedData,
        DataProtectionScope.CurrentUser). There is no separate AES key to manage or protect --
        the OS-managed, per-user DPAPI master key IS the protection. See README-HUMAN.md
        ("Credential store") for the full, honest threat model, including what this does NOT
        protect against.

        Accepts either a full PSCredential (UserName + Password) or a bare SecureString secret
        (an API token, a PAT, ...) with an optional, non-secret -UserName label.

        Idempotent: calling it again with the same Name overwrites the stored entry, ending in
        the same state either way. SupportsShouldProcess, so -WhatIf reports the write without
        performing it.

    .PARAMETER Name
        Store key. Letters/digits/'.'/'_'/'-' only, 1-128 chars, must start with a letter or
        digit (blocks path traversal such as '..\..\evil').

    .PARAMETER Credential
        A PSCredential. UserName is stored as cleartext metadata (it is not the secret);
        Password is DPAPI-protected.

    .PARAMETER SecureString
        A bare secret (token, password, connection string, ...) with no associated username.

    .PARAMETER UserName
        Optional, non-secret label stored alongside a -SecureString secret.

    .EXAMPLE
        Set-KritCredential -Name 'w365-portal' -Credential (Get-Credential)

    .EXAMPLE
        $token = Read-Host -AsSecureString 'GitHub PAT for SYSTEM git push'
        Set-KritCredential -Name 'es-mcp-git-push-pat' -SecureString $token -UserName 'es-mcp-system'

    .NOTES
        Author: Joshua Finley - Kritical Pty Ltd
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Credential')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Name,

        [Parameter(Mandatory, ParameterSetName = 'Credential', ValueFromPipeline)]
        [pscredential] $Credential,

        [Parameter(Mandatory, ParameterSetName = 'Secret')]
        [securestring] $SecureString,

        [Parameter(ParameterSetName = 'Secret')]
        [string] $UserName
    )
    process {
        # Validated (and throws on a bad Name) before anything else -- including before
        # ShouldProcess -- so a malformed Name never gets as far as a confirmation prompt.
        $path = Get-KritCredentialFilePath -Name $Name

        if ($PSCmdlet.ParameterSetName -eq 'Credential') {
            $secureToProtect = $Credential.Password
            $storedUserName  = $Credential.UserName
        } else {
            $secureToProtect = $SecureString
            $storedUserName  = $UserName
        }

        if (-not $PSCmdlet.ShouldProcess($path, "Write DPAPI-protected credential '$Name'")) {
            return
        }

        $protectedBase64 = Protect-KritCredentialSecureString -SecureString $secureToProtect
        $nowUtc   = (Get-Date).ToUniversalTime().ToString('o')
        $existing = $null
        if (Test-Path -LiteralPath $path) {
            try { $existing = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -ErrorAction Stop } catch { }
        }

        $envelope = [ordered]@{
            schema          = $script:KritCredentialStoreSchema
            name            = $Name
            userName        = $storedUserName
            scope           = 'CurrentUser'
            protectedBase64 = $protectedBase64
            createdUtc      = if ($existing -and $existing.createdUtc) { $existing.createdUtc } else { $nowUtc }
            updatedUtc      = $nowUtc
            createdBy       = "$env:USERDOMAIN\$env:USERNAME"
            machine         = $env:COMPUTERNAME
        }

        ($envelope | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $path -Encoding UTF8 -NoNewline
        Protect-KritCredentialStoreAcl -Path (Split-Path -Parent $path)  # keep dir ACL current

        [pscustomobject]@{
            Name       = $Name
            UserName   = $storedUserName
            Path       = $path
            UpdatedUtc = $nowUtc
        }
    }
}

function Get-KritCredential {
    <#
    .SYNOPSIS
        Retrieves a secret stored by Set-KritCredential.

    .DESCRIPTION
        FAILS CLOSED: an absent Name, a name stored by a different Windows account or a
        different machine, or a tampered/corrupted store entry all raise a non-terminating
        Write-Error and return NOTHING -- never a fabricated, partial, or garbage credential.
        Callers that need to branch on failure should check -ErrorVariable / $Error, or pass
        -ErrorAction Stop to turn the failure into an exception.

    .PARAMETER Name
        The store key used with Set-KritCredential.

    .PARAMETER AsSecureString
        Force a SecureString return even when the entry has an associated UserName. Default
        behaviour: returns a PSCredential when a UserName is present, a bare SecureString
        otherwise.

    .EXAMPLE
        $cred = Get-KritCredential -Name 'w365-portal'

    .EXAMPLE
        $token = Get-KritCredential -Name 'es-mcp-git-push-pat' -AsSecureString -ErrorAction Stop

    .NOTES
        Author: Joshua Finley - Kritical Pty Ltd
    #>
    [CmdletBinding()]
    [OutputType([pscredential], [securestring])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Name,

        [switch] $AsSecureString
    )

    try {
        $path = Get-KritCredentialFilePath -Name $Name
    } catch {
        Write-Error "Get-KritCredential: $($_.Exception.Message)"
        return
    }

    if (-not (Test-Path -LiteralPath $path)) {
        Write-Error "Get-KritCredential: no credential named '$Name' in the store for $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME."
        return
    }

    try {
        $envelope = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -ErrorAction Stop
        $secure   = Unprotect-KritCredentialSecureString -Base64CipherText $envelope.protectedBase64
    } catch {
        Write-Error "Get-KritCredential: failed to recover '$Name' -- the store entry is unreadable, corrupted, or was protected by a different Windows account/machine ($($_.Exception.Message)). Refusing to return a partial or fabricated credential."
        return
    }

    if ($AsSecureString -or -not $envelope.userName) {
        return $secure
    }
    return New-Object pscredential($envelope.userName, $secure)
}

function Remove-KritCredential {
    <#
    .SYNOPSIS
        Deletes a stored credential.

    .DESCRIPTION
        Idempotent delete semantics: removing an absent Name is a successful no-op (returns
        $false, no error) -- that is standard "delete" behaviour, and is deliberately different
        from Get-KritCredential's fail-closed behaviour on a *read* of an absent/invalid name.
        SupportsShouldProcess, so -WhatIf reports the deletion without performing it.

    .EXAMPLE
        Remove-KritCredential -Name 'w365-portal' -WhatIf

    .NOTES
        Author: Joshua Finley - Kritical Pty Ltd
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Name
    )
    $path = Get-KritCredentialFilePath -Name $Name
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Verbose "Remove-KritCredential: '$Name' not present -- nothing to remove."
        return $false
    }
    if ($PSCmdlet.ShouldProcess($path, "Delete stored credential '$Name'")) {
        Remove-Item -LiteralPath $path -Force
        return $true
    }
    return $false
}

function Get-KritCredentialList {
    <#
    .SYNOPSIS
        Lists the Names present in this account's credential store WITHOUT decrypting anything.

    .EXAMPLE
        Get-KritCredentialList | Format-Table

    .NOTES
        Author: Joshua Finley - Kritical Pty Ltd
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()
    $root = Get-KritCredentialStoreRoot
    Get-ChildItem -LiteralPath $root -Filter '*.kritcred.json' -File -ErrorAction SilentlyContinue |
        Sort-Object Name |
        ForEach-Object {
            $envelope = $null
            try { $envelope = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json -ErrorAction Stop } catch { }
            [pscustomobject]@{
                Name        = if ($envelope) { $envelope.name } else { ($_.BaseName -replace '\.kritcred$', '') }
                HasUserName = [bool]($envelope -and $envelope.userName)
                UserName    = if ($envelope) { $envelope.userName } else { $null }
                CreatedUtc  = if ($envelope) { $envelope.createdUtc } else { $null }
                UpdatedUtc  = if ($envelope) { $envelope.updatedUtc } else { $null }
                Path        = $_.FullName
            }
        }
}
