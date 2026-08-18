#requires -Modules Pester
<#
    All secret values in this file are synthetic, fabricated test fixtures ("FakeTestOnly-...")
    used ONLY to prove the encrypt/decrypt round trip and the fail-closed behaviour. None of
    them are real credentials, and none grant access to anything. The store root is redirected
    to an isolated temp directory for the duration of this file so these tests never touch the
    real per-operator credential store.
#>
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\..\src\Kritical.PS.Hardening.psm1') -Force

    $script:OrigLocalAppData = $env:LOCALAPPDATA
    $script:TestRoot = Join-Path ([IO.Path]::GetTempPath()) ('KritCredStoreTest_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:TestRoot -Force | Out-Null
    $env:LOCALAPPDATA = $script:TestRoot
}

AfterAll {
    $env:LOCALAPPDATA = $script:OrigLocalAppData
    if ($script:TestRoot -and (Test-Path -LiteralPath $script:TestRoot)) {
        Remove-Item -LiteralPath $script:TestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Kritical credential store (Set/Get/Remove/List-KritCredential)' {

    It 'round-trips a PSCredential (UserName + Password)' {
        $sec  = ConvertTo-SecureString 'FakeTestOnly-Passw0rd-9f7a2b' -AsPlainText -Force
        $cred = New-Object pscredential('svc-w365-waker', $sec)
        Set-KritCredential -Name 'roundtrip-cred' -Credential $cred -Confirm:$false

        $got = Get-KritCredential -Name 'roundtrip-cred'
        $got | Should -BeOfType [pscredential]
        $got.UserName | Should -Be 'svc-w365-waker'
        $got.GetNetworkCredential().Password | Should -Be 'FakeTestOnly-Passw0rd-9f7a2b'
    }

    It 'round-trips a bare SecureString secret (e.g. a token)' {
        $sec = ConvertTo-SecureString 'FakeTestOnly-Token-4d5e6f7a8b' -AsPlainText -Force
        Set-KritCredential -Name 'roundtrip-token' -SecureString $sec -Confirm:$false

        $got = Get-KritCredential -Name 'roundtrip-token'
        $got | Should -BeOfType [securestring]
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($got)
        try {
            [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) | Should -Be 'FakeTestOnly-Token-4d5e6f7a8b'
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }

    It 'fails closed on a Name that was never set -- no fabricated credential leaks out' {
        $result = Get-KritCredential -Name 'never-set-this-one' -ErrorAction SilentlyContinue -ErrorVariable errs
        $result | Should -BeNullOrEmpty
        $errs.Count | Should -BeGreaterThan 0
    }

    It 'does not persist the plaintext secret anywhere on disk' {
        $secretValue = 'FakeTestOnly-PlaintextCanary-1a2b3c'
        $sec = ConvertTo-SecureString $secretValue -AsPlainText -Force
        Set-KritCredential -Name 'plaintext-canary' -SecureString $sec -Confirm:$false

        $storeRoot = Join-Path $env:LOCALAPPDATA 'Kritical\CredentialStore'
        $file = Get-ChildItem -LiteralPath $storeRoot -Filter 'plaintext-canary.kritcred.json'
        $file | Should -Not -BeNullOrEmpty

        $raw = Get-Content -LiteralPath $file.FullName -Raw
        $raw | Should -Not -Match ([regex]::Escape($secretValue))
    }

    It 'RED case (planted): a tampered/corrupted ciphertext blob fails closed instead of decrypting into a plausible secret' {
        $sec = ConvertTo-SecureString 'FakeTestOnly-BeforeTamper-2b3c4d' -AsPlainText -Force
        Set-KritCredential -Name 'tamper-target' -SecureString $sec -Confirm:$false

        $storeRoot = Join-Path $env:LOCALAPPDATA 'Kritical\CredentialStore'
        $path = Join-Path $storeRoot 'tamper-target.kritcred.json'
        $envelope = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json

        # Deliberately corrupt the DPAPI blob with unrelated bytes of the wrong shape. This
        # must NOT decrypt into ANY plausible secret -- it must error out, hard.
        $garbage = [byte[]](1..40 | ForEach-Object { [byte]($_ * 7 % 251) })
        $envelope.protectedBase64 = [Convert]::ToBase64String($garbage)
        ($envelope | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $path -Encoding UTF8 -NoNewline

        $result = Get-KritCredential -Name 'tamper-target' -ErrorAction SilentlyContinue -ErrorVariable errs
        $result | Should -BeNullOrEmpty
        $errs.Count | Should -BeGreaterThan 0
    }

    It 'rejects a Name that attempts path traversal' {
        $sec = ConvertTo-SecureString 'FakeTestOnly-Irrelevant' -AsPlainText -Force
        { Set-KritCredential -Name '..\..\evil' -SecureString $sec -Confirm:$false } | Should -Throw
    }

    It 'Get-KritCredentialList reports stored names without exposing secret material' {
        $sec = ConvertTo-SecureString 'FakeTestOnly-ListMe-Value' -AsPlainText -Force
        Set-KritCredential -Name 'list-target' -SecureString $sec -Confirm:$false

        $list = Get-KritCredentialList
        ($list | Where-Object Name -eq 'list-target') | Should -Not -BeNullOrEmpty
        ($list | Get-Member -Name 'protectedBase64') | Should -BeNullOrEmpty
    }

    It 'Remove-KritCredential deletes an entry, then is idempotent on repeat removal' {
        $sec = ConvertTo-SecureString 'FakeTestOnly-RemoveMe-Value' -AsPlainText -Force
        Set-KritCredential -Name 'remove-target' -SecureString $sec -Confirm:$false

        (Remove-KritCredential -Name 'remove-target' -Confirm:$false) | Should -Be $true
        { Get-KritCredential -Name 'remove-target' -ErrorAction Stop } | Should -Throw
        (Remove-KritCredential -Name 'remove-target' -Confirm:$false) | Should -Be $false
    }

    It '-WhatIf on Set-KritCredential does not write anything' {
        $before = Get-KritCredentialList | Where-Object Name -eq 'whatif-target'
        $before | Should -BeNullOrEmpty

        $sec = ConvertTo-SecureString 'FakeTestOnly-WhatIf-Value' -AsPlainText -Force
        Set-KritCredential -Name 'whatif-target' -SecureString $sec -WhatIf

        $after = Get-KritCredentialList | Where-Object Name -eq 'whatif-target'
        $after | Should -BeNullOrEmpty
    }

    It 'the store directory ACL grants access only to the current identity (+ SYSTEM), not broad groups' {
        Get-KritCredentialList | Out-Null   # ensures store dir exists
        $storeRoot = Join-Path $env:LOCALAPPDATA 'Kritical\CredentialStore'
        $acl = Get-Acl -LiteralPath $storeRoot

        $acl.AreAccessRulesProtected | Should -Be $true

        $idents = $acl.Access | ForEach-Object { $_.IdentityReference.Value }
        $idents | Should -Not -Contain 'Everyone'
        $idents | Where-Object { $_ -match 'BUILTIN\\Users$' } | Should -BeNullOrEmpty
        $idents | Where-Object { $_ -match 'NT AUTHORITY\\Authenticated Users' } | Should -BeNullOrEmpty

        $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        $idents | Should -Contain $me
    }
}
