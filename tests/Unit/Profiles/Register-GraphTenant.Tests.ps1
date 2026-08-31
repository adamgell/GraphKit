BeforeAll {
    $repoRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $built = Get-ChildItem -Path (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $built) {
        throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first, then re-run the tests.'
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force

    $script:tenantId = '3a4b5c6d-1111-2222-3333-444455556666'
}

Describe 'Register-GraphTenant' {

    It 'persists a client-secret profile and reads it back' {
        $script:storePath = Join-Path $TestDrive ("profiles-{0}.json" -f [guid]::NewGuid())
        Register-GraphTenant -ProfileId 'acme' -Name 'Acme' -Kind 'customer' -TenantId $script:tenantId -Environment 'Global' -AuthMethod 'ClientSecret' -VaultName 'GraphKit' -SecretName 'acme-secret' -StorePath $script:storePath

        $store = InModuleScope GraphKit -Parameters @{ StorePath = $script:storePath } {
            Get-GraphProfileStore -StorePath $StorePath
        }
        @($store.Profiles).Count | Should -Be 1
        $store.Profiles[0].Credential.VaultName | Should -Be 'GraphKit'
        $store.Profiles[0].Credential.SecretName | Should -Be 'acme-secret'
    }

    It 'persists the exact PFX password secret version' {
        $script:storePath = Join-Path $TestDrive ("profiles-{0}.json" -f [guid]::NewGuid())
        $pfxPath = Join-Path $TestDrive 'registration.pfx'
        [System.IO.File]::WriteAllBytes($pfxPath, [byte[]] @(1, 2, 3))

        Register-GraphTenant -ProfileId 'pfx-versioned' -Name 'PFX' -Kind 'lab' `
            -TenantId $script:tenantId -Environment 'Global' -AuthMethod 'Certificate' `
            -PfxPath $pfxPath -PfxVaultName 'GraphKit' -PfxSecretName 'pfx-password' `
            -PfxSecretVersion 'version-2' -StorePath $script:storePath

        $store = InModuleScope GraphKit -Parameters @{ StorePath = $script:storePath } {
            Get-GraphProfileStore -StorePath $StorePath
        }
        $store.Profiles[0].Credential.Password.VaultName | Should -Be 'GraphKit'
        $store.Profiles[0].Credential.Password.SecretName | Should -Be 'pfx-password'
        $store.Profiles[0].Credential.Password.Version | Should -Be 'version-2'
    }

    It 'persists an encrypted vault-certificate password reference and requires a complete pair' {
        $script:storePath = Join-Path $TestDrive ("profiles-{0}.json" -f [guid]::NewGuid())

        Register-GraphTenant -ProfileId 'vault-cert' -Name 'Vault cert' -Kind 'lab' `
            -TenantId $script:tenantId -Environment 'Global' -AuthMethod 'Certificate' `
            -VaultName 'GraphKit' -CertificateName 'certificate-pfx' -CertificateVersion 'cert-v2' `
            -CertificatePasswordVaultName 'GraphKit' -CertificatePasswordSecretName 'certificate-password' `
            -CertificatePasswordVersion 'password-v3' -StorePath $script:storePath

        $store = InModuleScope GraphKit -Parameters @{ StorePath = $script:storePath } {
            Get-GraphProfileStore -StorePath $StorePath
        }
        $store.Profiles[0].Credential.Version | Should -Be 'cert-v2'
        $store.Profiles[0].Credential.Password.VaultName | Should -Be 'GraphKit'
        $store.Profiles[0].Credential.Password.SecretName | Should -Be 'certificate-password'
        $store.Profiles[0].Credential.Password.Version | Should -Be 'password-v3'

        $invalidStore = Join-Path $TestDrive ("profiles-{0}.json" -f [guid]::NewGuid())
        {
            Register-GraphTenant -ProfileId 'invalid-vault-cert' -Name 'Invalid' -Kind 'lab' `
                -TenantId $script:tenantId -Environment 'Global' -AuthMethod 'Certificate' `
                -VaultName 'GraphKit' -CertificateName 'certificate-pfx' `
                -CertificatePasswordVaultName 'GraphKit' -StorePath $invalidStore
        } | Should -Throw -ExpectedMessage '*must include both*'
    }

    It 'rejects an injected certificate object' {
        $script:storePath = Join-Path $TestDrive ("profiles-{0}.json" -f [guid]::NewGuid())
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
        {
            Register-GraphTenant -ProfileId 'acme' -Name 'Acme' -Kind 'lab' -TenantId $script:tenantId -Environment 'Global' -AuthMethod 'Certificate' -Certificate $cert -StorePath $script:storePath
        } | Should -Throw -ExpectedMessage '*cannot be persisted*'
    }

    It 'rejects an injected token provider' {
        $script:storePath = Join-Path $TestDrive ("profiles-{0}.json" -f [guid]::NewGuid())
        {
            Register-GraphTenant -ProfileId 'acme' -Name 'Acme' -Kind 'lab' -TenantId $script:tenantId -Environment 'Global' -AuthMethod 'ClientSecret' -VaultName 'v' -SecretName 's' -TokenProvider { 'tok' } -StorePath $script:storePath
        } | Should -Throw -ExpectedMessage '*cannot be persisted*'
    }

    It 'rejects an invalid ProfileId' {
        $script:storePath = Join-Path $TestDrive ("profiles-{0}.json" -f [guid]::NewGuid())
        {
            Register-GraphTenant -ProfileId 'INVALID!' -Name 'Acme' -Kind 'lab' -TenantId $script:tenantId -Environment 'Global' -AuthMethod 'ClientSecret' -VaultName 'v' -SecretName 's' -StorePath $script:storePath
        } | Should -Throw -ExpectedMessage '*not a valid canonical*'
    }

    It 'rejects an invalid TenantId GUID' {
        $script:storePath = Join-Path $TestDrive ("profiles-{0}.json" -f [guid]::NewGuid())
        {
            Register-GraphTenant -ProfileId 'acme' -Name 'Acme' -Kind 'lab' -TenantId 'not-a-guid' -Environment 'Global' -AuthMethod 'ClientSecret' -VaultName 'v' -SecretName 's' -StorePath $script:storePath
        } | Should -Throw -ExpectedMessage '*not a valid GUID*'
    }

    It 'rejects an invalid ClientId GUID' {
        $script:storePath = Join-Path $TestDrive ("profiles-{0}.json" -f [guid]::NewGuid())
        {
            Register-GraphTenant -ProfileId 'acme' -Name 'Acme' -Kind 'lab' -TenantId $script:tenantId -ClientId 'nope' -Environment 'Global' -AuthMethod 'ClientSecret' -VaultName 'v' -SecretName 's' -StorePath $script:storePath
        } | Should -Throw -ExpectedMessage '*not a valid GUID*'
    }

    It 'validates the customer Name via the injected taxonomy adapter' {
        $script:storePath = Join-Path $TestDrive ("profiles-{0}.json" -f [guid]::NewGuid())
        $adapter = { param($Name) if ($Name -ne 'KnownCustomer') { throw "unknown customer tag '$Name'" } }

        {
            Register-GraphTenant -ProfileId 'acme' -Name 'UnknownCustomer' -Kind 'customer' -TenantId $script:tenantId -Environment 'Global' -AuthMethod 'ClientSecret' -VaultName 'v' -SecretName 's' -TaxonomyAdapter $adapter -StorePath $script:storePath
        } | Should -Throw -ExpectedMessage '*unknown customer tag*'

        {
            Register-GraphTenant -ProfileId 'acme' -Name 'KnownCustomer' -Kind 'customer' -TenantId $script:tenantId -Environment 'Global' -AuthMethod 'ClientSecret' -VaultName 'v' -SecretName 's' -TaxonomyAdapter $adapter -StorePath $script:storePath
        } | Should -Not -Throw
    }

    It 'rejects a client-secret registration missing its credential parameters' {
        $script:storePath = Join-Path $TestDrive ("profiles-{0}.json" -f [guid]::NewGuid())
        {
            Register-GraphTenant -ProfileId 'acme' -Name 'Acme' -Kind 'lab' -TenantId $script:tenantId -Environment 'Global' -AuthMethod 'ClientSecret' -StorePath $script:storePath
        } | Should -Throw -ExpectedMessage '*requires -VaultName*'
    }

    It 'rejects a duplicate ProfileId' {
        $script:storePath = Join-Path $TestDrive ("profiles-{0}.json" -f [guid]::NewGuid())
        Register-GraphTenant -ProfileId 'dup' -Name 'Dup' -Kind 'lab' -TenantId $script:tenantId -Environment 'Global' -AuthMethod 'ClientSecret' -VaultName 'v' -SecretName 's' -StorePath $script:storePath

        {
            Register-GraphTenant -ProfileId 'dup' -Name 'Dup2' -Kind 'lab' -TenantId $script:tenantId -Environment 'Global' -AuthMethod 'ClientSecret' -VaultName 'v' -SecretName 's' -StorePath $script:storePath
        } | Should -Throw -ExpectedMessage '*already exists*'
    }
}
