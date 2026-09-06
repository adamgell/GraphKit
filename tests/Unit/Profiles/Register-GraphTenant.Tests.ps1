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
        Register-GraphTenant -ProfileId 'acme' -Name 'Acme' -Kind 'customer' -TenantId $script:tenantId -ClientId '7d6e5f44-9999-8888-7777-666655554444' -Environment 'Global' -AuthMethod 'ClientSecret' -VaultName 'GraphKit' -SecretName 'acme-secret' -StorePath $script:storePath

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
            -TenantId $script:tenantId -ClientId '7d6e5f44-9999-8888-7777-666655554444' -Environment 'Global' -AuthMethod 'Certificate' `
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
            -TenantId $script:tenantId -ClientId '7d6e5f44-9999-8888-7777-666655554444' -Environment 'Global' -AuthMethod 'Certificate' `
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
                -TenantId $script:tenantId -ClientId '7d6e5f44-9999-8888-7777-666655554444' `
                -Environment 'Global' -AuthMethod 'Certificate' `
                -VaultName 'GraphKit' -CertificateName 'certificate-pfx' `
                -CertificatePasswordVaultName 'GraphKit' -StorePath $invalidStore
        } | Should -Throw -ExpectedMessage '*must include both*'

        $versionOnlyStore = Join-Path $TestDrive ("profiles-{0}.json" -f [guid]::NewGuid())
        {
            Register-GraphTenant -ProfileId 'invalid-vault-cert-version' -Name 'Invalid' -Kind 'lab' `
                -TenantId $script:tenantId -ClientId '7d6e5f44-9999-8888-7777-666655554444' `
                -Environment 'Global' -AuthMethod 'Certificate' `
                -VaultName 'GraphKit' -CertificateName 'certificate-pfx' `
                -CertificatePasswordVersion 'password-v3' -StorePath $versionOnlyStore
        } | Should -Throw -ExpectedMessage '*must include both*'
        Test-Path -LiteralPath $versionOnlyStore | Should -BeFalse
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
            Register-GraphTenant -ProfileId 'acme' -Name 'UnknownCustomer' -Kind 'customer' -TenantId $script:tenantId -ClientId '7d6e5f44-9999-8888-7777-666655554444' -Environment 'Global' -AuthMethod 'ClientSecret' -VaultName 'v' -SecretName 's' -TaxonomyAdapter $adapter -StorePath $script:storePath
        } | Should -Throw -ExpectedMessage '*unknown customer tag*'

        {
            Register-GraphTenant -ProfileId 'acme' -Name 'KnownCustomer' -Kind 'customer' -TenantId $script:tenantId -ClientId '7d6e5f44-9999-8888-7777-666655554444' -Environment 'Global' -AuthMethod 'ClientSecret' -VaultName 'v' -SecretName 's' -TaxonomyAdapter $adapter -StorePath $script:storePath
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
        Register-GraphTenant -ProfileId 'dup' -Name 'Dup' -Kind 'lab' -TenantId $script:tenantId -ClientId '7d6e5f44-9999-8888-7777-666655554444' -Environment 'Global' -AuthMethod 'ClientSecret' -VaultName 'v' -SecretName 's' -StorePath $script:storePath

        {
            Register-GraphTenant -ProfileId 'dup' -Name 'Dup2' -Kind 'lab' -TenantId $script:tenantId -ClientId '7d6e5f44-9999-8888-7777-666655554444' -Environment 'Global' -AuthMethod 'ClientSecret' -VaultName 'v' -SecretName 's' -StorePath $script:storePath
        } | Should -Throw -ExpectedMessage '*already exists*'
    }

    It 'enforces the literal mode-discriminated identity matrix at registration' -ForEach @(
        @{ Case = 'certificate missing application client'; Mode = 'Certificate'; Extra = @{ VaultName = 'v'; CertificateName = 'cert' }; Expected = '*Certificate*ClientId*re-register*' }
        @{ Case = 'client secret missing application client'; Mode = 'ClientSecret'; Extra = @{ VaultName = 'v'; SecretName = 's' }; Expected = '*ClientSecret*ClientId*re-register*' }
        @{ Case = 'zero application client'; Mode = 'ClientSecret'; ClientId = '00000000-0000-0000-0000-000000000000'; Extra = @{ VaultName = 'v'; SecretName = 's' }; Expected = '*non-zero*ClientId*re-register*' }
        @{ Case = 'managed identity top-level application client'; Mode = 'ManagedIdentity'; ClientId = '7d6e5f44-9999-8888-7777-666655554444'; Extra = @{}; Expected = '*ManagedIdentity*must not*ClientId*re-register*' }
        @{ Case = 'managed identity invalid nested selector'; Mode = 'ManagedIdentity'; Extra = @{ ManagedIdentityClientId = 'not-a-guid' }; Expected = '*ManagedIdentityClientId*GUID*re-register*' }
        @{ Case = 'managed identity zero nested selector'; Mode = 'ManagedIdentity'; Extra = @{ ManagedIdentityClientId = '00000000-0000-0000-0000-000000000000' }; Expected = '*non-zero*ManagedIdentityClientId*re-register*' }
        @{ Case = 'bearer application client'; Mode = 'BearerToken'; ClientId = '7d6e5f44-9999-8888-7777-666655554444'; Extra = @{ VaultName = 'v'; SecretName = 's' }; Expected = '*BearerToken*must not*ClientId*re-register*' }
        @{ Case = 'bearer managed identity selector'; Mode = 'BearerToken'; Extra = @{ VaultName = 'v'; SecretName = 's'; ManagedIdentityClientId = '11111111-2222-3333-4444-555555555555' }; Expected = '*BearerToken*ManagedIdentityClientId*re-register*' }
    ) {
        $storePath = Join-Path $TestDrive ("strict-{0}.json" -f [guid]::NewGuid())
        $arguments = @{
            ProfileId = 'strict'; Name = $Case; Kind = 'lab'; TenantId = $script:tenantId
            Environment = 'Global'; AuthMethod = $Mode; StorePath = $storePath
        }
        if ($null -ne $ClientId) { $arguments.ClientId = $ClientId }
        foreach ($entry in $Extra.GetEnumerator()) { $arguments[$entry.Key] = $entry.Value }

        { Register-GraphTenant @arguments } | Should -Throw -ExpectedMessage $Expected
        $storePath | Should -Not -Exist -Because 'invalid mode metadata must fail before profile-store mutation'
    }

    It 'persists managed-identity selectors only at Credential.ClientId and omits every bearer identity' {
        $miStore = Join-Path $TestDrive 'mi-user.json'
        $bearerStore = Join-Path $TestDrive 'bearer-no-identity.json'
        $selector = '11111111-2222-3333-4444-555555555555'

        $mi = Register-GraphTenant -ProfileId mi-user -Name 'MI user' -Kind lab `
            -TenantId $script:tenantId -Environment Global -AuthMethod ManagedIdentity `
            -ManagedIdentityClientId $selector -StorePath $miStore
        $bearer = Register-GraphTenant -ProfileId bearer -Name Bearer -Kind lab `
            -TenantId $script:tenantId -Environment Global -AuthMethod BearerToken `
            -VaultName v -SecretName s -StorePath $bearerStore

        $mi.ClientId | Should -BeNullOrEmpty
        $mi.Keys | Should -Not -Contain 'ManagedIdentityClientId'
        $mi.Credential.ClientId | Should -BeExactly $selector
        $bearer.ClientId | Should -BeNullOrEmpty
        $bearer.Credential.Keys | Should -Not -Contain 'ClientId'
    }

    It 'preserves valid omission of ManagedIdentityClientId for every authentication mode' -ForEach @(
        @{ Case = 'certificate'; Mode = 'Certificate'; ClientId = '7d6e5f44-9999-8888-7777-666655554444'; Extra = @{ VaultName = 'v'; CertificateName = 'c' } }
        @{ Case = 'client secret'; Mode = 'ClientSecret'; ClientId = '7d6e5f44-9999-8888-7777-666655554444'; Extra = @{ VaultName = 'v'; SecretName = 's' } }
        @{ Case = 'managed identity system'; Mode = 'ManagedIdentity'; ClientId = $null; Extra = @{} }
        @{ Case = 'bearer'; Mode = 'BearerToken'; ClientId = $null; Extra = @{ VaultName = 'v'; SecretName = 's' } }
    ) {
        $storePath = Join-Path $TestDrive ("omit-mi-selector-{0}.json" -f [guid]::NewGuid())
        $arguments = @{
            ProfileId = 'omit-mi-selector'; Name = $Case; Kind = 'lab'; TenantId = $script:tenantId
            Environment = 'Global'; AuthMethod = $Mode; StorePath = $storePath
        }
        if ($null -ne $ClientId) { $arguments.ClientId = $ClientId }
        foreach ($entry in $Extra.GetEnumerator()) { $arguments[$entry.Key] = $entry.Value }

        $profile = Register-GraphTenant @arguments

        $profile.Keys | Should -Not -Contain 'ManagedIdentityClientId'
        $profile.Credential.Keys | Should -Not -Contain 'ManagedIdentityClientId'
        if ($Mode -eq 'ManagedIdentity') {
            $profile.ClientId | Should -BeNullOrEmpty
            $profile.Credential.Keys | Should -Not -Contain 'ClientId'
        }
    }

    It 'rejects an explicitly bound blank ManagedIdentityClientId before profile-store locking' -ForEach @(
        foreach ($valueCase in @(
            @{ Label = 'null'; Value = $null }
            @{ Label = 'empty'; Value = '' }
            @{ Label = 'whitespace'; Value = '  ' }
        )) {
            @{
                Case = "managed identity $($valueCase.Label)"; Mode = 'ManagedIdentity'
                Value = $valueCase.Value; ClientId = $null; Extra = @{}
                Expected = '*Credential.ClientId*non-empty*re-register*'
            }
            @{
                Case = "certificate $($valueCase.Label)"; Mode = 'Certificate'
                Value = $valueCase.Value; ClientId = '7d6e5f44-9999-8888-7777-666655554444'
                Extra = @{ VaultName = 'v'; CertificateName = 'c' }
                Expected = '*unsupported identity selector*Credential.ManagedIdentityClientId*re-register*'
            }
            @{
                Case = "client secret $($valueCase.Label)"; Mode = 'ClientSecret'
                Value = $valueCase.Value; ClientId = '7d6e5f44-9999-8888-7777-666655554444'
                Extra = @{ VaultName = 'v'; SecretName = 's' }
                Expected = '*unsupported identity selector*Credential.ManagedIdentityClientId*re-register*'
            }
            @{
                Case = "bearer $($valueCase.Label)"; Mode = 'BearerToken'
                Value = $valueCase.Value; ClientId = $null
                Extra = @{ VaultName = 'v'; SecretName = 's' }
                Expected = '*unsupported identity selector*Credential.ManagedIdentityClientId*re-register*'
            }
        }
    ) {
        $storePath = Join-Path $TestDrive ("bound-blank-mi-selector-{0}.json" -f [guid]::NewGuid())
        $arguments = @{
            ProfileId = 'bound-blank'; Name = $Case; Kind = 'lab'; TenantId = $script:tenantId
            Environment = 'Global'; AuthMethod = $Mode; StorePath = $storePath
            ManagedIdentityClientId = $Value
        }
        if ($null -ne $ClientId) { $arguments.ClientId = $ClientId }
        foreach ($entry in $Extra.GetEnumerator()) { $arguments[$entry.Key] = $entry.Value }
        Mock Enter-GraphProfileStoreLock -ModuleName GraphKit { throw 'invalid metadata reached profile-store locking' }

        { Register-GraphTenant @arguments } | Should -Throw -ExpectedMessage $Expected
        Should -Invoke Enter-GraphProfileStoreLock -ModuleName GraphKit -Times 0 -Exactly
        $storePath | Should -Not -Exist
    }

    It 'documents the exact identity selector matrix and ships valid application examples' {
        $help = Get-Help Register-GraphTenant -Full
        $clientIdHelp = $help.Parameters.Parameter | Where-Object Name -eq 'ClientId'
        $managedIdentityHelp = $help.Parameters.Parameter | Where-Object Name -eq 'ManagedIdentityClientId'
        $clientIdText = @($clientIdHelp.Description.Text) -join ' '
        $managedIdentityText = @($managedIdentityHelp.Description.Text) -join ' '
        $examples = @($help.Examples.Example | ForEach-Object { [string]$_.Code })
        $clientSecretExample = $examples | Where-Object { $_ -match '-AuthMethod\s+ClientSecret' } | Select-Object -First 1
        $certificateExample = $examples | Where-Object { $_ -match '-AuthMethod\s+Certificate' } | Select-Object -First 1

        $clientIdText | Should -Match '(?i)required.*Certificate.*ClientSecret'
        $clientIdText | Should -Match '(?i)(forbidden|must not).*ManagedIdentity.*BearerToken'
        $managedIdentityText | Should -Match '(?i)registration.*Credential\.ClientId'
        $managedIdentityText | Should -Match '(?i)system-assigned.*omit'
        $clientSecretExample | Should -Match '-ClientId\s+'
        $certificateExample | Should -Match '-ClientId\s+'
    }

    It 'preserves the literal public parameter signature' {
        $command = Get-Command Register-GraphTenant
        $expected = @(
            'AuthMethod', 'Certificate', 'CertificateName', 'CertificatePasswordSecretName',
            'CertificatePasswordVaultName', 'CertificatePasswordVersion', 'CertificateVersion',
            'ClientId', 'Environment', 'Kind', 'ManagedIdentityClientId', 'Name', 'PfxPath',
            'PfxSecretName', 'PfxSecretVersion', 'PfxVaultName', 'ProfileId', 'SecretName',
            'SecretVersion', 'StoreLocation', 'StoreName', 'StorePath', 'Subject', 'TaxonomyAdapter',
            'TenantId', 'Thumbprint', 'TokenProvider', 'VaultName'
        )
        @($command.Parameters.Keys | Where-Object { $_ -notin [System.Management.Automation.PSCmdlet]::CommonParameters -and $_ -notin [System.Management.Automation.PSCmdlet]::OptionalCommonParameters } | Sort-Object) |
            Should -Be ($expected | Sort-Object)
        $command.Parameters.ClientId.ParameterType.FullName | Should -BeExactly 'System.String'
        $command.Parameters.ManagedIdentityClientId.ParameterType.FullName | Should -BeExactly 'System.String'
    }
}
