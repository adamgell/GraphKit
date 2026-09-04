BeforeAll {
    $repoRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $built = Get-ChildItem -Path (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $built) {
        throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first, then re-run the tests.'
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force

    if ($null -eq ('GraphKit.Tests.Task6CredentialFixture' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace GraphKit.Tests;

public static class Task6CredentialFixture
{
    public static X509Certificate2 CreateCertificate()
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new(
            "CN=GraphKit-Task6-Test",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using X509Certificate2 source = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddHours(1));
#pragma warning disable SYSLIB0057
        return new X509Certificate2(
            source.Export(X509ContentType.Pkcs12),
            (string)null,
            X509KeyStorageFlags.Exportable);
#pragma warning restore SYSLIB0057
    }

    public static SecureString CreateSecret()
    {
        SecureString secret = new();
        foreach (char value in "task6-secret")
        {
            secret.AppendChar(value);
        }
        secret.MakeReadOnly();
        return secret;
    }
}
'@
    }

    $script:storePath = Join-Path $TestDrive 'profiles.json'
    InModuleScope GraphKit -Parameters @{ StorePath = $script:storePath } {
        Save-GraphProfileStore -Store @{
            SchemaVersion = 1
            Profiles      = @(
                @{
                    ProfileId   = 'acme'
                    Name        = 'Acme'
                    Kind        = 'customer'
                    TenantId    = '3a4b5c6d-1111-2222-3333-444455556666'
                    ClientId    = '7d6e5f44-9999-8888-7777-666655554444'
                    AuthMethod  = 'ClientSecret'
                    Environment = 'Global'
                    Credential  = @{ VaultName = 'GraphKit'; SecretName = 'acme-secret'; Version = $null }
                },
                @{
                    ProfileId = 'cert'; Name = 'Certificate'; Kind = 'lab'
                    TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
                    ClientId = '7d6e5f44-9999-8888-7777-666655554444'
                    AuthMethod = 'Certificate'; Environment = 'Global'
                    Credential = @{ VaultName = 'GraphKit'; CertificateName = 'cert'; Version = 'v1' }
                },
                @{
                    ProfileId = 'mi-system'; Name = 'MI system'; Kind = 'lab'
                    TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
                    ClientId = $null; AuthMethod = 'ManagedIdentity'; Environment = 'Global'
                    Credential = @{}
                },
                @{
                    ProfileId = 'mi-user'; Name = 'MI user'; Kind = 'lab'
                    TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
                    ClientId = $null; AuthMethod = 'ManagedIdentity'; Environment = 'Global'
                    Credential = @{ ClientId = '11111111-2222-3333-4444-555555555555' }
                },
                @{
                    ProfileId = 'mi-user-alt'; Name = 'MI user alternate format'; Kind = 'lab'
                    TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
                    ClientId = $null; AuthMethod = 'ManagedIdentity'; Environment = 'Global'
                    Credential = @{ ClientId = ' {11111111-2222-3333-4444-555555555555} ' }
                },
                @{
                    ProfileId = 'bearer'; Name = 'Bearer'; Kind = 'lab'
                    TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
                    ClientId = $null; AuthMethod = 'BearerToken'; Environment = 'Global'
                    Credential = @{ VaultName = 'GraphKit'; SecretName = 'bearer'; Version = 'v1' }
                }
            )
        } -StorePath $StorePath
    }
}

Describe 'Get-GraphContext' {

    BeforeEach {
        Mock Get-GraphVaultCredential -ModuleName GraphKit {
            param($Credential, $VaultName, $AuthMethod)
            $null = $Credential
            $null = $VaultName
            switch ($AuthMethod) {
                Certificate {
                    [pscustomobject]@{
                        AuthMethod = 'Certificate'
                        Material = [GraphKit.Tests.Task6CredentialFixture]::CreateCertificate()
                        OwnsMaterial = $true
                        CredentialGeneration = 'g1|Certificate|fixture'
                    }
                }
                ClientSecret {
                    [pscustomobject]@{
                        AuthMethod = 'ClientSecret'
                        Material = [GraphKit.Tests.Task6CredentialFixture]::CreateSecret()
                        OwnsMaterial = $true
                        CredentialGeneration = 'g1|ClientSecret|fixture'
                    }
                }
                BearerToken {
                    [pscustomobject]@{
                        AuthMethod = 'BearerToken'
                        Material = 'fixed-bearer-fixture'
                        OwnsMaterial = $false
                        CredentialGeneration = 'g1|BearerToken|fixture'
                    }
                }
                ManagedIdentity {
                    [pscustomobject]@{
                        AuthMethod = 'ManagedIdentity'
                        Material = $null
                        ManagedIdentityClientId = $Credential.ClientId
                        OwnsMaterial = $false
                        CredentialGeneration = 'g1|ManagedIdentity|fixture'
                    }
                }
            }
        }
    }

    It 'resolves a context with zero acquisitions (MsalFactory that throws if invoked)' {
        $factory = { throw 'MSAL must not be invoked during context resolution' }
        $context = Get-GraphContext -ProfileId 'acme' -StorePath $script:storePath -MsalFactory $factory

        $context.IdentityState | Should -Be 'NotAcquired'
        $context.TokenSource | Should -Not -BeNullOrEmpty
        $context.TokenSource.AuthMode | Should -Be 'ClientSecret'
    }

    It 'exposes the exact GraphKit.Context field set' {
        $factory = { throw 'not invoked' }
        $context = Get-GraphContext -ProfileId 'acme' -StorePath $script:storePath -MsalFactory $factory

        $expected = @('ProfileId', 'TenantId', 'Cloud', 'GraphBaseUri', 'ClientId', 'TokenSource', 'CredentialFingerprint', 'AcquisitionCacheKey', 'IdentityState')
        @($context.PSObject.Properties.Name | Sort-Object) | Should -Be ($expected | Sort-Object)
        $context.PSTypeNames -contains 'GraphKit.Context' | Should -BeTrue
    }

    It 'normalizes TenantId and GraphBaseUri to their contract types' {
        $context = Get-GraphContext -ProfileId 'acme' -StorePath $script:storePath -MsalFactory { throw 'not invoked' }

        $context.TenantId | Should -Be ([guid]'3a4b5c6d-1111-2222-3333-444455556666')
        $context.GraphBaseUri | Should -Be ([uri]'https://graph.microsoft.com')
        $context.ClientId | Should -Be ([guid]'7d6e5f44-9999-8888-7777-666655554444')
        $context.CredentialFingerprint | Should -Match '^[0-9a-f]{64}$'
    }

    It 'supports an injected token provider for context-only use' {
        $provider = { @{ Token = 'provider-token'; ExpiresOnUtc = (Get-Date).ToUniversalTime().AddHours(1) } }
        $context = Get-GraphContext -ProfileId 'acme' -StorePath $script:storePath -TokenProvider $provider

        $context.TokenSource.AuthMode | Should -Be 'Provider'
        $context.TokenSource.CanRefresh | Should -BeTrue
        $context.IdentityState | Should -Be 'NotAcquired'
    }

    It 'supports an injected certificate for context-only use' {
        $cert = [GraphKit.Tests.Task6CredentialFixture]::CreateCertificate()
        $context = Get-GraphContext -ProfileId 'acme' -StorePath $script:storePath -Certificate $cert -MsalFactory { throw 'not invoked' }

        $context.TokenSource.AuthMode | Should -Be 'Certificate'
        $context.TokenSource.CanRefresh | Should -BeTrue
        $context.IdentityState | Should -Be 'NotAcquired'
        $cert.Dispose()
    }

    It 'routes every persisted built-in to the exact compiled ABI without acquiring a token' -ForEach @(
        @{ ProfileId = 'acme'; Mode = 'ClientSecret'; ExpectedClientId = '7d6e5f44-9999-8888-7777-666655554444'; RequestClientId = '7d6e5f44-9999-8888-7777-666655554444'; ManagedIdentityClientId = $null }
        @{ ProfileId = 'cert'; Mode = 'Certificate'; ExpectedClientId = '7d6e5f44-9999-8888-7777-666655554444'; RequestClientId = '7d6e5f44-9999-8888-7777-666655554444'; ManagedIdentityClientId = $null }
        @{ ProfileId = 'mi-system'; Mode = 'ManagedIdentity'; ExpectedClientId = $null; RequestClientId = $null; ManagedIdentityClientId = $null }
        @{ ProfileId = 'mi-user'; Mode = 'ManagedIdentity'; ExpectedClientId = '11111111-2222-3333-4444-555555555555'; RequestClientId = $null; ManagedIdentityClientId = '11111111-2222-3333-4444-555555555555' }
        @{ ProfileId = 'bearer'; Mode = 'BearerToken'; ExpectedClientId = $null; RequestClientId = $null; ManagedIdentityClientId = $null }
    ) {
        $context = Get-GraphContext -ProfileId $ProfileId -StorePath $script:storePath

        $context.TokenSource -is [GraphKit.Auth.IGraphTokenSource] | Should -BeTrue
        $context.TokenSource.AuthMode | Should -BeExactly $Mode
        [string]$context.ClientId | Should -BeExactly ([string]$ExpectedClientId)
        $context.IdentityState | Should -BeExactly 'NotAcquired'
        $context.TokenSource.ExpiresOn | Should -Be ([datetimeoffset]::MinValue)

        $inner = [GraphKit.Auth.IGraphTokenSource].Assembly.GetType(
            'GraphKit.Auth.GraphTokenSourceProxy', $true, $false
        ).GetField('_inner', [Reflection.BindingFlags]'Instance,NonPublic').GetValue($context.TokenSource)
        $providerClientId = $inner.GetType().GetField('_clientId', [Reflection.BindingFlags]'Instance,NonPublic').GetValue($inner)
        $credential = $inner.GetType().GetField('_credentialReference', [Reflection.BindingFlags]'Instance,NonPublic').GetValue($inner)
        if ($Mode -eq 'ManagedIdentity') {
            # A successful ABI request proves its application ClientId was null:
            # the frozen constructor rejects any ClientId for ManagedIdentity.
            $credential.GetType().FullName | Should -BeExactly 'GraphKit.Auth.ManagedIdentityCredential'
            [string]$credential.UserAssignedClientId | Should -BeExactly ([string]$ManagedIdentityClientId)
            [string]$providerClientId | Should -BeExactly ([string]$ManagedIdentityClientId)
        }
        elseif ($Mode -eq 'BearerToken') {
            # The same frozen request constructor rejects a bearer application
            # ClientId, while the provider retains no source client identity.
            $credential.GetType().FullName | Should -BeExactly 'GraphKit.Auth.FixedBearerCredential'
            $providerClientId | Should -BeNullOrEmpty
        }
        else {
            [string]$providerClientId | Should -BeExactly ([string]$RequestClientId)
        }
    }

    It 'keeps every -MsalFactory built-in on the same-runspace legacy path, including bearer' -ForEach @(
        @{ ProfileId = 'acme'; ExpectedType = 'ConfidentialClientTokenSource' }
        @{ ProfileId = 'cert'; ExpectedType = 'ConfidentialClientTokenSource' }
        @{ ProfileId = 'mi-system'; ExpectedType = 'ManagedIdentityTokenSource' }
        @{ ProfileId = 'mi-user'; ExpectedType = 'ManagedIdentityTokenSource' }
        @{ ProfileId = 'bearer'; ExpectedType = 'FixedBearerTokenSource' }
    ) {
        $context = Get-GraphContext -ProfileId $ProfileId -StorePath $script:storePath `
            -MsalFactory { throw 'construction must not invoke the compatibility factory' }

        $context.TokenSource.GetType().Name | Should -BeExactly $ExpectedType
        $context.TokenSource -is [GraphKit.Auth.IGraphTokenSource] | Should -BeFalse
    }

    It 'uses a compiled caller-owned source for an injected certificate unless a compatibility factory is supplied' {
        $compiledCertificate = [GraphKit.Tests.Task6CredentialFixture]::CreateCertificate()
        $legacyCertificate = [GraphKit.Tests.Task6CredentialFixture]::CreateCertificate()
        try {
            $compiled = Get-GraphContext -ProfileId 'acme' -StorePath $script:storePath -Certificate $compiledCertificate
            $legacy = Get-GraphContext -ProfileId 'acme' -StorePath $script:storePath `
                -Certificate $legacyCertificate -MsalFactory { throw 'not invoked' }

            $compiled.TokenSource -is [GraphKit.Auth.IGraphTokenSource] | Should -BeTrue
            $legacy.TokenSource.GetType().Name | Should -BeExactly 'ConfidentialClientTokenSource'
            $compiled.TokenSource.Dispose()
            { $null = $compiledCertificate.GetCertHash() } | Should -Not -Throw -Because 'caller-owned injected material survives source disposal'
        }
        finally {
            $compiledCertificate.Dispose()
            $legacyCertificate.Dispose()
        }
    }

    It 'rejects an invalid persisted mode identity before any credential or vault access' {
        $invalidPath = Join-Path $TestDrive 'invalid-bearer-identity.json'
        InModuleScope GraphKit -Parameters @{ StorePath = $invalidPath } {
            Save-GraphProfileStore -Store @{
                SchemaVersion = 1
                Profiles = @(@{
                    ProfileId = 'invalid'; Name = 'Invalid'; Kind = 'lab'
                    TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
                    ClientId = '7d6e5f44-9999-8888-7777-666655554444'
                    AuthMethod = 'BearerToken'; Environment = 'Global'
                    Credential = @{ VaultName = 'GraphKit'; SecretName = 'bearer' }
                })
            } -StorePath $StorePath
        }

        { Get-GraphContext -ProfileId invalid -StorePath $invalidPath } |
            Should -Throw -ExpectedMessage '*BearerToken*re-register*'
        Should -Invoke Get-GraphVaultCredential -ModuleName GraphKit -Times 0 -Exactly
    }

    It 'rejects persisted managed-identity selector aliases before material or source work' -ForEach @(
        @{
            Case = 'top-level selector only'
            TopLevelSelector = '11111111-2222-3333-4444-555555555555'
            Credential = @{}
        }
        @{
            Case = 'top-level selector alongside canonical nested selector'
            TopLevelSelector = '11111111-2222-3333-4444-555555555555'
            Credential = @{ ClientId = '22222222-3333-4444-5555-666666666666' }
        }
        @{
            Case = 'alternate nested selector spelling'
            TopLevelSelector = $null
            Credential = @{ ManagedIdentityClientId = '11111111-2222-3333-4444-555555555555' }
        }
    ) {
        $invalidPath = Join-Path $TestDrive ("invalid-mi-{0}.json" -f [guid]::NewGuid())
        $profile = @{
            ProfileId = 'invalid-mi'; Name = $Case; Kind = 'lab'
            TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
            ClientId = $null; AuthMethod = 'ManagedIdentity'; Environment = 'Global'
            Credential = $Credential
        }
        if ($null -ne $TopLevelSelector) {
            $profile.ManagedIdentityClientId = $TopLevelSelector
        }
        InModuleScope GraphKit -Parameters @{ StorePath = $invalidPath; Profile = $profile } {
            Save-GraphProfileStore -Store @{ SchemaVersion = 1; Profiles = @($Profile) } -StorePath $StorePath
        }
        $ownedBefore = InModuleScope GraphKit { $script:GraphKitModuleLifecycle.OwnedResources.Count }

        { Get-GraphContext -ProfileId invalid-mi -StorePath $invalidPath } |
            Should -Throw -ExpectedMessage '*ManagedIdentity*re-register*'

        Should -Invoke Get-GraphVaultCredential -ModuleName GraphKit -Times 0 -Exactly
        (InModuleScope GraphKit { $script:GraphKitModuleLifecycle.OwnedResources.Count }) |
            Should -Be $ownedBefore -Because 'invalid persisted selectors must fail before source construction'
    }

    It 'rejects a present canonical nested selector with no value before vault or source work' -ForEach @(
        @{ Case = 'certificate null'; Mode = 'Certificate'; TopClientId = '7d6e5f44-9999-8888-7777-666655554444'; Credential = @{ VaultName = 'v'; CertificateName = 'c'; ClientId = $null } }
        @{ Case = 'certificate empty'; Mode = 'Certificate'; TopClientId = '7d6e5f44-9999-8888-7777-666655554444'; Credential = @{ VaultName = 'v'; CertificateName = 'c'; ClientId = '' } }
        @{ Case = 'certificate whitespace'; Mode = 'Certificate'; TopClientId = '7d6e5f44-9999-8888-7777-666655554444'; Credential = @{ VaultName = 'v'; CertificateName = 'c'; ClientId = '  ' } }
        @{ Case = 'client secret null'; Mode = 'ClientSecret'; TopClientId = '7d6e5f44-9999-8888-7777-666655554444'; Credential = @{ VaultName = 'v'; SecretName = 's'; ClientId = $null } }
        @{ Case = 'client secret empty'; Mode = 'ClientSecret'; TopClientId = '7d6e5f44-9999-8888-7777-666655554444'; Credential = @{ VaultName = 'v'; SecretName = 's'; ClientId = '' } }
        @{ Case = 'client secret whitespace'; Mode = 'ClientSecret'; TopClientId = '7d6e5f44-9999-8888-7777-666655554444'; Credential = @{ VaultName = 'v'; SecretName = 's'; ClientId = '  ' } }
        @{ Case = 'managed identity null'; Mode = 'ManagedIdentity'; TopClientId = $null; Credential = @{ ClientId = $null } }
        @{ Case = 'managed identity empty'; Mode = 'ManagedIdentity'; TopClientId = $null; Credential = @{ ClientId = '' } }
        @{ Case = 'managed identity whitespace'; Mode = 'ManagedIdentity'; TopClientId = $null; Credential = @{ ClientId = '  ' } }
        @{ Case = 'bearer null'; Mode = 'BearerToken'; TopClientId = $null; Credential = @{ VaultName = 'v'; SecretName = 's'; ClientId = $null } }
        @{ Case = 'bearer empty'; Mode = 'BearerToken'; TopClientId = $null; Credential = @{ VaultName = 'v'; SecretName = 's'; ClientId = '' } }
        @{ Case = 'bearer whitespace'; Mode = 'BearerToken'; TopClientId = $null; Credential = @{ VaultName = 'v'; SecretName = 's'; ClientId = '  ' } }
    ) {
        $invalidPath = Join-Path $TestDrive ("invalid-present-selector-{0}.json" -f [guid]::NewGuid())
        $profile = @{
            ProfileId = 'invalid-present'; Name = $Case; Kind = 'lab'
            TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
            ClientId = $TopClientId; AuthMethod = $Mode; Environment = 'Global'
            Credential = $Credential
        }
        InModuleScope GraphKit -Parameters @{ StorePath = $invalidPath; Profile = $profile } {
            Save-GraphProfileStore -Store @{ SchemaVersion = 1; Profiles = @($Profile) } -StorePath $StorePath
        }
        Mock New-GraphTokenSource -ModuleName GraphKit { throw 'invalid selector reached source construction' }

        { Get-GraphContext -ProfileId invalid-present -StorePath $invalidPath } |
            Should -Throw -ExpectedMessage '*re-register*'

        Should -Invoke Get-GraphVaultCredential -ModuleName GraphKit -Times 0 -Exactly
        Should -Invoke New-GraphTokenSource -ModuleName GraphKit -Times 0 -Exactly
    }

    It 'rejects a non-null blank top-level ClientId for non-application modes before source work' -ForEach @(
        @{ Case = 'managed identity empty'; Mode = 'ManagedIdentity'; TopClientId = ''; Credential = @{} }
        @{ Case = 'managed identity whitespace'; Mode = 'ManagedIdentity'; TopClientId = '  '; Credential = @{} }
        @{ Case = 'bearer empty'; Mode = 'BearerToken'; TopClientId = ''; Credential = @{ VaultName = 'v'; SecretName = 's' } }
        @{ Case = 'bearer whitespace'; Mode = 'BearerToken'; TopClientId = '  '; Credential = @{ VaultName = 'v'; SecretName = 's' } }
    ) {
        $invalidPath = Join-Path $TestDrive ("invalid-top-level-blank-{0}.json" -f [guid]::NewGuid())
        $profile = @{
            ProfileId = 'invalid-top'; Name = $Case; Kind = 'lab'
            TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
            ClientId = $TopClientId; AuthMethod = $Mode; Environment = 'Global'
            Credential = $Credential
        }
        InModuleScope GraphKit -Parameters @{ StorePath = $invalidPath; Profile = $profile } {
            Save-GraphProfileStore -Store @{ SchemaVersion = 1; Profiles = @($Profile) } -StorePath $StorePath
        }
        Mock New-GraphTokenSource -ModuleName GraphKit { throw 'blank top-level selector reached source construction' }

        { Get-GraphContext -ProfileId invalid-top -StorePath $invalidPath } |
            Should -Throw -ExpectedMessage '*re-register*'
        Should -Invoke New-GraphTokenSource -ModuleName GraphKit -Times 0 -Exactly
    }

    It 'rejects object and resource selector aliases by key presence before vault or source work' -ForEach @(
        foreach ($selectorName in @('ObjectId', 'ResourceId', 'ManagedIdentityObjectId', 'ManagedIdentityResourceId')) {
            foreach ($location in @('Profile', 'Credential')) {
                @{ Case = "$location.$selectorName"; SelectorName = $selectorName; Location = $location }
            }
        }
    ) {
        $invalidPath = Join-Path $TestDrive ("invalid-selector-alias-{0}.json" -f [guid]::NewGuid())
        $credential = @{}
        $profile = @{
            ProfileId = 'invalid-alias'; Name = $Case; Kind = 'lab'
            TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
            ClientId = $null; AuthMethod = 'ManagedIdentity'; Environment = 'Global'
            Credential = $credential
        }
        if ($Location -eq 'Profile') {
            $profile[$SelectorName] = $null
        }
        else {
            $credential[$SelectorName] = $null
        }
        InModuleScope GraphKit -Parameters @{ StorePath = $invalidPath; Profile = $profile } {
            Save-GraphProfileStore -Store @{ SchemaVersion = 1; Profiles = @($Profile) } -StorePath $StorePath
        }
        Mock New-GraphTokenSource -ModuleName GraphKit { throw 'invalid selector alias reached source construction' }

        { Get-GraphContext -ProfileId invalid-alias -StorePath $invalidPath } |
            Should -Throw -ExpectedMessage '*unsupported identity selector*re-register*'

        Should -Invoke Get-GraphVaultCredential -ModuleName GraphKit -Times 0 -Exactly
        Should -Invoke New-GraphTokenSource -ModuleName GraphKit -Times 0 -Exactly
    }

    It 'does not collapse distinct invalid top-level managed-identity selectors into system identity' {
        $invalidPath = Join-Path $TestDrive 'invalid-mi-collision.json'
        $profiles = @(
            @{
                ProfileId = 'invalid-mi-a'; Name = 'Invalid A'; Kind = 'lab'
                TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
                ClientId = $null; ManagedIdentityClientId = '11111111-2222-3333-4444-555555555555'
                AuthMethod = 'ManagedIdentity'; Environment = 'Global'; Credential = @{}
            }
            @{
                ProfileId = 'invalid-mi-b'; Name = 'Invalid B'; Kind = 'lab'
                TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
                ClientId = $null; ManagedIdentityClientId = '22222222-3333-4444-5555-666666666666'
                AuthMethod = 'ManagedIdentity'; Environment = 'Global'; Credential = @{}
            }
        )
        InModuleScope GraphKit -Parameters @{ StorePath = $invalidPath; Profiles = $profiles } {
            Save-GraphProfileStore -Store @{ SchemaVersion = 1; Profiles = $Profiles } -StorePath $StorePath
        }

        foreach ($profileId in @('invalid-mi-a', 'invalid-mi-b')) {
            { Get-GraphContext -ProfileId $profileId -StorePath $invalidPath } |
                Should -Throw -ExpectedMessage '*ManagedIdentityClientId*re-register*'
        }

        Should -Invoke Get-GraphVaultCredential -ModuleName GraphKit -Times 0 -Exactly
    }

    It 'canonicalizes one managed-identity selector for compiled and compatibility paths' {
        $script:Task6ManagedIdentityResolverSelectors = [System.Collections.Generic.List[string]]::new()
        Mock Get-GraphVaultCredential -ModuleName GraphKit -ParameterFilter { $AuthMethod -eq 'ManagedIdentity' } {
            $selector = [string] $Credential.ClientId
            $script:Task6ManagedIdentityResolverSelectors.Add($selector)
            [pscustomobject]@{
                AuthMethod = 'ManagedIdentity'
                Material = $null
                ManagedIdentityClientId = $selector
                OwnsMaterial = $false
                CredentialGeneration = "g1|ManagedIdentity|$selector"
            }
        }

        $compiledCanonical = Get-GraphContext -ProfileId mi-user -StorePath $script:storePath
        $compiledAlternate = Get-GraphContext -ProfileId mi-user-alt -StorePath $script:storePath
        $legacyCanonical = Get-GraphContext -ProfileId mi-user -StorePath $script:storePath `
            -MsalFactory { throw 'canonicalization test must not acquire' }
        $legacyAlternate = Get-GraphContext -ProfileId mi-user-alt -StorePath $script:storePath `
            -MsalFactory { throw 'canonicalization test must not acquire' }

        @($script:Task6ManagedIdentityResolverSelectors) | Should -Be @(
            '11111111-2222-3333-4444-555555555555',
            '11111111-2222-3333-4444-555555555555'
        )
        [string]$compiledAlternate.ClientId | Should -BeExactly ([string]$compiledCanonical.ClientId)
        $compiledAlternate.TokenSource.ClientId | Should -BeExactly $compiledCanonical.TokenSource.ClientId
        $compiledAlternate.TokenSource.CredentialGeneration | Should -BeExactly $compiledCanonical.TokenSource.CredentialGeneration
        $compiledAlternate.AcquisitionCacheKey | Should -BeExactly $compiledCanonical.AcquisitionCacheKey
        $legacyAlternate.TokenSource.ClientId | Should -BeExactly $legacyCanonical.TokenSource.ClientId
        $legacyAlternate.TokenSource.CredentialGeneration | Should -BeExactly $legacyCanonical.TokenSource.CredentialGeneration
        $legacyAlternate.AcquisitionCacheKey | Should -BeExactly $legacyCanonical.AcquisitionCacheKey
        $legacyAlternate.TokenSource.ClientId | Should -BeExactly '11111111-2222-3333-4444-555555555555'
    }

    It 'preserves the literal public parameter signature' {
        $command = Get-Command Get-GraphContext
        @($command.Parameters.Keys | Where-Object { $_ -notin [System.Management.Automation.PSCmdlet]::CommonParameters -and $_ -notin [System.Management.Automation.PSCmdlet]::OptionalCommonParameters } | Sort-Object) |
            Should -Be @('Certificate', 'MsalFactory', 'ProfileId', 'StorePath', 'TokenProvider')
        $command.Parameters.ProfileId.ParameterType.FullName | Should -BeExactly 'System.String'
        $command.Parameters.Certificate.ParameterType.FullName | Should -BeExactly 'System.Security.Cryptography.X509Certificates.X509Certificate2'
        $command.Parameters.TokenProvider.ParameterType.FullName | Should -BeExactly 'System.Management.Automation.ScriptBlock'
        $command.Parameters.MsalFactory.ParameterType.FullName | Should -BeExactly 'System.Management.Automation.ScriptBlock'
    }

    It 'rejects an unknown profile' {
        { Get-GraphContext -ProfileId 'missing' -StorePath $script:storePath -MsalFactory { throw 'not invoked' } } |
            Should -Throw -ExpectedMessage '*No profile with ProfileId*'
    }
}
