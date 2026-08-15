BeforeAll {
    $repoRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $built = Get-ChildItem -Path (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $built) {
        throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first, then re-run the tests.'
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force

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
                }
            )
        } -StorePath $StorePath
    }
}

Describe 'Get-GraphContext' {

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
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
        $context = Get-GraphContext -ProfileId 'acme' -StorePath $script:storePath -Certificate $cert -MsalFactory { throw 'not invoked' }

        $context.TokenSource.AuthMode | Should -Be 'Certificate'
        $context.TokenSource.CanRefresh | Should -BeTrue
        $context.IdentityState | Should -Be 'NotAcquired'
    }

    It 'rejects an unknown profile' {
        { Get-GraphContext -ProfileId 'missing' -StorePath $script:storePath -MsalFactory { throw 'not invoked' } } |
            Should -Throw -ExpectedMessage '*No profile with ProfileId*'
    }
}
