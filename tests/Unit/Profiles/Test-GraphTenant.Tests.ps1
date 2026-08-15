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
                @{ ProfileId = 'acme'; Name = 'Acme'; Kind = 'customer'; TenantId = '3a4b5c6d-1111-2222-3333-444455556666'; ClientId = '7d6e5f44-9999-8888-7777-666655554444'; AuthMethod = 'ClientSecret'; Environment = 'Global'; Credential = @{ VaultName = 'v'; SecretName = 's' } }
            )
        } -StorePath $StorePath
    }
}

Describe 'Test-GraphTenant' {

    It 'accepts a valid profile' {
        Test-GraphTenant -TenantProfile @{
            ProfileId = 'acme'; Name = 'Acme'; Kind = 'lab'; TenantId = '3a4b5c6d-1111-2222-3333-444455556666'; AuthMethod = 'ClientSecret'; Environment = 'Global'
        } | Should -BeTrue
    }

    It 'rejects a profile missing a required field' {
        Test-GraphTenant -TenantProfile @{
            ProfileId = 'acme'; TenantId = '3a4b5c6d-1111-2222-3333-444455556666'; AuthMethod = 'ClientSecret'; Environment = 'Global'
        } | Should -BeFalse
    }

    It 'rejects an invalid ProfileId regex' {
        Test-GraphTenant -TenantProfile @{
            ProfileId = 'BAD!'; Name = 'X'; Kind = 'lab'; TenantId = '3a4b5c6d-1111-2222-3333-444455556666'; AuthMethod = 'ClientSecret'; Environment = 'Global'
        } | Should -BeFalse
    }

    It 'rejects an invalid TenantId GUID' {
        Test-GraphTenant -TenantProfile @{
            ProfileId = 'acme'; Name = 'X'; Kind = 'lab'; TenantId = 'nope'; AuthMethod = 'ClientSecret'; Environment = 'Global'
        } | Should -BeFalse
    }

    It 'rejects an invalid ClientId GUID' {
        Test-GraphTenant -TenantProfile @{
            ProfileId = 'acme'; Name = 'X'; Kind = 'lab'; TenantId = '3a4b5c6d-1111-2222-3333-444455556666'; ClientId = 'nope'; AuthMethod = 'ClientSecret'; Environment = 'Global'
        } | Should -BeFalse
    }

    It 'rejects an unknown Environment' {
        Test-GraphTenant -TenantProfile @{
            ProfileId = 'acme'; Name = 'X'; Kind = 'lab'; TenantId = '3a4b5c6d-1111-2222-3333-444455556666'; AuthMethod = 'ClientSecret'; Environment = 'Mars'
        } | Should -BeFalse
    }

    It 'validates a stored profile by ProfileId without any network call' {
        Test-GraphTenant -ProfileId 'acme' -StorePath $script:storePath | Should -BeTrue
        Test-GraphTenant -ProfileId 'missing' -StorePath $script:storePath | Should -BeFalse
    }
}
