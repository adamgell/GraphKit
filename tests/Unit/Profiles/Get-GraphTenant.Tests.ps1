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
                @{ ProfileId = 'acme'; Name = 'Acme'; Kind = 'customer'; TenantId = '3a4b5c6d-1111-2222-3333-444455556666'; AuthMethod = 'ClientSecret'; Environment = 'Global'; Credential = @{ VaultName = 'v'; SecretName = 's' } },
                @{ ProfileId = 'lab01'; Name = 'Lab'; Kind = 'lab'; TenantId = '7d6e5f44-9999-8888-7777-666655554444'; AuthMethod = 'ManagedIdentity'; Environment = 'Global'; Credential = @{ ClientId = $null } }
            )
        } -StorePath $StorePath
    }
}

Describe 'Get-GraphTenant' {

    It 'lists every registered profile when no ProfileId is supplied' {
        @(Get-GraphTenant -StorePath $script:storePath).Count | Should -Be 2
    }

    It 'returns a single profile by ProfileId' {
        $profile = Get-GraphTenant -ProfileId 'acme' -StorePath $script:storePath
        $profile.ProfileId | Should -Be 'acme'
        $profile.Credential.SecretName | Should -Be 's'
    }

    It 'never accepts Name as a selector' {
        (Get-Command Get-GraphTenant).Parameters.ContainsKey('Name') | Should -BeFalse
    }

    It 'rejects an invalid ProfileId' {
        { Get-GraphTenant -ProfileId 'BAD!' -StorePath $script:storePath } | Should -Throw -ExpectedMessage '*not a valid canonical*'
    }

    It 'errors when the ProfileId does not exist' {
        { Get-GraphTenant -ProfileId 'missing' -StorePath $script:storePath } | Should -Throw -ExpectedMessage '*No profile with ProfileId*'
    }
}
