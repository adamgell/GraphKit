BeforeAll {
    $repoRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $built = Get-ChildItem -Path (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $built) {
        throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first, then re-run the tests.'
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force

    $script:storePath = Join-Path $TestDrive 'profiles.json'
}

Describe 'Remove-GraphTenant' {

    It 'removes an existing profile' {
        InModuleScope GraphKit -Parameters @{ StorePath = $script:storePath } {
            Save-GraphProfileStore -Store @{
                SchemaVersion = 1
                Profiles      = @(
                    @{ ProfileId = 'acme'; Name = 'Acme'; Kind = 'customer'; TenantId = '3a4b5c6d-1111-2222-3333-444455556666'; AuthMethod = 'ClientSecret'; Environment = 'Global'; Credential = @{ VaultName = 'v'; SecretName = 's' } },
                    @{ ProfileId = 'lab01'; Name = 'Lab'; Kind = 'lab'; TenantId = '7d6e5f44-9999-8888-7777-666655554444'; AuthMethod = 'ManagedIdentity'; Environment = 'Global'; Credential = @{ ClientId = $null } }
                )
            } -StorePath $StorePath
        }

        Remove-GraphTenant -ProfileId 'acme' -StorePath $script:storePath -Confirm:$false

        $store = InModuleScope GraphKit -Parameters @{ StorePath = $script:storePath } {
            Get-GraphProfileStore -StorePath $StorePath
        }
        @($store.Profiles).Count | Should -Be 1
        $store.Profiles[0].ProfileId | Should -Be 'lab01'
    }

    It 'rejects an invalid ProfileId' {
        { Remove-GraphTenant -ProfileId 'INVALID!' -StorePath $script:storePath -Confirm:$false } |
            Should -Throw -ExpectedMessage '*not a valid canonical*'
    }

    It 'errors when the profile does not exist' {
        { Remove-GraphTenant -ProfileId 'missing' -StorePath $script:storePath -Confirm:$false } |
            Should -Throw -ExpectedMessage '*No profile with ProfileId*'
    }
}
