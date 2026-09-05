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
                @{ ProfileId = 'acme'; Name = 'Acme'; Kind = 'customer'; TenantId = '3a4b5c6d-1111-2222-3333-444455556666'; ClientId = '11111111-2222-3333-4444-555555555555'; AuthMethod = 'ClientSecret'; Environment = 'Global'; Credential = @{ VaultName = 'v'; SecretName = 's' } }
            )
        } -StorePath $StorePath
    }
}

Describe 'Use-GraphTenant' {

    BeforeEach {
        Mock Get-GraphVaultCredential -ModuleName GraphKit {
            $material = [Security.SecureString]::new()
            $material.AppendChar('x')
            $material.MakeReadOnly()
            [pscustomobject]@{
                AuthMethod           = 'ClientSecret'
                Material             = $material
                OwnsMaterial         = $true
                CredentialGeneration = 'g1|ClientSecret|fixture'
            }
        }
    }

    It 'sets the script-scoped current context and returns it' {
        $context = Use-GraphTenant -ProfileId 'acme' -StorePath $script:storePath

        $context.PSTypeNames -contains 'GraphKit.Context' | Should -BeTrue
        $current = InModuleScope GraphKit { $script:GraphKitCurrentContext }
        $current | Should -Be $context
        $current.ProfileId | Should -Be 'acme'
    }

    It 'requires an existing profile' {
        { Use-GraphTenant -ProfileId 'missing' -StorePath $script:storePath } | Should -Throw -ExpectedMessage '*No profile with ProfileId*'
    }
}
