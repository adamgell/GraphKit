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
            ProfileId = 'acme'; Name = 'Acme'; Kind = 'lab'; TenantId = '3a4b5c6d-1111-2222-3333-444455556666'; ClientId = '7d6e5f44-9999-8888-7777-666655554444'; AuthMethod = 'ClientSecret'; Environment = 'Global'; Credential = @{ VaultName = 'v'; SecretName = 's' }
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

    It 'accepts the exact valid identity shape for each built-in auth mode' -ForEach @(
        @{ Mode = 'Certificate'; ClientId = '7d6e5f44-9999-8888-7777-666655554444'; Credential = @{ VaultName = 'v'; CertificateName = 'cert' } }
        @{ Mode = 'ClientSecret'; ClientId = '7d6e5f44-9999-8888-7777-666655554444'; Credential = @{ VaultName = 'v'; SecretName = 's' } }
        @{ Mode = 'ManagedIdentity'; ClientId = $null; Credential = @{} }
        @{ Mode = 'ManagedIdentity'; ClientId = $null; Credential = @{ ClientId = '11111111-2222-3333-4444-555555555555' } }
        @{ Mode = 'BearerToken'; ClientId = $null; Credential = @{ VaultName = 'v'; SecretName = 's' } }
    ) {
        Test-GraphTenant -TenantProfile @{
            ProfileId = 'valid'; Name = 'Valid'; Kind = 'lab'
            TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
            ClientId = $ClientId; AuthMethod = $Mode; Environment = 'Global'; Credential = $Credential
        } | Should -BeTrue
    }

    It 'rejects the exact same contradictory identity matrix as registration and context construction' -ForEach @(
        @{ Case = 'certificate missing app id'; Mode = 'Certificate'; ClientId = $null; Credential = @{ VaultName = 'v'; CertificateName = 'cert' } }
        @{ Case = 'certificate nested MI id'; Mode = 'Certificate'; ClientId = '7d6e5f44-9999-8888-7777-666655554444'; Credential = @{ VaultName = 'v'; CertificateName = 'cert'; ClientId = '11111111-2222-3333-4444-555555555555' } }
        @{ Case = 'secret missing app id'; Mode = 'ClientSecret'; ClientId = $null; Credential = @{ VaultName = 'v'; SecretName = 's' } }
        @{ Case = 'secret zero app id'; Mode = 'ClientSecret'; ClientId = '00000000-0000-0000-0000-000000000000'; Credential = @{ VaultName = 'v'; SecretName = 's' } }
        @{ Case = 'MI top-level app id'; Mode = 'ManagedIdentity'; ClientId = '7d6e5f44-9999-8888-7777-666655554444'; Credential = @{} }
        @{ Case = 'MI invalid selector'; Mode = 'ManagedIdentity'; ClientId = $null; Credential = @{ ClientId = 'nope' } }
        @{ Case = 'MI zero selector'; Mode = 'ManagedIdentity'; ClientId = $null; Credential = @{ ClientId = '00000000-0000-0000-0000-000000000000' } }
        @{ Case = 'bearer app id'; Mode = 'BearerToken'; ClientId = '7d6e5f44-9999-8888-7777-666655554444'; Credential = @{ VaultName = 'v'; SecretName = 's' } }
        @{ Case = 'bearer nested id'; Mode = 'BearerToken'; ClientId = $null; Credential = @{ VaultName = 'v'; SecretName = 's'; ClientId = '11111111-2222-3333-4444-555555555555' } }
    ) {
        Test-GraphTenant -TenantProfile @{
            ProfileId = 'invalid'; Name = $Case; Kind = 'lab'
            TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
            ClientId = $ClientId; AuthMethod = $Mode; Environment = 'Global'; Credential = $Credential
        } | Should -BeFalse
    }

    It 'rejects persisted managed-identity selector aliases identically' -ForEach @(
        @{
            Case = 'top-level selector only'
            TopLevelSelector = '11111111-2222-3333-4444-555555555555'
            Credential = @{}
        }
        @{
            Case = 'top-level and canonical nested selectors'
            TopLevelSelector = '11111111-2222-3333-4444-555555555555'
            Credential = @{ ClientId = '22222222-3333-4444-5555-666666666666' }
        }
        @{
            Case = 'alternate nested selector spelling'
            TopLevelSelector = $null
            Credential = @{ ManagedIdentityClientId = '11111111-2222-3333-4444-555555555555' }
        }
    ) {
        $profile = @{
            ProfileId = 'invalid-mi'; Name = $Case; Kind = 'lab'
            TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
            ClientId = $null; AuthMethod = 'ManagedIdentity'; Environment = 'Global'
            Credential = $Credential
        }
        if ($null -ne $TopLevelSelector) {
            $profile.ManagedIdentityClientId = $TopLevelSelector
        }

        Test-GraphTenant -TenantProfile $profile | Should -BeFalse
    }

    It 'rejects a present canonical nested selector with a null, empty, or whitespace value' -ForEach @(
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
        Test-GraphTenant -TenantProfile @{
            ProfileId = 'invalid-present'; Name = $Case; Kind = 'lab'
            TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
            ClientId = $TopClientId; AuthMethod = $Mode; Environment = 'Global'
            Credential = $Credential
        } | Should -BeFalse
    }

    It 'rejects a non-null blank top-level ClientId for ManagedIdentity and BearerToken' -ForEach @(
        @{ Case = 'managed identity empty'; Mode = 'ManagedIdentity'; TopClientId = ''; Credential = @{} }
        @{ Case = 'managed identity whitespace'; Mode = 'ManagedIdentity'; TopClientId = '  '; Credential = @{} }
        @{ Case = 'bearer empty'; Mode = 'BearerToken'; TopClientId = ''; Credential = @{ VaultName = 'v'; SecretName = 's' } }
        @{ Case = 'bearer whitespace'; Mode = 'BearerToken'; TopClientId = '  '; Credential = @{ VaultName = 'v'; SecretName = 's' } }
    ) {
        Test-GraphTenant -TenantProfile @{
            ProfileId = 'invalid-top'; Name = $Case; Kind = 'lab'
            TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
            ClientId = $TopClientId; AuthMethod = $Mode; Environment = 'Global'
            Credential = $Credential
        } | Should -BeFalse
    }

    It 'rejects object and resource identity-selector aliases by key presence' -ForEach @(
        foreach ($selectorName in @('ObjectId', 'ResourceId', 'ManagedIdentityObjectId', 'ManagedIdentityResourceId')) {
            foreach ($location in @('Profile', 'Credential')) {
                @{ Case = "$location.$selectorName"; SelectorName = $selectorName; Location = $location }
            }
        }
    ) {
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

        Test-GraphTenant -TenantProfile $profile | Should -BeFalse
    }

    It 'documents false plus corrective re-registration for invalid successor metadata' {
        $help = Get-Help Test-GraphTenant -Full
        $description = @($help.Description.Text) -join ' '

        $description | Should -Match '(?i)returns? false'
        $description | Should -Match '(?i)re-register'
    }

    It 'preserves the literal public parameter signature' {
        $command = Get-Command Test-GraphTenant
        @($command.Parameters.Keys | Where-Object { $_ -notin [System.Management.Automation.PSCmdlet]::CommonParameters -and $_ -notin [System.Management.Automation.PSCmdlet]::OptionalCommonParameters } | Sort-Object) |
            Should -Be @('ProfileId', 'StorePath', 'TenantProfile')
        $command.Parameters.ProfileId.ParameterType.FullName | Should -BeExactly 'System.String'
        $command.Parameters.TenantProfile.ParameterType.FullName | Should -BeExactly 'System.Collections.Hashtable'
    }
}
