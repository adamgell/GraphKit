BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) { throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first.' }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force

    $script:catalog = @(Get-GraphOperation -List)

    $script:Context = [PSCustomObject]@{
        Cloud         = 'Global'
        GraphBaseUri  = [uri] 'https://graph.microsoft.com'
        ProfileId     = 'contract-test'
        TenantId      = [guid] '00000000-0000-0000-0000-000000000001'
        ClientId      = '00000000-0000-0000-0000-000000000010'
        IdentityState = 'VerifiedForToken'
        TokenSource   = [PSCustomObject]@{ AuthMode = 'Certificate' }
    }

    function New-ContractTestEnvelope {
        param([object[]] $Data)

        [PSCustomObject]@{
            PSTypeName = 'GraphKit.OperationResult'
            Data       = $Data
            Outcome    = 'Succeeded'
            Certainty  = 'Known'
            Telemetry  = @()
            Provenance = $null
        }
    }
}

Describe 'TenantPulse collection descriptor contracts' {
    It 'ships the official expanded Intune unified-RBAC assignment read' {
        $descriptor = $script:catalog | Where-Object {
            $_.Type -eq 'DeviceManagementUnifiedRoleAssignment' -and $_.Operation -eq 'ListBeta'
        }

        $descriptor | Should -Not -BeNullOrEmpty
        $descriptor.ApiVersion | Should -Be 'beta'
        $descriptor.OperationKind | Should -Be 'Collection'
        $descriptor.HandlerStrategyId | Should -Be 'Collection.Default'
        $descriptor.PathTemplate | Should -Be '/roleManagement/deviceManagement/roleAssignments?$expand=roleDefinition,principals'
        $descriptor.AdvancedQuery.Supported | Should -BeFalse -Because 'the relationships are a required part of this operation shape'
        $descriptor.PagingStrategy | Should -Be 'NextLink'
        $descriptor.ReplayPolicy | Should -Be 'Safe'
        $descriptor.ThrottleClass | Should -Be 'Read'
        @($descriptor.RequiredPermissions.Value) | Should -Contain 'DeviceManagementRBAC.Read.All'
    }

    It 'ships the beta Intune template collection with baseline disposition fields' {
        $descriptor = $script:catalog | Where-Object {
            $_.Type -eq 'DeviceManagementTemplate' -and $_.Operation -eq 'ListBeta'
        }

        $descriptor | Should -Not -BeNullOrEmpty
        $descriptor.ApiVersion | Should -Be 'beta'
        $descriptor.OperationKind | Should -Be 'Collection'
        $descriptor.HandlerStrategyId | Should -Be 'Collection.Default'
        $descriptor.PathTemplate | Should -Be '/deviceManagement/templates'
        $descriptor.PagingStrategy | Should -Be 'NextLink'
        $descriptor.ReplayPolicy | Should -Be 'Safe'
        $descriptor.ThrottleClass | Should -Be 'Read'
        @($descriptor.RequiredPermissions.Value) | Should -Contain 'DeviceManagementConfiguration.Read.All'
    }

    It 'ships the distinct Settings Catalog configuration-policy template collection' {
        $descriptor = $script:catalog | Where-Object {
            $_.Type -eq 'DeviceManagementConfigurationPolicyTemplate' -and $_.Operation -eq 'ListBeta'
        }

        $descriptor | Should -Not -BeNullOrEmpty
        $descriptor.ApiVersion | Should -Be 'beta'
        $descriptor.OperationKind | Should -Be 'Collection'
        $descriptor.HandlerStrategyId | Should -Be 'Collection.Default'
        $descriptor.PathTemplate | Should -Be '/deviceManagement/configurationPolicyTemplates'
        $descriptor.PagingStrategy | Should -Be 'NextLink'
        $descriptor.ReplayPolicy | Should -Be 'Safe'
        $descriptor.ThrottleClass | Should -Be 'Read'
        @($descriptor.RequiredPermissions.Value) | Should -Contain 'DeviceManagementConfiguration.Read.All'
    }

    It 'ships the beta device-management intent collection that joins profiles to templates' {
        $descriptor = $script:catalog | Where-Object {
            $_.Type -eq 'DeviceManagementIntent' -and $_.Operation -eq 'ListBeta'
        }

        $descriptor | Should -Not -BeNullOrEmpty
        $descriptor.ApiVersion | Should -Be 'beta'
        $descriptor.OperationKind | Should -Be 'Collection'
        $descriptor.HandlerStrategyId | Should -Be 'Collection.Default'
        $descriptor.PathTemplate | Should -Be '/deviceManagement/intents'
        $descriptor.PagingStrategy | Should -Be 'NextLink'
        $descriptor.ReplayPolicy | Should -Be 'Safe'
        $descriptor.ThrottleClass | Should -Be 'Read'
        @($descriptor.RequiredPermissions.Value) | Should -Contain 'DeviceManagementConfiguration.Read.All'
    }

    It 'ships the official managed-device cleanup-rules collection' {
        $descriptor = $script:catalog | Where-Object {
            $_.Type -eq 'ManagedDeviceCleanupRule' -and $_.Operation -eq 'ListBeta'
        }

        $descriptor | Should -Not -BeNullOrEmpty
        $descriptor.ApiVersion | Should -Be 'beta'
        $descriptor.OperationKind | Should -Be 'Collection'
        $descriptor.HandlerStrategyId | Should -Be 'Collection.Default'
        $descriptor.PathTemplate | Should -Be '/deviceManagement/managedDeviceCleanupRules'
        $descriptor.PagingStrategy | Should -Be 'NextLink'
        $descriptor.ReplayPolicy | Should -Be 'Safe'
        $descriptor.ThrottleClass | Should -Be 'Read'
        @($descriptor.RequiredPermissions.Value) | Should -Contain 'DeviceManagementManagedDevices.Read.All'
    }

    It 'does not advertise the obsolete undocumented cleanup-settings singleton' {
        @($script:catalog | Where-Object {
            $_.PathTemplate -eq '/deviceManagement/managedDeviceCleanupSettings'
        }).Count | Should -Be 0
    }

    It 'ships the beta Apple enrollment-profile child collection needed by the IHA successor' {
        $descriptor = $script:catalog | Where-Object {
            $_.Type -eq 'AppleEnrollmentProfile' -and $_.Operation -eq 'ListByToken'
        }

        $descriptor | Should -Not -BeNullOrEmpty
        $descriptor.ApiVersion | Should -Be 'beta'
        $descriptor.Stability | Should -Be 'BetaOnly'
        $descriptor.OperationKind | Should -Be 'Collection'
        $descriptor.HandlerStrategyId | Should -Be 'Collection.Default'
        $descriptor.PathTemplate | Should -Be '/deviceManagement/depOnboardingSettings/{depOnboardingSettingId}/enrollmentProfiles'
        $descriptor.AdvancedQuery.Supported | Should -BeFalse
        $descriptor.PagingStrategy | Should -Be 'NextLink'
        $descriptor.DeduplicationKey | Should -Be 'id'
        $descriptor.ReplayPolicy | Should -Be 'Safe'
        $descriptor.ThrottleClass | Should -Be 'Read'
        @($descriptor.RequiredPermissions.Value) | Should -Be @('DeviceManagementServiceConfig.Read.All')
    }

    It 'preserves the documented polymorphic Apple enrollment-profile response fields' {
        $script:AppleEnrollmentProfileFixture = [pscustomobject]@{
            '@odata.type' = '#microsoft.graph.depIOSEnrollmentProfile'
            id = 'profile-1'
            displayName = 'Corporate iOS'
            description = 'Automated enrollment'
            requiresUserAuthentication = $true
            configurationEndpointUrl = 'https://example.test/configuration'
            enableAuthenticationViaCompanyPortal = $true
            requireCompanyPortalOnSetupAssistantEnrolledDevices = $true
            isDefault = $true
            isMandatory = $false
        }

        Mock Invoke-GraphPaging -ModuleName GraphKit {
            New-ContractTestEnvelope -Data @($script:AppleEnrollmentProfileFixture)
        }
        Mock Invoke-GraphHandlerStrategy -ModuleName GraphKit { throw 'unexpected singleton strategy call' }

        $rows = @(Get-GraphObject `
            -Context $script:Context `
            -Type AppleEnrollmentProfile `
            -Operation ListByToken `
            -Parameters @{ depOnboardingSettingId = 'token-1' })

        $rows | Should -HaveCount 1
        $rows[0].PSObject.TypeNames | Should -Contain 'GraphKit.AppleEnrollmentProfile'
        $rows[0].'@odata.type' | Should -BeExactly '#microsoft.graph.depIOSEnrollmentProfile'
        $rows[0].id | Should -BeExactly 'profile-1'
        $rows[0].displayName | Should -BeExactly 'Corporate iOS'
        $rows[0].description | Should -BeExactly 'Automated enrollment'
        $rows[0].requiresUserAuthentication | Should -BeTrue
        $rows[0].isDefault | Should -BeTrue
        $rows[0].isMandatory | Should -BeFalse
        Should-Invoke Invoke-GraphPaging -ModuleName GraphKit -Times 1 -Exactly
        Should-NotInvoke Invoke-GraphHandlerStrategy -ModuleName GraphKit
    }

    It 'ships the beta managed-device singleton needed for authoritative hardware detail' {
        $descriptor = $script:catalog | Where-Object {
            $_.Type -eq 'ManagedDevice' -and $_.Operation -eq 'GetBeta'
        }

        $descriptor | Should -Not -BeNullOrEmpty
        $descriptor.ApiVersion | Should -Be 'beta'
        $descriptor.Stability | Should -Be 'DualVersion'
        $descriptor.OperationKind | Should -Be 'Singleton'
        $descriptor.HandlerStrategyId | Should -Be 'Singleton.Default'
        $descriptor.PathTemplate | Should -Be '/deviceManagement/managedDevices/{id}?$select=id,hardwareInformation,deviceHealthAttestationState,physicalMemoryInBytes,processorArchitecture,skuFamily,skuNumber,managementFeatures,roleScopeTagIds,ethernetMacAddress,bootstrapTokenEscrowed'
        $descriptor.PagingStrategy | Should -Be 'None'
        $descriptor.AdvancedQuery.Supported | Should -BeFalse
        $descriptor.ReplayPolicy | Should -Be 'Safe'
        $descriptor.ThrottleClass | Should -Be 'Read'
        @($descriptor.RequiredPermissions.Value) | Should -Be @('DeviceManagementManagedDevices.Read.All')
    }

    It 'preserves the documented managed-device hardware and attestation response fields' {
        $script:ManagedDeviceDetailFixture = [pscustomobject]@{
            id = 'device-1'
            operatingSystem = 'Windows'
            hardwareInformation = [pscustomobject]@{
                serialNumber = 'SERIAL'
                totalStorageSpace = 1024
                freeStorageSpace = 512
                tpmVersion = '2.0'
            }
            deviceHealthAttestationState = [pscustomobject]@{
                secureBoot = 'enabled'
                bitLockerStatus = 'secured'
                tpmVersion = '2.0'
            }
        }

        Mock Invoke-GraphHandlerStrategy -ModuleName GraphKit {
            New-ContractTestEnvelope -Data @($script:ManagedDeviceDetailFixture)
        }
        Mock Invoke-GraphPaging -ModuleName GraphKit { throw 'unexpected paging call' }

        $rows = @(Get-GraphObject `
            -Context $script:Context `
            -Type ManagedDevice `
            -Operation GetBeta `
            -Parameters @{ id = 'device-1' })

        $rows | Should -HaveCount 1
        $rows[0].PSObject.TypeNames | Should -Contain 'GraphKit.ManagedDevice'
        $rows[0].id | Should -BeExactly 'device-1'
        $rows[0].hardwareInformation.tpmVersion | Should -BeExactly '2.0'
        $rows[0].deviceHealthAttestationState.secureBoot | Should -BeExactly 'enabled'
        Should-Invoke Invoke-GraphHandlerStrategy -ModuleName GraphKit -Times 1 -Exactly -ParameterFilter {
            $Descriptor.OperationKind -eq 'Singleton' -and
            $Descriptor.HandlerStrategyId -eq 'Singleton.Default'
        }
        Should-NotInvoke Invoke-GraphPaging -ModuleName GraphKit
    }
}
