BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) { throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first.' }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force

    $script:catalog = @(Get-GraphOperation -List)
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
        $fixture = [pscustomobject]@{
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

        # GraphKit's collection transport is intentionally schema-neutral. This pins the
        # operation-specific minimum shape TenantPulse relies on and prevents a future
        # projection from treating only the base enrollmentProfile fields as complete.
        @($fixture.PSObject.Properties.Name) | Should -Contain '@odata.type'
        @($fixture.PSObject.Properties.Name) | Should -Contain 'id'
        @($fixture.PSObject.Properties.Name) | Should -Contain 'displayName'
        @($fixture.PSObject.Properties.Name) | Should -Contain 'description'
        @($fixture.PSObject.Properties.Name) | Should -Contain 'requiresUserAuthentication'
        @($fixture.PSObject.Properties.Name) | Should -Contain 'isDefault'
        @($fixture.PSObject.Properties.Name) | Should -Contain 'isMandatory'
    }

    It 'ships the beta managed-device singleton needed for authoritative hardware detail' {
        $descriptor = $script:catalog | Where-Object {
            $_.Type -eq 'ManagedDevice' -and $_.Operation -eq 'GetBeta'
        }

        $descriptor | Should -Not -BeNullOrEmpty
        $descriptor.ApiVersion | Should -Be 'beta'
        $descriptor.Stability | Should -Be 'DualVersion'
        $descriptor.OperationKind | Should -Be 'Collection'
        $descriptor.HandlerStrategyId | Should -Be 'Collection.Default'
        $descriptor.PathTemplate | Should -Be '/deviceManagement/managedDevices/{id}?$select=id,hardwareInformation,deviceHealthAttestationState,physicalMemoryInBytes,processorArchitecture,skuFamily,skuNumber,managementFeatures,roleScopeTagIds,ethernetMacAddress,bootstrapTokenEscrowed'
        $descriptor.PagingStrategy | Should -Be 'None'
        $descriptor.AdvancedQuery.Supported | Should -BeFalse
        $descriptor.ReplayPolicy | Should -Be 'Safe'
        $descriptor.ThrottleClass | Should -Be 'Read'
        @($descriptor.RequiredPermissions.Value) | Should -Be @('DeviceManagementManagedDevices.Read.All')
    }

    It 'preserves the documented managed-device hardware and attestation response fields' {
        $fixture = [pscustomobject]@{
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

        $fixture.id | Should -Not -BeNullOrEmpty
        $fixture.hardwareInformation | Should -Not -BeNullOrEmpty
        $fixture.deviceHealthAttestationState | Should -Not -BeNullOrEmpty
        @($fixture.hardwareInformation.PSObject.Properties.Name) | Should -Contain 'tpmVersion'
        @($fixture.deviceHealthAttestationState.PSObject.Properties.Name) | Should -Contain 'secureBoot'
    }
}
