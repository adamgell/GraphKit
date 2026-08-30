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
}
