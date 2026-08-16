BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) { throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first.' }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force

    $script:catalog = @(Get-GraphOperation -List)
}

Describe 'Descriptor invariants that fail silently if broken' {

    It 'keeps the $select on Organization/GetMdmAuthority' {
        # mobileDeviceManagementAuthority is a workload-extension property: it is returned only
        # when named in $select, on the ENTITY url, and it is absent from /organization
        # entirely. Verified against a live tenant - /organization returns 28 properties at
        # v1.0 and 29 at beta, neither including it, and /organization/{id} without $select
        # returns 30 and still omits it.
        #
        # So the $select is part of the operation's identity, not a tuning detail. Removing it
        # from the PathTemplate - which looks like a harmless cleanup - does NOT cause an
        # error. It returns an organization object without the property, which any caller
        # reads as "no MDM authority configured". A hygiene check built on it would then pass
        # while asserting nothing, which is the failure mode this catalog exists to prevent.
        $descriptor = $script:catalog | Where-Object { $_.Type -eq 'Organization' -and $_.Operation -eq 'GetMdmAuthority' }

        $descriptor | Should -Not -BeNullOrEmpty
        $descriptor.PathTemplate | Should -BeLike '*$select=mobileDeviceManagementAuthority*'
        $descriptor.PathTemplate | Should -BeLike '/organization/{id}*' -Because 'the property is exposed on the entity, not the collection'
        $descriptor.OperationKind | Should -Be 'Singleton'
        $descriptor.PagingStrategy | Should -Be 'None'
    }

    It 'declares every singleton with the singleton handler and no paging' {
        # Collection.Default unwraps a 'value' array. Pointing it at a singleton that happens
        # to carry its own 'value' property replaces the object with that field, silently.
        foreach ($descriptor in ($script:catalog | Where-Object OperationKind -eq 'Singleton')) {
            $descriptor.HandlerStrategyId | Should -Be 'Singleton.Default' -Because "$($descriptor.Type)/$($descriptor.Operation) is a singleton"
            $descriptor.PagingStrategy | Should -Be 'None' -Because "$($descriptor.Type)/$($descriptor.Operation) is a singleton and cannot page"
        }
    }

    It 'gives every beta descriptor a reason' {
        # Beta is a per-operation fact that has to be justified, not a global mode.
        foreach ($descriptor in ($script:catalog | Where-Object ApiVersion -eq 'beta')) {
            $descriptor.BetaReason | Should -Not -BeNullOrEmpty -Because "$($descriptor.Type)/$($descriptor.Operation) is beta"
        }
    }

    It 'never pairs a ListBeta operation with a v1.0 ApiVersion' {
        # The operation name is how a caller selects a version; a ListBeta that quietly reads
        # v1.0 would hand back the narrower shape under a name promising the wider one.
        foreach ($descriptor in ($script:catalog | Where-Object Operation -like '*Beta')) {
            $descriptor.ApiVersion | Should -Be 'beta' -Because "$($descriptor.Type)/$($descriptor.Operation) is named Beta"
        }
    }
}

Describe 'Get-GraphOperation does not hand out the live catalog' {

    # The catalog is cached once per session and was handed out by reference, so a caller
    # mutating a returned descriptor mutated it for every later operation in that runspace.
    # Demonstrated before fixing: setting CredentialPolicy = 'None' on a returned descriptor
    # made the next Get-GraphOperation report None - meaning a subsequent request would have
    # run with no bearer token. Load-time validation is what makes a descriptor trustworthy,
    # and an object editable afterwards has escaped it.

    It 'a mutated result does not affect the next lookup' {
        $first = Get-GraphOperation -Type ManagedDevice -Operation List
        $first.CredentialPolicy = 'None'

        (Get-GraphOperation -Type ManagedDevice -Operation List).CredentialPolicy |
            Should -Be 'GraphBearer'
    }

    It 'copies nested structures, not just the top level' {
        # AdvancedQuery, Concurrency, Timeouts and RequiredPermissions are all nested; a shallow
        # copy would leave every one of them shared with the catalog and the fix would look like
        # it worked while the interesting fields stayed mutable.
        $first = Get-GraphOperation -Type ManagedDevice -Operation List
        $first.Concurrency['Mode'] = 'Mutated'
        $first.AdvancedQuery['Supported'] = 'Mutated'

        $second = Get-GraphOperation -Type ManagedDevice -Operation List
        $second.Concurrency['Mode'] | Should -Not -Be 'Mutated'
        $second.AdvancedQuery['Supported'] | Should -Not -Be 'Mutated'
    }

    It 'copies array members' {
        $first = Get-GraphOperation -Type ManagedDevice -Operation List
        $first.SupportedClouds[0] = 'Mutated'

        (Get-GraphOperation -Type ManagedDevice -Operation List).SupportedClouds |
            Should -Not -Contain 'Mutated'
    }

    It 'still returns a usable descriptor with its values intact' {
        # A copy that dropped or mangled fields would break every caller while passing the
        # isolation tests above.
        $d = Get-GraphOperation -Type ManagedDevice -Operation List
        $d.Type | Should -Be 'ManagedDevice'
        $d.PathTemplate | Should -Be '/deviceManagement/managedDevices'
        $d.SupportedClouds | Should -Contain 'Global'
        $d.RequiredPermissions[0].Value | Should -Not -BeNullOrEmpty
    }
}

Describe 'The admin-template walk and Settings Catalog assignments' {

    It 'fixes the load-bearing $expand on both admin-template child operations' {
        # Without $expand a definitionValue is ids + an enabled flag, and a presentationValue is
        # a value with no label. Both return 200, so dropping the expand does not fail - it
        # produces rows that cannot be interpreted, which a consumer reads as "the tenant
        # configured nothing meaningful".
        foreach ($case in @(
            @{ Type = 'GroupPolicyDefinitionValue';   Expand = 'definition' }
            @{ Type = 'GroupPolicyPresentationValue'; Expand = 'presentation' }
        )) {
            $d = $script:catalog | Where-Object { $_.Type -eq $case.Type -and $_.Operation -eq 'ListBeta' }
            $d | Should -Not -BeNullOrEmpty -Because "$($case.Type)/ListBeta must exist"
            $d.PathTemplate | Should -BeLike "*`$expand=$($case.Expand)*"
            $d.AdvancedQuery.Supported | Should -BeFalse -Because 'the fixed option must not be overridable'
        }
    }

    It 'parameterizes the presentationValue walk by BOTH ancestors' {
        $d = $script:catalog | Where-Object { $_.Type -eq 'GroupPolicyPresentationValue' -and $_.Operation -eq 'ListBeta' }
        $d.PathTemplate | Should -BeLike '*{id}*'
        $d.PathTemplate | Should -BeLike '*{definitionValueId}*'
    }

    It 'covers assignments for every policy type a conflict check compares' {
        # The gap this closes was invisible: a reconciliation across policy types simply
        # contributed nothing for Settings Catalog, so overlap involving it was never reported
        # and the run still looked complete.
        $assignmentTypes = @($script:catalog | Where-Object { $_.Type -like '*Assignment' } | ForEach-Object { $_.Type })
        foreach ($required in @(
            'DeviceCompliancePolicyAssignment'
            'DeviceConfigurationAssignment'
            'MobileAppAssignment'
            'ConfigurationPolicyAssignment'
        )) {
            $assignmentTypes | Should -Contain $required
        }
    }

    It 'roots every admin-template operation under the same parent collection' {
        $walk = @($script:catalog | Where-Object { $_.ResourceFamily -eq 'Intune.GroupPolicy' })
        $walk.Count | Should -Be 3
        foreach ($d in $walk) {
            $d.PathTemplate | Should -BeLike '/deviceManagement/groupPolicyConfigurations*'
            $d.ApiVersion | Should -Be 'beta' -Because 'v1.0 returns 400 BadRequest for this collection'
            $d.Method | Should -Be 'GET'
            $d.ReplayPolicy | Should -Be 'Safe'
        }
    }
}

