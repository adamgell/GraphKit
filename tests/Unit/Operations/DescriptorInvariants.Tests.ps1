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

Describe 'Directory settings need both halves to be interpretable' {

    It 'ships the instantiated settings AND the templates that supply their defaults' {
        # /settings returns only settings that have been INSTANTIATED. Verified against a live
        # tenant: 10 templates available, exactly one instantiated. So a consumer holding only
        # DirectorySetting.List sees nothing for Password Protection or Consent Policy and cannot
        # tell "default value, compliant" from "unknown" - it reports false non-compliance on every
        # tenant that never customised the setting.
        foreach ($t in @('DirectorySetting', 'DirectorySettingTemplate')) {
            $d = $script:catalog | Where-Object { $_.Type -eq $t -and $_.Operation -eq 'List' }
            $d | Should -Not -BeNullOrEmpty -Because "$t/List is half of an interpretable answer"
            $d.AdvancedQuery.Supported | Should -BeFalse -Because '/settings supports no query options'
            $d.PathTemplate | Should -Not -BeLike '*{*' -Because 'both are unparameterized lists, not per-template lookups'
        }
    }

    It 'keeps AuthorizationPolicy a singleton with no paging' {
        # /policies/authorizationPolicy returns one object with no 'value' wrapper. Collection
        # .Default would unwrap a property that is not there and return nothing while reporting
        # success - the failure is silent, so the shape is declared rather than inferred.
        $d = $script:catalog | Where-Object { $_.Type -eq 'AuthorizationPolicy' -and $_.Operation -eq 'Get' }
        $d | Should -Not -BeNullOrEmpty
        $d.OperationKind | Should -Be 'Singleton'
        $d.HandlerStrategyId | Should -Be 'Singleton.Default'
        $d.PagingStrategy | Should -Be 'None'
    }
}

Describe 'The write surface stays coherent as it grows' {

    BeforeAll {
        $script:writes = @($script:catalog | Where-Object { $_.ReplayPolicy -ne 'Safe' })
    }

    It 'gives every write a Write throttle class' {
        # Writes and reads share a throttle budget only if someone forgets this. Graph meters them
        # separately, so a write counted against the read budget makes back-pressure appear on the
        # wrong scope and the AIMD controller throttles the wrong thing.
        foreach ($w in $script:writes) {
            $w.ThrottleClass | Should -Be 'Write' -Because "$($w.Type)/$($w.Operation) mutates"
        }
    }

    It 'declares an Impact on every write' {
        # An undeclared Impact is treated as not-High, so a destructive operation added without one
        # silently skips the -Force requirement. The default is the permissive direction, which is
        # exactly why the declaration has to be mandatory for writes rather than optional.
        foreach ($w in $script:writes) {
            $w.Impact | Should -Not -BeNullOrEmpty -Because "$($w.Type)/$($w.Operation) must state how bad it is if run by mistake"
            $w.Impact | Should -BeIn @('Low', 'Medium', 'High')
        }
    }

    It 'pairs every assignment write with the read that makes it safe to use' {
        # Graph's /assign is a REPLACE: whatever is omitted is unassigned. A caller who cannot read
        # the current set before posting will silently destroy assignments they never saw. Shipping
        # the write without the read is therefore shipping a footgun.
        $pairs = @{
            'DeviceCompliancePolicy/Assign'     = 'DeviceCompliancePolicyAssignment/List'
            'DeviceConfiguration/Assign'        = 'DeviceConfigurationAssignment/List'
            'ConfigurationPolicy/AssignBeta'    = 'ConfigurationPolicyAssignment/ListBeta'
            'MobileApp/Assign'                  = 'MobileAppAssignment/List'
        }
        foreach ($write in $pairs.Keys) {
            $w = $write -split '/'
            $r = $pairs[$write] -split '/'
            ($script:catalog | Where-Object { $_.Type -eq $w[0] -and $_.Operation -eq $w[1] }) |
                Should -Not -BeNullOrEmpty -Because "$write must exist"
            ($script:catalog | Where-Object { $_.Type -eq $r[0] -and $_.Operation -eq $r[1] }) |
                Should -Not -BeNullOrEmpty -Because "$write is a REPLACE and needs $($pairs[$write]) to be usable safely"
        }
    }

    It 'never marks a write ReplayPolicy Safe' {
        # Safe means the retry engine may re-send after an ambiguous failure. For a write with no
        # reconcilable identity that is a duplicate mutation, not a retry.
        foreach ($w in $script:writes) {
            $w.ReplayPolicy | Should -BeIn @('Conditional', 'Reconciliable', 'NeverReplay')
        }
    }
}

