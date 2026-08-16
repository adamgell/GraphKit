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
