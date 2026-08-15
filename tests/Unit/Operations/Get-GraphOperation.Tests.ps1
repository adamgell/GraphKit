BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $repoRoot = $script:repoRoot
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw "No built GraphKit module found under '$repoRoot/output/module/GraphKit'. Run './build.ps1 -Tasks build' first."
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force -ErrorAction Stop
}

Describe 'Get-GraphOperation' {

    Context 'Catalog enumeration' {
        It 'returns every descriptor on disk with -List' {
            # Asserted against the descriptor files rather than a hard-coded number. A magic
            # count breaks on every legitimate catalog addition while catching nothing a file
            # comparison misses - and it silently passes if a descriptor is swapped rather
            # than added. This fails if any descriptor stops loading, which is the real risk.
            $onDisk = @(Get-ChildItem -Path (Join-Path $script:repoRoot 'source/Data/Operations') -Filter '*.psd1').Count
            $all = @(InModuleScope GraphKit { Get-GraphOperationInternal -List })

            $all.Count | Should -Be $onDisk
            $all.Count | Should -BeGreaterThan 0
        }

        It 'returns the originally shipped descriptors by Type and Operation' {
            $pairs = @(InModuleScope GraphKit {
                Get-GraphOperationInternal -List | ForEach-Object { "$($_['Type'])/$($_['Operation'])" } | Sort-Object
            })

            $pairs | Should -Contain 'MobileApp/Assign'
            $pairs | Should -Contain 'ManagedDevice/List'
            $pairs | Should -Contain 'DeviceReport/Export'
        }
    }

    Context 'Single lookup' {
        It 'resolves a descriptor by Type and Operation' {
            $d = InModuleScope GraphKit { Get-GraphOperationInternal -Type 'ManagedDevice' -Operation 'List' }

            $d | Should -Not -BeNullOrEmpty
            $d['Type'] | Should -Be 'ManagedDevice'
            $d['Operation'] | Should -Be 'List'
            $d['HandlerStrategyId'] | Should -Be 'Collection.Default'
        }

        It 'errors with available pairs when Type and Operation do not match' {
            $err = InModuleScope GraphKit {
                try {
                    $null = Get-GraphOperationInternal -Type 'ManagedDevice' -Operation 'Assign'
                }
                catch {
                    $_.Exception.Message
                }
            }

            $err | Should -Match "Type 'ManagedDevice' Operation 'Assign'"
            $err | Should -Match 'Available Type/Operation pairs'
            $err | Should -Match 'MobileApp/Assign'
            $err | Should -Match 'ManagedDevice/List'
        }

        It 'errors naming available Types for an unknown Type' {
            $err = InModuleScope GraphKit {
                try {
                    $null = Get-GraphOperationInternal -Type 'Bogus'
                }
                catch {
                    $_.Exception.Message
                }
            }

            $err | Should -Match "Type 'Bogus'"
            $err | Should -Match 'Available Types'
            $err | Should -Match 'MobileApp'
            $err | Should -Match 'ManagedDevice'
            $err | Should -Match 'DeviceReport'
        }
    }

    Context 'Cloud filter' {
        It 'filters by a supported cloud' {
            # Every descriptor declares USGov support today, so this equals the full catalog.
            # Compared against the catalog rather than a literal, so adding a descriptor that
            # omits USGov fails here loudly instead of drifting.
            $all = @(InModuleScope GraphKit { Get-GraphOperationInternal -Cloud 'USGov' })
            $total = @(InModuleScope GraphKit { Get-GraphOperationInternal -List }).Count

            $all.Count | Should -Be $total
        }

        It 'returns only the descriptors that declare the requested cloud' {
            # This previously asserted that China matched nothing. That premise died when
            # directory descriptors (Group, User, ServicePrincipal, GroupMember) were added -
            # those resources genuinely exist in every cloud, unlike the Intune ones. The
            # property under test is the filter itself, so it is now asserted directly:
            # every returned descriptor declares the cloud, and every omitted one does not.
            $matching = @(InModuleScope GraphKit { Get-GraphOperationInternal -Cloud 'China' })
            $all = @(InModuleScope GraphKit { Get-GraphOperationInternal -List })

            foreach ($d in $matching) { $d['SupportedClouds'] | Should -Contain 'China' }

            $expected = @($all | Where-Object { $_['SupportedClouds'] -contains 'China' }).Count
            $matching.Count | Should -Be $expected
        }
    }

    Context 'Public wrapper' {
        It 'lists the catalog through the exported command' {
            $all = @(Get-GraphOperation -List)
            $internal = @(InModuleScope GraphKit { Get-GraphOperationInternal -List })

            $all.Count | Should -Be $internal.Count
            $all.Count | Should -BeGreaterThan 0
        }

        It 'resolves a single descriptor through the exported command' {
            $d = Get-GraphOperation -Type 'MobileApp' -Operation 'Assign'

            $d['ResourceFamily'] | Should -Be 'Intune.MobileApps'
        }
    }
}
