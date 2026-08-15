BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw "No built GraphKit module found under '$repoRoot/output/module/GraphKit'. Run './build.ps1 -Tasks build' first."
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force -ErrorAction Stop
}

Describe 'Get-GraphOperation' {

    Context 'Catalog enumeration' {
        It 'returns every descriptor with -List' {
            $all = @(InModuleScope GraphKit { Get-GraphOperationInternal -List })

            $all.Count | Should -Be 3
        }

        It 'returns all three known descriptors by Type and Operation' {
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
            $all = @(InModuleScope GraphKit { Get-GraphOperationInternal -Cloud 'USGov' })

            $all.Count | Should -Be 3
        }

        It 'returns no descriptors for a cloud nobody declares support for' {
            # No v1 descriptor declares support for China, so the cloud filter
            # returns no descriptors.
            $matching = @(InModuleScope GraphKit { Get-GraphOperationInternal -Cloud 'China' })

            $matching.Count | Should -Be 0
        }
    }

    Context 'Public wrapper' {
        It 'lists the catalog through the exported command' {
            $all = @(Get-GraphOperation -List)

            $all.Count | Should -Be 3
        }

        It 'resolves a single descriptor through the exported command' {
            $d = Get-GraphOperation -Type 'MobileApp' -Operation 'Assign'

            $d['ResourceFamily'] | Should -Be 'Intune.MobileApps'
        }
    }
}
