BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw "No built GraphKit module found under '$repoRoot/output/module/GraphKit'. Run './build.ps1 -Tasks build' first."
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force -ErrorAction Stop
}

Describe 'GraphHandlerStrategyRegistry' {

    Context 'Register-GraphHandlerStrategy' {
        It 'registers a known v1 strategy ID' {
            InModuleScope GraphKit {
                Register-GraphHandlerStrategy -Id 'Collection.Default' -Handler { 'handled' }

                $script:GraphHandlerStrategyRegistry.ContainsKey('Collection.Default') | Should -BeTrue
            }
        }

        It 'rejects an unknown strategy ID' {
            $err = InModuleScope GraphKit {
                try {
                    Register-GraphHandlerStrategy -Id 'Collection.Fancy' -Handler { 'x' }
                }
                catch {
                    $_.Exception.Message
                }
            }

            $err | Should -Match 'not a known v1 strategy'
            $err | Should -Match 'Collection.Fancy'
        }
    }

    Context 'Resolve-GraphHandlerStrategy' {
        It 'returns the registered handler scriptblock' {
            $handler = InModuleScope GraphKit {
                Register-GraphHandlerStrategy -Id 'Action.Default' -Handler { 'acted' }

                Resolve-GraphHandlerStrategy -Id 'Action.Default'
            }

            $handler | Should -Not -BeNullOrEmpty
            (& $handler) | Should -Be 'acted'
        }

        It 'rejects an unknown strategy ID (kind prefix validated)' {
            $err = InModuleScope GraphKit {
                try {
                    $null = Resolve-GraphHandlerStrategy -Id 'Bogus.Default'
                }
                catch {
                    $_.Exception.Message
                }
            }

            $err | Should -Match 'kind prefixes Collection, Action, Reconciliation, or LongRunningJob'
        }

        It 'rejects a known but unregistered strategy ID' {
            $err = InModuleScope GraphKit {
                try {
                    $null = Resolve-GraphHandlerStrategy -Id 'Reconciliation.StableExternalKey'
                }
                catch {
                    $_.Exception.Message
                }
            }

            $err | Should -Match 'has not been registered'
        }
    }

    Context 'Assert-GraphHandlerStrategyId' {
        It 'accepts Collection.Default with OperationKind Collection' {
            InModuleScope GraphKit {
                { Assert-GraphHandlerStrategyId -Id 'Collection.Default' -OperationKind 'Collection' -ReplayPolicy 'Safe' } |
                    Should -Not -Throw
            }
        }

        It 'accepts Action.Default with OperationKind Action' {
            InModuleScope GraphKit {
                { Assert-GraphHandlerStrategyId -Id 'Action.Default' -OperationKind 'Action' -ReplayPolicy 'NeverReplay' } |
                    Should -Not -Throw
            }
        }

        It 'accepts LongRunningJob.PollStatus with OperationKind LongRunningJob' {
            InModuleScope GraphKit {
                { Assert-GraphHandlerStrategyId -Id 'LongRunningJob.PollStatus' -OperationKind 'LongRunningJob' -ReplayPolicy 'Safe' } |
                    Should -Not -Throw
            }
        }

        It 'accepts Reconciliation.StableExternalKey with ReplayPolicy Reconciliable' {
            InModuleScope GraphKit {
                { Assert-GraphHandlerStrategyId -Id 'Reconciliation.StableExternalKey' -OperationKind 'Action' -ReplayPolicy 'Reconciliable' } |
                    Should -Not -Throw
            }
        }

        It 'rejects an unknown strategy ID' {
            $err = InModuleScope GraphKit {
                try {
                    $null = Assert-GraphHandlerStrategyId -Id 'Collection.Fancy' -OperationKind 'Collection' -ReplayPolicy 'Safe'
                }
                catch {
                    $_.Exception.Message
                }
            }

            $err | Should -Match 'not a known v1 strategy'
        }

        It 'rejects a wrong OperationKind prefix' {
            $err = InModuleScope GraphKit {
                try {
                    $null = Assert-GraphHandlerStrategyId -Id 'Collection.Default' -OperationKind 'Action' -ReplayPolicy 'Safe'
                }
                catch {
                    $_.Exception.Message
                }
            }

            $err | Should -Match "kind prefix 'Collection'"
            $err | Should -Match "OperationKind 'Collection'"
        }

        It 'rejects Reconciliation.StableExternalKey without ReplayPolicy Reconciliable' {
            $err = InModuleScope GraphKit {
                try {
                    $null = Assert-GraphHandlerStrategyId -Id 'Reconciliation.StableExternalKey' -OperationKind 'Action' -ReplayPolicy 'Safe'
                }
                catch {
                    $_.Exception.Message
                }
            }

            $err | Should -Match "ReplayPolicy 'Reconciliable'"
        }
    }
}
