BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw "No built GraphKit module found under '$repoRoot/output/module/GraphKit'. Run './build.ps1 -Tasks build' first."
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force -ErrorAction Stop

    function New-TestDescriptor {
        param([string] $ReplayPolicy = 'Safe', [string] $Method = 'GET', [hashtable] $Condition = $null)

        return @{
            SchemaVersion  = 1
            ReplayPolicy   = $ReplayPolicy
            Condition      = $Condition
            Reconciliation = $null
        }
    }
}

Describe 'Get-GraphRetryDecision' {

    Context '2xx' {
        It 'is success and never replays, even with Retry-After present' {
            $d = InModuleScope GraphKit -ArgumentList (New-TestDescriptor) {
                param($Descriptor)
                Get-GraphRetryDecision -Descriptor $Descriptor -Method GET -StatusCode 202 `
                    -AttemptCertainty Succeeded -HasRetryAfter $true -IsKnownTransient409 $false -ForceRefreshUsed $false -CanRefresh $true
            }

            $d.ShouldRetry | Should -BeFalse
            $d.Outcome | Should -Be 'Succeeded'
            $d.Certainty | Should -Be 'Known'
            $d.ForceRefresh | Should -BeFalse
        }
    }

    Context '401' {
        It 'forces exactly one refresh when the token source can refresh' {
            $d = InModuleScope GraphKit -ArgumentList (New-TestDescriptor) {
                param($Descriptor)
                Get-GraphRetryDecision -Descriptor $Descriptor -Method GET -StatusCode 401 `
                    -AttemptCertainty Rejected -HasRetryAfter $false -IsKnownTransient409 $false -ForceRefreshUsed $false -CanRefresh $true
            }

            $d.ShouldRetry | Should -BeTrue
            $d.ForceRefresh | Should -BeTrue
        }

        It 'does not retry a second 401 (no loop)' {
            $d = InModuleScope GraphKit -ArgumentList (New-TestDescriptor) {
                param($Descriptor)
                Get-GraphRetryDecision -Descriptor $Descriptor -Method GET -StatusCode 401 `
                    -AttemptCertainty Rejected -HasRetryAfter $false -IsKnownTransient409 $false -ForceRefreshUsed $true -CanRefresh $true
            }

            $d.ShouldRetry | Should -BeFalse
            $d.Outcome | Should -Be 'Failed'
            $d.Certainty | Should -Be 'Known'
        }

        It 'does not retry when the source cannot refresh' {
            $d = InModuleScope GraphKit -ArgumentList (New-TestDescriptor) {
                param($Descriptor)
                Get-GraphRetryDecision -Descriptor $Descriptor -Method GET -StatusCode 401 `
                    -AttemptCertainty Rejected -HasRetryAfter $false -IsKnownTransient409 $false -ForceRefreshUsed $false -CanRefresh $false
            }

            $d.ShouldRetry | Should -BeFalse
            $d.Outcome | Should -Be 'Failed'
        }
    }

    Context '403 / 404' {
        It 'never retries' {
            foreach ($code in @(403, 404)) {
                $d = InModuleScope GraphKit -ArgumentList (New-TestDescriptor), $code {
                    param($Descriptor, $StatusCode)
                    Get-GraphRetryDecision -Descriptor $Descriptor -Method GET -StatusCode $StatusCode `
                        -AttemptCertainty Rejected -HasRetryAfter $false -IsKnownTransient409 $false -ForceRefreshUsed $false -CanRefresh $true
                }

                $d.ShouldRetry | Should -BeFalse -Because "status $code must not retry"
                $d.Outcome | Should -Be 'Failed'
                $d.Certainty | Should -Be 'Known'
            }
        }
    }

    Context '409' {
        It 'retries only known transient inner codes' {
            $transient = InModuleScope GraphKit -ArgumentList (New-TestDescriptor) {
                param($Descriptor)
                Get-GraphRetryDecision -Descriptor $Descriptor -Method POST -StatusCode 409 `
                    -AttemptCertainty Rejected -HasRetryAfter $false -IsKnownTransient409 $true -ForceRefreshUsed $false -CanRefresh $true
            }
            $transient.ShouldRetry | Should -BeTrue

            $real = InModuleScope GraphKit -ArgumentList (New-TestDescriptor) {
                param($Descriptor)
                Get-GraphRetryDecision -Descriptor $Descriptor -Method POST -StatusCode 409 `
                    -AttemptCertainty Rejected -HasRetryAfter $false -IsKnownTransient409 $false -ForceRefreshUsed $false -CanRefresh $true
            }
            $real.ShouldRetry | Should -BeFalse
            $real.Outcome | Should -Be 'Failed'
            $real.Certainty | Should -Be 'Known'
        }
    }

    Context '429 (Rejected)' {
        It 'retries under Safe' {
            $d = InModuleScope GraphKit -ArgumentList (New-TestDescriptor -ReplayPolicy Safe) {
                param($Descriptor)
                Get-GraphRetryDecision -Descriptor $Descriptor -Method POST -StatusCode 429 `
                    -AttemptCertainty Rejected -HasRetryAfter $true -IsKnownTransient409 $false -ForceRefreshUsed $false -CanRefresh $true
            }
            $d.ShouldRetry | Should -BeTrue
        }



        It 'does not retry under NeverReplay' {
            $d = InModuleScope GraphKit -ArgumentList (New-TestDescriptor -ReplayPolicy NeverReplay) {
                param($Descriptor)
                Get-GraphRetryDecision -Descriptor $Descriptor -Method POST -StatusCode 429 `
                    -AttemptCertainty Rejected -HasRetryAfter $true -IsKnownTransient409 $false -ForceRefreshUsed $false -CanRefresh $true
            }
            $d.ShouldRetry | Should -BeFalse
            $d.Outcome | Should -Be 'Failed'
            $d.Certainty | Should -Be 'Known'
        }

        It 'retries Conditional only when the descriptor permits the method' {
            $permitted = InModuleScope GraphKit -ArgumentList (New-TestDescriptor -ReplayPolicy Conditional -Method PUT -Condition @{ Method = 'PUT' }) {
                param($Descriptor)
                Get-GraphRetryDecision -Descriptor $Descriptor -Method PUT -StatusCode 429 `
                    -AttemptCertainty Rejected -HasRetryAfter $true -IsKnownTransient409 $false -ForceRefreshUsed $false -CanRefresh $true
            }
            $permitted.ShouldRetry | Should -BeTrue

            $denied = InModuleScope GraphKit -ArgumentList (New-TestDescriptor -ReplayPolicy Conditional -Method PATCH -Condition @{ Method = 'PUT' }) {
                param($Descriptor)
                Get-GraphRetryDecision -Descriptor $Descriptor -Method PATCH -StatusCode 429 `
                    -AttemptCertainty Rejected -HasRetryAfter $true -IsKnownTransient409 $false -ForceRefreshUsed $false -CanRefresh $true
            }
            $denied.ShouldRetry | Should -BeFalse
        }
    }
    Context '3xx' {
        It 'surfaces a redirect as a definitive non-success (never retried)' {
            $d = InModuleScope GraphKit -ArgumentList (New-TestDescriptor) {
                param($Descriptor)
                Get-GraphRetryDecision -Descriptor $Descriptor -Method GET -StatusCode 302 `
                    -AttemptCertainty Rejected -HasRetryAfter $false -IsKnownTransient409 $false -ForceRefreshUsed $false -CanRefresh $true
            }

            $d.ShouldRetry | Should -BeFalse
            $d.Outcome | Should -Be 'Failed'
            $d.Certainty | Should -Be 'Known'
        }
    }

    Context 'other 4xx' {
        It 'never retries a permanent client error such as 400' {
            $d = InModuleScope GraphKit -ArgumentList (New-TestDescriptor) {
                param($Descriptor)
                Get-GraphRetryDecision -Descriptor $Descriptor -Method GET -StatusCode 400 `
                    -AttemptCertainty Rejected -HasRetryAfter $false -IsKnownTransient409 $false -ForceRefreshUsed $false -CanRefresh $true
            }

            $d.ShouldRetry | Should -BeFalse
            $d.Outcome | Should -Be 'Failed'
            $d.Certainty | Should -Be 'Known'
        }
    }

    Context 'Ambiguous (5xx / timeout)' {
        It 'retries reads' {
            $d = InModuleScope GraphKit -ArgumentList (New-TestDescriptor -ReplayPolicy Safe) {
                param($Descriptor)
                Get-GraphRetryDecision -Descriptor $Descriptor -Method GET -StatusCode 503 `
                    -AttemptCertainty Ambiguous -HasRetryAfter $false -IsKnownTransient409 $false -ForceRefreshUsed $false -CanRefresh $true
            }
            $d.ShouldRetry | Should -BeTrue
        }

        It 'does not replay an ambiguous POST (Failed + Indeterminate)' {
            $d = InModuleScope GraphKit -ArgumentList (New-TestDescriptor -ReplayPolicy NeverReplay) {
                param($Descriptor)
                Get-GraphRetryDecision -Descriptor $Descriptor -Method POST -StatusCode 503 `
                    -AttemptCertainty Ambiguous -HasRetryAfter $false -IsKnownTransient409 $false -ForceRefreshUsed $false -CanRefresh $true
            }
            $d.ShouldRetry | Should -BeFalse
            $d.Outcome | Should -Be 'Failed'
            $d.Certainty | Should -Be 'Indeterminate'
        }

        It 'does not replay an ambiguous timeout POST' {
            $d = InModuleScope GraphKit -ArgumentList (New-TestDescriptor -ReplayPolicy NeverReplay) {
                param($Descriptor)
                Get-GraphRetryDecision -Descriptor $Descriptor -Method POST -StatusCode 408 `
                    -AttemptCertainty Ambiguous -HasRetryAfter $false -IsKnownTransient409 $false -ForceRefreshUsed $false -CanRefresh $true
            }
            $d.ShouldRetry | Should -BeFalse
            $d.Outcome | Should -Be 'Failed'
            $d.Certainty | Should -Be 'Indeterminate'
        }

        It 'reconciles under Reconciliable' {
            $d = InModuleScope GraphKit -ArgumentList (New-TestDescriptor -ReplayPolicy Reconciliable) {
                param($Descriptor)
                Get-GraphRetryDecision -Descriptor $Descriptor -Method POST -StatusCode 503 `
                    -AttemptCertainty Ambiguous -HasRetryAfter $false -IsKnownTransient409 $false -ForceRefreshUsed $false -CanRefresh $true
            }
            $d.ShouldRetry | Should -BeFalse
            $d.Reconcile | Should -BeTrue
            $d.Outcome | Should -Be 'Failed'
            $d.Certainty | Should -Be 'Indeterminate'
        }

        It 'replays Conditional only with explicit ambiguous-transport permission' {
            $permitted = InModuleScope GraphKit -ArgumentList (New-TestDescriptor -ReplayPolicy Conditional -Method PUT -Condition @{ Method = 'PUT'; AllowAmbiguousTransport = $true }) {
                param($Descriptor)
                Get-GraphRetryDecision -Descriptor $Descriptor -Method PUT -StatusCode 503 `
                    -AttemptCertainty Ambiguous -HasRetryAfter $false -IsKnownTransient409 $false -ForceRefreshUsed $false -CanRefresh $true
            }
            $permitted.ShouldRetry | Should -BeTrue

            $denied = InModuleScope GraphKit -ArgumentList (New-TestDescriptor -ReplayPolicy Conditional -Method PUT -Condition @{ Method = 'PUT' }) {
                param($Descriptor)
                Get-GraphRetryDecision -Descriptor $Descriptor -Method PUT -StatusCode 503 `
                    -AttemptCertainty Ambiguous -HasRetryAfter $false -IsKnownTransient409 $false -ForceRefreshUsed $false -CanRefresh $true
            }
            $denied.ShouldRetry | Should -BeFalse
            $denied.Certainty | Should -Be 'Indeterminate'
        }
    }
}
