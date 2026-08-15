BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw "No built GraphKit module found under '$repoRoot/output/module/GraphKit'. Run './build.ps1 -Tasks build' first."
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force -ErrorAction Stop
}

Describe 'Get-GraphRetryDelay' {

    Context 'whole-value delta-seconds' {
        It 'parses a plain integer' {
            $r = InModuleScope GraphKit {
                Get-GraphRetryDelay -RetryAfterValues '30' -UtcNow ([datetime] '2026-01-01T00:00:00Z') -Attempt 1 -Jitter { 1.0 }
            }
            $r.DelaySeconds | Should -Be 30
            $r.Source | Should -Be 'RetryAfterDelta'
            $r.Malformed | Should -BeFalse
        }
    }

    Context 'whole-value HTTP-date' {
        It 'computes delta against the response Date header' {
            $r = InModuleScope GraphKit {
                Get-GraphRetryDelay -RetryAfterValues 'Thu, 01 Jan 2026 00:00:30 GMT' `
                    -ResponseDate ([datetime] '2026-01-01T00:00:00Z') -UtcNow ([datetime] '2026-01-01T00:00:00Z') -Attempt 1 -Jitter { 1.0 }
            }
            $r.DelaySeconds | Should -Be 30
            $r.Source | Should -Be 'RetryAfterDate'
            $r.Malformed | Should -BeFalse
        }

        It 'uses the Date header so workstation skew cannot shorten the delay' {
            # Workstation clock is 5 minutes ahead of the server.
            $r = InModuleScope GraphKit {
                Get-GraphRetryDelay -RetryAfterValues 'Thu, 01 Jan 2026 00:00:30 GMT' `
                    -ResponseDate ([datetime] '2026-01-01T00:00:00Z') -UtcNow ([datetime] '2026-01-01T00:05:00Z') -Attempt 1 -Jitter { 1.0 }
            }
            $r.DelaySeconds | Should -Be 30
        }

        It 'does not split a comma inside an HTTP date' {
            $r = InModuleScope GraphKit {
                Get-GraphRetryDelay -RetryAfterValues 'Wed, 21 Oct 2015 07:28:00 GMT' `
                    -ResponseDate ([datetime] '2015-10-21T07:27:30Z') -UtcNow ([datetime] '2026-01-01T00:00:00Z') -Attempt 1 -Jitter { 1.0 }
            }
            $r.DelaySeconds | Should -Be 30
            $r.Source | Should -Be 'RetryAfterDate'
            $r.Malformed | Should -BeFalse
        }
    }

    Context 'malformed comma-separated numeric list' {
        It 'falls back to the comma list and flags malformed' {
            $r = InModuleScope GraphKit {
                Get-GraphRetryDelay -RetryAfterValues '30,120' -UtcNow ([datetime] '2026-01-01T00:00:00Z') -Attempt 1 -Jitter { 1.0 }
            }
            $r.DelaySeconds | Should -Be 120
            $r.Source | Should -Be 'RetryAfterList'
            $r.Malformed | Should -BeTrue
        }
    }

    Context 'multiple header values as a collection' {
        It 'chooses the conservative maximum' {
            $r = InModuleScope GraphKit {
                Get-GraphRetryDelay -RetryAfterValues @('30', '60') -UtcNow ([datetime] '2026-01-01T00:00:00Z') -Attempt 1 -Jitter { 1.0 }
            }
            $r.DelaySeconds | Should -Be 60
            $r.Source | Should -Be 'RetryAfterDelta'
        }
    }

    Context 'x-ms-retry-after-ms' {
        It 'parses milliseconds separately' {
            $r = InModuleScope GraphKit {
                Get-GraphRetryDelay -RetryAfterValues $null -XmsRetryAfterMs '5000' -UtcNow ([datetime] '2026-01-01T00:00:00Z') -Attempt 1 -Jitter { 1.0 }
            }
            $r.DelaySeconds | Should -Be 5
            $r.Source | Should -Be 'XmsRetryAfterMs'
        }
    }

    Context 'source precedence' {
        It 'prefers the larger of Retry-After (date) and x-ms-retry-after-ms' {
            $r = InModuleScope GraphKit {
                Get-GraphRetryDelay -RetryAfterValues 'Thu, 01 Jan 2026 00:01:00 GMT' `
                    -ResponseDate ([datetime] '2026-01-01T00:00:00Z') -XmsRetryAfterMs '5000' -UtcNow ([datetime] '2026-01-01T00:00:00Z') -Attempt 1 -Jitter { 1.0 }
            }
            $r.DelaySeconds | Should -Be 60
            $r.Source | Should -Be 'RetryAfterDate'
        }

        It 'prefers the larger of delta-seconds and x-ms-retry-after-ms' {
            $r = InModuleScope GraphKit {
                Get-GraphRetryDelay -RetryAfterValues '30' -XmsRetryAfterMs '60000' -UtcNow ([datetime] '2026-01-01T00:00:00Z') -Attempt 1 -Jitter { 1.0 }
            }
            $r.DelaySeconds | Should -Be 60
            $r.Source | Should -Be 'XmsRetryAfterMs'
        }
    }

    Context 'clamping' {
        It 'never yields a negative delay, and does not retry instantly on a negative value' {
            # The spec's "clamp negative values" exists so a malformed header cannot
            # produce a negative sleep. It was previously implemented as clamp-to-zero,
            # which meant a malformed 'Retry-After: -5' retried IMMEDIATELY against an
            # endpoint that had just refused the request. A negative (or zero) value is
            # not a usable server directive, so it now falls through to jittered
            # exponential backoff: still never negative, but no longer instant.
            $r = InModuleScope GraphKit {
                Get-GraphRetryDelay -RetryAfterValues '-5' -UtcNow ([datetime] '2026-01-01T00:00:00Z') -Attempt 1 -Jitter { 1.0 }
            }
            $r.DelaySeconds | Should -BeGreaterThan 0
            $r.Source | Should -Be 'ExponentialBackoff'
        }

        It 'does not retry instantly when the server sends a literal zero' {
            $r = InModuleScope GraphKit {
                Get-GraphRetryDelay -RetryAfterValues '0' -UtcNow ([datetime] '2026-01-01T00:00:00Z') -Attempt 1 -Jitter { 1.0 }
            }
            $r.DelaySeconds | Should -BeGreaterThan 0
        }

        It 'clamps excessive values to the configured maximum' {
            $r = InModuleScope GraphKit {
                Get-GraphRetryDelay -RetryAfterValues '10000' -UtcNow ([datetime] '2026-01-01T00:00:00Z') -Attempt 1 -Jitter { 1.0 } -MaximumAcceptedSeconds 120
            }
            $r.DelaySeconds | Should -Be 120
        }
    }

    Context 'no usable header' {
        It 'computes jittered exponential backoff' {
            $r = InModuleScope GraphKit {
                Get-GraphRetryDelay -RetryAfterValues $null -UtcNow ([datetime] '2026-01-01T00:00:00Z') -Attempt 3 -Jitter { 0.5 } -BaseDelaySeconds 1 -MaximumAcceptedSeconds 120
            }
            # base 1s doubling: attempt 3 -> 4s, jitter 0.5 -> 2s
            $r.DelaySeconds | Should -Be 2
            $r.Source | Should -Be 'ExponentialBackoff'
        }

        It 'flags an unparseable header as malformed and falls back to backoff' {
            $r = InModuleScope GraphKit {
                Get-GraphRetryDelay -RetryAfterValues 'garbage' -UtcNow ([datetime] '2026-01-01T00:00:00Z') -Attempt 1 -Jitter { 1.0 }
            }
            $r.Malformed | Should -BeTrue
            $r.Source | Should -Be 'ExponentialBackoff'
        }
    }
}
