BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    # Import the BUILT module (never dot-source source files: they would redefine module classes
    # and Add-Type types in test scope). Pester discovers tests per file, so each file imports it.
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built GraphKit module found under output/module/GraphKit; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force

    $script:Context = [PSCustomObject]@{
        Cloud         = 'Global'
        GraphBaseUri  = [uri] 'https://graph.microsoft.com'
        ProfileId     = 'ivy24'
        TenantId      = [guid] '00000000-0000-0000-0000-000000000001'
        IdentityState = 'VerifiedForToken'
    }

    $script:NoopDelay = { param([int] $Seconds) }

    $script:RecordedBodies = [System.Collections.Generic.List[string]]::new()
    $script:RecordedDescriptor = $null
    $script:BatchQueue = [System.Collections.Generic.Queue[object]]::new()

    function New-BatchResponse {
        param([string] $Id, [int] $Status, $Body = $null, [hashtable] $Headers = @{})

        @{ id = $Id; status = $Status; headers = $Headers; body = $Body }
    }

    function New-BatchEnvelope {
        param([AllowNull()] [object[]] $Responses, [string] $Outcome = 'Succeeded', [string] $Certainty = 'Known')

        [PSCustomObject]@{
            PSTypeName = 'GraphKit.OperationResult'
            Data       = if ($Outcome -eq 'Succeeded') { @{ responses = @($Responses) } } else { @() }
            Outcome    = $Outcome
            Certainty  = $Certainty
            Telemetry  = @()
            Provenance = @{}
        }
    }

    function Reset-BatchState {
        $script:RecordedBodies.Clear()
        $script:RecordedDescriptor = $null
        $script:BatchQueue.Clear()
    }

    # The retry engine's live path must never escape a unit test. A default throwing mock is
    # registered before the per-test mocks; tests that exercise the transport path override it.
    Mock Invoke-GraphRetry -ModuleName GraphKit {
        throw 'Invoke-GraphRetry must be mocked in this test.'
    }
}

Describe 'Invoke-GraphBatch' {
    Context 'Ordered envelopes' {
        It 'returns one envelope per subrequest in submission order' {
            Reset-BatchState
            $script:BatchQueue.Enqueue((New-BatchEnvelope @(
                        (New-BatchResponse '2' 200 @{ id = 'two' }),
                        (New-BatchResponse '1' 200 @{ id = 'one' })
                    )))

            Mock Invoke-GraphRetry -ModuleName GraphKit {
                $script:RecordedBodies.Add($Body)
                $script:RecordedDescriptor = $Descriptor
                return $script:BatchQueue.Dequeue()
            }

            $result = Invoke-GraphBatch -Context $script:Context -Requests @(
                @{ Id = '1'; Method = 'GET'; Uri = 'https://graph.microsoft.com/v1.0/a' },
                @{ Id = '2'; Method = 'GET'; Uri = 'https://graph.microsoft.com/v1.0/b' }
            ) -DelayScript $script:NoopDelay

            @($result) | Should -HaveCount 2
            $result[0].Id | Should -Be '1'
            $result[1].Id | Should -Be '2'
            $result[0].Outcome | Should -Be 'Succeeded'
            $result[1].Outcome | Should -Be 'Succeeded'
        }
    }

    Context 'Dependency failures (424)' {
        It 'reports a 424 against the dependent subrequest with the blocking id recorded' {
            Reset-BatchState
            $script:BatchQueue.Enqueue((New-BatchEnvelope @(
                        (New-BatchResponse '1' 403),
                        (New-BatchResponse '2' 424)
                    )))

            Mock Invoke-GraphRetry -ModuleName GraphKit { return $script:BatchQueue.Dequeue() }

            $result = Invoke-GraphBatch -Context $script:Context -Requests @(
                @{ Id = '1'; Method = 'GET'; Uri = 'https://graph.microsoft.com/v1.0/a' },
                @{ Id = '2'; Method = 'GET'; Uri = 'https://graph.microsoft.com/v1.0/b'; DependsOn = @('1') }
            ) -DelayScript $script:NoopDelay

            $result[1].Id | Should -Be '2'
            $result[1].Outcome | Should -Be 'Failed'
            $result[1].BlockedById | Should -Contain '1'
        }
    }

    Context 'Read-only by default' {
        It 'rejects a write subrequest without a Safe descriptor' {
            {
                Invoke-GraphBatch -Context $script:Context -Requests @(
                    @{ Id = '1'; Method = 'POST'; Uri = 'https://graph.microsoft.com/v1.0/write' }
                ) -DelayScript $script:NoopDelay
            } | Should -Throw -ExpectedMessage '*Safe*'
        }

        It 'rejects a write whose descriptor is not Safe' {
            Mock Get-GraphOperation -ModuleName GraphKit { return @{ ReplayPolicy = 'NeverReplay' } }

            {
                Invoke-GraphBatch -Context $script:Context -Requests @(
                    @{ Id = '1'; Method = 'POST'; Uri = 'https://graph.microsoft.com/v1.0/write'; Type = 'Thing'; Operation = 'Write' }
                ) -DelayScript $script:NoopDelay
            } | Should -Throw -ExpectedMessage '*NeverReplay*'
        }

        It 'allows a write subrequest proven Safe by its descriptor' {
            Reset-BatchState
            Mock Get-GraphOperation -ModuleName GraphKit { return @{ ReplayPolicy = 'Safe' } }
            $script:BatchQueue.Enqueue((New-BatchEnvelope @((New-BatchResponse '1' 204))))

            Mock Invoke-GraphRetry -ModuleName GraphKit { return $script:BatchQueue.Dequeue() }

            $result = Invoke-GraphBatch -Context $script:Context -Requests @(
                @{ Id = '1'; Method = 'POST'; Uri = 'https://graph.microsoft.com/v1.0/write'; Type = 'Thing'; Operation = 'Write'; Body = @{ x = 1 } }
            ) -DelayScript $script:NoopDelay

            @($result) | Should -HaveCount 1
            $result[0].Outcome | Should -Be 'Succeeded'
        }
    }

    Context 'Write replay safety' {
        It 'never replays a successful write subrequest when retrying failed reads' {
            Reset-BatchState
            Mock Get-GraphOperation -ModuleName GraphKit { return @{ ReplayPolicy = 'Safe' } }

            $script:BatchQueue.Enqueue((New-BatchEnvelope @(
                        (New-BatchResponse '1' 204),
                        (New-BatchResponse '2' 429 $null @{ 'Retry-After' = '0' })
                    )))
            $script:BatchQueue.Enqueue((New-BatchEnvelope @((New-BatchResponse '2' 200 @{ id = 'ok' }))))

            Mock Invoke-GraphRetry -ModuleName GraphKit {
                $script:RecordedBodies.Add($Body)
                return $script:BatchQueue.Dequeue()
            }

            $result = Invoke-GraphBatch -Context $script:Context -Requests @(
                @{ Id = '1'; Method = 'POST'; Uri = 'https://graph.microsoft.com/v1.0/write'; Type = 'Thing'; Operation = 'Write'; Body = @{ x = 1 } },
                @{ Id = '2'; Method = 'GET'; Uri = 'https://graph.microsoft.com/v1.0/read' }
            ) -DelayScript $script:NoopDelay

            $script:RecordedBodies | Should -HaveCount 2

            $retryBody = $script:RecordedBodies[1] | ConvertFrom-Json
            @($retryBody.requests) | Should -HaveCount 1
            $retryBody.requests[0].id | Should -Be '2'

            $result[0].Outcome | Should -Be 'Succeeded'
            $result[1].Outcome | Should -Be 'Succeeded'
        }
    }

    Context 'Whole-batch rules' {
        It 'surfaces every subrequest as indeterminate without replaying the whole batch' {
            Reset-BatchState
            $script:BatchQueue.Enqueue((New-BatchEnvelope $null 'Failed' 'Indeterminate'))

            Mock Invoke-GraphRetry -ModuleName GraphKit {
                $script:RecordedBodies.Add($Body)
                $script:RecordedDescriptor = $Descriptor
                return $script:BatchQueue.Dequeue()
            }

            $result = Invoke-GraphBatch -Context $script:Context -Requests @(
                @{ Id = '1'; Method = 'GET'; Uri = 'https://graph.microsoft.com/v1.0/a' },
                @{ Id = '2'; Method = 'GET'; Uri = 'https://graph.microsoft.com/v1.0/b' }
            ) -DelayScript $script:NoopDelay

            @($result) | Should -HaveCount 2
            $result[0].Outcome | Should -Be 'Failed'
            $result[0].Certainty | Should -Be 'Indeterminate'
            $result[1].Certainty | Should -Be 'Indeterminate'
            $script:RecordedBodies | Should -HaveCount 1
        }

        It 'marks the batch descriptor Safe when every subrequest is Safe' {
            Reset-BatchState
            $script:BatchQueue.Enqueue((New-BatchEnvelope @(
                        (New-BatchResponse '1' 200 @{ id = 'x' })
                    )))

            Mock Invoke-GraphRetry -ModuleName GraphKit {
                $script:RecordedDescriptor = $Descriptor
                return $script:BatchQueue.Dequeue()
            }

            $null = Invoke-GraphBatch -Context $script:Context -Requests @(
                @{ Id = '1'; Method = 'GET'; Uri = 'https://graph.microsoft.com/v1.0/a' }
            ) -DelayScript $script:NoopDelay

            $script:RecordedDescriptor.ReplayPolicy | Should -Be 'Safe'
        }
    }
}
