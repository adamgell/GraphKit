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
            Mock Get-GraphOperation -ModuleName GraphKit { return @{ ReplayPolicy = 'NeverReplay'; Method = 'POST'; PathTemplate = '/write' } }

            {
                Invoke-GraphBatch -Context $script:Context -Requests @(
                    @{ Id = '1'; Method = 'POST'; Uri = 'https://graph.microsoft.com/v1.0/write'; Type = 'Thing'; Operation = 'Write' }
                ) -DelayScript $script:NoopDelay
            } | Should -Throw -ExpectedMessage '*NeverReplay*'
        }

        It 'allows a write subrequest proven Safe by its descriptor' {
            Reset-BatchState
            Mock Get-GraphOperation -ModuleName GraphKit { return @{ ReplayPolicy = 'Safe'; Method = 'POST'; PathTemplate = '/write' } }
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
            Mock Get-GraphOperation -ModuleName GraphKit { return @{ ReplayPolicy = 'Safe'; Method = 'POST'; PathTemplate = '/write' } }

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

Describe 'Batch refuses to carry a mutating subrequest' {
    # This guard is why Invoke-GraphBatch needs no ShouldProcess gate of its own: a batch cannot
    # mutate anything, by construction. That makes it load-bearing - and it had NO test, so a
    # refactor could have deleted it and every existing test would still have passed. The gate on
    # Invoke-GraphOperation would then have been the only write protection in the module, with a
    # completely ungated bulk path sitting next to it.

    BeforeAll {
        $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
        $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
            Sort-Object Name -Descending | Select-Object -First 1
        Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force

        $script:ctx = [PSCustomObject]@{
            ProfileId    = 'batch-guard-probe'
            GraphBaseUri = [uri] 'https://graph.microsoft.com'
            TokenSource  = $null
            TenantId     = [guid]::Empty
        }
    }

    It 'refuses a write whose descriptor is not ReplayPolicy Safe' {
        # MobileApp.Assign is the catalog's one genuine mutation (NeverReplay). $batch retries the
        # whole envelope, so a non-replay-safe subrequest inside it could be re-sent after a
        # partial failure with no way to know whether it already committed.
        {
            Invoke-GraphBatch -Context $script:ctx -Requests @(
                @{ Id = '1'; Method = 'POST'
                   Uri = 'https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps/x/assign'
                   Type = 'MobileApp'; Operation = 'Assign'; Body = @{} }
            )
        } | Should -Throw -ExpectedMessage '*only Safe writes may be batched*'
    }

    It 'refuses a write that names no descriptor at all' {
        # Without this, a caller could smuggle any mutation into a batch simply by omitting the
        # Type/Operation that would have revealed its ReplayPolicy - the guard would have nothing
        # to consult and the request would sail through.
        {
            Invoke-GraphBatch -Context $script:ctx -Requests @(
                @{ Id = '1'; Method = 'DELETE'
                   Uri = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/x' }
            )
        } | Should -Throw -ExpectedMessage '*requires Type and Operation*'
    }

    It 'refuses every mutating verb, not just the one that was tested' {
        foreach ($verb in @('POST', 'PUT', 'PATCH', 'DELETE')) {
            {
                Invoke-GraphBatch -Context $script:ctx -Requests @(
                    @{ Id = '1'; Method = $verb; Uri = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/x' }
                )
            } | Should -Throw -Because "$verb must not bypass the batch write guard"
        }
    }
}

Describe 'The batch guard cannot be forged' {
    # The guard checked only the NAMED descriptor's ReplayPolicy while forwarding the caller's
    # Method and Uri verbatim, so any Safe read descriptor was a skeleton key to any verb at any
    # URL. Three tests existed for this guard and all three passed, because every one declared its
    # subrequest honestly - and the mock returned a descriptor carrying ONLY ReplayPolicy, mocking
    # away the very fields a forgery abuses. The tests could not have caught it.

    BeforeAll {
        $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
        $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
            Sort-Object Name -Descending | Select-Object -First 1
        Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force
        $script:ctx = [PSCustomObject]@{
            ProfileId = 'forge-probe'; GraphBaseUri = [uri] 'https://graph.microsoft.com'
            TokenSource = $null; TenantId = [guid]::Empty
        }
    }

    It 'refuses a subrequest whose METHOD differs from its declared descriptor' {
        {
            Invoke-GraphBatch -Context $script:ctx -Requests @(
                @{ Id = '1'; Method = 'POST'
                   Uri = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices'
                   Type = 'ManagedDevice'; Operation = 'List' })
        } | Should -Throw -ExpectedMessage '*whose method is GET, but sends POST*'
    }

    It 'refuses a subrequest whose PATH does not match its declared descriptor' {
        # The forgery that reaches the path check: DeviceReport/Export is POST and Safe, so the
        # method matches and only the path can catch it. Declaring ManagedDevice/List instead
        # would trip the METHOD check first and never exercise this one.
        # Assert the SPECIFIC guard message. A bare -Throw passed even with the guard deleted,
        # because this probe context has no token source and the call throws anyway - the test was
        # green for the wrong reason and a mutation proved it.
        {
            Invoke-GraphBatch -Context $script:ctx -Requests @(
                @{ Id = '1'; Method = 'POST'
                   Uri = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/abc/wipe'
                   Body = @{ keepEnrollmentData = $false }
                   Type = 'DeviceReport'; Operation = 'Export' })
        } | Should -Throw -ExpectedMessage '*does not match the path template*'
    }

    It 'still accepts an honest subrequest whose id varies' {
        # The path check compares SHAPE, not the literal path - {id} must still match any id, or
        # every parameterized read in a batch would break.
        # Assert it gets PAST the guard, not that it succeeds: this probe context deliberately
        # carries no token source, so the call must fail at credential policy. Asserting
        # -Not -Throw here would be testing the fixture, not the guard.
        $err = $null
        try {
            Invoke-GraphBatch -Context $script:ctx -Requests @(
                @{ Id = '1'; Method = 'GET'
                   Uri = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/any-id-here' })
        } catch { $err = $_.Exception.Message }

        $err | Should -Not -BeLike '*does not match the path template*' -Because 'a varying id must still match the shape'
        $err | Should -Not -BeLike '*must match the request*'
        $err | Should -BeLike '*token source*' -Because 'it should reach credential policy, which is past the guard'
    }
}

