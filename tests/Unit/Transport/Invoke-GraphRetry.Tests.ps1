BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw "No built GraphKit module found under '$repoRoot/output/module/GraphKit'. Run './build.ps1 -Tasks build' first."
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force -ErrorAction Stop

    # ---- Throttle seam (not this suite's subject): recording mocks that replace ----
    # ---- the live throttle functions inside the module. Live calls are impossible ----
    # ---- because these mocks match every call. ----
    Mock New-GraphThrottleScope -ModuleName GraphKit {
        return $script:scopeToReturn
    }
    Mock Wait-GraphThrottleGate -ModuleName GraphKit {
        if ($null -ne $script:throttleWaitScript) { & $script:throttleWaitScript }
        return $script:admissionToReturn
    }
    Mock Complete-GraphThrottleGate -ModuleName GraphKit {
        param($Admission, [switch] $Success)
        $script:completeCalls++
    }
    Mock Update-GraphThrottleState -ModuleName GraphKit {
        param($Scope, [bool] $Qualified, [int] $RetryAfterSeconds, [int] $StatusCode)

        $script:throttleUpdates.Add([pscustomobject] @{
            Qualified         = $Qualified
            RetryAfterSeconds = $RetryAfterSeconds
            StatusCode        = $StatusCode
            Scope             = $Scope
        })
    }

    function New-TestTransportResult {
        param(
            [int] $StatusCode = 200,
            [hashtable] $Headers = @{},
            [object] $Body = $null,
            [bool] $ResponseReceived = $true,
            [string] $RequestId = $null
        )

        # Duck-typed GraphTransportResult: plain PSCustomObject, never a module class.
        return [pscustomobject] @{
            StatusCode         = $StatusCode
            Headers            = $Headers
            Body               = $Body
            RequestId          = $RequestId
            TransportException = $null
            ResponseReceived   = $ResponseReceived
        }
    }

    function New-TestContext {
        param([object] $TokenSource = $null, [string] $IdentityState = 'VerifiedForToken')

        return [pscustomobject] @{
            ProfileId             = 'ivy24'
            TenantId              = [guid] '00000000-0000-0000-0000-000000000001'
            Cloud                 = 'Global'
            GraphBaseUri          = [uri] 'https://graph.microsoft.com'
            ClientId              = 'client'
            TokenSource           = $TokenSource
            CredentialFingerprint = 'test-fingerprint'
            AcquisitionCacheKey   = 'test-acquisition-cache-key'
            IdentityState         = $IdentityState
        }
    }

    function New-TestDescriptor {
        param(
            [string] $ReplayPolicy = 'Safe',
            [string] $CredentialPolicy = 'None',
            [string] $ApiVersion = 'v1.0',
            [string] $ResourceFamily = 'Test.Family',
            [hashtable] $Condition = $null
        )

        return @{
            ReplayPolicy     = $ReplayPolicy
            CredentialPolicy = $CredentialPolicy
            ApiVersion       = $ApiVersion
            ResourceFamily   = $ResourceFamily
            Condition        = $Condition
            Reconciliation   = $null
        }
    }

    function New-TestSend {
        return {
            param($Uri, $Method, $Headers, $Body, $CancellationToken, $CredentialPolicy, $TokenSource, $ExpectedAuthority, $TargetTenantId, $VerifyTenantBinding)
            $script:sendCount++
            $script:lastSendHeaders = $Headers
            return $script:results.Dequeue()
        }
    }

    function New-TestInjections {
        return @{
            Send   = (New-TestSend)
            UtcNow = { $script:clock }
            Delay  = { param([double] $s) $script:clock = $script:clock.AddSeconds($s); $script:requestedDelays.Add($s) }
            Jitter = { 0.5 }
        }
    }

    function New-TestTokenSource {
        param([bool] $CanRefresh = $true, [guid] $VerifiedTenantId = [guid] '00000000-0000-0000-0000-000000000001')

        $source = [pscustomobject] @{
            CanRefresh           = $CanRefresh
            VerifiedTenantId     = $VerifiedTenantId
            CredentialGeneration = 'test-generation'
        }

        # Duck-typed GraphTokenSource: Acquire is a ScriptMethod so the module can
        # invoke it as .Acquire($force, $ct). $this binds to the source at call time.
        $source = $source | Add-Member -MemberType ScriptMethod -Name Acquire -Value {
            param([bool] $forceRefresh, $ct)
            $script:acquireCalls.Add($forceRefresh)
            return [pscustomobject] @{
                AccessToken          = 'test-token'
                ExpiresOnUtc         = [System.DateTimeOffset]::UtcNow.AddHours(1)
                VerifiedTenantId     = $this.VerifiedTenantId
                TokenFingerprint     = 'test-token-fingerprint'
                CredentialGeneration = $this.CredentialGeneration
            }
        } -PassThru

        return $source
    }
}

Describe 'Invoke-GraphRetry (virtual clock)' {

    Context 'shared test state' {
        BeforeEach {
            $script:results = [System.Collections.Generic.Queue[object]]::new()
            $script:sendCount = 0
            $script:requestedDelays = [System.Collections.Generic.List[double]]::new()
            $script:clock = [datetime] '2026-01-01T00:00:00Z'
            $script:throttleUpdates = [System.Collections.Generic.List[object]]::new()
            $script:completeCalls = 0
            $script:acquireCalls = [System.Collections.Generic.List[bool]]::new()
            $script:lastSendHeaders = $null
            $script:scopeToReturn = @{
                CoarseKey      = 'Global|tenant|client|Read'
                LeafKey        = 'Global|tenant|client|Test.Family|Read'
                ThrottleClass  = 'Read'
                ResourceFamily = 'Test.Family'
                Cloud          = 'Global'
                TenantId       = 'tenant'
                ClientId       = 'client'
            }
            $script:admissionToReturn = @{ Admission = 1 }
            $script:throttleWaitScript = $null
        }

        Context 'retry matrix' {
            It 'requests the exact server-directed delay and replays' {
                $script:results.Enqueue((New-TestTransportResult -StatusCode 429 -Headers @{ 'Retry-After' = '30' }))
                $script:results.Enqueue((New-TestTransportResult -StatusCode 200 -Body @{ value = @() }))

                $r = InModuleScope GraphKit -ArgumentList (New-TestContext), (New-TestDescriptor), (New-TestInjections) {
                    param($Context, $Descriptor, $Injections)
                    Invoke-GraphRetry -Context $Context -Descriptor $Descriptor `
                        -Uri ([uri] 'https://graph.microsoft.com/v1.0/me') -Method GET -Headers @{} -Body $null `
                        -CancellationToken ([System.Threading.CancellationToken]::None) -Injections $Injections
                }

                $r.Outcome | Should -Be 'Succeeded'
                $script:sendCount | Should -Be 2
                $script:requestedDelays.Count | Should -Be 1
                $script:requestedDelays[0] | Should -Be 30
            }

            It 'accepts 202 + Retry-After as success and records pacing without replaying' {
                $script:results.Enqueue((New-TestTransportResult -StatusCode 202 -Headers @{ 'Retry-After' = '60' } -Body @{}))

                $r = InModuleScope GraphKit -ArgumentList (New-TestContext), (New-TestDescriptor), (New-TestInjections) {
                    param($Context, $Descriptor, $Injections)
                    Invoke-GraphRetry -Context $Context -Descriptor $Descriptor `
                        -Uri ([uri] 'https://graph.microsoft.com/v1.0/me') -Method GET -Headers @{} -Body $null `
                        -CancellationToken ([System.Threading.CancellationToken]::None) -Injections $Injections
                }

                $r.Outcome | Should -Be 'Succeeded'
                $r.Certainty | Should -Be 'Known'
                $script:sendCount | Should -Be 1
                $script:requestedDelays.Count | Should -Be 0
                $r.Telemetry[0].DelaySeconds | Should -Be 60
                $r.Telemetry[0].DelaySource | Should -Be 'RetryAfterDelta'
            }

            It 'does not replay an ambiguous POST and surfaces Failed + Indeterminate' {
                $script:results.Enqueue((New-TestTransportResult -StatusCode 503))

                $r = InModuleScope GraphKit -ArgumentList (New-TestContext), (New-TestDescriptor -ReplayPolicy NeverReplay), (New-TestInjections) {
                    param($Context, $Descriptor, $Injections)
                    Invoke-GraphRetry -Context $Context -Descriptor $Descriptor `
                        -Uri ([uri] 'https://graph.microsoft.com/v1.0/me') -Method POST -Headers @{} -Body @{} `
                        -CancellationToken ([System.Threading.CancellationToken]::None) -Injections $Injections
                }

                $r.Outcome | Should -Be 'Failed'
                $r.Certainty | Should -Be 'Indeterminate'
                $script:sendCount | Should -Be 1
            }

            It 'forces exactly one token refresh after a 401, then replays' {
                $tokenSource = New-TestTokenSource
                $script:results.Enqueue((New-TestTransportResult -StatusCode 401))
                $script:results.Enqueue((New-TestTransportResult -StatusCode 200 -Body @{ value = @() }))

                $r = InModuleScope GraphKit -ArgumentList (New-TestContext -TokenSource $tokenSource), (New-TestDescriptor -CredentialPolicy GraphBearer), (New-TestInjections) {
                    param($Context, $Descriptor, $Injections)
                    Invoke-GraphRetry -Context $Context -Descriptor $Descriptor `
                        -Uri ([uri] 'https://graph.microsoft.com/v1.0/me') -Method GET -Headers @{} -Body $null `
                        -CancellationToken ([System.Threading.CancellationToken]::None) -Injections $Injections
                }

                $r.Outcome | Should -Be 'Succeeded'
                $script:sendCount | Should -Be 2
                $script:acquireCalls.Count | Should -Be 2
                $script:acquireCalls | Should -Contain $true
            }

            It 'stops after a second 401 without looping' {
                $tokenSource = New-TestTokenSource
                $script:results.Enqueue((New-TestTransportResult -StatusCode 401))
                $script:results.Enqueue((New-TestTransportResult -StatusCode 401))

                $r = InModuleScope GraphKit -ArgumentList (New-TestContext -TokenSource $tokenSource), (New-TestDescriptor -CredentialPolicy GraphBearer), (New-TestInjections) {
                    param($Context, $Descriptor, $Injections)
                    Invoke-GraphRetry -Context $Context -Descriptor $Descriptor `
                        -Uri ([uri] 'https://graph.microsoft.com/v1.0/me') -Method GET -Headers @{} -Body $null `
                        -CancellationToken ([System.Threading.CancellationToken]::None) -Injections $Injections -MaxAttempts 10
                }

                $r.Outcome | Should -Be 'Failed'
                $r.Certainty | Should -Be 'Known'
                $script:sendCount | Should -Be 2
            }
        }

        Context 'deadlines and cancellation' {
            It 'returns DeadlineExpired when the deadline expires while throttled' {
                $script:throttleWaitScript = { $script:clock = $script:clock.AddSeconds(400) }

                $r = InModuleScope GraphKit -ArgumentList (New-TestContext), (New-TestDescriptor), (New-TestInjections) {
                    param($Context, $Descriptor, $Injections)
                    Invoke-GraphRetry -Context $Context -Descriptor $Descriptor `
                        -Uri ([uri] 'https://graph.microsoft.com/v1.0/me') -Method GET -Headers @{} -Body $null `
                        -CancellationToken ([System.Threading.CancellationToken]::None) -Injections $Injections -DeadlineSeconds 300
                }

                $r.Outcome | Should -Be 'DeadlineExpired'
                $r.Certainty | Should -Be 'Indeterminate'
                $script:sendCount | Should -Be 0
            }

            It 'returns Cancelled for a pre-cancelled token' {
                $cts = [System.Threading.CancellationTokenSource]::new()
                $cts.Cancel()

                $r = InModuleScope GraphKit -ArgumentList (New-TestContext), (New-TestDescriptor), (New-TestInjections), $cts.Token {
                    param($Context, $Descriptor, $Injections, $CancellationToken)
                    Invoke-GraphRetry -Context $Context -Descriptor $Descriptor `
                        -Uri ([uri] 'https://graph.microsoft.com/v1.0/me') -Method GET -Headers @{} -Body $null `
                        -CancellationToken $CancellationToken -Injections $Injections
                }

                $r.Outcome | Should -Be 'Cancelled'
                $script:sendCount | Should -Be 0
            }
        }

        Context 'attempt accounting' {
            It 'performs exactly one send per attempt' {
                $script:results.Enqueue((New-TestTransportResult -StatusCode 429 -Headers @{ 'Retry-After' = '1' }))
                $script:results.Enqueue((New-TestTransportResult -StatusCode 429 -Headers @{ 'Retry-After' = '1' }))
                $script:results.Enqueue((New-TestTransportResult -StatusCode 200 -Body @{ value = @() }))

                $r = InModuleScope GraphKit -ArgumentList (New-TestContext), (New-TestDescriptor), (New-TestInjections) {
                    param($Context, $Descriptor, $Injections)
                    Invoke-GraphRetry -Context $Context -Descriptor $Descriptor `
                        -Uri ([uri] 'https://graph.microsoft.com/v1.0/me') -Method GET -Headers @{} -Body $null `
                        -CancellationToken ([System.Threading.CancellationToken]::None) -Injections $Injections
                }

                $r.Outcome | Should -Be 'Succeeded'
                $script:sendCount | Should -Be 3
                $r.Telemetry.Count | Should -Be 3
                $r.Telemetry[0].Attempt | Should -Be 1
                $r.Telemetry[2].Attempt | Should -Be 3
            }
        }

        Context 'throttle state update' {
            It 'reports qualified throttle state when a server delay is present' {
                $script:results.Enqueue((New-TestTransportResult -StatusCode 429 -Headers @{ 'Retry-After' = '30' }))
                $script:results.Enqueue((New-TestTransportResult -StatusCode 200 -Body @{ value = @() }))

                $null = InModuleScope GraphKit -ArgumentList (New-TestContext), (New-TestDescriptor), (New-TestInjections) {
                    param($Context, $Descriptor, $Injections)
                    Invoke-GraphRetry -Context $Context -Descriptor $Descriptor `
                        -Uri ([uri] 'https://graph.microsoft.com/v1.0/me') -Method GET -Headers @{} -Body $null `
                        -CancellationToken ([System.Threading.CancellationToken]::None) -Injections $Injections
                }

                $script:throttleUpdates.Count | Should -Be 1
                $script:throttleUpdates[0].Qualified | Should -BeTrue
                $script:throttleUpdates[0].StatusCode | Should -Be 429
                $script:throttleUpdates[0].RetryAfterSeconds | Should -Be 30
            }

            It 'reports unqualified throttle state when no delay header exists' {
                $script:results.Enqueue((New-TestTransportResult -StatusCode 429))
                $script:results.Enqueue((New-TestTransportResult -StatusCode 200 -Body @{ value = @() }))

                $null = InModuleScope GraphKit -ArgumentList (New-TestContext), (New-TestDescriptor), (New-TestInjections) {
                    param($Context, $Descriptor, $Injections)
                    Invoke-GraphRetry -Context $Context -Descriptor $Descriptor `
                        -Uri ([uri] 'https://graph.microsoft.com/v1.0/me') -Method GET -Headers @{} -Body $null `
                        -CancellationToken ([System.Threading.CancellationToken]::None) -Injections $Injections
                }

                $script:throttleUpdates.Count | Should -Be 1
                $script:throttleUpdates[0].Qualified | Should -BeFalse
            }
        }

        Context 'envelope contract' {
            It 'returns an envelope with the exact contract field names' {
                $script:results.Enqueue((New-TestTransportResult -StatusCode 200 -Body @{ value = @(1, 2) }))

                $r = InModuleScope GraphKit -ArgumentList (New-TestContext), (New-TestDescriptor), (New-TestInjections) {
                    param($Context, $Descriptor, $Injections)
                    Invoke-GraphRetry -Context $Context -Descriptor $Descriptor `
                        -Uri ([uri] 'https://graph.microsoft.com/v1.0/me') -Method GET -Headers @{} -Body $null `
                        -CancellationToken ([System.Threading.CancellationToken]::None) -Injections $Injections
                }

                $r.PSObject.TypeNames | Should -Contain 'GraphKit.OperationResult'

                $names = @($r.PSObject.Properties.Name)
                foreach ($f in @('Data', 'Outcome', 'Certainty', 'Telemetry', 'Provenance')) {
                    $names | Should -Contain $f
                }

                $pn = @($r.Provenance.Keys)
                foreach ($f in @('ProfileId', 'TenantId', 'ApiVersion', 'ResourceFamily', 'RetrievedUtc', 'IdentityState', 'ActualTenantId')) {
                    $pn | Should -Contain $f
                }

                $r.Data | Should -Not -BeNullOrEmpty
                $r.Outcome | Should -Be 'Succeeded'
            }

            It 'adds a client-request-id header on every attempt' {
                $script:results.Enqueue((New-TestTransportResult -StatusCode 200 -Body @{ value = @() }))

                $null = InModuleScope GraphKit -ArgumentList (New-TestContext), (New-TestDescriptor), (New-TestInjections) {
                    param($Context, $Descriptor, $Injections)
                    Invoke-GraphRetry -Context $Context -Descriptor $Descriptor `
                        -Uri ([uri] 'https://graph.microsoft.com/v1.0/me') -Method GET -Headers @{} -Body $null `
                        -CancellationToken ([System.Threading.CancellationToken]::None) -Injections $Injections
                }

                $script:lastSendHeaders.ContainsKey('client-request-id') | Should -BeTrue
            }
        }
    }
}
