BeforeAll {
    $repoRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $built = Get-ChildItem -Path (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $built) {
        throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first, then re-run the tests.'
    }
    $script:BuiltManifest = Join-Path $built.FullName 'GraphKit.psd1'
    Import-Module $script:BuiltManifest -Force
}

Describe 'GraphTokenSource' {

    Context 'Token source implementations' {

        It 'ConfidentialClientTokenSource reports CanRefresh true and Certificate metadata' {
            InModuleScope GraphKit {
                $source = [ConfidentialClientTokenSource]::new(
                    { throw 'not invoked at construction' },
                    'Certificate',
                    'https://graph.microsoft.com',
                    '7d6e5f44-9999-8888-7777-666655554444',
                    'gen-cert'
                )
                $source.CanRefresh | Should -BeTrue
                $source.AuthMode | Should -Be 'Certificate'
                $source.Audience | Should -Be 'https://graph.microsoft.com'
                $source.CredentialGeneration | Should -Be 'gen-cert'
            }
        }

        It 'ManagedIdentityTokenSource reports CanRefresh true and ManagedIdentity metadata' {
            InModuleScope GraphKit {
                $source = [ManagedIdentityTokenSource]::new(
                    { throw 'not invoked at construction' },
                    'https://graph.microsoft.com',
                    '7d6e5f44-9999-8888-7777-666655554444',
                    'gen-mi'
                )
                $source.CanRefresh | Should -BeTrue
                $source.AuthMode | Should -Be 'ManagedIdentity'
            }
        }

        It 'ProviderTokenSource reports CanRefresh true and honors token plus expiry' {
            InModuleScope GraphKit {
                $state = @{ calls = 0 }
                $provider = {
                    $state.calls++
                    @{ Token = 'provider-token'; ExpiresOnUtc = (Get-Date).ToUniversalTime().AddHours(1) }
                }
                $source = [ProviderTokenSource]::new($provider, 'https://graph.microsoft.com', $null, 'gen-prov')

                $source.CanRefresh | Should -BeTrue
                $source.AuthMode | Should -Be 'Provider'

                $result = $source.Acquire($false, [System.Threading.CancellationToken]::None)
                $result.AccessToken | Should -Be 'provider-token'
                $result.TokenFingerprint | Should -Not -BeNullOrEmpty
                $state.calls | Should -Be 1

                # A cached token is reused without a second provider call.
                $null = $source.Acquire($false, [System.Threading.CancellationToken]::None)
                $state.calls | Should -Be 1
            }
        }

        It 'FixedBearerTokenSource reports CanRefresh false and fails immediately on forceRefresh' {
            InModuleScope GraphKit {
                $source = [FixedBearerTokenSource]::new('fixed-bearer', 'https://graph.microsoft.com', 'gen-fixed')
                $source.CanRefresh | Should -BeFalse
                $source.Acquire($false, [System.Threading.CancellationToken]::None).AccessToken | Should -Be 'fixed-bearer'

                { $source.Acquire($true, [System.Threading.CancellationToken]::None) } | Should -Throw
            }
        }
    }

    Context 'New-GraphTokenSource factory' {

        It 'builds the correct source per AuthMethod with the right CanRefresh' {
            InModuleScope GraphKit {
                $cloud = @{ GraphBaseUri = 'https://graph.microsoft.com'; Authority = 'https://login.microsoftonline.com'; Resource = 'https://graph.microsoft.com' }

                $secret = New-GraphTokenSource -Profile @{
                    AuthMethod = 'ClientSecret'; ClientId = '7d6e5f44-9999-8888-7777-666655554444'
                    Credential = @{ VaultName = 'v'; SecretName = 's' }
                } -Cloud $cloud -MsalFactory { throw 'not invoked' }
                $secret.CanRefresh | Should -BeTrue
                $secret.AuthMode | Should -Be 'ClientSecret'

                $cert = New-GraphTokenSource -Profile @{
                    AuthMethod = 'Certificate'; ClientId = $null
                    Credential = @{ PfxPath = '/tmp/x.pfx'; Password = @{ VaultName = 'v'; SecretName = 'p' } }
                } -Cloud $cloud -MsalFactory { throw 'not invoked' }
                $cert.CanRefresh | Should -BeTrue
                $cert.AuthMode | Should -Be 'Certificate'

                $mi = New-GraphTokenSource -Profile @{ AuthMethod = 'ManagedIdentity'; Credential = @{} } -Cloud $cloud
                $mi.CanRefresh | Should -BeTrue
                $mi.AuthMode | Should -Be 'ManagedIdentity'

                $bearer = New-GraphTokenSource -Profile @{
                    AuthMethod = 'BearerToken'; Credential = @{ Token = 'fixed-value' }
                } -Cloud $cloud
                $bearer.CanRefresh | Should -BeFalse
                $bearer.AuthMode | Should -Be 'BearerToken'
            }
        }
    }

    Context 'Assert-GraphTokenSource duck contract' {

        It 'accepts a source that satisfies the contract' {
            InModuleScope GraphKit {
                $source = [ProviderTokenSource]::new({ @{ Token = 't'; ExpiresOnUtc = (Get-Date).AddHours(1) } }, 'https://graph.microsoft.com', $null, 'g')
                { Assert-GraphTokenSource -Source $source } | Should -Not -Throw
            }
        }

        It 'names every missing member on a contract violation' {
            InModuleScope GraphKit {
                { Assert-GraphTokenSource -Source ([pscustomobject]@{ CanRefresh = $true }) } |
                    Should -Throw -ExpectedMessage '*AuthMode*'
            }
        }
    }

    Context 'Single-flight acquisition' {

        It 'runs the leader acquisition once and cleans up the flight' {
            InModuleScope GraphKit {
                $state = @{ calls = 0 }
                $result = Invoke-GraphTokenSingleFlight -Key 'leader-key' -AcquireScript { $state.calls++; 'leader-result' }
                $result | Should -Be 'leader-result'
                $state.calls | Should -Be 1
                [GraphTokenFlightRegistry]::Flights.ContainsKey('leader-key') | Should -BeFalse
            }
        }

        It 'returns the in-flight result to a concurrent caller without a second acquisition' {
            InModuleScope GraphKit {
                $flight = [GraphTokenFlight]::new()
                $null = $flight.Completion.TrySetResult('already-acquired')
                [GraphTokenFlightRegistry]::Flights['seeded-key'] = $flight

                try {
                    $state = @{ calls = 0 }
                    $result = Invoke-GraphTokenSingleFlight -Key 'seeded-key' -AcquireScript { $state.calls++; 'should-not-run' }
                    $result | Should -Be 'already-acquired'
                    $state.calls | Should -Be 0
                }
                finally {
                    $removed = [GraphTokenFlight]$null
                    $null = [GraphTokenFlightRegistry]::Flights.TryRemove('seeded-key', [ref]$removed)
                }
            }
        }

        It 'lets a cancelled waiter leave without cancelling or removing the shared flight' {
            InModuleScope GraphKit {
                $key = 'cancelled-waiter-key'
                $flight = [GraphTokenFlight]::new()
                [GraphTokenFlightRegistry]::Flights[$key] = $flight
                $cts = [System.Threading.CancellationTokenSource]::new()
                $cts.Cancel()

                try {
                    $state = @{ calls = 0 }
                    $message = try {
                        $null = Invoke-GraphTokenSingleFlight -Key $key -CancellationToken $cts.Token `
                            -AcquireScript { $state.calls++; 'should-not-run' }
                        ''
                    }
                    catch {
                        $_.Exception.Message
                    }

                    $message | Should -BeLike '*canceled*'
                    $state.calls | Should -Be 0
                    [GraphTokenFlightRegistry]::Flights.ContainsKey($key) | Should -BeTrue
                }
                finally {
                    if ($null -ne $flight.PSObject.Properties['Completion']) {
                        $null = $flight.Completion.TrySetResult('cleanup')
                    }
                    elseif ($null -ne $flight.PSObject.Properties['Done']) {
                        $flight.Done.Set()
                    }
                    $removed = [GraphTokenFlight]$null
                    $null = [GraphTokenFlightRegistry]::Flights.TryRemove($key, [ref]$removed)
                    $cts.Dispose()
                }
            }
        }

        It 'does not make a live waiter inherit cancellation from the former leader' {
            InModuleScope GraphKit {
                $key = 'cancelled-leader-key'
                $flight = [GraphTokenFlight]::new()
                $null = $flight.Completion.TrySetException(
                    [System.OperationCanceledException]::new('former leader cancelled')
                )
                $flight.LeaderCancellationRequested = $true
                [GraphTokenFlightRegistry]::Flights[$key] = $flight

                try {
                    $state = @{ calls = 0 }
                    $result = Invoke-GraphTokenSingleFlight -Key $key `
                        -CancellationToken ([System.Threading.CancellationToken]::None) `
                        -AcquireScript { $state.calls++; 'replacement-result' }

                    $result | Should -Be 'replacement-result'
                    $state.calls | Should -Be 1
                }
                finally {
                    $removed = [GraphTokenFlight]$null
                    $null = [GraphTokenFlightRegistry]::Flights.TryRemove($key, [ref]$removed)
                }
            }
        }

        It 'fans out an unsignalled provider cancellation exception without re-electing' {
            InModuleScope GraphKit {
                $key = 'provider-oce-key'
                $flight = [GraphTokenFlight]::new()
                $null = $flight.Completion.TrySetException(
                    [System.OperationCanceledException]::new('provider timed out internally')
                )
                [GraphTokenFlightRegistry]::Flights[$key] = $flight

                try {
                    $state = @{ calls = 0 }
                    {
                        $null = Invoke-GraphTokenSingleFlight -Key $key `
                            -CancellationToken ([System.Threading.CancellationToken]::None) `
                            -AcquireScript { $state.calls++; 'must-not-re-elect' }
                    } | Should -Throw -ExpectedMessage '*provider timed out internally*'

                    $state.calls | Should -Be 0
                }
                finally {
                    $removed = [GraphTokenFlight]$null
                    $null = [GraphTokenFlightRegistry]::Flights.TryRemove($key, [ref]$removed)
                }
            }
        }

        It 'adopts a shared forced-refresh result into the follower source cache' {
            InModuleScope GraphKit {
                $key = 'forced-refresh-cache-adoption-key'
                $leaderState = @{ calls = 0 }
                $followerState = @{ calls = 0 }
                $expiry = [System.DateTimeOffset]::UtcNow.AddHours(1)

                $leader = [ProviderTokenSource]::new({
                    $leaderState.calls++
                    $token = if ($leaderState.calls -eq 1) { 'leader-old-token' } else { 'shared-fresh-token' }
                    @{ Token = $token; ExpiresOnUtc = $expiry }
                }.GetNewClosure(), 'https://graph.microsoft.com', 'shared-client', 'shared-generation')
                $follower = [ProviderTokenSource]::new({
                    $followerState.calls++
                    @{ Token = 'follower-rejected-token'; ExpiresOnUtc = $expiry }
                }.GetNewClosure(), 'https://graph.microsoft.com', 'shared-client', 'shared-generation')

                $delayedOrdinary = $leader.Acquire($false, [System.Threading.CancellationToken]::None)
                $null = $follower.Acquire($false, [System.Threading.CancellationToken]::None)
                $fresh = $leader.Acquire($true, [System.Threading.CancellationToken]::None)

                $flightKey = Get-GraphTokenFlightKey -AcquisitionKey $key -ForceRefresh:$true
                $flight = [GraphTokenFlight]::new()
                $null = $flight.Completion.TrySetResult($fresh)
                [GraphTokenFlightRegistry]::Flights[$flightKey] = $flight

                try {
                    {
                        $null = Send-GraphHttpRequest `
                            -Uri ([uri] 'https://graph.microsoft.com/v1.0/mutation') `
                            -Method POST -Body @{} -CredentialPolicy GraphBearer `
                            -ExpectedAuthority ([uri] 'https://graph.microsoft.com') `
                            -TokenSource $follower -TokenAcquisitionKey $key -ForceRefresh:$true `
                            -TargetTenantId ([guid] '00000000-0000-0000-0000-000000000001') `
                            -VerifyTenantBinding -TenantBindingProver {
                                param($Context, $TokenResult, $CancellationToken)
                                throw 'cache-adoption-proof-sentinel'
                            }
                    } | Should -Throw -ExpectedMessage '*cache-adoption-proof-sentinel*'

                    $afterSharedRefresh = $follower.Acquire($false, [System.Threading.CancellationToken]::None)
                    $afterSharedRefresh.AccessToken | Should -Be 'shared-fresh-token'
                    $followerState.calls | Should -Be 1
                }
                finally {
                    $removed = [GraphTokenFlight]$null
                    $null = [GraphTokenFlightRegistry]::Flights.TryRemove($flightKey, [ref]$removed)
                }

                # Reproduce the dangerous ordering deterministically: the forced
                # result has already been adopted, then an ordinary flight from
                # the same clock tick, with a later expiry, reaches sender adoption
                # last. Forced-refresh precedence is the only reason it cannot win.
                $delayedOrdinary.ReceivedOnUtc = $fresh.ReceivedOnUtc
                $delayedOrdinary.ExpiresOnUtc = $fresh.ExpiresOnUtc.AddMinutes(30)
                $ordinaryFlightKey = Get-GraphTokenFlightKey -AcquisitionKey $key -ForceRefresh:$false
                $ordinaryFlight = [GraphTokenFlight]::new()
                $null = $ordinaryFlight.Completion.TrySetResult($delayedOrdinary)
                [GraphTokenFlightRegistry]::Flights[$ordinaryFlightKey] = $ordinaryFlight

                try {
                    {
                        $null = Send-GraphHttpRequest `
                            -Uri ([uri] 'https://graph.microsoft.com/v1.0/mutation') `
                            -Method POST -Body @{} -CredentialPolicy GraphBearer `
                            -ExpectedAuthority ([uri] 'https://graph.microsoft.com') `
                            -TokenSource $follower -TokenAcquisitionKey $key -ForceRefresh:$false `
                            -TargetTenantId ([guid] '00000000-0000-0000-0000-000000000001') `
                            -VerifyTenantBinding -TenantBindingProver {
                                param($Context, $TokenResult, $CancellationToken)
                                throw 'late-ordinary-proof-sentinel'
                            }
                    } | Should -Throw -ExpectedMessage '*late-ordinary-proof-sentinel*'
                }
                finally {
                    $removed = [GraphTokenFlight]$null
                    $null = [GraphTokenFlightRegistry]::Flights.TryRemove($ordinaryFlightKey, [ref]$removed)
                }

                $afterSharedRefresh = $follower.Acquire($false, [System.Threading.CancellationToken]::None)
                $afterSharedRefresh.AccessToken | Should -Be 'shared-fresh-token'
                $followerState.calls | Should -Be 1
            }
        }

        It 'collapses N concurrent same-tuple acquires to a single acquisition' {
            $key = 'tuple-key'

            $ready = [System.Threading.CountdownEvent]::new(8)
            $go = [System.Threading.ManualResetEventSlim]::new($false)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.Ready', $ready)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.Go', $go)

            $jobs = $null
            try {
                $jobs = 1..8 | ForEach-Object {
                    Start-ThreadJob -ThrottleLimit 8 -ScriptBlock {
                        param($key, $manifest)
                        Import-Module $manifest
                        $ready = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.Ready')
                        $go = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.Go')
                        $null = $ready.Signal()
                        $null = $go.Wait()
                        & (Get-Module GraphKit) {
                            Invoke-GraphTokenSingleFlight -Key $key -AcquireScript {
                                Start-Sleep -Milliseconds 400
                                [pscustomobject]@{ Token = [guid]::NewGuid().ToString() }
                            }
                        }
                    } -ArgumentList $key, $script:BuiltManifest
                }

                $null = $ready.Wait(15000)
                $go.Set()

                $results = @($jobs | Receive-Job -Wait -AutoRemoveJob)
                @($results.Token | Sort-Object -Unique).Count | Should -Be 1
            }
            finally {
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.Ready', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.Go', $null)
                if ($null -ne $jobs) {
                    $jobs | Where-Object { $_.State -ne 'Completed' } | Remove-Job -Force -ErrorAction SilentlyContinue
                }
            }
        }

        It 'surfaces an acquisition failure to every concurrent waiter' {
            $key = 'failure-key'

            $ready = [System.Threading.CountdownEvent]::new(8)
            $go = [System.Threading.ManualResetEventSlim]::new($false)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.Ready', $ready)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.Go', $go)

            $jobs = $null
            try {
                $jobs = 1..8 | ForEach-Object {
                    Start-ThreadJob -ThrottleLimit 8 -ScriptBlock {
                        param($key, $manifest)
                        Import-Module $manifest
                        $ready = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.Ready')
                        $go = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.Go')
                        $null = $ready.Signal()
                        $null = $go.Wait()
                        try {
                            $null = & (Get-Module GraphKit) {
                                Invoke-GraphTokenSingleFlight -Key $key -AcquireScript { throw 'acquisition failed' }
                            }
                            'ok'
                        }
                        catch {
                            'err'
                        }
                    } -ArgumentList $key, $script:BuiltManifest
                }

                $null = $ready.Wait(15000)
                $go.Set()

                $results = @($jobs | Receive-Job -Wait -AutoRemoveJob)
                @($results | Where-Object { $_ -ne 'err' }).Count | Should -Be 0
                $results.Count | Should -Be 8
            }
            finally {
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.Ready', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.Go', $null)
                if ($null -ne $jobs) {
                    $jobs | Where-Object { $_.State -ne 'Completed' } | Remove-Job -Force -ErrorAction SilentlyContinue
                }
            }
        }

        It 'fans one unsignalled provider cancellation exception out to concurrent waiters' {
            $key = 'provider-oce-concurrency-key'
            $calls = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
            $ready = [System.Threading.CountdownEvent]::new(8)
            $go = [System.Threading.ManualResetEventSlim]::new($false)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProviderOceCalls', $calls)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProviderOceReady', $ready)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProviderOceGo', $go)

            $jobs = $null
            try {
                $jobs = 1..8 | ForEach-Object {
                    Start-ThreadJob -ThrottleLimit 8 -ScriptBlock {
                        param($Key, $Manifest)
                        Import-Module $Manifest
                        $ready = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ProviderOceReady')
                        $go = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ProviderOceGo')
                        $null = $ready.Signal()
                        $null = $go.Wait()

                        try {
                            $null = & (Get-Module GraphKit) {
                                param($FlightKey)
                                Invoke-GraphTokenSingleFlight -Key $FlightKey `
                                    -CancellationToken ([System.Threading.CancellationToken]::None) `
                                    -AcquireScript {
                                        $queue = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ProviderOceCalls')
                                        $queue.Enqueue('acquire')
                                        Start-Sleep -Milliseconds 800
                                        throw [System.OperationCanceledException]::new('provider timed out internally')
                                    }
                            } $Key
                            'unexpected-success'
                        }
                        catch {
                            $_.Exception.Message
                        }
                    } -ArgumentList $key, $script:BuiltManifest
                }

                $ready.Wait(15000) | Should -BeTrue
                $go.Set()
                $results = @($jobs | Receive-Job -Wait -AutoRemoveJob)
                $jobs = $null

                $calls.Count | Should -Be 1
                $results.Count | Should -Be 8
                @($results | Where-Object { $_ -notlike '*provider timed out internally*' }).Count | Should -Be 0
            }
            finally {
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProviderOceCalls', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProviderOceReady', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProviderOceGo', $null)
                if ($null -ne $jobs) {
                    $jobs | Where-Object { $_.State -ne 'Completed' } | Remove-Job -Force -ErrorAction SilentlyContinue
                }
                $ready.Dispose()
                $go.Dispose()
            }
        }

        It 're-elects one replacement after an actual leader cancellation' {
            $key = 'actual-cancelled-leader-key'
            $leaderCts = [System.Threading.CancellationTokenSource]::new()
            $leaderStarted = [System.Threading.CountdownEvent]::new(1)
            $waitersReady = [System.Threading.CountdownEvent]::new(7)
            $waitersGo = [System.Threading.ManualResetEventSlim]::new($false)
            $replacementStarted = [System.Threading.CountdownEvent]::new(1)
            $releaseReplacement = [System.Threading.ManualResetEventSlim]::new($false)
            $calls = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.LeaderCts', $leaderCts)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.LeaderStarted', $leaderStarted)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.WaitersReady', $waitersReady)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.WaitersGo', $waitersGo)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ReplacementStarted', $replacementStarted)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ReleaseReplacement', $releaseReplacement)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.CancelledLeaderCalls', $calls)

            $leaderJob = $null
            $waiterJobs = $null
            try {
                $leaderJob = Start-ThreadJob -ScriptBlock {
                    param($Key, $Manifest)
                    Import-Module $Manifest
                    try {
                        $null = & (Get-Module GraphKit) {
                            param($FlightKey)
                            $cts = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.LeaderCts')
                            Invoke-GraphTokenSingleFlight -Key $FlightKey -CancellationToken $cts.Token `
                                -AcquireScript {
                                    $queue = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.CancelledLeaderCalls')
                                    $started = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.LeaderStarted')
                                    $queue.Enqueue('leader')
                                    $null = $started.Signal()
                                    $null = $cts.Token.WaitHandle.WaitOne()
                                    $cts.Token.ThrowIfCancellationRequested()
                                }.GetNewClosure()
                        } $Key
                        'unexpected-leader-success'
                    }
                    catch {
                        'leader-cancelled'
                    }
                } -ArgumentList $key, $script:BuiltManifest

                $leaderStarted.Wait(15000) | Should -BeTrue
                InModuleScope GraphKit -Parameters @{ K = $key } {
                    param($K)
                    $oldFlight = [GraphTokenFlightRegistry]::Flights[$K]
                    [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.OldLeaderFlight', $oldFlight)
                }

                $waiterJobs = 1..7 | ForEach-Object {
                    Start-ThreadJob -ThrottleLimit 8 -ScriptBlock {
                        param($Key, $Manifest)
                        Import-Module $Manifest
                        $ready = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.WaitersReady')
                        $go = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.WaitersGo')
                        $null = $ready.Signal()
                        $null = $go.Wait()

                        & (Get-Module GraphKit) {
                            param($FlightKey)
                            Invoke-GraphTokenSingleFlight -Key $FlightKey `
                                -CancellationToken ([System.Threading.CancellationToken]::None) `
                                -AcquireScript {
                                    $queue = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.CancelledLeaderCalls')
                                    $started = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ReplacementStarted')
                                    $release = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ReleaseReplacement')
                                    $queue.Enqueue('replacement')
                                    $null = $started.Signal()
                                    $null = $release.Wait()
                                    'replacement-result'
                                }
                        } $Key
                    } -ArgumentList $key, $script:BuiltManifest
                }

                $waitersReady.Wait(15000) | Should -BeTrue
                $waitersGo.Set()
                Start-Sleep -Milliseconds 200
                $leaderCts.Cancel()

                $replacementStarted.Wait(15000) | Should -BeTrue
                $leaderResult = @($leaderJob | Receive-Job -Wait)
                Remove-Job -Job $leaderJob -Force -ErrorAction SilentlyContinue
                $leaderJob = $null
                $leaderResult | Should -Contain 'leader-cancelled'

                # The old leader's finally block has now run while the replacement
                # is still held open. Its exact-instance cleanup must not remove the
                # replacement registered under the same key.
                InModuleScope GraphKit -Parameters @{ K = $key } {
                    param($K)
                    $oldFlight = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.OldLeaderFlight')
                    [GraphTokenFlightRegistry]::Flights.ContainsKey($K) | Should -BeTrue
                    [object]::ReferenceEquals([GraphTokenFlightRegistry]::Flights[$K], $oldFlight) | Should -BeFalse
                }

                $releaseReplacement.Set()
                $waiterResults = @($waiterJobs | Receive-Job -Wait)
                Remove-Job -Job $waiterJobs -Force -ErrorAction SilentlyContinue
                $waiterJobs = $null
                $waiterResults.Count | Should -Be 7
                @($waiterResults | Where-Object { $_ -ne 'replacement-result' }).Count | Should -Be 0
                @($calls | Where-Object { $_ -eq 'leader' }).Count | Should -Be 1
                @($calls | Where-Object { $_ -eq 'replacement' }).Count | Should -Be 1
                InModuleScope GraphKit -Parameters @{ K = $key } {
                    param($K)
                    [GraphTokenFlightRegistry]::Flights.ContainsKey($K) | Should -BeFalse
                }
            }
            finally {
                $releaseReplacement.Set()
                $waitersGo.Set()
                $leaderCts.Cancel()
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.LeaderCts', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.LeaderStarted', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.WaitersReady', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.WaitersGo', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ReplacementStarted', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ReleaseReplacement', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.CancelledLeaderCalls', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.OldLeaderFlight', $null)
                if ($null -ne $leaderJob -and $leaderJob.State -ne 'Completed') {
                    $leaderJob | Remove-Job -Force -ErrorAction SilentlyContinue
                }
                if ($null -ne $waiterJobs) {
                    $waiterJobs | Where-Object { $_.State -ne 'Completed' } | Remove-Job -Force -ErrorAction SilentlyContinue
                }
                $leaderCts.Dispose()
                $leaderStarted.Dispose()
                $waitersReady.Dispose()
                $waitersGo.Dispose()
                $replacementStarted.Dispose()
                $releaseReplacement.Dispose()
            }
        }

        It 'collapses real sender acquisitions across contexts sharing one canonical tuple' {
            $key = 'production-sender-tuple-key'
            $calls = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
            $ready = [System.Threading.CountdownEvent]::new(8)
            $go = [System.Threading.ManualResetEventSlim]::new($false)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProductionSingleFlightCalls', $calls)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProductionSingleFlightReady', $ready)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProductionSingleFlightGo', $go)

            $jobs = $null
            try {
                $jobs = 1..8 | ForEach-Object {
                    Start-ThreadJob -ThrottleLimit 8 -ScriptBlock {
                        param($Key, $Manifest)
                        Import-Module $Manifest
                        $ready = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ProductionSingleFlightReady')
                        $go = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ProductionSingleFlightGo')
                        $null = $ready.Signal()
                        $null = $go.Wait()

                        & (Get-Module GraphKit) {
                            param($AcquisitionKey)
                            $provider = {
                                $queue = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ProductionSingleFlightCalls')
                                $queue.Enqueue('acquire')
                                Start-Sleep -Milliseconds 400
                                return @{
                                    Token        = 'runtime-single-flight-token'
                                    ExpiresOnUtc = [System.DateTimeOffset]::UtcNow.AddHours(1)
                                }
                            }
                            $source = [ProviderTokenSource]::new(
                                $provider, 'https://graph.microsoft.com', 'client-id', 'runtime-generation'
                            )
                            $prover = {
                                param($Context, $TokenResult, $CancellationToken)
                                throw "proof-sentinel:$($TokenResult.TokenFingerprint)"
                            }

                            try {
                                $null = Send-GraphHttpRequest `
                                    -Uri ([uri] 'https://graph.microsoft.com/v1.0/mutation') `
                                    -Method POST -Body @{} -CredentialPolicy GraphBearer `
                                    -ExpectedAuthority ([uri] 'https://graph.microsoft.com') `
                                    -TokenSource $source -TokenAcquisitionKey $AcquisitionKey `
                                    -TargetTenantId ([guid] '00000000-0000-0000-0000-000000000001') `
                                    -VerifyTenantBinding -TenantBindingProver $prover
                                return 'unexpected-success'
                            }
                            catch {
                                return $_.Exception.Message
                            }
                        } $Key
                    } -ArgumentList $key, $script:BuiltManifest
                }

                $null = $ready.Wait(15000)
                $go.Set()
                $results = @($jobs | Receive-Job -Wait -AutoRemoveJob)

                $calls.Count | Should -Be 1
                $results.Count | Should -Be 8
                @($results | Where-Object { $_ -notlike 'proof-sentinel:*' }).Count | Should -Be 0
                @($results | Sort-Object -Unique).Count | Should -Be 1
                InModuleScope GraphKit -Parameters @{ K = $key } {
                    param($K)
                    $flightKey = Get-GraphTokenFlightKey -AcquisitionKey $K -ForceRefresh:$false
                    [GraphTokenFlightRegistry]::Flights.ContainsKey($flightKey) | Should -BeFalse
                }
            }
            finally {
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProductionSingleFlightCalls', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProductionSingleFlightReady', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ProductionSingleFlightGo', $null)
                if ($null -ne $jobs) {
                    $jobs | Where-Object { $_.State -ne 'Completed' } | Remove-Job -Force -ErrorAction SilentlyContinue
                }
                $ready.Dispose()
                $go.Dispose()
            }
        }
    }

    Context 'Canonical tuple normalization' {

        It 'yields the same key for GUID case, host case and scope order differences' {
            InModuleScope GraphKit {
                $k1 = Get-GraphTokenAcquisitionKey `
                    -Environment 'Global' `
                    -TenantId '3A4B5C6D-1111-2222-3333-444455556666' `
                    -Authority 'HTTPS://LOGIN.MICROSOFTONLINE.COM' `
                    -Resource 'https://graph.microsoft.com' `
                    -ClientId '7D6E5F44-9999-8888-7777-666655554444' `
                    -AuthMode 'Certificate' `
                    -IdentitySelector '' `
                    -Generation 'gen' `
                    -Scopes @('https://graph.microsoft.com/b', 'https://graph.microsoft.com/a')

                $k2 = Get-GraphTokenAcquisitionKey `
                    -Environment 'Global' `
                    -TenantId '3a4b5c6d-1111-2222-3333-444455556666' `
                    -Authority 'https://login.microsoftonline.com' `
                    -Resource 'https://graph.microsoft.com' `
                    -ClientId '7d6e5f44-9999-8888-7777-666655554444' `
                    -AuthMode 'Certificate' `
                    -IdentitySelector '' `
                    -Generation 'gen' `
                    -Scopes @('https://graph.microsoft.com/a', 'https://graph.microsoft.com/b')

                $k1 | Should -Be $k2
            }
        }

        It 'yields a different key when a tuple component changes' {
            InModuleScope GraphKit {
                $k1 = Get-GraphTokenAcquisitionKey -Environment 'Global' -TenantId '3a4b5c6d-1111-2222-3333-444455556666' -Authority 'https://login.microsoftonline.com' -Resource 'https://graph.microsoft.com' -ClientId '7d6e5f44-9999-8888-7777-666655554444' -AuthMode 'Certificate' -IdentitySelector '' -Generation 'gen'
                $k2 = Get-GraphTokenAcquisitionKey -Environment 'Global' -TenantId '3a4b5c6d-1111-2222-3333-444455556666' -Authority 'https://login.microsoftonline.com' -Resource 'https://graph.microsoft.com' -ClientId '7d6e5f44-9999-8888-7777-666655554444' -AuthMode 'ClientSecret' -IdentitySelector '' -Generation 'gen'
                $k1 | Should -Not -Be $k2
            }
        }

        It 'keeps ordinary and forced acquisitions in different in-flight groups' {
            InModuleScope GraphKit {
                $ordinary = Get-GraphTokenFlightKey -AcquisitionKey 'same-tuple' -ForceRefresh:$false
                $forced = Get-GraphTokenFlightKey -AcquisitionKey 'same-tuple' -ForceRefresh:$true

                $ordinary | Should -Not -Be $forced
                $ordinary | Should -Not -Match 'True|False'
                $forced | Should -Not -Match 'True|False'
            }
        }

        It 'collapses same-mode callers while ordinary and forced flights remain separate' {
            $key = 'mode-partition-key'
            $calls = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
            $ready = [System.Threading.CountdownEvent]::new(6)
            $go = [System.Threading.ManualResetEventSlim]::new($false)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ModeCalls', $calls)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ModeReady', $ready)
            [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ModeGo', $go)

            $jobs = $null
            try {
                $jobs = 0..5 | ForEach-Object {
                    $force = $_ -ge 3
                    Start-ThreadJob -ThrottleLimit 6 -ScriptBlock {
                        param($Key, $Force, $Manifest)
                        Import-Module $Manifest
                        $ready = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ModeReady')
                        $go = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ModeGo')
                        $null = $ready.Signal()
                        $null = $go.Wait()

                        & (Get-Module GraphKit) {
                            param($AcquisitionKey, $ForceRefresh)
                            $mode = if ($ForceRefresh) { 'refresh' } else { 'ordinary' }
                            $flightKey = Get-GraphTokenFlightKey `
                                -AcquisitionKey $AcquisitionKey -ForceRefresh:$ForceRefresh
                            Invoke-GraphTokenSingleFlight -Key $flightKey -AcquireScript {
                                $queue = [System.AppDomain]::CurrentDomain.GetData('GraphKitTest.ModeCalls')
                                $queue.Enqueue($mode)
                                Start-Sleep -Milliseconds 500
                                $mode
                            }.GetNewClosure()
                        } $Key $Force
                    } -ArgumentList $key, $force, $script:BuiltManifest
                }

                $ready.Wait(15000) | Should -BeTrue
                $go.Set()
                $results = @($jobs | Receive-Job -Wait -AutoRemoveJob)
                $jobs = $null

                @($calls | Where-Object { $_ -eq 'ordinary' }).Count | Should -Be 1
                @($calls | Where-Object { $_ -eq 'refresh' }).Count | Should -Be 1
                @($results | Where-Object { $_ -eq 'ordinary' }).Count | Should -Be 3
                @($results | Where-Object { $_ -eq 'refresh' }).Count | Should -Be 3
            }
            finally {
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ModeCalls', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ModeReady', $null)
                [System.AppDomain]::CurrentDomain.SetData('GraphKitTest.ModeGo', $null)
                if ($null -ne $jobs) {
                    $jobs | Where-Object { $_.State -ne 'Completed' } | Remove-Job -Force -ErrorAction SilentlyContinue
                }
                $ready.Dispose()
                $go.Dispose()
            }
        }
    }
}
