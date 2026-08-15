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
                $flight.Result = 'already-acquired'
                $flight.Done.Set()
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
    }
}
