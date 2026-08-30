BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw "No built GraphKit module found under '$repoRoot/output/module/GraphKit'. Run './build.ps1 -Tasks build' first."
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force -ErrorAction Stop

    $script:TenantId = [guid] '00000000-0000-0000-0000-000000000001'
    $script:OtherTenantId = [guid] '00000000-0000-0000-0000-000000000002'

    function New-TestContext {
        param([guid] $TenantId = $script:TenantId)

        return [pscustomobject] @{
            ProfileId     = 'ivy24'
            TenantId      = $TenantId
            Cloud         = 'Global'
            GraphBaseUri  = [uri] 'https://graph.microsoft.com'
            ClientId      = 'client'
            TokenSource   = $null
            IdentityState = 'VerifiedForToken'
        }
    }

    function New-TestTokenResult {
        param(
            [string] $Fingerprint = 'fp1',
            [string] $Generation = 'g1',
            [string] $VerifiedTenantId = $null
        )

        return [pscustomobject] @{
            AccessToken          = 'test-bearer-token'
            ExpiresOnUtc         = [System.DateTimeOffset]::UtcNow.AddHours(1)
            VerifiedTenantId     = $VerifiedTenantId
            TokenFingerprint     = $Fingerprint
            CredentialGeneration = $Generation
        }
    }

    function New-TestProofEnvelope {
        param([guid] $TenantId = $script:TenantId)

        return [pscustomobject] @{
            PSTypeName = 'GraphKit.OperationResult'
            Outcome    = 'Succeeded'
            Data       = @{ value = @( @{ id = $TenantId.ToString() } ) }
            Telemetry  = @()
        }
    }

    function New-TestTokenSource {
        param(
            [string] $Fingerprint = 'fp1',
            [string] $Generation = 'g1',
            [string] $VerifiedTenantId = $null
        )

        # Duck-typed token source: a plain PSCustomObject exposing the module's
        # Acquire/CanRefresh contract. Acquire is a ScriptMethod (never a
        # scriptblock property) because the module invokes
        # $TokenSource.Acquire($forceRefresh, $ct) as a method.
        $source = [pscustomobject] @{
            CanRefresh           = $true
            TokenFingerprint     = $Fingerprint
            VerifiedTenantId     = $VerifiedTenantId
            CredentialGeneration = $Generation
        }

        $source = $source | Add-Member -MemberType ScriptMethod -Name Acquire -Value {
            param([bool] $forceRefresh, $ct)
            return [pscustomobject] @{
                AccessToken          = 'test-bearer-token'
                ExpiresOnUtc         = [System.DateTimeOffset]::UtcNow.AddHours(1)
                VerifiedTenantId     = $this.VerifiedTenantId
                TokenFingerprint     = $this.TokenFingerprint
                CredentialGeneration = $this.CredentialGeneration
            }
        } -PassThru

        return $source
    }

    function Get-FreePort {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $port = ([System.Net.IPEndPoint] $listener.LocalEndpoint).Port
        $listener.Stop()
        return $port
    }

    # The retry engine's live path must never escape a unit test. A default
    # throwing mock is registered before the per-test mocks; the recursion test
    # overrides it.
    Mock Invoke-GraphRetry -ModuleName GraphKit {
        throw 'Invoke-GraphRetry must be mocked in this test.'
    }
}

Describe 'Confirm-GraphTenantBinding' {

    Context 'binding cache' {
        BeforeEach {
            $script:proofCalls = 0
            $script:proofEnvelope = New-TestProofEnvelope
        }

        It 'performs the proof on a new fingerprint and records the binding' {
            $cache = @{}
            $transport = { param($Context, $Descriptor, $Uri) $script:proofCalls++; return $script:proofEnvelope }

            $result = InModuleScope GraphKit -ArgumentList $cache, (New-TestContext), (New-TestTokenResult), $transport {
                param($Cache, $Context, $TokenResult, $Transport)
                Confirm-GraphTenantBinding -Context $Context -TokenResult $TokenResult -ProofTransport $Transport -ProofCache $Cache
                return $TokenResult
            }

            $script:proofCalls | Should -Be 1
            $result.VerifiedTenantId | Should -Be $script:TenantId.ToString()
            $cache.Count | Should -Be 1
        }

        It 'skips the proof call when the binding is already cached' {
            $cache = @{}
            $transport = { param($Context, $Descriptor, $Uri) $script:proofCalls++; return $script:proofEnvelope }

            $null = InModuleScope GraphKit -ArgumentList $cache, (New-TestContext), (New-TestTokenResult), $transport {
                param($Cache, $Context, $TokenResult, $Transport)
                Confirm-GraphTenantBinding -Context $Context -TokenResult $TokenResult -ProofTransport $Transport -ProofCache $Cache
            }
            $script:proofCalls | Should -Be 1

            $null = InModuleScope GraphKit -ArgumentList $cache, (New-TestContext), (New-TestTokenResult), $transport {
                param($Cache, $Context, $TokenResult, $Transport)
                Confirm-GraphTenantBinding -Context $Context -TokenResult $TokenResult -ProofTransport $Transport -ProofCache $Cache
            }

            $script:proofCalls | Should -Be 1
        }

        It 're-proves when the fingerprint changes even with the same generation and tenant' {
            $cache = @{}
            $transport = { param($Context, $Descriptor, $Uri) $script:proofCalls++; return $script:proofEnvelope }

            $null = InModuleScope GraphKit -ArgumentList $cache, (New-TestContext), (New-TestTokenResult -Fingerprint 'fp-a'), $transport {
                param($Cache, $Context, $TokenResult, $Transport)
                Confirm-GraphTenantBinding -Context $Context -TokenResult $TokenResult -ProofTransport $Transport -ProofCache $Cache
            }
            $null = InModuleScope GraphKit -ArgumentList $cache, (New-TestContext), (New-TestTokenResult -Fingerprint 'fp-b'), $transport {
                param($Cache, $Context, $TokenResult, $Transport)
                Confirm-GraphTenantBinding -Context $Context -TokenResult $TokenResult -ProofTransport $Transport -ProofCache $Cache
            }

            $script:proofCalls | Should -Be 2
        }
    }

    Context 'proof outcomes' {
        BeforeEach {
            $script:proofCalls = 0
        }

        It 'still proves when a provider claims a tenant without a recorded binding' {
            $cache = @{}
            $script:proofEnvelope = New-TestProofEnvelope
            $transport = { param($Context, $Descriptor, $Uri) $script:proofCalls++; return $script:proofEnvelope }

            # The result already carries the tenant id (a provider's claim); the
            # prover must not trust it and must still issue the proof read.
            $tokenResult = New-TestTokenResult -VerifiedTenantId $script:TenantId.ToString()

            $null = InModuleScope GraphKit -ArgumentList $cache, (New-TestContext), $tokenResult, $transport {
                param($Cache, $Context, $TokenResult, $Transport)
                Confirm-GraphTenantBinding -Context $Context -TokenResult $TokenResult -ProofTransport $Transport -ProofCache $Cache
            }

            $script:proofCalls | Should -Be 1
        }
        It 'throws a hard error naming both tenants when the proof returns a different tenant' {
            $cache = @{}
            $script:proofEnvelope = [pscustomobject] @{
                Outcome = 'Succeeded'
                Data    = @{ value = @( @{ id = $script:OtherTenantId.ToString() } ) }
            }
            $transport = { param($Context, $Descriptor, $Uri) return $script:proofEnvelope }

            $message = InModuleScope GraphKit -ArgumentList $cache, (New-TestContext), (New-TestTokenResult), $transport {
                param($Cache, $Context, $TokenResult, $Transport)
                try {
                    Confirm-GraphTenantBinding -Context $Context -TokenResult $TokenResult -ProofTransport $Transport -ProofCache $Cache
                    return ''
                }
                catch {
                    return $_.Exception.Message
                }
            }

            $message | Should -BeLike '*Tenant binding failed*'
            $message | Should -BeLike "*$($script:OtherTenantId)*"
            $message | Should -BeLike "*$($script:TenantId)*"
        }

        It 'issues the proof read through the retry pipeline as a GET with the synthetic read descriptor' {
            $cache = @{}
            $script:proofCall = $null
            Mock Invoke-GraphRetry -ModuleName GraphKit {
                param($Context, $Descriptor, $Uri, $Method, $Headers, $Body, $CancellationToken)
                $script:proofCall = [pscustomobject] @{
                    Method     = $Method
                    Uri        = $Uri
                    Descriptor = $Descriptor
                }
                return [pscustomobject] @{
                    Outcome = 'Succeeded'
                    Data    = @{ value = @( @{ id = $script:TenantId.ToString() } ) }
                }
            }

            $null = InModuleScope GraphKit -ArgumentList $cache, (New-TestContext), (New-TestTokenResult) {
                param($Cache, $Context, $TokenResult)
                Confirm-GraphTenantBinding -Context $Context -TokenResult $TokenResult -ProofCache $Cache
            }

            $script:proofCall | Should -Not -BeNullOrEmpty
            $script:proofCall.Method | Should -Be 'GET'
            $script:proofCall.Uri.AbsoluteUri | Should -Be 'https://graph.microsoft.com/v1.0/organization'
            $script:proofCall.Descriptor.CredentialPolicy | Should -Be 'GraphBearer'
            $script:proofCall.Descriptor.ReplayPolicy | Should -Be 'Safe'
            $script:proofCall.Descriptor.ThrottleClass | Should -Be 'Read'
            $script:proofCall.Descriptor.ResourceFamily | Should -Be 'Graph.Directory'
            $script:proofCall.Descriptor.IdentityRequirement | Should -Be 'Verified'
            $script:proofCall.Descriptor.Keys | Should -Not -Contain 'VerifyTenantBinding'
        }

        It 'forwards the caller cancellation token into the proof retry pipeline' {
            $cache = @{}
            $script:proofCancellationToken = [System.Threading.CancellationToken]::None
            $cts = [System.Threading.CancellationTokenSource]::new()
            $cts.Cancel()

            Mock Invoke-GraphRetry -ModuleName GraphKit {
                param($Context, $Descriptor, $Uri, $Method, $Headers, $Body, $CancellationToken)
                $script:proofCancellationToken = $CancellationToken
                return [pscustomobject] @{
                    Outcome = 'Cancelled'
                    Data    = $null
                }
            }

            $message = InModuleScope GraphKit -ArgumentList $cache, (New-TestContext), (New-TestTokenResult), $cts.Token {
                param($Cache, $Context, $TokenResult, $CancellationToken)
                try {
                    Confirm-GraphTenantBinding -Context $Context -TokenResult $TokenResult `
                        -ProofCache $Cache -CancellationToken $CancellationToken
                    return ''
                }
                catch {
                    return $_.Exception.Message
                }
            }

            $script:proofCancellationToken.IsCancellationRequested | Should -BeTrue
            $message | Should -BeLike '*Tenant proof failed*'
        }
    }
}

Describe 'Send-GraphHttpRequest tenant-proof wiring' {

    Context 'proof before mutating send' {
        BeforeEach {
            $script:proverCalls = 0
            $script:proofCalls = 0
        }

        It 'runs the injected prover before the send for an unverified token and proceeds once verified' {
            $port = Get-FreePort
            $authority = [uri] "http://127.0.0.1:$port"
            $tokenSource = New-TestTokenSource -Fingerprint 'fp-unverified' -Generation 'g1' -VerifiedTenantId $null
            $prover = {
                param($Context, $TokenResult)
                $script:proverCalls++
                $TokenResult.VerifiedTenantId = [string] $Context.TenantId
            }

            $result = InModuleScope GraphKit -ArgumentList $authority, $tokenSource, $prover, $script:TenantId {
                param($Authority, $TokenSource, $Prover, $TenantId)
                Send-GraphHttpRequest -Uri ([uri] "$($Authority.AbsoluteUri)/x") -Method POST -Body @{} `
                    -CredentialPolicy GraphBearer -ExpectedAuthority $Authority -TokenSource $TokenSource `
                    -TargetTenantId $TenantId -VerifyTenantBinding -TenantBindingProver $Prover
            }

            $script:proverCalls | Should -Be 1
            # The send was attempted (connection refused to the dead port), which
            # only happens after the prover set VerifiedTenantId and the binding
            # enforcement passed.
            $result.ResponseReceived | Should -BeFalse
            $result.TransportException | Should -Not -BeNullOrEmpty
        }

        It 'passes cancellation raised during acquisition to the prover before any mutation send' {
            $port = Get-FreePort
            $authority = [uri] "http://127.0.0.1:$port"
            $cts = [System.Threading.CancellationTokenSource]::new()
            $tokenSource = New-TestTokenSource -Fingerprint 'fp-cancelled' -Generation 'g1' -VerifiedTenantId $null
            $tokenSource | Add-Member -MemberType NoteProperty -Name CancellationSource -Value $cts
            $tokenSource | Add-Member -MemberType ScriptMethod -Name Acquire -Force -Value {
                param([bool] $forceRefresh, $ct)
                $this.CancellationSource.Cancel()
                return [pscustomobject] @{
                    AccessToken          = 'test-bearer-token'
                    ExpiresOnUtc         = [System.DateTimeOffset]::UtcNow.AddHours(1)
                    VerifiedTenantId     = $null
                    TokenFingerprint     = $this.TokenFingerprint
                    CredentialGeneration = $this.CredentialGeneration
                }
            }
            $script:proverSawCancellation = $false
            $prover = {
                param($Context, $TokenResult, [System.Threading.CancellationToken] $CancellationToken)
                $script:proverSawCancellation = $CancellationToken.IsCancellationRequested
                $CancellationToken.ThrowIfCancellationRequested()
                $TokenResult.VerifiedTenantId = [string] $Context.TenantId
            }

            $message = InModuleScope GraphKit -ArgumentList $authority, $tokenSource, $prover, $script:TenantId, $cts.Token {
                param($Authority, $TokenSource, $Prover, $TenantId, $CancellationToken)
                try {
                    Send-GraphHttpRequest -Uri ([uri] "$($Authority.AbsoluteUri)/mutation") -Method POST -Body @{} `
                        -CredentialPolicy GraphBearer -ExpectedAuthority $Authority -TokenSource $TokenSource `
                        -TargetTenantId $TenantId -VerifyTenantBinding -TenantBindingProver $Prover `
                        -CancellationToken $CancellationToken
                    return ''
                }
                catch {
                    return $_.Exception.Message
                }
            }

            $script:proverSawCancellation | Should -BeTrue
            $message | Should -BeLike '*operation was canceled*'
        }

        It 'does not invoke the prover when the current fingerprint is already verified' {
            $port = Get-FreePort
            $authority = [uri] "http://127.0.0.1:$port"
            $tokenSource = New-TestTokenSource -Fingerprint 'fp-verified' -Generation 'g1' -VerifiedTenantId $script:TenantId.ToString()
            $prover = { param($Context, $TokenResult) $script:proverCalls++ }
            $script:proofEnvelope = New-TestProofEnvelope
            $proofTransport = { param($Context, $Descriptor, $Uri) $script:proofCalls++; return $script:proofEnvelope }

            $result = InModuleScope GraphKit -ArgumentList $authority, $tokenSource, $prover, $proofTransport, $script:TenantId {
                param($Authority, $TokenSource, $Prover, $ProofTransport, $TenantId)

                # Record a binding for the current fingerprint/generation/tenant
                # so the sender sees the token as already verified.
                $context = [pscustomobject] @{
                    TenantId     = $TenantId
                    GraphBaseUri = $Authority
                    TokenSource  = $TokenSource
                }
                $tokenResult = [pscustomobject] @{
                    AccessToken          = 'test-bearer-token'
                    VerifiedTenantId     = $TenantId.ToString()
                    TokenFingerprint     = 'fp-verified'
                    CredentialGeneration = 'g1'
                }
                Confirm-GraphTenantBinding -Context $context -TokenResult $tokenResult -ProofTransport $ProofTransport

                Send-GraphHttpRequest -Uri ([uri] "$($Authority.AbsoluteUri)/x") -Method POST -Body @{} `
                    -CredentialPolicy GraphBearer -ExpectedAuthority $Authority -TokenSource $TokenSource `
                    -TargetTenantId $TenantId -VerifyTenantBinding -TenantBindingProver $Prover
            }

            $script:proofCalls | Should -Be 1
            $script:proverCalls | Should -Be 0
            $result.ResponseReceived | Should -BeFalse
        }

        It 'still throws the existing hard error when the prover leaves the token unverified' {
            $port = Get-FreePort
            $authority = [uri] "http://127.0.0.1:$port"
            $tokenSource = New-TestTokenSource -Fingerprint 'fp-unverified' -Generation 'g1' -VerifiedTenantId $null
            $prover = { param($Context, $TokenResult) $script:proverCalls++ }

            $message = InModuleScope GraphKit -ArgumentList $authority, $tokenSource, $prover, $script:TenantId {
                param($Authority, $TokenSource, $Prover, $TenantId)
                try {
                    Send-GraphHttpRequest -Uri ([uri] "$($Authority.AbsoluteUri)/x") -Method POST -Body @{} `
                        -CredentialPolicy GraphBearer -ExpectedAuthority $Authority -TokenSource $TokenSource `
                        -TargetTenantId $TenantId -VerifyTenantBinding -TenantBindingProver $Prover
                    return ''
                }
                catch {
                    return $_.Exception.Message
                }
            }

            $script:proverCalls | Should -Be 1
            $message | Should -BeLike '*Tenant binding failed*'
        }
    }
}
