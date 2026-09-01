BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw "No built GraphKit module found under '$repoRoot/output/module/GraphKit'. Run './build.ps1 -Tasks build' first."
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force -ErrorAction Stop

    if ($null -eq ('GraphKit.Tests.TenantDeadlineIgnoringHandler' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Net;
using System.Net.Http;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace GraphKit.Tests
{
    public sealed class TenantDeadlineIgnoringHandler : HttpMessageHandler
    {
        private int _sendCount;

        public int SendCount { get { return Volatile.Read(ref _sendCount); } }
        public CancellationTokenSource CompletionCancellation { get; set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _sendCount);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = CompletionCancellation == null
                    ? new StringContent("{\"value\":[]}")
                    : new CompletionCancellingContent(CompletionCancellation)
            });
        }

        private sealed class CompletionCancellingContent : HttpContent
        {
            private static readonly byte[] Body = Encoding.UTF8.GetBytes("{\"value\":[]}");
            private readonly CancellationTokenSource _cancellation;

            public CompletionCancellingContent(CancellationTokenSource cancellation)
            {
                _cancellation = cancellation;
            }

            protected override Task SerializeToStreamAsync(Stream stream, TransportContext context)
            {
                return SerializeAndCancel(stream);
            }

            protected override Task SerializeToStreamAsync(
                Stream stream,
                TransportContext context,
                CancellationToken cancellationToken)
            {
                return SerializeAndCancel(stream);
            }

            private Task SerializeAndCancel(Stream stream)
            {
                stream.Write(Body, 0, Body.Length);
                _cancellation.Cancel();
                return Task.CompletedTask;
            }

            protected override bool TryComputeLength(out long length)
            {
                length = Body.Length;
                return true;
            }
        }
    }
}
'@
    }

    $script:TenantId = [guid] '00000000-0000-0000-0000-000000000001'
    $script:OtherTenantId = [guid] '00000000-0000-0000-0000-000000000002'

    function New-TestContext {
        param([guid] $TenantId = $script:TenantId)

        return [pscustomobject] @{
            ProfileId     = 'ivy24'
            TenantId      = $TenantId
            Cloud         = 'Global'
            GraphBaseUri  = [uri] 'https://graph.microsoft.com'
            ClientId      = [guid] '00000000-0000-0000-0000-000000000010'
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
            [string] $VerifiedTenantId = $null,
            [object] $ElapsedCapture
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
            AcquireFlags         = [System.Collections.Generic.List[bool]]::new()
            ElapsedCapture       = $ElapsedCapture
        }

        $source = $source | Add-Member -MemberType ScriptMethod -Name Acquire -Value {
            param([bool] $forceRefresh, $ct)
            $this.AcquireFlags.Add($forceRefresh)
            if ($null -ne $this.ElapsedCapture) {
                $this.ElapsedCapture.Elapsed = $this.ElapsedCapture.AfterAcquire
            }
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

        It 'rejects a <Shape> <Field> before consulting the binding cache' -ForEach @(
            @{ Shape = 'null';       Field = 'TokenFingerprint';     Value = $null }
            @{ Shape = 'empty';      Field = 'TokenFingerprint';     Value = '' }
            @{ Shape = 'whitespace'; Field = 'TokenFingerprint';     Value = '   ' }
            @{ Shape = 'null';       Field = 'CredentialGeneration'; Value = $null }
            @{ Shape = 'empty';      Field = 'CredentialGeneration'; Value = '' }
            @{ Shape = 'whitespace'; Field = 'CredentialGeneration'; Value = "`t" }
        ) {
            $cache = @{}
            $tokenResult = New-TestTokenResult
            $tokenResult.$Field = $Value
            $transport = {
                param($Context, $Descriptor, $Uri)
                $script:proofCalls++
                return $script:proofEnvelope
            }

            {
                InModuleScope GraphKit -ArgumentList $cache, (New-TestContext), $tokenResult, $transport {
                    param($Cache, $Context, $TokenResult, $Transport)
                    Confirm-GraphTenantBinding -Context $Context -TokenResult $TokenResult `
                        -ProofTransport $Transport -ProofCache $Cache
                }
            } | Should -Throw -ExpectedMessage "*$Field*"

            $script:proofCalls | Should -Be 0
            $cache.Count | Should -Be 0
        }

        It 'cannot reuse one empty-metadata binding for two distinct bearer tokens' {
            $cache = @{}
            $transport = {
                param($Context, $Descriptor, $Uri)
                $script:proofCalls++
                return $script:proofEnvelope
            }
            $first = New-TestTokenResult -Fingerprint '' -Generation ''
            $first.AccessToken = 'first-distinct-bearer'
            $second = New-TestTokenResult -Fingerprint '' -Generation ''
            $second.AccessToken = 'second-distinct-bearer'
            $failures = [System.Collections.Generic.List[object]]::new()

            foreach ($tokenResult in @($first, $second)) {
                $failure = InModuleScope GraphKit -ArgumentList $cache, (New-TestContext), $tokenResult, $transport {
                    param($Cache, $Context, $TokenResult, $Transport)
                    try {
                        Confirm-GraphTenantBinding -Context $Context -TokenResult $TokenResult `
                            -ProofTransport $Transport -ProofCache $Cache
                        return $null
                    }
                    catch {
                        return $_.Exception
                    }
                }
                $failures.Add($failure)
            }

            $failures | Should -HaveCount 2
            foreach ($failure in $failures) {
                $failure | Should -Not -BeNullOrEmpty
                $failure.Message | Should -Match 'TokenFingerprint|CredentialGeneration'
                $failure.Message | Should -Not -Match 'first-distinct-bearer|second-distinct-bearer'
            }
            $script:proofCalls | Should -Be 0
            $cache.Count | Should -Be 0
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
                param($Context, $Descriptor, $Uri, $Method, $Headers, $Body, $CancellationToken, $DeadlineSeconds)
                $script:proofCall = [pscustomobject] @{
                    Method          = $Method
                    Uri             = $Uri
                    Descriptor      = $Descriptor
                    Context         = $Context
                    DeadlineSeconds = $DeadlineSeconds
                    Scope           = New-GraphThrottleScope -Context $Context -Descriptor $Descriptor
                }
                return [pscustomobject] @{
                    Outcome = 'Succeeded'
                    Data    = @{ value = @( @{ id = $script:TenantId.ToString() } ) }
                }
            }

            $null = InModuleScope GraphKit -ArgumentList $cache, (New-TestContext), (New-TestTokenResult) {
                param($Cache, $Context, $TokenResult)
                Confirm-GraphTenantBinding -Context $Context -TokenResult $TokenResult -ProofCache $Cache `
                    -RemainingDeadline ([TimeSpan]::FromSeconds(17))
            }

            $script:proofCall | Should -Not -BeNullOrEmpty
            $script:proofCall.Method | Should -Be 'GET'
            $script:proofCall.Uri.AbsoluteUri | Should -Be 'https://graph.microsoft.com/v1.0/organization'
            $script:proofCall.Descriptor.CredentialPolicy | Should -Be 'GraphBearer'
            $script:proofCall.Descriptor.ReplayPolicy | Should -Be 'Safe'
            $script:proofCall.Descriptor.ThrottleClass | Should -Be 'Read'
            $script:proofCall.Descriptor.ResourceFamily | Should -Be 'Graph.Directory'
            $script:proofCall.Descriptor.IdentityRequirement | Should -Be 'AllowUnverifiedRead'
            $script:proofCall.Descriptor.Keys | Should -Not -Contain 'VerifyTenantBinding'
            $script:proofCall.Context.Cloud | Should -BeExactly 'Global'
            $script:proofCall.Context.ClientId | Should -Be ([guid] '00000000-0000-0000-0000-000000000010')
            $script:proofCall.Scope.CoarseKey | Should -BeExactly 'Global|00000000-0000-0000-0000-000000000001|00000000-0000-0000-0000-000000000010|Read'
            $script:proofCall.Scope.LeafKey | Should -BeExactly 'Global|00000000-0000-0000-0000-000000000001|00000000-0000-0000-0000-000000000010|Read|Graph.Directory'
            $script:proofCall.DeadlineSeconds | Should -Be 17
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

            $failure = InModuleScope GraphKit -ArgumentList $cache, (New-TestContext), (New-TestTokenResult), $cts.Token {
                param($Cache, $Context, $TokenResult, $CancellationToken)
                try {
                    Confirm-GraphTenantBinding -Context $Context -TokenResult $TokenResult `
                        -ProofCache $Cache -CancellationToken $CancellationToken
                    return $null
                }
                catch {
                    return $_.Exception
                }
            }

            $script:proofCancellationToken.IsCancellationRequested | Should -BeTrue
            $failure | Should -Not -BeNullOrEmpty
            $isCancellation = $false
            $candidate = $failure
            while ($null -ne $candidate) {
                if ($candidate -is [System.OperationCanceledException]) {
                    $isCancellation = $true
                    break
                }
                $candidate = $candidate.InnerException
            }
            $isCancellation | Should -BeTrue -Because 'caller cancellation during the nested proof must preserve the retry pipeline cancellation outcome'
            $failure.Message | Should -Not -Match 'Tenant proof failed'
        }

        It 'preserves caller cancellation when the remaining proof budget is also zero' {
            $cache = @{}
            $cts = [System.Threading.CancellationTokenSource]::new()
            $cts.Cancel()

            try {
                $failure = InModuleScope GraphKit -ArgumentList $cache, (New-TestContext), (New-TestTokenResult), $cts.Token {
                    param($Cache, $Context, $TokenResult, $CancellationToken)
                    try {
                        Confirm-GraphTenantBinding -Context $Context -TokenResult $TokenResult `
                            -ProofCache $Cache -CancellationToken $CancellationToken `
                            -RemainingDeadline ([TimeSpan]::Zero) `
                            -ProofTransport { throw 'proof transport must not run at the cancelled boundary' }
                        return $null
                    }
                    catch {
                        return $_.Exception
                    }
                }

                $isCancellation = $false
                $candidate = $failure
                while ($null -ne $candidate) {
                    if ($candidate -is [System.OperationCanceledException]) {
                        $isCancellation = $true
                        break
                    }
                    $candidate = $candidate.InnerException
                }

                $isCancellation | Should -BeTrue
                $failure | Should -Not -BeOfType ([System.TimeoutException])
                $cache.Count | Should -Be 0
            }
            finally {
                $cts.Dispose()
            }
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

        It 'rejects an inherited deadline exhausted at sender entry before token acquisition' {
            $port = Get-FreePort
            $authority = [uri] "http://127.0.0.1:$port"
            $tokenSource = New-TestTokenSource -Fingerprint 'fp-entry-deadline' -Generation 'g-entry'
            $capture = [pscustomobject] @{ ProverCalls = 0; FactoryCalls = 0 }
            $prover = {
                param($Context, $TokenResult)
                $capture.ProverCalls++
                $TokenResult.VerifiedTenantId = [string] $Context.TenantId
            }.GetNewClosure()
            $factory = {
                param($ConnectTimeoutSeconds)
                $capture.FactoryCalls++
                throw 'target HTTP client factory must not run after deadline exhaustion'
            }.GetNewClosure()
            $bindingContext = [pscustomobject] @{
                Cloud             = 'Global'
                ClientId          = [guid] '00000000-0000-0000-0000-000000000010'
                RemainingDeadline = [TimeSpan]::Zero
            }

            $failure = InModuleScope GraphKit -ArgumentList $authority, $tokenSource, $prover, $factory, $bindingContext, $script:TenantId {
                param($Authority, $TokenSource, $Prover, $Factory, $BindingContext, $TenantId)
                try {
                    Send-GraphHttpRequest -Uri ([uri] "$($Authority.AbsoluteUri)/x") -Method POST -Body @{} `
                        -CredentialPolicy GraphBearer -ExpectedAuthority $Authority -TokenSource $TokenSource `
                        -TargetTenantId $TenantId -VerifyTenantBinding -TenantBindingProver $Prover `
                        -TenantBindingContext $BindingContext -HttpClientFactory $Factory
                    return $null
                }
                catch {
                    return $_.Exception
                }
            }

            $isDeadline = $false
            $candidate = $failure
            while ($null -ne $candidate) {
                if ($candidate -is [System.TimeoutException] -and
                    $candidate.Data['GraphKit.TenantBindingDeadlineExpired'] -eq $true) {
                    $isDeadline = $true
                    break
                }
                $candidate = $candidate.InnerException
            }
            $isDeadline | Should -BeTrue
            $tokenSource.AcquireFlags | Should -HaveCount 0
            $capture.ProverCalls | Should -Be 0
            $capture.FactoryCalls | Should -Be 0
        }

        It 'rejects a cached binding when acquisition consumes the inherited monotonic budget' {
            $port = Get-FreePort
            $authority = [uri] "http://127.0.0.1:$port"
            $elapsed = [pscustomobject] @{
                Elapsed      = [TimeSpan]::Zero
                AfterAcquire = [TimeSpan]::FromSeconds(5)
            }
            $tokenSource = New-TestTokenSource -Fingerprint 'fp-cache-deadline' -Generation 'g-cache' `
                -VerifiedTenantId $script:TenantId.ToString() -ElapsedCapture $elapsed
            $capture = [pscustomobject] @{ ProverCalls = 0; FactoryCalls = 0 }
            $prover = { param($Context, $TokenResult) $capture.ProverCalls++ }.GetNewClosure()
            $factory = {
                param($ConnectTimeoutSeconds)
                $capture.FactoryCalls++
                throw 'target HTTP client factory must not run after deadline exhaustion'
            }.GetNewClosure()
            $elapsedProvider = { $elapsed.Elapsed }.GetNewClosure()
            $bindingContext = [pscustomobject] @{
                Cloud             = 'Global'
                ClientId          = [guid] '00000000-0000-0000-0000-000000000010'
                RemainingDeadline = [TimeSpan]::FromSeconds(5)
                Elapsed           = $elapsedProvider
            }

            $failure = InModuleScope GraphKit -ArgumentList $authority, $tokenSource, $prover, $factory, $bindingContext, $script:TenantId {
                param($Authority, $TokenSource, $Prover, $Factory, $BindingContext, $TenantId)
                $key = Get-GraphTenantBindingKey -Fingerprint 'fp-cache-deadline' -Generation 'g-cache' -TenantId $TenantId
                $script:GraphTenantBindingCache[$key] = $true
                try {
                    try {
                        Send-GraphHttpRequest -Uri ([uri] "$($Authority.AbsoluteUri)/x") -Method POST -Body @{} `
                            -CredentialPolicy GraphBearer -ExpectedAuthority $Authority -TokenSource $TokenSource `
                            -TargetTenantId $TenantId -VerifyTenantBinding -TenantBindingProver $Prover `
                            -TenantBindingContext $BindingContext -HttpClientFactory $Factory
                        return $null
                    }
                    catch {
                        return $_.Exception
                    }
                }
                finally {
                    $null = $script:GraphTenantBindingCache.Remove($key)
                }
            }

            $isDeadline = $false
            $candidate = $failure
            while ($null -ne $candidate) {
                if ($candidate -is [System.TimeoutException] -and
                    $candidate.Data['GraphKit.TenantBindingDeadlineExpired'] -eq $true) {
                    $isDeadline = $true
                    break
                }
                $candidate = $candidate.InnerException
            }
            $isDeadline | Should -BeTrue
            $tokenSource.AcquireFlags | Should -Be @($false)
            $capture.ProverCalls | Should -Be 0
            $capture.FactoryCalls | Should -Be 0
        }

        It 'rejects a proof that completes exactly as the inherited monotonic budget expires' {
            $port = Get-FreePort
            $authority = [uri] "http://127.0.0.1:$port"
            $elapsed = [pscustomobject] @{
                Elapsed      = [TimeSpan]::Zero
                AfterAcquire = [TimeSpan]::Zero
            }
            $tokenSource = New-TestTokenSource -Fingerprint 'fp-proof-boundary' -Generation 'g-proof' `
                -ElapsedCapture $elapsed
            $capture = [pscustomobject] @{ ProverCalls = 0; FactoryCalls = 0 }
            $prover = {
                param($Context, $TokenResult)
                $capture.ProverCalls++
                $TokenResult.VerifiedTenantId = [string] $Context.TenantId
                $key = Get-GraphTenantBindingKey -Fingerprint $TokenResult.TokenFingerprint `
                    -Generation $TokenResult.CredentialGeneration -TenantId $Context.TenantId
                $script:GraphTenantBindingCache[$key] = $true
                $elapsed.Elapsed = [TimeSpan]::FromSeconds(5)
            }.GetNewClosure()
            $factory = {
                param($ConnectTimeoutSeconds)
                $capture.FactoryCalls++
                throw 'target HTTP client factory must not run after deadline exhaustion'
            }.GetNewClosure()
            $elapsedProvider = { $elapsed.Elapsed }.GetNewClosure()
            $bindingContext = [pscustomobject] @{
                Cloud             = 'Global'
                ClientId          = [guid] '00000000-0000-0000-0000-000000000010'
                RemainingDeadline = [TimeSpan]::FromSeconds(5)
                Elapsed           = $elapsedProvider
            }

            $failure = InModuleScope GraphKit -ArgumentList $authority, $tokenSource, $prover, $factory, $bindingContext, $script:TenantId {
                param($Authority, $TokenSource, $Prover, $Factory, $BindingContext, $TenantId)
                $key = Get-GraphTenantBindingKey -Fingerprint 'fp-proof-boundary' -Generation 'g-proof' -TenantId $TenantId
                try {
                    try {
                        Send-GraphHttpRequest -Uri ([uri] "$($Authority.AbsoluteUri)/x") -Method POST -Body @{} `
                            -CredentialPolicy GraphBearer -ExpectedAuthority $Authority -TokenSource $TokenSource `
                            -TargetTenantId $TenantId -VerifyTenantBinding -TenantBindingProver $Prover `
                            -TenantBindingContext $BindingContext -HttpClientFactory $Factory
                        return $null
                    }
                    catch {
                        return $_.Exception
                    }
                }
                finally {
                    $null = $script:GraphTenantBindingCache.Remove($key)
                }
            }

            $isDeadline = $false
            $candidate = $failure
            while ($null -ne $candidate) {
                if ($candidate -is [System.TimeoutException] -and
                    $candidate.Data['GraphKit.TenantBindingDeadlineExpired'] -eq $true) {
                    $isDeadline = $true
                    break
                }
                $candidate = $candidate.InnerException
            }
            $isDeadline | Should -BeTrue
            $tokenSource.AcquireFlags | Should -Be @($false)
            $capture.ProverCalls | Should -Be 1
            $capture.FactoryCalls | Should -Be 0
        }

        It 'rejects a successful target response that completes at the inherited deadline' {
            $authority = [uri] 'https://graph.microsoft.com'
            $handler = [GraphKit.Tests.TenantDeadlineIgnoringHandler]::new()
            $client = [System.Net.Http.HttpClient]::new($handler, $false)
            $tokenSource = New-TestTokenSource -Fingerprint 'fp-target-boundary' -Generation 'g-target' `
                -VerifiedTenantId $script:TenantId.ToString()
            $capture = [pscustomobject] @{ FactoryCalls = 0 }
            $elapsedProvider = {
                if ($handler.SendCount -gt 0) {
                    return [TimeSpan]::FromSeconds(5)
                }
                return [TimeSpan]::Zero
            }.GetNewClosure()
            $bindingContext = [pscustomobject] @{
                Cloud             = 'Global'
                ClientId          = [guid] '00000000-0000-0000-0000-000000000010'
                RemainingDeadline = [TimeSpan]::FromSeconds(5)
                Elapsed           = $elapsedProvider
            }
            $factory = {
                param($ConnectTimeoutSeconds)
                $capture.FactoryCalls++
                return [pscustomobject] @{
                    Client          = $client
                    OwnedByGraphKit = $false
                }
            }.GetNewClosure()

            try {
                $failure = InModuleScope GraphKit -ArgumentList $authority, $tokenSource, $factory, $bindingContext, $script:TenantId {
                    param($Authority, $TokenSource, $Factory, $BindingContext, $TenantId)
                    $state = New-GraphModuleLifecycleState
                    $key = Get-GraphTenantBindingKey -Fingerprint 'fp-target-boundary' -Generation 'g-target' -TenantId $TenantId
                    $script:GraphTenantBindingCache[$key] = $true
                    try {
                        try {
                            Send-GraphHttpRequest -Uri ([uri] "$($Authority.AbsoluteUri.TrimEnd('/'))/v1.0/test") `
                                -Method GET -CredentialPolicy GraphBearer -ExpectedAuthority $Authority `
                                -TokenSource $TokenSource -TargetTenantId $TenantId -VerifyTenantBinding `
                                -TenantBindingContext $BindingContext -HttpClientFactory $Factory `
                                -LifecycleState $state
                            return $null
                        }
                        catch {
                            return $_.Exception
                        }
                    }
                    finally {
                        $null = $script:GraphTenantBindingCache.Remove($key)
                        Stop-GraphModule -State $state
                    }
                }

                $isDeadline = $false
                $candidate = $failure
                while ($null -ne $candidate) {
                    if ($candidate -is [System.TimeoutException] -and
                        $candidate.Data['GraphKit.TenantBindingDeadlineExpired'] -eq $true) {
                        $isDeadline = $true
                        break
                    }
                    $candidate = $candidate.InnerException
                }

                $isDeadline | Should -BeTrue
                $tokenSource.AcquireFlags | Should -Be @($false)
                $capture.FactoryCalls | Should -Be 1
                $handler.SendCount | Should -Be 1
            }
            finally {
                $client.Dispose()
                $handler.Dispose()
            }
        }

        It 'preserves caller cancellation raised after a successful target body completes' {
            $authority = [uri] 'https://graph.microsoft.com'
            $cts = [System.Threading.CancellationTokenSource]::new()
            $handler = [GraphKit.Tests.TenantDeadlineIgnoringHandler]::new()
            $handler.CompletionCancellation = $cts
            $client = [System.Net.Http.HttpClient]::new($handler, $false)
            $tokenSource = New-TestTokenSource -Fingerprint 'fp-target-cancel' -Generation 'g-target-cancel' `
                -VerifiedTenantId $script:TenantId.ToString()
            $capture = [pscustomobject] @{ FactoryCalls = 0 }
            $bindingContext = [pscustomobject] @{
                Cloud             = 'Global'
                ClientId          = [guid] '00000000-0000-0000-0000-000000000010'
                RemainingDeadline = [TimeSpan]::FromSeconds(5)
                Elapsed           = { [TimeSpan]::Zero }
            }
            $factory = {
                param($ConnectTimeoutSeconds)
                $capture.FactoryCalls++
                return [pscustomobject] @{
                    Client          = $client
                    OwnedByGraphKit = $false
                }
            }.GetNewClosure()

            try {
                $failure = InModuleScope GraphKit -ArgumentList $authority, $tokenSource, $factory, $bindingContext, $script:TenantId, $cts.Token {
                    param($Authority, $TokenSource, $Factory, $BindingContext, $TenantId, $CancellationToken)
                    $state = New-GraphModuleLifecycleState
                    $key = Get-GraphTenantBindingKey -Fingerprint 'fp-target-cancel' -Generation 'g-target-cancel' -TenantId $TenantId
                    $script:GraphTenantBindingCache[$key] = $true
                    try {
                        try {
                            Send-GraphHttpRequest -Uri ([uri] "$($Authority.AbsoluteUri.TrimEnd('/'))/v1.0/test") `
                                -Method GET -CredentialPolicy GraphBearer -ExpectedAuthority $Authority `
                                -TokenSource $TokenSource -TargetTenantId $TenantId -VerifyTenantBinding `
                                -TenantBindingContext $BindingContext -HttpClientFactory $Factory `
                                -LifecycleState $state -CancellationToken $CancellationToken
                            return $null
                        }
                        catch {
                            return $_.Exception
                        }
                    }
                    finally {
                        $null = $script:GraphTenantBindingCache.Remove($key)
                        Stop-GraphModule -State $state
                    }
                }

                $isCancellation = $false
                $isDeadline = $false
                $candidate = $failure
                while ($null -ne $candidate) {
                    if ($candidate -is [System.OperationCanceledException]) {
                        $isCancellation = $true
                    }
                    if ($candidate -is [System.TimeoutException] -and
                        $candidate.Data['GraphKit.TenantBindingDeadlineExpired'] -eq $true) {
                        $isDeadline = $true
                    }
                    $candidate = $candidate.InnerException
                }

                $tokenSource.AcquireFlags | Should -Be @($false)
                $capture.FactoryCalls | Should -Be 1
                $handler.SendCount | Should -Be 1
                $cts.IsCancellationRequested | Should -BeTrue
                $isCancellation | Should -BeTrue
                $isDeadline | Should -BeFalse
            }
            finally {
                $client.Dispose()
                $handler.Dispose()
                $cts.Dispose()
            }
        }
    }
}
