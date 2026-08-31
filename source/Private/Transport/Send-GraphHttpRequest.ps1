<#
    The real Graph HTTP sender.

    GraphKit owns this transport: one module/session-scoped HttpClient backed by a
    SocketsHttpHandler that never follows redirects, never stores cookies, never
    installs a retry handler, and never carries a default Authorization header.
    Every GraphKit attempt produces exactly one physical send, which is what makes
    the retry engine's replay guarantees enforceable.

    This function NEVER throws for transport or HTTP outcomes (timeouts, connection
    resets, 3xx/4xx/5xx statuses): it normalizes them into a GraphTransportResult.
    The only hard errors are credential-boundary violations, which throw before any
    token is acquired or any bytes leave the process.

    Split timeouts: the connection phase is bounded by the handler ConnectTimeout;
    the header phase and body phase are bounded by linked CancellationTokenSources
    that CancelAfter the configured number of seconds.
#>

# Module/session-scoped transport. Created lazily and shared across all sends so
# connection pooling survives between requests; disposed on module removal.
# Keyed by connect-timeout seconds. ConnectTimeout is a handler-level property
# fixed when the handler is constructed, so a single shared client would silently
# honour only the FIRST caller's -TimeoutConnectionSeconds and ignore every later
# value - an API that accepts a per-call, range-validated parameter it does not
# apply. One client per distinct timeout keeps the parameter honest while
# preserving connection pooling within each timeout class (in practice one or two).
# The cache lives in the centralized lifecycle state so creation, admission and
# removal use one lock and one ownership ledger.

function Get-GraphHttpClient {
    [CmdletBinding()]
    [OutputType([System.Net.Http.HttpClient])]
    param(
        [int] $ConnectTimeoutSeconds = 10,

        [object] $State = $script:GraphKitModuleLifecycle,

        # Deterministic test seam. The result must declare both the client and
        # whether GraphKit owns it; injected clients remain caller-owned.
        [scriptblock] $ClientFactory
    )

    if ($null -eq $State) {
        throw [System.InvalidOperationException]::new('GraphKit module lifecycle state is unavailable.')
    }

    $key = [string] $ConnectTimeoutSeconds
    [System.Threading.Monitor]::Enter($State.SyncRoot)
    try {
        if ($State.StopRequested -or $State.CleanupStarted) {
            throw [System.ObjectDisposedException]::new(
                'GraphKit',
                'The GraphKit module is stopping and cannot create or return an HTTP client.'
            )
        }

        if ($State.HttpClients.ContainsKey($key)) {
            return [System.Net.Http.HttpClient] $State.HttpClients[$key].Client
        }

        if ($null -ne $ClientFactory) {
            $created = & $ClientFactory $ConnectTimeoutSeconds
            if ($null -eq $created -or
                $null -eq $created.PSObject.Properties['Client'] -or
                $created.Client -isnot [System.Net.Http.HttpClient] -or
                $null -eq $created.PSObject.Properties['OwnedByGraphKit']) {
                throw [System.InvalidOperationException]::new(
                    'The GraphKit HTTP client factory must return Client (HttpClient) and OwnedByGraphKit properties.'
                )
            }

            $client = [System.Net.Http.HttpClient] $created.Client
            $ownedByGraphKit = [bool] $created.OwnedByGraphKit
        }
        else {
            $handler = [System.Net.Http.SocketsHttpHandler]::new()
            try {
                $handler.AllowAutoRedirect = $false
                $handler.UseCookies = $false
                $handler.PooledConnectionLifetime = [TimeSpan]::FromMinutes(5)
                $handler.ConnectTimeout = [TimeSpan]::FromSeconds($ConnectTimeoutSeconds)

                # No handler is chained and no DelegatingHandler wraps this client,
                # so nothing can retry behind GraphKit's back.
                $client = [System.Net.Http.HttpClient]::new($handler, $true)
                $handler = $null
                # GraphKit enforces per-phase timeouts itself; disable HttpClient's
                # own 100s wall-clock cap so it cannot fire before a configured
                # phase timeout.
                $client.Timeout = [System.Threading.Timeout]::InfiniteTimeSpan
            }
            finally {
                if ($null -ne $handler) {
                    $handler.Dispose()
                }
            }
            $ownedByGraphKit = $true
        }

        $entry = [pscustomobject] @{
            Client          = $client
            OwnedByGraphKit = $ownedByGraphKit
        }
        $State.HttpClients.Add($key, $entry)
        try {
            $null = Register-GraphModuleOwnedResource -State $State -Resource $client `
                -OwnedByGraphKit:$ownedByGraphKit
        }
        catch {
            $null = $State.HttpClients.Remove($key)
            # Register-GraphModuleOwnedResource transfers ownership only on a
            # successful return. A failed registration leaves this client here
            # for exactly-once disposal, including a shutdown race.
            if ($ownedByGraphKit) {
                $client.Dispose()
            }
            throw
        }

        return $client
    }
    finally {
        [System.Threading.Monitor]::Exit($State.SyncRoot)
    }
}

function Send-GraphHttpRequest {
    [CmdletBinding()]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'CredentialPolicy', Justification = 'ValidateSet values are credential policy names, not passwords; values are cross-file contract literals')]
    param(
        [Parameter(Mandatory = $true)]
        [uri] $Uri,

        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS')]
        [string] $Method,

        [hashtable] $Headers,

        [AllowNull()]
        [object] $Body,

        [ValidateRange(1, 3600)]
        [int] $TimeoutConnectionSeconds = 10,

        [ValidateRange(1, 3600)]
        [int] $TimeoutHeadersSeconds = 10,

        [ValidateRange(1, 3600)]
        [int] $TimeoutBodySeconds = 30,

        [System.Threading.CancellationToken] $CancellationToken = [System.Threading.CancellationToken]::None,

        [object] $TokenSource,

        [bool] $ForceRefresh = $false,

        [string] $TokenAcquisitionKey,

        [ValidateSet('GraphBearer', 'None')]
        [string] $CredentialPolicy = 'None',

        [uri] $ExpectedAuthority,

        [guid] $TargetTenantId = [guid]::Empty,

        [switch] $VerifyTenantBinding,

        [scriptblock] $TenantBindingProver,

        # Private deterministic seams. Production callers use the current
        # module lifecycle and the GraphKit-owned client factory.
        [object] $LifecycleState = $script:GraphKitModuleLifecycle,

        [scriptblock] $HttpClientFactory
    )

    $leaseAcquired = $false
    $lifetimeCts = $null
    $phaseCts = $null
    $request = $null
    $response = $null

    $moduleCancellationToken = Enter-GraphModuleOperation -State $LifecycleState
    $leaseAcquired = $true
    try {
        $lifetimeCts = [System.Threading.CancellationTokenSource]::CreateLinkedTokenSource(
            $CancellationToken,
            $moduleCancellationToken
        )
        $effectiveCancellationToken = $lifetimeCts.Token

    $result = [GraphTransportResult]::new()
    $result.StatusCode = 0
    $result.Headers = [hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
    $result.RequestId = $null
    $result.TransportException = $null
    $result.ResponseReceived = $false
    $result.VerifiedTenantId = $null
    $result.TokenFingerprint = $null
    $result.CredentialGeneration = $null

    # ---- Credential boundary (non-bypassable, enforced before any send) ----
    if ($CredentialPolicy -eq 'GraphBearer') {
        # A Graph bearer token must only ever be addressed at the exact cloud
        # authority (scheme AND host) this context expects. Any mismatch is a hard
        # error naming the offending authority - never a silent downgrade and never
        # a silent send of a token to a foreign host.
        if ($null -eq $ExpectedAuthority) {
            throw 'GraphBearer credential policy requires -ExpectedAuthority.'
        }

        $schemeMatches = [string]::Equals($Uri.Scheme, $ExpectedAuthority.Scheme, [System.StringComparison]::OrdinalIgnoreCase)
        $authorityMatches = [string]::Equals($Uri.Authority, $ExpectedAuthority.Authority, [System.StringComparison]::OrdinalIgnoreCase)

        if (-not ($schemeMatches -and $authorityMatches)) {
            throw (
                'Credential boundary violated: refusing to send a Graph bearer token to ' +
                "'{0}'; expected the cloud authority '{1}'." -f ([string] $Uri.OriginalString), ([string] $ExpectedAuthority.OriginalString)
            )
        }

        if ($null -eq $TokenSource) {
            throw 'GraphBearer credential policy requires a token source.'
        }

        # Legacy PowerShell-class sources cannot execute Acquire safely after a
        # context crosses runspaces. Check the captured field here, before the
        # single-flight registry can make this caller wait on an unrelated
        # leader and before invoking any source method. GraphKit.Auth replaces
        # this containment with a compiled runspace-neutral source.
        if ($TokenSource -is [GraphTokenSourceBase]) {
            $currentRunspace = [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace
            $currentRunspaceId = if ($null -eq $currentRunspace) {
                [guid]::Empty
            }
            else {
                $currentRunspace.InstanceId
            }
            $sourceRunspaceId = ([GraphTokenSourceBase] $TokenSource).CreationRunspaceId
            if ($currentRunspaceId -ne $sourceRunspaceId) {
                throw [System.InvalidOperationException]::new(
                    'This legacy PowerShell token source is bound to the runspace where its context was created. ' +
                    'Cross-runspace context use is disabled because PowerShell-class token acquisition can hang; ' +
                    'the compiled GraphKit.Auth token source is required for that contract.'
                )
            }
        }
    }

    # ---- Build the request ----
    $httpMethod = [System.Net.Http.HttpMethod]::new($Method.ToUpperInvariant())
    $request = [System.Net.Http.HttpRequestMessage]::new($httpMethod, $Uri)

    if ($null -ne $Body) {
        if ($Body -is [byte[]]) {
            $content = [System.Net.Http.ByteArrayContent]::new($Body)
        }
        elseif ($Body -is [string]) {
            $content = [System.Net.Http.StringContent]::new(
                $Body,
                [System.Text.Encoding]::UTF8,
                'application/json'
            )
        }
        else {
            $json = ConvertTo-Json -InputObject $Body -Depth 100 -Compress
            $content = [System.Net.Http.StringContent]::new(
                $json,
                [System.Text.Encoding]::UTF8,
                'application/json'
            )
        }

        $request.Content = $content
    }

    if ($null -ne $Headers) {
        foreach ($entry in $Headers.GetEnumerator()) {
            $name = [string] $entry.Key
            $value = [string] $entry.Value

            if ($name -ieq 'Content-Type') {
                if ($null -eq $request.Content) {
                    $request.Content = [System.Net.Http.StringContent]::new('')
                }
                $request.Content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse($value)
                continue
            }

            if ($name -ieq 'Content-Length' -or $name -ieq 'Host') {
                # Computed by the handler; cannot be set per-message.
                continue
            }

            [void] $request.Headers.TryAddWithoutValidation($name, $value)
        }
    }

    # Authorization is attached per-message, never as a default header.
    if ($CredentialPolicy -eq 'GraphBearer') {
        # The sender is the sole token-acquisition owner for this physical
        # attempt. Keeping acquisition beside the credential boundary makes the
        # value acquired, tenant-proved and attached to Authorization one exact
        # result rather than three independently rotating provider values.
        if ([string]::IsNullOrEmpty($TokenAcquisitionKey)) {
            # Direct private callers and injected tests may not carry a context.
            # Production Invoke-GraphRetry always supplies the canonical tuple.
            $tokenResult = $TokenSource.Acquire($ForceRefresh, $effectiveCancellationToken)
        }
        else {
            $sourceForAcquire = $TokenSource
            $forceForAcquire = $ForceRefresh
            $cancellationForAcquire = $effectiveCancellationToken
            $flightKey = Get-GraphTokenFlightKey `
                -AcquisitionKey $TokenAcquisitionKey `
                -ForceRefresh:$ForceRefresh
            $tokenResult = Invoke-GraphTokenSingleFlight `
                -Key $flightKey `
                -CancellationToken $effectiveCancellationToken `
                -AcquireScript {
                    $sourceForAcquire.Acquire($forceForAcquire, $cancellationForAcquire)
                }.GetNewClosure()
        }
        if ($null -eq $tokenResult) {
            throw 'GraphBearer credential policy: token source returned no token.'
        }
        if (-not [string]::IsNullOrEmpty($TokenAcquisitionKey) -and
            $TokenSource -is [GraphTokenSourceBase] -and
            $tokenResult -is [GraphTokenResult]) {
            # The winner caches inside Acquire, but every follower owns a separate
            # immutable context and token-source instance. Adopt the shared result
            # into each follower so a forced-refresh follower cannot serve its
            # previously rejected cached token on the next ordinary request.
            ([GraphTokenSourceBase] $TokenSource).AdoptSharedResult(
                [GraphTokenResult] $tokenResult,
                $ForceRefresh
            )
        }
        if ($VerifyTenantBinding) {
            # Mutating sends require tenant proof BEFORE the request is issued.
            # A result that carries no VerifiedTenantId, or whose binding is not
            # recorded for the current fingerprint + generation + tenant, is
            # proven now. A provider's claim is never trusted: only a recorded
            # binding skips the proof call.
            $verifiedTenant = [string] $tokenResult.VerifiedTenantId
            $claimMatches = -not [string]::IsNullOrEmpty($verifiedTenant) -and
                [string]::Equals($verifiedTenant, [string] $TargetTenantId, [System.StringComparison]::OrdinalIgnoreCase)

            $bindingCached = $false
            if ($claimMatches) {
                $bindingCached = Test-GraphTenantBinding `
                    -Fingerprint ([string] $tokenResult.TokenFingerprint) `
                    -Generation ([string] $tokenResult.CredentialGeneration) `
                    -TenantId $TargetTenantId
            }

            if (-not $claimMatches -or -not $bindingCached) {
                # The sender is deliberately context-free (it receives the
                # expected authority, target tenant and token source rather than
                # the full context), so reconstruct the minimal shape the prover
                # needs to build its proof read and binding key.
                $proofContext = [pscustomobject] @{
                    TenantId     = $TargetTenantId
                    GraphBaseUri = $ExpectedAuthority
                    TokenSource  = $TokenSource
                }

                $prover = $TenantBindingProver
                if ($null -eq $prover) {
                    $prover = {
                        param($Context, $TokenResult, $CancellationToken)
                        Confirm-GraphTenantBinding -Context $Context -TokenResult $TokenResult `
                            -CancellationToken $CancellationToken
                    }
                }

                & $prover -Context $proofContext -TokenResult $tokenResult -CancellationToken $effectiveCancellationToken
            }

            if ($null -eq $tokenResult -or
                [string]::IsNullOrEmpty([string] $tokenResult.VerifiedTenantId) -or
                -not [string]::Equals([string] $tokenResult.VerifiedTenantId, [string] $TargetTenantId, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw (
                    'Tenant binding failed: token is not verified for tenant {0}.' -f $TargetTenantId
                )
            }
        }

        $request.Headers.Authorization =
            [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', [string] $tokenResult.AccessToken)

        # Return only non-secret identity metadata to the retry/provenance layer.
        # A provider may CLAIM VerifiedTenantId; provenance may trust it only when
        # the fingerprint/generation/tenant tuple is in GraphKit's proof cache.
        $bindingRecorded = $TargetTenantId -ne [guid]::Empty -and
            -not [string]::IsNullOrEmpty([string] $tokenResult.VerifiedTenantId) -and
            [string]::Equals([string] $tokenResult.VerifiedTenantId, [string] $TargetTenantId, [System.StringComparison]::OrdinalIgnoreCase) -and
            (Test-GraphTenantBinding `
                -Fingerprint ([string] $tokenResult.TokenFingerprint) `
                -Generation ([string] $tokenResult.CredentialGeneration) `
                -TenantId $TargetTenantId)

        $result.VerifiedTenantId = if ($bindingRecorded) { $TargetTenantId.ToString() } else { $null }
        $result.TokenFingerprint = [string] $tokenResult.TokenFingerprint
        $result.CredentialGeneration = [string] $tokenResult.CredentialGeneration
    }

    # ---- Send (one attempt = exactly one physical send) ----
    $client = Get-GraphHttpClient -State $LifecycleState `
        -ConnectTimeoutSeconds $TimeoutConnectionSeconds `
        -ClientFactory $HttpClientFactory

    # The connection phase is bounded by the handler ConnectTimeout (set once);
    # header and body phases are bounded via a linked CancellationTokenSource.
    $phaseCts = [System.Threading.CancellationTokenSource]::CreateLinkedTokenSource($effectiveCancellationToken)

    try {
        $phaseCts.CancelAfter([TimeSpan]::FromSeconds($TimeoutHeadersSeconds))

        $response = $client.SendAsync(
            $request,
            [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead,
            $phaseCts.Token
        ).GetAwaiter().GetResult()

        $result.ResponseReceived = $true
        $result.StatusCode = [int] $response.StatusCode

        # ---- Normalize headers ----
        foreach ($kv in $response.Headers) {
            $result.Headers[[string] $kv.Key] = ($kv.Value -join ', ')
        }
        if ($null -ne $response.Content) {
            foreach ($kv in $response.Content.Headers) {
                $name = [string] $kv.Key
                $value = ($kv.Value -join ', ')
                if ($result.Headers.ContainsKey($name)) {
                    $result.Headers[$name] = "$($result.Headers[$name]), $value"
                }
                else {
                    $result.Headers[$name] = $value
                }
            }
        }

        $result.RequestId = if ($result.Headers.ContainsKey('request-id')) { [string] $result.Headers['request-id'] } else { $null }

        # ---- Read the body under its own timeout ----
        $phaseCts.CancelAfter([TimeSpan]::FromSeconds($TimeoutBodySeconds))
        $bodyBytes = $response.Content.ReadAsByteArrayAsync($phaseCts.Token).GetAwaiter().GetResult()

        $result.Body = ConvertFrom-GraphResponseBody -Bytes $bodyBytes -Headers $result.Headers
    }
    catch {
        # Unwrap PowerShell's MethodInvocationException to the underlying
        # transport exception (HttpRequestException, TaskCanceledException, ...).
        $ex = $_.Exception
        if ($null -ne $ex -and $null -ne $ex.InnerException) {
            $ex = $ex.InnerException
        }
        $result.TransportException = $ex
        # Preserve ResponseReceived/StatusCode when the failure happened while
        # reading the body (response headers WERE received). Only a failure before
        # the response (connect/header timeout, reset) leaves them unset.
        if (-not $result.ResponseReceived) {
            $result.StatusCode = 0
        }
    }
    return $result
    }
    finally {
        # The lease is released last. Stop-GraphModule cannot dispose a cached
        # client while this sender still owns any request, response or linked
        # cancellation source associated with that client.
        try {
            if ($null -ne $response) {
                $response.Dispose()
            }
        }
        finally {
            try {
                if ($null -ne $request) {
                    $request.Dispose()
                }
            }
            finally {
                try {
                    if ($null -ne $phaseCts) {
                        $phaseCts.Dispose()
                    }
                }
                finally {
                    try {
                        if ($null -ne $lifetimeCts) {
                            $lifetimeCts.Dispose()
                        }
                    }
                    finally {
                        if ($leaseAcquired) {
                            Exit-GraphModuleOperation -State $LifecycleState
                        }
                    }
                }
            }
        }
    }
}

<#
    Normalize a raw response body into the transport result contract:
    parsed hashtable for JSON, raw string for other text, byte[] for binary,
    $null for empty. Malformed or mid-response-truncated JSON is retained as the
    raw string rather than silently dropped.
#>
function ConvertFrom-GraphResponseBody {
    param(
        [AllowNull()]
        [byte[]] $Bytes,

        [hashtable] $Headers
    )

    if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
        return $null
    }

    $contentType = $null
    if ($null -ne $Headers -and $Headers.ContainsKey('Content-Type')) {
        $contentType = [string] $Headers['Content-Type']
    }

    if (-not [string]::IsNullOrEmpty($contentType) -and $contentType -match 'json') {
        $text = $null
        try {
            $text = [System.Text.Encoding]::UTF8.GetString($Bytes)
            $trimmed = $text.Trim()
            if ($trimmed.Length -gt 0 -and ($trimmed[0] -eq '{' -or $trimmed[0] -eq '[')) {
                return (ConvertFrom-Json -InputObject $text -AsHashtable -ErrorAction Stop)
            }
        }
        catch {
            Write-Verbose ('Body JSON parse skipped: {0}' -f $_.Exception.Message)
        }

        # Content-Type claimed JSON but the payload is not parseable JSON - a gateway or
        # WAF returning an HTML error page under a JSON content type, or a mid-response
        # truncation. Return the DECODED STRING, which is what the comment above always
        # promised. Falling through to the byte[] return below (the previous behaviour)
        # handed the caller a byte dump: Get-GraphErrorCodeChain finds nothing in it, and
        # an operator debugging an outage sees '60 104 116 109 108 62' instead of the
        # gateway's message.
        if ($null -ne $text) {
            return $text
        }
    }

    if (-not [string]::IsNullOrEmpty($contentType) -and $contentType -match 'text|xml|html|javascript') {
        return [System.Text.Encoding]::UTF8.GetString($Bytes)
    }

    # Binary or unclassified content type: return the raw bytes.
    return $Bytes
}
