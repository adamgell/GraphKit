<#
    The retry engine: one GraphKit attempt loop that owns replay decisions.

    Consumes the normalized GraphTransportResult contract, never provider-specific
    PowerShell or HttpClient exception shapes. Send, UtcNow, Delay, and Jitter are
    injectable, so the full matrix and every deadline/cancellation path is testable
    with virtual time (a five-minute scenario runs in milliseconds).

    Returns exactly one GraphKit.OperationResult envelope and never throws for
    transport-level outcomes. The only hard errors are credential-boundary
    violations raised by the sender before any token leaves the process.
#>

# Known transient Graph error codes that make an otherwise permanent 409 Conflict
# safely retryable. Curated v1 set; extensible. Anything else on a 409 is treated
# as a real conflict and is never replayed.
$script:GraphKnownTransientErrorCodes = @(
    'SyncStateNotFound'
    'Directory_ReplicaUnavailable'
    'ServiceUnavailable'
    'Timeout'
    'ServerBusy'
)

function Get-GraphAttemptCertainty {
    param(
        [int] $StatusCode,
        [bool] $ResponseReceived,

        [AllowNull()]
        [object] $TransportException
    )

    if ($ResponseReceived) {
        # Accepted means the service owns the work. Replaying a 202 can duplicate
        # an asynchronous operation even when its optional response body failed.
        if ($StatusCode -eq 202) { return 'Succeeded' }

        # Headers alone do not make a 2xx usable. A timeout/reset while reading
        # its body leaves a normalized transport failure and incomplete data.
        if ($StatusCode -ge 200 -and $StatusCode -lt 300 -and $null -ne $TransportException) {
            return 'Ambiguous'
        }
        if ($StatusCode -ge 200 -and $StatusCode -lt 300) { return 'Succeeded' }
        if ($StatusCode -eq 408) { return 'Ambiguous' }
        if ($StatusCode -ge 500 -and $StatusCode -le 599) { return 'Ambiguous' }
        # 4xx: a clean refusal before execution (429, 401, 403, 404, 409, ...).
        return 'Rejected'
    }

    # Timeout or connection reset with no response.
    return 'Ambiguous'
}

function Test-GraphDeadlineExpired {
    param(
        [System.Diagnostics.Stopwatch] $Stopwatch,
        [datetime] $DeadlineUtc,
        [scriptblock] $UtcNow,
        [double] $DeadlineSeconds
    )

    if ($Stopwatch.Elapsed.TotalSeconds -ge [double] $DeadlineSeconds) { return $true }
    if ((& $UtcNow) -ge $DeadlineUtc) { return $true }
    return $false
}

function Get-GraphResponseHeader {
    param(
        [AllowNull()]
        [hashtable] $Headers,

        [Parameter(Mandatory = $true)]
        [string] $Name
    )

    if ($null -eq $Headers) { return $null }

    foreach ($key in $Headers.Keys) {
        if ([string]::Equals([string] $key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $Headers[$key]
        }
    }

    return $null
}

function ConvertTo-GraphDate {
    param(
        [AllowNull()]
        [string] $Value
    )

    if ([string]::IsNullOrEmpty($Value)) { return $null }

    $dto = [System.DateTimeOffset]::MinValue
    if ([System.DateTimeOffset]::TryParse(
            $Value,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AllowWhiteSpaces,
            [ref] $dto)) {
        return $dto.UtcDateTime
    }

    return $null
}

function Test-GraphKnownTransient409 {
    param(
        [AllowNull()]
        [object] $Body
    )

    foreach ($code in (Get-GraphErrorCodeChain -Body $Body)) {
        if ($script:GraphKnownTransientErrorCodes -contains $code) {
            return $true
        }
    }

    return $false
}

function Invoke-GraphRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object] $Context,

        [Parameter(Mandatory = $true)]
        [hashtable] $Descriptor,

        [Parameter(Mandatory = $true)]
        [uri] $Uri,

        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS')]
        [string] $Method,

        [AllowNull()]
        [hashtable] $Headers,

        [AllowNull()]
        [object] $Body,

        [System.Threading.CancellationToken] $CancellationToken = [System.Threading.CancellationToken]::None,

        [hashtable] $Injections,

        [ValidateRange(1, 100)]
        [int] $MaxAttempts = 5,

        [ValidateRange(0.001, 86400)]
        [double] $DeadlineSeconds = 300
    )

    # ---- Resolve injections ----
    $send = $null
    $utcNow = $null
    $delay = $null
    $jitter = $null

    if ($null -ne $Injections) {
        $send = $Injections['Send']
        $utcNow = $Injections['UtcNow']
        $delay = $Injections['Delay']
        $jitter = $Injections['Jitter']
    }

    if ($null -eq $send) {
        $sendCommand = Get-Command Send-GraphHttpRequest -ErrorAction SilentlyContinue
        if ($null -ne $sendCommand) {
            $send = $sendCommand.ScriptBlock
        }
        else {
            throw 'Invoke-GraphRetry: no Send injection and Send-GraphHttpRequest is unavailable.'
        }
    }
    if ($null -eq $utcNow) { $utcNow = { [datetime]::UtcNow } }
    if ($null -eq $delay) {
        $delay = {
            param(
                [double] $Seconds,
                [System.Threading.CancellationToken] $CancellationToken = [System.Threading.CancellationToken]::None
            )

            if ($Seconds -le 0) { return }
            if ($CancellationToken.CanBeCanceled) {
                if ($CancellationToken.WaitHandle.WaitOne([TimeSpan]::FromSeconds($Seconds))) {
                    $CancellationToken.ThrowIfCancellationRequested()
                }
            }
            else {
                Start-Sleep -Seconds $Seconds
            }
        }
    }
    if ($null -eq $jitter) { $jitter = { Get-Random -Minimum 0.0 -Maximum 1.0 } }

    # ---- Deadline: monotonic Stopwatch plus the injected (virtual) clock ----
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $deadlineUtc = (& $utcNow).AddSeconds([double] $DeadlineSeconds)

    $logicalOperationId = [guid]::NewGuid()

    $credentialPolicy = [string] $Descriptor.CredentialPolicy
    $isMutating = $Method -notin @('GET', 'HEAD')
    # Catalog operations declare whether tenant-attributed results require proof.
    # Method-based mutation remains the fail-closed fallback for raw/private callers
    # whose synthesized descriptor predates IdentityRequirement. A verified GET must
    # be proved just as a write is: Graph's shared authority cannot identify which
    # tenant the bearer addresses.
    $requiresTenantBinding = $isMutating -or
        ([string] $Descriptor.IdentityRequirement -ceq 'Verified')
    $canRefresh = ($null -ne $Context.TokenSource) -and ($Context.TokenSource.CanRefresh -eq $true)

    # ---- Throttle scope (coarse + leaf) ----
    $scope = New-GraphThrottleScope -Context $Context -Descriptor $Descriptor

    $telemetry = [System.Collections.Generic.List[object]]::new()
    $forceRefreshPending = $false
    $forceRefreshUsed = $false

    $outcome = $null
    $certaintyFinal = 'Known'
    $data = @()
    $verifiedTenantId = $null
    $verifiedTokenFingerprint = $null
    $verifiedCredentialGeneration = $null
    $lastAttemptCertainty = $null

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        # ---- Deadline / cancellation before the throttle gate ----
        if ($CancellationToken.IsCancellationRequested) {
            $outcome = 'Cancelled'
            $certaintyFinal = 'Indeterminate'
            break
        }
        if (Test-GraphDeadlineExpired -Stopwatch $stopwatch -DeadlineUtc $deadlineUtc -UtcNow $utcNow -DeadlineSeconds $DeadlineSeconds) {
            $outcome = 'DeadlineExpired'
            $certaintyFinal = 'Indeterminate'
            break
        }

        # ---- Throttle admission ----
        $remainingGateStopwatchSeconds = [double] $DeadlineSeconds - $stopwatch.Elapsed.TotalSeconds
        $remainingGateClockSeconds = ($deadlineUtc - (& $utcNow)).TotalSeconds
        $remainingGateSeconds = [Math]::Max(
            0.0,
            [Math]::Min($remainingGateStopwatchSeconds, $remainingGateClockSeconds)
        )
        try {
            $admission = Wait-GraphThrottleGate -Scope $scope `
                -CancellationToken $CancellationToken `
                -UtcNow (& $utcNow) `
                -UtcNowScript $utcNow `
                -DeadlineUtc $deadlineUtc `
                -RemainingDeadline ([TimeSpan]::FromSeconds($remainingGateSeconds))
        }
        catch {
            $gateFailure = $_.Exception
            $candidate = $gateFailure
            $isCancellationFailure = $false
            $isOperationDeadline = $false
            while ($null -ne $candidate) {
                if ($candidate -is [System.OperationCanceledException]) {
                    $isCancellationFailure = $true
                }
                if ($candidate -is [System.TimeoutException] -and
                    $candidate.Data['GraphKit.OperationDeadlineExpired'] -eq $true) {
                    $isOperationDeadline = $true
                }
                $candidate = $candidate.InnerException
            }

            if ($CancellationToken.IsCancellationRequested -and
                ($isCancellationFailure -or $isOperationDeadline)) {
                $outcome = 'Cancelled'
                $certaintyFinal = 'Indeterminate'
                break
            }
            if ($isOperationDeadline) {
                $outcome = 'DeadlineExpired'
                $certaintyFinal = 'Indeterminate'
                break
            }
            throw
        }

        # ---- Deadline / cancellation mid-throttle (wait may have consumed time) ----
        if ($CancellationToken.IsCancellationRequested -or
            (Test-GraphDeadlineExpired -Stopwatch $stopwatch -DeadlineUtc $deadlineUtc -UtcNow $utcNow -DeadlineSeconds $DeadlineSeconds)) {
            if ($null -ne $admission) { Complete-GraphThrottleGate -Admission $admission }

            if ($CancellationToken.IsCancellationRequested) {
                $outcome = 'Cancelled'
            }
            else {
                $outcome = 'DeadlineExpired'
            }
            $certaintyFinal = 'Indeterminate'
            break
        }

        # Everything from token acquisition to the admission release runs under try/catch.
        # Wait-GraphThrottleGate has already taken a slot at this point, and the only
        # releases were the normal-completion path and the mid-throttle deadline path - so
        # ANY throw in between leaked the slot permanently. TokenSource.Acquire throwing is
        # not hypothetical: a wrong vault secret name, a certificate without a private key,
        # or an MSAL service exception all reach here.
        #
        # A leak is worse than it sounds. The coordinator starts at InitialConcurrency = 2,
        # so two failures on one scope exhaust it for the rest of the session, and every
        # later operation on that tenant|client|class|family then blocks and reports
        # back-pressure - blaming Graph for a slot this module never gave back.
        try {
            # ---- Build per-attempt request headers (never mutate the caller's table) ----
            $clientRequestId = [guid]::NewGuid()
            $sendHeaders = @{}
            if ($null -ne $Headers) {
                foreach ($entry in $Headers.GetEnumerator()) {
                    $sendHeaders[$entry.Key] = $entry.Value
                }
            }
            $sendHeaders['client-request-id'] = $clientRequestId.ToString()

            $sendParams = @{
                Uri               = $Uri
                Method            = $Method
                Headers           = $sendHeaders
                Body              = $Body
                CancellationToken = $CancellationToken
                CredentialPolicy  = $credentialPolicy
            }

            # Per-operation transport timeouts. Added ONLY when the descriptor declares them, for
            # two reasons: the transport's defaults stay authoritative for every other operation,
            # and an injected test sender - which declares only the parameters it needs - is not
            # handed a parameter it cannot bind. Splatting an unbindable parameter into an injected
            # delegate is precisely how the -CancellationToken defect reached a live tenant.
            $descriptorTimeouts = $Descriptor.Timeouts
            if ($descriptorTimeouts -is [hashtable]) {
                # The operation deadline must still win. Deadline expiry is only checked BETWEEN
                # attempts, so once a send begins nothing else bounds it: a descriptor declaring a
                # 600-second timeout under a 300-second deadline would overrun the deadline by
                # minutes on a single attempt, and the caller's timeout would mean nothing. Clamp
                # each phase to whatever remains, with a one-second floor so a nearly-expired
                # deadline fails fast rather than passing 0 (which several stacks read as infinite).
                $remainingSeconds = [Math]::Max(1, [int]([double] $DeadlineSeconds - $stopwatch.Elapsed.TotalSeconds))

                # The phases run SEQUENTIALLY, so capping each at the full remaining budget
                # would let one attempt take phases x remaining: three declared phases under a
                # 300s deadline could hold a single attempt for ~900s, and the deadline is only
                # checked BETWEEN attempts. Divide the budget across the phases declared.
                $phaseMap = @(
                    @{ Key = 'ConnectionSeconds'; Param = 'TimeoutConnectionSeconds' }
                    @{ Key = 'HeadersSeconds'; Param = 'TimeoutHeadersSeconds' }
                    @{ Key = 'BodySeconds'; Param = 'TimeoutBodySeconds' }
                )
                $declaredPhases = @($phaseMap | Where-Object { $descriptorTimeouts.ContainsKey($_.Key) })
                $perPhaseBudget = [Math]::Max(1, [int]($remainingSeconds / [Math]::Max(1, $declaredPhases.Count)))

                foreach ($phase in $declaredPhases) {
                    $declared = [int] $descriptorTimeouts[$phase.Key]
                    $sendParams[$phase.Param] = [Math]::Min($declared, $perPhaseBudget)
                }
            }

            if ($credentialPolicy -eq 'GraphBearer') {
                $sendParams.TokenSource = $Context.TokenSource
                $sendParams.ForceRefresh = $forceRefreshPending
                $sendParams.TokenAcquisitionKey = [string] $Context.AcquisitionCacheKey
                $sendParams.ExpectedAuthority = $Context.GraphBaseUri
                $sendParams.TargetTenantId = $Context.TenantId
                if ($requiresTenantBinding) {
                    $sendParams.VerifyTenantBinding = $true
                    # The proof is part of this attempt, not a new operation with
                    # a fresh five-minute clock. Pass the smaller remaining budget
                    # reported by the monotonic and injected clocks, plus the exact
                    # caller scope needed by the nested proof admission.
                    $remainingStopwatchSeconds = [double] $DeadlineSeconds - $stopwatch.Elapsed.TotalSeconds
                    $remainingClockSeconds = ($deadlineUtc - (& $utcNow)).TotalSeconds
                    $remainingProofSeconds = [Math]::Max(
                        0.0,
                        [Math]::Min($remainingStopwatchSeconds, $remainingClockSeconds)
                    )
                    $sendParams.TenantBindingContext = [pscustomobject] @{
                        Cloud             = $Context.Cloud
                        ClientId          = $Context.ClientId
                        RemainingDeadline = [TimeSpan]::FromSeconds($remainingProofSeconds)
                        DeadlineUtc       = $deadlineUtc
                        UtcNow            = $utcNow
                    }
                }
            }

            # ---- One attempt = exactly one send ----
            $result = & $send @sendParams

            # Sender cancellation is normalized like every other transport
            # outcome. Consume only GraphKit's boolean marker; do not infer
            # cancellation from provider-specific exception messages or types.
            $candidate = $result.TransportException
            $isOperationCancellation = $false
            while ($null -ne $candidate) {
                if ($candidate -is [System.Exception] -and
                    $candidate.Data['GraphKit.OperationCancellation'] -eq $true) {
                    $isOperationCancellation = $true
                    break
                }
                $candidate = $candidate.InnerException
            }
            if ($isOperationCancellation) {
                throw $result.TransportException
            }

            # A handler may ignore cancellation and still return a clean-looking
            # response. Recheck immediately, before body/provenance/telemetry can
            # be accepted as a successful operation result.
            $CancellationToken.ThrowIfCancellationRequested()

            if ($forceRefreshPending) {
                $forceRefreshPending = $false
                $forceRefreshUsed = $true
            }

            $attemptVerifiedTenantId = $null
            $attemptTokenFingerprint = $null
            $attemptCredentialGeneration = $null
            if (-not [string]::IsNullOrEmpty([string] $result.VerifiedTenantId) -and
                [string]::Equals([string] $result.VerifiedTenantId, [string] $Context.TenantId, [System.StringComparison]::OrdinalIgnoreCase)) {
                if ([string]::IsNullOrWhiteSpace([string] $result.TokenFingerprint) -or
                    [string]::IsNullOrWhiteSpace([string] $result.CredentialGeneration)) {
                    throw [System.InvalidOperationException]::new(
                        'VerifiedForToken transport provenance requires a non-empty TokenFingerprint and CredentialGeneration.'
                    )
                }
                $attemptVerifiedTenantId = $Context.TenantId
                $attemptTokenFingerprint = [string] $result.TokenFingerprint
                $attemptCredentialGeneration = [string] $result.CredentialGeneration
            }

            # ---- Runtime certainty, then release admission ----
            # Complete-GraphThrottleGate's -Success switch drives additive-increase
            # (AIMD restore); without it a qualified throttle never recovers.
            $certainty = Get-GraphAttemptCertainty -StatusCode $result.StatusCode `
                -ResponseReceived $result.ResponseReceived -TransportException $result.TransportException
            $lastAttemptCertainty = $certainty

            if ($null -ne $admission) { Complete-GraphThrottleGate -Admission $admission -Success:($certainty -eq 'Succeeded') }
            $admission = $null
        }
        catch {
            $sendFailure = $_.Exception
            if ($null -ne $admission) {
                Complete-GraphThrottleGate -Admission $admission
                $admission = $null
            }

            # Cancellation can occur while this caller is waiting on another
            # context's in-flight token acquisition. Preserve the retry engine's
            # established Cancelled envelope instead of leaking a credential-path
            # OperationCanceledException, but never mask an unrelated failure just
            # because the caller token happened to be signalled at the same time.
            $candidate = $sendFailure
            $isCancellationFailure = $false
            $isOperationCancellation = $false
            $isTenantBindingDeadline = $false
            while ($null -ne $candidate) {
                if ($candidate -is [System.OperationCanceledException]) {
                    $isCancellationFailure = $true
                }
                if ($candidate -is [System.Exception] -and
                    $candidate.Data['GraphKit.OperationCancellation'] -eq $true) {
                    $isOperationCancellation = $true
                }
                if ($candidate -is [System.TimeoutException] -and
                    $candidate.Data['GraphKit.TenantBindingDeadlineExpired'] -eq $true) {
                    $isTenantBindingDeadline = $true
                }
                $candidate = $candidate.InnerException
            }

            # Caller cancellation wins at a simultaneous proof-deadline boundary.
            # The sender normally preserves OCE causality, but a marked deadline
            # can be thrown in the narrow race after the proof checked its token.
            if ($isOperationCancellation -or
                ($CancellationToken.IsCancellationRequested -and
                    ($isCancellationFailure -or $isTenantBindingDeadline))) {
                $outcome = 'Cancelled'
                $certaintyFinal = 'Indeterminate'
                break
            }
            if ($isTenantBindingDeadline) {
                $outcome = 'DeadlineExpired'
                $certaintyFinal = 'Indeterminate'
                break
            }
            throw
        }

        # ---- Decision ----

        $hasRetryAfter = ($null -ne (Get-GraphResponseHeader -Headers $result.Headers -Name 'Retry-After'))
        $isKnownTransient409 = ($result.StatusCode -eq 409) -and (Test-GraphKnownTransient409 -Body $result.Body)

        $decision = Get-GraphRetryDecision `
            -Descriptor $Descriptor `
            -Method $Method `
            -StatusCode $result.StatusCode `
            -AttemptCertainty $certainty `
            -HasRetryAfter $hasRetryAfter `
            -IsKnownTransient409 $isKnownTransient409 `
            -ForceRefreshUsed $forceRefreshUsed `
            -CanRefresh $canRefresh

        if ($decision.ForceRefresh) {
            $forceRefreshPending = $true
        }

        # ---- Delay: retry, throttle state, or 2xx pacing ----
        $throttled = $result.StatusCode -in @(429, 503)
        $pacing = ($hasRetryAfter -and $certainty -eq 'Succeeded')

        $delayInfo = $null
        if ($decision.ShouldRetry -or $throttled -or $pacing) {
            $delayInfo = Get-GraphRetryDelay `
                -RetryAfterValues (Get-GraphResponseHeader -Headers $result.Headers -Name 'Retry-After') `
                -XmsRetryAfterMs (Get-GraphResponseHeader -Headers $result.Headers -Name 'x-ms-retry-after-ms') `
                -ResponseDate (ConvertTo-GraphDate -Value (Get-GraphResponseHeader -Headers $result.Headers -Name 'Date')) `
                -UtcNow (& $utcNow) `
                -Attempt $attempt `
                -Jitter $jitter `
                -MaximumAcceptedSeconds 120
        }

        # ---- Throttle state update (qualified = server-directed delay) ----
        $qualified = $null
        $retryAfterSeconds = $null
        if ($throttled) {
            $qualified = ($null -ne $delayInfo) -and ($delayInfo.Source -ne 'ExponentialBackoff')
            $retryAfterSeconds = if ($null -ne $delayInfo) { [int] [Math]::Ceiling($delayInfo.DelaySeconds) } else { 0 }
            Update-GraphThrottleState -Scope $scope -Qualified $qualified -RetryAfterSeconds $retryAfterSeconds -StatusCode $result.StatusCode
        }
        elseif ($pacing) {
            $retryAfterSeconds = if ($null -ne $delayInfo) { [int] [Math]::Ceiling($delayInfo.DelaySeconds) } else { 0 }
            Update-GraphThrottleState -Scope $scope -Qualified $true -RetryAfterSeconds $retryAfterSeconds -StatusCode $result.StatusCode
        }

        # ---- Per-attempt telemetry record ----
        $throttleSnapshot = @{
            CoarseKey         = $scope.CoarseKey
            LeafKey           = $scope.LeafKey
            ThrottleClass     = $scope.ThrottleClass
            ResourceFamily    = $scope.ResourceFamily
            Qualified         = $qualified
            RetryAfterSeconds = $retryAfterSeconds
        }

        $attemptOutcome = 'Failed'
        if ($decision.ShouldRetry) { $attemptOutcome = 'Retrying' }
        elseif ($decision.Outcome -eq 'Succeeded') { $attemptOutcome = 'Succeeded' }

        $record = New-GraphTelemetry `
            -LogicalOperationId $logicalOperationId `
            -ClientRequestId $clientRequestId `
            -ResponseRequestId $result.RequestId `
            -ResponseDate (Get-GraphResponseHeader -Headers $result.Headers -Name 'Date') `
            -XmsAgsDiagnostic (Get-GraphResponseHeader -Headers $result.Headers -Name 'x-ms-ags-diagnostic') `
            -Uri $Uri `
            -Attempt $attempt `
            -StatusCode $result.StatusCode `
            -DelaySeconds ($(if ($null -ne $delayInfo) { $delayInfo.DelaySeconds } else { $null })) `
            -DelaySource ($(if ($null -ne $delayInfo) { $delayInfo.Source } else { $null })) `
            -ThrottleState $throttleSnapshot `
            -BatchSubrequestId $null `
            -AttemptOutcome $attemptOutcome `
            -AttemptCertainty $certainty `
            -Body $result.Body

        $telemetry.Add($record)

        # ---- Retry or finish ----
        if ($decision.ShouldRetry) {
            if ($null -ne $delayInfo) {
                # Never grant a retry sleep a fresh or unbounded budget. Clamp it
                # to the smaller remaining monotonic/injected-clock deadline and
                # pass caller/proof cancellation into the wait implementation.
                if ($CancellationToken.IsCancellationRequested) {
                    $outcome = 'Cancelled'
                    $certaintyFinal = 'Indeterminate'
                    break
                }

                $remainingStopwatchSeconds = [double] $DeadlineSeconds - $stopwatch.Elapsed.TotalSeconds
                $remainingClockSeconds = ($deadlineUtc - (& $utcNow)).TotalSeconds
                $remainingDelaySeconds = [Math]::Max(
                    0.0,
                    [Math]::Min($remainingStopwatchSeconds, $remainingClockSeconds)
                )
                if ($remainingDelaySeconds -le 0.0) {
                    $outcome = 'DeadlineExpired'
                    $certaintyFinal = 'Indeterminate'
                    break
                }

                $requestedDelaySeconds = [double] $delayInfo.DelaySeconds
                $boundedDelaySeconds = [Math]::Min($requestedDelaySeconds, $remainingDelaySeconds)
                try {
                    & $delay $boundedDelaySeconds -CancellationToken $CancellationToken
                }
                catch {
                    $delayFailure = $_.Exception
                    $candidate = $delayFailure
                    $isCancellationFailure = $false
                    while ($null -ne $candidate) {
                        if ($candidate -is [System.OperationCanceledException]) {
                            $isCancellationFailure = $true
                            break
                        }
                        $candidate = $candidate.InnerException
                    }

                    if ($CancellationToken.IsCancellationRequested -and $isCancellationFailure) {
                        $outcome = 'Cancelled'
                        $certaintyFinal = 'Indeterminate'
                        break
                    }
                    throw
                }

                if ($CancellationToken.IsCancellationRequested) {
                    $outcome = 'Cancelled'
                    $certaintyFinal = 'Indeterminate'
                    break
                }
                if ($requestedDelaySeconds -ge $remainingDelaySeconds -or
                    (Test-GraphDeadlineExpired -Stopwatch $stopwatch -DeadlineUtc $deadlineUtc -UtcNow $utcNow -DeadlineSeconds $DeadlineSeconds)) {
                    $outcome = 'DeadlineExpired'
                    $certaintyFinal = 'Indeterminate'
                    break
                }
            }
            continue
        }

        # Tenant verification belongs to the token used by this terminal attempt.
        # A proven token that receives 401 must never lend its identity to the
        # refreshed token whose response becomes the operation result.
        $verifiedTenantId = $attemptVerifiedTenantId
        $verifiedTokenFingerprint = $attemptTokenFingerprint
        $verifiedCredentialGeneration = $attemptCredentialGeneration
        $outcome = $decision.Outcome
        $certaintyFinal = $decision.Certainty
        if ($decision.Outcome -eq 'Succeeded') {
            $data = $result.Body
        }
        break
    }

    # ---- Loop exhausted without a terminal decision: retries ran out ----
    if ($null -eq $outcome) {
        $outcome = 'Failed'
        $certaintyFinal = if ($lastAttemptCertainty -eq 'Rejected') { 'Known' } else { 'Indeterminate' }
    }

    $provenance = @{
        ProfileId      = $Context.ProfileId
        TenantId       = $verifiedTenantId
        ApiVersion     = $Descriptor.ApiVersion
        ResourceFamily = $Descriptor.ResourceFamily
        RetrievedUtc   = (& $utcNow)
        IdentityState  = if ($null -ne $verifiedTenantId) { 'VerifiedForToken' } else { $Context.IdentityState }
        ActualTenantId = $verifiedTenantId
        TokenFingerprint = $verifiedTokenFingerprint
        CredentialGeneration = $verifiedCredentialGeneration
        Cloud          = $Context.Cloud
    }

    # Carry the operation's declared secret-bearing properties on the envelope so it is
    # self-describing. Export-GraphResult receives a result, not a descriptor - provenance
    # records ResourceFamily and ApiVersion but not Type or Operation - so without this it has
    # no way to know what the rows contain and could only guess by property name, which is
    # exactly the approach that redacts compliance settings while missing scriptContent.
    # Travelling on the envelope also survives an envelope being serialised and reloaded.
    if ($null -ne $Descriptor.SensitiveProperties -and @($Descriptor.SensitiveProperties).Count -gt 0) {
        $provenance['SensitiveProperties'] = @($Descriptor.SensitiveProperties)
    }

    return [pscustomobject] @{
        PSTypeName = 'GraphKit.OperationResult'
        Data       = $data
        Outcome    = $outcome
        Certainty  = $certaintyFinal
        Telemetry  = @($telemetry)
        Provenance = $provenance
    }
}
