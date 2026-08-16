<#
    The retry engine: one GraphKit attempt loop that owns replay decisions.

    Consumes the normalized GraphTransportResult contract, never PowerShell or
    HttpClient exception internals. Send, UtcNow, Delay, and Jitter are injectable,
    so the full matrix and every deadline/cancellation path is testable with
    virtual time (a five-minute scenario runs in milliseconds).

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
        [bool] $ResponseReceived
    )

    if ($ResponseReceived) {
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
        [int] $DeadlineSeconds
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

        [ValidateRange(1, 86400)]
        [int] $DeadlineSeconds = 300
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
    if ($null -eq $delay) { $delay = { param([double] $Seconds) Start-Sleep -Seconds $Seconds } }
    if ($null -eq $jitter) { $jitter = { Get-Random -Minimum 0.0 -Maximum 1.0 } }

    # ---- Deadline: monotonic Stopwatch plus the injected (virtual) clock ----
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $deadlineUtc = (& $utcNow).AddSeconds([double] $DeadlineSeconds)

    $logicalOperationId = [guid]::NewGuid()

    $credentialPolicy = [string] $Descriptor.CredentialPolicy
    $isMutating = $Method -notin @('GET', 'HEAD')
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
        $admission = Wait-GraphThrottleGate -Scope $scope

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
            # ---- Token acquisition (force refresh when the prior decision demanded it) ----
            if ($credentialPolicy -eq 'GraphBearer' -and $null -ne $Context.TokenSource) {
                $acquireForce = $forceRefreshPending
                $tokenResult = $Context.TokenSource.Acquire($acquireForce, $CancellationToken)
                if ($acquireForce) {
                    $forceRefreshPending = $false
                    $forceRefreshUsed = $true
                }

                if ($null -ne $tokenResult -and
                    -not [string]::IsNullOrEmpty([string] $tokenResult.VerifiedTenantId) -and
                    [string]::Equals([string] $tokenResult.VerifiedTenantId, [string] $Context.TenantId, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $verifiedTenantId = $Context.TenantId
                }
            }

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
                $sendParams.ExpectedAuthority = $Context.GraphBaseUri
                $sendParams.TargetTenantId = $Context.TenantId
                if ($isMutating) {
                    $sendParams.VerifyTenantBinding = $true
                }
            }

            # ---- One attempt = exactly one send ----
            $result = & $send @sendParams

            # ---- Runtime certainty, then release admission ----
            # Complete-GraphThrottleGate's -Success switch drives additive-increase
            # (AIMD restore); without it a qualified throttle never recovers.
            $certainty = Get-GraphAttemptCertainty -StatusCode $result.StatusCode -ResponseReceived $result.ResponseReceived
            $lastAttemptCertainty = $certainty

            if ($null -ne $admission) { Complete-GraphThrottleGate -Admission $admission -Success:($certainty -eq 'Succeeded') }
            $admission = $null
        }
        catch {
            if ($null -ne $admission) {
                Complete-GraphThrottleGate -Admission $admission
                $admission = $null
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
                & $delay $delayInfo.DelaySeconds
            }
            continue
        }

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
        IdentityState  = $Context.IdentityState
        ActualTenantId = $verifiedTenantId
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
