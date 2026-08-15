<#
    Semantics-aware retry decision.

    A status code alone cannot decide a retry. The decision is a function of the
    operation's intrinsic ReplayPolicy, the HTTP method, and the runtime attempt
    certainty (whether the previous attempt may have committed).

    This is a pure function: it performs no I/O, no timing, and no side effects.
    Get-GraphRetryDelay is called only AFTER this function permits a retry - the
    delay parser never decides whether to retry.

    Certainty axis (runtime):
      Succeeded        A 2xx response was received.
      Rejected         The service refused before executing (e.g. a clean 429).
      Ambiguous        Timeout, connection reset, or 502/503/504 with no body.
      MayHaveCommitted Ambiguous plus evidence of partial effect (reconciliation).

    Decision rules (spec "Retry must be semantics-aware"):
      - 2xx is always success; a 2xx carrying Retry-After is success + pacing, never replay.
      - 401 triggers at most one forced refresh (only when the token source can refresh).
      - 403/404 never retry.
      - 409 retries only for known transient inner error codes.
      - Rejected (clean 429) retries under any policy but NeverReplay.
      - Ambiguous retries only under Safe, reconciles under Reconciliable, otherwise
        Failed + Indeterminate with no replay.
#>
function Get-GraphRetryDecision {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $Descriptor,

        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS')]
        [string] $Method,

        [Parameter(Mandatory = $true)]
        [int] $StatusCode,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Rejected', 'Ambiguous', 'MayHaveCommitted', 'Succeeded')]
        [string] $AttemptCertainty,

        [bool] $HasRetryAfter,

        [bool] $IsKnownTransient409,

        [bool] $ForceRefreshUsed,

        [bool] $CanRefresh
    )

    $replayPolicy = [string] $Descriptor.ReplayPolicy
    $isRead = $Method -in @('GET', 'HEAD')

    # Successful response: never replay. A 2xx carrying Retry-After is still a
    # success (the client must pace future traffic, not resend this request).
    if ($AttemptCertainty -eq 'Succeeded') {
        return [pscustomobject] @{
            ShouldRetry  = $false
            ForceRefresh = $false
            Reconcile    = $false
            Outcome      = 'Succeeded'
            Certainty    = 'Known'
        }
    }

    # 3xx surfaced (redirects are disabled): a definitive non-success, never
    # retried. Redirect-following for SafeGetOnly happens upstream of the retry
    # engine, so a 3xx here is always surfaced, never replayed.
    if ($StatusCode -ge 300 -and $StatusCode -lt 400) {
        return [pscustomobject] @{
            ShouldRetry  = $false
            ForceRefresh = $false
            Reconcile    = $false
            Outcome      = 'Failed'
            Certainty    = 'Known'
        }
    }


    # 401: at most one forced token acquisition + one replay. A second 401 is an
    # audience/tenant/claims problem, not an invitation to loop.
    if ($StatusCode -eq 401) {
        if ($CanRefresh -and -not $ForceRefreshUsed) {
            return [pscustomobject] @{
                ShouldRetry  = $true
                ForceRefresh = $true
                Reconcile    = $false
                Outcome      = $null
                Certainty    = $null
            }
        }

        return [pscustomobject] @{
            ShouldRetry  = $false
            ForceRefresh = $false
            Reconcile    = $false
            Outcome      = 'Failed'
            Certainty    = 'Known'
        }
    }

    # 403 / 404: client error, never retry.
    if ($StatusCode -in @(403, 404)) {
        return [pscustomobject] @{
            ShouldRetry  = $false
            ForceRefresh = $false
            Reconcile    = $false
            Outcome      = 'Failed'
            Certainty    = 'Known'
        }
    }

    # 409 Conflict: only known transient inner error codes are retryable; an
    # ordinary conflict means the state already exists and must not be replayed.
    if ($StatusCode -eq 409) {
        if ($IsKnownTransient409 -and $replayPolicy -ne 'NeverReplay') {
            return [pscustomobject] @{
                ShouldRetry  = $true
                ForceRefresh = $false
                Reconcile    = $false
                Outcome      = $null
                Certainty    = $null
            }
        }

        return [pscustomobject] @{
            ShouldRetry  = $false
            ForceRefresh = $false
            Reconcile    = $false
            Outcome      = 'Failed'
            Certainty    = 'Known'
        }
    }

    # ---- Rejected: the service refused before executing (clean 429). ----
    if ($AttemptCertainty -eq 'Rejected') {
        # Any 4xx other than 429 (400, 422, ...) is a permanent client error:
        # no retry. 401/403/404/409 are handled above; 429 is the retryable case.
        if ($StatusCode -ge 400 -and $StatusCode -lt 500 -and $StatusCode -ne 429) {
            return [pscustomobject] @{
                ShouldRetry  = $false
                ForceRefresh = $false
                Reconcile    = $false
                Outcome      = 'Failed'
                Certainty    = 'Known'
            }
        }

        if ($replayPolicy -eq 'NeverReplay') {
            return [pscustomobject] @{
                ShouldRetry  = $false
                ForceRefresh = $false
                Reconcile    = $false
                Outcome      = 'Failed'
                Certainty    = 'Known'
            }
        }

        # Conditional operations replay only where the descriptor permits the method.
        if ($replayPolicy -eq 'Conditional') {
            $condition = $Descriptor.Condition
            $permitted = ($null -ne $condition -and $condition -is [hashtable] -and
                [string]::Equals([string] $condition['Method'], $Method, [System.StringComparison]::OrdinalIgnoreCase))

            if (-not $permitted) {
                return [pscustomobject] @{
                    ShouldRetry  = $false
                    ForceRefresh = $false
                    Reconcile    = $false
                    Outcome      = 'Failed'
                    Certainty    = 'Known'
                }
            }
        }

        return [pscustomobject] @{
            ShouldRetry  = $true
            ForceRefresh = $false
            Reconcile    = $false
            Outcome      = $null
            Certainty    = $null
        }
    }

    # ---- Ambiguous / MayHaveCommitted: the commit state is unknown. ----
    # The descriptor is authoritative. An earlier form read
    #   $safe = $isRead -or $replayPolicy -eq 'Safe'
    # which let the HTTP verb override an explicit NeverReplay on a GET - honouring
    # the descriptor on the Rejected path but ignoring it here, on the path where the
    # commit state is unknown. ReplayPolicy exists precisely so safety is not inferred
    # from the verb (a one-shot export download is a GET that must not be replayed).
    $safe = $replayPolicy -eq 'Safe' -or ($isRead -and $replayPolicy -ne 'NeverReplay')

    if ($safe) {
        # Reads and Safe operations can always replay: replay cannot change state.
        return [pscustomobject] @{
            ShouldRetry  = $true
            ForceRefresh = $false
            Reconcile    = $false
            Outcome      = $null
            Certainty    = $null
        }
    }

    if ($replayPolicy -eq 'Reconciliable') {
        # Do not blindly replay; signal reconciliation (query the intended result).
        return [pscustomobject] @{
            ShouldRetry  = $false
            ForceRefresh = $false
            Reconcile    = $true
            Outcome      = 'Failed'
            Certainty    = 'Indeterminate'
        }
    }

    if ($replayPolicy -eq 'Conditional') {
        $condition = $Descriptor.Condition
        $permitsAmbiguous = ($null -ne $condition -and $condition -is [hashtable] -and
            [string]::Equals([string] $condition['Method'], $Method, [System.StringComparison]::OrdinalIgnoreCase) -and
            $condition.ContainsKey('AllowAmbiguousTransport') -and
            $condition['AllowAmbiguousTransport'] -eq $true)

        if ($permitsAmbiguous) {
            return [pscustomobject] @{
                ShouldRetry  = $true
                ForceRefresh = $false
                Reconcile    = $false
                Outcome      = $null
                Certainty    = $null
            }
        }
    }

    # Ambiguous write with no safe/reconciliation/conditional permission: surface
    # the indeterminate outcome without replaying.
    return [pscustomobject] @{
        ShouldRetry  = $false
        ForceRefresh = $false
        Reconcile    = $false
        Outcome      = 'Failed'
        Certainty    = 'Indeterminate'
    }
}
