# Wait-GraphThrottleGate — waits out the strictest scoped cooldown, then acquires leaf admission.
#
# Consults both the coarse and leaf gates and waits for the strictest (longest) active
# cooldown. The wait is performed through the injected -Delay scriptblock (default
# Start-Sleep) so tests can substitute virtual time. Admission is leaf-scoped: the coarse
# gate participates only via its cooldown. Returns an admission record that
# Complete-GraphThrottleGate consumes to release the slot.

function Wait-GraphThrottleGate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Scope,

        [object] $Coordinator,

        [scriptblock] $Delay,

        [System.Threading.CancellationToken] $CancellationToken = [System.Threading.CancellationToken]::None,

        [System.DateTime] $UtcNow = [System.DateTime]::MinValue,

        # Optional inherited operation deadline. Invoke-GraphRetry supplies all
        # three values from its one caller budget; direct legacy callers may omit
        # them and retain the existing admission-timeout-only behaviour.
        [System.TimeSpan] $RemainingDeadline,

        [System.DateTime] $DeadlineUtc = [System.DateTime]::MinValue,

        [scriptblock] $UtcNowScript,

        # Bound on how long to wait for an admission slot. Reaching it is back-pressure,
        # not a transport failure, and is reported as such.
        [ValidateRange(1, 3600)]
        [int] $AdmissionTimeoutSeconds = 120
    )

    if ($UtcNow -eq [System.DateTime]::MinValue) {
        $UtcNow = [System.DateTime]::UtcNow
    }

    if ($null -eq $Coordinator) {
        $Coordinator = Get-GraphThrottleCoordinator
    }

    $CancellationToken.ThrowIfCancellationRequested()

    $deadlineEnabled = $PSBoundParameters.ContainsKey('RemainingDeadline')
    $deadlineStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $initialRemaining = if ($deadlineEnabled) { $RemainingDeadline } else { [TimeSpan]::MaxValue }
    $getRemainingMilliseconds = {
        if (-not $deadlineEnabled) { return [double]::PositiveInfinity }

        $remaining = $initialRemaining - $deadlineStopwatch.Elapsed
        if ($DeadlineUtc -ne [System.DateTime]::MinValue -and $null -ne $UtcNowScript) {
            $clockRemaining = $DeadlineUtc - (& $UtcNowScript)
            if ($clockRemaining -lt $remaining) {
                $remaining = $clockRemaining
            }
        }

        return [Math]::Max(0.0, $remaining.TotalMilliseconds)
    }.GetNewClosure()
    $newDeadlineException = {
        $failure = [System.TimeoutException]::new(
            'The Graph operation deadline expired while waiting for throttle admission.'
        )
        $failure.Data['GraphKit.OperationDeadlineExpired'] = $true
        return $failure
    }

    # Production waits block on the token wait handle, so cancellation wakes the
    # thread without polling or duration-based guesses. An injected delay receives
    # the token as its second positional argument only when it declares a
    # CancellationToken parameter. That preserves the original one-parameter test
    # seam, including advanced scriptblocks that reject undeclared parameters.
    # Cancellation is checked again immediately after every injected step.
    $delayAcceptsCancellationToken = $false
    if ($null -ne $Delay -and $null -ne $Delay.Ast.ParamBlock) {
        $delayAcceptsCancellationToken = @(
            $Delay.Ast.ParamBlock.Parameters | Where-Object {
                $_.Name.VariablePath.UserPath -eq 'CancellationToken'
            }
        ).Count -gt 0
    }

    $wait = {
        param([long] $Milliseconds)

        $CancellationToken.ThrowIfCancellationRequested()
        if ($Milliseconds -le 0) { return }

        if ($null -eq $Delay) {
            if ($CancellationToken.CanBeCanceled) {
                if ($CancellationToken.WaitHandle.WaitOne([TimeSpan]::FromMilliseconds($Milliseconds))) {
                    $CancellationToken.ThrowIfCancellationRequested()
                }
            }
            else {
                Start-Sleep -Milliseconds $Milliseconds
            }
        }
        else {
            if ($delayAcceptsCancellationToken) {
                & $Delay $Milliseconds $CancellationToken
            }
            else {
                & $Delay $Milliseconds
            }
            $CancellationToken.ThrowIfCancellationRequested()
        }
    }.GetNewClosure()

    $coarseWait = $Coordinator.GetWaitMilliseconds([string] $Scope.CoarseKey, $UtcNow)
    $leafWait = $Coordinator.GetWaitMilliseconds([string] $Scope.LeafKey, $UtcNow)
    $waitMilliseconds = [long] [Math]::Max($coarseWait, $leafWait)

    if ($waitMilliseconds -gt 0) {
        $remainingBeforeCooldown = [double] (& $getRemainingMilliseconds)
        if ($remainingBeforeCooldown -le 0.0) {
            $CancellationToken.ThrowIfCancellationRequested()
            throw (& $newDeadlineException)
        }

        $boundedCooldown = [long] [Math]::Ceiling(
            [Math]::Min([double] $waitMilliseconds, $remainingBeforeCooldown)
        )
        & $wait $boundedCooldown

        # Cancellation wins if it arrives at the same instant as expiry.
        $CancellationToken.ThrowIfCancellationRequested()
        if ($boundedCooldown -lt $waitMilliseconds -or
            $boundedCooldown -ge $remainingBeforeCooldown -or
            ([double] (& $getRemainingMilliseconds)) -le 0.0) {
            throw (& $newDeadlineException)
        }
    }

    # Admission: wait for a free slot, do not fail because one is busy.
    #
    # An earlier form called AcquireAdmission unconditionally, which throws when every
    # slot is taken. That fired exactly when a qualified 429 had cut MaxConcurrent to
    # the floor - i.e. when admission control was doing its job - turning back-pressure
    # into an InvalidOperationException in the request path. The gate now polls
    # TryAcquireAdmission through the same injected -Delay used for the cooldown, so
    # virtual-clock tests keep working.
    $admissionWaited = 0.0
    $pollMilliseconds = 50

    $acquired = $false
    while (-not $acquired) {
        $CancellationToken.ThrowIfCancellationRequested()
        $remainingBeforeAcquire = [double] (& $getRemainingMilliseconds)
        if ($remainingBeforeAcquire -le 0.0) {
            $CancellationToken.ThrowIfCancellationRequested()
            throw (& $newDeadlineException)
        }

        $acquired = $Coordinator.TryAcquireAdmission([string] $Scope.LeafKey)
        if ($acquired) {
            # Cancellation and expiry can race TryAcquireAdmission. Release the
            # exact slot before surfacing either condition; cancellation wins.
            if ($CancellationToken.IsCancellationRequested -or
                ([double] (& $getRemainingMilliseconds)) -le 0.0) {
                $Coordinator.ReleaseAdmission([string] $Scope.LeafKey, $false)
                $CancellationToken.ThrowIfCancellationRequested()
                throw (& $newDeadlineException)
            }
            break
        }

        if ($admissionWaited -ge $AdmissionTimeoutSeconds * 1000.0) {
            # Cancellation may arrive inside the final TryAcquireAdmission call.
            # It wins over the independent back-pressure timeout at that exact
            # boundary, just as it does at operation-deadline boundaries.
            $CancellationToken.ThrowIfCancellationRequested()
            throw (
                "Throttle admission timed out after {0}s waiting for a slot on scope '{1}'. " -f
                $AdmissionTimeoutSeconds, $Scope.LeafKey
            ) + 'Concurrency is at the floor and in-flight work is not completing; this is back-pressure, not a transport error.'
        }

        $remainingAdmissionTimeout = ($AdmissionTimeoutSeconds * 1000.0) - $admissionWaited
        $remainingOperation = [double] (& $getRemainingMilliseconds)
        $boundedPoll = [long] [Math]::Ceiling(
            [Math]::Min(
                [double] $pollMilliseconds,
                [Math]::Min($remainingAdmissionTimeout, $remainingOperation)
            )
        )
        if ($boundedPoll -le 0) {
            $CancellationToken.ThrowIfCancellationRequested()
            throw (& $newDeadlineException)
        }

        & $wait $boundedPoll

        $admissionWaited += $boundedPoll
        $CancellationToken.ThrowIfCancellationRequested()
        if ($boundedPoll -ge $remainingOperation -or
            ([double] (& $getRemainingMilliseconds)) -le 0.0) {
            throw (& $newDeadlineException)
        }
    }

    $admission = @{
        Key             = [string] $Scope.LeafKey
        AcquiredUtc     = $UtcNow.AddMilliseconds([double] $waitMilliseconds + $admissionWaited)
        Coordinator     = $Coordinator
        CooldownWaitMs  = $waitMilliseconds
        AdmissionWaitMs = $admissionWaited
    }

    # Cancellation can race the successful TryAcquire. Release the exact slot
    # before surfacing cancellation so no caller can inherit an admission that
    # must never progress to a send.
    if ($CancellationToken.IsCancellationRequested) {
        $Coordinator.ReleaseAdmission([string] $Scope.LeafKey, $false)
        $CancellationToken.ThrowIfCancellationRequested()
    }

    return $admission
}
