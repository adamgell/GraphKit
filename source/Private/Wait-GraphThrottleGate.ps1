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

        [System.DateTime] $UtcNow = [System.DateTime]::MinValue,

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

    $coarseWait = $Coordinator.GetWaitMilliseconds([string] $Scope.CoarseKey, $UtcNow)
    $leafWait = $Coordinator.GetWaitMilliseconds([string] $Scope.LeafKey, $UtcNow)
    $waitMilliseconds = [long] [Math]::Max($coarseWait, $leafWait)

    if ($waitMilliseconds -gt 0) {
        if ($null -eq $Delay) {
            Start-Sleep -Milliseconds $waitMilliseconds
        }
        else {
            & $Delay -Milliseconds $waitMilliseconds
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

    while (-not $Coordinator.TryAcquireAdmission([string] $Scope.LeafKey)) {
        if ($admissionWaited -ge $AdmissionTimeoutSeconds * 1000.0) {
            throw (
                "Throttle admission timed out after {0}s waiting for a slot on scope '{1}'. " -f
                    $AdmissionTimeoutSeconds, $Scope.LeafKey
            ) + 'Concurrency is at the floor and in-flight work is not completing; this is back-pressure, not a transport error.'
        }

        if ($null -eq $Delay) {
            Start-Sleep -Milliseconds $pollMilliseconds
        }
        else {
            & $Delay -Milliseconds $pollMilliseconds
        }

        $admissionWaited += $pollMilliseconds
    }

    return @{
        Key             = [string] $Scope.LeafKey
        AcquiredUtc     = $UtcNow.AddMilliseconds([double] $waitMilliseconds)
        Coordinator     = $Coordinator
        CooldownWaitMs  = $waitMilliseconds
        AdmissionWaitMs = $admissionWaited
    }
}
