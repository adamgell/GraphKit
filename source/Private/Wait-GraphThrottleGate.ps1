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

        [System.DateTime] $UtcNow = [System.DateTime]::MinValue
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

    $Coordinator.AcquireAdmission([string] $Scope.LeafKey)

    return @{
        Key         = [string] $Scope.LeafKey
        AcquiredUtc = $UtcNow.AddMilliseconds([double] $waitMilliseconds)
        Coordinator = $Coordinator
    }
}
