# Update-GraphThrottleState — folds a response outcome back into the scoped throttle state.
#
# 429 / 503 are throttle signals: a qualified signal (reliable response metadata pointing at
# the resource family) cuts the leaf gate's MaxConcurrent to the floor and applies the
# cooldown; an unqualified signal only applies the coarse-gate cooldown. A 2xx carrying
# Retry-After is a success that paces later work: the leaf cooldown is applied without any
# admission cut. All other status codes leave throttle state untouched.

function Update-GraphThrottleState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Scope,

        [Parameter(Mandatory)]
        [bool] $Qualified,

        [Parameter(Mandatory)]
        [int] $RetryAfterSeconds,

        [Parameter(Mandatory)]
        [int] $StatusCode,

        [object] $Coordinator,

        [System.DateTime] $UtcNow = [System.DateTime]::MinValue
    )

    if ($UtcNow -eq [System.DateTime]::MinValue) {
        $UtcNow = [System.DateTime]::UtcNow
    }

    if ($null -eq $Coordinator) {
        $Coordinator = Get-GraphThrottleCoordinator
    }

    if ($StatusCode -eq 429 -or $StatusCode -eq 503) {
        if ($Qualified) {
            $Coordinator.RecordThrottle([string] $Scope.LeafKey, $true, $RetryAfterSeconds, $UtcNow)
        }
        else {
            $Coordinator.RecordThrottle([string] $Scope.CoarseKey, $false, $RetryAfterSeconds, $UtcNow)
        }
        return
    }

    if ($StatusCode -ge 200 -and $StatusCode -le 299 -and $RetryAfterSeconds -gt 0) {
        $Coordinator.ApplyCooldown([string] $Scope.LeafKey, $RetryAfterSeconds, $UtcNow)
        return
    }

    # Any other status code: no throttle state update.
}
