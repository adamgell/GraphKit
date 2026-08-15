# Complete-GraphThrottleGate — releases a throttle admission slot acquired by Wait-GraphThrottleGate.
#
# On success (the -Success switch), a success streak step is applied so sustained success
# restores concurrency via the coordinator's additive increase. On failure the slot is
# released without touching the streak.

function Complete-GraphThrottleGate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Admission,

        [switch] $Success
    )

    $coordinator = $Admission.Coordinator
    if ($null -eq $coordinator) {
        throw [System.InvalidOperationException]::new(
            'Complete-GraphThrottleGate: the admission record carries no Coordinator. ' +
            'The record must come from Wait-GraphThrottleGate.')
    }

    $coordinator.ReleaseAdmission([string] $Admission.Key, [bool] $Success)
}
