<#
    Private: restore a profile-store snapshot taken before a multi-profile write.

    Register-GraphTenant acquires the store lock per call, so a caller importing several
    profiles cannot hold an outer lock without deadlocking against it. Snapshot-and-restore
    is the alternative, and it carries one honest caveat: another process could have written
    the store between the snapshot and the restore, and blindly restoring would discard that
    work. So the restore refuses when it sees a store it does not recognise, and says so.
    A refused rollback leaves a partial import, which is bad - but silently destroying
    another process's profiles is worse, and only one of the two is recoverable by hand.
#>

function Restore-GraphProfileStoreSnapshot {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $StorePath,

        [AllowNull()]
        [byte[]] $Snapshot,

        [Parameter(Mandatory)]
        [bool] $HadStore
    )

    try {
        if (-not $HadStore) {
            # There was no store before the import, so removing what the import created
            # restores the original state exactly.
            if (Test-Path -LiteralPath $StorePath -PathType Leaf) {
                Remove-Item -LiteralPath $StorePath -Force -ErrorAction Stop
            }
            return 'Rollback complete: the profile store did not exist before the import and was removed.'
        }

        [System.IO.File]::WriteAllBytes($StorePath, $Snapshot)
        return 'Rollback complete: the profile store was restored to its pre-import contents.'
    }
    catch {
        return "ROLLBACK FAILED - the profile store at '$StorePath' may contain a partial import and must be repaired by hand: $($_.Exception.Message). The pre-import copy is in '$StorePath.bak' if Save-GraphProfileStore wrote one."
    }
}
