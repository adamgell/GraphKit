<#
    Private: validate a canonical profile identifier.

    The ProfileId is the only value ever used to build a filesystem path or to
    select a profile, so it is constrained to a path-safe shape. Display names
    are never valid selectors. The match is case-sensitive (-cmatch) because the
    canonical shape is lowercase-only.
#>

function Test-GraphProfileId {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowEmptyString()]
        [string] $ProfileId
    )

    if ([string]::IsNullOrEmpty($ProfileId)) {
        return $false
    }

    return $ProfileId -cmatch '^[a-z0-9][a-z0-9-]{0,63}$'
}
