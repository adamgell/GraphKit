<#
    Private: verify that a candidate path resolves beneath a root directory.

    Path containment is verified, never assumed. Both paths are canonicalized
    lexically ('.', '..', redundant separators, and an absolute path all resolve
    to an absolute path even when the target does not yet exist) and compared
    ordinally after trailing-separator normalization, so a '../' escape or an
    absolute path outside the root cannot slip through. Every evidence write in
    GraphKit calls this before touching the filesystem.
#>
function Test-GraphPathContainment {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowEmptyString()]
        [string] $Root,

        [Parameter(Mandatory, Position = 1)]
        [AllowEmptyString()]
        [string] $Candidate
    )

    if ([string]::IsNullOrWhiteSpace($Root) -or [string]::IsNullOrWhiteSpace($Candidate)) {
        return $false
    }

    $sep = [System.IO.Path]::DirectorySeparatorChar
    $altSep = [System.IO.Path]::AltDirectorySeparatorChar

    # GetFullPath resolves '.', '..', and separators lexically without requiring
    # the path to exist, so a candidate that has not been created yet is still
    # normalized against the same rules the filesystem will apply on write.
    $rootFull = [System.IO.Path]::GetFullPath($Root)
    $candidateFull = [System.IO.Path]::GetFullPath($Candidate)

    $rootTrimmed = $rootFull.TrimEnd($sep, $altSep)
    $candidateTrimmed = $candidateFull.TrimEnd($sep, $altSep)

    # A candidate equal to the root is contained; otherwise it must sit strictly
    # beneath it (root + separator prefix) on an ordinal, case-sensitive basis.
    if ([string]::Equals($rootTrimmed, $candidateTrimmed, [System.StringComparison]::Ordinal)) {
        return $true
    }

    $prefix = $rootTrimmed + $sep

    return $candidateTrimmed.StartsWith($prefix, [System.StringComparison]::Ordinal)
}
