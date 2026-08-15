<#
    Private: build the vault-evidence summary DTO from a declared field set.

    Evidence pages are summaries built from an ALLOWLIST, never filtered by a
    denylist. Raw Graph objects must not reach the writer, so this builder
    accepts a field hashtable and REJECTS any field name that is not on the
    declared allowlist - a new Graph property therefore cannot silently appear
    in evidence. A second, independent assertion refuses field names that match
    credential patterns (tenant id, client id, secret, token, bearer) - belt
    and braces, not the primary control.
#>
function New-GraphEvidenceSummary {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Fields
    )

    # Credential assertion runs first so both independent checks are reachable:
    # a credential-named field is refused here, while any other unknown field is
    # refused by the allowlist below.
    $credentialPattern = '(?i)(tenant\s*id|client\s*id|secret|token|bearer|password|authorization|credential)'

    foreach ($key in @($Fields.Keys)) {
        if ("$key" -match $credentialPattern) {
            throw "Evidence summary field name '$key' matches a credential pattern and is refused; evidence pages must never carry credential material."
        }
    }

    $allowlist = @(
        'ProfileId'
        'Name'
        'Kind'
        'GeneratedUtc'
        'SourcePaths'
        'Counts'
        'Notes'
    )

    foreach ($key in @($Fields.Keys)) {
        if ($key -notin $allowlist) {
            throw "Evidence summary field '$key' is not on the declared allowlist. Evidence pages are built from a fixed field set; unknown fields are rejected, never dropped."
        }
    }

    if ([string]::IsNullOrWhiteSpace([string] $Fields['ProfileId'])) {
        throw 'Evidence summary requires a non-empty ProfileId; it is the only value ever used to build evidence paths.'
    }

    $sourcePaths = if ($null -eq $Fields['SourcePaths']) { @() } else { @($Fields['SourcePaths']) }
    $counts = if ($null -eq $Fields['Counts']) { @{} } else { $Fields['Counts'] }
    $notes = if ($null -eq $Fields['Notes']) { @() } else { @($Fields['Notes']) }

    # The allowlist above constrains top-level field NAMES. Counts and Notes are the
    # two containers whose contents a caller controls, so they are constrained too -
    # otherwise the allowlist stops at depth 1 and PII or a credential reaches the
    # page inside a value rather than as a field. The name-pattern check above
    # inspects names only and cannot see a secret carried in a value.
    #
    # Counts is a name -> integer rollup, which is what "summaries with counts, not
    # rows" means. A non-integer value is a row in disguise and is refused.
    foreach ($countKey in @($counts.Keys)) {
        if ("$countKey" -match $credentialPattern) {
            throw "Evidence 'Counts' key '$countKey' matches a credential pattern and is refused."
        }

        $countValue = $counts[$countKey]
        if ($countValue -isnot [int] -and $countValue -isnot [long] -and $countValue -isnot [double]) {
            throw (
                "Evidence 'Counts' entry '$countKey' must be numeric; got " +
                "'$($countValue.GetType().Name)'. Counts carries rollups, never rows or identifiers."
            )
        }
    }

    # Notes is free text by design, so it cannot be shape-constrained. It IS scanned
    # for credential material, because a bearer token pasted into a note would
    # otherwise pass every other check in this function.
    foreach ($note in $notes) {
        $noteText = [string] $note
        if ($noteText -match '(?i)\b(eyJ[A-Za-z0-9_\-]{10,}|bearer\s+\S{10,})') {
            throw 'An evidence note appears to contain a bearer token and is refused.'
        }
        if ($noteText -match $credentialPattern) {
            throw "An evidence note matches a credential pattern ('$($Matches[0])') and is refused. Notes are summaries, not credential material."
        }
    }

    $summary = [pscustomobject] [ordered] @{
        ProfileId    = [string] $Fields['ProfileId']
        Name         = [string] $Fields['Name']
        Kind         = [string] $Fields['Kind']
        GeneratedUtc = $Fields['GeneratedUtc']
        SourcePaths  = $sourcePaths
        Counts       = $counts
        Notes        = $notes
    }

    $summary.PSObject.TypeNames.Insert(0, 'GraphKit.EvidenceSummary')

    return $summary
}
