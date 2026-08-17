<#
    .SYNOPSIS
        Builds the absolute request URI for an operation from its path template and parameters.

    .DESCRIPTION
        Substitutes '{token}' placeholders in the descriptor's PathTemplate from the supplied
        parameters (a missing token is an actionable error), then attaches OData query options only
        where the descriptor's AdvancedQuery block declares them supported. Query options the
        descriptor does not declare are rejected rather than passed through optimistically, because
        silently-unsupported options are a documented Graph failure mode and a spec violation.

    .NOTES
        ConsistencyLevel is an HTTP header (it belongs on the request, and on the subrequest in
        batch), not a query parameter, so it is surfaced by the caller rather than encoded here.
#>
function Resolve-GraphUri {
    [CmdletBinding()]
    [OutputType([uri])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [hashtable] $Descriptor,

        [Parameter(Mandatory, Position = 1)]
        [hashtable] $Parameters,

        [Parameter(Mandatory, Position = 2)]
        [uri] $BaseUri
    )

    $pathTemplate = [string] $Descriptor.PathTemplate
    if ([string]::IsNullOrWhiteSpace($pathTemplate)) {
        throw "Descriptor for '{0}/{1}' declares no PathTemplate." -f $Descriptor.Type, $Descriptor.Operation
    }

    $path = $pathTemplate

    # 1. Substitute path tokens. Hashtables compare keys case-insensitively, matching how a caller
    #    naturally supplies '{id}' as 'id' or 'Id'.
    $tokenMatches = [regex]::Matches($pathTemplate, '\{([^{}]+)\}')
    foreach ($match in $tokenMatches) {
        $tokenName = $match.Groups[1].Value
        if (-not $Parameters.ContainsKey($tokenName)) {
            throw "Operation '{0}/{1}' requires path parameter '{2}' which was not supplied." -f $Descriptor.Type, $Descriptor.Operation, $tokenName
        }

        $tokenValue = [string] $Parameters[$tokenName]
        if ([string]::IsNullOrEmpty($tokenValue)) {
            throw "Path parameter '{0}' for operation '{1}/{2}' has no value." -f $tokenName, $Descriptor.Type, $Descriptor.Operation
        }

        # A token value must not contain a dot-segment. EscapeDataString does NOT escape '.'
        # (it is RFC 3986 unreserved), and [uri] then COLLAPSES dot-segments, so an id of '..'
        # deletes the segment it was substituted into:
        #
        #     /deviceManagement/deviceConfigurations/{id}   id='..'
        #       -> https://graph.microsoft.com/beta/deviceManagement/
        #
        # A single-item GET silently becomes a COLLECTION GET, so an export scoped to one policy
        # quietly contains every policy in the tenant. Two of these walk past the /beta prefix
        # entirely. Nothing about the response signals the substitution went wrong.
        #
        # The earlier traversal test missed this because it used '../..', where the SLASH gets
        # escaped to %2F and .NET preserves it - so the assertion passed while testing a case
        # that was never vulnerable. A bare '..' has no slash to escape.
        if ($tokenValue -eq '.' -or $tokenValue -eq '..' -or $tokenValue -match '(^|/)\.\.?($|/)') {
            throw "Path parameter '{0}' for operation '{1}/{2}' contains a path segment ('{3}') that would change which resource is addressed." -f $tokenName, $Descriptor.Type, $Descriptor.Operation, $tokenValue
        }

        $path = $path.Replace($match.Value, [uri]::EscapeDataString($tokenValue))
    }

    # 2. Advanced query support. Supported operators come from AllowedOperators; $count is gated on
    #    the Count flag (or an explicit '$count' allowlist entry) so advanced queries only pass when
    #    the descriptor declares them.
    $advancedQuery = $Descriptor.AdvancedQuery
    if ($null -eq $advancedQuery) {
        $advancedQuery = @{ Supported = $false }
    }

    $allowedOperators = @(
        $advancedQuery.AllowedOperators |
            Where-Object { $null -ne $_ -and '' -ne ([string] $_) }
    )
    $countSupported = [bool] $advancedQuery.Count

    # 3. Options already baked into the template. A handful of descriptors carry a load-bearing
    #    query option in PathTemplate because the operation is meaningless without it -
    #    Organization/GetMdmAuthority's $select, the admin-template $expand. Their names are
    #    collected so a caller cannot supply the same option a second time: Graph rejects a
    #    duplicated option, and its error names the option rather than the descriptor that fixed
    #    it, sending the reader to the wrong place.
    #
    #    Read from $path, not $pathTemplate, and only AFTER substitution - which is safe because
    #    EscapeDataString turns a '?' inside a token value into %3F, so no supplied value can
    #    forge a query string here.
    $templateQueryIndex = $path.IndexOf('?')
    $bakedOptionNames = @{}
    if ($templateQueryIndex -ge 0) {
        foreach ($pair in $path.Substring($templateQueryIndex + 1).Split('&')) {
            $bakedName = $pair.Split('=')[0]
            if (-not [string]::IsNullOrEmpty($bakedName)) { $bakedOptionNames[$bakedName] = $true }
        }
    }

    # 4. Collect and validate query options. Only keys prefixed with '$' are query options; every
    #    other parameter (path token already consumed, Body for actions, etc.) is ignored here and
    #    consumed by its own stage of the pipeline.
    $queryParts = [System.Collections.Generic.List[string]]::new()
    foreach ($parameterName in $Parameters.Keys) {
        # Guard the type before calling a string method on it: a hashtable key of 5 threw
        # "[System.Int32] does not contain a method named 'StartsWith'" instead of anything a
        # caller could act on.
        if ($parameterName -isnot [string]) { continue }
        if (-not $parameterName.StartsWith('$')) {
            continue
        }

        $parameterValue = $Parameters[$parameterName]
        if ($null -eq $parameterValue) {
            continue
        }

        if ($bakedOptionNames.ContainsKey($parameterName)) {
            throw (
                "Query option '{0}' is fixed by operation '{1}/{2}' and cannot be supplied again. " +
                'The descriptor bakes it into the path because the operation does not return ' +
                'usable data without it.'
            ) -f $parameterName, $Descriptor.Type, $Descriptor.Operation
        }

        $isCount = ($parameterName -eq '$count')
        $declared = if ($isCount) {
            $countSupported -or ($allowedOperators -contains '$count')
        } else {
            $allowedOperators -contains $parameterName
        }

        if (-not $declared) {
            throw (
                "Query option '{0}' is not supported by operation '{1}/{2}'. " +
                'Refusing to pass through an unsupported query option.'
            ) -f $parameterName, $Descriptor.Type, $Descriptor.Operation
        }

        $queryParts.Add(('{0}={1}' -f $parameterName, [uri]::EscapeDataString([string] $parameterValue)))
    }

    # 5. Assemble the absolute URI. A template that already carries a query must EXTEND it with
    #    '&'. Joining with '?' unconditionally produced 'path?$select=a?$filter=b', which is not
    #    two options: the second '?' becomes part of the first option's value, so the caller's
    #    filter silently does nothing instead of failing loudly.
    $baseString = $BaseUri.AbsoluteUri.TrimEnd('/')
    $queryString = ''
    if ($queryParts.Count -gt 0) {
        $separator = if ($templateQueryIndex -ge 0) { '&' } else { '?' }
        $queryString = $separator + ($queryParts -join '&')
    }

    return [uri] ('{0}{1}{2}' -f $baseString, $path, $queryString)
}
