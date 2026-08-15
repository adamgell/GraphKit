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

    # 3. Collect and validate query options. Only keys prefixed with '$' are query options; every
    #    other parameter (path token already consumed, Body for actions, etc.) is ignored here and
    #    consumed by its own stage of the pipeline.
    $queryParts = [System.Collections.Generic.List[string]]::new()
    foreach ($parameterName in $Parameters.Keys) {
        if (-not $parameterName.StartsWith('$')) {
            continue
        }

        $parameterValue = $Parameters[$parameterName]
        if ($null -eq $parameterValue) {
            continue
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

    # 4. Assemble the absolute URI.
    $baseString = $BaseUri.AbsoluteUri.TrimEnd('/')
    $queryString = if ($queryParts.Count -gt 0) { '?' + ($queryParts -join '&') } else { '' }

    return [uri] ('{0}{1}{2}' -f $baseString, $path, $queryString)
}
