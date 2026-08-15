<#
    Per-attempt sanitized telemetry record builder.

    Telemetry is a first-class result object, not verbose text. This builder emits
    one record per attempt containing only support-relevant, non-sensitive fields.
    It never carries bearer tokens, secrets, credentials, PII, raw query values, or
    free-form error messages.

    Query sanitization (design rule 8): parameter NAMES are retained, but only
    explicitly value-safe OData values survive - $top/$skip/$count integer values.
    $filter, $search, and every other caller-supplied value are redacted. A SAS
    signature carried in a query is therefore never recorded.
#>

<#
    Extract the structural Graph error code chain from a normalized body:
    error.code plus the nested innererror.code chain. Free-form messages are
    dropped, and only codes matching a simple token shape (word chars, dot, dash)
    are retained - anything else is treated as free-form and discarded.
#>
function Get-GraphErrorCodeChain {
    param(
        [AllowNull()]
        [object] $Body
    )

    $codes = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $Body) { return @($codes) }

    $current = $null
    if ($Body -is [System.Collections.IDictionary]) {
        $current = $Body['error']
    }
    elseif ($Body -is [pscustomobject]) {
        $errorProp = $Body.PSObject.Properties['error']
        if ($null -ne $errorProp) { $current = $errorProp.Value }
    }

    $guard = 0
    while ($null -ne $current -and $guard -lt 16) {
        $guard++

        $code = $null
        $next = $null
        if ($current -is [System.Collections.IDictionary]) {
            if ($current.Contains('code')) { $code = $current['code'] }
            if ($current.Contains('innererror')) { $next = $current['innererror'] }
        }
        elseif ($current -is [pscustomobject]) {
            if ($null -ne $current.PSObject.Properties['code']) { $code = $current.PSObject.Properties['code'].Value }
            if ($null -ne $current.PSObject.Properties['innererror']) { $next = $current.PSObject.Properties['innererror'].Value }
        }
        else {
            break
        }

        if ($null -ne $code -and $code -is [string] -and $code -match '^[\w.\-]+$') {
            $codes.Add($code)
        }

        $current = $next
    }

    return @($codes)
}

function New-GraphTelemetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [guid] $LogicalOperationId,

        [Parameter(Mandatory = $true)]
        [guid] $ClientRequestId,

        [AllowNull()]
        [string] $ResponseRequestId,

        [AllowNull()]
        [string] $ResponseDate,

        [AllowNull()]
        [string] $XmsAgsDiagnostic,

        [Parameter(Mandatory = $true)]
        [uri] $Uri,

        [Parameter(Mandatory = $true)]
        [int] $Attempt,

        [int] $StatusCode = 0,

        [AllowNull()]
        [double] $DelaySeconds,

        [AllowNull()]
        [string] $DelaySource,

        [AllowNull()]
        [hashtable] $ThrottleState,

        [AllowNull()]
        [string] $BatchSubrequestId,

        [AllowNull()]
        [string] $AttemptOutcome,

        [AllowNull()]
        [string] $AttemptCertainty,

        [AllowNull()]
        [object] $Body
    )

    $sanitizedUri = Get-GraphSanitizedUri -Uri $Uri
    $errorChain = Get-GraphErrorCodeChain -Body $Body

    return [pscustomobject] @{
        LogicalOperationId = $LogicalOperationId
        ClientRequestId    = $ClientRequestId
        ResponseRequestId  = $ResponseRequestId
        ResponseDate       = $ResponseDate
        XmsAgsDiagnostic   = $XmsAgsDiagnostic
        SanitizedUri       = $sanitizedUri
        Attempt            = $Attempt
        StatusCode         = $StatusCode
        DelaySeconds       = $DelaySeconds
        DelaySource        = $DelaySource
        ThrottleState      = $ThrottleState
        BatchSubrequestId  = $BatchSubrequestId
        AttemptOutcome     = $AttemptOutcome
        AttemptCertainty   = $AttemptCertainty
        GraphErrorCode     = $errorChain
    }
}

<#
    Rebuild a URI with query VALUES redacted. Parameter names are kept; only
    $top/$skip/$count integer values are retained verbatim.
#>
function Get-GraphSanitizedUri {
    param(
        [Parameter(Mandatory = $true)]
        [uri] $Uri
    )

    if ([string]::IsNullOrEmpty($Uri.Query)) {
        return $Uri.AbsoluteUri
    }

    $base = $Uri.GetLeftPart([System.UriPartial]::Path)
    $query = $Uri.Query.TrimStart('?')

    $pairs = [System.Collections.Generic.List[string]]::new()
    foreach ($segment in $query -split '&') {
        if ([string]::IsNullOrEmpty($segment)) { continue }

        $idx = $segment.IndexOf('=')
        if ($idx -lt 0) {
            # Bare flag with no value: keep the name only.
            $pairs.Add($segment)
            continue
        }

        $name = $segment.Substring(0, $idx)
        $value = $segment.Substring($idx + 1)

        $safeInt = $name -in @('$top', '$skip', '$count') -and $value -match '^\d+$'
        if ($safeInt) {
            $pairs.Add("$name=$value")
        }
        else {
            $pairs.Add("$name=<redacted>")
        }
    }

    if ($pairs.Count -eq 0) {
        return $base
    }

    return "$base`?$($pairs -join '&')"
}
