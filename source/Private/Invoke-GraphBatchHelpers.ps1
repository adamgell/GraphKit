<#
    Builds the Graph $batch request body for the supplied subrequests, using the relative-path url
    form Graph expects ('/v1.0/...').
#>
function ConvertTo-GraphBatchBody {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Subrequests)

    $graphRequests = [System.Collections.Generic.List[object]]::new()

    foreach ($sub in $Subrequests) {
        $url = $sub.Uri.AbsolutePath
        if ($sub.Uri.Query) {
            $url += $sub.Uri.Query
        }

        $graphRequest = @{
            id     = $sub.Id
            method = $sub.Method
            url    = $url
            headers = $sub.Headers
        }

        if ($sub.DependsOn.Count -gt 0) {
            $graphRequest['dependsOn'] = @($sub.DependsOn)
        }

        if ($null -ne $sub.Body) {
            $graphRequest['body'] = $sub.Body
        }

        $graphRequests.Add($graphRequest)
    }

    return @{ requests = @($graphRequests) }
}

<#
    Normalizes the parsed batch response Data (hashtable or PSCustomObject) into a map of
    subrequest id -> response.
#>
function ConvertTo-GraphBatchResponseMap {
    [CmdletBinding()]
    param([AllowNull()] $Data)

    $map = @{}

    $data = $Data
    if ($data -is [string]) {
        $data = $data | ConvertFrom-Json -AsHashtable
    }

    $responses = @()
    if ($data -is [System.Collections.IDictionary] -and $data.ContainsKey('responses')) {
        $responses = @($data['responses'])
    } elseif ($null -ne $data -and $data.PSObject.Properties['responses']) {
        $responses = @($data.responses)
    }

    foreach ($response in $responses) {
        $responseId = if ($response -is [System.Collections.IDictionary]) { [string] $response['id'] } else { [string] $response.id }
        if ($null -ne $responseId -and '' -ne $responseId) {
            $map[$responseId] = $response
        }
    }

    return $map
}

<#
    Builds one GraphKit.OperationResult envelope for a batch subrequest, recording the subrequest id
    and (for 424) the blocking ids.
#>
function New-GraphBatchEnvelope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Subrequest,
        [Parameter(Mandatory)] [string] $Outcome,
        [Parameter(Mandatory)] [string] $Certainty,
        [AllowNull()] $Data,
        [AllowNull()] [int] $StatusCode,
        [AllowNull()] [object[]] $Telemetry,
        [AllowNull()] [hashtable] $Provenance,
        [AllowNull()] [string[]] $BlockedById
    )

    return [PSCustomObject]@{
        PSTypeName  = 'GraphKit.OperationResult'
        Id          = $Subrequest.Id
        Data        = $Data
        Outcome     = $Outcome
        Certainty   = $Certainty
        Telemetry   = @($Telemetry)
        Provenance  = $Provenance
        StatusCode  = $StatusCode
        BlockedById = @($BlockedById)
    }
}

<#
    Determines which dependency ids blocked a 424 subrequest by checking which of its dependsOn
    ids failed (non-2xx). Falls back to the declared dependencies when none can be determined.
#>
function Get-GraphBlockingId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Subrequest,
        [Parameter(Mandatory)] [hashtable] $ResponseById
    )

    $blocking = [System.Collections.Generic.List[string]]::new()

    foreach ($depId in $Subrequest.DependsOn) {
        if (-not $ResponseById.ContainsKey($depId)) {
            continue
        }

        $depResponse = $ResponseById[$depId]
        $depStatus = if ($depResponse -is [System.Collections.IDictionary]) { [int] $depResponse['status'] } else { [int] $depResponse.status }

        if ($depStatus -lt 200 -or $depStatus -ge 300) {
            $blocking.Add($depId)
        }
    }

    if ($blocking.Count -eq 0 -and $Subrequest.DependsOn.Count -gt 0) {
        $blocking.AddRange([string[]] @($Subrequest.DependsOn))
    }

    return @($blocking)
}

<#
    Extracts the Retry-After delta-seconds from a subrequest response's headers, clamped to
    non-negative. Returns 0 when absent or malformed.
#>
function Get-GraphSubrequestRetryAfter {
    [CmdletBinding()]
    [OutputType([int])]
    param([AllowNull()] $Headers)

    $raw = $null
    if ($Headers -is [System.Collections.IDictionary] -and $Headers.ContainsKey('Retry-After')) {
        $raw = $Headers['Retry-After']
    } elseif ($null -ne $Headers -and $Headers.PSObject.Properties['Retry-After']) {
        $raw = $Headers.'Retry-After'
    }

    $xmsRaw = $null
    if ($Headers -is [System.Collections.IDictionary] -and $Headers.ContainsKey('x-ms-retry-after-ms')) {
        $xmsRaw = $Headers['x-ms-retry-after-ms']
    } elseif ($null -ne $Headers -and $Headers.PSObject.Properties['x-ms-retry-after-ms']) {
        $xmsRaw = $Headers.'x-ms-retry-after-ms'
    }

    $dateRaw = $null
    if ($Headers -is [System.Collections.IDictionary] -and $Headers.ContainsKey('Date')) {
        $dateRaw = $Headers['Date']
    } elseif ($null -ne $Headers -and $Headers.PSObject.Properties['Date']) {
        $dateRaw = $Headers.'Date'
    }

    if ($null -eq $raw -and $null -eq $xmsRaw) {
        return 0
    }

    # Route through the same hostile parser the outer response uses. An earlier form
    # here was a bare [int]::TryParse, so an inner subrequest carrying an HTTP-date,
    # the malformed "30,120" comma form, or x-ms-retry-after-ms yielded 0 seconds -
    # i.e. no delay at all before the failed subrequest was retried. Graph's own
    # guidance is that batch throttling is read from the INNER response, which makes
    # this the one place the parser must not be weaker.
    $responseDate = $null
    if ($null -ne $dateRaw) {
        $parsedDate = [datetime]::MinValue
        if ([datetime]::TryParse(
                [string] $dateRaw,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal,
                [ref] $parsedDate)) {
            $responseDate = $parsedDate
        }
    }

    $delay = Get-GraphRetryDelay -RetryAfterValues $raw -XmsRetryAfterMs $xmsRaw -ResponseDate $responseDate

    return [int] [Math]::Ceiling([double] $delay.DelaySeconds)
}
