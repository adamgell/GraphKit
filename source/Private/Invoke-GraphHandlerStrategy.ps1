<#
    .SYNOPSIS
        Executes an operation through its registered handler strategy.

    .DESCRIPTION
        The operation catalog describes each operation; the handler strategy registry decides how
        it runs. This command resolves the descriptor's HandlerStrategyId to its registered
        implementation and invokes it with the context, descriptor, parameters and the injected
        transport delegate. Reconciliation strategies additionally receive the intended state. The
        four v1 strategies are registered here at import (idempotently).

    .NOTES
        Strategy handlers use only the injected transport delegate; they never call
        Invoke-GraphRetry directly, so the retry engine remains the sole replay owner.
#>
function Invoke-GraphHandlerStrategy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject] $Context,

        [Parameter(Mandatory)]
        [hashtable] $Descriptor,

        [Parameter(Mandatory)]
        [hashtable] $Parameters,

        [Parameter(Mandatory)]
        [scriptblock] $Transport,

        [Parameter()]
        $IntendedState
    )

    Ensure-GraphV1StrategiesRegistered

    $handler = Resolve-GraphHandlerStrategy -Id $Descriptor.HandlerStrategyId

    if ($PSBoundParameters.ContainsKey('IntendedState')) {
        return & $handler -Context $Context -Descriptor $Descriptor -Parameters $Parameters -Transport $Transport -IntendedState $IntendedState
    }

    return & $handler -Context $Context -Descriptor $Descriptor -Parameters $Parameters -Transport $Transport
}

<#
    Builds the request headers for an operation from its descriptor and parameters. The
    ConsistencyLevel header is emitted only when the descriptor declares advanced-query support;
    RequiredPagingHeaders are emitted here and repeated per page by the paging loop; a configured
    concurrency header (ETag / If-Match) is taken from the parameters when present.
#>
function Get-GraphRequestHeaders {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Descriptor,

        [Parameter()]
        [hashtable] $Parameters = @{}
    )

    $headers = @{}

    $advancedQuery = $Descriptor.AdvancedQuery
    if (
        $null -ne $advancedQuery -and
        [bool] $advancedQuery.Supported -and
        -not [string]::IsNullOrWhiteSpace([string] $advancedQuery.ConsistencyLevel)
    ) {
        $headers['ConsistencyLevel'] = [string] $advancedQuery.ConsistencyLevel
    }

    foreach ($entry in @($Descriptor.RequiredPagingHeaders)) {
        if ($entry -is [System.Collections.IDictionary] -and $entry.Contains('Name') -and $entry.Contains('Value')) {
            $headers[[string] $entry['Name']] = $entry['Value']
        }
    }

    $concurrency = $Descriptor.Concurrency
    if (
        $null -ne $concurrency -and
        $concurrency.Mode -in @('ETag', 'Header') -and
        -not [string]::IsNullOrWhiteSpace([string] $concurrency.Header)
    ) {
        $headerName = [string] $concurrency.Header
        if ($Parameters.ContainsKey($headerName)) {
            $headers[$headerName] = $Parameters[$headerName]
        } elseif ([bool] $concurrency.Required) {
            throw "Concurrency header '{0}' is required for operation '{1}/{2}' but was not supplied." -f $headerName, $Descriptor.Type, $Descriptor.Operation
        }
    }

    return $headers
}

# --- v1 handler strategies ---------------------------------------------------

$script:CollectionDefaultStrategy = {
    param($Context, $Descriptor, $Parameters, $Transport)

    $baseUri = [uri] ('{0}/{1}' -f $Context.GraphBaseUri.AbsoluteUri.TrimEnd('/'), $Descriptor.ApiVersion)
    $uri = Resolve-GraphUri -Descriptor $Descriptor -Parameters $Parameters -BaseUri $baseUri

    if ($Descriptor.PagingStrategy -eq 'NextLink') {
        $requestFactory = {
            param([uri] $Uri, [hashtable] $Descriptor)

            @{
                Uri     = $Uri
                Method  = $Descriptor.Method
                Headers = Get-GraphRequestHeaders -Descriptor $Descriptor
                Body    = $null
            }
        }

        return Invoke-GraphPaging `
            -Context $Context `
            -Descriptor $Descriptor `
            -FirstPageUri $uri `
            -RequestFactoryScript $requestFactory `
            -TransportScript $Transport
    }

    $headers = Get-GraphRequestHeaders -Descriptor $Descriptor -Parameters $Parameters
    $result = & $Transport -Uri $uri -Method $Descriptor.Method -Headers $headers -Body $null -CancellationToken ([System.Threading.CancellationToken]::None)

    # Normalize a non-paging collection to rows: the parsed body carries a 'value' array plus
    # collection metadata; the public envelope exposes the rows.
    if (
        $null -ne $result -and
        $result.Outcome -eq 'Succeeded' -and
        $result.Data -is [System.Collections.IDictionary] -and
        $result.Data.ContainsKey('value')
    ) {
        $result.Data = @($result.Data['value'])
    }

    return $result
}

$script:ActionDefaultStrategy = {
    param($Context, $Descriptor, $Parameters, $Transport)

    if (-not $Parameters.ContainsKey('Body') -or $null -eq $Parameters['Body']) {
        throw "Action '{0}/{1}' requires a request body; supply it via -Parameters @{{ Body = ... }}." -f $Descriptor.Type, $Descriptor.Operation
    }

    $body = $Parameters['Body']

    $baseUri = [uri] ('{0}/{1}' -f $Context.GraphBaseUri.AbsoluteUri.TrimEnd('/'), $Descriptor.ApiVersion)
    $uri = Resolve-GraphUri -Descriptor $Descriptor -Parameters $Parameters -BaseUri $baseUri
    $headers = Get-GraphRequestHeaders -Descriptor $Descriptor -Parameters $Parameters

    return & $Transport -Uri $uri -Method $Descriptor.Method -Headers $headers -Body $body -CancellationToken ([System.Threading.CancellationToken]::None)
}

$script:ReconciliationStableExternalKeyStrategy = {
    param($Context, $Descriptor, $Parameters, $Transport, $IntendedState)

    # A Reconciliable operation queries its intended result by a stable external key after an
    # ambiguous write; this strategy performs that lookup using ONLY the read delegate. The retry
    # engine consumes the result to decide whether the write committed. $IntendedState is received
    # for the reconciliation decision and is not written by this read-only strategy.
    $reconciliation = $Descriptor.Reconciliation
    if ($null -eq $reconciliation) {
        throw "Descriptor '{0}/{1}' is Reconciliable but declares no Reconciliation block." -f $Descriptor.Type, $Descriptor.Operation
    }

    $stableKey = $reconciliation.StableExternalKey
    if ([string]::IsNullOrWhiteSpace([string] $stableKey)) {
        throw "Reconciliation block on '{0}/{1}' must declare a StableExternalKey." -f $Descriptor.Type, $Descriptor.Operation
    }

    if (-not $Parameters.ContainsKey($stableKey)) {
        throw "Reconciliation requires the stable external key '{0}' in parameters for '{1}/{2}'." -f $stableKey, $Descriptor.Type, $Descriptor.Operation
    }

    $baseUri = [uri] ('{0}/{1}' -f $Context.GraphBaseUri.AbsoluteUri.TrimEnd('/'), $Descriptor.ApiVersion)
    $lookupUri = Resolve-GraphUri -Descriptor $Descriptor -Parameters $Parameters -BaseUri $baseUri
    $headers = Get-GraphRequestHeaders -Descriptor $Descriptor -Parameters $Parameters

    return & $Transport -Uri $lookupUri -Method 'GET' -Headers $headers -Body $null -CancellationToken ([System.Threading.CancellationToken]::None)
}

$script:LongRunningJobPollStatusStrategy = {
    param($Context, $Descriptor, $Parameters, $Transport)

    $baseUri = [uri] ('{0}/{1}' -f $Context.GraphBaseUri.AbsoluteUri.TrimEnd('/'), $Descriptor.ApiVersion)
    $submitUri = Resolve-GraphUri -Descriptor $Descriptor -Parameters $Parameters -BaseUri $baseUri
    $headers = Get-GraphRequestHeaders -Descriptor $Descriptor -Parameters $Parameters
    $body = if ($Parameters.ContainsKey('Body')) { $Parameters['Body'] } else { $null }

    # 1. Submit the job.
    $submitResult = & $Transport -Uri $submitUri -Method $Descriptor.Method -Headers $headers -Body $body -CancellationToken ([System.Threading.CancellationToken]::None)
    if ($null -eq $submitResult -or $submitResult.Outcome -ne 'Succeeded') {
        return $submitResult
    }

    # 2. Resolve the status URI from the submit response body (id -> exportJobs/{id},
    #    statusLocation, or url). A Location header takes precedence when the transport exposes it.
    $jobData = $submitResult.Data
    $statusUri = $null
    if ($submitResult.PSObject.Properties['ResponseHeaders'] -and $submitResult.ResponseHeaders.Location) {
        $statusUri = [uri] $submitResult.ResponseHeaders.Location
    } elseif ($jobData -is [System.Collections.IDictionary]) {
        if ($jobData.Contains('statusLocation') -and $jobData['statusLocation']) {
            $statusUri = [uri] $jobData['statusLocation']
        } elseif ($jobData.Contains('url') -and $jobData['url']) {
            $statusUri = [uri] $jobData['url']
        } elseif ($jobData.Contains('id') -and $jobData['id']) {
            $statusUri = [uri] ('{0}/{1}' -f $submitUri.AbsoluteUri.TrimEnd('/'), [uri]::EscapeDataString([string] $jobData['id']))
        }
    }

    if ($null -eq $statusUri) {
        throw "Long-running job '{0}/{1}' returned no status URI; cannot poll for completion." -f $Descriptor.Type, $Descriptor.Operation
    }

    # 3. Poll until the job reaches a terminal state or the poll budget is exhausted.
    $maxPolls = 100
    $pollCount = 0
    $lastResult = $submitResult
    $reachedTerminal = $false
    $lastStatus = $null

    while ($pollCount -lt $maxPolls) {
        $pollCount++
        $pollHeaders = Get-GraphRequestHeaders -Descriptor $Descriptor -Parameters $Parameters
        $lastResult = & $Transport -Uri $statusUri -Method 'GET' -Headers $pollHeaders -Body $null -CancellationToken ([System.Threading.CancellationToken]::None)

        if ($null -eq $lastResult -or $lastResult.Outcome -ne 'Succeeded') {
            return $lastResult
        }

        $pollData = $lastResult.Data
        $status = $null
        if ($pollData -is [System.Collections.IDictionary] -and $pollData.Contains('status')) {
            $status = [string] $pollData['status']
        } elseif ($null -ne $pollData -and $pollData.PSObject.Properties['status']) {
            $status = [string] $pollData.status
        }

        $lastStatus = $status

        if ($status -in @('completed', 'succeeded', 'failed', 'unknown', 'cancelled')) {
            $reachedTerminal = $true
            break
        }
    }

    # Exhausting the poll budget is NOT completion. This previously fell out of the
    # loop and returned the last in-progress status as though it were the operation's
    # result, so a caller received a job-status object instead of a report with no
    # signal that the job never finished - the same "bounded work reported as
    # complete" failure as a truncated page set. Outcome becomes DeadlineExpired and
    # certainty Indeterminate: the job may well still be running server-side, which is
    # precisely an unknown outcome rather than a failure.
    if (-not $reachedTerminal) {
        $lastResult.Outcome = 'DeadlineExpired'
        $lastResult.Certainty = 'Indeterminate'

        Write-Warning (
            "Long-running job '{0}/{1}' did not reach a terminal status within {2} polls (last status: '{3}'). " -f
                $Descriptor.Type, $Descriptor.Operation, $maxPolls, ([string] $lastStatus)
        )
    }

    return $lastResult
}

# --- registration ------------------------------------------------------------

$script:GraphV1StrategiesRegistered = $false

function Ensure-GraphV1StrategiesRegistered {
    [CmdletBinding()]
    param()

    if ($script:GraphV1StrategiesRegistered) {
        return
    }

    Register-GraphHandlerStrategy -Id 'Collection.Default' -Handler $script:CollectionDefaultStrategy
    Register-GraphHandlerStrategy -Id 'Action.Default' -Handler $script:ActionDefaultStrategy
    Register-GraphHandlerStrategy -Id 'Reconciliation.StableExternalKey' -Handler $script:ReconciliationStableExternalKeyStrategy
    Register-GraphHandlerStrategy -Id 'LongRunningJob.PollStatus' -Handler $script:LongRunningJobPollStatusStrategy

    $script:GraphV1StrategiesRegistered = $true
}

# Register at import when the registry is already available. ModuleBuilder concatenates Private
# files alphabetically, which can place this file before the registry, so the idempotent
# Ensure-GraphV1StrategiesRegistered also runs on first strategy execution to guarantee the four
# strategies are present before any descriptor resolves against them.
if (Get-Command -Name Register-GraphHandlerStrategy -ErrorAction SilentlyContinue) {
    Ensure-GraphV1StrategiesRegistered
}
