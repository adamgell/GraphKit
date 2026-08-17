<#
    .SYNOPSIS
        Executes a Microsoft Graph batch request and returns one ordered result per subrequest.

    .DESCRIPTION
        Sends a single batch request to the Graph $batch endpoint and returns one
        GraphKit.OperationResult envelope per original subrequest, in submission order. v1 batching
        is read-only by default: a write subrequest is rejected unless an operation descriptor with
        ReplayPolicy Safe proves it replayable. Dependency failures (424) are reported against the
        dependent subrequest with the blocking id recorded. Only failed, retryable, Safe subrequests
        are replayed (after the longest applicable delay); successful write subrequests are never
        replayed, and the whole batch is never replayed after an ambiguous transport failure unless
        every subrequest is Safe.

    .EXAMPLE
        Invoke-GraphBatch -ProfileId contoso -Requests @(
            @{ Id = '1'; Method = 'GET'; Uri = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices' },
            @{ Id = '2'; Method = 'GET'; Uri = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$top=10' }
        )

        Issues both managed-device reads in a single batch call and returns two ordered envelopes.

    .EXAMPLE
        Invoke-GraphBatch -Context $context -Requests @(
            @{ Id = '1'; Method = 'GET'; Uri = 'https://graph.microsoft.com/v1.0/me' }
        )

        Returns one envelope for the single read subrequest, proving the batch path and envelope shape.

    .PARAMETER Context
        The immutable GraphKit context owning the token source. Mutually exclusive with -ProfileId;
        supply exactly one.

    .PARAMETER ProfileId
        The canonical profile identifier to resolve into a context via Get-GraphContext. Mutually
        exclusive with -Context; supply exactly one.

    .PARAMETER Requests
        An array of subrequest hashtables, each with Id, Method, Uri and optional Headers, Body,
        DependsOn, Type and Operation. Write subrequests (anything but GET/HEAD) must also supply
        Type and Operation naming a descriptor whose ReplayPolicy is Safe.

    .PARAMETER MaxRetryWaves
        The maximum number of retry waves for failed, retryable, Safe subrequests. Each wave re-sends
        only the still-failed Safe subrequests after the longest applicable Retry-After delay.

    .PARAMETER DelayScript
        A scriptblock invoked with -Seconds to wait between retry waves. Inject a no-op during
        testing; the default calls Start-Sleep.
#>
function Invoke-GraphBatch {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]], [object[]])]
    param(
        [Parameter()]
        [PSCustomObject] $Context,

        [Parameter()]
        [string] $ProfileId,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Requests,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int] $MaxRetryWaves = 1,

        [Parameter()]
        [scriptblock] $DelayScript = { param([int] $Seconds) Start-Sleep -Seconds $Seconds }
    )

    # 1. Resolve the context.
    if ($null -ne $Context -and $PSBoundParameters.ContainsKey('ProfileId')) {
        throw 'Provide either -Context or -ProfileId, not both.'
    }

    if ($null -eq $Context) {
        if (-not $PSBoundParameters.ContainsKey('ProfileId') -or [string]::IsNullOrWhiteSpace($ProfileId)) {
            throw 'Provide either -Context or -ProfileId.'
        }

        $Context = Get-GraphContext -ProfileId $ProfileId
    }

    # 2. Validate and normalize subrequests.
    $normalized = [System.Collections.Generic.List[object]]::new()
    $seenIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $hasWrite = $false

    foreach ($item in $Requests) {
        $id = [string] $item.Id
        if ([string]::IsNullOrWhiteSpace($id)) {
            throw 'Each batch subrequest requires an Id.'
        }

        if (-not $seenIds.Add($id)) {
            throw "Duplicate batch subrequest Id '$id'."
        }

        $method = ([string] $item.Method).ToUpperInvariant()
        if ($method -notin @('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE')) {
            throw "Batch subrequest '$id' has unsupported method '$method'."
        }

        $uri = [uri] $item.Uri
        if ($null -eq $uri -or -not $uri.IsAbsoluteUri) {
            throw "Batch subrequest '$id' requires an absolute Uri."
        }

        $replaySafe = $false
        $descriptor = $null

        if ($method -in @('GET', 'HEAD')) {
            $replaySafe = $true
        } else {
            $hasWrite = $true

            if ([string]::IsNullOrWhiteSpace([string] $item.Type) -or [string]::IsNullOrWhiteSpace([string] $item.Operation)) {
                throw "Batch subrequest '$id' is a write ($method) and requires Type and Operation naming a descriptor whose ReplayPolicy is Safe."
            }

            $descriptor = Get-GraphOperation -Type $item.Type -Operation $item.Operation
            if ($descriptor.ReplayPolicy -ne 'Safe') {
                throw "Batch subrequest '$id' is a write ($method) whose descriptor ReplayPolicy is '$($descriptor.ReplayPolicy)'; only Safe writes may be batched."
            }

            # The named descriptor must MATCH the request actually being sent. Checking only the
            # descriptor's ReplayPolicy made the guard forgeable: Method and Uri came from the
            # caller and were forwarded verbatim, so naming any Safe read descriptor let an
            # arbitrary verb reach an arbitrary Graph URL. Demonstrated -
            #
            #     Method='POST'  Uri='.../managedDevices/{id}/wipe'
            #     Type='ManagedDevice'  Operation='List'      <- Safe read
            #
            # passed the guard and put a device wipe in the batch body. Every Safe descriptor in
            # the catalog was a skeleton key, and the guard stopped only callers who told the
            # truth about what they were sending.
            $declaredMethod = ([string] $descriptor.Method).ToUpperInvariant()
            if ($declaredMethod -ne $method) {
                throw "Batch subrequest '$id' declares '$($item.Type)/$($item.Operation)', whose method is $declaredMethod, but sends $method. The descriptor must match the request."
            }

            # Compare the PATH SHAPE, not the literal path: the template carries {tokens} that the
            # caller has already substituted. Turning the template into an anchored regex means a
            # subrequest must target the endpoint its descriptor actually describes, while any id
            # is still accepted. [^/]+ so a token cannot span a segment boundary and reach a
            # different endpoint.
            $templatePath = ([string] $descriptor.PathTemplate) -replace '\?.*$', ''
            $pattern = '^' + ([regex]::Escape($templatePath) -replace '\\\{[^{}]+\\\}', '[^/]+') + '/?$'
            $actualPath = $uri.AbsolutePath -replace '^/(v1\.0|beta)', ''
            if ($actualPath -notmatch $pattern) {
                throw "Batch subrequest '$id' targets '$actualPath', which does not match the path template '$templatePath' of the descriptor it declares ('$($item.Type)/$($item.Operation)')."
            }

            $replaySafe = $true
        }

        $dependsOn = @()
        if ($null -ne $item.DependsOn) {
            $dependsOn = @($item.DependsOn | ForEach-Object { [string] $_ })
        }

        $normalized.Add([PSCustomObject]@{
                Id         = $id
                Method     = $method
                Uri        = $uri
                Headers    = if ($null -ne $item.Headers) { $item.Headers } else { @{} }
                Body       = $item.Body
                DependsOn  = $dependsOn
                ReplaySafe = $replaySafe
                Descriptor = $descriptor
            })
    }

    # 3. Validate dependency references point at real subrequest ids.
    foreach ($sub in $normalized) {
        foreach ($depId in $sub.DependsOn) {
            if (-not $seenIds.Contains($depId)) {
                throw "Batch subrequest '$($sub.Id)' depends on unknown id '$depId'."
            }
        }
    }

    # 4. Batch endpoint and transport. The batch POST is replay-safe only when every subrequest is
    #    Safe, which validation guarantees in v1.
    $batchUri = [uri] ('{0}/v1.0/$batch' -f $Context.GraphBaseUri.AbsoluteUri.TrimEnd('/'))

    $allSafe = -not $hasWrite -or (($normalized | Where-Object { -not $_.ReplaySafe }).Count -eq 0)

    $batchDescriptor = @{
        CredentialPolicy = 'GraphBearer'
        AllowedHosts     = @()
        ReplayPolicy     = if ($allSafe) { 'Safe' } else { 'NeverReplay' }
        Type             = '$batch'
        Operation        = 'Batch'
        ResourceFamily   = 'Graph.Batch'
        ThrottleClass    = if ($hasWrite) { 'Write' } else { 'Read' }
    }

    $transport = {
        param(
            [uri] $Uri,
            [string] $Method,
            [hashtable] $Headers,
            $Body,
            [System.Threading.CancellationToken] $CancellationToken
        )

        $null = Test-GraphCredentialPolicy -Uri $Uri -Descriptor $batchDescriptor -Context $Context

        Invoke-GraphRetry `
            -Context $Context `
            -Descriptor $batchDescriptor `
            -Uri $Uri `
            -Method $Method `
            -Headers $Headers `
            -Body $Body `
            -CancellationToken $CancellationToken
    }

    $batchHeaders = @{ 'Content-Type' = 'application/json' }

    # 5. Send the batch and retry failed retryable Safe subrequests across bounded waves.
    $envelopesById = @{}
    $pending = @($normalized)
    $finalProvenance = $null

    for ($wave = 0; $wave -le $MaxRetryWaves -and $pending.Count -gt 0; $wave++) {
        $batchBody = ConvertTo-GraphBatchBody -Subrequests $pending
        $bodyJson = $batchBody | ConvertTo-Json -Depth 12 -Compress

        $batchResult = & $transport -Uri $batchUri -Method 'POST' -Headers $batchHeaders -Body $bodyJson -CancellationToken ([System.Threading.CancellationToken]::None)

        if ($null -eq $finalProvenance) {
            $finalProvenance = $batchResult.Provenance
        }

        # Whole-batch failure (transport error or non-2xx batch response): every subrequest in this
        # wave carries the batch outcome. No per-subrequest response exists to disaggregate.
        if ($null -eq $batchResult -or $batchResult.Outcome -ne 'Succeeded') {
            foreach ($sub in $pending) {
                $envelopesById[$sub.Id] = New-GraphBatchEnvelope `
                    -Subrequest $sub `
                    -Outcome ($batchResult.Outcome) `
                    -Certainty ($batchResult.Certainty) `
                    -Data @() `
                    -StatusCode $null `
                    -Telemetry $batchResult.Telemetry `
                    -Provenance $finalProvenance `
                    -BlockedById @()
            }

            $pending = @()
            continue
        }

        # Parse per-subrequest responses.
        $responseById = ConvertTo-GraphBatchResponseMap -Data $batchResult.Data

        $nextPending = [System.Collections.Generic.List[object]]::new()
        $retryDelays = [System.Collections.Generic.List[int]]::new()

        foreach ($sub in $pending) {
            $response = $responseById[$sub.Id]

            if ($null -eq $response) {
                # The batch omitted a response for this subrequest: surface it as indeterminate.
                $envelopesById[$sub.Id] = New-GraphBatchEnvelope `
                    -Subrequest $sub `
                    -Outcome 'Failed' `
                    -Certainty 'Indeterminate' `
                    -Data @() `
                    -StatusCode $null `
                    -Telemetry $batchResult.Telemetry `
                    -Provenance $finalProvenance `
                    -BlockedById @()
                continue
            }

            $status = [int] $response['status']
            $responseBody = if ($response.ContainsKey('body')) { $response['body'] } else { $null }
            $responseHeaders = if ($response.ContainsKey('headers')) { $response['headers'] } else { @{} }

            if ($status -ge 200 -and $status -lt 300) {
                $envelopesById[$sub.Id] = New-GraphBatchEnvelope `
                    -Subrequest $sub `
                    -Outcome 'Succeeded' `
                    -Certainty 'Known' `
                    -Data $responseBody `
                    -StatusCode $status `
                    -Telemetry $batchResult.Telemetry `
                    -Provenance $finalProvenance `
                    -BlockedById @()
                continue
            }

            if ($status -eq 424) {
                $blocking = Get-GraphBlockingId -Subrequest $sub -ResponseById $responseById
                $envelopesById[$sub.Id] = New-GraphBatchEnvelope `
                    -Subrequest $sub `
                    -Outcome 'Failed' `
                    -Certainty 'Known' `
                    -Data $responseBody `
                    -StatusCode $status `
                    -Telemetry $batchResult.Telemetry `
                    -Provenance $finalProvenance `
                    -BlockedById $blocking
                continue
            }

            # Retryable transient failure on a Safe subrequest -> retry in a later wave. Successful
            # write subrequests already returned above and are never replayed.
            if ($sub.ReplaySafe -and $status -in @(408, 429, 500, 502, 503, 504)) {
                $nextPending.Add($sub)
                $retryDelays.Add((Get-GraphSubrequestRetryAfter -Headers $responseHeaders))
                continue
            }

            $envelopesById[$sub.Id] = New-GraphBatchEnvelope `
                -Subrequest $sub `
                -Outcome 'Failed' `
                -Certainty 'Known' `
                -Data $responseBody `
                -StatusCode $status `
                -Telemetry $batchResult.Telemetry `
                -Provenance $finalProvenance `
                -BlockedById @()
        }

        $pending = @($nextPending)

        if ($pending.Count -gt 0 -and $wave -lt $MaxRetryWaves -and $retryDelays.Count -gt 0) {
            $longestDelay = ($retryDelays | Measure-Object -Maximum).Maximum
            if ($longestDelay -gt 0) {
                & $DelayScript -Seconds $longestDelay
            }
        }
    }

    # Any subrequests still pending after the retry budget are surfaced as indeterminate failures.
    foreach ($sub in $pending) {
        $envelopesById[$sub.Id] = New-GraphBatchEnvelope `
            -Subrequest $sub `
            -Outcome 'Failed' `
            -Certainty 'Indeterminate' `
            -Data @() `
            -StatusCode $null `
            -Telemetry @() `
            -Provenance $finalProvenance `
            -BlockedById @()
    }

    # 6. Return ordered envelopes matching submission order.
    $ordered = [System.Collections.Generic.List[object]]::new()
    foreach ($sub in $normalized) {
        $ordered.Add($envelopesById[$sub.Id])
    }

    return @($ordered)
}
