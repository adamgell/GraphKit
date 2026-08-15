<#
    .SYNOPSIS
        Executes a paginated Graph collection request, honouring the spec paging rules.

    .DESCRIPTION
        Pages through an @odata.nextLink chain: each nextLink is treated as opaque but validated
        through the nextLink authority guard before any token is attached. Required paging headers
        are repeated on every page. An empty page that still carries a nextLink continues (per the
        documented service issue). Optional deduplication by a stable ID key removes duplicates
        without relying on the service. A configurable page cap prevents runaway pagination.
        Each page is retried through the supplied transport delegate, and per-page telemetry is
        accumulated into the final result.
#>
function Invoke-GraphPaging {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject] $Context,

        [Parameter(Mandatory)]
        [hashtable] $Descriptor,

        [Parameter(Mandatory)]
        [uri] $FirstPageUri,

        [Parameter(Mandatory)]
        [scriptblock] $RequestFactoryScript,

        [Parameter(Mandatory)]
        [scriptblock] $TransportScript,

        [Parameter()]
        [ValidateRange(1, 2000)]
        [int] $MaxPages = 200
    )

    $allData = [System.Collections.Generic.List[object]]::new()
    $allTelemetry = [System.Collections.Generic.List[object]]::new()
    $seenIds = $null
    if ($Descriptor.DeduplicationKey) {
        $seenIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    }

    $nextLink = $FirstPageUri
    $pageCount = 0

    while ($nextLink -and $pageCount -lt $MaxPages) {
        $pageCount++

        # Validate the nextLink authority before attaching a bearer token. The link is opaque
        # (may have been redirected or replayed) and must never receive a credential on a
        # hostile authority.
        $null = Test-GraphNextLinkAuthority -NextLink $nextLink -Context $Context

        # Build the page request. The factory may repeat RequiredPagingHeaders.
        $request = & $RequestFactoryScript -Uri $nextLink -Descriptor $Descriptor

        # Execute with retry via the transport delegate.
        $pageResult = & $TransportScript `
            -Uri $request.Uri `
            -Method $request.Method `
            -Headers $request.Headers `
            -Body $request.Body

        if ($null -eq $pageResult) {
            throw "Transport delegate returned null for page $pageCount; expected a GraphKit.OperationResult."
        }

        # Collect per-page telemetry.
        if ($pageResult.Telemetry) {
            @($pageResult.Telemetry).ForEach{ $allTelemetry.Add($_) }
        }

        # A non-success outcome stops pagination.
        if ($pageResult.Outcome -ne 'Succeeded') {
            $allData = @($allData)
            $allTelemetry = @($allTelemetry)
            return [PSCustomObject]@{
                PSTypeName = 'GraphKit.OperationResult'
                Data       = $allData
                Outcome    = $pageResult.Outcome
                Certainty  = $pageResult.Certainty
                Telemetry  = $allTelemetry
                Provenance = $pageResult.Provenance
            }
        }

        # Collect rows from this page. Data is the parsed response body; for collections it is a
        # hashtable or PSCustomObject with a 'value' array and an '@odata.nextLink' property.
        $pageData = $pageResult.Data
        $pageRows = @()
        if ($pageData -is [System.Collections.IDictionary] -and $pageData.ContainsKey('value')) {
            $pageRows = @($pageData['value'])
        } elseif ($pageData -is [PSCustomObject] -and (Get-Member -InputObject $pageData -Name 'value' -MemberType Properties)) {
            $pageRows = @($pageData.value)
        } elseif ($null -ne $pageData) {
            # Single-object response or unexpected shape; treat the whole thing as one row.
            $pageRows = @($pageData)
        }

        # Apply deduplication by stable key when the descriptor specifies one.
        if ($null -ne $seenIds) {
            $dedupKey = $Descriptor.DeduplicationKey
            foreach ($row in $pageRows) {
                # Resolve the dedup key: if the row is a dictionary, index it; if a PSCustomObject,
                # dot-access it.
                $keyValue = if ($row -is [System.Collections.IDictionary]) {
                    $row[$dedupKey]
                } elseif ($null -ne $row) {
                    $row.$dedupKey
                } else {
                    $null
                }

                if ($null -ne $keyValue) {
                    if ($seenIds.Add([string] $keyValue)) {
                        $allData.Add($row)
                    }
                } else {
                    # No dedup key on this row; cannot dedup, so keep it.
                    $allData.Add($row)
                }
            }
        } else {
            $pageRows.ForEach{ $allData.Add($_) }
        }


        # Extract nextLink. The link is opaque; we do not parse or modify it.
        $nextLink = $null
        if ($pageData -is [System.Collections.IDictionary] -and $pageData.ContainsKey('@odata.nextLink')) {
            $nextLink = $pageData['@odata.nextLink']
        } elseif ($pageData -is [PSCustomObject] -and (Get-Member -InputObject $pageData -Name '@odata.nextLink' -MemberType Properties)) {
            $nextLink = $pageData.'@odata.nextLink'
        }

        if ($nextLink) {
            try {
                $nextLink = [uri] $nextLink
            } catch {
                throw "Invalid @odata.nextLink on page $($pageCount): $_"
            }
        }
    }

    # A page cap that is hit must be carried BY THE ENVELOPE, not only by a warning.
    # This previously returned Outcome 'Succeeded' + Certainty 'Known' with a
    # Write-Warning, so a programmatic consumer - the entire reason the envelope
    # exists - could not tell the collection was truncated, and the warning
    # disappears entirely under $WarningPreference = 'SilentlyContinue' or when the
    # pipeline is captured. Silent truncation reads as "covered everything" when it
    # did not, and Certainty exists precisely to say otherwise.
    $truncated = ($pageCount -ge $MaxPages -and $null -ne $nextLink)

    if ($truncated) {
        Write-Warning "Paging reached the page cap ($MaxPages); remaining pages were not fetched."
    }

    return [PSCustomObject]@{
        PSTypeName = 'GraphKit.OperationResult'
        Data       = @($allData)
        Outcome    = 'Succeeded'
        # The pages that were fetched are known-good; what is NOT known is whether the
        # collection is complete, which is what Indeterminate records here.
        Certainty  = $(if ($truncated) { 'Indeterminate' } else { 'Known' })
        Truncated  = $truncated
        PageCount  = $pageCount
        Telemetry  = @($allTelemetry)
        Provenance = $null
    }
}
