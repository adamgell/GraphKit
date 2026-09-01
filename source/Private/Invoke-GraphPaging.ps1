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
        [int] $MaxPages = 200,

        [Parameter()]
        [System.Threading.CancellationToken] $CancellationToken = [System.Threading.CancellationToken]::None,

        [Parameter()]
        [ValidateRange(0.001, 86400)]
        [double] $DeadlineSeconds = 300,

        [Parameter()]
        [scriptblock] $UtcNow
    )

    if ($null -eq $UtcNow) { $UtcNow = { [datetime]::UtcNow } }
    $operationStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $deadlineUtc = (& $UtcNow).AddSeconds($DeadlineSeconds)
    $getRemainingSeconds = {
        $remainingStopwatch = $DeadlineSeconds - $operationStopwatch.Elapsed.TotalSeconds
        $remainingClock = ($deadlineUtc - (& $UtcNow)).TotalSeconds
        return [Math]::Max(0.0, [Math]::Min($remainingStopwatch, $remainingClock))
    }.GetNewClosure()

    $allData = [System.Collections.Generic.List[object]]::new()
    $allTelemetry = [System.Collections.Generic.List[object]]::new()
    $aggregateProvenance = $null
    $verifiedTokenIdentity = $null
    $seenIds = $null
    if ($Descriptor.DeduplicationKey) {
        $seenIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    }

    $nextLink = $FirstPageUri
    $pageCount = 0

    while ($nextLink -and $pageCount -lt $MaxPages) {
        # Caller cancellation wins at the exact deadline boundary. No URI
        # validation, request construction, acquisition or send may begin after
        # this one collection-wide budget is exhausted.
        if ($CancellationToken.IsCancellationRequested) {
            return [pscustomobject] @{
                PSTypeName = 'GraphKit.OperationResult'
                Data       = @()
                Outcome    = 'Cancelled'
                Certainty  = 'Indeterminate'
                Telemetry  = @($allTelemetry)
                Provenance = $aggregateProvenance
                PageCount  = $pageCount
            }
        }
        $remainingSeconds = [double] (& $getRemainingSeconds)
        if ($remainingSeconds -lt 0.001) {
            return [pscustomobject] @{
                PSTypeName = 'GraphKit.OperationResult'
                Data       = @()
                Outcome    = 'DeadlineExpired'
                Certainty  = 'Indeterminate'
                Telemetry  = @($allTelemetry)
                Provenance = $aggregateProvenance
                PageCount  = $pageCount
            }
        }

        $pageCount++

        # Validate the nextLink authority before attaching a bearer token. The link is opaque
        # (may have been redirected or replayed) and must never receive a credential on a
        # hostile authority.
        $null = Test-GraphNextLinkAuthority -NextLink $nextLink -Context $Context

        # Build the page request. The factory may repeat RequiredPagingHeaders.
        $request = & $RequestFactoryScript -Uri $nextLink -Descriptor $Descriptor

        # URI validation and request construction are part of this collection's
        # one budget. Recompute immediately before transport so elapsed setup
        # time cannot be handed to retry as a fresh/stale allowance. Retry cannot
        # represent less than one millisecond, so a smaller positive remainder is
        # expired here rather than rounded up or surfaced as a binding failure.
        if ($CancellationToken.IsCancellationRequested) {
            return [pscustomobject] @{
                PSTypeName = 'GraphKit.OperationResult'
                Data       = @()
                Outcome    = 'Cancelled'
                Certainty  = 'Indeterminate'
                Telemetry  = @($allTelemetry)
                Provenance = $aggregateProvenance
                PageCount  = $pageCount
            }
        }
        $remainingSeconds = [double] (& $getRemainingSeconds)
        if ($remainingSeconds -lt 0.001) {
            return [pscustomobject] @{
                PSTypeName = 'GraphKit.OperationResult'
                Data       = @()
                Outcome    = 'DeadlineExpired'
                Certainty  = 'Indeterminate'
                Telemetry  = @($allTelemetry)
                Provenance = $aggregateProvenance
                PageCount  = $pageCount
            }
        }

        # Execute with retry via the transport delegate.
        #
        # -CancellationToken is passed explicitly. Omitting it bound $null to a parameter
        # typed [System.Threading.CancellationToken], which cannot accept null, so EVERY
        # paged read failed with "Cannot convert null to type CancellationToken". The unit
        # suite never caught it because injected test transports do not type that
        # parameter strictly - only a real paged read against a live tenant does.
        $pageResult = & $TransportScript `
            -Uri $request.Uri `
            -Method $request.Method `
            -Headers $request.Headers `
            -Body $request.Body `
            -CancellationToken $CancellationToken `
            -DeadlineSeconds $remainingSeconds

        if ($null -eq $pageResult) {
            throw "Transport delegate returned null for page $pageCount; expected a GraphKit.OperationResult."
        }

        # Collect per-page telemetry.
        if ($pageResult.Telemetry) {
            @($pageResult.Telemetry).ForEach{ $allTelemetry.Add($_) }
        }

        # A non-success outcome stops pagination.
        if ($pageResult.Outcome -ne 'Succeeded') {
            $allTelemetry = @($allTelemetry)
            return [PSCustomObject]@{
                PSTypeName = 'GraphKit.OperationResult'
                # A collection is one certainty boundary. Never return a
                # successful prefix when a later page failed, cancelled or ran
                # out of budget: consumers cannot treat that prefix as complete.
                Data       = @()
                Outcome    = $pageResult.Outcome
                Certainty  = $pageResult.Certainty
                Telemetry  = $allTelemetry
                Provenance = $pageResult.Provenance
                PageCount  = $pageCount
            }
        }

        # A successful transport result is not allowed to outlive the pager's
        # canonical collection deadline. Check before provenance validation or
        # row retention so a late terminal page cannot be returned as success.
        # Cancellation wins when it arrives at the same boundary.
        if ($CancellationToken.IsCancellationRequested) {
            return [pscustomobject] @{
                PSTypeName = 'GraphKit.OperationResult'
                Data       = @()
                Outcome    = 'Cancelled'
                Certainty  = 'Indeterminate'
                Telemetry  = @($allTelemetry)
                Provenance = $aggregateProvenance
                PageCount  = $pageCount
            }
        }
        if ([double] (& $getRemainingSeconds) -le 0.0) {
            return [pscustomobject] @{
                PSTypeName = 'GraphKit.OperationResult'
                Data       = @()
                Outcome    = 'DeadlineExpired'
                Certainty  = 'Indeterminate'
                Telemetry  = @($allTelemetry)
                Provenance = $aggregateProvenance
                PageCount  = $pageCount
            }
        }

        # A collection envelope attributes every aggregated row to one context, so
        # every successful page of a Verified operation must independently carry
        # the transport's exact tenant proof. Checking only the final page could
        # relabel rows from an earlier unverified or wrong-tenant page. Validate
        # before retaining any row, then carry the final validated provenance onto
        # the aggregate instead of discarding it.
        $pageProvenance = $pageResult.Provenance
        if ([string] $Descriptor.IdentityRequirement -ceq 'Verified') {
            $contextTenant = [guid]::Empty
            $pageTenant = [guid]::Empty
            $actualTenant = [guid]::Empty
            $contextTenantParsed = [guid]::TryParse([string] $Context.TenantId, [ref] $contextTenant)
            $pageTenantParsed = $null -ne $pageProvenance -and
                [guid]::TryParse([string] $pageProvenance.TenantId, [ref] $pageTenant)
            $actualTenantParsed = $null -ne $pageProvenance -and
                [guid]::TryParse([string] $pageProvenance.ActualTenantId, [ref] $actualTenant)
            $identityVerified = $null -ne $pageProvenance -and
                ([string] $pageProvenance.IdentityState -ceq 'VerifiedForToken')
            $tokenFingerprint = if ($null -ne $pageProvenance) { [string] $pageProvenance.TokenFingerprint } else { $null }
            $credentialGeneration = if ($null -ne $pageProvenance) { [string] $pageProvenance.CredentialGeneration } else { $null }
            $pageCloud = if ($null -ne $pageProvenance) { [string] $pageProvenance.Cloud } else { $null }
            $cloudMatches = [string]::Equals(
                $pageCloud,
                [string] $Context.Cloud,
                [System.StringComparison]::OrdinalIgnoreCase
            )
            $tokenIdentityComplete =
                -not [string]::IsNullOrWhiteSpace($tokenFingerprint) -and
                -not [string]::IsNullOrWhiteSpace($credentialGeneration)
            $tokenIdentityMatches = $true
            if ($null -ne $verifiedTokenIdentity) {
                $tokenIdentityMatches =
                    [string]::Equals($tokenFingerprint, [string] $verifiedTokenIdentity.TokenFingerprint, [System.StringComparison]::Ordinal) -and
                    [string]::Equals($credentialGeneration, [string] $verifiedTokenIdentity.CredentialGeneration, [System.StringComparison]::Ordinal) -and
                    [string]::Equals($pageCloud, [string] $verifiedTokenIdentity.Cloud, [System.StringComparison]::OrdinalIgnoreCase)
            }

            if (-not $contextTenantParsed -or $contextTenant -eq [guid]::Empty -or
                -not $pageTenantParsed -or -not $actualTenantParsed -or
                -not $identityVerified -or
                $pageTenant -ne $contextTenant -or $actualTenant -ne $contextTenant -or
                -not $cloudMatches -or -not $tokenIdentityComplete -or -not $tokenIdentityMatches) {
                throw [System.InvalidOperationException]::new(
                    'A successful page of a Verified operation did not carry exact VerifiedForToken tenant provenance or exact-token provenance.'
                )
            }

            if ($null -eq $verifiedTokenIdentity) {
                $verifiedTokenIdentity = [pscustomobject] @{
                    TokenFingerprint     = $tokenFingerprint
                    CredentialGeneration = $credentialGeneration
                    Cloud                = $pageCloud
                }
            }
            $aggregateProvenance = $pageProvenance
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
        Provenance = $aggregateProvenance
    }
}
