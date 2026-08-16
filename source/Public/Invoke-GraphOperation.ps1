<#
    .SYNOPSIS
        Executes a single Microsoft Graph operation and returns one canonical result envelope.

    .DESCRIPTION
        Resolves a context (from -Context or -ProfileId) and an operation descriptor (from
        -Type/-Operation) or a raw URI (-Uri/-Method/-Body), validates the credential policy and
        authority before any send, executes the operation's registered handler strategy through the
        GraphKit-owned transport, warns once per session for BetaPreferred operations, stamps
        provenance, and returns exactly one GraphKit.OperationResult envelope per logical operation.
        -Raw bypasses descriptor and query validation only; credential policy and authority checks
        remain non-bypassable.

    .EXAMPLE
        Invoke-GraphOperation -ProfileId contoso -Type MobileApp -Operation Assign -Parameters @{ id = '00000000-0000-0000-0000-000000000000'; Body = @{ assignments = @() } }

        Resolves the contoso context, looks up the MobileApp Assign descriptor, and posts an assignment.

    .EXAMPLE
        Invoke-GraphOperation -Context $context -Uri 'https://graph.microsoft.com/v1.0/me' -Method GET

        Issues a raw GET through the trusted transport; descriptor validation is bypassed but the
        credential policy and authority checks still apply.

    .PARAMETER Type
        The operation type to resolve from the catalog, for example 'ManagedDevice'. Combine with
        -Operation to select a single descriptor governing method, path and replay policy.

    .PARAMETER Operation
        The operation name to resolve from the catalog, for example 'List'. Combine with -Type to
        select the single descriptor that governs how the request is executed.

    .PARAMETER Parameters
        A hashtable of operation parameters: path-token values (such as 'id') and any OData query
        options (such as '$filter' or '$top') the descriptor declares supported, plus 'Body' for
        action operations. Missing path tokens and unsupported query options raise actionable errors.

    .PARAMETER Uri
        The absolute request URI for raw mode. The credential policy and authority are still
        validated against the context before any bearer token is attached.

    .PARAMETER Method
        The HTTP method for the raw request, for example 'GET' or 'POST'. Raw mode still enforces
        credential policy and the exact Graph authority.

    .PARAMETER Body
        The request body for a raw request. It is serialized by the transport and never replayed
        automatically on ambiguity.

    .PARAMETER Context
        The immutable GraphKit context owning the token source. Mutually exclusive with -ProfileId;
        supply exactly one.

    .PARAMETER ProfileId
        The canonical profile identifier to resolve into a context via Get-GraphContext. Mutually
        exclusive with -Context; supply exactly one.
    .NOTES
        Named Invoke-GraphOperation, not Invoke-GraphRequest, because Microsoft.Graph.Authentication
        (a required module) exports an SDK cmdlet named Invoke-GraphRequest; a same-named export
        would collide in every session.
#>
function Invoke-GraphOperation {
    [CmdletBinding(DefaultParameterSetName = 'Descriptor')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Descriptor', Position = 0)]
        [string] $Type,

        [Parameter(Mandatory, ParameterSetName = 'Descriptor', Position = 1)]
        [string] $Operation,

        [Parameter(ParameterSetName = 'Descriptor')]
        [hashtable] $Parameters,

        [Parameter(Mandatory, ParameterSetName = 'Raw')]
        [uri] $Uri,

        [Parameter(Mandatory, ParameterSetName = 'Raw')]
        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
        [string] $Method,

        [Parameter(ParameterSetName = 'Raw')]
        $Body,

        [Parameter()]
        [PSCustomObject] $Context,

        [Parameter()]
        [string] $ProfileId
    )

    # 1. Resolve the context: exactly one of -Context / -ProfileId.
    if ($null -ne $Context -and $PSBoundParameters.ContainsKey('ProfileId')) {
        throw 'Provide either -Context or -ProfileId, not both.'
    }

    if ($null -eq $Context) {
        if (-not $PSBoundParameters.ContainsKey('ProfileId') -or [string]::IsNullOrWhiteSpace($ProfileId)) {
            throw 'Provide either -Context or -ProfileId.'
        }

        $Context = Get-GraphContext -ProfileId $ProfileId
    }

    $raw = ($PSCmdlet.ParameterSetName -eq 'Raw')

    # 2. Resolve the descriptor (or synthesize a minimal one for raw mode). Descriptor bypass
    #    never bypasses credential policy.
    if ($raw) {
        $Descriptor = @{
            CredentialPolicy = 'GraphBearer'
            AllowedHosts     = @()
        }
        $requestUri = $Uri
        $Method = $Method.ToUpperInvariant()
    } else {
        $Descriptor = Get-GraphOperation -Type $Type -Operation $Operation
        $parameters = if ($PSBoundParameters.ContainsKey('Parameters') -and $null -ne $Parameters) { $Parameters } else { @{} }

        $baseUri = [uri] ('{0}/{1}' -f $Context.GraphBaseUri.AbsoluteUri.TrimEnd('/'), $Descriptor.ApiVersion)
        $requestUri = Resolve-GraphUri -Descriptor $Descriptor -Parameters $parameters -BaseUri $baseUri
    }

    # 3. Warn once per session for BetaPreferred operations (BetaOnly is used without ceremony).
    if (-not $raw -and $Descriptor.Stability -eq 'BetaPreferred') {
        $betaKey = '{0}/{1}' -f $Descriptor.Type, $Descriptor.Operation
        if ($script:GraphBetaPreferredWarned.Add($betaKey)) {
            $betaMessage = "Operation '{0}' prefers the beta Graph API surface." -f $betaKey
            if (-not [string]::IsNullOrWhiteSpace([string] $Descriptor.BetaReason)) {
                $betaMessage += ' BetaReason: ' + $Descriptor.BetaReason
            }
            $betaMessage += ' Beta carries no breaking-change guarantee; pin the fields you depend on with a contract test.'
            Write-Warning $betaMessage
        }
    }

    # 4. Credential policy and authority check. Non-bypassable, and active under -Raw too.
    $null = Test-GraphCredentialPolicy -Uri $requestUri -Descriptor $Descriptor -Context $Context

    # 5. Build the transport delegate. It re-applies the credential policy on every hop (paging
    #    and job-polling included) and delegates replay decisions to Invoke-GraphRetry.
    $transport = {
        param(
            [uri] $Uri,
            [string] $Method,
            [hashtable] $Headers,
            $Body,
            [System.Threading.CancellationToken] $CancellationToken
        )

        $null = Test-GraphCredentialPolicy -Uri $Uri -Descriptor $Descriptor -Context $Context

        Invoke-GraphRetry `
            -Context $Context `
            -Descriptor $Descriptor `
            -Uri $Uri `
            -Method $Method `
            -Headers $Headers `
            -Body $Body `
            -CancellationToken $CancellationToken
    }

    # 6. Execute the registered strategy.
    $result = if ($raw) {
        & $transport -Uri $requestUri -Method $Method -Headers @{} -Body $Body -CancellationToken ([System.Threading.CancellationToken]::None)
    } else {
        Invoke-GraphHandlerStrategy -Context $Context -Descriptor $Descriptor -Parameters $parameters -Transport $transport
    }

    if ($null -eq $result) {
        throw 'The operation produced no result envelope; expected exactly one GraphKit.OperationResult.'
    }

    # 7. Stamp provenance (non-destructively: preserve tenant-verification fields the transport
    #    already recorded). TenantId and ActualTenantId are null unless the identity is verified.
    if ($null -eq $result.Provenance) {
        $result.Provenance = @{}
    }

    $provenance = $result.Provenance
    $verified = ($Context.IdentityState -eq 'VerifiedForToken')

    $defaults = @{
        ProfileId      = $Context.ProfileId
        TenantId       = if ($verified) { $Context.TenantId } else { $null }
        ApiVersion     = if ($raw) { $null } else { $Descriptor.ApiVersion }
        ResourceFamily = if ($raw) { $null } else { $Descriptor.ResourceFamily }
        RetrievedUtc   = [datetime]::UtcNow
        IdentityState  = $Context.IdentityState
    }

    # The operation's declared secret-bearing properties travel with the envelope so
    # Export-GraphResult knows what the rows contain. Only set when the descriptor declares
    # any - an absent key means nothing was declared, which is different from an empty list.
    # A raw request has no descriptor and therefore no declaration, which the exporter reports
    # rather than treating as "nothing to redact".
    if (-not $raw -and $null -ne $Descriptor.SensitiveProperties -and @($Descriptor.SensitiveProperties).Count -gt 0) {
        $defaults['SensitiveProperties'] = @($Descriptor.SensitiveProperties)
    }

    foreach ($key in $defaults.Keys) {
        if (-not $provenance.ContainsKey($key)) {
            $provenance[$key] = $defaults[$key]
        }
    }

    if (-not $provenance.ContainsKey('ActualTenantId')) {
        $provenance['ActualTenantId'] = if ($verified) { $Context.TenantId } else { $null }
    }

    return $result
}

# Session-scoped set of operations already warned about, so a BetaPreferred operation warns once
# per session rather than once per call.
$script:GraphBetaPreferredWarned = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
