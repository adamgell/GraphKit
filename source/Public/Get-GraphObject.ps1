<#
    .SYNOPSIS
        Reads Microsoft Graph objects for a type and projects rows onto the success stream.

    .DESCRIPTION
        Get-GraphObject is the ergonomic read accessor for the GraphKit operation catalog. It
        resolves a context and a read operation descriptor (defaulting -Operation to 'List' when
        only -Type is given), executes the request through the GraphKit-owned transport and retry
        engine, then projects the result envelope's Data rows onto the success stream. Each row is
        stamped with a 'GraphKit.<Type>' PSTypeName plus _Tenant, _RetrievedUtc, _GraphPath and
        _ApiVersion provenance. Any non-Succeeded outcome throws (the message names the Outcome
        and Certainty) so a failure can never be mistaken for an empty result. Use -PassThruResult
        to receive the single GraphKit.OperationResult envelope instead of rows; rows and envelopes
        are never mixed on one stream.

    .EXAMPLE
        Get-GraphObject -ProfileId ivy24 -Type MobileApp

        Lists every mobile app in the ivy24 tenant (Operation defaults to 'List'), returning one
        stamped GraphKit.MobileApp row per app.

    .EXAMPLE
        Get-GraphObject -Context $ctx -Type ManagedDevice -Operation Get -Parameters @{ id = '00000000-0000-0000-0000-000000000001' }

        Reads a single managed device by id and returns one stamped GraphKit.ManagedDevice row.

    .PARAMETER Type
        The operation type to read from the catalog, for example 'MobileApp', 'ManagedDevice' or
        'DeviceConfiguration'. Each returned row's PSTypeName becomes 'GraphKit.<Type>'.

    .PARAMETER Operation
        The operation name to read, for example 'List' or 'Get'. Defaults to 'List' when omitted,
        so supplying -Type alone enumerates that type's collection.

    .PARAMETER Parameters
        A hashtable of operation parameters: path-token values (such as 'id') and any OData query
        options (such as '$filter' or '$top') the descriptor declares supported.

    .PARAMETER PassThruResult
        Return the single GraphKit.OperationResult envelope instead of stamped rows. Envelope-only
        mode never emits rows, so the output stream never mixes the two shapes.

    .PARAMETER PageCap
        The maximum number of pages to fetch for a paged collection, guarding against runaway
        pagination. A warning is emitted if the cap is reached with pages remaining.

    .PARAMETER Context
        The immutable GraphKit context owning the token source. Mutually exclusive with -ProfileId;
        supply exactly one.

    .PARAMETER ProfileId
        The canonical profile identifier to resolve into a context via Get-GraphContext. Mutually
        exclusive with -Context; supply exactly one.
#>
function Get-GraphObject {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $Type,

        [Parameter(Position = 1)]
        [string] $Operation,

        [Parameter()]
        [hashtable] $Parameters,

        [Parameter()]
        [switch] $PassThruResult,

        [Parameter()]
        [ValidateRange(1, 2000)]
        [int] $PageCap = 200,

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

    # 2. Default the operation to 'List' for the read accessor's collection ergonomics.
    if ([string]::IsNullOrWhiteSpace($Operation)) {
        $Operation = 'List'
    }

    # 3. Resolve the descriptor.
    $Descriptor = Get-GraphOperation -Type $Type -Operation $Operation

    $parameters = if ($PSBoundParameters.ContainsKey('Parameters') -and $null -ne $Parameters) { $Parameters } else { @{} }

    # 4. Build the request URI; its path (query-free) becomes the _GraphPath provenance stamp.
    $baseUri = [uri] ('{0}/{1}' -f $Context.GraphBaseUri.AbsoluteUri.TrimEnd('/'), $Descriptor.ApiVersion)
    $requestUri = Resolve-GraphUri -Descriptor $Descriptor -Parameters $parameters -BaseUri $baseUri

    # 5. Credential policy and authority check. Non-bypassable, and re-applied per hop by the
    #    transport delegate below.
    $null = Test-GraphCredentialPolicy -Uri $requestUri -Descriptor $Descriptor -Context $Context

    # 6. Build the transport delegate. It re-applies the credential policy on every hop (paging
    #    included) and delegates replay decisions to Invoke-GraphRetry.
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

    # 7. Execute. Paged collections page through Invoke-GraphPaging (honouring -PageCap); every
    #    other operation executes through its registered handler strategy.
    $result = if ($Descriptor.PagingStrategy -eq 'NextLink') {
        $requestFactory = {
            param([uri] $Uri, [hashtable] $Descriptor)

            @{
                Uri     = $Uri
                Method  = $Descriptor.Method
                Headers = Get-GraphRequestHeaders -Descriptor $Descriptor
                Body    = $null
            }
        }

        Invoke-GraphPaging `
            -Context $Context `
            -Descriptor $Descriptor `
            -FirstPageUri $requestUri `
            -RequestFactoryScript $requestFactory `
            -TransportScript $transport `
            -MaxPages $PageCap
    } else {
        Invoke-GraphHandlerStrategy -Context $Context -Descriptor $Descriptor -Parameters $parameters -Transport $transport
    }

    if ($null -eq $result) {
        throw 'The operation produced no result envelope; expected exactly one GraphKit.OperationResult.'
    }

    # 8. Stamp provenance on the envelope (non-destructively), matching Invoke-GraphOperation.
    #    TenantId and ActualTenantId are null unless the identity is verified.
    $retrievedUtc = [datetime]::UtcNow
    $verified = ($Context.IdentityState -eq 'VerifiedForToken')

    if ($null -eq $result.Provenance) {
        $result.Provenance = @{}
    }

    $provenance = $result.Provenance
    $defaults = @{
        ProfileId      = $Context.ProfileId
        TenantId       = if ($verified) { $Context.TenantId } else { $null }
        ApiVersion     = $Descriptor.ApiVersion
        ResourceFamily = $Descriptor.ResourceFamily
        RetrievedUtc   = $retrievedUtc
        IdentityState  = $Context.IdentityState
    }

    foreach ($key in $defaults.Keys) {
        if (-not $provenance.ContainsKey($key)) {
            $provenance[$key] = $defaults[$key]
        }
    }

    if (-not $provenance.ContainsKey('ActualTenantId')) {
        $provenance['ActualTenantId'] = if ($verified) { $Context.TenantId } else { $null }
    }

    # 9. A non-Succeeded outcome throws, naming the Outcome and Certainty, so a failure is never
    #    mistaken for an empty result.
    if ($result.Outcome -ne 'Succeeded') {
        throw "Get-GraphObject failed for '{0}/{1}': Outcome '{2}', Certainty '{3}'." -f $Type, $Operation, $result.Outcome, $result.Certainty
    }

    # 10. -PassThruResult is envelope-only output; rows and envelopes are never mixed.
    if ($PassThruResult) {
        return $result
    }

    # 11. Project the envelope's Data rows onto the success stream, stamping each row with the
    #     type name and row-level provenance fields.
    $typeName = 'GraphKit.' + $Descriptor.Type
    $graphPath = $requestUri.AbsolutePath
    $apiVersion = [string] $Descriptor.ApiVersion
    $tenant = [string] $Context.ProfileId

    $stampedRows = [System.Collections.Generic.List[object]]::new()

    foreach ($row in @($result.Data)) {
        if ($null -eq $row) { continue }

        $obj = if ($row -is [System.Collections.IDictionary]) { [PSCustomObject] $row } else { $row }

        $obj.PSObject.TypeNames.Insert(0, $typeName)

        Add-Member -InputObject $obj -NotePropertyName '_Tenant' -NotePropertyValue $tenant -Force
        Add-Member -InputObject $obj -NotePropertyName '_RetrievedUtc' -NotePropertyValue $retrievedUtc -Force
        Add-Member -InputObject $obj -NotePropertyName '_GraphPath' -NotePropertyValue $graphPath -Force
        Add-Member -InputObject $obj -NotePropertyName '_ApiVersion' -NotePropertyValue $apiVersion -Force

        $stampedRows.Add($obj)
    }

    return $stampedRows
}
