function Get-GraphOperation {
    <#
    .SYNOPSIS
        Gets a validated operation descriptor from the GraphKit operation catalog.

    .DESCRIPTION
        Resolves one or more operation descriptors from the GraphKit catalog. Each
        descriptor governs how GraphKit executes a Microsoft Graph operation: method,
        path template, API version, replay policy, concurrency, required permissions,
        and supported clouds. Use -Type and -Operation together to resolve a single
        descriptor, -List to enumerate the whole catalog, or -Cloud to filter by
        supported sovereign cloud.

    .EXAMPLE
        Get-GraphOperation -Type MobileApp -Operation Assign

        Returns the single descriptor that governs mobile app assignments.

    .EXAMPLE
        Get-GraphOperation -List

        Returns every operation descriptor currently shipped in the catalog.

    .PARAMETER Type
        The operation type to filter the catalog by, for example 'MobileApp' or
        'ManagedDevice'. Combine with -Operation to resolve a single descriptor.

    .PARAMETER Operation
        The operation name to filter the catalog by, for example 'Assign' or 'List'.
        Combine with -Type to resolve a single descriptor.

    .PARAMETER List
        Return every operation descriptor in the catalog rather than a filtered subset.

    .PARAMETER Cloud
        Only return descriptors that declare support for the specified cloud, for
        example 'Global', 'USGov', or 'USGovDoD'.
    #>

    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Position = 0)]
        [string] $Type,

        [Parameter(Position = 1)]
        [string] $Operation,

        [Parameter()]
        [switch] $List,

        [Parameter()]
        [string] $Cloud
    )

    Get-GraphOperationInternal -Type $Type -Operation $Operation -List:$List -Cloud $Cloud
}
