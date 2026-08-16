function Use-GraphTenant {
    <#
    .SYNOPSIS
        Selects an immutable GraphKit context as the current convenience context.

    .DESCRIPTION
        Resolves a tenant profile into an immutable GraphKit.Context and stores
        it in a script-scoped convenience variable for interactive use. There is
        no reconnection: token acquisition happens per context, on demand, and
        low-level work never consults this convenience variable once a context
        has been resolved. Requires an existing profile.

    .PARAMETER ProfileId
        The canonical profile identifier (^[a-z0-9][a-z0-9-]{0,63}$) of the
        tenant profile to resolve. Only the canonical id selects a profile.

    .PARAMETER StorePath
        Optional override for the profile store path. Defaults to
        ~/.graphkit/profiles.json when omitted.

    .EXAMPLE
        Use-GraphTenant -ProfileId contoso
        $script:GraphKitCurrentContext   # the resolved GraphKit.Context
    #>
    [CmdletBinding()]
    [OutputType('GraphKit.Context')]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $ProfileId,

        [string] $StorePath
    )

    $context = Get-GraphContext -ProfileId $ProfileId -StorePath $StorePath
    $script:GraphKitCurrentContext = $context
    return $context
}
