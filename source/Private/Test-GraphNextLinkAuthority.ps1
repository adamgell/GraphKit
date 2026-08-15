<#
    .SYNOPSIS
        Validates that a Graph URI targets the expected cloud authority over HTTPS before any
        bearer token is attached.

    .DESCRIPTION
        A nextLink (or any Graph URI the pipeline is about to credential) is opaque but never
        trusted. This guard refuses to let a bearer token reach a non-HTTPS endpoint, a non-443
        port, or any host that is not the exact cloud-specific Graph authority for the supplied
        context. It is the single choke point both direct requests and paging hops pass through.

    .NOTES
        On success it returns $true; on any violation it throws a hard error naming the offending
        authority. It never returns $false as a soft signal, because a silent downgrade would be
        exactly the credential leak this module exists to prevent.
#>
function Test-GraphNextLinkAuthority {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [uri] $NextLink,

        [Parameter(Mandatory)]
        [PSCustomObject] $Context
    )

    if ($null -eq $NextLink -or -not $NextLink.IsAbsoluteUri) {
        throw 'Refusing to attach a Graph bearer token to a relative or empty nextLink; an absolute HTTPS URI is required.'
    }

    if ($NextLink.Scheme -ne 'https') {
        throw "Refusing to attach a Graph bearer token to non-HTTPS authority '{0}'." -f $NextLink.Authority
    }

    if ($NextLink.Port -ne 443) {
        throw "Refusing to attach a Graph bearer token to authority '{0}' - only port 443 is permitted." -f $NextLink.Authority
    }

    $expectedUri = [uri] $Context.GraphBaseUri
    $expectedAuthority = Get-GraphUriAuthority -Uri $expectedUri
    $actualAuthority = Get-GraphUriAuthority -Uri $NextLink

    if ($actualAuthority -cne $expectedAuthority) {
        throw (
            "Untrusted Graph authority '{0}' - expected '{1}' for cloud '{2}'. " +
            'Refusing to attach a bearer token.'
        ) -f $actualAuthority, $expectedAuthority, $Context.Cloud
    }

    return $true
}

<#
    Internal. Normalizes a URI to its authority key: lowercased host plus a port only when the
    port differs from the scheme's default. Kept in this file so the credential-policy check and
    the nextLink check share one definition of "authority".
#>
function Get-GraphUriAuthority {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [uri] $Uri
    )

    $hostName = $Uri.Host.ToLowerInvariant()
    $defaultPort = if ($Uri.Scheme -eq 'https') { 443 } elseif ($Uri.Scheme -eq 'http') { 80 } else { -1 }

    if ($Uri.Port -ne $defaultPort) {
        return '{0}:{1}' -f $hostName, $Uri.Port
    }

    return $hostName
}
