# New-GraphThrottleScope — computes the throttle scope keys for a Graph operation.
#
# Two gates coordinate every request (see the design spec, "Throttle state must be scoped,
# not global"):
#   Coarse  : <Cloud>|<TenantId>|<ClientId>|<Read|Write>
#   Leaf    : <Coarse>|<ResourceFamily>
#
# The coarse gate coordinates limits shared across resource families; the leaf gate
# coordinates the tighter per-family limits. Token acquisition uses a third, separate scope
# key (<Authority>|<Resource>|<AuthMode>) and is produced with the -Acquisition switch.

function New-GraphThrottleScope {
    [CmdletBinding(DefaultParameterSetName = 'Request')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Request')]
        [Parameter(ParameterSetName = 'Acquisition')]
        [object] $Context,

        [Parameter(Mandatory, ParameterSetName = 'Request')]
        [hashtable] $Descriptor,

        [Parameter(Mandatory, ParameterSetName = 'Acquisition')]
        [switch] $Acquisition,

        [Parameter(ParameterSetName = 'Acquisition')]
        [string] $Authority,

        [Parameter(ParameterSetName = 'Acquisition')]
        [string] $Resource,

        [Parameter(ParameterSetName = 'Acquisition')]
        [string] $AuthMode
    )

    $cloud = ''
    $tenantId = ''
    $clientId = ''

    if ($null -ne $Context) {
        $cloud = [string] $Context.Cloud
        $tenantId = ConvertTo-GraphThrottleGuid -Value $Context.TenantId
        $clientId = ConvertTo-GraphThrottleGuid -Value $Context.ClientId
    }

    if ($Acquisition) {
        if (-not $PSBoundParameters.ContainsKey('Authority')) {
            $Authority = $cloud
        }
        if (-not $PSBoundParameters.ContainsKey('Resource') -and $null -ne $Context -and $null -ne $Context.TokenSource) {
            $Resource = [string] $Context.TokenSource.Audience
        }
        if (-not $PSBoundParameters.ContainsKey('AuthMode') -and $null -ne $Context -and $null -ne $Context.TokenSource) {
            $AuthMode = [string] $Context.TokenSource.AuthMode
        }

        $tokenKey = '{0}|{1}|{2}' -f $Authority, $Resource, $AuthMode

        return @{
            CoarseKey      = $tokenKey
            LeafKey        = $tokenKey
            ThrottleClass  = $null
            ResourceFamily = $null
            Cloud          = $cloud
            TenantId       = $tenantId
            ClientId       = $clientId
        }
    }

    $throttleClass = [string] $Descriptor.ThrottleClass
    if ($throttleClass -ne 'Write') {
        $throttleClass = 'Read'
    }

    $resourceFamily = [string] $Descriptor.ResourceFamily

    $coarseKey = '{0}|{1}|{2}|{3}' -f $cloud, $tenantId, $clientId, $throttleClass
    $leafKey = '{0}|{1}' -f $coarseKey, $resourceFamily

    return @{
        CoarseKey      = $coarseKey
        LeafKey        = $leafKey
        ThrottleClass  = $throttleClass
        ResourceFamily = $resourceFamily
        Cloud          = $cloud
        TenantId       = $tenantId
        ClientId       = $clientId
    }
}

# Normalizes a tenant/client id to a lowercase invariant GUID string. Null-safe: a null,
# empty, or all-zero GUID yields an empty string so the scope key remains well-formed.
function ConvertTo-GraphThrottleGuid {
    [CmdletBinding()]
    param(
        [object] $Value
    )

    if ($null -eq $Value) {
        return ''
    }

    if ($Value -is [guid]) {
        if ($Value -eq [guid]::Empty) {
            return ''
        }
        return $Value.ToString().ToLowerInvariant()
    }

    $text = [string] $Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return ''
    }

    $parsed = [guid]::Empty
    if ([guid]::TryParse($text, [ref] $parsed) -and $parsed -ne [guid]::Empty) {
        return $parsed.ToString().ToLowerInvariant()
    }

    return $text.Trim().ToLowerInvariant()
}
