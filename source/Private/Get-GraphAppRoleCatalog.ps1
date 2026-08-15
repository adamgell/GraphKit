<#
    Permission-analysis read primitives (phase 3).

    Every Graph read in this slice goes through the normal request pipeline:
    each read synthesizes a Safe GET descriptor and delegates to
    Invoke-GraphRetry, so throttling, replay semantics and the credential
    boundary apply exactly as they do for catalog-driven operations. The token's
    claims are never consulted as an authorization inventory.

    Two session-scoped caches live here, both unrelated to the credential cache:
      - GraphServicePrincipalCache : <tenant>|<appId>    -> service principal object
      - GraphAppRoleCatalogCache   : <normalized tenant> -> Microsoft Graph appRoles
    The Microsoft Graph service-principal appRoles list is large and effectively
    static within a run, so it is resolved once per tenant for the session. The
    catalog cache key is the normalized tenant id alone (lowercase GUID string,
    or the lowercased raw value when the id is not a GUID), so the key never
    varies between resolutions of the same tenant.
#>

# Microsoft Graph's own well-known application id. Its appRoles are the source of
# truth for resolving an appRoleId (an opaque GUID carried by every
# appRoleAssignment) back to the stable permission value.
$script:GraphServicePrincipalAppId = '00000003-0000-0000-c000-000000000000'

$script:GraphServicePrincipalCache = [System.Collections.Generic.Dictionary[string, object]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)

$script:GraphAppRoleCatalogCache = [System.Collections.Generic.Dictionary[string, object]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)

function Get-GraphTenantCacheKey {
    # A session-scope cache key that keeps one tenant's directory reads isolated
    # from another's (and one cloud's from another's). Null-safe: a context with
    # no TenantId or GraphBaseUri still yields a stable, distinct key.
    param(
        [Parameter(Mandatory = $true)]
        [object] $Context
    )

    $base = ''
    if ($null -ne $Context.GraphBaseUri) {
        $base = $Context.GraphBaseUri.AbsoluteUri.TrimEnd('/')
    }

    $tenant = ''
    if ($null -ne $Context.TenantId) {
        $tenant = [string] $Context.TenantId
    }

    return ('{0}|{1}' -f $base, $tenant).ToLowerInvariant()
}

function Get-GraphDirectoryUri {
    # Builds an absolute directory URI from a version-less Graph base URI and a
    # path-and-query fragment (which callers format with literal `$filter`
    # tokens already embedded).
    param(
        [Parameter(Mandatory = $true)]
        [object] $Context,

        [Parameter(Mandatory = $true)]
        [string] $PathAndQuery
    )

    return [uri] ('{0}{1}' -f $Context.GraphBaseUri.AbsoluteUri.TrimEnd('/'), $PathAndQuery)
}

function Get-GraphEnvelopeStatusCode {
    # The last attempt's status code from an OperationResult envelope's telemetry,
    # or 0 when the envelope carries none. Used only to classify a failed read for
    # the bootstrap-trap error; never returned to callers.
    param(
        [AllowNull()]
        [object] $Envelope
    )

    if ($null -eq $Envelope.Telemetry -or @($Envelope.Telemetry).Count -eq 0) {
        return 0
    }

    $last = @($Envelope.Telemetry)[-1]
    if ($null -eq $last -or $null -eq $last.StatusCode) {
        return 0
    }

    return [int] $last.StatusCode
}

function Invoke-GraphDirectoryRead {
    # One directory GET through the normal pipeline. Synthesizes a Safe read
    # descriptor, delegates to Invoke-GraphRetry, and interprets the envelope:
    # success returns the raw Data; a 403 raises the analyzer's own bootstrap-trap
    # error (never a bare 403, never a fallback to token claims); any other
    # failure raises an actionable read error naming the resource and tenant.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object] $Context,

        [Parameter(Mandatory = $true)]
        [uri] $Uri,

        [Parameter(Mandatory = $true)]
        [string] $ResourceFamily
    )

    $descriptor = @{
        CredentialPolicy    = 'GraphBearer'
        AllowedHosts        = @()
        ApiVersion          = 'v1.0'
        Stability           = 'Stable'
        BetaReason          = $null
        ResourceFamily      = $ResourceFamily
        ThrottleClass       = 'Read'
        ReplayPolicy        = 'Safe'
        IdentityRequirement = 'Verified'
    }

    $envelope = Invoke-GraphRetry `
        -Context $Context `
        -Descriptor $descriptor `
        -Uri $Uri `
        -Method 'GET' `
        -Headers @{} `
        -Body $null `
        -CancellationToken ([System.Threading.CancellationToken]::None)

    if ($null -eq $envelope) {
        throw "GraphKit read of '$ResourceFamily' in tenant '{0}' produced no result envelope." -f $Context.TenantId
    }

    if ($envelope.Outcome -eq 'Succeeded') {
        return $envelope.Data
    }

    $statusCode = Get-GraphEnvelopeStatusCode -Envelope $envelope

    if ($statusCode -eq 403) {
        throw (
            "GraphKit permission analysis cannot proceed: reading '$ResourceFamily' in tenant '{0}' returned 403 Forbidden. " +
            "This is the analyzer's own prerequisite, not the target application's: the analyzer identity needs the " +
            "application permission 'Application.Read.All' or 'Directory.Read.All' in that tenant. Grant one of those " +
            "permissions to the analyzer's service principal (or run the analysis under a separate read-only app " +
            'registration), then retry.' -f $Context.TenantId
        )
    }

    $status = if ($statusCode -gt 0) { [string] $statusCode } else { 'unknown' }
    throw (
        "GraphKit read of '$ResourceFamily' in tenant '{0}' failed (status {1}, certainty {2})." -f
        $Context.TenantId, $status, $Envelope.Certainty
    )
}

function Get-GraphServicePrincipalByAppId {
    # Resolves a service principal by application id within the context's tenant,
    # or returns $null when none exists. Resolution is cached for the session per
    # tenant + appId, so a second resolution never re-enters the pipeline. The
    # directory $filter form returns 200 with an empty value (never 404) when the
    # principal is absent, so absence is an empty result, not a transport error.
    param(
        [Parameter(Mandatory = $true)]
        [object] $Context,

        [Parameter(Mandatory = $true)]
        [string] $AppId
    )

    $tenantKey = Get-GraphTenantCacheKey -Context $Context
    $cacheKey = '{0}|{1}' -f $tenantKey, $AppId.ToLowerInvariant()

    if ($script:GraphServicePrincipalCache.ContainsKey($cacheKey)) {
        return $script:GraphServicePrincipalCache[$cacheKey]
    }

    $pathAndQuery = "/v1.0/servicePrincipals?`$filter=appId eq '{0}'&`$select=id,appId,appRoles" -f $AppId
    $uri = Get-GraphDirectoryUri -Context $Context -PathAndQuery $pathAndQuery

    $data = Invoke-GraphDirectoryRead -Context $Context -Uri $uri -ResourceFamily 'Directory.ServicePrincipals'

    $principal = $null
    if ($null -ne $data -and $null -ne $data.value -and @($data.value).Count -gt 0) {
        $principal = @($data.value)[0]
    }

    $script:GraphServicePrincipalCache[$cacheKey] = $principal
    return $principal
}

function Get-GraphAppRoleCatalog {
    # Returns the Microsoft Graph service principal's appRoles list for the
    # context's tenant, resolved once per tenant per session. appRoleId values
    # are opaque GUIDs on every appRoleAssignment; this catalog is how they map
    # back to stable permission values (for example
    # 'DeviceManagementManagedDevices.Read.All'). The session cache is keyed by
    # the normalized tenant id, and the catalog array is returned as a single
    # object (the cached instance on repeat resolutions), never enumerated into
    # the pipeline.
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [object] $Context
    )

    $tenantId = [string] $Context.TenantId
    $parsed = [guid]::Empty
    $cacheKey = if ([guid]::TryParse($tenantId, [ref] $parsed)) {
        $parsed.ToString()
    } else {
        $tenantId.ToLowerInvariant()
    }

    if ($script:GraphAppRoleCatalogCache.ContainsKey($cacheKey)) {
        return , $script:GraphAppRoleCatalogCache[$cacheKey]
    }

    $graphPrincipal = Get-GraphServicePrincipalByAppId -Context $Context -AppId $script:GraphServicePrincipalAppId

    $appRoles = @()
    if ($null -ne $graphPrincipal -and $null -ne $graphPrincipal.appRoles) {
        $appRoles = @($graphPrincipal.appRoles)
    }

    $script:GraphAppRoleCatalogCache[$cacheKey] = $appRoles
    return , $appRoles
}

function Get-GraphPermissionEntry {
    # Normalizes a permission entry (hashtable or object with Type/Value) into a
    # stable PSCustomObject carrying Type and Value, or returns $null for a null
    # entry. Comparison is always by this normalized shape.
    param(
        [AllowNull()]
        [object] $Entry
    )

    if ($null -eq $Entry) {
        return $null
    }

    if ($Entry -is [System.Collections.IDictionary]) {
        return [PSCustomObject] @{
            Type  = [string] $Entry['Type']
            Value = [string] $Entry['Value']
        }
    }

    return [PSCustomObject] @{
        Type  = [string] $Entry.Type
        Value = [string] $Entry.Value
    }
}

function Test-GraphPermissionEntryMatch {
    # Two permission entries match when Type and Value are equal (both compared
    # case-insensitively; permission values are identifiers, not display text).
    param(
        [AllowNull()]
        [object] $A,

        [AllowNull()]
        [object] $B
    )

    $left = Get-GraphPermissionEntry -Entry $A
    $right = Get-GraphPermissionEntry -Entry $B

    if ($null -eq $left -or $null -eq $right) {
        return $false
    }

    return (
        [string]::Equals($left.Type, $right.Type, [System.StringComparison]::OrdinalIgnoreCase) -and
        [string]::Equals($left.Value, $right.Value, [System.StringComparison]::OrdinalIgnoreCase)
    )
}

function Format-GraphPermissionList {
    # Renders a permission-entry list as a comma-separated string of values for a
    # finding's Value field. Empty (or null) renders as 'None' so a finding never
    # carries a blank value.
    param(
        [AllowEmptyCollection()]
        [object[]] $Entries
    )

    if ($null -eq $Entries -or @($Entries).Count -eq 0) {
        return 'None'
    }

    $values = foreach ($item in $Entries) {
        $normalized = Get-GraphPermissionEntry -Entry $item
        if ($null -ne $normalized -and -not [string]::IsNullOrWhiteSpace($normalized.Value)) {
            $normalized.Value
        }
    }

    if ($null -eq $values -or @($values).Count -eq 0) {
        return 'None'
    }

    return (@($values) -join ', ')
}
