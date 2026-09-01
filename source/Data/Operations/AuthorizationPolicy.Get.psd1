<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    The tenant's authorization policy - the singleton governing default user permissions: whether
    users may register applications, create tenants, read other users, and how guest access is
    restricted.

    A SINGLETON, not a collection. /policies/authorizationPolicy returns one object with no 'value'
    wrapper, so Collection.Default would unwrap a property that is not there and yield nothing
    while reporting success. That failure is silent, which is why OperationKind and
    HandlerStrategyId are part of the descriptor rather than inferred from the path shape.
#>
@{
    SchemaVersion       = 1

    Type                = 'AuthorizationPolicy'
    Operation           = 'Get'
    OperationKind       = 'Singleton'
    HandlerStrategyId   = 'Singleton.Default'

    ApiVersion          = 'v1.0'
    Stability           = 'Stable'
    BetaReason          = $null

    Method              = 'GET'
    PathTemplate        = '/policies/authorizationPolicy'
    RequestBodyKind     = $null
    ResponseKind        = 'Json'
    PagingStrategy      = 'None'
    RequiredPagingHeaders = @()
    DeduplicationKey    = $null
    SupportsAll         = $false
    SupportsDelta       = $false

    ReplayPolicy        = 'Safe'
    Condition           = $null
    Reconciliation      = $null

    AdvancedQuery       = @{ Supported = $false }
    Concurrency         = @{ Mode = 'None'; Header = $null; Required = $false; AllowWildcard = $false }

    CredentialPolicy    = 'GraphBearer'
    AllowedHosts        = @()
    RedirectPolicy      = 'None'
    IdentityRequirement = 'Verified'

    ResourceFamily      = 'Directory.Policy'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'Policy.Read.All' }
    )
    RequiredLicense     = @()
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
