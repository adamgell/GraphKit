<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Directory users, used to resolve primary users on device records.
#>
@{
    SchemaVersion       = 1

    Type                = 'User'
    Operation           = 'List'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'v1.0'
    Stability           = 'Stable'
    BetaReason          = $null

    Method              = 'GET'
    PathTemplate        = '/users'
    RequestBodyKind     = $null
    ResponseKind        = 'Json'
    PagingStrategy      = 'NextLink'
    RequiredPagingHeaders = @()
    DeduplicationKey    = 'id'
    SupportsAll         = $false
    SupportsDelta       = $false

    ReplayPolicy        = 'Safe'
    Condition           = $null
    Reconciliation      = $null

    AdvancedQuery       = @{ Supported = $true }
    Concurrency         = @{ Mode = 'None'; Header = $null; Required = $false; AllowWildcard = $false }

    CredentialPolicy    = 'GraphBearer'
    AllowedHosts        = @()
    RedirectPolicy      = 'None'
    IdentityRequirement = 'Verified'

    ResourceFamily      = 'Directory.User'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'User.Read.All' }
    )
    RequiredLicense     = @()
    SupportedClouds     = @('Global', 'China', 'Germany', 'USGov', 'USGovDoD')
}
