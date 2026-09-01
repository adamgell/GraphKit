<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Conditional-access named locations. Not available in every cloud, hence the narrower list.

    The declared permission is Policy.Read.All, NOT Policy.Read.ConditionalAccess. The narrower
    scope was proved insufficient on 2026-08-15. The corrected declaration was then positively
    verified app-only on 2026-08-29: the token carried Policy.Read.All and the endpoint returned
    HTTP 200 with one row. Only a live call settles a descriptor's permission claim.
#>
@{
    SchemaVersion       = 1

    Type                = 'NamedLocation'
    Operation           = 'List'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'v1.0'
    Stability           = 'Stable'
    BetaReason          = $null

    Method              = 'GET'
    PathTemplate        = '/identity/conditionalAccess/namedLocations'
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

    AdvancedQuery       = @{ Supported = $false }
    Concurrency         = @{ Mode = 'None'; Header = $null; Required = $false; AllowWildcard = $false }

    CredentialPolicy    = 'GraphBearer'
    AllowedHosts        = @()
    RedirectPolicy      = 'None'
    IdentityRequirement = 'Verified'

    ResourceFamily      = 'Directory.ConditionalAccess'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'Policy.Read.All' }
    )
    RequiredLicense     = @()
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
