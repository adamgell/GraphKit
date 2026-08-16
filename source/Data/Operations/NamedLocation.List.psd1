<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Conditional-access named locations. Not available in every cloud, hence the narrower list.

    The declared permission is Policy.Read.All, NOT Policy.Read.ConditionalAccess. Verified
    against a live tenant on 2026-08-15: an app-only token whose roles claim demonstrably
    contained Policy.Read.ConditionalAccess still received 403 AccessDenied "required scopes are
    missing" from this endpoint, while the same call succeeded delegated. The narrower
    conditional-access scope covers the policies collection but not namedLocations. Only a live
    call finds this - the permission a descriptor declares is a claim about the service, and the
    service is the only authority on it.
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

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'Policy.Read.All' }
    )
    RequiredLicense     = @()
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
