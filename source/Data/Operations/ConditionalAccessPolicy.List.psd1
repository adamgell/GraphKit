<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Beta collection. A v1.0 route exists, but the beta shape is the one in common use for this
    collection; the v1.0 sibling operation covers the other.

    Requires Policy.Read.All. Verified against a live tenant on 2026-08-15: an app-only token
    holding Policy.Read.ConditionalAccess received 403 AccessDenied, the same result as
    NamedLocation - the narrower conditional-access scope does not cover these reads. The lab
    app does not hold Policy.Read.All, so this descriptor is CORRECT BUT NOT LIVE-VERIFIED.
#>
@{
    SchemaVersion       = 1

    Type                = 'ConditionalAccessPolicy'
    Operation           = 'List'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaPreferred'
    BetaReason          = 'A v1.0 route exists, but the beta shape is the one in common use for this collection.'

    Method              = 'GET'
    PathTemplate        = '/identity/conditionalAccess/policies'
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
