<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Tenant organization record. Note the shape: /organization is a COLLECTION on the wire that
    contains exactly one element, not a singleton, so this is a Collection operation and the
    caller takes the first element. mdmAuthority lives on that element and is the usual reason
    to read it.

    Beta sibling of Organization.List.
#>
@{
    SchemaVersion       = 1

    Type                = 'Organization'
    Operation           = 'ListBeta'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'beta'
    Stability           = 'DualVersion'
    BetaReason          = 'Beta sibling of Organization.List, for callers that need beta-only fields on the organization record.'

    Method              = 'GET'
    PathTemplate        = '/organization'
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

    ResourceFamily      = 'Directory.Organization'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'Organization.Read.All' }
    )
    RequiredLicense     = @()
    SupportedClouds     = @('Global', 'China', 'Germany', 'USGov', 'USGovDoD')
}
