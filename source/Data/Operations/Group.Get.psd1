<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    A single group's identity, description, and protection flags for Intune assignment
    reporting and RBAC group protection (TP.INT.0013). Distinct from Group.List, which
    returns the collection without these select-only properties.

    $select is part of this operation's identity and lives in the PathTemplate.
    isAssignableToRole and isManagementRestricted are omitted unless selected. A Get
    without $select does not error - it returns an object that looks unprotected, which
    is a silent false Fail for TP.INT.0013.
#>
@{
    SchemaVersion       = 1

    Type                = 'Group'
    Operation           = 'Get'
    OperationKind       = 'Singleton'
    HandlerStrategyId   = 'Singleton.Default'

    ApiVersion          = 'v1.0'
    Stability           = 'Stable'
    BetaReason          = $null

    Method              = 'GET'
    PathTemplate        = '/groups/{id}?$select=id,displayName,description,isAssignableToRole,isManagementRestricted'
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

    ResourceFamily      = 'Directory.Group'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'Group.Read.All' }
    )
    RequiredLicense     = @()
    SupportedClouds     = @('Global', 'China', 'Germany', 'USGov', 'USGovDoD')
}
