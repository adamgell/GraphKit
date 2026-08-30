<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Intune unified-RBAC role assignments with the relationships TenantPulse needs to interpret
    each assignment. This is deliberately distinct from the older
    DeviceManagementRoleAssignment/List operation: the service exposes a different resource
    shape below /roleManagement/deviceManagement, and the fixed $expand is part of this
    operation's contract rather than a caller-controlled optimization.

    LIVE-VERIFIED 2026-08-29 with an app-only token carrying
    DeviceManagementRBAC.Read.All: HTTP 200, three rows, every row carried an expanded
    roleDefinition, and every expanded principal was a group. CloudPC.Read.All was absent from
    the token, proving DeviceManagementRBAC.Read.All sufficient despite the beta documentation's
    unusual least-privileged permission table.
#>
@{
    SchemaVersion       = 1

    Type                = 'DeviceManagementUnifiedRoleAssignment'
    Operation           = 'ListBeta'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaOnly'
    BetaReason          = 'The roleManagement/deviceManagement provider and unifiedRoleAssignmentMultiple response are beta-only.'

    Method              = 'GET'
    PathTemplate        = '/roleManagement/deviceManagement/roleAssignments?$expand=roleDefinition,principals'
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

    ResourceFamily      = 'Intune.RBAC'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementRBAC.Read.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
