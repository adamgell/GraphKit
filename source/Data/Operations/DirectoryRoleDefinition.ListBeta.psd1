<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Directory role definitions - the roles themselves, as opposed to
    DirectoryRoleAssignment.List which lists who holds them. Join the two on roleDefinitionId to
    turn an assignment into a role name.

    Carries isPrivileged, which is the supported way to classify a role as privileged. Deriving
    that from a hardcoded list of role template GUIDs goes stale silently as Entra adds roles.
#>
@{
    SchemaVersion       = 1

    Type                = 'DirectoryRoleDefinition'
    Operation           = 'ListBeta'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'beta'
    Stability           = 'DualVersion'
    BetaReason          = 'isPrivileged is BETA-ONLY. Verified against a live tenant: v1.0 returns 11 properties without it, beta returns 15 with it, and v1.0 with $select=isPrivileged returns HTTP 400. Any privileged-role classification must read beta.'

    Method              = 'GET'
    PathTemplate        = '/roleManagement/directory/roleDefinitions'
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

    ResourceFamily      = 'Directory.RoleManagement'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'RoleManagement.Read.Directory' }
    )
    RequiredLicense     = @()
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
