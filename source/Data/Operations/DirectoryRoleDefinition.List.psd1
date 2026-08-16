<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Directory role definitions - the roles themselves, as opposed to
    DirectoryRoleAssignment.List which lists who holds them. Join the two on roleDefinitionId to
    turn an assignment into a role name.

    NOTE: this v1.0 operation does NOT carry isPrivileged. Verified against a live tenant -
    v1.0 returns 11 properties and omits it, and asking for it via $select returns HTTP 400.
    Use DirectoryRoleDefinition.ListBeta for privileged classification; deriving it from a
    hardcoded list of role template GUIDs goes stale silently as Entra adds roles.
#>
@{
    SchemaVersion       = 1

    Type                = 'DirectoryRoleDefinition'
    Operation           = 'List'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'v1.0'
    Stability           = 'Stable'
    BetaReason          = $null

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
