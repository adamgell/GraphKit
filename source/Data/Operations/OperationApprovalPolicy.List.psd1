<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Beta collection. Multi Admin Approval policies are not on v1.0.
    List rows expose id, displayName, and policyType on the entity; no extra query options.
#>
@{
    SchemaVersion       = 1

    Type                = 'OperationApprovalPolicy'
    Operation           = 'List'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaOnly'
    BetaReason          = 'Multi Admin Approval policies are not on v1.0.'

    Method              = 'GET'
    PathTemplate        = '/deviceManagement/operationApprovalPolicies'
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

    ResourceFamily      = 'Intune.ServiceConfig'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementRBAC.Read.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
