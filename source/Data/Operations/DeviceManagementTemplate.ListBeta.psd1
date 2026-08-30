<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Intune device-management templates, including the security-baseline template metadata a
    consumer needs to distinguish a current template from a deprecated version. Policies and
    their assignments remain separate operations; this collection supplies templateType,
    versionInfo, and isDeprecated.

    LIVE-VERIFIED 2026-08-29 with an app-only token carrying
    DeviceManagementConfiguration.Read.All: HTTP 200, seventeen rows, with versionInfo and
    isDeprecated present in the returned shape.
#>
@{
    SchemaVersion       = 1

    Type                = 'DeviceManagementTemplate'
    Operation           = 'ListBeta'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaOnly'
    BetaReason          = 'Intune device-management templates are exposed only on beta.'

    Method              = 'GET'
    PathTemplate        = '/deviceManagement/templates'
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

    ResourceFamily      = 'Intune.SettingsCatalog'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementConfiguration.Read.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
