<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Settings Catalog configuration-policy templates. This is a distinct resource from the
    legacy /deviceManagement/templates collection: configuration-policy template references
    on modern policies join to this collection and expose lifecycleState rather than the
    legacy isDeprecated field.

    Microsoft documents the beta application-permission contract for this GET collection.
    LIVE-VERIFIED 2026-08-29 with an app-only token carrying
    DeviceManagementConfiguration.Read.All: HTTP 200, sixty-eight rows, with native version,
    lifecycleState, and templateFamily present on every returned row.
#>
@{
    SchemaVersion       = 1

    Type                = 'DeviceManagementConfigurationPolicyTemplate'
    Operation           = 'ListBeta'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaOnly'
    BetaReason          = 'Settings Catalog configuration-policy templates are exposed only on beta.'

    Method              = 'GET'
    PathTemplate        = '/deviceManagement/configurationPolicyTemplates'
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

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementConfiguration.Read.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
