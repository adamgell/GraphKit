<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Intune device-management intents. Security-baseline profiles on this service surface carry
    templateId and the native Boolean isAssigned; consumers join templateId to
    DeviceManagementTemplate/ListBeta to determine whether the profile was created from a
    deprecated template version.

    LIVE-VERIFIED 2026-08-29 with an app-only token carrying
    DeviceManagementConfiguration.Read.All. The returned intent shape carried templateId and
    isAssigned and joined to the template collection for every intent in the verification tenant.
#>
@{
    SchemaVersion       = 1

    Type                = 'DeviceManagementIntent'
    Operation           = 'ListBeta'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaOnly'
    BetaReason          = 'Device-management intents are exposed only on beta.'

    Method              = 'GET'
    PathTemplate        = '/deviceManagement/intents'
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
