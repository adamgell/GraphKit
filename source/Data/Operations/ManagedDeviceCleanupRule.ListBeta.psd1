<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    The documented per-platform managed-device cleanup rules collection. This replaces the
    undocumented /deviceManagement/managedDeviceCleanupSettings singleton previously carried by
    the catalog. A consumer must evaluate the returned rules; there is no tenant-wide singleton
    with the same supported service contract.

    LIVE-VERIFIED 2026-08-29 with an app-only token carrying
    DeviceManagementManagedDevices.Read.All: HTTP 200, one row, including
    deviceInactivityBeforeRetirementInDays. The removed cleanup-settings path returned 403 with
    this token and with DeviceManagementConfiguration.Read.All.
#>
@{
    SchemaVersion       = 1

    Type                = 'ManagedDeviceCleanupRule'
    Operation           = 'ListBeta'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaOnly'
    BetaReason          = 'Managed-device cleanup rules are exposed only on beta.'

    Method              = 'GET'
    PathTemplate        = '/deviceManagement/managedDeviceCleanupRules'
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

    ResourceFamily      = 'Intune.ManagedDevices'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementManagedDevices.Read.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
