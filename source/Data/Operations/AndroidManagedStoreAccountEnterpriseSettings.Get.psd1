<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Tenant-wide Android Enterprise managed Google Play store-account settings. A singleton:
    the response IS the object, with no collection envelope. Returns bindStatus,
    lastAppSyncStatus, and lastAppSyncDateTime for connector health.
#>
@{
    SchemaVersion       = 1

    Type                = 'AndroidManagedStoreAccountEnterpriseSettings'
    Operation           = 'Get'
    OperationKind       = 'Singleton'
    HandlerStrategyId   = 'Singleton.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaOnly'
    BetaReason          = 'Android Enterprise store-account settings are not on v1.0.'

    Method              = 'GET'
    PathTemplate        = '/deviceManagement/androidManagedStoreAccountEnterpriseSettings'
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

    ResourceFamily      = 'Intune.Connector'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementConfiguration.Read.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
