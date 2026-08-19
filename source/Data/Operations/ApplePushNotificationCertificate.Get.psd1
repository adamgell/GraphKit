<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Tenant-wide Apple Push Notification certificate (APNs). A singleton: the response IS the
    object, with no collection envelope. Returns expirationDateTime and appleIdentifier for
    expiry evidence; the certificate blob is a secret and is declared sensitive.
#>
@{
    SchemaVersion       = 1

    Type                = 'ApplePushNotificationCertificate'
    Operation           = 'Get'
    OperationKind       = 'Singleton'
    HandlerStrategyId   = 'Singleton.Default'

    ApiVersion          = 'v1.0'
    Stability           = 'Stable'
    BetaReason          = $null

    Method              = 'GET'
    PathTemplate        = '/deviceManagement/applePushNotificationCertificate'
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

    SensitiveProperties = @('certificate')

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementServiceConfig.Read.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
