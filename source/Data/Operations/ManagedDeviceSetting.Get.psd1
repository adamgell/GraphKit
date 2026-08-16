<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Tenant-wide Intune device settings. A singleton: the response IS the object, with no
    collection envelope.
#>
@{
    SchemaVersion       = 1

    Type                = 'ManagedDeviceSetting'
    Operation           = 'Get'
    OperationKind       = 'Singleton'
    HandlerStrategyId   = 'Singleton.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaOnly'
    BetaReason          = 'The Intune service settings singleton is not exposed on v1.0.'

    Method              = 'GET'
    PathTemplate        = '/deviceManagement/settings'
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

    ResourceFamily      = 'Intune.ServiceConfig'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementConfiguration.Read.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
