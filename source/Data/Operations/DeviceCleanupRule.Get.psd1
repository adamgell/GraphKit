<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Device cleanup rule singleton.

    NOT LIVE-VERIFIED. Against the verification tenant on 2026-08-15 this returned 403 with an
    app-only token holding DeviceManagementConfiguration.Read.All, so the declared permission is
    a best guess and may be wrong in the same way NamedLocation and DeviceManagementScript were.
    Confirm the required scope from the service's own 403 before relying on this descriptor.
#>
@{
    SchemaVersion       = 1

    Type                = 'DeviceCleanupRule'
    Operation           = 'Get'
    OperationKind       = 'Singleton'
    HandlerStrategyId   = 'Singleton.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaOnly'
    BetaReason          = 'Managed-device cleanup settings are not exposed on v1.0.'

    Method              = 'GET'
    PathTemplate        = '/deviceManagement/managedDeviceCleanupSettings'
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
