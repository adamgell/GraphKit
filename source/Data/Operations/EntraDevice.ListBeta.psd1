<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Entra device objects - the directory's view of a device, distinct from
    /deviceManagement/managedDevices which is Intune's view. A device can appear in one and not
    the other, which is normally the point of reading both.

    Beta sibling of EntraDevice.List.
#>
@{
    SchemaVersion       = 1

    Type                = 'EntraDevice'
    Operation           = 'ListBeta'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'beta'
    Stability           = 'DualVersion'
    BetaReason          = 'Beta sibling of EntraDevice.List, for callers that need beta-only device properties.'

    Method              = 'GET'
    PathTemplate        = '/devices'
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

    ResourceFamily      = 'Directory.Device'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'Device.Read.All' }
    )
    RequiredLicense     = @()
    SupportedClouds     = @('Global', 'China', 'Germany', 'USGov', 'USGovDoD')
}
