<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Beta collection. A v1.0 route exists, but the beta shape is the one in common use for this
    collection; the v1.0 sibling operation covers the other.

    The permission is DeviceManagementScripts.Read.All, NOT the DeviceManagementConfiguration
    scope that covers the neighbouring configuration collections. Verified against a live tenant
    on 2026-08-15: the Intune service returned 403 naming the required scopes explicitly. The
    tenant used for verification does not hold that scope, so this descriptor is CORRECT BUT NOT
    LIVE-VERIFIED - grant DeviceManagementScripts.Read.All and re-run the descriptor
    verification to close it.
    The response carries scriptContent - the full body of a deployment script. Scripts
    routinely embed credentials, connection strings and API keys, so it is declared sensitive
    and redacted from every export format. Declared from Microsoft's documented schema rather
    than from observation: the verification tenant does not hold DeviceManagementScripts.Read.All,
    so this operation returns 403 there and the response has never been seen.
#>
@{
    SchemaVersion       = 1

    Type                = 'DeviceManagementScript'
    Operation           = 'List'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaPreferred'
    BetaReason          = 'A v1.0 route exists, but the beta shape is the one in common use for this collection.'

    Method              = 'GET'
    PathTemplate        = '/deviceManagement/deviceManagementScripts'
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

    ResourceFamily      = 'Intune.Script'
    ThrottleClass       = 'Read'

    SensitiveProperties = @('scriptContent')

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementScripts.Read.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
