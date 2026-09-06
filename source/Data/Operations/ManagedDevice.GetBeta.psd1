<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Beta singleton sibling used when a caller needs the full per-device hardware and
    health-attestation shape. Microsoft documents that many hardwareInformation values are
    default/null on collection reads and require a GET for the device id with the property
    included in $select. This operation pins the minimum safe detail projection in its path,
    along with the service version, permission, and read semantics; callers cannot broaden it
    into credential-like properties through arbitrary query input.

    Live response/permission verification remains separate from this deterministic contract.
#>
@{
    SchemaVersion       = 1

    Type                = 'ManagedDevice'
    Operation           = 'GetBeta'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'beta'
    Stability           = 'DualVersion'
    BetaReason          = 'The beta singleton carries the detailed hardware and device-health shape required by the IHA successor.'

    Method              = 'GET'
    PathTemplate        = '/deviceManagement/managedDevices/{id}?$select=id,hardwareInformation,deviceHealthAttestationState,physicalMemoryInBytes,processorArchitecture,skuFamily,skuNumber,managementFeatures,roleScopeTagIds,ethernetMacAddress,bootstrapTokenEscrowed'
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

    ResourceFamily      = 'Intune.ManagedDevices'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementManagedDevices.Read.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
