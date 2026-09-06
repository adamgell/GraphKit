<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Delete the Intune record for one device. Requires an {id} parameter.

    Impact is Medium. This removes the MANAGEMENT RECORD, not the machine: the device keeps
    working and its user notices nothing until it next tries to check in. Easy to confuse with
    Wipe when scanning a script, which is exactly why the two carry different declared impacts
    rather than relying on the reader to know the difference.

    A DELETE with no body - which is why the Action strategy had to stop demanding one.
#>
@{
    SchemaVersion       = 1

    Type                = 'ManagedDevice'
    Operation           = 'Delete'
    OperationKind       = 'Action'
    HandlerStrategyId   = 'Action.Default'

    ApiVersion          = 'v1.0'
    Stability           = 'Stable'
    BetaReason          = $null

    Method              = 'DELETE'
    PathTemplate        = '/deviceManagement/managedDevices/{id}'
    RequestBodyKind     = $null
    ResponseKind        = 'NoContent'
    PagingStrategy      = 'None'
    RequiredPagingHeaders = @()
    DeduplicationKey    = $null
    SupportsAll         = $false
    SupportsDelta       = $false

    ReplayPolicy        = 'NeverReplay'
    Impact              = 'Medium'
    Condition           = $null
    Reconciliation      = $null

    AdvancedQuery       = @{ Supported = $false }
    Concurrency         = @{ Mode = 'None'; Header = $null; Required = $false; AllowWildcard = $false }

    CredentialPolicy    = 'GraphBearer'
    AllowedHosts        = @()
    RedirectPolicy      = 'None'
    IdentityRequirement = 'Verified'

    ResourceFamily      = 'Intune.ManagedDevices'
    ThrottleClass       = 'Write'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementManagedDevices.PrivilegedOperations.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
