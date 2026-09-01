<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Ask one enrolled device to check in with Intune. Requires an {id} parameter - the managedDevice
    id from ManagedDevice.List.

    A BODYLESS action: RequestBodyKind is $null, and the Action.Default strategy takes that
    declaration as the contract. Supplying a Body is an error rather than something ignored.

    ReplayPolicy is NeverReplay, and that is a judgement worth stating because a sync looks
    harmless. It is not replay-safe in the sense the retry engine means: the request is a command
    to the device, the service returns 204 with no identifier to reconcile against, and a retry
    after an ambiguous failure cannot tell whether the first one was delivered. Nothing is
    corrupted by a duplicate sync, but "nothing bad happens" is not the same property as "the
    engine can prove it already committed", and conflating them is how a genuinely unsafe
    operation gets marked Safe later by analogy.

    FULLY LIVE-VERIFIED, and the before/after is what makes the declared permission trustworthy.
    Called against a real lab device it returned HTTP 403 with a token carrying only
    DeviceManagementManagedDevices.ReadWrite.All; after PrivilegedOperations.All was granted the
    same call returned HTTP 204 Succeeded. So the declaration is neither wrong nor over-strict -
    ReadWrite genuinely is not enough - and the bodyless action path is proven end to end.
#>
@{
    SchemaVersion       = 1

    Type                = 'ManagedDevice'
    Operation           = 'SyncDevice'
    OperationKind       = 'Action'
    HandlerStrategyId   = 'Action.Default'

    ApiVersion          = 'v1.0'
    Stability           = 'Stable'
    BetaReason          = $null

    Method              = 'POST'
    PathTemplate        = '/deviceManagement/managedDevices/{id}/syncDevice'
    RequestBodyKind     = $null
    ResponseKind        = 'NoContent'
    PagingStrategy      = 'None'
    RequiredPagingHeaders = @()
    DeduplicationKey    = $null
    SupportsAll         = $false
    SupportsDelta       = $false

    ReplayPolicy        = 'NeverReplay'

    Impact              = 'Low'   # asking a device to check in changes no configuration and loses no data; it is the least consequential write in the catalog
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
