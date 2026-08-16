<#
    Operation descriptor - data only.

    This is the normative example from the design spec. Descriptors are versioned, data-only
    .psd1 files: behavioural fields reference validated strategy IDs, never scriptblocks, so a
    descriptor can be loaded with Import-PowerShellDataFile without executing anything.
#>
@{
    SchemaVersion       = 1

    Type                = 'MobileApp'
    Operation           = 'Assign'
    OperationKind       = 'Action'
    HandlerStrategyId   = 'Action.Default'

    ApiVersion          = 'v1.0'
    Stability           = 'Stable'
    BetaReason          = $null

    Method              = 'POST'
    PathTemplate        = '/deviceAppManagement/mobileApps/{id}/assign'
    RequestBodyKind     = 'MobileAppAssignmentSet'
    ResponseKind        = 'NoContent'
    PagingStrategy      = 'None'
    RequiredPagingHeaders = @()
    DeduplicationKey    = $null
    SupportsAll         = $false
    SupportsDelta       = $false

    # Intrinsic replay policy. Attempt certainty is determined at runtime and is NOT stored here.
    ReplayPolicy        = 'NeverReplay'
    Condition           = $null
    Reconciliation      = $null

    AdvancedQuery       = @{ Supported = $false }
    Concurrency         = @{ Mode = 'None'; Header = $null; Required = $false; AllowWildcard = $false }

    CredentialPolicy    = 'GraphBearer'
    AllowedHosts        = @()
    RedirectPolicy      = 'None'
    IdentityRequirement = 'Verified'

    ResourceFamily      = 'Intune.MobileApps'
    ThrottleClass       = 'Write'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementApps.ReadWrite.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
