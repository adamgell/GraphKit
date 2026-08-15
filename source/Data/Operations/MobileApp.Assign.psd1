<#
    Operation descriptor - data only.

    This is the normative example from the design spec, present so the build's CopyPaths
    handling is actually exercised rather than assumed. Descriptors are versioned, data-only
    .psd1 files: behavioural fields reference validated strategy IDs, never scriptblocks, so
    a descriptor can be loaded with Import-PowerShellDataFile without executing anything.

    The loader, validator and strategy registry are phase 1.2.
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

    # Intrinsic replay policy. Attempt certainty is determined at runtime and is NOT stored here.
    ReplayPolicy        = 'NeverReplay'
    Reconciliation      = $null

    AdvancedQuery       = @{ Supported = $false }
    Concurrency         = @{ Mode = 'None' }

    CredentialPolicy    = 'GraphBearer'
    AllowedHosts        = @()

    ResourceFamily      = 'Intune.MobileApps'
    ThrottleClass       = 'Write'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementApps.ReadWrite.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
