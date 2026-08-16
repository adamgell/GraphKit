<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Replace the assignments of one device configuration profile. Requires an {id} parameter and a
    Body holding the complete assignment set.

    A REPLACE, not an append. Graph's /assign takes the full desired set and silently unassigns
    anything omitted, so posting a single assignment intending to ADD one removes every other.
    Read DeviceConfigurationAssignment.List first and post the union.

    Impact Medium: an assignment change is disruptive - a policy can reach devices it was never
    meant to, or stop reaching devices that need it - but it destroys no data and is reversible by
    posting the previous set.

    LIVE-VERIFIED end to end against a lab tenant: create, assign, read back through
    DeviceConfigurationAssignment.List, delete.
#>
@{
    SchemaVersion       = 1

    Type                = 'DeviceConfiguration'
    Operation           = 'Assign'
    OperationKind       = 'Action'
    HandlerStrategyId   = 'Action.Default'

    ApiVersion          = 'v1.0'
    Stability           = 'Stable'
    BetaReason          = $null

    Method              = 'POST'
    PathTemplate        = '/deviceManagement/deviceConfigurations/{id}/assign'
    RequestBodyKind     = 'DeviceConfigurationAssignmentSet'
    ResponseKind        = 'Json'
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

    ResourceFamily      = 'Intune.DeviceConfiguration'
    ThrottleClass       = 'Write'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementConfiguration.ReadWrite.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
