<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Windows Autopilot deployment profiles. Distinct from AutopilotDevice.List, which lists
    device identities rather than the profiles that assign them.

    $expand=assignments is part of this operation's identity and lives in the PathTemplate.
    Without it Graph omits the assignments relationship, every profile looks unassigned, and
    TP.INT.0026 false-Fails. A caller who forgets the expand does not get an error - they get
    objects without assignments, which is the silent-nothing outcome this catalog exists to
    prevent.
#>
@{
    SchemaVersion       = 1

    Type                = 'WindowsAutopilotDeploymentProfile'
    Operation           = 'List'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaOnly'
    BetaReason          = 'Windows Autopilot deployment profiles are documented only on beta; AutopilotDevice.List is already beta for the same reason.'

    Method              = 'GET'
    PathTemplate        = '/deviceManagement/windowsAutopilotDeploymentProfiles?$expand=assignments'
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

    ResourceFamily      = 'Intune.Enrollment'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementServiceConfig.Read.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
