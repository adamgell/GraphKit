<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Eligible PIM directory role instances. Path MUST include /roleManagement/directory/;
    the root /roleEligibilityScheduleInstances path is not the official Graph GET.
#>
@{
    SchemaVersion       = 1

    Type                = 'RoleEligibilityScheduleInstance'
    Operation           = 'List'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'v1.0'
    Stability           = 'Stable'
    BetaReason          = $null

    Method              = 'GET'
    PathTemplate        = '/roleManagement/directory/roleEligibilityScheduleInstances'
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

    ResourceFamily      = 'Directory.RoleManagement'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'RoleEligibilitySchedule.Read.Directory' }
    )
    RequiredLicense     = @()
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
