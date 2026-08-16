<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    The app install summary report, read by reporting tools as "app install errors".

    This is the one collection in a typical inventory surface that is not a read: it is a POST
    to a report endpoint that returns the report body in the response. That shape is why it
    needed an Action descriptor rather than another Collection one, and why it was the last gap.

    ReplayPolicy is 'Safe' even though the method is POST. That is deliberate and is the narrow
    case the policy exists to express: this POST computes and returns a report, it creates
    nothing and mutates nothing, so replaying it after an ambiguous failure cannot double-apply
    anything. ThrottleClass stays 'Read' for the same reason - it belongs in the read budget,
    not the write one.
#>
@{
    SchemaVersion       = 1

    Type                = 'AppInstallSummaryReport'
    Operation           = 'Get'
    OperationKind       = 'Action'
    HandlerStrategyId   = 'Action.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaOnly'
    BetaReason          = 'The Intune reports endpoints are not exposed on v1.0.'

    Method              = 'POST'
    PathTemplate        = '/deviceManagement/reports/getAppsInstallSummaryReport'
    RequestBodyKind     = 'ReportFilter'
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

    ResourceFamily      = 'Intune.Report'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementApps.Read.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
