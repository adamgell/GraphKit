<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Beta sibling of DeviceCompliancePolicy.List.psd1, added so a beta-reading caller can be
    served without losing fields. Callers commonly read this collection from beta, and the beta
    shape carries properties v1.0 does not.

    This is deliberately a SEPARATE operation rather than flipping the v1.0 descriptor's
    ApiVersion. Type + Operation is the catalog key, so one descriptor cannot serve both
    versions - and changing the existing one would silently alter the response shape for every
    current caller of the v1.0 operation, which is already live-verified. Stability is
    'DualVersion': the operation genuinely exists at both versions, and the caller chooses which
    by naming the operation. That keeps API version a per-operation fact rather than a global
    mode, which is what the design requires.
#>
@{
    SchemaVersion       = 1

    Type                = 'DeviceCompliancePolicy'
    Operation           = 'ListBeta'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'beta'
    Stability           = 'DualVersion'
    BetaReason          = 'Beta sibling of DeviceCompliancePolicy.List. Compliance policy types are richer on beta; several platform-specific policy shapes are beta-only.'

    Method              = 'GET'
    PathTemplate        = '/deviceManagement/deviceCompliancePolicies'
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

    ResourceFamily      = 'Intune.DeviceCompliancePolicy'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementConfiguration.Read.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
