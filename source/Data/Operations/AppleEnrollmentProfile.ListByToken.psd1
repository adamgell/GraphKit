<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Lists the Apple Automated Device Enrollment profiles attached to one DEP onboarding
    token. Microsoft exposes this relationship only in beta. The token id is explicit in
    the path so callers cannot accidentally treat profiles from different Apple tokens as
    one tenant-wide collection.

    The descriptor and deterministic response contract are implemented from Microsoft's
    documented path and application permission. Live service permission/shape verification
    remains a separate release gate.
#>
@{
    SchemaVersion       = 1

    Type                = 'AppleEnrollmentProfile'
    Operation           = 'ListByToken'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaOnly'
    BetaReason          = 'Apple DEP enrollment profiles are exposed only beneath the beta depOnboardingSettings relationship.'

    Method              = 'GET'
    PathTemplate        = '/deviceManagement/depOnboardingSettings/{depOnboardingSettingId}/enrollmentProfiles'
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

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementServiceConfig.Read.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
