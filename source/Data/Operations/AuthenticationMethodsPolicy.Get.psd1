<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Authentication methods policy singleton (IHA calls this collection "MFA").

    NOT LIVE-VERIFIED: requires Policy.Read.All, which the Ivy24 lab app does not hold. It
    returned 403 accessDenied, consistent with the declared permission being correct but
    ungranted - the same position as ConditionalAccessPolicy.
#>
@{
    SchemaVersion       = 1

    Type                = 'AuthenticationMethodsPolicy'
    Operation           = 'Get'
    OperationKind       = 'Singleton'
    HandlerStrategyId   = 'Singleton.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaOnly'
    BetaReason          = 'IntuneHealthAutomation reads the beta shape of this policy.'

    Method              = 'GET'
    PathTemplate        = '/policies/authenticationMethodsPolicy'
    RequestBodyKind     = $null
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

    ResourceFamily      = 'Directory.Policy'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'Policy.Read.All' }
    )
    RequiredLicense     = @()
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
