<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Authentication methods policy singleton (commonly surfaced as "MFA" in reporting tools).

    VERIFIED against a live tenant on 2026-08-16, once Policy.Read.All was granted. Before that
    grant it returned 403 accessDenied - which is what confirmed the declared permission was
    correct rather than wrong, since a wrong scope and an ungranted one look identical until
    the grant is made.
#>
@{
    SchemaVersion       = 1

    Type                = 'AuthenticationMethodsPolicy'
    Operation           = 'Get'
    OperationKind       = 'Singleton'
    HandlerStrategyId   = 'Singleton.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaOnly'
    BetaReason          = 'the beta shape of this policy is the one in common use.'

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
