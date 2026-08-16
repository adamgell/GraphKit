<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Security defaults enforcement policy. A singleton: the response IS the policy object, with
    no collection envelope, so this uses Singleton.Default rather than Collection.Default -
    the collection handler would unwrap a 'value' property and hand back one of its fields.

    Requires Policy.Read.All. Directory.Read.All is NOT sufficient for the identity policy
    endpoints; that distinction has already caught NamedLocation and ConditionalAccessPolicy
    in this catalog, both of which returned 403 to a token carrying the narrower
    Policy.Read.ConditionalAccess.
#>
@{
    SchemaVersion       = 1

    Type                = 'SecurityDefaultsPolicy'
    Operation           = 'Get'
    OperationKind       = 'Singleton'
    HandlerStrategyId   = 'Singleton.Default'

    ApiVersion          = 'v1.0'
    Stability           = 'Stable'
    BetaReason          = $null

    Method              = 'GET'
    PathTemplate        = '/policies/identitySecurityDefaultsEnforcementPolicy'
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
