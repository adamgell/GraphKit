<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Service principals. The permission analyzer already reads these privately; this is the
    public read path.
    passwordCredentials and keyCredentials are declared sensitive. Verified against a live
    tenant: passwordCredentials entries carry a secretText field and keyCredentials carry a key
    field. Graph normally returns those null outside a create response, but a property that CAN
    carry a secret should not depend on that to stay out of an export.

    preferredTokenSigningKeyThumbprint and tokenEncryptionKeyId are deliberately NOT declared -
    a thumbprint and a key id are public identifiers, and redacting them would remove useful
    evidence for no gain.
#>
@{
    SchemaVersion       = 1

    Type                = 'ServicePrincipal'
    Operation           = 'List'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'v1.0'
    Stability           = 'Stable'
    BetaReason          = $null

    Method              = 'GET'
    PathTemplate        = '/servicePrincipals'
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

    ResourceFamily      = 'Directory.ServicePrincipal'
    ThrottleClass       = 'Read'

    # Declared at the VALUE fields, not the arrays. Declaring 'passwordCredentials' wholesale
    # replaced the entire array with [REDACTED] and took endDateTime, startDateTime and keyId
    # with it - which is exactly the metadata a credential-hygiene check reads, and it never
    # reads the secret. Redacting the identifying data alongside the secret makes the export
    # useless for the one job it is for.
    SensitiveProperties = @(
        'passwordCredentials.secretText'
        'passwordCredentials.hint'
        'keyCredentials.key'
        'keyCredentials.customKeyIdentifier'
    )

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'Application.Read.All' }
    )
    RequiredLicense     = @()
    SupportedClouds     = @('Global', 'China', 'Germany', 'USGov', 'USGovDoD')
}
