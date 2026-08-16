<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Administrative Template ("ADMX-backed") policies. This is the root of a three-level walk:
    a configuration holds definitionValues, and each definitionValue holds presentationValues.
    Reading only this level tells you a policy EXISTS and nothing about what it sets, so it is
    of limited use on its own - see GroupPolicyDefinitionValue.ListBeta.

    Beta-only, verified rather than assumed: /v1.0/deviceManagement/groupPolicyConfigurations
    returns 400 BadRequest against a live tenant (not the 404 you would expect, and not an empty
    collection - so a caller who guessed v1.0 gets an error that looks like a malformed request
    rather than a missing API).

    Live-verified against a lab tenant: 8 configurations returned, HTTP 200.
#>
@{
    SchemaVersion       = 1

    Type                = 'GroupPolicyConfiguration'
    Operation           = 'ListBeta'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaOnly'
    BetaReason          = 'Administrative Template policies are exposed only on beta; the v1.0 path does not exist.'

    Method              = 'GET'
    PathTemplate        = '/deviceManagement/groupPolicyConfigurations'
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

    ResourceFamily      = 'Intune.GroupPolicy'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementConfiguration.Read.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
