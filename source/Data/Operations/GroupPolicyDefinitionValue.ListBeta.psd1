<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    The settings configured inside one Administrative Template policy. Requires an {id}
    parameter - the configuration id from GroupPolicyConfiguration.ListBeta.

    The $expand=definition is LOAD-BEARING and therefore fixed in the path rather than left to
    the caller. Without it a definitionValue is a row of ids, an enabled flag and timestamps
    with no indication of which Group Policy setting it configures - technically a successful
    response, and useless. This is the same reasoning as Organization/GetMdmAuthority's fixed
    $select: an operation whose output is meaningless without a query option should not depend
    on every caller remembering it.

    Because the option is fixed, AdvancedQuery stays unsupported and Resolve-GraphUri refuses a
    caller-supplied $expand rather than emitting it twice.

    VERIFICATION STATUS - path, auth and error handling are live-verified; a POPULATED response
    is not. Every groupPolicyConfiguration in the lab tenant returned 0 definitionValues, and
    that was checked rather than assumed: a bogus parent id returns ResourceNotFound from the
    GroupPolicyAdminService, so this endpoint does distinguish "missing" from "empty" and the
    zeros are real. Those policies have createdDateTime == lastModifiedDateTime, i.e. they are
    unpopulated shells. A tenant with configured administrative templates is still needed to
    confirm the shape of a non-empty row.
#>
@{
    SchemaVersion       = 1

    Type                = 'GroupPolicyDefinitionValue'
    Operation           = 'ListBeta'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaOnly'
    BetaReason          = 'Administrative Template policies are exposed only on beta; the v1.0 path does not exist.'

    Method              = 'GET'
    PathTemplate        = '/deviceManagement/groupPolicyConfigurations/{id}/definitionValues?$expand=definition'
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
