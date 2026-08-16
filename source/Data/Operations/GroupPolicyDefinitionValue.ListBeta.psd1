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

    LIVE-VERIFIED against a populated response. The lab tenant's own administrative templates are
    all unpopulated shells (createdDateTime == lastModifiedDateTime), so a fixture policy was
    created there specifically to verify this walk - "GraphKit verification fixture - do not
    deploy", unassigned, left in place so future changes can re-verify without another write.

    A populated row carries: configurationType, createdDateTime, definition, enabled, id,
    lastModifiedDateTime. The expanded 'definition' carries categoryPath, classType, displayName,
    explainText, groupPolicyCategoryId, hasRelatedDefinitions, id, lastModifiedDateTime,
    minDeviceCspVersion, minUserCspVersion, policyType, supportedOn, version.

    The $expand being load-bearing is measured, not argued: the same request without it returns
    HTTP 200 and the identical row MINUS the 'definition' key. Nothing errors - the caller just
    gets a row that cannot say which Group Policy setting it configures.
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
