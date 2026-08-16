<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Assignments for one Settings Catalog policy. Requires an {id} parameter - the policy id from
    ConfigurationPolicy.ListBeta.

    This closes a gap in the catalog: assignment descriptors already existed for compliance
    policies, device configurations and mobile apps, so a caller reconciling assignment overlap
    across policy types could cover every type EXCEPT Settings Catalog - and silently, because
    the missing type just contributed nothing to the comparison.

    Beta because its parent is: configurationPolicies is a beta collection, and an assignment
    cannot be read from a version on which the policy does not exist - verified, not assumed;
    /v1.0/deviceManagement/configurationPolicies returns 400 BadRequest on a live tenant.

    Live-verified against a lab tenant with a POPULATED response: rows carry 'intent' and a
    'target' whose @odata.type is groupAssignmentTarget with a groupId. Worth recording how that
    verification nearly went wrong - the first eight policies sampled all returned zero
    assignments, which read like a broken descriptor but was the sort order: they were
    consecutive ASR audit rules. Sampling across all 781 policies found the assigned one.
#>
@{
    SchemaVersion       = 1

    Type                = 'ConfigurationPolicyAssignment'
    Operation           = 'ListBeta'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaOnly'
    BetaReason          = 'Settings Catalog policies live on beta, so their assignments do too.'

    Method              = 'GET'
    PathTemplate        = '/deviceManagement/configurationPolicies/{id}/assignments'
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

    ResourceFamily      = 'Intune.SettingsCatalog'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementConfiguration.Read.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
