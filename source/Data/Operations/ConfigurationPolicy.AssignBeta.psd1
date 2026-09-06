<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Replace the assignments of one Settings Catalog policy. Requires an {id} parameter and a Body
    holding the complete assignment set.

    Named AssignBeta rather than Assign because Type + Operation is the catalog key and the
    beta-only surface must not shadow a future v1.0 sibling - the same convention the ListBeta
    reads follow.

    A REPLACE, like every other Graph /assign: omitted assignments are removed. Pair it with
    ConfigurationPolicyAssignment.ListBeta to read the current set before replacing it.

    LIVE-VERIFIED end to end against a lab tenant. Worth recording what the fixture cost, because
    it is a real constraint on this API: a Settings Catalog policy cannot be created with an empty
    settings array - the service rejects it with "dCV2Policy.Settings : Count is not >= 1 and
    <= 5000". The verification fixture had to carry one real settingInstance borrowed from an
    existing policy. -WhatIf left the assignment count at 0; the real call returned Succeeded and
    ConfigurationPolicyAssignment.ListBeta read back one assignment.
#>
@{
    SchemaVersion       = 1

    Type                = 'ConfigurationPolicy'
    Operation           = 'AssignBeta'
    OperationKind       = 'Action'
    HandlerStrategyId   = 'Action.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaOnly'
    BetaReason          = 'Settings Catalog policies live on beta, so assigning them does too.'

    Method              = 'POST'
    PathTemplate        = '/deviceManagement/configurationPolicies/{id}/assign'
    RequestBodyKind     = 'ConfigurationPolicyAssignmentSet'
    ResponseKind        = 'Json'
    PagingStrategy      = 'None'
    RequiredPagingHeaders = @()
    DeduplicationKey    = $null
    SupportsAll         = $false
    SupportsDelta       = $false

    ReplayPolicy        = 'NeverReplay'
    Impact              = 'Medium'
    Condition           = $null
    Reconciliation      = $null

    AdvancedQuery       = @{ Supported = $false }
    Concurrency         = @{ Mode = 'None'; Header = $null; Required = $false; AllowWildcard = $false }

    CredentialPolicy    = 'GraphBearer'
    AllowedHosts        = @()
    RedirectPolicy      = 'None'
    IdentityRequirement = 'Verified'

    ResourceFamily      = 'Intune.SettingsCatalog'
    ThrottleClass       = 'Write'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementConfiguration.ReadWrite.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
