<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Replace the assignments of one compliance policy. Requires an {id} parameter and a Body holding
    the full assignment set.

    This is a REPLACE, not an append - Graph's /assign takes the complete desired set and whatever
    is omitted is unassigned. That is the sharp edge: a caller who posts one assignment intending to
    add it silently removes every other. Read DeviceCompliancePolicyAssignment.List first and post
    the union.

    NeverReplay for the ordinary reason: the response carries no identifier that lets the retry
    engine tell a committed write from a lost response.

    LIVE-VERIFIED end to end against a lab tenant: a throwaway compliance policy was created,
    assigned through this descriptor, read back through DeviceCompliancePolicyAssignment.List
    (1 groupAssignmentTarget returned), and deleted. -WhatIf was run first against the same live
    policy and left the assignment count at 0, so the dry run is proven against a real service
    rather than a mock.
#>
@{
    SchemaVersion       = 1

    Type                = 'DeviceCompliancePolicy'
    Operation           = 'Assign'
    OperationKind       = 'Action'
    HandlerStrategyId   = 'Action.Default'

    ApiVersion          = 'v1.0'
    Stability           = 'Stable'
    BetaReason          = $null

    Method              = 'POST'
    PathTemplate        = '/deviceManagement/deviceCompliancePolicies/{id}/assign'
    RequestBodyKind     = 'DeviceCompliancePolicyAssignmentSet'
    ResponseKind        = 'Json'
    PagingStrategy      = 'None'
    RequiredPagingHeaders = @()
    DeduplicationKey    = $null
    SupportsAll         = $false
    SupportsDelta       = $false

    ReplayPolicy        = 'NeverReplay'

    Impact              = 'Medium'   # a compliance assignment change can flip devices to non-compliant and trigger conditional-access blocks, which is disruptive and fully reversible by restoring the previous set
    Condition           = $null
    Reconciliation      = $null

    AdvancedQuery       = @{ Supported = $false }
    Concurrency         = @{ Mode = 'None'; Header = $null; Required = $false; AllowWildcard = $false }

    CredentialPolicy    = 'GraphBearer'
    AllowedHosts        = @()
    RedirectPolicy      = 'None'
    IdentityRequirement = 'Verified'

    ResourceFamily      = 'Intune.DeviceCompliancePolicy'
    ThrottleClass       = 'Write'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementConfiguration.ReadWrite.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
