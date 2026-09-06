<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Remove company data from one enrolled device and unenroll it. Requires an {id} parameter.

    Impact is Medium, not High: the user's own data is untouched and the device can be re-enrolled,
    so this is disruptive rather than destructive. Medium means -WhatIf works and nothing prompts
    by default - the same treatment as any other write.

    FULLY LIVE-VERIFIED against a real enrolled device, which was genuinely retired and then
    re-enrolled by the operator. -WhatIf ran first against that same device and sent nothing; the
    real call returned HTTP 204 Succeeded. Sibling evidence backs the permission independently:
    ManagedDevice.SyncDevice uses the identical bodyless path and returned 403 before
    PrivilegedOperations.All was granted, 204 after.

    This is the one operation in the catalog whose verification had a cost someone had to agree to
    pay, and it is worth stating why it was worth paying: a retire that silently no-ops looks
    exactly like a retire that worked, and no unit test can tell the difference.
#>
@{
    SchemaVersion       = 1

    Type                = 'ManagedDevice'
    Operation           = 'Retire'
    OperationKind       = 'Action'
    HandlerStrategyId   = 'Action.Default'

    ApiVersion          = 'v1.0'
    Stability           = 'Stable'
    BetaReason          = $null

    Method              = 'POST'
    PathTemplate        = '/deviceManagement/managedDevices/{id}/retire'
    RequestBodyKind     = $null
    ResponseKind        = 'NoContent'
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

    ResourceFamily      = 'Intune.ManagedDevices'
    ThrottleClass       = 'Write'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementManagedDevices.PrivilegedOperations.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
