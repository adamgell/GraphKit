<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Remove company data from one enrolled device and unenroll it. Requires an {id} parameter.

    Impact is Medium, not High: the user's own data is untouched and the device can be re-enrolled,
    so this is disruptive rather than destructive. Medium means -WhatIf works and nothing prompts
    by default - the same treatment as any other write.

    PERMISSION VERIFIED, OPERATION NOT. Called live against a lab device, this returned HTTP 403
    with a token carrying DeviceManagementManagedDevices.ReadWrite.All - which is exactly what
    confirms the declaration above is correct rather than over-strict: ReadWrite is not enough, and
    PrivilegedOperations.All really is required. The lab app does not hold that scope, so the
    operation itself has never executed successfully. Granting it is the only way to close that,
    and it should be a deliberate decision, not a convenience.
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

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementManagedDevices.PrivilegedOperations.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
