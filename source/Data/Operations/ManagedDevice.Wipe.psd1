<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Factory-reset one enrolled device. Requires an {id} parameter and a Body.

    Impact is HIGH, the only operation in the catalog that declares it. This is irreversible
    end-user data loss: a mistyped id resets a real person's laptop and nothing brings it back.
    High impact means Invoke-GraphOperation additionally requires an interactive confirmation or an
    explicit -Force, because ShouldProcess alone does not prompt under the default
    $ConfirmPreference.

    The body is REQUIRED rather than optional even though Graph accepts an empty one. keepUserData
    and keepEnrollmentData default to false server-side, so an empty body is the most destructive
    possible call - and it is the one a caller writes by accident. Forcing the body makes the
    caller state what they intend to keep.

    PERMISSION VERIFIED, OPERATION DELIBERATELY NOT. The sibling device actions return 403 with a
    ReadWrite.All token, confirming PrivilegedOperations.All is genuinely required. This one will
    not be live-verified at all: there is no safe way to prove a factory reset works except by
    factory-resetting something.

    What IS verified live is the GATE. Against a real device id in the lab tenant, -WhatIf printed
    the request and sent nothing, and the call without -Force was refused with
    GraphKit.HighImpactConfirmationRequired. The protection is proven even though the operation is
    not.
#>
@{
    SchemaVersion       = 1

    Type                = 'ManagedDevice'
    Operation           = 'Wipe'
    OperationKind       = 'Action'
    HandlerStrategyId   = 'Action.Default'

    ApiVersion          = 'v1.0'
    Stability           = 'Stable'
    BetaReason          = $null

    Method              = 'POST'
    PathTemplate        = '/deviceManagement/managedDevices/{id}/wipe'
    RequestBodyKind     = 'ManagedDeviceWipeOptions'
    ResponseKind        = 'NoContent'
    PagingStrategy      = 'None'
    RequiredPagingHeaders = @()
    DeduplicationKey    = $null
    SupportsAll         = $false
    SupportsDelta       = $false

    ReplayPolicy        = 'NeverReplay'
    Impact              = 'High'
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
