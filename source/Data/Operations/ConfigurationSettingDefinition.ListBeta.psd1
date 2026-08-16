<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    The Settings Catalog definition corpus - what every setting MEANS, as opposed to what a
    policy sets. Join to ConfigurationPolicySetting.ListBeta on the setting definition id.

    TWO THINGS WILL BITE A CALLER HERE, and both are declared rather than documented:

      1. NEVER $select. The response is a polymorphic base type, and $select naming a
         sub-type-only field (options, for instance) is rejected by the service. AdvancedQuery
         declares Supported = $false, so Resolve-GraphUri REFUSES a query option rather than
         forwarding it - a loud error at the call site instead of a service-side rejection that
         reads like a permissions problem. This is the mirror of Organization/GetMdmAuthority:
         there the $select is mandatory and lives in the path; here it must never appear.

      2. IT CURRENTLY FAILS AT GRAPHKIT'S DEFAULTS, and the reason is measured rather than
         guessed. Verified against a live tenant on 2026-08-15: this endpoint returns the entire
         corpus in ONE page - 18,227 items, 55,164,526 bytes, no nextLink - and takes about 16
         seconds just to transfer. The transport's body-read phase timeout
         (TimeoutBodySeconds) is 30 seconds and is not currently plumbed through the public
         API, so the read is cancelled mid-body and reported as Outcome Failed with Certainty
         Indeterminate. That reporting is right - a body truncated by a client-side timeout
         genuinely leaves the outcome unknown - but it means this operation cannot succeed
         until the timeout is configurable. -PageCap does not help: the failure is on the first
         page, not on paging depth.

         Resolving it is a design decision: a descriptor field for the expected body timeout is
         the natural fit, since "this operation returns tens of megabytes" is an operation fact
         like any other, but it touches both the schema and the transport.
#>
@{
    SchemaVersion       = 1

    Type                = 'ConfigurationSettingDefinition'
    Operation           = 'ListBeta'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaOnly'
    BetaReason          = 'The Settings Catalog definition corpus exists only on beta.'

    Method              = 'GET'
    PathTemplate        = '/deviceManagement/configurationSettings'
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
