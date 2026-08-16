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

      2. IT CURRENTLY FAILS AT GRAPHKIT'S DEFAULTS, and the cause is the HEADERS timeout,
         not the body timeout. Measured against a live tenant on 2026-08-15, three runs:

             time to first byte : 10.5 - 13.5 s   <-- the bottleneck
             body read          :  2.7 -  2.8 s
             UTF8 decode        :  ~0 s
             JSON parse         :  1.0 -  1.3 s
             total              : 14.2 - 17.6 s
             payload            : 18,227 items, 55,164,526 bytes, ONE page, no nextLink

         The service takes 10-13 seconds to begin responding because it composes the whole
         corpus before sending. TimeoutHeadersSeconds defaults to 10, so the request is
         cancelled before the first byte arrives: StatusCode 0, a transport exception, and a
         correctly Indeterminate outcome. TimeoutBodySeconds (30) is never reached - the body
         transfers in under three seconds.

         Proven by calling the transport directly: headers timeout 10 gives StatusCode 0;
         headers timeout 45 gives StatusCode 200 and all 18,227 items.

         So -PageCap is irrelevant here (there is no second page), and raising the body timeout
         would change nothing. What this operation needs is a per-operation headers timeout of
         roughly 60 seconds - about 4x the observed worst case, since a tenant with more
         settings or a slower link will be slower than the lab. Raising the GLOBAL default is
         the wrong fix: a 10-second time-to-first-byte limit is worth keeping for every other
         operation, and a hung endpoint should fail fast.

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
