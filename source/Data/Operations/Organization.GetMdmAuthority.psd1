<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    The tenant's mobile device management authority - 'intune', 'sccm', 'office365',
    'unknown', or 'none'. This is the onboarding-hygiene signal; it is NOT available from
    Organization.List.

    Three facts about this property, each verified against a live tenant on 2026-08-15, and all
    three are why this needs its own operation rather than a field on the organization record:

      1. It is exposed on the ENTITY, not the collection. GET /organization returns 28 properties
         at v1.0 and 29 at beta, and mobileDeviceManagementAuthority is in neither.
      2. It is select-only. GET /organization/{id} without $select returns 30 properties and
         still omits it - a workload-extension property is materialised only when named.
      3. It is NOT beta-only. v1.0/organization/{id}?$select=... returns it, so there is no
         reason to take a beta dependency for this signal.

    The $select is therefore part of the operation's identity and lives in the PathTemplate. A
    caller who forgets it does not get an error - they get an object without the property, which
    reads as "no authority configured" and is exactly the silent-nothing outcome this catalog
    exists to prevent.

    The {id} is the organization id, which equals the tenant id.
#>
@{
    SchemaVersion       = 1

    Type                = 'Organization'
    Operation           = 'GetMdmAuthority'
    OperationKind       = 'Singleton'
    HandlerStrategyId   = 'Singleton.Default'

    ApiVersion          = 'v1.0'
    Stability           = 'Stable'
    BetaReason          = $null

    Method              = 'GET'
    PathTemplate        = '/organization/{id}?$select=mobileDeviceManagementAuthority'
    RequestBodyKind     = $null
    ResponseKind        = 'Json'
    PagingStrategy      = 'None'
    RequiredPagingHeaders = @()
    DeduplicationKey    = $null
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

    ResourceFamily      = 'Directory.Organization'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'Organization.Read.All' }
    )
    RequiredLicense     = @()
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
