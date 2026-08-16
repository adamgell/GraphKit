<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    Tenant-wide directory settings - the instantiated setting templates covering consent policy,
    password protection, and guest/group ownership behaviour.

    ONE unparameterized list, not a lookup per template. /settings returns every instantiated
    template as a row carrying its own templateId, so a caller filters client-side on templateId
    rather than issuing a request per template. Getting this wrong costs a request per template
    and returns the same data.

    A row is { id, templateId, displayName, values: [ { name, value } ] } - the settings are a
    name/value array inside the row, not top-level properties, so a consumer reads
    values | Where-Object name -eq '<SettingName>'.

    No query options: /settings does not support $filter or $select, so AdvancedQuery stays
    unsupported and Resolve-GraphUri refuses them rather than passing them through to be ignored.
#>
@{
    SchemaVersion       = 1

    Type                = 'DirectorySetting'
    Operation           = 'List'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaOnly'
    BetaReason          = 'Directory settings are exposed as /settings only on beta; v1.0 offers groupSettings, which is a different and narrower surface.'

    Method              = 'GET'
    PathTemplate        = '/settings'
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

    ResourceFamily      = 'Directory.Organization'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'Directory.Read.All' }
    )
    RequiredLicense     = @()
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
