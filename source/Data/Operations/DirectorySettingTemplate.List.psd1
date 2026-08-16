<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    The directory setting TEMPLATES available in the tenant, with each setting's default value.

    This is the companion to DirectorySetting.List and a consumer checking tenant configuration
    needs both, because /settings returns only settings that have been INSTANTIATED. Verified
    against a live tenant: 10 templates are available while just one (Group.Unified) had ever been
    instantiated, so "Password Rule Settings" and "Consent Policy Settings" were absent from
    /settings entirely.

    Absence therefore means THE TEMPLATE DEFAULTS APPLY - not that the tenant is unconfigured and
    not that it is non-compliant. A check that reads a missing row as a failure reports false
    non-compliance on every tenant that never customised the setting, which is most of them. This
    operation supplies the defaults needed to resolve that correctly.

    A row is { id, displayName, description, values: [ { name, type, defaultValue, description } ] }.
#>
@{
    SchemaVersion       = 1

    Type                = 'DirectorySettingTemplate'
    Operation           = 'List'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaOnly'
    BetaReason          = 'Directory setting templates are exposed only on beta; v1.0 offers groupSettingTemplates, a narrower surface.'

    Method              = 'GET'
    PathTemplate        = '/directorySettingTemplates'
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
