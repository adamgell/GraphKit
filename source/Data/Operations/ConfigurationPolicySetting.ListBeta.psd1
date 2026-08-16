<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    The settings inside one Settings Catalog policy. Requires an {id} parameter - the policy id
    from ConfigurationPolicy.ListBeta.

    Returns settingInstances, whose shape is polymorphic per setting type, so this is paged
    normally but deliberately declares no advanced query support: a $select against a
    polymorphic base type is rejected by the service for sub-type-only fields.
    Setting values live under settingInstance.groupSettingCollectionValue, which is where a
    Wi-Fi pre-shared key or VPN secret appears. The declaration is a dotted path on purpose:
    declaring settingInstance wholesale would redact settingDefinitionId and the rest of the
    branch too, leaving a row that says nothing about which setting it described. Verified
    against a live tenant - settingInstance carries @odata.type, auditRuleInformation,
    groupSettingCollectionValue, settingDefinitionId and settingInstanceTemplateReference.
#>
@{
    SchemaVersion       = 1

    Type                = 'ConfigurationPolicySetting'
    Operation           = 'ListBeta'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaOnly'
    BetaReason          = 'The settings expansion of a Settings Catalog policy exists only on beta.'

    Method              = 'GET'
    PathTemplate        = '/deviceManagement/configurationPolicies/{id}/settings'
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

    SensitiveProperties = @('settingInstance.groupSettingCollectionValue')

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementConfiguration.Read.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
