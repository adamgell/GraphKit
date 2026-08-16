<#
    Operation descriptor - data only. Loaded with Import-PowerShellDataFile.

    The values supplied to one Administrative Template setting - the third and last level of the
    admin-template walk. Takes TWO path parameters:

        id                  the groupPolicyConfiguration id  (GroupPolicyConfiguration.ListBeta)
        definitionValueId   the definitionValue id           (GroupPolicyDefinitionValue.ListBeta)

    Resolve-GraphUri substitutes every {token} it finds by name, so multi-level parameterization
    needs nothing special beyond distinct token names; a token that is not supplied is an error
    naming the token, not a literal '{definitionValueId}' sent to Graph.

    $expand=presentation is LOAD-BEARING and fixed for the same reason as the definitionValue
    $expand: without it a presentationValue carries a value and an id with no label, so there is
    no way to tell which field of the setting it filled in.

    LIVE-VERIFIED end to end against a populated response, via a fixture policy created in the
    lab tenant for this purpose ("GraphKit verification fixture - do not deploy", unassigned,
    left in place). Two presentation value types were exercised:

        groupPolicyPresentationValueText     value = a string
        groupPolicyPresentationValueDecimal  value = a number

    A populated row carries: @odata.type, createdDateTime, id, lastModifiedDateTime,
    presentation, value. The expanded 'presentation' carries @odata.type, defaultValue, id,
    label, lastModifiedDateTime, required, plus type-specific fields - maxLength for a text box,
    minValue/maxValue/spin/spinStep for a decimal one.

    The $expand being load-bearing is measured: the same request without it returns HTTP 200 and
    the identical row MINUS the 'presentation' key, so the value survives and the label that says
    what it means does not.

    A presentationValue's 'value' is whatever the ADMX author declared - text, decimal, list.
    Administrative templates configure Windows components rather than storing credentials, so
    nothing is declared sensitive here; if a customer template turns out to carry a secret in a
    text presentation, the declaration belongs on THIS descriptor and the change is one line.
#>
@{
    SchemaVersion       = 1

    Type                = 'GroupPolicyPresentationValue'
    Operation           = 'ListBeta'
    OperationKind       = 'Collection'
    HandlerStrategyId   = 'Collection.Default'

    ApiVersion          = 'beta'
    Stability           = 'BetaOnly'
    BetaReason          = 'Administrative Template policies are exposed only on beta; the v1.0 path does not exist.'

    Method              = 'GET'
    PathTemplate        = '/deviceManagement/groupPolicyConfigurations/{id}/definitionValues/{definitionValueId}/presentationValues?$expand=presentation'
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

    ResourceFamily      = 'Intune.GroupPolicy'
    ThrottleClass       = 'Read'

    SupportedAuthModes  = @('Certificate', 'ClientSecret', 'ManagedIdentity')
    RequiredPermissions = @(
        @{ Type = 'Application'; Value = 'DeviceManagementConfiguration.Read.All' }
    )
    RequiredLicense     = @('Microsoft Intune')
    SupportedClouds     = @('Global', 'USGov', 'USGovDoD')
}
