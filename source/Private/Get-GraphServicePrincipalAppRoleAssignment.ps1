<#
    Customer-tenant permission reads and app-role assignment resolution (phase 3).

    The application object lives only in the app's home tenant; the service
    principal and its grants live in the customer tenant. These helpers read the
    customer-tenant side: the service principal by appId, its appRoleAssignments,
    its delegated oauth2PermissionGrants, and the resolution of each appRoleId
    against the Microsoft Graph service principal's appRoles (via
    Get-GraphAppRoleCatalog, which is cached per tenant for the session).

    All reads go through the normal pipeline (Invoke-GraphDirectoryRead ->
    Invoke-GraphRetry), never around it, and never via token claims.
#>

function Get-GraphAppRoleAssignments {
    # Reads the raw appRoleAssignments collection for a service principal. The
    # returned entries carry appRoleId (an opaque GUID), principalId and
    # resourceId; value resolution happens in
    # Get-GraphServicePrincipalAppRoleAssignment, not here.
    param(
        [Parameter(Mandatory = $true)]
        [object] $Context,

        [Parameter(Mandatory = $true)]
        [string] $ServicePrincipalId
    )

    $pathAndQuery = '/v1.0/servicePrincipals/{0}/appRoleAssignments' -f $ServicePrincipalId
    $uri = Get-GraphDirectoryUri -Context $Context -PathAndQuery $pathAndQuery

    $data = Invoke-GraphDirectoryRead -Context $Context -Uri $uri -ResourceFamily 'Directory.AppRoleAssignments'

    if ($null -ne $data -and $null -ne $data.value) {
        return @($data.value)
    }

    return @()
}

function Get-GraphOauth2PermissionGrants {
    # Reads the delegated grants (oauth2PermissionGrants) held by a client service
    # principal. These are separate from app-role assignments and are the only
    # delegated-permission inventory consulted; token scp claims are not.
    param(
        [Parameter(Mandatory = $true)]
        [object] $Context,

        [Parameter(Mandatory = $true)]
        [string] $ClientServicePrincipalId
    )

    $pathAndQuery = "/v1.0/oauth2PermissionGrants?`$filter=clientId eq '{0}'" -f $ClientServicePrincipalId
    $uri = Get-GraphDirectoryUri -Context $Context -PathAndQuery $pathAndQuery

    $data = Invoke-GraphDirectoryRead -Context $Context -Uri $uri -ResourceFamily 'Directory.Oauth2PermissionGrants'

    if ($null -ne $data -and $null -ne $data.value) {
        return @($data.value)
    }

    return @()
}

function Get-GraphServicePrincipalAppRoleAssignment {
    # Resolves the customer-tenant service principal by appId and returns a
    # record with the principal plus its app-role assignments, each resolved
    # against the Microsoft Graph service principal's appRoles. A missing
    # principal yields ServicePrincipal = $null (an absence finding upstream, not
    # an error). Assignments whose appRoleId is not a Graph app role carry
    # AppRoleValue = $null and are ignored by Graph-permission analysis.
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [object] $Context,

        [Parameter(Mandatory = $true)]
        [string] $TargetAppId
    )

    $principal = Get-GraphServicePrincipalByAppId -Context $Context -AppId $TargetAppId

    if ($null -eq $principal) {
        return [PSCustomObject] @{
            PSTypeName        = 'GraphKit.ServicePrincipalAppRoleAssignment'
            ServicePrincipal  = $null
            AppRoleAssignments = @()
        }
    }

    $catalog = @(Get-GraphAppRoleCatalog -Context $Context)
    $valueById = @{}
    foreach ($role in $catalog) {
        if ($null -ne $role.id) {
            $valueById[[string] $role.id] = [string] $role.value
        }
    }

    $rawAssignments = @(Get-GraphAppRoleAssignments -Context $Context -ServicePrincipalId ([string] $principal.id))

    $resolved = foreach ($assignment in $rawAssignments) {
        $appRoleId = [string] $assignment.appRoleId
        $value = $null
        if ($valueById.ContainsKey($appRoleId)) {
            $value = $valueById[$appRoleId]
        }

        [PSCustomObject] @{
            AppRoleId           = $appRoleId
            AppRoleValue        = $value
            PrincipalId         = [string] $assignment.principalId
            PrincipalType       = [string] $assignment.principalType
            ResourceId          = [string] $assignment.resourceId
            ResourceDisplayName = [string] $assignment.resourceDisplayName
            CreatedDateTime     = [string] $assignment.createdDateTime
        }
    }

    return [PSCustomObject] @{
        PSTypeName         = 'GraphKit.ServicePrincipalAppRoleAssignment'
        ServicePrincipal   = $principal
        AppRoleAssignments = @($resolved)
    }
}

function Test-GraphProfileAppOnly {
    # True when the context's token source uses a client-credentials flow
    # (Certificate / ClientSecret / ManagedIdentity) that can only exercise
    # application permissions; false for flows that may be delegated; $null when
    # the auth mode cannot be determined (no token source, or an unknown mode).
    param(
        [Parameter(Mandatory = $true)]
        [object] $Context
    )

    if ($null -eq $Context.TokenSource) {
        return $null
    }

    $mode = [string] $Context.TokenSource.AuthMode
    if ($mode -in @('Certificate', 'ClientSecret', 'ManagedIdentity')) {
        return $true
    }

    if ($mode -in @('BearerToken', 'Provider')) {
        return $false
    }

    return $null
}

function New-GraphPermissionFinding {
    # A single permission finding: a PSTypeName 'GraphKit.PermissionFinding'
    # record with the stable finding id, its value, a human detail, and the
    # target tenant + application it describes. Never carries credentials or raw
    # query values.
    param(
        [Parameter(Mandatory = $true)]
        [string] $Finding,

        [Parameter(Mandatory = $true)]
        [string] $Value,

        [Parameter(Mandatory = $true)]
        [string] $Detail,

        [AllowEmptyString()]
        [string] $TargetTenantId,

        [AllowEmptyString()]
        [string] $TargetAppId
    )

    return [PSCustomObject] @{
        PSTypeName     = 'GraphKit.PermissionFinding'
        Finding        = $Finding
        Value          = $Value
        Detail         = $Detail
        TargetTenantId = $TargetTenantId
        TargetAppId    = $TargetAppId
    }
}
