function Get-GraphAppRegistrationPermission {
    <#
        .SYNOPSIS
            Returns the application permissions a target app registration requests in its home tenant.

        .DESCRIPTION
            Reads the home-tenant application object's requiredResourceAccess collection and returns the
            application (app-role) permissions it requests from Microsoft Graph, resolved from the opaque
            appRoleId back to the stable permission value via the session-scoped Graph appRoles catalog.
            requiredResourceAccess proves only that the registration requests a permission, never that it
            was consented or granted; the customer-tenant grants are a separate read (see Test-GraphPermission).
            The application object exists only in its home tenant, so the supplied context must be the home
            tenant: when the object cannot be found there, the command throws an actionable error naming the
            home-tenant requirement rather than returning an empty set and implying no permissions.

        .EXAMPLE
            $configured = Get-GraphAppRegistrationPermission -Context $homeContext -TargetAppId '11111111-2222-3333-4444-555555555555'

            Resolves the home-tenant context and lists the Graph application permissions that app registration requests.

        .PARAMETER Context
            The immutable GraphKit context for the application's home tenant (the tenant that owns the
            application object). The customer-tenant context cannot see this object and must not be used here.

        .PARAMETER TargetAppId
            The application (client) id of the registration to inspect. This selects the home-tenant
            application object by its appId; the display name is never a selector.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]], [object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [object] $Context,

        [Parameter(Mandatory = $true)]
        [guid] $TargetAppId
    )

    $appId = $TargetAppId.ToString()

    $pathAndQuery = "/v1.0/applications?`$filter=appId eq '{0}'&`$select=id,appId,requiredResourceAccess" -f $appId
    $uri = Get-GraphDirectoryUri -Context $Context -PathAndQuery $pathAndQuery

    $data = Invoke-GraphDirectoryRead -Context $Context -Uri $uri -ResourceFamily 'Directory.Applications'

    if ($null -eq $data -or $null -eq $data.value -or @($data.value).Count -eq 0) {
        throw (
            "No application registration with appId '{0}' was found in the context tenant '{1}'. " +
            "The application object exists only in its home tenant; confirm the supplied context targets " +
            "the application's home tenant (a customer-tenant context cannot read this object)." -f
            $appId, $Context.TenantId
        )
    }

    $application = @($data.value)[0]

    $catalog = @(Get-GraphAppRoleCatalog -Context $Context)
    $valueById = @{}
    foreach ($role in $catalog) {
        if ($null -ne $role.id) {
            $valueById[[string] $role.id] = [string] $role.value
        }
    }

    $configured = [System.Collections.Generic.List[object]]::new()

    if ($null -ne $application.requiredResourceAccess) {
        foreach ($resource in @($application.requiredResourceAccess)) {
            if ([string]::Equals(
                    [string] $resource.resourceAppId,
                    $script:GraphServicePrincipalAppId,
                    [System.StringComparison]::OrdinalIgnoreCase)) {
                foreach ($access in @($resource.resourceAccess)) {
                    if ([string] $access.type -ne 'Role') {
                        continue
                    }

                    $roleId = [string] $access.id
                    $value = $null
                    if ($valueById.ContainsKey($roleId)) {
                        $value = $valueById[$roleId]
                    }

                    [void] $configured.Add([PSCustomObject] @{
                            Type  = 'Application'
                            Value = $value
                            Id    = $roleId
                        })
                }
            }
        }
    }

    return @($configured)
}
