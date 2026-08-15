function Grant-GraphAppPermission {
    <#
        .SYNOPSIS
            Grants application permissions to a target application in its customer tenant.

        .DESCRIPTION
            Grants Graph application (app-role) permissions to a target application by computing the diff
            between the requested permission set and the assignments already present on the customer-tenant
            service principal, then applying only the missing grants through the normal Graph request
            pipeline. The operation is idempotent: re-running with the same permission set grants nothing
            already present. It declares SupportsShouldProcess and names the target tenant and application in
            its ShouldProcess message, so -WhatIf reports the grants it would apply without sending anything.
            Each permission is a hashtable with Type = 'Application' and a Value naming a Graph application
            permission (for example 'DeviceManagementManagedDevices.Read.All'); the appRoleId is resolved
            from the session-scoped Microsoft Graph appRoles catalog rather than taken from token claims.

        .EXAMPLE
            Grant-GraphAppPermission -Context $customer -TargetAppId '11111111-2222-3333-4444-555555555555' -Permission @(
                @{ Type = 'Application'; Value = 'DeviceManagementManagedDevices.Read.All' }
            )

            Computes the missing grant and assigns it to the application's customer-tenant service principal.

        .EXAMPLE
            Grant-GraphAppPermission -Context $customer -TargetAppId '11111111-2222-3333-4444-555555555555' -Permission $desired -WhatIf

            Reports the grants that would be applied without issuing a single request.

        .PARAMETER Context
            The immutable GraphKit context for the customer tenant that owns the application's service
            principal and will receive the app-role assignments.

        .PARAMETER TargetAppId
            The application (client) id of the registration to grant permissions to. The customer-tenant
            service principal is located by this appId; display names are never selectors.

        .PARAMETER Permission
            The application permissions to ensure are granted, as an array of hashtables each carrying
            Type = 'Application' and a Value naming a Microsoft Graph application permission. Only missing
            grants are applied; already-granted entries are left untouched.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([PSCustomObject[]], [object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [object] $Context,

        [Parameter(Mandatory = $true)]
        [guid] $TargetAppId,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [hashtable[]] $Permission
    )

    $appId = $TargetAppId.ToString()
    $tenantId = [string] $Context.TenantId

    # 1. Validate and normalize the requested permission set.
    $requested = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $Permission) {
        $normalized = Get-GraphPermissionEntry -Entry $entry
        if ($null -eq $normalized -or [string]::IsNullOrWhiteSpace($normalized.Value)) {
            throw 'Each -Permission entry must carry a Value naming a Microsoft Graph application permission.'
        }

        if (-not [string]::Equals($normalized.Type, 'Application', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw (
                "Permission '{0}' has Type '{1}'; only Type 'Application' permissions can be granted." -f
                $normalized.Value, $normalized.Type
            )
        }

        [void] $requested.Add($normalized)
    }

    # 2. Resolve the customer service principal (the grantee) and the Graph
    #    service principal (the resource) plus its appRoles catalog.
    $customerPrincipal = Get-GraphServicePrincipalByAppId -Context $Context -AppId $appId
    if ($null -eq $customerPrincipal) {
        throw (
            "No service principal for appId '{0}' exists in tenant '{1}'; cannot grant permissions to a missing principal." -f
            $appId, $tenantId
        )
    }

    $graphPrincipal = Get-GraphServicePrincipalByAppId -Context $Context -AppId $script:GraphServicePrincipalAppId
    if ($null -eq $graphPrincipal) {
        throw "The Microsoft Graph service principal could not be resolved in tenant '{0}'." -f $tenantId
    }

    $catalog = @(Get-GraphAppRoleCatalog -Context $Context)
    $idByValue = @{}
    foreach ($role in $catalog) {
        if ($null -ne $role.value) {
            $idByValue[[string] $role.value] = [string] $role.id
        }
    }

    # 3. Resolve each requested permission to its appRoleId and compute the diff
    #    against the assignments already present (idempotent: already-granted
    #    roles are never re-applied).
    $existingAssignments = @(Get-GraphAppRoleAssignments -Context $Context -ServicePrincipalId ([string] $customerPrincipal.id))
    $alreadyGranted = @($existingAssignments | ForEach-Object { [string] $_.appRoleId })

    $toGrant = [System.Collections.Generic.List[object]]::new()
    foreach ($request in $requested) {
        if (-not $idByValue.ContainsKey($request.Value)) {
            throw (
                "Permission '{0}' is not a known Microsoft Graph application permission in tenant '{1}'." -f
                $request.Value, $tenantId
            )
        }

        $appRoleId = $idByValue[$request.Value]
        if ($alreadyGranted -notcontains $appRoleId) {
            [void] $toGrant.Add([PSCustomObject] @{
                    Value       = $request.Value
                    AppRoleId   = $appRoleId
                    ResourceId  = [string] $graphPrincipal.id
                    PrincipalId = [string] $customerPrincipal.id
                })
        }
    }

    # 4. Apply only the missing grants through the normal pipeline.
    $descriptor = @{
        CredentialPolicy    = 'GraphBearer'
        AllowedHosts        = @()
        ApiVersion          = 'v1.0'
        Stability           = 'Stable'
        BetaReason          = $null
        ResourceFamily      = 'Directory.AppRoleAssignments'
        ThrottleClass       = 'Write'
        ReplayPolicy        = 'NeverReplay'
        IdentityRequirement = 'Verified'
    }

    $applied = [System.Collections.Generic.List[object]]::new()

    foreach ($grant in $toGrant) {
        $target = "tenant '{0}' application '{1}'" -f $tenantId, $appId
        $action = "grant application permission '{0}'" -f $grant.Value

        if ($PSCmdlet.ShouldProcess($target, $action)) {
            $uri = Get-GraphDirectoryUri `
                -Context $Context `
                -PathAndQuery ('/v1.0/servicePrincipals/{0}/appRoleAssignments' -f $grant.ResourceId)

            $body = @{
                principalId = $grant.PrincipalId
                resourceId  = $grant.ResourceId
                appRoleId   = $grant.AppRoleId
            }

            $envelope = Invoke-GraphRetry `
                -Context $Context `
                -Descriptor $descriptor `
                -Uri $uri `
                -Method 'POST' `
                -Headers @{} `
                -Body $body `
                -CancellationToken ([System.Threading.CancellationToken]::None)

            if ($null -eq $envelope -or $envelope.Outcome -ne 'Succeeded') {
                throw (
                    "Failed to grant application permission '{0}' to appId '{1}' in tenant '{2}'." -f
                    $grant.Value, $appId, $tenantId
                )
            }

            [void] $applied.Add($grant)
        }
    }

    return @($applied)
}
