function Test-GraphPermission {
    <#
        .SYNOPSIS
            Analyzes a target application's permission state across its home and customer tenants.

        .DESCRIPTION
            Computes the four permission states for a target application registration: Configured (from the
            home-tenant application object's requiredResourceAccess), Granted (from the customer-tenant
            service principal's app-role assignments, resolved against the Microsoft Graph appRoles),
            Excess/Missing relative to a baseline catalog, and AuthenticationCompatible. Configured is
            tri-state: Yes, No, or Unknown when no home-tenant context is supplied. The command emits one
            GraphKit.PermissionFinding record per finding - Configured, Granted, ExcessGranted,
            MissingGrant and AuthenticationCompatible always, plus ConfiguredButNotGranted,
            GrantedButNotConfigured, DelegatedGrantPresent, ServicePrincipalMissing and BetaOnlyRequired
            when relevant. Directory reads are the source of truth; access-token claims are never consulted.
            When the analyzer's own identity lacks Application.Read.All or Directory.Read.All in the customer
            tenant, the command throws an actionable bootstrap-trap error naming that prerequisite.

        .EXAMPLE
            Test-GraphPermission -Context $customer -TargetAppId '11111111-2222-3333-4444-555555555555' -HomeTenantContext $home -Baseline $catalog

            Emits one finding per permission state, comparing the granted set against the configured set and the operation-catalog baseline.

        .EXAMPLE
            Test-GraphPermission -ProfileId acme -TargetAppId '11111111-2222-3333-4444-555555555555'

            Runs the analysis with no home-tenant context, so the Configured finding reports Unknown rather than guessing No.

        .PARAMETER Context
            The immutable GraphKit context for the customer tenant, whose service principal and grants are
            analyzed. Mutually exclusive with -ProfileId; supply exactly one.

        .PARAMETER ProfileId
            The canonical profile identifier to resolve into the customer-tenant context via Get-GraphContext.
            Mutually exclusive with -Context; supply exactly one.

        .PARAMETER TargetAppId
            The application (client) id of the registration under analysis. The same id selects the
            home-tenant application object and the customer-tenant service principal; display names never do.

        .PARAMETER HomeTenantContext
            The immutable GraphKit context for the application's home tenant, or $null. When omitted or
            $null the Configured state is reported as Unknown rather than an invented No.

        .PARAMETER Baseline
            The expected permission catalog: an array of permission entries (@{ Type; Value }) and/or
            operation descriptors carrying RequiredPermissions and an optional Stability. Application
            entries define the expected grants; a descriptor with Stability 'BetaOnly' produces a
            BetaOnlyRequired finding naming that operation.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Context')]
    [OutputType([PSCustomObject[]], [object[]])]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Context', Position = 0)]
        [object] $Context,

        [Parameter(Mandatory = $true, ParameterSetName = 'ProfileId', Position = 0)]
        [string] $ProfileId,

        [Parameter(Mandatory = $true)]
        [guid] $TargetAppId,

        [AllowNull()]
        [object] $HomeTenantContext,

        [AllowEmptyCollection()]
        [object[]] $Baseline = @()
    )

    # 1. Resolve the customer-tenant context: exactly one of -Context / -ProfileId.
    if ($PSBoundParameters.ContainsKey('ProfileId')) {
        if ($null -ne $Context) {
            throw 'Provide either -Context or -ProfileId, not both.'
        }
        $Context = Get-GraphContext -ProfileId $ProfileId
    }

    if ($null -eq $Context) {
        throw 'Provide either -Context or -ProfileId.'
    }

    $tenantId = [string] $Context.TenantId
    $appId = $TargetAppId.ToString()
    $findings = [System.Collections.Generic.List[object]]::new()

    # 2. Normalize the baseline: flatten operation descriptors into permission
    #    entries and remember beta-only operations.
    $expected = [System.Collections.Generic.List[object]]::new()
    $betaOnly = [System.Collections.Generic.List[string]]::new()

    foreach ($entry in $Baseline) {
        if ($null -eq $entry) {
            continue
        }

        if ($entry -is [System.Collections.IDictionary] -and $entry.ContainsKey('RequiredPermissions')) {
            foreach ($permission in @($entry['RequiredPermissions'])) {
                if ($null -ne $permission) {
                    [void] $expected.Add($permission)
                }
            }

            if ([string] $entry['Stability'] -eq 'BetaOnly') {
                [void] $betaOnly.Add(('{0}/{1}' -f $entry['Type'], $entry['Operation']))
            }
        } else {
            [void] $expected.Add($entry)
        }
    }

    $expectedApp = @(
        $expected |
            Where-Object { (Get-GraphPermissionEntry -Entry $_).Type -eq 'Application' }
    )

    # 3. Configured: tri-state, Unknown when no home-tenant context is available.
    $configured = $null
    $configuredApp = @()

    if ($null -eq $HomeTenantContext) {
        [void] $findings.Add((New-GraphPermissionFinding `
                    -Finding 'Configured' `
                    -Value 'Unknown' `
                    -Detail 'No home-tenant context was supplied, so requiredResourceAccess could not be read.' `
                    -TargetTenantId $tenantId `
                    -TargetAppId $appId))
    } else {
        $configured = @(Get-GraphAppRegistrationPermission -Context $HomeTenantContext -TargetAppId $TargetAppId)
        $configuredApp = @(
            $configured |
                Where-Object { (Get-GraphPermissionEntry -Entry $_).Type -eq 'Application' }
        )

        if ($configuredApp.Count -eq 0) {
            [void] $findings.Add((New-GraphPermissionFinding `
                        -Finding 'Configured' `
                        -Value 'No' `
                        -Detail 'No Graph application permissions are requested in requiredResourceAccess.' `
                        -TargetTenantId $tenantId `
                        -TargetAppId $appId))
        } else {
            [void] $findings.Add((New-GraphPermissionFinding `
                        -Finding 'Configured' `
                        -Value 'Yes' `
                        -Detail ('{0} Graph application permission(s) requested.' -f $configuredApp.Count) `
                        -TargetTenantId $tenantId `
                        -TargetAppId $appId))
        }
    }

    # 4. Granted: customer-tenant service principal + app-role assignments.
    $resolved = Get-GraphServicePrincipalAppRoleAssignment -Context $Context -TargetAppId $appId
    $servicePrincipal = $resolved.ServicePrincipal

    $granted = @()
    $delegated = @()

    if ($null -eq $servicePrincipal) {
        [void] $findings.Add((New-GraphPermissionFinding `
                    -Finding 'ServicePrincipalMissing' `
                    -Value 'Yes' `
                    -Detail ('No service principal for the application exists in tenant {0}.' -f $tenantId) `
                    -TargetTenantId $tenantId `
                    -TargetAppId $appId))
    } else {
        $granted = @(
            $resolved.AppRoleAssignments |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_.AppRoleValue) } |
                ForEach-Object {
                    [PSCustomObject] @{
                        Type  = 'Application'
                        Value = $_.AppRoleValue
                        Id    = $_.AppRoleId
                    }
                }
        )

        $delegated = @(Get-GraphOauth2PermissionGrants -Context $Context -ClientServicePrincipalId ([string] $servicePrincipal.id))
    }

    [void] $findings.Add((New-GraphPermissionFinding `
                -Finding 'Granted' `
                -Value $(if ($granted.Count -gt 0) { 'Yes' } else { 'No' }) `
                -Detail ('{0} Graph application permission(s) granted in the customer tenant.' -f $granted.Count) `
                -TargetTenantId $tenantId `
                -TargetAppId $appId))

    # 5. Excess / missing against the baseline catalog.
    $baselineComparison = Compare-GraphPermission -Baseline $expectedApp -Actual $granted

    [void] $findings.Add((New-GraphPermissionFinding `
                -Finding 'ExcessGranted' `
                -Value (Format-GraphPermissionList -Entries $baselineComparison.Extra) `
                -Detail 'Granted application permissions not present in the baseline catalog.' `
                -TargetTenantId $tenantId `
                -TargetAppId $appId))

    [void] $findings.Add((New-GraphPermissionFinding `
                -Finding 'MissingGrant' `
                -Value (Format-GraphPermissionList -Entries $baselineComparison.Missing) `
                -Detail 'Baseline application permissions not granted in the customer tenant.' `
                -TargetTenantId $tenantId `
                -TargetAppId $appId))

    # 6. Configured-but-not-granted / granted-but-no-longer-configured. Only
    #    determinable when the configured set is known (a home-tenant context was
    #    supplied); a missing home context cannot distinguish them.
    if ($null -ne $configured) {
        $configuredComparison = Compare-GraphPermission -Baseline $configuredApp -Actual $granted

        if (@($configuredComparison.Missing).Count -gt 0) {
            [void] $findings.Add((New-GraphPermissionFinding `
                        -Finding 'ConfiguredButNotGranted' `
                        -Value (Format-GraphPermissionList -Entries $configuredComparison.Missing) `
                        -Detail 'Application permissions configured in the home tenant but not granted in the customer tenant.' `
                        -TargetTenantId $tenantId `
                        -TargetAppId $appId))
        }

        if (@($configuredComparison.Extra).Count -gt 0) {
            [void] $findings.Add((New-GraphPermissionFinding `
                        -Finding 'GrantedButNotConfigured' `
                        -Value (Format-GraphPermissionList -Entries $configuredComparison.Extra) `
                        -Detail 'Application permissions granted in the customer tenant but no longer configured in the home tenant.' `
                        -TargetTenantId $tenantId `
                        -TargetAppId $appId))
        }
    }

    # 7. Delegated grants vs app-only profile, and authentication compatibility.
    $appOnly = Test-GraphProfileAppOnly -Context $Context

    if (@($delegated).Count -gt 0 -and $appOnly -eq $true) {
        [void] $findings.Add((New-GraphPermissionFinding `
                    -Finding 'DelegatedGrantPresent' `
                    -Value 'Yes' `
                    -Detail 'Delegated oauth2PermissionGrants exist but the profile authenticates app-only, so they cannot be exercised.' `
                    -TargetTenantId $tenantId `
                    -TargetAppId $appId))
    }

    $hasApplicationGrant = $granted.Count -gt 0
    $hasDelegatedGrant = @($delegated).Count -gt 0

    $authenticationCompatible = 'Unknown'
    if ($null -eq $appOnly) {
        $authenticationCompatible = 'Unknown'
    } elseif ($appOnly) {
        # App-only flows exercise application permissions only.
        $authenticationCompatible = if ($hasApplicationGrant) { 'Yes' } elseif ($hasDelegatedGrant) { 'No' } else { 'Unknown' }
    } else {
        # Delegated-capable flows exercise delegated grants, not app roles.
        $authenticationCompatible = if ($hasDelegatedGrant) { 'Yes' } elseif ($hasApplicationGrant) { 'No' } else { 'Unknown' }
    }

    [void] $findings.Add((New-GraphPermissionFinding `
                -Finding 'AuthenticationCompatible' `
                -Value $authenticationCompatible `
                -Detail 'Whether the granted permission types are usable with the profile authentication mode.' `
                -TargetTenantId $tenantId `
                -TargetAppId $appId))

    # 8. Beta-only required operations from the baseline.
    if ($betaOnly.Count -gt 0) {
        [void] $findings.Add((New-GraphPermissionFinding `
                    -Finding 'BetaOnlyRequired' `
                    -Value (@($betaOnly) -join ', ') `
                    -Detail 'Baseline operations require the beta Graph surface, which carries no stability guarantee.' `
                    -TargetTenantId $tenantId `
                    -TargetAppId $appId))
    }

    return @($findings)
}
