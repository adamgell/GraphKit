BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built GraphKit module found under output/module/GraphKit; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force

    $script:TargetAppId = '11111111-2222-3333-4444-555555555555'

    $script:Context = [PSCustomObject]@{
        Cloud         = 'Global'
        GraphBaseUri  = [uri] 'https://graph.microsoft.com'
        ProfileId     = 'ivy24'
        TenantId      = [guid] '00000000-0000-0000-0000-000000000001'
        ClientId      = [guid] 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        IdentityState = 'VerifiedForToken'
        TokenSource   = [PSCustomObject]@{ AuthMode = 'ClientSecret' }
    }

    $script:HomeContext = [PSCustomObject]@{
        Cloud         = 'Global'
        GraphBaseUri  = [uri] 'https://graph.microsoft.com'
        ProfileId     = 'ivy24'
        TenantId      = [guid] '00000000-0000-0000-0000-000000000002'
        ClientId      = [guid] 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        IdentityState = 'VerifiedForToken'
        TokenSource   = [PSCustomObject]@{ AuthMode = 'ClientSecret' }
    }

    # The retry engine's live path must never escape a unit test.
    Mock Invoke-GraphRetry -ModuleName GraphKit {
        throw 'Invoke-GraphRetry must be mocked in this test.'
    }
}

Describe 'Test-GraphPermission' {

    Context 'Four-state separation' {

        It 'reports Configured as Unknown when no home-tenant context is supplied' {
            Mock Get-GraphServicePrincipalAppRoleAssignment -ModuleName GraphKit {
                return [PSCustomObject]@{
                    ServicePrincipal   = $null
                    AppRoleAssignments = @()
                }
            }

            $findings = @(Test-GraphPermission -Context $script:Context -TargetAppId $script:TargetAppId)

            $configured = $findings | Where-Object { $_.Finding -eq 'Configured' }
            $configured | Should -Not -BeNullOrEmpty
            $configured.Value | Should -Be 'Unknown'

            $granted = $findings | Where-Object { $_.Finding -eq 'Granted' }
            $granted.Value | Should -Be 'No'
        }

        It 'reports Configured as Yes when the home-tenant object requests application permissions' {
            Mock Get-GraphAppRegistrationPermission -ModuleName GraphKit {
                return @(
                    [PSCustomObject]@{ Type = 'Application'; Value = 'A.Read.All'; Id = 'role-1' }
                )
            }
            Mock Get-GraphServicePrincipalAppRoleAssignment -ModuleName GraphKit {
                return [PSCustomObject]@{
                    ServicePrincipal   = [PSCustomObject]@{ id = 'sp-1' }
                    AppRoleAssignments = @(
                        [PSCustomObject]@{ AppRoleId = 'role-1'; AppRoleValue = 'A.Read.All' }
                    )
                }
            }
            Mock Get-GraphOauth2PermissionGrants -ModuleName GraphKit { return @() }

            $findings = @(Test-GraphPermission -Context $script:Context -TargetAppId $script:TargetAppId -HomeTenantContext $script:HomeContext)

            ($findings | Where-Object { $_.Finding -eq 'Configured' }).Value | Should -Be 'Yes'
            ($findings | Where-Object { $_.Finding -eq 'Granted' }).Value | Should -Be 'Yes'
        }
    }

    Context 'Granted but not configured' {

        It 'emits a granted-but-not-configured finding when the grant exceeds the configured set' {
            Mock Get-GraphAppRegistrationPermission -ModuleName GraphKit { return @() }
            Mock Get-GraphServicePrincipalAppRoleAssignment -ModuleName GraphKit {
                return [PSCustomObject]@{
                    ServicePrincipal   = [PSCustomObject]@{ id = 'sp-1' }
                    AppRoleAssignments = @(
                        [PSCustomObject]@{ AppRoleId = 'role-1'; AppRoleValue = 'Stale.Role' }
                    )
                }
            }
            Mock Get-GraphOauth2PermissionGrants -ModuleName GraphKit { return @() }

            $findings = @(Test-GraphPermission -Context $script:Context -TargetAppId $script:TargetAppId -HomeTenantContext $script:HomeContext)

            $finding = $findings | Where-Object { $_.Finding -eq 'GrantedButNotConfigured' }
            $finding | Should -Not -BeNullOrEmpty
            $finding.Value | Should -Be 'Stale.Role'
        }
    }

    Context 'Baseline excess and missing' {

        It 'reports MissingGrant for baseline permissions not granted and ExcessGranted for grants beyond the baseline' {
            Mock Get-GraphAppRegistrationPermission -ModuleName GraphKit {
                return @(
                    [PSCustomObject]@{ Type = 'Application'; Value = 'A.Read.All'; Id = 'role-1' },
                    [PSCustomObject]@{ Type = 'Application'; Value = 'B.Read.All'; Id = 'role-2' }
                )
            }
            Mock Get-GraphServicePrincipalAppRoleAssignment -ModuleName GraphKit {
                return [PSCustomObject]@{
                    ServicePrincipal   = [PSCustomObject]@{ id = 'sp-1' }
                    AppRoleAssignments = @(
                        [PSCustomObject]@{ AppRoleId = 'role-1'; AppRoleValue = 'A.Read.All' },
                        [PSCustomObject]@{ AppRoleId = 'role-9'; AppRoleValue = 'Surplus.Role' }
                    )
                }
            }
            Mock Get-GraphOauth2PermissionGrants -ModuleName GraphKit { return @() }

            $baseline = @(
                @{ Type = 'Application'; Value = 'A.Read.All' },
                @{ Type = 'Application'; Value = 'B.Read.All' }
            )

            $findings = @(Test-GraphPermission -Context $script:Context -TargetAppId $script:TargetAppId -HomeTenantContext $script:HomeContext -Baseline $baseline)

            ($findings | Where-Object { $_.Finding -eq 'MissingGrant' }).Value | Should -Be 'B.Read.All'
            ($findings | Where-Object { $_.Finding -eq 'ExcessGranted' }).Value | Should -Be 'Surplus.Role'
        }
    }

    Context 'Bootstrap trap' {

        It 'throws an actionable error naming the analyzer prerequisite, never a bare 403' {
            Mock Invoke-GraphRetry -ModuleName GraphKit {
                return [PSCustomObject]@{
                    PSTypeName = 'GraphKit.OperationResult'
                    Data       = $null
                    Outcome    = 'Failed'
                    Certainty  = 'Known'
                    Telemetry  = @( @{ StatusCode = 403 } )
                    Provenance = @{}
                }
            }

            $message = $null
            try {
                Test-GraphPermission -Context $script:Context -TargetAppId $script:TargetAppId | Out-Null
            } catch {
                $message = $_.Exception.Message
            }
            $message | Should -Not -BeNullOrEmpty
            $message | Should -Match 'Application\.Read\.All'
            $message | Should -Match 'Directory\.Read\.All'
            $message | Should -Match 'prerequisite'
        }
    }

    Context 'Token claims are not consulted' {

        It 'never exports a token-claims authority' {
            $tokenCommand = Get-Command Get-GraphTokenPermission -ErrorAction SilentlyContinue
            $null -eq $tokenCommand | Should -BeTrue
        }

        It 'derives findings from directory reads with no token-decode function involved' {
            Mock Get-GraphAppRegistrationPermission -ModuleName GraphKit {
                return @(
                    [PSCustomObject]@{ Type = 'Application'; Value = 'A.Read.All'; Id = 'role-1' }
                )
            }
            Mock Get-GraphServicePrincipalAppRoleAssignment -ModuleName GraphKit {
                return [PSCustomObject]@{
                    ServicePrincipal   = [PSCustomObject]@{ id = 'sp-1' }
                    AppRoleAssignments = @(
                        [PSCustomObject]@{ AppRoleId = 'role-1'; AppRoleValue = 'A.Read.All' }
                    )
                }
            }
            Mock Get-GraphOauth2PermissionGrants -ModuleName GraphKit { return @() }

            $findings = @(Test-GraphPermission -Context $script:Context -TargetAppId $script:TargetAppId -HomeTenantContext $script:HomeContext -Baseline @(@{ Type = 'Application'; Value = 'A.Read.All' }))

            ($findings | Where-Object { $_.Finding -eq 'Granted' }).Value | Should -Be 'Yes'
            ($findings | Where-Object { $_.Finding -eq 'MissingGrant' }).Value | Should -Be 'None'
        }
    }
}
