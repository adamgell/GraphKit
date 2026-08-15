BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built GraphKit module found under output/module/GraphKit; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force

    $script:GraphAppId = '00000003-0000-0000-c000-000000000000'
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

    # The retry engine's live path must never escape a unit test. Grant's read
    # dependencies are mocked below, so Invoke-GraphRetry is only reached when a
    # grant is actually applied.
    Mock Invoke-GraphRetry -ModuleName GraphKit {
        throw 'Invoke-GraphRetry must be mocked in this test.'
    }
}

Describe 'Grant-GraphAppPermission' {

    Context 'Idempotency' {

        It 'grants nothing when the permission is already assigned' {
            Mock Get-GraphServicePrincipalByAppId -ModuleName GraphKit {
                param($Context, $AppId)
                if ($AppId -eq $script:GraphAppId) {
                    return [PSCustomObject]@{ id = 'graph-sp'; appId = $AppId }
                }
                return [PSCustomObject]@{ id = 'sp-1'; appId = $AppId }
            }
            Mock Get-GraphAppRoleCatalog -ModuleName GraphKit {
                return @( @{ id = 'role-1'; value = 'A.Read.All' } )
            }
            Mock Get-GraphAppRoleAssignments -ModuleName GraphKit {
                return @( @{ appRoleId = 'role-1'; principalId = 'sp-1'; resourceId = 'graph-sp' } )
            }

            $applied = @(Grant-GraphAppPermission -Context $script:Context -TargetAppId $script:TargetAppId -Permission @(
                    @{ Type = 'Application'; Value = 'A.Read.All' }
                ))

            $applied.Count | Should -Be 0
            Should-Invoke Invoke-GraphRetry -ModuleName GraphKit -Times 0 -Exactly
        }
    }

    Context 'Applying the diff' {

        It 'applies only the missing grant through the pipeline' {
            Mock Get-GraphServicePrincipalByAppId -ModuleName GraphKit {
                param($Context, $AppId)
                if ($AppId -eq $script:GraphAppId) {
                    return [PSCustomObject]@{ id = 'graph-sp'; appId = $AppId }
                }
                return [PSCustomObject]@{ id = 'sp-1'; appId = $AppId }
            }
            Mock Get-GraphAppRoleCatalog -ModuleName GraphKit {
                return @(
                    @{ id = 'role-1'; value = 'A.Read.All' },
                    @{ id = 'role-2'; value = 'B.Read.All' }
                )
            }
            Mock Get-GraphAppRoleAssignments -ModuleName GraphKit {
                return @( @{ appRoleId = 'role-1'; principalId = 'sp-1'; resourceId = 'graph-sp' } )
            }
            Mock Invoke-GraphRetry -ModuleName GraphKit {
                return [PSCustomObject]@{
                    PSTypeName = 'GraphKit.OperationResult'
                    Data       = @()
                    Outcome    = 'Succeeded'
                    Certainty  = 'Known'
                    Telemetry  = @()
                    Provenance = @{}
                }
            }

            $applied = @(Grant-GraphAppPermission -Context $script:Context -TargetAppId $script:TargetAppId -Permission @(
                    @{ Type = 'Application'; Value = 'A.Read.All' },
                    @{ Type = 'Application'; Value = 'B.Read.All' }
                ))

            $applied.Count | Should -Be 1
            $applied[0].Value | Should -Be 'B.Read.All'
            $applied[0].AppRoleId | Should -Be 'role-2'
            Should-Invoke Invoke-GraphRetry -ModuleName GraphKit -Times 1 -Exactly
        }
    }

    Context 'SupportsShouldProcess' {

        It 'sends nothing under -WhatIf even when a grant is missing' {
            Mock Get-GraphServicePrincipalByAppId -ModuleName GraphKit {
                param($Context, $AppId)
                if ($AppId -eq $script:GraphAppId) {
                    return [PSCustomObject]@{ id = 'graph-sp'; appId = $AppId }
                }
                return [PSCustomObject]@{ id = 'sp-1'; appId = $AppId }
            }
            Mock Get-GraphAppRoleCatalog -ModuleName GraphKit {
                return @( @{ id = 'role-1'; value = 'A.Read.All' } )
            }
            Mock Get-GraphAppRoleAssignments -ModuleName GraphKit { return @() }

            Grant-GraphAppPermission -Context $script:Context -TargetAppId $script:TargetAppId -Permission @(
                @{ Type = 'Application'; Value = 'A.Read.All' }
            ) -WhatIf

            Should-Invoke Invoke-GraphRetry -ModuleName GraphKit -Times 0 -Exactly
        }
    }

    Context 'Input validation' {

        It 'rejects a permission whose Type is not Application' {
            Mock Get-GraphServicePrincipalByAppId -ModuleName GraphKit {
                param($Context, $AppId)
                return [PSCustomObject]@{ id = 'sp-1'; appId = $AppId }
            }

            {
                Grant-GraphAppPermission -Context $script:Context -TargetAppId $script:TargetAppId -Permission @(
                    @{ Type = 'Delegated'; Value = 'Some.Scope' }
                )
            } | Should -Throw -ExpectedMessage "*only Type 'Application'*"
        }

        It 'rejects a permission that is not a known Graph application permission' {
            Mock Get-GraphServicePrincipalByAppId -ModuleName GraphKit {
                param($Context, $AppId)
                if ($AppId -eq $script:GraphAppId) {
                    return [PSCustomObject]@{ id = 'graph-sp'; appId = $AppId }
                }
                return [PSCustomObject]@{ id = 'sp-1'; appId = $AppId }
            }
            Mock Get-GraphAppRoleCatalog -ModuleName GraphKit {
                return @( @{ id = 'role-1'; value = 'A.Read.All' } )
            }
            Mock Get-GraphAppRoleAssignments -ModuleName GraphKit { return @() }

            {
                Grant-GraphAppPermission -Context $script:Context -TargetAppId $script:TargetAppId -Permission @(
                    @{ Type = 'Application'; Value = 'Not.A.Real.Permission' }
                )
            } | Should -Throw -ExpectedMessage '*not a known Microsoft Graph application permission*'
        }
    }
}
