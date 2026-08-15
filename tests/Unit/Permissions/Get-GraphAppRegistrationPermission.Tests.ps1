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

    # The retry engine's live path must never escape a unit test.
    Mock Invoke-GraphRetry -ModuleName GraphKit {
        throw 'Invoke-GraphRetry must be mocked in this test.'
    }
}

Describe 'Get-GraphAppRegistrationPermission' {

    It 'returns the configured application permissions resolved against the Graph appRoles catalog' {
        Mock Invoke-GraphRetry -ModuleName GraphKit {
            return [PSCustomObject]@{
                PSTypeName = 'GraphKit.OperationResult'
                Data       = @{
                    value = @(
                        @{
                            id    = 'app-object-1'
                            appId = $script:TargetAppId
                            requiredResourceAccess = @(
                                @{
                                    resourceAppId  = $script:GraphAppId
                                    resourceAccess = @(
                                        @{ id = 'role-1'; type = 'Role' },
                                        @{ id = 'scope-1'; type = 'Scope' }
                                    )
                                }
                            )
                        }
                    )
                }
                Outcome    = 'Succeeded'
                Certainty  = 'Known'
                Telemetry  = @()
                Provenance = @{}
            }
        }
        Mock Get-GraphAppRoleCatalog -ModuleName GraphKit {
            return @( @{ id = 'role-1'; value = 'DeviceManagementManagedDevices.Read.All' } )
        }

        $result = @(Get-GraphAppRegistrationPermission -Context $script:Context -TargetAppId $script:TargetAppId)

        $result.Count | Should -Be 1
        $result[0].Type | Should -Be 'Application'
        $result[0].Value | Should -Be 'DeviceManagementManagedDevices.Read.All'
        $result[0].Id | Should -Be 'role-1'
    }

    It 'ignores requiredResourceAccess entries aimed at resources other than Microsoft Graph' {
        Mock Invoke-GraphRetry -ModuleName GraphKit {
            return [PSCustomObject]@{
                PSTypeName = 'GraphKit.OperationResult'
                Data       = @{
                    value = @(
                        @{
                            id    = 'app-object-1'
                            appId = $script:TargetAppId
                            requiredResourceAccess = @(
                                @{
                                    resourceAppId  = '99999999-0000-0000-c000-000000000000'
                                    resourceAccess = @( @{ id = 'other-role'; type = 'Role' } )
                                },
                                @{
                                    resourceAppId  = $script:GraphAppId
                                    resourceAccess = @( @{ id = 'role-1'; type = 'Role' } )
                                }
                            )
                        }
                    )
                }
                Outcome    = 'Succeeded'
                Certainty  = 'Known'
                Telemetry  = @()
                Provenance = @{}
            }
        }
        Mock Get-GraphAppRoleCatalog -ModuleName GraphKit {
            return @( @{ id = 'role-1'; value = 'Graph.Only.Role' } )
        }

        $result = @(Get-GraphAppRegistrationPermission -Context $script:Context -TargetAppId $script:TargetAppId)

        $result.Count | Should -Be 1
        $result[0].Value | Should -Be 'Graph.Only.Role'
    }

    It 'errors naming the home-tenant requirement when the application object is not found' {
        Mock Invoke-GraphRetry -ModuleName GraphKit {
            return [PSCustomObject]@{
                PSTypeName = 'GraphKit.OperationResult'
                Data       = @{ value = @() }
                Outcome    = 'Succeeded'
                Certainty  = 'Known'
                Telemetry  = @()
                Provenance = @{}
            }
        }

        {
            Get-GraphAppRegistrationPermission -Context $script:Context -TargetAppId $script:TargetAppId
        } | Should -Throw -ExpectedMessage '*home tenant*'
    }
}

Describe 'Session-scoped directory caches' {

    It 'resolves the Graph appRoles catalog once per tenant per session' {
        InModuleScope GraphKit {
            $script:GraphAppRoleCatalogCache.Clear()
            $script:GraphServicePrincipalCache.Clear()
        }

        Mock Invoke-GraphRetry -ModuleName GraphKit {
            return [PSCustomObject]@{
                PSTypeName = 'GraphKit.OperationResult'
                Data       = @{
                    value = @(
                        @{
                            id       = 'graph-sp'
                            appId    = $script:GraphAppId
                            appRoles = @( @{ id = 'role-1'; value = 'A.Read.All' } )
                        }
                    )
                }
                Outcome    = 'Succeeded'
                Certainty  = 'Known'
                Telemetry  = @()
                Provenance = @{}
            }
        }

        $first = InModuleScope GraphKit -Parameters @{ Context = $script:Context } {
            param($Context)
            @(Get-GraphAppRoleCatalog -Context $Context)
        }
        $second = InModuleScope GraphKit -Parameters @{ Context = $script:Context } {
            param($Context)
            @(Get-GraphAppRoleCatalog -Context $Context)
        }

        $first.Count | Should -Be 1
        $second.Count | Should -Be 1
        Should-Invoke Invoke-GraphRetry -ModuleName GraphKit -Times 1 -Exactly
    }

    It 'caches service-principal resolution per tenant and appId' {
        InModuleScope GraphKit {
            $script:GraphAppRoleCatalogCache.Clear()
            $script:GraphServicePrincipalCache.Clear()
        }

        Mock Invoke-GraphRetry -ModuleName GraphKit {
            return [PSCustomObject]@{
                PSTypeName = 'GraphKit.OperationResult'
                Data       = @{
                    value = @(
                        @{ id = 'sp-1'; appId = $script:TargetAppId }
                    )
                }
                Outcome    = 'Succeeded'
                Certainty  = 'Known'
                Telemetry  = @()
                Provenance = @{}
            }
        }

        $first = InModuleScope GraphKit -Parameters @{ Context = $script:Context; AppId = $script:TargetAppId } {
            param($Context, $AppId)
            Get-GraphServicePrincipalByAppId -Context $Context -AppId $AppId
        }
        $second = InModuleScope GraphKit -Parameters @{ Context = $script:Context; AppId = $script:TargetAppId } {
            param($Context, $AppId)
            Get-GraphServicePrincipalByAppId -Context $Context -AppId $AppId
        }

        $first.id | Should -Be 'sp-1'
        $second.id | Should -Be 'sp-1'
        Should-Invoke Invoke-GraphRetry -ModuleName GraphKit -Times 1 -Exactly
    }
}
