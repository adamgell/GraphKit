BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    # Import the BUILT module (never dot-source source files: they would redefine module classes
    # and Add-Type types in test scope). Pester discovers tests per file, so each file imports it.
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built GraphKit module found under output/module/GraphKit; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force

    $script:Context = [PSCustomObject]@{
        Cloud        = 'Global'
        GraphBaseUri = [uri] 'https://graph.microsoft.com/v1.0'
    }
}

Describe 'Test-GraphNextLinkAuthority' {
    Context 'Get-GraphUriAuthority normalization' {
        It 'returns the host without a port for the default HTTPS port' {
            InModuleScope GraphKit {
                Get-GraphUriAuthority -Uri 'https://graph.microsoft.com/v1.0/me'
            } | Should -Be 'graph.microsoft.com'
        }

        It 'includes a non-default port in the authority key' {
            InModuleScope GraphKit {
                Get-GraphUriAuthority -Uri 'https://graph.microsoft.com:8443/me'
            } | Should -Be 'graph.microsoft.com:8443'
        }

        It 'lowercases the host' {
            InModuleScope GraphKit {
                Get-GraphUriAuthority -Uri 'https://Graph.Microsoft.com/v1.0/me'
            } | Should -Be 'graph.microsoft.com'
        }
    }

    Context 'Acceptance' {
        It 'accepts an exact HTTPS authority match on port 443' {
            InModuleScope GraphKit -ArgumentList $script:Context {
                param($Context)

                Test-GraphNextLinkAuthority -NextLink 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices' -Context $Context
            } | Should -BeTrue
        }

        It 'blocks a hostile host before any token attach' {
            {
                InModuleScope GraphKit -ArgumentList $script:Context {
                    param($Context)

                    Test-GraphNextLinkAuthority -NextLink 'https://evil.example.com/v1.0/me' -Context $Context
                }
            } | Should -Throw -ExpectedMessage '*evil.example.com*'
        }

        It 'blocks a non-HTTPS scheme' {
            {
                InModuleScope GraphKit -ArgumentList $script:Context {
                    param($Context)

                    Test-GraphNextLinkAuthority -NextLink 'http://graph.microsoft.com/v1.0/me' -Context $Context
                }
            } | Should -Throw -ExpectedMessage '*non-HTTPS*'
        }

        It 'blocks a non-443 port even on the right host' {
            {
                InModuleScope GraphKit -ArgumentList $script:Context {
                    param($Context)

                    Test-GraphNextLinkAuthority -NextLink 'https://graph.microsoft.com:8443/v1.0/me' -Context $Context
                }
            } | Should -Throw -ExpectedMessage '*8443*'
        }

        It 'blocks a relative nextLink' {
            {
                InModuleScope GraphKit -ArgumentList $script:Context {
                    param($Context)

                    Test-GraphNextLinkAuthority -NextLink 'relative/path' -Context $Context
                }
            } | Should -Throw -ExpectedMessage '*relative*'
        }

        It 'blocks a differing sovereign-cloud authority' {
            $usContext = [PSCustomObject]@{
                Cloud        = 'USGov'
                GraphBaseUri = [uri] 'https://graph.microsoft.us/v1.0'
            }

            {
                InModuleScope GraphKit -ArgumentList $usContext {
                    param($usContext)

                    Test-GraphNextLinkAuthority -NextLink 'https://graph.microsoft.com/v1.0/me' -Context $usContext
                }
            } | Should -Throw -ExpectedMessage '*graph.microsoft.com*'
        }
    }
}
