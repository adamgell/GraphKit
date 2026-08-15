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

    $script:BaseUri = [uri] 'https://graph.microsoft.com/v1.0'

    $script:AssignDescriptor = @{
        Type          = 'MobileApp'
        Operation     = 'Assign'
        PathTemplate  = '/deviceAppManagement/mobileApps/{id}/assign'
        AdvancedQuery = @{ Supported = $false }
    }

    $script:ListDescriptor = @{
        Type          = 'ManagedDevice'
        Operation     = 'List'
        PathTemplate  = '/deviceManagement/managedDevices'
        AdvancedQuery = @{
            Supported        = $true
            Count            = $true
            AllowedOperators = @('$filter', '$select', '$top', '$expand', '$orderby')
        }
    }

    $script:NoAdvancedQueryDescriptor = @{
        Type          = 'ManagedDevice'
        Operation     = 'List'
        PathTemplate  = '/deviceManagement/managedDevices'
        AdvancedQuery = @{ Supported = $false }
    }
}

Describe 'Resolve-GraphUri' {
    Context 'Path token substitution' {
        It 'substitutes a path token from parameters' {
            $uri = InModuleScope GraphKit -ArgumentList $script:AssignDescriptor, $script:BaseUri {
                param($AssignDescriptor, $BaseUri)

                Resolve-GraphUri -Descriptor $AssignDescriptor -Parameters @{ id = 'abc-123' } -BaseUri $BaseUri
            }

            $uri.AbsoluteUri | Should -Be 'https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps/abc-123/assign'
        }

        It 'rejects a missing path token with an actionable error naming it' {
            {
                InModuleScope GraphKit -ArgumentList $script:AssignDescriptor, $script:BaseUri {
                    param($AssignDescriptor, $BaseUri)

                    Resolve-GraphUri -Descriptor $AssignDescriptor -Parameters @{} -BaseUri $BaseUri
                }
            } | Should -Throw -ExpectedMessage "*'id'*"
        }

        It 'URI-encodes a path token value' {
            $uri = InModuleScope GraphKit -ArgumentList $script:AssignDescriptor, $script:BaseUri {
                param($AssignDescriptor, $BaseUri)

                Resolve-GraphUri -Descriptor $AssignDescriptor -Parameters @{ id = 'a b/c' } -BaseUri $BaseUri
            }

            $uri.AbsoluteUri | Should -Match 'a%20b%2Fc'
        }
    }

    Context 'Query options' {
        It 'builds a query string for declared options' {
            $uri = InModuleScope GraphKit -ArgumentList $script:ListDescriptor, $script:BaseUri {
                param($ListDescriptor, $BaseUri)

                Resolve-GraphUri -Descriptor $ListDescriptor -Parameters @{ '$top' = 10; '$filter' = "name eq 'x'" } -BaseUri $BaseUri
            }

            $uri.Query | Should -Match '\$top=10'
            $uri.Query | Should -Match '\$filter=name%20eq%20%27x%27'
        }

        It 'rejects an undeclared query option rather than passing it through' {
            {
                InModuleScope GraphKit -ArgumentList $script:ListDescriptor, $script:BaseUri {
                    param($ListDescriptor, $BaseUri)

                    Resolve-GraphUri -Descriptor $ListDescriptor -Parameters @{ '$search' = 'foo' } -BaseUri $BaseUri
                }
            } | Should -Throw -ExpectedMessage "*'`$search'*"
        }

        It 'rejects any query option when advanced query is unsupported' {
            {
                InModuleScope GraphKit -ArgumentList $script:NoAdvancedQueryDescriptor, $script:BaseUri {
                    param($NoAdvancedQueryDescriptor, $BaseUri)

                    Resolve-GraphUri -Descriptor $NoAdvancedQueryDescriptor -Parameters @{ '$top' = 10 } -BaseUri $BaseUri
                }
            } | Should -Throw -ExpectedMessage "*'`$top'*"
        }

        It 'allows $count when the descriptor declares Count support' {
            $uri = InModuleScope GraphKit -ArgumentList $script:ListDescriptor, $script:BaseUri {
                param($ListDescriptor, $BaseUri)

                Resolve-GraphUri -Descriptor $ListDescriptor -Parameters @{ '$count' = $true } -BaseUri $BaseUri
            }

            $uri.Query | Should -Match '\$count=true'
        }

        It 'ignores non-query parameters such as a request Body' {
            $uri = InModuleScope GraphKit -ArgumentList $script:AssignDescriptor, $script:BaseUri {
                param($AssignDescriptor, $BaseUri)

                Resolve-GraphUri -Descriptor $AssignDescriptor -Parameters @{ id = 'abc'; Body = @{ x = 1 } } -BaseUri $BaseUri
            }

            $uri.AbsoluteUri | Should -Be 'https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps/abc/assign'
        }
    }
}
