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

    # A descriptor that fixes a query option in its path. Real instances:
    # Organization/GetMdmAuthority ($select) and the two admin-template $expand descriptors.
    $script:BakedQueryDescriptor = @{
        Type          = 'GroupPolicyDefinitionValue'
        Operation     = 'ListBeta'
        PathTemplate  = '/deviceManagement/groupPolicyConfigurations/{id}/definitionValues?$expand=definition'
        AdvancedQuery = @{ Supported = $false }
    }

    # Same, but ALSO accepting caller options - the combination that was silently broken.
    $script:BakedQueryPlusOptionsDescriptor = @{
        Type          = 'GroupPolicyDefinitionValue'
        Operation     = 'ListBeta'
        PathTemplate  = '/deviceManagement/groupPolicyConfigurations/{id}/definitionValues?$expand=definition'
        AdvancedQuery = @{
            Supported        = $true
            Count            = $false
            AllowedOperators = @('$filter', '$select', '$expand')
        }
    }

    $script:TwoTokenDescriptor = @{
        Type          = 'GroupPolicyPresentationValue'
        Operation     = 'ListBeta'
        PathTemplate  = '/deviceManagement/groupPolicyConfigurations/{id}/definitionValues/{definitionValueId}/presentationValues?$expand=presentation'
        AdvancedQuery = @{ Supported = $false }
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

Describe 'A PathTemplate that already carries a query' {

    It 'extends the fixed query with & rather than a second ?' {
        # The defect this guards. Joining with '?' unconditionally produced
        # '...definitionValues?$expand=definition?$filter=x'. That is not two options: the
        # second '?' is just a character inside $expand's VALUE, so Graph applies the expand
        # to a nonsense value and IGNORES the filter. The caller gets 200 and a full,
        # unfiltered collection - a wrong answer that looks like a right one.
        $uri = InModuleScope GraphKit -ArgumentList $script:BakedQueryPlusOptionsDescriptor, $script:BaseUri {
            param($Descriptor, $BaseUri)
            Resolve-GraphUri -Descriptor $Descriptor -Parameters @{ id = 'abc'; '$filter' = "enabled eq true" } -BaseUri $BaseUri
        }

        # Assert with -Match, not -BeLike: in a PowerShell wildcard '?' means ANY ONE
        # CHARACTER, so '*definition?*' happily matches 'definition&' and the check passes
        # whether or not the bug is present.
        $uri.AbsoluteUri | Should -Not -Match 'definition\?' -Because 'a second ? does not start a second option'
        ([regex]::Matches($uri.AbsoluteUri, '\?')).Count | Should -Be 1
        $uri.AbsoluteUri | Should -Match 'definition&\$filter='
        $uri.Query | Should -BeLike '*$expand=definition*'
        $uri.Query | Should -BeLike '*$filter=*'
    }

    It 'still uses ? when the template has no fixed query' {
        $uri = InModuleScope GraphKit -ArgumentList $script:ListDescriptor, $script:BaseUri {
            param($Descriptor, $BaseUri)
            Resolve-GraphUri -Descriptor $Descriptor -Parameters @{ '$filter' = 'x eq 1' } -BaseUri $BaseUri
        }

        ([regex]::Matches($uri.AbsoluteUri, '\?')).Count | Should -Be 1
        $uri.AbsoluteUri | Should -BeLike '*managedDevices?$filter=*'
    }

    It 'refuses a caller-supplied option that the descriptor already fixes' {
        # Emitting $expand twice makes Graph reject the whole request, and its error names the
        # option rather than the descriptor that fixed it - which sends the reader looking in
        # their own call instead of at the catalog.
        {
            InModuleScope GraphKit -ArgumentList $script:BakedQueryPlusOptionsDescriptor, $script:BaseUri {
                param($Descriptor, $BaseUri)
                Resolve-GraphUri -Descriptor $Descriptor -Parameters @{ id = 'abc'; '$expand' = 'something' } -BaseUri $BaseUri
            }
        } | Should -Throw -ExpectedMessage '*is fixed by operation*'
    }

    It 'leaves the fixed option intact when no caller options are supplied' {
        $uri = InModuleScope GraphKit -ArgumentList $script:BakedQueryDescriptor, $script:BaseUri {
            param($Descriptor, $BaseUri)
            Resolve-GraphUri -Descriptor $Descriptor -Parameters @{ id = 'abc' } -BaseUri $BaseUri
        }

        $uri.AbsoluteUri | Should -Be 'https://graph.microsoft.com/v1.0/deviceManagement/groupPolicyConfigurations/abc/definitionValues?$expand=definition'
    }
}

Describe 'Multi-level path parameterization' {

    It 'substitutes two distinct tokens' {
        $uri = InModuleScope GraphKit -ArgumentList $script:TwoTokenDescriptor, $script:BaseUri {
            param($Descriptor, $BaseUri)
            Resolve-GraphUri -Descriptor $Descriptor -Parameters @{ id = 'CFG'; definitionValueId = 'DV' } -BaseUri $BaseUri
        }

        $uri.AbsolutePath | Should -Be '/v1.0/deviceManagement/groupPolicyConfigurations/CFG/definitionValues/DV/presentationValues'
    }

    It 'names the MISSING token rather than sending a literal placeholder to Graph' {
        # Without this, an omitted second token ships '{definitionValueId}' in the URL and the
        # failure surfaces as a Graph 404 about a resource id that the caller never wrote.
        {
            InModuleScope GraphKit -ArgumentList $script:TwoTokenDescriptor, $script:BaseUri {
                param($Descriptor, $BaseUri)
                Resolve-GraphUri -Descriptor $Descriptor -Parameters @{ id = 'CFG' } -BaseUri $BaseUri
            }
        } | Should -Throw -ExpectedMessage "*requires path parameter 'definitionValueId'*"
    }

    It 'escapes a token value so it cannot forge a path segment or a query' {
        $uri = InModuleScope GraphKit -ArgumentList $script:TwoTokenDescriptor, $script:BaseUri {
            param($Descriptor, $BaseUri)
            Resolve-GraphUri -Descriptor $Descriptor -Parameters @{ id = '../../admin'; definitionValueId = 'x?$top=1' } -BaseUri $BaseUri
        }

        # AbsoluteUri, not ToString(): ToString() renders a friendlier unescaped form, so
        # asserting on it would show traversal that is not actually on the wire - and would
        # equally hide it if it were.
        $uri.AbsoluteUri | Should -Not -BeLike '*/../*'
        $uri.AbsoluteUri | Should -BeLike '*..%2F..%2Fadmin*'
        ([regex]::Matches($uri.AbsoluteUri, '\?')).Count | Should -Be 1 -Because 'the fixed $expand is the only query; a token value must not open another'
        $uri.AbsoluteUri | Should -Not -BeLike '*$top=1*'
    }
}
