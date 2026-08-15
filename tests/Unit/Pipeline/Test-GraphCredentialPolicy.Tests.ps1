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

    $script:BearerDescriptor = @{
        CredentialPolicy = 'GraphBearer'
        AllowedHosts     = @()
    }

    $script:NoneDescriptor = @{
        CredentialPolicy = 'None'
        AllowedHosts     = @('storage.example.com')
    }
}

Describe 'Test-GraphCredentialPolicy' {
    Context 'GraphBearer' {
        It 'accepts an exact HTTPS Graph authority match' {
            InModuleScope GraphKit -ArgumentList $script:BearerDescriptor, $script:Context {
                param($BearerDescriptor, $Context)

                Test-GraphCredentialPolicy -Uri 'https://graph.microsoft.com/v1.0/me' -Descriptor $BearerDescriptor -Context $Context
            } | Should -BeTrue
        }

        It 'rejects a hostile authority with a hard error naming it' {
            {
                InModuleScope GraphKit -ArgumentList $script:BearerDescriptor, $script:Context {
                    param($BearerDescriptor, $Context)

                    Test-GraphCredentialPolicy -Uri 'https://evil.example.com/me' -Descriptor $BearerDescriptor -Context $Context
                }
            } | Should -Throw -ExpectedMessage '*evil.example.com*'
        }

        It 'rejects a missing context rather than downgrading' {
            {
                InModuleScope GraphKit -ArgumentList $script:BearerDescriptor {
                    param($BearerDescriptor)

                    Test-GraphCredentialPolicy -Uri 'https://graph.microsoft.com/v1.0/me' -Descriptor $BearerDescriptor
                }
            } | Should -Throw -ExpectedMessage '*requires a context*'
        }
    }

    Context 'None' {
        It 'accepts an allowlisted HTTPS host' {
            InModuleScope GraphKit -ArgumentList $script:NoneDescriptor {
                param($NoneDescriptor)

                Test-GraphCredentialPolicy -Uri 'https://storage.example.com/sas' -Descriptor $NoneDescriptor
            } | Should -BeTrue
        }

        It 'rejects a host outside the allowlist, naming it' {
            {
                InModuleScope GraphKit -ArgumentList $script:NoneDescriptor {
                    param($NoneDescriptor)

                    Test-GraphCredentialPolicy -Uri 'https://unlisted.example.com/sas' -Descriptor $NoneDescriptor
                }
            } | Should -Throw -ExpectedMessage '*unlisted.example.com*'
        }

        It 'rejects a non-HTTPS host even when allowlisted' {
            {
                InModuleScope GraphKit -ArgumentList $script:NoneDescriptor {
                    param($NoneDescriptor)

                    Test-GraphCredentialPolicy -Uri 'http://storage.example.com/sas' -Descriptor $NoneDescriptor
                }
            } | Should -Throw -ExpectedMessage '*HTTPS*'
        }

        It 'rejects an empty allowlist (defense in depth)' {
            $emptyAllowlist = @{ CredentialPolicy = 'None'; AllowedHosts = @() }

            {
                InModuleScope GraphKit -ArgumentList $emptyAllowlist {
                    param($emptyAllowlist)

                    Test-GraphCredentialPolicy -Uri 'https://storage.example.com/sas' -Descriptor $emptyAllowlist
                }
            } | Should -Throw -ExpectedMessage '*non-empty*'
        }
    }

    Context 'Unknown policy' {
        It 'rejects an unknown credential policy' {
            {
                InModuleScope GraphKit -ArgumentList $script:Context {
                    param($Context)

                    Test-GraphCredentialPolicy -Uri 'https://graph.microsoft.com/v1.0/me' -Descriptor @{ CredentialPolicy = 'Bogus' } -Context $Context
                }
            } | Should -Throw -ExpectedMessage '*Bogus*'
        }
    }
}
