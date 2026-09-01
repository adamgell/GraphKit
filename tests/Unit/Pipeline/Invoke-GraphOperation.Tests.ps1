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
        Cloud         = 'Global'
        GraphBaseUri  = [uri] 'https://graph.microsoft.com'
        ProfileId     = 'ivy24'
        TenantId      = [guid] '00000000-0000-0000-0000-000000000001'
        IdentityState = 'VerifiedForToken'
        TokenSource   = [PSCustomObject]@{ AuthMode = 'Certificate' }
    }

    function New-FakeEnvelope {
        [PSCustomObject]@{
            PSTypeName = 'GraphKit.OperationResult'
            Data       = @()
            Outcome    = 'Succeeded'
            Certainty  = 'Known'
            Telemetry  = @()
            Provenance = $null
        }
    }

    # The retry engine's live path must never escape a unit test. A default throwing mock is
    # registered before the per-test mocks; tests that exercise the transport path override it.
    Mock Invoke-GraphRetry -ModuleName GraphKit {
        throw 'Invoke-GraphRetry must be mocked in this test.'
    }
}

Describe 'Invoke-GraphOperation' {
    Context 'BetaPreferred warning' {
        It 'warns once per session, not once per call' {
            Mock Get-GraphOperation -ModuleName GraphKit {
                return @{
                    Type = 'Thing'; Operation = 'Read'; Stability = 'BetaPreferred'
                    BetaReason = 'v1.0 missing a field'; ApiVersion = 'beta'
                    ResourceFamily = 'F'; CredentialPolicy = 'GraphBearer'; AllowedHosts = @()
                    SupportedAuthModes = @('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')
                }
            }
            Mock Resolve-GraphUri -ModuleName GraphKit { return [uri] 'https://graph.microsoft.com/beta/thing' }
            Mock Invoke-GraphHandlerStrategy -ModuleName GraphKit { return (New-FakeEnvelope) }
            Mock Write-Warning -ModuleName GraphKit { }

            Invoke-GraphOperation -Context $script:Context -Type Thing -Operation Read | Out-Null
            Invoke-GraphOperation -Context $script:Context -Type Thing -Operation Read | Out-Null

            Should-Invoke Write-Warning -ModuleName GraphKit -Times 1 -Exactly
        }

        It 'does not warn for a Stable operation' {
            Mock Get-GraphOperation -ModuleName GraphKit {
                return @{
                    Type = 'Thing'; Operation = 'Read'; Stability = 'Stable'
                    ApiVersion = 'v1.0'; ResourceFamily = 'F'
                    CredentialPolicy = 'GraphBearer'; AllowedHosts = @()
                    SupportedAuthModes = @('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')
                }
            }
            Mock Resolve-GraphUri -ModuleName GraphKit { return [uri] 'https://graph.microsoft.com/v1.0/thing' }
            Mock Invoke-GraphHandlerStrategy -ModuleName GraphKit { return (New-FakeEnvelope) }
            Mock Write-Warning -ModuleName GraphKit { }

            Invoke-GraphOperation -Context $script:Context -Type Thing -Operation Read | Out-Null

            Should-Invoke Write-Warning -ModuleName GraphKit -Times 0 -Exactly
        }
    }

    Context 'Credential boundary under -Raw' {
        It 'blocks a hostile authority even though descriptor validation is bypassed' {
            Mock Invoke-GraphRetry -ModuleName GraphKit { throw 'unexpected transport call' }

            {
                Invoke-GraphOperation -Context $script:Context -Uri 'https://evil.example.com/v1.0/me' -Method GET
            } | Should -Throw -ExpectedMessage '*evil.example.com*'
        }

        It 'executes a valid raw request through the transport' {
            Mock Invoke-GraphRetry -ModuleName GraphKit { return (New-FakeEnvelope) }

            $result = Invoke-GraphOperation -Context $script:Context -Uri 'https://graph.microsoft.com/v1.0/me' -Method GET

            $result.Outcome | Should -Be 'Succeeded'
            Should-Invoke Invoke-GraphRetry -ModuleName GraphKit -Times 1 -Exactly
        }
    }

    Context 'Descriptor auth-mode policy' {
        It 'rejects an unsupported context auth mode before URI resolution or handler execution' {
            $context = [PSCustomObject]@{}
            foreach ($property in $script:Context.PSObject.Properties) {
                $context | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value
            }
            $context.TokenSource = [PSCustomObject]@{ AuthMode = 'BearerToken' }

            Mock Get-GraphOperation -ModuleName GraphKit {
                return @{
                    Type = 'Thing'; Operation = 'Read'; Stability = 'Stable'
                    ApiVersion = 'v1.0'; ResourceFamily = 'F'
                    CredentialPolicy = 'GraphBearer'; AllowedHosts = @()
                    SupportedAuthModes = @('Certificate')
                }
            }
            Mock Resolve-GraphUri -ModuleName GraphKit { throw 'URI resolution must not run' }
            Mock Invoke-GraphHandlerStrategy -ModuleName GraphKit { throw 'handler must not run' }

            {
                Invoke-GraphOperation -Context $context -Type Thing -Operation Read
            } | Should -Throw -ExpectedMessage "*does not support auth mode 'BearerToken'*"

            Should-NotInvoke Resolve-GraphUri -ModuleName GraphKit
            Should-NotInvoke Invoke-GraphHandlerStrategy -ModuleName GraphKit
        }

        It 'does not apply descriptor auth-mode policy to a raw request' {
            Mock Invoke-GraphRetry -ModuleName GraphKit { return (New-FakeEnvelope) }

            $result = Invoke-GraphOperation -Context $script:Context -Uri 'https://graph.microsoft.com/v1.0/me' -Method GET

            $result.Outcome | Should -Be 'Succeeded'
            Should-Invoke Invoke-GraphRetry -ModuleName GraphKit -Times 1 -Exactly
        }
    }

    Context 'Collection paging deadline composition' {
        It 'forwards the pager inherited remaining deadline through Collection.Default into retry' {
            $script:retryDeadlineSeconds = $null
            $script:retryBoundParameters = $null
            $script:transportParameterNames = $null

            Mock Get-GraphOperation -ModuleName GraphKit {
                return @{
                    Type                  = 'Thing'
                    Operation             = 'List'
                    OperationKind         = 'Collection'
                    HandlerStrategyId     = 'Collection.Default'
                    Method                = 'GET'
                    PathTemplate          = '/things'
                    PagingStrategy        = 'NextLink'
                    DeduplicationKey      = 'id'
                    RequiredPagingHeaders = @()
                    AdvancedQuery         = @{ Supported = $false }
                    Concurrency           = @{ Mode = 'None'; Header = $null; Required = $false; AllowWildcard = $false }
                    ReplayPolicy          = 'Safe'
                    ResponseKind          = 'Json'
                    Stability             = 'Stable'
                    ApiVersion            = 'v1.0'
                    ResourceFamily        = 'F'
                    CredentialPolicy      = 'GraphBearer'
                    AllowedHosts          = @()
                    SupportedAuthModes    = @('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')
                }
            }
            Mock Resolve-GraphUri -ModuleName GraphKit {
                return [uri] 'https://graph.microsoft.com/v1.0/things'
            }
            Mock Invoke-GraphRetry -ModuleName GraphKit {
                param($DeadlineSeconds)
                $script:retryBoundParameters = @{} + $PSBoundParameters
                $script:retryDeadlineSeconds = [double] $DeadlineSeconds
                return (New-FakeEnvelope)
            }
            Mock Invoke-GraphPaging -ModuleName GraphKit {
                param($Context, $Descriptor, $FirstPageUri, $RequestFactoryScript, $TransportScript)
                $script:transportParameterNames = @(
                    $TransportScript.Ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }
                )
                & $TransportScript $FirstPageUri 'GET' @{} $null `
                    ([System.Threading.CancellationToken]::None) 17.25
            }

            $result = InModuleScope GraphKit -ArgumentList $script:Context {
                param($Context)
                Invoke-GraphOperation -Context $Context -Type Thing -Operation List
            }

            $result.Outcome | Should -BeExactly 'Succeeded'
            $script:transportParameterNames | Should -Contain 'DeadlineSeconds'
            $script:retryBoundParameters.Keys | Should -Contain 'DeadlineSeconds'
            $script:retryDeadlineSeconds | Should -Be 17.25
            Should-Invoke Invoke-GraphRetry -ModuleName GraphKit -Times 1 -Exactly -ParameterFilter {
                [double] $DeadlineSeconds -eq 17.25
            }
        }
    }

    Context 'Provenance stamping' {
        It 'stamps provenance onto the returned envelope' {
            Mock Get-GraphOperation -ModuleName GraphKit {
                return @{
                    Type = 'Thing'; Operation = 'Read'; Stability = 'Stable'
                    ApiVersion = 'v1.0'; ResourceFamily = 'F'
                    CredentialPolicy = 'GraphBearer'; AllowedHosts = @()
                    SupportedAuthModes = @('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')
                }
            }
            Mock Resolve-GraphUri -ModuleName GraphKit { return [uri] 'https://graph.microsoft.com/v1.0/thing' }
            Mock Invoke-GraphHandlerStrategy -ModuleName GraphKit { return (New-FakeEnvelope) }

            $result = Invoke-GraphOperation -Context $script:Context -Type Thing -Operation Read

            $result.Provenance.ProfileId | Should -Be 'ivy24'
            $result.Provenance.ApiVersion | Should -Be 'v1.0'
            $result.Provenance.ResourceFamily | Should -Be 'F'
            $result.Provenance.TenantId | Should -Be ([guid] '00000000-0000-0000-0000-000000000001')
            $result.Provenance.IdentityState | Should -Be 'VerifiedForToken'
            $result.Provenance.ActualTenantId | Should -Be ([guid] '00000000-0000-0000-0000-000000000001')
        }
    }

    Context 'Input validation' {
        It 'rejects supplying both -Context and -ProfileId' {
            {
                Invoke-GraphOperation -Context $script:Context -ProfileId ivy24 -Uri 'https://graph.microsoft.com/v1.0/me' -Method GET
            } | Should -Throw -ExpectedMessage '*not both*'
        }
    }
}
