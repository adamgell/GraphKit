BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw "No built GraphKit module found under '$repoRoot/output/module/GraphKit'. Run './build.ps1 -Tasks build' first."
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force -ErrorAction Stop
}

Describe 'New-GraphTelemetry' {

    Context 'query sanitization' {
        It 'keeps only value-safe OData integers and redacts everything else' {
            $r = InModuleScope GraphKit {
                $uri = [uri] 'https://graph.microsoft.com/v1.0/users?$top=10&$filter=startswith(displayName,%27Adam%27)&$select=id,displayName&sig=secret123'
                New-GraphTelemetry -LogicalOperationId ([guid]::NewGuid()) -ClientRequestId ([guid]::NewGuid()) `
                    -Uri $uri -Attempt 1 -StatusCode 200
            }

            $r.SanitizedUri | Should -Match '\$top=10'
            $r.SanitizedUri | Should -Match '\$filter=<redacted>'
            $r.SanitizedUri | Should -Match '\$select=<redacted>'
            $r.SanitizedUri | Should -Match 'sig=<redacted>'
            $r.SanitizedUri | Should -Not -Match 'secret123'
            $r.SanitizedUri | Should -Not -Match 'Adam'
        }

        It 'passes through a URI with no query unchanged' {
            $r = InModuleScope GraphKit {
                $uri = [uri] 'https://graph.microsoft.com/v1.0/me'
                New-GraphTelemetry -LogicalOperationId ([guid]::NewGuid()) -ClientRequestId ([guid]::NewGuid()) `
                    -Uri $uri -Attempt 1 -StatusCode 200
            }
            $r.SanitizedUri | Should -Be 'https://graph.microsoft.com/v1.0/me'
        }
    }

    Context 'Graph error code chain' {
        It 'extracts the structural code chain and drops free-form messages' {
            $r = InModuleScope GraphKit {
                $body = @{
                    error = @{
                        code    = 'Request_ResourceNotFound'
                        message = 'The resource was not found. This must never appear in telemetry.'
                        innererror = @{
                            code = 'InnerCode'
                            message = 'Another free-form message to drop.'
                        }
                    }
                }

                New-GraphTelemetry -LogicalOperationId ([guid]::NewGuid()) -ClientRequestId ([guid]::NewGuid()) `
                    -Uri ([uri] 'https://graph.microsoft.com/v1.0/me') -Attempt 1 -StatusCode 404 -Body $body
            }

            $r.GraphErrorCode | Should -Contain 'Request_ResourceNotFound'
            $r.GraphErrorCode | Should -Contain 'InnerCode'
            ($r.GraphErrorCode -join ' ') | Should -Not -Match 'not found'
        }

        It 'yields an empty chain for a body without an error block' {
            $r = InModuleScope GraphKit {
                New-GraphTelemetry -LogicalOperationId ([guid]::NewGuid()) -ClientRequestId ([guid]::NewGuid()) `
                    -Uri ([uri] 'https://graph.microsoft.com/v1.0/me') -Attempt 1 -StatusCode 200 -Body @{ value = @() }
            }
            $r.GraphErrorCode.Count | Should -Be 0
        }
    }

    Context 'record shape' {
        It 'exposes every contract field with the exact names' {
            $r = InModuleScope GraphKit {
                New-GraphTelemetry -LogicalOperationId ([guid]::NewGuid()) -ClientRequestId ([guid]::NewGuid()) `
                    -Uri ([uri] 'https://graph.microsoft.com/v1.0/me') -Attempt 1 -StatusCode 429 -DelaySeconds 30 -DelaySource 'RetryAfterDelta'
            }

            $names = @($r.PSObject.Properties.Name)
            foreach ($expected in @('LogicalOperationId', 'ClientRequestId', 'ResponseRequestId', 'ResponseDate',
                'XmsAgsDiagnostic', 'SanitizedUri', 'Attempt', 'StatusCode', 'DelaySeconds', 'DelaySource',
                'ThrottleState', 'BatchSubrequestId', 'AttemptOutcome', 'AttemptCertainty', 'GraphErrorCode')) {
                $names | Should -Contain $expected
            }
        }
    }
}
