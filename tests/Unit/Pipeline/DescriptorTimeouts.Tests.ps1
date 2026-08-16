BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) { throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first.' }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force
    $script:repoRoot = $repoRoot
}

Describe 'Per-operation transport timeouts' {

    Context 'plumbing' {

        It 'passes declared timeouts to the sender' {
            # A descriptor declaring Timeouts must actually reach Send-GraphHttpRequest.
            # Without this, a descriptor could declare a timeout that is silently never read -
            # the operation keeps failing and the declaration looks like it should have fixed it.
            $captured = $null
            $send = {
                param($Uri, $Method, $Headers, $Body, $CancellationToken, $CredentialPolicy,
                      $TokenSource, $ExpectedAuthority, $TargetTenantId, $VerifyTenantBinding,
                      $TenantBindingProver, $TimeoutConnectionSeconds, $TimeoutHeadersSeconds, $TimeoutBodySeconds)
                $script:captured = @{ Headers = $TimeoutHeadersSeconds; Body = $TimeoutBodySeconds }
                [PSCustomObject]@{ StatusCode = 200; Headers = @{}; Body = @{ value = @() }; RequestId = 'x'; TransportException = $null; ResponseReceived = $true }
            }

            InModuleScope GraphKit -Parameters @{ Send = $send } {
                $descriptor = @{
                    Type = 'T'; Operation = 'O'; Method = 'GET'; PathTemplate = '/x'
                    CredentialPolicy = 'None'; ResponseKind = 'Json'; ReplayPolicy = 'Safe'
                    ThrottleClass = 'Read'; ResourceFamily = 'F'
                    Timeouts = @{ HeadersSeconds = 60; BodySeconds = 45 }
                }
                $context = [PSCustomObject]@{ Cloud = 'Global'; GraphBaseUri = [uri]'https://graph.microsoft.com'; TenantId = 'tid'; TokenSource = $null }
                $null = Invoke-GraphRetry -Context $context -Descriptor $descriptor -Uri ([uri]'https://graph.microsoft.com/v1.0/x') `
                    -Method GET -Headers @{} -Body $null -DeadlineSeconds 30 `
                    -CancellationToken ([System.Threading.CancellationToken]::None) `
                    -Injections @{ Send = $Send; Delay = { param($Seconds) }; Jitter = { 0.0 } }
            }

            $script:captured.Headers | Should -Be 60
            $script:captured.Body | Should -Be 45
        }

        It 'passes NO timeout parameters when the descriptor declares none' {
            # This is the safety property, not a nicety. An injected sender declares only the
            # parameters it needs; splatting one it cannot bind throws "A parameter cannot be
            # found that matches parameter name". That is exactly how the -CancellationToken
            # defect reached a live tenant - every test sender accepted it loosely, the real
            # one did not. A sender WITHOUT the timeout parameters must still work.
            $send = {
                param($Uri, $Method, $Headers, $Body, $CancellationToken, $CredentialPolicy,
                      $TokenSource, $ExpectedAuthority, $TargetTenantId, $VerifyTenantBinding, $TenantBindingProver)
                [PSCustomObject]@{ StatusCode = 200; Headers = @{}; Body = @{ value = @() }; RequestId = 'x'; TransportException = $null; ResponseReceived = $true }
            }

            {
                InModuleScope GraphKit -Parameters @{ Send = $send } {
                    $descriptor = @{
                        Type = 'T'; Operation = 'O'; Method = 'GET'; PathTemplate = '/x'
                        CredentialPolicy = 'None'; ResponseKind = 'Json'; ReplayPolicy = 'Safe'
                        ThrottleClass = 'Read'; ResourceFamily = 'F'
                    }
                    $context = [PSCustomObject]@{ Cloud = 'Global'; GraphBaseUri = [uri]'https://graph.microsoft.com'; TenantId = 'tid'; TokenSource = $null }
                    $null = Invoke-GraphRetry -Context $context -Descriptor $descriptor -Uri ([uri]'https://graph.microsoft.com/v1.0/x') `
                        -Method GET -Headers @{} -Body $null -DeadlineSeconds 30 `
                        -CancellationToken ([System.Threading.CancellationToken]::None) `
                        -Injections @{ Send = $Send; Delay = { param($Seconds) }; Jitter = { 0.0 } }
                }
            } | Should -Not -Throw
        }
    }

    Context 'validation' {

        BeforeEach {
            $script:descriptorDir = Join-Path $TestDrive ([guid]::NewGuid())
            $null = New-Item -ItemType Directory -Path $script:descriptorDir -Force
            $script:template = Get-Content (Join-Path $script:repoRoot 'source/Data/Operations/ManagedDevice.List.psd1') -Raw
        }

        It 'rejects an unknown Timeouts key rather than ignoring it' {
            # The whole reason this is validated: @{ HeadersTimeout = 60 } instead of
            # @{ HeadersSeconds = 60 } would be accepted, read by nothing, and the operation
            # would keep timing out while the descriptor looked like it declared a fix.
            $path = Join-Path $script:descriptorDir 'Bad.List.psd1'
            ($script:template -replace "ThrottleClass       = 'Read'", "ThrottleClass       = 'Read'`n    Timeouts            = @{ HeadersTimeout = 60 }") |
                Set-Content -LiteralPath $path -Encoding utf8

            InModuleScope GraphKit -Parameters @{ Path = $path } {
                { Import-GraphOperationDescriptor -Path $Path } | Should -Throw -ExpectedMessage '*unknown key*HeadersTimeout*'
            }
        }

        It 'rejects a non-positive timeout' {
            $path = Join-Path $script:descriptorDir 'Bad2.List.psd1'
            ($script:template -replace "ThrottleClass       = 'Read'", "ThrottleClass       = 'Read'`n    Timeouts            = @{ HeadersSeconds = 0 }") |
                Set-Content -LiteralPath $path -Encoding utf8

            InModuleScope GraphKit -Parameters @{ Path = $path } {
                { Import-GraphOperationDescriptor -Path $Path } | Should -Throw -ExpectedMessage '*positive integer*'
            }
        }

        It 'accepts a valid Timeouts block' {
            $path = Join-Path $script:descriptorDir 'Good.List.psd1'
            ($script:template -replace "ThrottleClass       = 'Read'", "ThrottleClass       = 'Read'`n    Timeouts            = @{ HeadersSeconds = 60; BodySeconds = 90 }") |
                Set-Content -LiteralPath $path -Encoding utf8

            InModuleScope GraphKit -Parameters @{ Path = $path } {
                $d = Import-GraphOperationDescriptor -Path $Path
                $d.Timeouts.HeadersSeconds | Should -Be 60
                $d.Timeouts.BodySeconds | Should -Be 90
            }
        }
    }
}
