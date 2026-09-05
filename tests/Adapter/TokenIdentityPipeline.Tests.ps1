BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory `
        -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw "No built GraphKit module found under '$repoRoot/output/module/GraphKit'. Run './build.ps1 -Tasks build' first."
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force -ErrorAction Stop

    $script:TenantId = [guid] '00000000-0000-0000-0000-000000000001'
    # Port zero is reserved and cannot name a listening TCP destination. These
    # cases prove cancellation happens before transport, so no server is needed.
    $script:NoSendAuthority = [uri] 'http://127.0.0.1:0/'
    $script:openServers = [System.Collections.Generic.List[object]]::new()

    function Start-TokenPipelineServer {
        param(
            [object[]] $Responses,
            [scriptblock] $CandidatePortProvider = {
                param([int] $Attempt)

                [System.Security.Cryptography.RandomNumberGenerator]::GetInt32(
                    49152,
                    65536)
            }
        )

        $listener = $null
        $port = 0
        $bindFailure = $null
        foreach ($attempt in 1..16) {
            $candidatePort = & $CandidatePortProvider $attempt
            $candidate = [System.Net.HttpListener]::new()
            $candidate.Prefixes.Add("http://127.0.0.1:$candidatePort/")
            try {
                $candidate.Start()
                $listener = $candidate
                $port = $candidatePort
                break
            }
            catch [System.Net.HttpListenerException] {
                $bindFailure = $_.Exception
                try { $candidate.Close() } catch { }
            }
        }
        if ($null -eq $listener) {
            throw [System.InvalidOperationException]::new(
                'Could not bind the token-pipeline loopback server after 16 attempts.',
                $bindFailure)
        }

        $runspace = [runspacefactory]::CreateRunspace()
        $runspace.Open()
        $powershell = [powershell]::Create()
        $powershell.Runspace = $runspace
        [void] $powershell.AddScript({
            param($Listener, $Responses)

            $captured = [System.Collections.Generic.List[object]]::new()
            try {
                foreach ($responseDefinition in @($Responses)) {
                    $context = $Listener.GetContext()
                    $captured.Add([pscustomobject] @{
                        Path          = $context.Request.Url.PathAndQuery
                        Authorization = $context.Request.Headers['Authorization']
                    })

                    $context.Response.StatusCode = [int] $responseDefinition.StatusCode
                    if (-not [string]::IsNullOrEmpty([string] $responseDefinition.Body)) {
                        $bytes = [System.Text.Encoding]::UTF8.GetBytes([string] $responseDefinition.Body)
                        $context.Response.ContentType = 'application/json'
                        $context.Response.ContentLength64 = $bytes.Length
                        $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                    }
                    $context.Response.Close()
                }
            }
            catch {
                $captured.Add([pscustomobject] @{ Error = $_.Exception.Message })
            }

            return ,$captured.ToArray()
        }).AddArgument($listener).AddArgument($Responses)

        $handle = $powershell.BeginInvoke()
        $server = [pscustomobject] @{
            Listener  = $listener
            PowerShell = $powershell
            Handle    = $handle
            Runspace  = $runspace
            Authority = [uri] "http://127.0.0.1:$port/"
        }
        $script:openServers.Add($server)
        return $server
    }

    function Stop-TokenPipelineServer {
        param($Server)

        if ($null -eq $Server) { return @() }

        $captured = @()
        if ($null -ne $Server.Listener) {
            try { $Server.Listener.Stop() } catch { }
            try { $Server.Listener.Close() } catch { }
        }
        if ($null -ne $Server.PowerShell -and $null -ne $Server.Handle) {
            try { $captured = @($Server.PowerShell.EndInvoke($Server.Handle)) }
            catch { $captured = @([pscustomobject] @{ Error = $_.Exception.Message }) }
        }
        if ($null -ne $Server.Runspace) {
            try { $Server.Runspace.Close() } catch { }
            try { $Server.Runspace.Dispose() } catch { }
        }
        return $captured
    }

    function New-RotatingTokenSource {
        param([string] $ClaimedTenantId = $null)

        $source = [pscustomobject] @{
            CanRefresh           = $true
            AuthMode             = 'Provider'
            Audience             = 'https://graph.microsoft.com'
            ClientId             = 'client-id'
            CredentialGeneration = 'generation-1'
            ClaimedTenantId      = $ClaimedTenantId
            AcquireFlags         = [System.Collections.Generic.List[bool]]::new()
        }

        $source | Add-Member -MemberType ScriptMethod -Name Acquire -Value {
            param([bool] $forceRefresh, $cancellationToken)

            $this.AcquireFlags.Add($forceRefresh)
            $ordinal = $this.AcquireFlags.Count
            return [pscustomobject] @{
                AccessToken           = "token-$ordinal"
                ExpiresOnUtc          = [System.DateTimeOffset]::MinValue
                ReceivedOnUtc         = [System.DateTimeOffset]::UtcNow
                TokenType             = 'Bearer'
                Scopes                = @('https://graph.microsoft.com/.default')
                VerifiedTenantId      = $this.ClaimedTenantId
                TokenFingerprint      = "fingerprint-$ordinal"
                CredentialGeneration = $this.CredentialGeneration
            }
        }

        return $source
    }

    function New-TokenPipelineContext {
        param(
            [uri] $Authority,
            [object] $TokenSource,
            [guid] $ClientId = [guid] '00000000-0000-0000-0000-000000000010'
        )

        return [pscustomobject] @{
            ProfileId             = 'token-identity-test'
            TenantId              = $script:TenantId
            Cloud                 = 'Global'
            GraphBaseUri          = $Authority
            ClientId              = $ClientId
            TokenSource           = $TokenSource
            CredentialFingerprint = 'credential-fingerprint'
            AcquisitionCacheKey   = 'token-identity-acquisition-key'
            IdentityState         = 'NotAcquired'
        }
    }

    function New-TokenPipelineDescriptor {
        param(
            [string] $ReplayPolicy = 'Safe',
            [string] $ThrottleClass = 'Read',
            [string] $IdentityRequirement
        )

        $descriptor = @{
            CredentialPolicy = 'GraphBearer'
            ReplayPolicy     = $ReplayPolicy
            ThrottleClass    = $ThrottleClass
            ResourceFamily   = 'Graph.Test'
            ApiVersion       = 'v1.0'
            Condition        = $null
            Reconciliation   = $null
        }

        if ($PSBoundParameters.ContainsKey('IdentityRequirement')) {
            $descriptor.IdentityRequirement = $IdentityRequirement
        }

        return $descriptor
    }
}

Describe 'Composed retry and sender token identity' {
    AfterEach {
        foreach ($server in @($script:openServers)) {
            if ($null -eq $server) { continue }
            if ($null -ne $server.Listener) {
                try { $server.Listener.Stop() } catch { }
                try { $server.Listener.Close() } catch { }
            }
            if ($null -ne $server.PowerShell -and $null -ne $server.Handle) {
                try { $null = $server.PowerShell.EndInvoke($server.Handle) } catch { }
            }
            if ($null -ne $server.Runspace) {
                try { $server.Runspace.Close() } catch { }
                try { $server.Runspace.Dispose() } catch { }
            }
        }
        $script:openServers.Clear()
        InModuleScope GraphKit {
            $script:GraphTenantBindingCache = @{}
        }
    }

    It 'retries an occupied bind candidate and reports the exact bound authority' {
        $script:collisionCandidateCalls = 0
        $script:collisionBlocker = [System.Net.Sockets.TcpListener]::new(
            [System.Net.IPAddress]::Loopback,
            0)
        $script:collisionBlocker.Start()
        $script:collisionBlockedPort =
            ([System.Net.IPEndPoint] $script:collisionBlocker.LocalEndpoint).Port

        try {
            $server = Start-TokenPipelineServer -Responses @() -CandidatePortProvider {
                param([int] $Attempt)

                $script:collisionCandidateCalls++
                if ($Attempt -eq 2) {
                    $script:collisionBlocker.Stop()
                }
                return $script:collisionBlockedPort
            }

            $script:collisionCandidateCalls | Should -Be 2
            $server.Authority.AbsoluteUri | Should -BeExactly (
                "http://127.0.0.1:{0}/" -f $script:collisionBlockedPort)
        }
        finally {
            $script:collisionBlocker.Stop()
            $script:collisionBlocker.Dispose()
        }
    }

    It 'acquires exactly once for one ordinary Graph attempt' {
        $server = Start-TokenPipelineServer -Responses @(
            @{ StatusCode = 204; Body = $null }
        )
        $authority = $server.Authority
        $tokenSource = New-RotatingTokenSource

        $result = InModuleScope GraphKit -ArgumentList (New-TokenPipelineContext -Authority $authority -TokenSource $tokenSource), (New-TokenPipelineDescriptor), $authority {
            param($Context, $Descriptor, $Authority)
            Invoke-GraphRetry -Context $Context -Descriptor $Descriptor -Uri ([uri]::new($Authority, 'resource')) `
                -Method GET -Headers @{} -Body $null -CancellationToken ([System.Threading.CancellationToken]::None)
        }

        $captured = Stop-TokenPipelineServer $server
        $result.Outcome | Should -Be 'Succeeded'
        $tokenSource.AcquireFlags.Count | Should -Be 1
        $captured.Count | Should -Be 1
        $captured[0].Authorization | Should -Be 'Bearer token-1'
    }

    It 'proves a descriptor-verified GET even when the provider claims the tenant without a cache record' {
        $server = Start-TokenPipelineServer -Responses @(
            @{ StatusCode = 200; Body = '{"value":[]}' }
        )
        $authority = $server.Authority
        $tokenSource = New-RotatingTokenSource -ClaimedTenantId $script:TenantId.ToString()
        $script:verifiedGetProofCalls = 0
        $script:verifiedGetProofToken = $null
        $script:verifiedGetProofScope = $null
        $script:verifiedGetProofRemaining = [TimeSpan]::Zero

        Mock Confirm-GraphTenantBinding -ModuleName GraphKit {
            param($Context, $TokenResult, $CancellationToken, $RemainingDeadline)

            $script:verifiedGetProofCalls++
            $script:verifiedGetProofToken = [string] $TokenResult.AccessToken
            $script:verifiedGetProofRemaining = [TimeSpan] $RemainingDeadline
            $script:verifiedGetProofScope = & (Get-Module GraphKit) {
                param($ProofContext, $ProofTokenResult)
                $scope = New-GraphThrottleScope -Context $ProofContext -Descriptor @{
                    ThrottleClass  = 'Read'
                    ResourceFamily = 'Graph.Directory'
                }
                $cacheKey = Get-GraphTenantBindingKey `
                    -Fingerprint ([string] $ProofTokenResult.TokenFingerprint) `
                    -Generation ([string] $ProofTokenResult.CredentialGeneration) `
                    -TenantId $ProofContext.TenantId
                $script:GraphTenantBindingCache[$cacheKey] = $true
                return $scope
            } $Context $TokenResult
            $TokenResult.VerifiedTenantId = [string] $Context.TenantId
        }

        $result = InModuleScope GraphKit -ArgumentList `
            (New-TokenPipelineContext -Authority $authority -TokenSource $tokenSource), `
            (New-TokenPipelineDescriptor -IdentityRequirement Verified), $authority {
            param($Context, $Descriptor, $Authority)
            Invoke-GraphRetry -Context $Context -Descriptor $Descriptor -Uri ([uri]::new($Authority, 'resource')) `
                -Method GET -Headers @{} -Body $null -DeadlineSeconds 17 `
                -CancellationToken ([System.Threading.CancellationToken]::None)
        }

        $captured = Stop-TokenPipelineServer $server
        $result.Outcome | Should -Be 'Succeeded'
        $result.Provenance.IdentityState | Should -BeExactly 'VerifiedForToken'
        $result.Provenance.TenantId | Should -Be $script:TenantId
        $result.Provenance.ActualTenantId | Should -Be $script:TenantId
        $result.Provenance.TokenFingerprint | Should -BeExactly 'fingerprint-1'
        $result.Provenance.CredentialGeneration | Should -BeExactly 'generation-1'
        $result.Provenance.Cloud | Should -BeExactly 'Global'
        $result.Provenance.Keys | Should -Not -Contain 'ClientId'
        $result.Provenance.Keys | Should -Not -Contain 'ClientScopeFingerprint'
        $script:verifiedGetProofCalls | Should -Be 1
        $script:verifiedGetProofToken | Should -BeExactly 'token-1'
        $script:verifiedGetProofRemaining | Should -BeGreaterThan ([TimeSpan]::Zero)
        $script:verifiedGetProofRemaining | Should -BeLessOrEqual ([TimeSpan]::FromSeconds(17))
        $script:verifiedGetProofScope.CoarseKey | Should -BeExactly 'Global|00000000-0000-0000-0000-000000000001|00000000-0000-0000-0000-000000000010|Read'
        $script:verifiedGetProofScope.LeafKey | Should -BeExactly 'Global|00000000-0000-0000-0000-000000000001|00000000-0000-0000-0000-000000000010|Read|Graph.Directory'
        $captured | Should -HaveCount 1
        $captured[0].Path | Should -Be '/resource'
        $captured[0].Authorization | Should -BeExactly 'Bearer token-1'
    }

    It 'returns DeadlineExpired and releases admission before acquisition when the inherited proof budget is exhausted' {
        $authority = $script:NoSendAuthority
        $tokenSource = New-RotatingTokenSource
        $script:deadlineProofEntered = 0
        $script:deadlineProofSawCancellation = $false

        Mock Confirm-GraphTenantBinding -ModuleName GraphKit {
            param($Context, $TokenResult, [System.Threading.CancellationToken] $CancellationToken, $RemainingDeadline)
            $script:deadlineProofEntered++
            $script:deadlineProofSawCancellation = $CancellationToken.IsCancellationRequested
            $CancellationToken.ThrowIfCancellationRequested()
        }

        $capture = InModuleScope GraphKit -ArgumentList `
            (New-TokenPipelineContext -Authority $authority -TokenSource $tokenSource), `
            (New-TokenPipelineDescriptor -IdentityRequirement Verified), $authority {
            param($Context, $Descriptor, $Authority)

            $script:deadlineClock = [datetime] '2026-09-01T12:00:00Z'
            $script:deadlineOuterBudget = [TimeSpan]::Zero
            $send = {
                param($Uri, $Method, $Headers, $Body, $CancellationToken, $CredentialPolicy,
                      $TokenSource, $ForceRefresh, $TokenAcquisitionKey, $ExpectedAuthority,
                      $TargetTenantId, $VerifyTenantBinding, $TenantBindingContext)

                # The outer retry supplied both monotonic remaining time and its
                # injected clock deadline. Move that clock to the exact deadline
                # without sleeping; the sender must deduct it before proof.
                $script:deadlineOuterBudget = [TimeSpan] $TenantBindingContext.RemainingDeadline
                $script:deadlineClock = $script:deadlineClock.AddSeconds(5)
                Send-GraphHttpRequest -Uri $Uri -Method $Method -Headers $Headers -Body $Body `
                    -CancellationToken $CancellationToken -CredentialPolicy $CredentialPolicy `
                    -TokenSource $TokenSource -ForceRefresh:$ForceRefresh `
                    -TokenAcquisitionKey $TokenAcquisitionKey -ExpectedAuthority $ExpectedAuthority `
                    -TargetTenantId $TargetTenantId -VerifyTenantBinding:$VerifyTenantBinding `
                    -TenantBindingContext $TenantBindingContext
            }

            $scope = New-GraphThrottleScope -Context $Context -Descriptor $Descriptor
            $result = Invoke-GraphRetry -Context $Context -Descriptor $Descriptor `
                -Uri ([uri]::new($Authority, 'resource')) -Method GET -Headers @{} -Body $null `
                -DeadlineSeconds 5 -CancellationToken ([System.Threading.CancellationToken]::None) `
                -Injections @{
                    Send   = $send
                    UtcNow = { $script:deadlineClock }
                    Delay  = { param($Seconds) }
                    Jitter = { 0.0 }
                }
            [pscustomobject] @{
                Result      = $result
                InFlight    = (Get-GraphThrottleCoordinator).GetInFlight([string] $scope.LeafKey)
                OuterBudget = $script:deadlineOuterBudget
            }
        }

        $capture.Result.Outcome | Should -BeExactly 'DeadlineExpired'
        $capture.Result.Certainty | Should -BeExactly 'Indeterminate'
        $capture.InFlight | Should -Be 0
        $capture.OuterBudget | Should -BeGreaterThan ([TimeSpan]::Zero)
        $capture.OuterBudget | Should -BeLessOrEqual ([TimeSpan]::FromSeconds(5))
        $script:deadlineProofEntered | Should -Be 0
        $script:deadlineProofSawCancellation | Should -BeFalse
        $tokenSource.AcquireFlags | Should -HaveCount 0
    }

    It 'returns Cancelled and releases admission when a descriptor-verified GET is cancelled during proof' {
        $authority = $script:NoSendAuthority
        $cts = [System.Threading.CancellationTokenSource]::new()
        $tokenSource = New-RotatingTokenSource
        $tokenSource | Add-Member -MemberType NoteProperty -Name CancellationSource -Value $cts
        $clockCapture = [pscustomobject] @{ UtcNow = [datetime] '2026-09-01T12:00:00Z' }
        $tokenSource | Add-Member -MemberType NoteProperty -Name ClockCapture -Value $clockCapture
        $tokenSource | Add-Member -MemberType ScriptMethod -Name Acquire -Force -Value {
            param([bool] $forceRefresh, $cancellationToken)

            $this.AcquireFlags.Add($forceRefresh)
            $this.CancellationSource.Cancel()
            $this.ClockCapture.UtcNow = $this.ClockCapture.UtcNow.AddSeconds(5)
            return [pscustomobject] @{
                AccessToken           = 'cancelled-verified-get-token'
                ExpiresOnUtc          = [System.DateTimeOffset]::UtcNow.AddHours(1)
                ReceivedOnUtc         = [System.DateTimeOffset]::UtcNow
                TokenType             = 'Bearer'
                Scopes                = @('https://graph.microsoft.com/.default')
                VerifiedTenantId      = $null
                TokenFingerprint      = 'cancelled-verified-get-fingerprint'
                CredentialGeneration = $this.CredentialGeneration
            }
        }
        $script:cancelledVerifiedGetProofCalls = 0

        Mock Confirm-GraphTenantBinding -ModuleName GraphKit {
            param($Context, $TokenResult, [System.Threading.CancellationToken] $CancellationToken)
            $script:cancelledVerifiedGetProofCalls++
            $CancellationToken.ThrowIfCancellationRequested()
        }

        try {
            $capture = InModuleScope GraphKit -ArgumentList `
                (New-TokenPipelineContext -Authority $authority -TokenSource $tokenSource), `
                (New-TokenPipelineDescriptor -IdentityRequirement Verified), $authority, $cts.Token, $clockCapture {
                param($Context, $Descriptor, $Authority, $CancellationToken, $ClockCapture)

                $utcNow = { $ClockCapture.UtcNow }.GetNewClosure()
                $scope = New-GraphThrottleScope -Context $Context -Descriptor $Descriptor
                $result = Invoke-GraphRetry -Context $Context -Descriptor $Descriptor `
                    -Uri ([uri]::new($Authority, 'resource')) -Method GET -Headers @{} -Body $null `
                    -DeadlineSeconds 5 -CancellationToken $CancellationToken `
                    -Injections @{
                        UtcNow = $utcNow
                        Delay  = { param($Seconds) }
                        Jitter = { 0.0 }
                    }
                [pscustomobject] @{
                    Result   = $result
                    InFlight = (Get-GraphThrottleCoordinator).GetInFlight([string] $scope.LeafKey)
                }
            }

            $capture.Result.Outcome | Should -BeExactly 'Cancelled'
            $capture.Result.Certainty | Should -BeExactly 'Indeterminate'
            $capture.InFlight | Should -Be 0
            $script:cancelledVerifiedGetProofCalls | Should -Be 1
        }
        finally {
            $cts.Dispose()
        }
    }

    It 'uses false then true acquisition flags across one 401 refresh' {
        $server = Start-TokenPipelineServer -Responses @(
            @{ StatusCode = 401; Body = '{"error":{"code":"InvalidAuthenticationToken"}}' }
            @{ StatusCode = 200; Body = '{"value":[]}' }
        )
        $authority = $server.Authority
        $tokenSource = New-RotatingTokenSource
        $injections = @{
            Delay  = { param([double] $Seconds) }
            Jitter = { 0.0 }
        }

        $result = InModuleScope GraphKit -ArgumentList (New-TokenPipelineContext -Authority $authority -TokenSource $tokenSource), (New-TokenPipelineDescriptor), $authority, $injections {
            param($Context, $Descriptor, $Authority, $Injections)
            Invoke-GraphRetry -Context $Context -Descriptor $Descriptor -Uri ([uri]::new($Authority, 'resource')) `
                -Method GET -Headers @{} -Body $null -CancellationToken ([System.Threading.CancellationToken]::None) `
                -Injections $Injections
        }

        $captured = Stop-TokenPipelineServer $server
        $result.Outcome | Should -Be 'Succeeded'
        @($tokenSource.AcquireFlags) | Should -Be @($false, $true)
        @($captured.Authorization) | Should -Be @('Bearer token-1', 'Bearer token-2')
    }

    It 'does not elevate an unproven provider tenant claim into provenance' {
        $server = Start-TokenPipelineServer -Responses @(
            @{ StatusCode = 200; Body = '{"value":[]}' }
        )
        $authority = $server.Authority
        $tokenSource = New-RotatingTokenSource -ClaimedTenantId $script:TenantId.ToString()

        $result = InModuleScope GraphKit -ArgumentList (New-TokenPipelineContext -Authority $authority -TokenSource $tokenSource), (New-TokenPipelineDescriptor), $authority {
            param($Context, $Descriptor, $Authority)
            Invoke-GraphRetry -Context $Context -Descriptor $Descriptor -Uri ([uri]::new($Authority, 'resource')) `
                -Method GET -Headers @{} -Body $null -CancellationToken ([System.Threading.CancellationToken]::None)
        }

        $null = Stop-TokenPipelineServer $server
        $result.Outcome | Should -Be 'Succeeded'
        $result.Provenance.ActualTenantId | Should -BeNullOrEmpty
        $result.Provenance.IdentityState | Should -Be 'NotAcquired'
    }

    It 'does not carry an earlier token proof across a 401 refresh' {
        $server = Start-TokenPipelineServer -Responses @(
            @{ StatusCode = 401; Body = '{"error":{"code":"InvalidAuthenticationToken"}}' }
            @{ StatusCode = 200; Body = '{"value":[]}' }
        )
        $authority = $server.Authority
        $tokenSource = New-RotatingTokenSource -ClaimedTenantId $script:TenantId.ToString()

        InModuleScope GraphKit -ArgumentList $script:TenantId {
            param($TenantId)
            $key = Get-GraphTenantBindingKey -Fingerprint 'fingerprint-1' -Generation 'generation-1' -TenantId $TenantId
            $script:GraphTenantBindingCache[$key] = $true
        }

        $injections = @{
            Delay  = { param([double] $Seconds) }
            Jitter = { 0.0 }
        }
        $result = InModuleScope GraphKit -ArgumentList (New-TokenPipelineContext -Authority $authority -TokenSource $tokenSource), (New-TokenPipelineDescriptor), $authority, $injections {
            param($Context, $Descriptor, $Authority, $Injections)
            Invoke-GraphRetry -Context $Context -Descriptor $Descriptor -Uri ([uri]::new($Authority, 'resource')) `
                -Method GET -Headers @{} -Body $null -CancellationToken ([System.Threading.CancellationToken]::None) `
                -Injections $Injections
        }

        $captured = Stop-TokenPipelineServer $server
        $result.Outcome | Should -Be 'Succeeded'
        @($captured.Authorization) | Should -Be @('Bearer token-1', 'Bearer token-2')
        $result.Provenance.ActualTenantId | Should -BeNullOrEmpty
        $result.Provenance.IdentityState | Should -Be 'NotAcquired'
    }

    It 'cancels during acquisition before tenant proof or mutation bytes are sent' {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $port = ([System.Net.IPEndPoint] $listener.LocalEndpoint).Port
        $authority = [uri] "http://127.0.0.1:$port"
        $cts = [System.Threading.CancellationTokenSource]::new()
        $tokenSource = New-RotatingTokenSource
        $tokenSource | Add-Member -MemberType NoteProperty -Name CancellationSource -Value $cts
        $tokenSource | Add-Member -MemberType NoteProperty -Name LastResult -Value $null
        $tokenSource | Add-Member -MemberType ScriptMethod -Name Acquire -Force -Value {
            param([bool] $forceRefresh, $cancellationToken)

            $this.AcquireFlags.Add($forceRefresh)
            $this.LastResult = [pscustomobject] @{
                AccessToken           = 'cancelled-token'
                ExpiresOnUtc          = [System.DateTimeOffset]::MinValue
                ReceivedOnUtc         = [System.DateTimeOffset]::UtcNow
                TokenType             = 'Bearer'
                Scopes                = @('https://graph.microsoft.com/.default')
                VerifiedTenantId      = $null
                TokenFingerprint      = 'cancelled-fingerprint'
                CredentialGeneration = $this.CredentialGeneration
            }
            $this.CancellationSource.Cancel()
            return $this.LastResult
        }

        try {
            $result = InModuleScope GraphKit -ArgumentList (New-TokenPipelineContext -Authority $authority -TokenSource $tokenSource), (New-TokenPipelineDescriptor -ReplayPolicy NeverReplay -ThrottleClass Write), $authority, $cts.Token {
                param($Context, $Descriptor, $Authority, $CancellationToken)
                Invoke-GraphRetry -Context $Context -Descriptor $Descriptor -Uri ([uri]::new($Authority, 'mutation')) `
                    -Method POST -Headers @{} -Body @{ value = 'x' } -CancellationToken $CancellationToken
            }

            $listener.Pending() | Should -BeFalse
            $tokenSource.AcquireFlags.Count | Should -Be 1
            $tokenSource.LastResult.VerifiedTenantId | Should -BeNullOrEmpty
            (InModuleScope GraphKit { $script:GraphTenantBindingCache.Count }) | Should -Be 0
            $result.Outcome | Should -BeExactly 'Cancelled'
            $result.Certainty | Should -BeExactly 'Indeterminate'
        }
        finally {
            $listener.Stop()
            $cts.Dispose()
        }
    }

    It 'proves and sends a mutation with the same exact token' {
        $tenantBody = '{"value":[{"id":"' + $script:TenantId.ToString() + '"}]}'
        $server = Start-TokenPipelineServer -Responses @(
            @{ StatusCode = 200; Body = $tenantBody }
            @{ StatusCode = 204; Body = $null }
        )
        $authority = $server.Authority
        $tokenSource = New-RotatingTokenSource

        $result = InModuleScope GraphKit -ArgumentList (New-TokenPipelineContext -Authority $authority -TokenSource $tokenSource), (New-TokenPipelineDescriptor -ReplayPolicy NeverReplay -ThrottleClass Write), $authority {
            param($Context, $Descriptor, $Authority)
            Invoke-GraphRetry -Context $Context -Descriptor $Descriptor -Uri ([uri]::new($Authority, 'mutation')) `
                -Method POST -Headers @{} -Body @{ value = 'x' } `
                -CancellationToken ([System.Threading.CancellationToken]::None)
        }

        $captured = Stop-TokenPipelineServer $server
        $result.Outcome | Should -Be 'Succeeded'
        $tokenSource.AcquireFlags.Count | Should -Be 1
        $captured.Count | Should -Be 2
        $captured[0].Path | Should -Be '/v1.0/organization'
        $captured[1].Path | Should -Be '/mutation'
        $captured[0].Authorization | Should -Be $captured[1].Authorization
        $captured[1].Authorization | Should -Be 'Bearer token-1'
        $result.Provenance.ActualTenantId | Should -Be $script:TenantId
        $result.Provenance.IdentityState | Should -Be 'VerifiedForToken'
        $result.Provenance.TokenFingerprint | Should -BeExactly 'fingerprint-1'
        $result.Provenance.CredentialGeneration | Should -BeExactly 'generation-1'
        $result.Provenance.Cloud | Should -BeExactly 'Global'
        $result.Provenance.Keys | Should -Not -Contain 'ClientId'
        $result.Provenance.Keys | Should -Not -Contain 'ClientScopeFingerprint'
    }
}
