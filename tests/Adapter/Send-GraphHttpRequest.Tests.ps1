BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw "No built GraphKit module found under '$repoRoot/output/module/GraphKit'. Run './build.ps1 -Tasks build' first."
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force -ErrorAction Stop

    $script:VerifiedTenant = [guid] '00000000-0000-0000-0000-000000000001'
    $script:openServers = [System.Collections.Generic.List[object]]::new()

    function Get-FreePort {
        $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $l.Start()
        $port = ([System.Net.IPEndPoint] $l.LocalEndpoint).Port
        $l.Stop()
        return $port
    }

    function New-TestTokenSource {
        # Duck-typed token source: a plain PSCustomObject exposing the module's
        # Acquire/CanRefresh contract, never a module class. Acquire must be a
        # ScriptMethod (not a scriptblock property) because the module invokes
        # $TokenSource.Acquire($forceRefresh, $ct) as a method.
        $source = [pscustomobject] @{
            CanRefresh           = $true
            VerifiedTenantId     = $script:VerifiedTenant
            CredentialGeneration = 'test-generation'
        }
        $source | Add-Member -MemberType ScriptMethod -Name Acquire -Value {
            param([bool] $forceRefresh, $ct)
            [pscustomobject] @{
                AccessToken          = 'test-bearer-token'
                VerifiedTenantId     = $script:VerifiedTenant
                TokenFingerprint     = 'test-fingerprint'
                CredentialGeneration = 'test-generation'
            }
        }
        return $source
    }

    <#
        Start an HttpListener serving one request on a background runspace.
        The handler scriptblock receives -Context, -Listener, and a -Captured
        dictionary it may populate; that dictionary is returned from Stop-.
        -HoldSeconds keeps the connection open after the handler returns so
        the client-side timeouts (header/body/cancellation) can fire while
        the response is still pending.
    #>
    function Start-GraphLoopback {
        param([int] $Port, [scriptblock] $Handler, [int] $HoldSeconds = 0)

        $listener = [System.Net.HttpListener]::new()
        $listener.Prefixes.Add("http://127.0.0.1:$Port/")
        $listener.Start()

        $runspace = [runspacefactory]::CreateRunspace()
        $runspace.Open()
        $ps = [powershell]::Create()
        $ps.Runspace = $runspace
        [void] $ps.AddScript({
            param($Listener, $Handler, $HoldSeconds)
            $captured = [System.Collections.Generic.Dictionary[string, object]]::new()
            try {
                $ctx = $Listener.GetContext()
                $captured['Authorization'] = $ctx.Request.Headers['Authorization']
                $captured['Path'] = $ctx.Request.Url.PathAndQuery
                & $Handler -Context $ctx -Listener $Listener -Captured $captured
                if ($HoldSeconds -gt 0) {
                    [System.Threading.Thread]::Sleep([int] ($HoldSeconds * 1000))
                }
            }
            catch {
                $captured['Error'] = $_.Exception.Message
            }
            finally {
                try { $ctx.Response.Close() } catch { }
            }
            $captured
        }).AddArgument($listener).AddArgument($Handler).AddArgument($HoldSeconds)

        $handle = $ps.BeginInvoke()

        $server = [pscustomobject] @{
            Listener = $listener
            Ps       = $ps
            Handle   = $handle
            Runspace = $runspace
        }
        $script:openServers.Add($server)
        return $server
    }

    function Stop-GraphLoopback {
        param($Server)

        if ($null -eq $Server) {
            return $null
        }

        # Complete the runspace before touching the listener: every test in
        # this file connects, so EndInvoke returns promptly. Stopping the
        # listener first could fault an in-flight probe or handler inside the
        # runspace, and a throw there tears down the host session.
        if ($null -ne $Server.Ps -and $null -ne $Server.Handle) {
            try { $captured = $Server.Ps.EndInvoke($Server.Handle) } catch { $captured = @{ Error = $_.Exception.Message } }
        }
        if ($null -ne $Server.Listener) {
            try { $Server.Listener.Stop() } catch { }
            try { $Server.Listener.Close() } catch { }
        }
        if ($null -ne $Server.Runspace) {
            try { $Server.Runspace.Close() } catch { }
            try { $Server.Runspace.Dispose() } catch { }
        }
        return $captured
    }
}

Describe 'Send-GraphHttpRequest (loopback through the real sender)' {

    Context 'loopback server lifecycle' {
        AfterEach {
            foreach ($server in @($script:openServers)) {
                if ($null -eq $server) { continue }
                # Stop the listener first so a runspace still blocked in
                # Listener.GetContext() fails fast instead of hanging EndInvoke().
                if ($null -ne $server.Listener) {
                    try { $server.Listener.Stop() } catch { }
                    try { $server.Listener.Close() } catch { }
                }
                if ($null -ne $server.Ps -and $null -ne $server.Handle) {
                    try { $null = $server.Ps.EndInvoke($server.Handle) } catch { }
                }
                if ($null -ne $server.Runspace) {
                    try { $server.Runspace.Close() } catch { }
                    try { $server.Runspace.Dispose() } catch { }
                }
            }
            $script:openServers.Clear()
        }


    It 'does not follow redirects: a 3xx surfaces as the result' {
        $port = Get-FreePort
        $null = Start-GraphLoopback -Port $port -Handler {
            param($Context, $Listener, $Captured)
            $Context.Response.StatusCode = 302
            $Context.Response.RedirectLocation = 'http://127.0.0.1:1/redirected'
        }

        $r = InModuleScope GraphKit -ArgumentList $port {
            param($Port)
            Send-GraphHttpRequest -Uri ([uri] "http://127.0.0.1:$Port/x") -Method GET -CredentialPolicy None
        }

        $r.ResponseReceived | Should -BeTrue
        $r.StatusCode | Should -Be 302
    }

    It 'GraphBearer attaches only to the exact expected authority' {
        $port = Get-FreePort
        $server = Start-GraphLoopback -Port $port -Handler {
            param($Context, $Listener, $Captured)
            $Context.Response.StatusCode = 204
        }
        $authority = [uri] "http://127.0.0.1:$port"

        $r = InModuleScope GraphKit -ArgumentList $port, $authority, (New-TestTokenSource) {
            param($Port, $ExpectedAuthority, $TokenSource)
            Send-GraphHttpRequest -Uri ([uri] "http://127.0.0.1:$Port/x") -Method GET `
                -CredentialPolicy GraphBearer -ExpectedAuthority $ExpectedAuthority -TokenSource $TokenSource
        }

        $captured = Stop-GraphLoopback $server
        $captured['Authorization'] | Should -Be 'Bearer test-bearer-token'
        $r.StatusCode | Should -Be 204
    }

    It 'GraphBearer refuses a foreign authority with a hard error' {
        $port = Get-FreePort
        $wrongAuthority = [uri] 'https://graph.microsoft.com'

        InModuleScope GraphKit -ArgumentList $port, $wrongAuthority, (New-TestTokenSource) {
            param($Port, $WrongAuthority, $TokenSource)
            { Send-GraphHttpRequest -Uri ([uri] "http://127.0.0.1:$Port/x") -Method GET `
                -CredentialPolicy GraphBearer -ExpectedAuthority $WrongAuthority -TokenSource $TokenSource } |
                Should -Throw '*Credential boundary violated*'
        }
    }

    It 'None policy never carries an Authorization header' {
        $port = Get-FreePort
        $server = Start-GraphLoopback -Port $port -Handler {
            param($Context, $Listener, $Captured)
            $Context.Response.StatusCode = 204
        }

        $r = InModuleScope GraphKit -ArgumentList $port {
            param($Port)
            Send-GraphHttpRequest -Uri ([uri] "http://127.0.0.1:$Port/x") -Method GET -CredentialPolicy None
        }

        $captured = Stop-GraphLoopback $server
        $captured['Authorization'] | Should -BeNullOrEmpty
        $r.StatusCode | Should -Be 204
    }

    It 'enforces the tenant-binding gate on mutating sends' {
        $port = Get-FreePort
        $server = Start-GraphLoopback -Port $port -Handler {
            param($Context, $Listener, $Captured)
            $Context.Response.StatusCode = 204
        }
        $authority = [uri] "http://127.0.0.1:$port"

        # Matching tenant: the injected prover stands in for the real
        # /organization proof read and marks the token verified for the target
        # tenant, so the binding gate passes and the send is attempted.
        $verifiedProver = {
            param($Context, $TokenResult)
            $TokenResult.VerifiedTenantId = $Context.TenantId
        }
        $r = InModuleScope GraphKit -ArgumentList $port, $authority, (New-TestTokenSource), $script:VerifiedTenant, $verifiedProver {
            param($Port, $ExpectedAuthority, $TokenSource, $TargetTenantId, $TenantBindingProver)
            Send-GraphHttpRequest -Uri ([uri] "http://127.0.0.1:$Port/x") -Method POST -Body @{} `
                -CredentialPolicy GraphBearer -ExpectedAuthority $ExpectedAuthority -TokenSource $TokenSource `
                -TargetTenantId $TargetTenantId -VerifyTenantBinding -TenantBindingProver $TenantBindingProver
        }
        $captured = Stop-GraphLoopback $server
        $r.StatusCode | Should -Be 204

        # Mismatched tenant: the injected prover confirms the token's REAL
        # tenant (the one its source was issued for), which is not the target,
        # so the sender's binding gate fires its hard error and nothing is sent.
        $realTenantProver = {
            param($Context, $TokenResult)
            $TokenResult.VerifiedTenantId = [string] $Context.TokenSource.VerifiedTenantId
        }
        $port2 = Get-FreePort
        InModuleScope GraphKit -ArgumentList $port2, ([uri] "http://127.0.0.1:$port2"), (New-TestTokenSource), ([guid] 'ffffffff-ffff-ffff-ffff-ffffffffffff'), $realTenantProver {
            param($Port, $ExpectedAuthority, $TokenSource, $TargetTenantId, $TenantBindingProver)
            { Send-GraphHttpRequest -Uri ([uri] "http://127.0.0.1:$Port/x") -Method POST -Body @{} `
                -CredentialPolicy GraphBearer -ExpectedAuthority $ExpectedAuthority -TokenSource $TokenSource `
                -TargetTenantId $TargetTenantId -VerifyTenantBinding -TenantBindingProver $TenantBindingProver } |
                Should -Throw '*Tenant binding failed*'
        }
    }

    It 'normalizes a connection failure into a result (never throws)' {
        $port = Get-FreePort  # nothing listens here

        $r = InModuleScope GraphKit -ArgumentList $port {
            param($Port)
            Send-GraphHttpRequest -Uri ([uri] "http://127.0.0.1:$Port/x") -Method GET -CredentialPolicy None -TimeoutConnectionSeconds 2
        }

        $r.ResponseReceived | Should -BeFalse
        $r.StatusCode | Should -Be 0
        $r.TransportException | Should -Not -BeNullOrEmpty
    }

    It 'fires the header timeout independently' {
        $port = Get-FreePort
        # Hold the connection open past the client's 1s header timeout without
        # ever writing a response. The hold runs in the loopback runspace, not
        # the handler, so the handler scriptblock is never active while the
        # client aborts the connection.
        $null = Start-GraphLoopback -Port $port -HoldSeconds 2 -Handler {
            param($Context, $Listener, $Captured)
        }

        $r = InModuleScope GraphKit -ArgumentList $port {
            param($Port)
            Send-GraphHttpRequest -Uri ([uri] "http://127.0.0.1:$Port/x") -Method GET -CredentialPolicy None -TimeoutHeadersSeconds 1
        }

        $r.ResponseReceived | Should -BeFalse
        $r.StatusCode | Should -Be 0
        $r.TransportException | Should -Not -BeNullOrEmpty
    }

    It 'fires the body timeout independently of the header phase' {
        $port = Get-FreePort
        # Send headers and the first body chunk, then hold the connection open
        # past the client's 1s body timeout without sending the rest. The hold
        # runs in the loopback runspace, not the handler, so the handler
        # scriptblock is never active while the client aborts the connection.
        $null = Start-GraphLoopback -Port $port -HoldSeconds 2 -Handler {
            param($Context, $Listener, $Captured)
            $Context.Response.StatusCode = 200
            $Context.Response.ContentType = 'application/json'
            $Context.Response.SendChunked = $true
            $first = [System.Text.Encoding]::UTF8.GetBytes('{"value":')
            $Context.Response.OutputStream.Write($first, 0, $first.Length)
            $Context.Response.OutputStream.Flush()
        }

        $r = InModuleScope GraphKit -ArgumentList $port {
            param($Port)
            Send-GraphHttpRequest -Uri ([uri] "http://127.0.0.1:$Port/x") -Method GET -CredentialPolicy None -TimeoutBodySeconds 1
        }

        $r.ResponseReceived | Should -BeTrue
        $r.StatusCode | Should -Be 200
        $r.TransportException | Should -Not -BeNullOrEmpty
    }

    It 'a cancelled token aborts an in-flight request' {
        $port = Get-FreePort
        # Hold the connection open past the client's 250ms cancellation without
        # ever writing a response. The hold runs in the loopback runspace, not
        # the handler, so the handler scriptblock is never active while the
        # client aborts the connection.
        $null = Start-GraphLoopback -Port $port -HoldSeconds 3 -Handler {
            param($Context, $Listener, $Captured)
        }

        $cts = [System.Threading.CancellationTokenSource]::new()
        $cts.CancelAfter(250)

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r = InModuleScope GraphKit -ArgumentList $port, $cts.Token {
            param($Port, $CancellationToken)
            Send-GraphHttpRequest -Uri ([uri] "http://127.0.0.1:$Port/x") -Method GET -CredentialPolicy None `
                -CancellationToken $CancellationToken -TimeoutHeadersSeconds 30
        }
        $sw.Stop()

        $r.ResponseReceived | Should -BeFalse
        $r.TransportException | Should -Not -BeNullOrEmpty
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 5
    }

    It 'issues exactly one physical send (no hidden retry handler)' {
        $port = Get-FreePort
        $server = Start-GraphLoopback -Port $port -Handler {
            param($Context, $Listener, $Captured)

            # Record the request BEFORE closing the response. Closing releases the client,
            # so the test scope can resume and read $Captured while this runspace has not yet
            # executed the line after Close() - the assertion then sees $null instead of 1.
            # That is a genuine happens-before bug in the test, and it failed roughly one run
            # in three under load.
            $Captured['Count'] = 1

            $Context.Response.StatusCode = 503
            $Context.Response.Close()
        }

        $r = InModuleScope GraphKit -ArgumentList $port {
            param($Port)
            Send-GraphHttpRequest -Uri ([uri] "http://127.0.0.1:$Port/x") -Method GET -CredentialPolicy None
        }
        # A second request should never arrive: probe for one with a bounded
        # wait from the test scope. The listener is still live here; it is
        # only stopped after the probe finishes, so the pending operation
        # cannot fault while this scriptblock runs.
        $second = $false
        try {
            $iar = $server.Listener.BeginGetContext($null, $null)
            if ($null -ne $iar -and $iar.AsyncWaitHandle.WaitOne(1000)) {
                $second = $true
            }
        }
        catch { }

        $captured = Stop-GraphLoopback $server
        if ($second) { $captured['Count'] = 2 }
        $r.StatusCode | Should -Be 503
        $captured['Count'] | Should -Be 1
    }

    It 'normalizes duplicate response headers into a single joined value' {
        $port = Get-FreePort
        $server = Start-GraphLoopback -Port $port -Handler {
            param($Context, $Listener, $Captured)
            $Context.Response.StatusCode = 200
            $Context.Response.Headers.Add('X-Dup', 'a')
            $Context.Response.Headers.Add('X-Dup', 'b')
        }

        $r = InModuleScope GraphKit -ArgumentList $port {
            param($Port)
            Send-GraphHttpRequest -Uri ([uri] "http://127.0.0.1:$Port/x") -Method GET -CredentialPolicy None
        }

        $captured = Stop-GraphLoopback $server
        $r.Headers['X-Dup'] | Should -Be 'a, b'
    }

    It 'normalizes an empty body to null' {
        $port = Get-FreePort
        $server = Start-GraphLoopback -Port $port -Handler {
            param($Context, $Listener, $Captured)
            $Context.Response.StatusCode = 204
        }

        $r = InModuleScope GraphKit -ArgumentList $port {
            param($Port)
            Send-GraphHttpRequest -Uri ([uri] "http://127.0.0.1:$Port/x") -Method GET -CredentialPolicy None
        }

        $captured = Stop-GraphLoopback $server
        $r.StatusCode | Should -Be 204
        $r.Body | Should -BeNullOrEmpty
    }

    It 'normalizes a mid-response connection close into a result' {
        $port = Get-FreePort
        $null = Start-GraphLoopback -Port $port -Handler {
            param($Context, $Listener, $Captured)
            $Context.Response.StatusCode = 200
            $Context.Response.ContentLength64 = 1000
            $partial = [System.Text.Encoding]::UTF8.GetBytes('{"value":')
            $Context.Response.OutputStream.Write($partial, 0, $partial.Length)
            $Context.Response.OutputStream.Flush()
            $Context.Response.Abort()
        }

        $r = InModuleScope GraphKit -ArgumentList $port {
            param($Port)
            Send-GraphHttpRequest -Uri ([uri] "http://127.0.0.1:$Port/x") -Method GET -CredentialPolicy None
        }

        $r.ResponseReceived | Should -BeTrue
        $r.TransportException | Should -Not -BeNullOrEmpty
    }

    It 'feeds a malformed Retry-After through the delay parser' {
        $port = Get-FreePort
        $server = Start-GraphLoopback -Port $port -Handler {
            param($Context, $Listener, $Captured)
            $Context.Response.StatusCode = 429
            $Context.Response.AddHeader('Retry-After', '30,120')
        }

        $r = InModuleScope GraphKit -ArgumentList $port {
            param($Port)
            Send-GraphHttpRequest -Uri ([uri] "http://127.0.0.1:$Port/x") -Method GET -CredentialPolicy None
        }

        $captured = Stop-GraphLoopback $server
        $r.StatusCode | Should -Be 429

        $delay = InModuleScope GraphKit -ArgumentList $r.Headers['Retry-After'] {
            param($RetryAfterValues)
            Get-GraphRetryDelay -RetryAfterValues $RetryAfterValues -UtcNow ([datetime]::UtcNow) -Attempt 1 -Jitter { 1.0 }
        }
        $delay.DelaySeconds | Should -Be 120
        $delay.Malformed | Should -BeTrue
        $delay.Source | Should -Be 'RetryAfterList'
    }
}
}
