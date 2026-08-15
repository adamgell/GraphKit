<#
    Loopback tests through the REAL sender.

    Every other transport test injects Send, which means they pass whether or not the
    actual HttpClient behaves. A sender that silently follows redirects, forwards
    Authorization to a redirect target, ignores the split timeouts, or has a retrying
    handler installed underneath would satisfy the entire unit suite. The properties
    GraphKit promises about the WIRE have to be asserted on the wire.

    These run against an in-process HttpListener on 127.0.0.1, so they are deterministic
    and need no network or tenant. They are the tests the design spec calls for under
    "The real sender must be tested, not only the injected one".
#>

BeforeAll {
    $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:ModulePath = Join-Path $repoRoot 'output/module/GraphKit/0.0.1/GraphKit.psd1'
    Import-Module $script:ModulePath -Force -ErrorAction Stop

    # --- Minimal loopback server -------------------------------------------------
    # Handlers are keyed by absolute path. Each returns a hashtable describing the
    # response; the listener thread records what it actually received so tests can
    # assert on the request as well as the response.
    class LoopbackServer {
        [System.Net.HttpListener] $Listener
        [string] $Prefix
        [hashtable] $Handlers
        [System.Collections.Concurrent.ConcurrentBag[object]] $Received
        [System.Threading.Tasks.Task] $Pump
        [bool] $Stopping

        LoopbackServer([int] $Port) {
            $this.Prefix = "http://127.0.0.1:$Port/"
            $this.Listener = [System.Net.HttpListener]::new()
            $this.Listener.Prefixes.Add($this.Prefix)
            $this.Handlers = @{}
            $this.Received = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
        }

        [void] Start() {
            $this.Listener.Start()
            $listener = $this.Listener
            $handlers = $this.Handlers
            $received = $this.Received

            $this.Pump = [System.Threading.Tasks.Task]::Run([Action] {
                    while ($listener.IsListening) {
                        try {
                            $context = $listener.GetContext()
                        }
                        catch {
                            break
                        }

                        $request = $context.Request
                        $path = $request.Url.AbsolutePath

                        $received.Add([pscustomobject] @{
                                Path          = $path
                                Method        = $request.HttpMethod
                                Authorization = $request.Headers['Authorization']
                                Query         = $request.Url.Query
                            })

                        $spec = $handlers[$path]
                        if ($null -eq $spec) { $spec = @{ Status = 404; Body = '{}' } }

                        $response = $context.Response
                        try {
                            if ($spec.ContainsKey('DelaySeconds')) {
                                [System.Threading.Thread]::Sleep([int] ($spec['DelaySeconds'] * 1000))
                            }

                            $response.StatusCode = [int] $spec['Status']
                            if ($spec.ContainsKey('Location')) {
                                $response.AddHeader('Location', [string] $spec['Location'])
                            }
                            $response.ContentType = 'application/json'

                            $bytes = [System.Text.Encoding]::UTF8.GetBytes([string] $spec['Body'])
                            $response.ContentLength64 = $bytes.Length
                            $response.OutputStream.Write($bytes, 0, $bytes.Length)
                        }
                        catch {
                            # Client hung up (expected for timeout tests).
                        }
                        finally {
                            try { $response.OutputStream.Close() } catch { }
                        }
                    }
                })
        }

        [void] Stop() {
            $this.Stopping = $true
            try { $this.Listener.Stop() } catch { }
            try { $this.Listener.Close() } catch { }
        }
    }

    function Get-FreePort {
        $probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $probe.Start()
        $port = ([System.Net.IPEndPoint] $probe.LocalEndpoint).Port
        $probe.Stop()
        return $port
    }

    $script:Port = Get-FreePort
    $script:Server = [LoopbackServer]::new($script:Port)
    $script:Server.Handlers['/ok'] = @{ Status = 200; Body = '{"value":[{"id":"1"}]}' }
    $script:Server.Handlers['/redirect'] = @{ Status = 302; Body = ''; Location = "http://127.0.0.1:$($script:Port)/target" }
    $script:Server.Handlers['/target'] = @{ Status = 200; Body = '{"reached":"target"}' }
    $script:Server.Handlers['/slowbody'] = @{ Status = 200; Body = '{"value":[]}'; DelaySeconds = 3 }
    $script:Server.Start()

    $script:BaseUri = [uri] "http://127.0.0.1:$($script:Port)/"

    # A token source that hands out a recognizable bearer so the listener can prove
    # whether Authorization was attached.
    $script:FakeToken = 'LOOPBACK-TOKEN-VALUE'
    $script:TokenSource = [pscustomobject] @{ AuthMode = 'Test'; CanRefresh = $false }
    $script:TokenSource | Add-Member -MemberType ScriptMethod -Name Acquire -Value {
        param($ForceRefresh, $Cancellation)
        [pscustomobject] @{
            AccessToken          = 'LOOPBACK-TOKEN-VALUE'
            VerifiedTenantId     = [guid]::Empty.ToString()
            TokenFingerprint     = 'fp'
            CredentialGeneration = 'gen'
        }
    }
}

AfterAll {
    if ($null -ne $script:Server) { $script:Server.Stop() }
}

Describe 'Real sender: credential boundary' {

    It 'never attaches Authorization under CredentialPolicy None' {
        # This is the report-download path: a SAS-signed URL on a non-Graph host that
        # carries its own authorization and must never receive the Graph bearer.
        $result = InModuleScope GraphKit -Parameters @{ Uri = [uri] "$($script:BaseUri)ok" } {
            param($Uri)
            Send-GraphHttpRequest -Uri $Uri -Method GET -CredentialPolicy 'None'
        }

        $result.StatusCode | Should -Be 200

        $seen = @($script:Server.Received | Where-Object { $_.Path -eq '/ok' })
        $seen.Count | Should -BeGreaterThan 0
        foreach ($r in $seen) {
            $r.Authorization | Should -BeNullOrEmpty -Because 'CredentialPolicy None must never carry an Authorization header'
        }
    }

    It 'refuses to send a Graph bearer to a host that is not the expected authority' {
        # The listener must NEVER be reached: the guard fires before any bytes leave.
        $before = @($script:Server.Received).Count

        {
            InModuleScope GraphKit -Parameters @{
                Uri      = [uri] "$($script:BaseUri)ok"
                Expected = [uri] 'https://graph.microsoft.com/'
                Source   = $script:TokenSource
            } {
                param($Uri, $Expected, $Source)
                Send-GraphHttpRequest -Uri $Uri -Method GET `
                    -CredentialPolicy 'GraphBearer' -ExpectedAuthority $Expected -TokenSource $Source
            }
        } | Should -Throw -ExpectedMessage '*Credential boundary violated*'

        @($script:Server.Received).Count | Should -Be $before -Because 'the guard must fire before any bytes leave the process'
    }
}

Describe 'Real sender: redirects' {

    It 'does not follow redirects, and surfaces the 3xx instead' {
        $result = InModuleScope GraphKit -Parameters @{ Uri = [uri] "$($script:BaseUri)redirect" } {
            param($Uri)
            Send-GraphHttpRequest -Uri $Uri -Method GET -CredentialPolicy 'None'
        }

        $result.StatusCode | Should -Be 302 -Because 'AllowAutoRedirect is disabled so a 3xx is surfaced, never followed'

        @($script:Server.Received | Where-Object { $_.Path -eq '/target' }).Count |
            Should -Be 0 -Because 'following the redirect would carry credentials to an attacker-chosen host'
    }
}

Describe 'Real sender: timeouts and cancellation' {

    It 'enforces the body timeout independently of the header phase' {
        # Headers return immediately; the body is delayed 3s. A 1s body timeout must
        # fire, and it must arrive as a normalized transport result, not an exception.
        $result = InModuleScope GraphKit -Parameters @{ Uri = [uri] "$($script:BaseUri)slowbody" } {
            param($Uri)
            Send-GraphHttpRequest -Uri $Uri -Method GET -CredentialPolicy 'None' `
                -TimeoutHeadersSeconds 10 -TimeoutBodySeconds 1
        }

        $result.TransportException | Should -Not -BeNullOrEmpty -Because 'the body phase must time out on its own budget'
        $result.ResponseReceived | Should -BeTrue -Because 'headers WERE received; only the body phase failed'
    }

    It 'aborts an in-flight request when the caller cancels' {
        $result = InModuleScope GraphKit -Parameters @{ Uri = [uri] "$($script:BaseUri)slowbody" } {
            param($Uri)
            $cts = [System.Threading.CancellationTokenSource]::new()
            $cts.CancelAfter(200)
            Send-GraphHttpRequest -Uri $Uri -Method GET -CredentialPolicy 'None' `
                -TimeoutHeadersSeconds 10 -TimeoutBodySeconds 10 -CancellationToken $cts.Token
        }

        $result.TransportException | Should -Not -BeNullOrEmpty -Because 'a cancelled token must actually abort the request'
    }
}

Describe 'Real sender: exactly one physical send per attempt' {

    It 'issues exactly one request even for a status the retry engine would replay' {
        # Proves no DelegatingHandler or retry handler is installed underneath. A 503
        # is the status most likely to be retried by a hidden handler.
        $script:Server.Handlers['/five03'] = @{ Status = 503; Body = '{"error":{"code":"serviceUnavailable"}}' }

        $before = @($script:Server.Received | Where-Object { $_.Path -eq '/five03' }).Count

        $result = InModuleScope GraphKit -Parameters @{ Uri = [uri] "$($script:BaseUri)five03" } {
            param($Uri)
            Send-GraphHttpRequest -Uri $Uri -Method GET -CredentialPolicy 'None'
        }

        $result.StatusCode | Should -Be 503
        $after = @($script:Server.Received | Where-Object { $_.Path -eq '/five03' }).Count
        ($after - $before) | Should -Be 1 -Because 'one GraphKit attempt must equal exactly one physical send'
    }
}

Describe 'Real sender: response normalization' {

    It 'never throws for an HTTP outcome, it normalizes' {
        $script:Server.Handlers['/notfound'] = @{ Status = 404; Body = '{"error":{"code":"itemNotFound"}}' }

        $result = InModuleScope GraphKit -Parameters @{ Uri = [uri] "$($script:BaseUri)notfound" } {
            param($Uri)
            Send-GraphHttpRequest -Uri $Uri -Method GET -CredentialPolicy 'None'
        }

        $result.StatusCode | Should -Be 404
        $result.ResponseReceived | Should -BeTrue
        $result.Body.error.code | Should -Be 'itemNotFound'
    }

    It 'returns a raw string when the body is not parseable JSON' {
        $script:Server.Handlers['/html'] = @{ Status = 502; Body = '<html>gateway</html>' }

        $result = InModuleScope GraphKit -Parameters @{ Uri = [uri] "$($script:BaseUri)html" } {
            param($Uri)
            Send-GraphHttpRequest -Uri $Uri -Method GET -CredentialPolicy 'None'
        }

        $result.StatusCode | Should -Be 502
        # Content-Type is application/json but the body is not JSON: it must be retained
        # as the raw string rather than silently dropped.
        "$($result.Body)" | Should -Match 'gateway'
    }
}
