<#
    Loopback tests through the REAL sender.

    Every other transport test injects Send, which means they pass whether or not the
    actual HttpClient behaves. A sender that silently follows redirects, forwards
    Authorization to a redirect target, ignores the split timeouts, or has a retrying
    handler installed underneath would satisfy the entire unit suite. The properties
    GraphKit promises about the WIRE have to be asserted on the wire.

    These run against an in-process HttpListener on 127.0.0.1: deterministic, no network,
    no tenant. They are the tests the design spec calls for under "The real sender must be
    tested, not only the injected one".

    Deliberately no PowerShell class here - the listener state is a plain hashtable, so
    repeated local runs cannot pick up a stale type definition.
#>

BeforeAll {
    $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    # Discover the built version rather than naming it: a hard-coded path silently
    # breaks the whole file on any version bump, which is exactly what happened.
    $built = Get-ChildItem -Path (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $built) {
        throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first, then re-run the tests.'
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force -ErrorAction Stop

    function Start-LoopbackServer {
        param([hashtable] $Handlers)

        $probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $probe.Start()
        $port = ([System.Net.IPEndPoint] $probe.LocalEndpoint).Port
        $probe.Stop()

        $listener = [System.Net.HttpListener]::new()
        $listener.Prefixes.Add("http://127.0.0.1:$port/")
        $listener.Start()

        $received = [System.Collections.Concurrent.ConcurrentBag[object]]::new()

        # A dedicated RUNSPACE, not a raw thread: HttpListener.GetContext blocks and the
        # request must be served while the test's own thread waits inside the sender, but a
        # System.Threading.Thread has no runspace and cannot execute a PowerShell scriptblock.
        $runspace = [runspacefactory]::CreateRunspace()
        $runspace.Open()
        $runspace.SessionStateProxy.SetVariable('listener', $listener)
        $runspace.SessionStateProxy.SetVariable('handlers', $Handlers)
        $runspace.SessionStateProxy.SetVariable('received', $received)

        $pump = [powershell]::Create()
        $pump.Runspace = $runspace
        $null = $pump.AddScript({
                while ($listener.IsListening) {
                    try { $context = $listener.GetContext() } catch { break }

                    $request = $context.Request
                    $received.Add([pscustomobject] @{
                            Path          = $request.Url.AbsolutePath
                            Method        = $request.HttpMethod
                            Authorization = $request.Headers['Authorization']
                        })

                    $spec = $handlers[$request.Url.AbsolutePath]
                    if ($null -eq $spec) { $spec = @{ Status = 404; Body = '{}' } }

                    $response = $context.Response
                    try {
                        $response.StatusCode = [int] $spec['Status']
                        if ($spec.ContainsKey('Location')) { $response.AddHeader('Location', [string] $spec['Location']) }
                        $response.ContentType = 'application/json'

                        $bytes = [System.Text.Encoding]::UTF8.GetBytes([string] $spec['Body'])

                        if ($spec.ContainsKey('DelaySeconds')) {
                            # To stall the BODY phase specifically, headers must already be
                            # on the wire. HttpListener does not emit them until the first
                            # write, so declare the full length, write one byte, flush, and
                            # only then stall. Stalling before any write would instead be
                            # absorbed by the HEADER phase and prove nothing about the body
                            # budget.
                            $response.ContentLength64 = $bytes.Length + 1
                            $response.OutputStream.Write([byte[]] @(32), 0, 1)
                            $response.OutputStream.Flush()
                            Start-Sleep -Seconds ([int] $spec['DelaySeconds'])
                        }
                        else {
                            $response.ContentLength64 = $bytes.Length
                        }

                        $response.OutputStream.Write($bytes, 0, $bytes.Length)
                    }
                    catch { }
                    finally { try { $response.OutputStream.Close() } catch { } }
                }
            })
        $null = $pump.BeginInvoke()

        return @{
            Port     = $port
            BaseUri  = [uri] "http://127.0.0.1:$port/"
            Listener = $listener
            Received = $received
            Pump     = $pump
            Runspace = $runspace
        }
    }

    $script:Handlers = @{
        '/ok'       = @{ Status = 200; Body = '{"value":[{"id":"1"}]}' }
        '/target'   = @{ Status = 200; Body = '{"reached":"target"}' }
        '/five03'   = @{ Status = 503; Body = '{"error":{"code":"serviceUnavailable"}}' }
        '/notfound' = @{ Status = 404; Body = '{"error":{"code":"itemNotFound"}}' }
        '/html'     = @{ Status = 502; Body = '<html>gateway</html>' }
        '/slowbody' = @{ Status = 200; Body = '{"value":[]}'; DelaySeconds = 4 }
    }

    $script:Server = Start-LoopbackServer -Handlers $script:Handlers
    $script:Handlers['/redirect'] = @{ Status = 302; Body = ''; Location = "$($script:Server.BaseUri)target" }
    $script:BaseUri = $script:Server.BaseUri

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

    function Get-ReceivedCount {
        param([string] $Path)
        return @($script:Server.Received | Where-Object { $_.Path -eq $Path }).Count
    }
}

AfterAll {
    if ($null -ne $script:Server) {
        try { $script:Server.Listener.Stop() } catch { }
        try { $script:Server.Listener.Close() } catch { }
        try { $script:Server.Pump.Dispose() } catch { }
        try { $script:Server.Runspace.Dispose() } catch { }
    }
}

Describe 'Real sender: credential boundary' {

    It 'never attaches Authorization under CredentialPolicy None' {
        # The report-download path: a SAS-signed URL on a non-Graph host that carries its
        # own authorization and must never receive the Graph bearer.
        $uri = [uri] "$($script:BaseUri)ok"
        $result = InModuleScope GraphKit -Parameters @{ U = $uri } {
            param($U)
            Send-GraphHttpRequest -Uri $U -Method GET -CredentialPolicy 'None'
        }

        $result.StatusCode | Should -Be 200

        $seen = @($script:Server.Received | Where-Object { $_.Path -eq '/ok' })
        $seen.Count | Should -BeGreaterThan 0
        foreach ($r in $seen) {
            $r.Authorization | Should -BeNullOrEmpty -Because 'CredentialPolicy None must never carry an Authorization header'
        }
    }

    It 'refuses to send a Graph bearer to a host that is not the expected authority' {
        $before = @($script:Server.Received).Count
        $uri = [uri] "$($script:BaseUri)ok"

        {
            InModuleScope GraphKit -Parameters @{ U = $uri; E = [uri] 'https://graph.microsoft.com/'; S = $script:TokenSource } {
                param($U, $E, $S)
                Send-GraphHttpRequest -Uri $U -Method GET -CredentialPolicy 'GraphBearer' -ExpectedAuthority $E -TokenSource $S
            }
        } | Should -Throw -ExpectedMessage '*Credential boundary violated*'

        @($script:Server.Received).Count | Should -Be $before -Because 'the guard must fire before any bytes leave the process'
    }
}

Describe 'Real sender: redirects are not followed' {

    It 'surfaces the 3xx and never reaches the redirect target' {
        $uri = [uri] "$($script:BaseUri)redirect"
        $result = InModuleScope GraphKit -Parameters @{ U = $uri } {
            param($U)
            Send-GraphHttpRequest -Uri $U -Method GET -CredentialPolicy 'None'
        }

        $result.StatusCode | Should -Be 302 -Because 'AllowAutoRedirect is disabled so a 3xx is surfaced, never followed'
        Get-ReceivedCount -Path '/target' | Should -Be 0 -Because 'following a redirect would carry credentials to an attacker-chosen host'
    }
}

Describe 'Real sender: timeouts and cancellation' {

    It 'enforces the body timeout independently of the header phase' {
        # Headers commit immediately; the body stalls 4s. A 1s body budget must fire while
        # a generous 10s header budget is untouched.
        $uri = [uri] "$($script:BaseUri)slowbody"
        $result = InModuleScope GraphKit -Parameters @{ U = $uri } {
            param($U)
            Send-GraphHttpRequest -Uri $U -Method GET -CredentialPolicy 'None' `
                -TimeoutHeadersSeconds 10 -TimeoutBodySeconds 1
        }

        $result.TransportException | Should -Not -BeNullOrEmpty -Because 'the body phase must time out on its own budget'
    }

    It 'aborts an in-flight request when the caller cancels' {
        $uri = [uri] "$($script:BaseUri)slowbody"
        $result = InModuleScope GraphKit -Parameters @{ U = $uri } {
            param($U)
            $cts = [System.Threading.CancellationTokenSource]::new()
            $cts.CancelAfter(300)
            Send-GraphHttpRequest -Uri $U -Method GET -CredentialPolicy 'None' `
                -TimeoutHeadersSeconds 30 -TimeoutBodySeconds 30 -CancellationToken $cts.Token
        }

        $result.TransportException | Should -Not -BeNullOrEmpty -Because 'a cancelled token must actually abort the request'
    }
}

Describe 'Real sender: exactly one physical send per attempt' {

    It 'issues exactly one request for a 503, proving no hidden retry handler' {
        $before = Get-ReceivedCount -Path '/five03'
        $uri = [uri] "$($script:BaseUri)five03"

        $result = InModuleScope GraphKit -Parameters @{ U = $uri } {
            param($U)
            Send-GraphHttpRequest -Uri $U -Method GET -CredentialPolicy 'None'
        }

        $result.StatusCode | Should -Be 503
        ((Get-ReceivedCount -Path '/five03') - $before) | Should -Be 1 -Because 'one GraphKit attempt must equal exactly one physical send'
    }
}

Describe 'Real sender: response normalization' {

    It 'never throws for an HTTP outcome, it normalizes' {
        $uri = [uri] "$($script:BaseUri)notfound"
        $result = InModuleScope GraphKit -Parameters @{ U = $uri } {
            param($U)
            Send-GraphHttpRequest -Uri $U -Method GET -CredentialPolicy 'None'
        }

        $result.StatusCode | Should -Be 404
        $result.ResponseReceived | Should -BeTrue
        $result.Body.error.code | Should -Be 'itemNotFound'
    }

    It 'retains a non-JSON body as a raw string rather than dropping it' {
        $uri = [uri] "$($script:BaseUri)html"
        $result = InModuleScope GraphKit -Parameters @{ U = $uri } {
            param($U)
            Send-GraphHttpRequest -Uri $U -Method GET -CredentialPolicy 'None'
        }

        $result.StatusCode | Should -Be 502
        "$($result.Body)" | Should -Match 'gateway'
    }
}
