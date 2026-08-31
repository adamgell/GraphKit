BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $built) {
        throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first, then re-run the tests.'
    }
    $script:BuiltManifest = Join-Path $built.FullName 'GraphKit.psd1'
    Import-Module $script:BuiltManifest -Force -ErrorAction Stop

    if ($null -eq ('GraphKit.Tests.LifecycleBlockingHandler' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace GraphKit.Tests
{
    public sealed class LifecycleBlockingHandler : HttpMessageHandler
    {
        private int _disposeCount;
        private int _sendCount;

        public int DisposeCount { get { return _disposeCount; } }
        public int SendCount { get { return _sendCount; } }
        public CancellationToken SeenToken { get; private set; }
        public TaskCompletionSource<bool> Started { get; } =
            new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _sendCount);
            SeenToken = cancellationToken;
            Started.TrySetResult(true);
            await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
            throw new InvalidOperationException("The blocking test handler resumed without cancellation.");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Interlocked.Increment(ref _disposeCount);
            }
            base.Dispose(disposing);
        }
    }
}
'@
    }
}

Describe 'Send-GraphHttpRequest module lifecycle adapter' {
    It 'links module cancellation into token acquisition and releases the lease on a hard auth failure' {
        $state = InModuleScope GraphKit {
            New-GraphModuleLifecycleState
        }
        $source = [pscustomobject] @{
            LifecycleState = $state
            SawCancellation = $false
        }
        $source | Add-Member -MemberType ScriptMethod -Name Acquire -Value {
            param([bool] $ForceRefresh, [System.Threading.CancellationToken] $CancellationToken)
            $this.LifecycleState.ShutdownCts.Cancel()
            $this.SawCancellation = $CancellationToken.IsCancellationRequested
            throw 'token-acquire-sentinel'
        }

        try {
            $caught = $null
            try {
                InModuleScope GraphKit -Parameters @{ State = $state; Source = $source } {
                    param($State, $Source)
                    Send-GraphHttpRequest -Uri ([uri] 'https://graph.microsoft.com/v1.0/me') `
                        -Method GET -CredentialPolicy GraphBearer `
                        -ExpectedAuthority ([uri] 'https://graph.microsoft.com') `
                        -TokenSource $Source -LifecycleState $State
                }
            }
            catch {
                $caught = $_.Exception
            }

            $caught | Should -Not -BeNullOrEmpty
            $caught.Message | Should -Match 'token-acquire-sentinel'
            $source.SawCancellation | Should -BeTrue
            $state.ActiveOperations | Should -Be 0
            $state.Drained.IsSet | Should -BeTrue
        }
        finally {
            InModuleScope GraphKit -Parameters @{ State = $state } {
                param($State)
                Stop-GraphModule -State $State
            }
        }
    }

    It 'cancels an in-flight physical send, drains it, and leaves an injected client caller-owned' {
        $state = InModuleScope GraphKit {
            New-GraphModuleLifecycleState
        }
        $handler = [GraphKit.Tests.LifecycleBlockingHandler]::new()
        $client = [System.Net.Http.HttpClient]::new($handler, $true)
        $stateKey = 'GraphKitTest.SenderState.' + [guid]::NewGuid().ToString('N')
        $clientKey = 'GraphKitTest.SenderClient.' + [guid]::NewGuid().ToString('N')
        [System.AppDomain]::CurrentDomain.SetData($stateKey, $state)
        [System.AppDomain]::CurrentDomain.SetData($clientKey, $client)
        $sendJob = $null
        $stopJob = $null

        try {
            $sendJob = Start-ThreadJob -ScriptBlock {
                param($Manifest, $StateKey, $ClientKey)
                Import-Module $Manifest -Force -ErrorAction Stop
                $sharedState = [System.AppDomain]::CurrentDomain.GetData($StateKey)
                $sharedClient = [System.AppDomain]::CurrentDomain.GetData($ClientKey)
                & (Get-Module GraphKit) {
                    param($State, $Client)
                    $factory = {
                        param([int] $ConnectTimeoutSeconds)
                        [pscustomobject] @{
                            Client          = $Client
                            OwnedByGraphKit = $false
                        }
                    }.GetNewClosure()
                    Send-GraphHttpRequest -Uri ([uri] 'https://graph.microsoft.com/v1.0/me') `
                        -Method GET -CredentialPolicy None -LifecycleState $State `
                        -HttpClientFactory $factory -TimeoutHeadersSeconds 30 -TimeoutBodySeconds 30
                } $sharedState $sharedClient
            } -ArgumentList $script:BuiltManifest, $stateKey, $clientKey

            $handler.Started.Task.Wait(5000) | Should -BeTrue
            $state.ActiveOperations | Should -Be 1

            $stopJob = Start-ThreadJob -ScriptBlock {
                param($Manifest, $StateKey)
                Import-Module $Manifest -Force -ErrorAction Stop
                $sharedState = [System.AppDomain]::CurrentDomain.GetData($StateKey)
                & (Get-Module GraphKit) {
                    param($State)
                    Stop-GraphModule -State $State
                } $sharedState
            } -ArgumentList $script:BuiltManifest, $stateKey

            $stopCompleted = $stopJob | Wait-Job -Timeout 5
            if ($null -eq $stopCompleted) {
                $client.CancelPendingRequests()
                throw 'Stop-GraphModule did not cancel and drain the in-flight sender within five seconds.'
            }

            $null = $stopJob | Receive-Job -Wait -ErrorAction Stop
            $result = $sendJob | Receive-Job -Wait -ErrorAction Stop

            $handler.SendCount | Should -Be 1
            $handler.SeenToken.IsCancellationRequested | Should -BeTrue
            $result.TransportException | Should -Not -BeNullOrEmpty
            $state.ActiveOperations | Should -Be 0
            $state.CleanupComplete | Should -BeTrue
            $handler.DisposeCount | Should -Be 0
            { $client.CancelPendingRequests() } | Should -Not -Throw
        }
        finally {
            try { $client.CancelPendingRequests() } catch { }
            if ($null -ne $sendJob) {
                $sendJob | Remove-Job -Force -ErrorAction SilentlyContinue
            }
            if ($null -ne $stopJob) {
                $stopJob | Remove-Job -Force -ErrorAction SilentlyContinue
            }
            [System.AppDomain]::CurrentDomain.SetData($stateKey, $null)
            [System.AppDomain]::CurrentDomain.SetData($clientKey, $null)
            $client.Dispose()
        }
    }
}
