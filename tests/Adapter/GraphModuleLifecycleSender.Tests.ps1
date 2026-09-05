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
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace GraphKit.Tests
{
    public sealed class LifecycleBlockingHandler : HttpMessageHandler
    {
        public const string ContractMarker = "GraphKit.Task8.LifecycleSenderFixture/2";
        private int _disposeCount;
        private int _sendCount;

        public int DisposeCount { get { return _disposeCount; } }
        public int SendCount { get { return _sendCount; } }
        public CancellationToken SeenToken { get; private set; }
        public TaskCompletionSource<bool> Started { get; } =
            new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<bool> Exited { get; } =
            new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _sendCount);
            SeenToken = cancellationToken;
            Started.TrySetResult(true);
            try
            {
                await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
                throw new InvalidOperationException("The blocking test handler resumed without cancellation.");
            }
            finally
            {
                Exited.TrySetResult(true);
            }
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

    public sealed class LifecycleCompletionCancellingHandler : HttpMessageHandler
    {
        private int _disposeCount;
        private int _sendCount;

        public int DisposeCount { get { return _disposeCount; } }
        public int SendCount { get { return _sendCount; } }
        public CancellationToken SeenToken { get; private set; }
        public CancellationTokenSource CompletionCancellation { get; set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _sendCount);
            SeenToken = cancellationToken;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new CompletionCancellingContent(CompletionCancellation)
            });
        }

        private sealed class CompletionCancellingContent : HttpContent
        {
            private static readonly byte[] Body = Encoding.UTF8.GetBytes("{\"value\":[]}");
            private readonly CancellationTokenSource _cancellation;

            public CompletionCancellingContent(CancellationTokenSource cancellation)
            {
                _cancellation = cancellation;
            }

            protected override Task SerializeToStreamAsync(Stream stream, TransportContext context)
            {
                return SerializeAndCancel(stream);
            }

            protected override Task SerializeToStreamAsync(
                Stream stream,
                TransportContext context,
                CancellationToken cancellationToken)
            {
                return SerializeAndCancel(stream);
            }

            private Task SerializeAndCancel(Stream stream)
            {
                stream.Write(Body, 0, Body.Length);
                _cancellation.Cancel();
                return Task.CompletedTask;
            }

            protected override bool TryComputeLength(out long length)
            {
                length = Body.Length;
                return true;
            }
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

    public sealed class LifecycleCleanupProbe : IDisposable
    {
        private readonly string _name;
        private readonly LifecycleBlockingHandler _handler;
        private readonly ConcurrentQueue<string> _order;
        private int _disposeCount;
        private int _preconditionsSatisfied;

        public LifecycleCleanupProbe(
            string name,
            LifecycleBlockingHandler handler,
            ConcurrentQueue<string> order)
        {
            _name = name;
            _handler = handler;
            _order = order;
        }

        public int DisposeCount => Volatile.Read(ref _disposeCount);
        public bool PreconditionsSatisfied => Volatile.Read(ref _preconditionsSatisfied) != 0;

        public void Dispose()
        {
            if (_handler.SeenToken.IsCancellationRequested && _handler.Exited.Task.IsCompleted)
                Volatile.Write(ref _preconditionsSatisfied, 1);
            _order.Enqueue(_name);
            Interlocked.Increment(ref _disposeCount);
        }
    }
}
'@
    }
    $handlerType = 'GraphKit.Tests.LifecycleBlockingHandler' -as [type]
    $handlerMarker = if ($null -ne $handlerType) {
        $handlerType.GetField('ContractMarker')
    }
    else {
        $null
    }
    if ($null -eq $handlerMarker -or
        [string] $handlerMarker.GetRawConstantValue() -cne
            'GraphKit.Task8.LifecycleSenderFixture/2') {
        throw (
            'The process-global lifecycle sender fixture is stale. ' +
            'Run this file in a fresh PowerShell process.'
        )
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

    It 'marks module cancellation raised during token acquisition for retry classification' {
        $state = InModuleScope GraphKit {
            New-GraphModuleLifecycleState
        }
        $source = [pscustomobject] @{
            LifecycleState = $state
        }
        $source | Add-Member -MemberType ScriptMethod -Name Acquire -Value {
            param([bool] $ForceRefresh, [System.Threading.CancellationToken] $CancellationToken)
            $this.LifecycleState.ShutdownCts.Cancel()
            $CancellationToken.ThrowIfCancellationRequested()
        }

        try {
            $failure = $null
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
                $failure = $_.Exception
            }

            $isCancellation = $false
            $isMarked = $false
            $candidate = $failure
            while ($null -ne $candidate) {
                if ($candidate -is [System.OperationCanceledException]) {
                    $isCancellation = $true
                }
                if ($candidate.Data['GraphKit.OperationCancellation'] -eq $true) {
                    $isMarked = $true
                }
                $candidate = $candidate.InnerException
            }

            $failure | Should -Not -BeNullOrEmpty
            $isCancellation | Should -BeTrue
            $isMarked | Should -BeTrue
            $state.ShutdownCts.IsCancellationRequested | Should -BeTrue
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

    It 'normalizes a clean response that races module shutdown before it can become success' {
        $state = InModuleScope GraphKit {
            New-GraphModuleLifecycleState
        }
        $handler = [GraphKit.Tests.LifecycleCompletionCancellingHandler]::new()
        $handler.CompletionCancellation = $state.ShutdownCts
        $client = [System.Net.Http.HttpClient]::new($handler, $false)
        $factory = {
            param([int] $ConnectTimeoutSeconds)
            [pscustomobject] @{
                Client          = $client
                OwnedByGraphKit = $false
            }
        }.GetNewClosure()

        try {
            $result = InModuleScope GraphKit -Parameters @{
                State = $state
                Factory = $factory
            } {
                param($State, $Factory)
                Send-GraphHttpRequest -Uri ([uri] 'https://graph.microsoft.com/v1.0/me') `
                    -Method GET -CredentialPolicy None -LifecycleState $State `
                    -HttpClientFactory $Factory
            }

            $handler.SendCount | Should -Be 1
            $state.ShutdownCts.IsCancellationRequested | Should -BeTrue
            $result.ResponseReceived | Should -BeTrue
            $result.StatusCode | Should -Be 200
            $result.TransportException | Should -Not -BeNullOrEmpty
            $result.TransportException.Data['GraphKit.OperationCancellation'] | Should -BeTrue
            $state.ActiveOperations | Should -Be 0
            $state.Drained.IsSet | Should -BeTrue
            $handler.DisposeCount | Should -Be 0
        }
        finally {
            InModuleScope GraphKit -Parameters @{ State = $state } {
                param($State)
                Stop-GraphModule -State $State
            }
            $client.Dispose()
        }
    }

    It 'cancels an in-flight physical send, drains it, and leaves an injected client caller-owned' {
        $state = InModuleScope GraphKit {
            New-GraphModuleLifecycleState
        }
        $handler = [GraphKit.Tests.LifecycleBlockingHandler]::new()
        $client = [System.Net.Http.HttpClient]::new($handler, $true)
        $cleanupOrder = [Collections.Concurrent.ConcurrentQueue[string]]::new()
        $hostCleanup = [GraphKit.Tests.LifecycleCleanupProbe]::new(
            'host', $handler, $cleanupOrder)
        $sourceCleanup = [GraphKit.Tests.LifecycleCleanupProbe]::new(
            'source', $handler, $cleanupOrder)
        InModuleScope GraphKit -Parameters @{
            State = $state
            HostCleanup = $hostCleanup
            SourceCleanup = $sourceCleanup
        } {
            param($State, $HostCleanup, $SourceCleanup)
            $null = Register-GraphModuleOwnedResource `
                -State $State -Resource $HostCleanup -OwnedByGraphKit:$true
            $null = Register-GraphModuleOwnedResource `
                -State $State -Resource $SourceCleanup -OwnedByGraphKit:$true
        }
        $registered = @($state.OwnedResources)
        $registered.Count | Should -Be 2
        [object]::ReferenceEquals($registered[0], $hostCleanup) | Should -BeTrue
        [object]::ReferenceEquals($registered[1], $sourceCleanup) | Should -BeTrue
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

            $sendCompleted = @($sendJob | Wait-Job -Timeout 10)
            $sendCompleted.Count | Should -Be 1
            $null = $stopJob | Receive-Job -ErrorAction Stop
            $result = $sendJob | Receive-Job -ErrorAction Stop

            $handler.SendCount | Should -Be 1
            $handler.SeenToken.IsCancellationRequested | Should -BeTrue
            $handler.Exited.Task.IsCompleted | Should -BeTrue
            $result.TransportException | Should -Not -BeNullOrEmpty
            $result.TransportException.Data['GraphKit.OperationCancellation'] | Should -BeTrue
            $state.WaitForCleanup(5000) | Should -BeTrue
            $state.ActiveOperations | Should -Be 0
            $state.CleanupComplete | Should -BeTrue
            $state.OwnedResources.Count | Should -Be 0
            @($state.GetFailures()).Count | Should -Be 0
            @($cleanupOrder.ToArray()) | Should -Be @('source', 'host')
            $sourceCleanup.DisposeCount | Should -Be 1
            $hostCleanup.DisposeCount | Should -Be 1
            $sourceCleanup.PreconditionsSatisfied | Should -BeTrue
            $hostCleanup.PreconditionsSatisfied | Should -BeTrue
            $handler.DisposeCount | Should -Be 0
            { $client.CancelPendingRequests() } | Should -Not -Throw
        }
        finally {
            try { $client.CancelPendingRequests() } catch { }
            if ($null -ne $sendJob) {
                $null = @($sendJob | Wait-Job -Timeout 10)
                $sendJob | Remove-Job -Force -ErrorAction SilentlyContinue
            }
            if ($null -ne $stopJob) {
                $null = @($stopJob | Wait-Job -Timeout 10)
                $stopJob | Remove-Job -Force -ErrorAction SilentlyContinue
            }
            [System.AppDomain]::CurrentDomain.SetData($stateKey, $null)
            [System.AppDomain]::CurrentDomain.SetData($clientKey, $null)
            $client.Dispose()
        }
    }
}
