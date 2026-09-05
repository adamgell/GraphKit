BeforeAll {
    $repoRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $built = Get-ChildItem -Path (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $built) {
        throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first, then re-run the tests.'
    }
    $script:BuiltManifest = Join-Path $built.FullName 'GraphKit.psd1'
    Import-Module $script:BuiltManifest -Force -ErrorAction Stop

    if ($null -eq ('GraphKit.Tests.TrackingDisposable' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Reflection;
using System.Threading;

namespace GraphKit.Tests
{
    public sealed class TrackingDisposable : IDisposable
    {
        public const string ContractMarker = "GraphKit.Task7.ModuleLifecycleFixture/1";
        private int _disposeCount;
        public int DisposeCount { get { return _disposeCount; } }
        public ManualResetEventSlim Disposed { get; } = new ManualResetEventSlim(false);

        public void Dispose()
        {
            Interlocked.Increment(ref _disposeCount);
            Disposed.Set();
        }
    }

    public sealed class BlockingCancellationCallback
    {
        public ManualResetEventSlim Started { get; } = new ManualResetEventSlim(false);
        public ManualResetEventSlim Release { get; } = new ManualResetEventSlim(false);
        public Action Callback { get { return Invoke; } }

        private void Invoke()
        {
            Started.Set();
            Release.Wait();
        }
    }

    public sealed class ThrowingCancellationCallback
    {
        private readonly string _message;

        public ThrowingCancellationCallback(string message)
        {
            _message = message;
        }

        public Action Callback { get { return Invoke; } }

        private void Invoke()
        {
            throw new InvalidOperationException(_message);
        }
    }

    public sealed class FailureObservingDisposable : IDisposable
    {
        private readonly object _state;
        private int _disposeCount;
        private int _failureCountAtDispose = -1;

        public FailureObservingDisposable(object state)
        {
            _state = state;
        }

        public int DisposeCount { get { return Volatile.Read(ref _disposeCount); } }
        public int FailureCountAtDispose { get { return Volatile.Read(ref _failureCountAtDispose); } }

        public void Dispose()
        {
            MethodInfo getFailures = _state.GetType().GetMethod(
                "GetFailures",
                BindingFlags.Instance | BindingFlags.Public);
            Exception[] failures = (Exception[])getFailures.Invoke(_state, null);
            Volatile.Write(ref _failureCountAtDispose, failures.Length);
            Interlocked.Increment(ref _disposeCount);
        }
    }

    public sealed class StaleModuleLifecycleState
    {
        public static string ContractMarker
        {
            get { return "GraphKit.ModuleLifecycle.RuntimeV0/stale"; }
        }
    }

    public sealed class BlockingDisposable : IDisposable
    {
        private int _disposeCount;
        public int DisposeCount { get { return _disposeCount; } }
        public ManualResetEventSlim Started { get; } = new ManualResetEventSlim(false);
        public ManualResetEventSlim Release { get; } = new ManualResetEventSlim(false);
        public ManualResetEventSlim Completed { get; } = new ManualResetEventSlim(false);

        public void Dispose()
        {
            Started.Set();
            Release.Wait();
            Interlocked.Increment(ref _disposeCount);
            Completed.Set();
        }
    }

    public sealed class OrderedDisposable : IDisposable
    {
        private readonly string _name;
        private readonly ConcurrentQueue<string> _order;
        private readonly bool _throws;
        private int _disposeCount;

        public OrderedDisposable(string name, ConcurrentQueue<string> order, bool throws)
        {
            _name = name;
            _order = order;
            _throws = throws;
        }

        public int DisposeCount { get { return Volatile.Read(ref _disposeCount); } }

        public void Dispose()
        {
            Interlocked.Increment(ref _disposeCount);
            _order.Enqueue(_name);
            if (_throws) throw new InvalidOperationException("dispose-failed-" + _name);
        }
    }
}
'@
    }
    $trackingType = 'GraphKit.Tests.TrackingDisposable' -as [type]
    $trackingMarker = if ($null -ne $trackingType) {
        $trackingType.GetField('ContractMarker')
    }
    else {
        $null
    }
    if ($null -eq $trackingMarker -or
        [string] $trackingMarker.GetRawConstantValue() -cne
            'GraphKit.Task7.ModuleLifecycleFixture/1') {
        throw (
            'The process-global GraphModuleLifecycle test fixture is stale. ' +
            'Run this file in a fresh PowerShell process.'
        )
    }
}

Describe 'GraphKit module lifecycle' {
    It 'pins the compiled lifecycle coordinator to the expected namespace and ABI surface' {
        InModuleScope GraphKit {
            $expectedTypeName = 'GraphKit.Internal.RuntimeV1.ModuleLifecycleState'
            $expectedMarker = 'GraphKit.ModuleLifecycle.RuntimeV1/2026-08-30.2'
            $stateType = $expectedTypeName -as [type]

            $stateType | Should -Not -BeNullOrEmpty
            $stateType.FullName | Should -BeExactly $expectedTypeName
            $stateType.GetProperty(
                'ContractMarker',
                [System.Reflection.BindingFlags]'Public, Static'
            ).GetValue($null) | Should -BeExactly $expectedMarker

            {
                $null = Assert-GraphModuleLifecycleTypeContract -Type $stateType
            } | Should -Not -Throw

            {
                $null = Assert-GraphModuleLifecycleTypeContract -Type ([GraphKit.Tests.StaleModuleLifecycleState])
            } | Should -Throw -ExceptionType ([System.InvalidOperationException]) -ExpectedMessage '*ContractMarker*EnterOperation*'
        }
    }

    It 'waits for an active operation before disposing only GraphKit-owned resources' {
        $state = InModuleScope GraphKit {
            New-GraphModuleLifecycleState
        }
        $owned = [GraphKit.Tests.TrackingDisposable]::new()
        $injected = [GraphKit.Tests.TrackingDisposable]::new()

        InModuleScope GraphKit -Parameters @{ State = $state; Owned = $owned; Injected = $injected } {
            param($State, $Owned, $Injected)
            $null = Register-GraphModuleOwnedResource -State $State -Resource $Owned -OwnedByGraphKit:$true
            $null = Register-GraphModuleOwnedResource -State $State -Resource $Injected -OwnedByGraphKit:$false
            $null = Enter-GraphModuleOperation -State $State
        }

        $stateKey = 'GraphKitTest.LifecycleState.' + [guid]::NewGuid().ToString('N')
        [System.AppDomain]::CurrentDomain.SetData($stateKey, $state)
        $stopJob = $null
        try {
            $stopJob = Start-ThreadJob -ScriptBlock {
                param($Manifest, $StateKey)
                Import-Module $Manifest -Force -ErrorAction Stop
                $sharedState = [System.AppDomain]::CurrentDomain.GetData($StateKey)
                & (Get-Module GraphKit) {
                    param($State)
                    Stop-GraphModule -State $State -DrainTimeoutMilliseconds 30000
                } $sharedState
            } -ArgumentList $script:BuiltManifest, $stateKey

            $state.ShutdownCts.Token.WaitHandle.WaitOne(10000) | Should -BeTrue `
                -Because 'Stop must signal the module lifetime before waiting for the active operation, including on a loaded CI worker'
            $stopJob.State | Should -Not -Be 'Completed' -Because 'cleanup must drain the active operation before disposing shared transport resources'
            $owned.DisposeCount | Should -Be 0
            $injected.DisposeCount | Should -Be 0

            InModuleScope GraphKit -Parameters @{ State = $state } {
                param($State)
                Exit-GraphModuleOperation -State $State
            }

            $completedJobs = @($stopJob | Wait-Job -Timeout 10)
            $completedJobs.Count | Should -Be 1 -Because 'active-operation release must let module cleanup finish within the bounded liveness timeout'
            $null = $stopJob | Receive-Job -ErrorAction Stop
            $owned.DisposeCount | Should -Be 1
            $injected.DisposeCount | Should -Be 0 -Because 'caller-injected resources remain caller-owned'
        }
        finally {
            [System.AppDomain]::CurrentDomain.SetData($stateKey, $null)
            if ($null -ne $stopJob) {
                $stopJob | Remove-Job -Force -ErrorAction SilentlyContinue
            }
        }
    }

    It 'makes cleanup idempotent and refuses new operations after stop' {
        $state = InModuleScope GraphKit {
            New-GraphModuleLifecycleState
        }
        $owned = [GraphKit.Tests.TrackingDisposable]::new()

        InModuleScope GraphKit -Parameters @{ State = $state; Owned = $owned } {
            param($State, $Owned)
            $null = Register-GraphModuleOwnedResource -State $State -Resource $Owned -OwnedByGraphKit:$true
            Stop-GraphModule -State $State
            Stop-GraphModule -State $State
        }

        $owned.DisposeCount | Should -Be 1
        $state.WaitForCleanup(0) | Should -BeTrue
        $state.WaitForCleanup(0) | Should -BeTrue `
            -Because 'completed cleanup waits must remain safe after lifecycle signals are released'
        $shutdownDisposeError = try {
            $state.ShutdownCts.Cancel()
            $null
        }
        catch {
            $_.Exception
        }
        $shutdownDisposeError | Should -Not -BeNullOrEmpty
        $shutdownDisposeError.GetBaseException() | Should -BeOfType ([System.ObjectDisposedException])

        $drainedDisposeError = try {
            $null = $state.Drained.Wait(0)
            $null
        }
        catch {
            $_.Exception
        }
        $drainedDisposeError | Should -Not -BeNullOrEmpty
        $drainedDisposeError.GetBaseException() | Should -BeOfType ([System.ObjectDisposedException])
        {
            InModuleScope GraphKit -Parameters @{ State = $state } {
                param($State)
                $null = Enter-GraphModuleOperation -State $State
            }
        } | Should -Throw -ExceptionType ([System.ObjectDisposedException])
    }

    It 'leaves ownership with the caller when registration races shutdown' {
        $state = InModuleScope GraphKit {
            New-GraphModuleLifecycleState
        }
        $owned = [GraphKit.Tests.TrackingDisposable]::new()

        InModuleScope GraphKit -Parameters @{ State = $state } {
            param($State)
            Stop-GraphModule -State $State
        }

        {
            InModuleScope GraphKit -Parameters @{ State = $state; Owned = $owned } {
                param($State, $Owned)
                $null = Register-GraphModuleOwnedResource -State $State -Resource $Owned -OwnedByGraphKit:$true
            }
        } | Should -Throw -ExceptionType ([System.ObjectDisposedException])

        $owned.DisposeCount | Should -Be 0 -Because 'a failed registration never accepted ownership'
        $owned.Dispose()
        $owned.DisposeCount | Should -Be 1
    }

    It 'bounds shutdown and lets the final non-cooperative operation perform deferred cleanup' {
        $state = InModuleScope GraphKit {
            New-GraphModuleLifecycleState
        }
        $owned = [GraphKit.Tests.TrackingDisposable]::new()

        InModuleScope GraphKit -Parameters @{ State = $state; Owned = $owned } {
            param($State, $Owned)
            $null = Register-GraphModuleOwnedResource -State $State -Resource $Owned -OwnedByGraphKit:$true
            $null = Enter-GraphModuleOperation -State $State
            Stop-GraphModule -State $State -DrainTimeoutMilliseconds 25 -WarningAction SilentlyContinue
        }

        $state.StopRequested | Should -BeTrue
        $state.CleanupDeferred | Should -BeTrue
        $state.CleanupComplete | Should -BeFalse
        $owned.DisposeCount | Should -Be 0 -Because 'active operations retain every owned resource'

        InModuleScope GraphKit -Parameters @{ State = $state } {
            param($State)
            Exit-GraphModuleOperation -State $State
        }

        $state.WaitForCleanup(5000) | Should -BeTrue
        $state.CleanupComplete | Should -BeTrue
        $owned.DisposeCount | Should -Be 1
    }

    It 'waits for cancellation callbacks after operations drain before disposing resources' {
        $state = InModuleScope GraphKit {
            New-GraphModuleLifecycleState
        }
        $blocker = [GraphKit.Tests.BlockingCancellationCallback]::new()
        $owned = [GraphKit.Tests.TrackingDisposable]::new()
        $registration = $null
        try {
            $token = InModuleScope GraphKit -Parameters @{ State = $state; Owned = $owned } {
                param($State, $Owned)
                $null = Register-GraphModuleOwnedResource -State $State -Resource $Owned -OwnedByGraphKit:$true
                Enter-GraphModuleOperation -State $State
            }
            $registration = $token.Register($blocker.Callback)

            $watch = [System.Diagnostics.Stopwatch]::StartNew()
            InModuleScope GraphKit -Parameters @{ State = $state } {
                param($State)
                Stop-GraphModule -State $State -DrainTimeoutMilliseconds 25 -WarningAction SilentlyContinue
            }
            $watch.Stop()

            $watch.ElapsedMilliseconds | Should -BeLessThan 1000
            $state.StopRequested | Should -BeTrue
            $state.CleanupDeferred | Should -BeTrue
            $state.CancellationTask | Should -Not -BeNullOrEmpty
            $blocker.Started.Wait(5000) | Should -BeTrue
            $state.CancellationTask.IsCompleted | Should -BeFalse

            InModuleScope GraphKit -Parameters @{ State = $state } {
                param($State)
                Exit-GraphModuleOperation -State $State
            }

            $state.Drained.IsSet | Should -BeTrue
            $state.CleanupStarted | Should -BeFalse
            $state.CleanupComplete | Should -BeFalse
            $owned.DisposeCount | Should -Be 0 -Because 'cancellation callbacks still have access to operation-owned resources'

            $blocker.Release.Set()
            $state.CancellationTask.Wait(5000) | Should -BeTrue
            $state.WaitForCleanup(5000) | Should -BeTrue
            $state.CleanupComplete | Should -BeTrue
            $owned.DisposeCount | Should -Be 1
        }
        finally {
            $blocker.Release.Set()
            if ($null -ne $registration) {
                $registration.Dispose()
            }
            $blocker.Started.Dispose()
            $blocker.Release.Dispose()
        }
    }

    It 'records every fast cancellation callback failure before cleanup can dispose resources' {
        foreach ($iteration in 1..128) {
            $state = InModuleScope GraphKit {
                New-GraphModuleLifecycleState
            }
            $sentinel = "graphkit-fast-cancellation-$iteration"
            $callback = [GraphKit.Tests.ThrowingCancellationCallback]::new($sentinel)
            $owned = [GraphKit.Tests.FailureObservingDisposable]::new($state)
            $registration = $null

            try {
                $token = InModuleScope GraphKit -Parameters @{ State = $state; Owned = $owned } {
                    param($State, $Owned)
                    $null = Register-GraphModuleOwnedResource -State $State -Resource $Owned -OwnedByGraphKit:$true
                    $operationToken = Enter-GraphModuleOperation -State $State
                    Exit-GraphModuleOperation -State $State
                    return $operationToken
                }
                $registration = $token.Register($callback.Callback)

                $stopFailure = $null
                try {
                    InModuleScope GraphKit -Parameters @{ State = $state } {
                        param($State)
                        Stop-GraphModule -State $State
                    }
                }
                catch {
                    $stopFailure = $_.Exception
                }

                $stopFailure | Should -Not -BeNullOrEmpty
                $stopFailure.ToString() | Should -Match ([regex]::Escape($sentinel))
                $state.WaitForCleanup(0) | Should -BeTrue
                $state.CleanupComplete | Should -BeTrue
                $state.CancellationObserved | Should -BeTrue
                $owned.DisposeCount | Should -Be 1
                $owned.FailureCountAtDispose | Should -Be 1 -Because 'cleanup must not begin until callback failure recording is complete'
                @($state.GetFailures()).Count | Should -Be 1
            }
            finally {
                if ($null -ne $registration) {
                    $registration.Dispose()
                }
            }
        }
    }

    It 'returns within the stop bound while a disposable blocks and completes cleanup later' {
        $state = InModuleScope GraphKit {
            New-GraphModuleLifecycleState
        }
        $owned = [GraphKit.Tests.BlockingDisposable]::new()
        $stateKey = 'GraphKitTest.BlockingDisposeState.' + [guid]::NewGuid().ToString('N')
        [System.AppDomain]::CurrentDomain.SetData($stateKey, $state)
        $stopJob = $null

        try {
            InModuleScope GraphKit -Parameters @{ State = $state; Owned = $owned } {
                param($State, $Owned)
                $null = Register-GraphModuleOwnedResource -State $State -Resource $Owned -OwnedByGraphKit:$true
            }

            $stopJob = Start-ThreadJob -ScriptBlock {
                param($Manifest, $StateKey)
                Import-Module $Manifest -Force -ErrorAction Stop
                $sharedState = [System.AppDomain]::CurrentDomain.GetData($StateKey)
                & (Get-Module GraphKit) {
                    param($State)
                    Stop-GraphModule -State $State -DrainTimeoutMilliseconds 25 -WarningAction SilentlyContinue
                } $sharedState
            } -ArgumentList $script:BuiltManifest, $stateKey

            $owned.Started.Wait(5000) | Should -BeTrue -Because 'cleanup must eventually attempt disposal'
            $completedBeforeRelease = $null -ne ($stopJob | Wait-Job -Timeout 10)

            $owned.Release.Set()
            $completedJobs = @($stopJob | Wait-Job -Timeout 10)
            $completedJobs.Count | Should -Be 1 -Because 'the background dispose must complete after its explicit release gate opens'
            $null = $stopJob | Receive-Job -ErrorAction Stop

            $completedBeforeRelease | Should -BeTrue -Because 'blocking Dispose must run outside the bounded module-removal path'
            $state.WaitForCleanup(5000) | Should -BeTrue
            $state.CleanupComplete | Should -BeTrue
            $owned.Completed.IsSet | Should -BeTrue
            $owned.DisposeCount | Should -Be 1
        }
        finally {
            $owned.Release.Set()
            [System.AppDomain]::CurrentDomain.SetData($stateKey, $null)
            if ($null -ne $stopJob) {
                $stopJob | Remove-Job -Force -ErrorAction SilentlyContinue
            }
            $owned.Started.Dispose()
            $owned.Release.Dispose()
            $owned.Completed.Dispose()
        }
    }

    It 'disposes exact host and source probes once in LIFO order and reports an observed failure' {
        $state = InModuleScope GraphKit {
            New-GraphModuleLifecycleState
        }
        $order = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
        $hostProbe = [GraphKit.Tests.OrderedDisposable]::new('host', $order, $false)
        $source1Probe = [GraphKit.Tests.OrderedDisposable]::new('source1', $order, $true)
        $source2Probe = [GraphKit.Tests.OrderedDisposable]::new('source2', $order, $false)
        $injected = [GraphKit.Tests.OrderedDisposable]::new('injected', $order, $false)

        InModuleScope GraphKit -Parameters @{
            State = $state
            HostProbe = $hostProbe
            Source1Probe = $source1Probe
            Source2Probe = $source2Probe
            Injected = $injected
        } {
            param($State, $HostProbe, $Source1Probe, $Source2Probe, $Injected)
            $null = Register-GraphModuleOwnedResource -State $State -Resource $HostProbe -OwnedByGraphKit:$true
            $null = Register-GraphModuleOwnedResource -State $State -Resource $Source1Probe -OwnedByGraphKit:$true
            $null = Register-GraphModuleOwnedResource -State $State -Resource $Source2Probe -OwnedByGraphKit:$true
            $null = Register-GraphModuleOwnedResource -State $State -Resource $Injected -OwnedByGraphKit:$false
        }

        $registered = @($state.OwnedResources)
        $registered.Count | Should -Be 3
        [object]::ReferenceEquals($registered[0], $hostProbe) | Should -BeTrue
        [object]::ReferenceEquals($registered[1], $source1Probe) | Should -BeTrue
        [object]::ReferenceEquals($registered[2], $source2Probe) | Should -BeTrue

        {
            InModuleScope GraphKit -Parameters @{ State = $state } {
                param($State)
                Stop-GraphModule -State $State
            }
        } | Should -Throw -ExceptionType ([System.AggregateException]) -ExpectedMessage '*dispose-failed-source1*'

        $state.WaitForCleanup(0) | Should -BeTrue
        $state.CleanupComplete | Should -BeTrue
        $state.ActiveOperations | Should -Be 0
        $state.OwnedResources.Count | Should -Be 0
        @($order.ToArray()) | Should -Be @('source2', 'source1', 'host')
        $hostProbe.DisposeCount | Should -Be 1
        $source1Probe.DisposeCount | Should -Be 1
        $source2Probe.DisposeCount | Should -Be 1
        $injected.DisposeCount | Should -Be 0
        @($state.GetFailures()).Count | Should -Be 1
    }

    It 'does not clear a process-wide token flight during module-scoped cleanup' {
        $state = InModuleScope GraphKit {
            New-GraphModuleLifecycleState
        }
        $key = 'module-removal-flight-' + [guid]::NewGuid().ToString('N')

        try {
            InModuleScope GraphKit -Parameters @{ State = $state; Key = $key } {
                param($State, $Key)
                $flight = [GraphTokenFlight]::new()
                [GraphTokenFlightRegistry]::Flights[$Key] = $flight
                Stop-GraphModule -State $State

                [GraphTokenFlightRegistry]::Flights.ContainsKey($Key) | Should -BeTrue
                [object]::ReferenceEquals([GraphTokenFlightRegistry]::Flights[$Key], $flight) | Should -BeTrue
            }
        }
        finally {
            InModuleScope GraphKit -Parameters @{ Key = $key } {
                param($Key)
                $removed = [GraphTokenFlight] $null
                $null = [GraphTokenFlightRegistry]::Flights.TryRemove($Key, [ref] $removed)
                if ($null -ne $removed) {
                    $null = $removed.Completion.TrySetResult('test-cleanup')
                }
            }
        }
    }

    It 'initializes the real module lifecycle and disposes owned resources on removal' {
        $job = Start-ThreadJob -ScriptBlock {
            param($Manifest)

            $module = Import-Module $Manifest -Force -PassThru -ErrorAction Stop
            $state = & $module {
                $script:GraphKitModuleLifecycle
            }
            $owned = [GraphKit.Tests.TrackingDisposable]::new()

            & $module {
                param($Resource)
                $null = Register-GraphModuleOwnedResource -Resource $Resource -OwnedByGraphKit:$true
            } $owned

            $stateType = $state.PSObject.TypeNames[0]
            $onRemoveInstalled = $module.OnRemove -is [scriptblock]
            $resourceRegistered =
                $state.OwnedResources.Count -ge 1 -and
                [object]::ReferenceEquals($state.OwnedResources[$state.OwnedResources.Count - 1], $owned)

            $null = Remove-Module -ModuleInfo $module -Force -ErrorAction Stop

            [pscustomobject] @{
                StateType          = $stateType
                OnRemoveInstalled  = $onRemoveInstalled
                ResourceRegistered = $resourceRegistered
                ModuleRemoved      = $null -eq (Get-Module -Name GraphKit)
                StopRequested      = $state.StopRequested
                CleanupComplete    = $state.CleanupComplete
                ResourceDisposed   = $owned.Disposed.Wait(5000)
                DisposeCount       = $owned.DisposeCount
            }
        } -ArgumentList $script:BuiltManifest

        try {
            $completed = $job | Wait-Job -Timeout 15
            $completed | Should -Not -BeNullOrEmpty -Because 'module removal must remain bounded'
            $job.State | Should -Be 'Completed'

            $result = @($job | Receive-Job -ErrorAction Stop)
            $result.Count | Should -Be 1
            $result[0].StateType | Should -Be 'GraphKit.ModuleLifecycleState'
            $result[0].OnRemoveInstalled | Should -BeTrue
            $result[0].ResourceRegistered | Should -BeTrue
            $result[0].ModuleRemoved | Should -BeTrue
            $result[0].StopRequested | Should -BeTrue
            $result[0].CleanupComplete | Should -BeTrue
            $result[0].ResourceDisposed | Should -BeTrue
            $result[0].DisposeCount | Should -Be 1
        }
        finally {
            $job | Remove-Job -Force -ErrorAction SilentlyContinue
        }
    }

    It 'registers the compiled auth host before sources so module cleanup is source-first LIFO' {
        $job = Start-ThreadJob -ScriptBlock {
            param($Manifest)
            $module = Import-Module $Manifest -Force -PassThru -ErrorAction Stop
            $result = & $module {
                $before = @($script:GraphKitModuleLifecycle.OwnedResources)
                $source1 = New-GraphAuthTokenSource -Profile @{
                    TenantId = '3a4b5c6d-1111-2222-3333-444455556666'
                    ClientId = $null
                    AuthMethod = 'BearerToken'
                    Environment = 'Global'
                    Credential = @{ Token = 'module-lifecycle-fixed-bearer'; Version = 'fixture-v1' }
                } -Cloud @{
                    Name = 'Global'
                    Authority = [uri]'https://login.microsoftonline.com'
                        Resource = [uri]'https://graph.microsoft.com'
                }
                $source2 = New-GraphAuthTokenSource -Profile @{
                    TenantId = '4b5c6d7e-2222-3333-4444-555566667777'
                    ClientId = $null
                    AuthMethod = 'BearerToken'
                    Environment = 'Global'
                    Credential = @{
                        Token = 'module-lifecycle-fixed-bearer-two'
                        Version = 'fixture-v2'
                    }
                } -Cloud @{
                    Name = 'Global'
                    Authority = [uri]'https://login.microsoftonline.com'
                    Resource = [uri]'https://graph.microsoft.com'
                }
                $resources = @($script:GraphKitModuleLifecycle.OwnedResources)
                [pscustomobject]@{
                    BeforeCount = $before.Count
                    BeforeType = $before[0].GetType().FullName
                    HostReferenceMatches = [object]::ReferenceEquals($before[0], $script:GraphKitAuthHost)
                    ExactResourceReferences =
                        $resources.Count -eq 3 -and
                        [object]::ReferenceEquals($resources[0], $script:GraphKitAuthHost) -and
                        [object]::ReferenceEquals($resources[1], $source1) -and
                        [object]::ReferenceEquals($resources[2], $source2)
                    ResourceTypes = @($resources | ForEach-Object { $_.GetType().FullName })
                    State = $script:GraphKitModuleLifecycle
                    Source1 = $source1
                    Source2 = $source2
                }
            }
            $null = Remove-Module -ModuleInfo $module -Force -ErrorAction Stop
            $rejectedCount = 0
            foreach ($source in @($result.Source1, $result.Source2)) {
                try {
                    $null = $source.Acquire($false, [Threading.CancellationToken]::None)
                }
                catch [ObjectDisposedException] {
                    $rejectedCount++
                }
            }
            [pscustomobject]@{
                BeforeCount = $result.BeforeCount
                BeforeType = $result.BeforeType
                HostReferenceMatches = $result.HostReferenceMatches
                ExactResourceReferences = $result.ExactResourceReferences
                ResourceTypes = $result.ResourceTypes
                SourceRejectedCount = $rejectedCount
                CleanupObserved = $result.State.WaitForCleanup(5000)
                CleanupComplete = $result.State.CleanupComplete
                ActiveOperations = $result.State.ActiveOperations
                OwnedResourceCount = $result.State.OwnedResources.Count
                FailureCount = @($result.State.GetFailures()).Count
            }
        } -ArgumentList $script:BuiltManifest

        try {
            $job | Wait-Job -Timeout 15 | Should -Not -BeNullOrEmpty
            $result = @($job | Receive-Job -ErrorAction Stop)
            $result.Count | Should -Be 1
            $result[0].BeforeCount | Should -Be 1
            $result[0].BeforeType | Should -BeExactly 'GraphKit.Auth.GraphAuthHost'
            $result[0].HostReferenceMatches | Should -BeTrue
            $result[0].ExactResourceReferences | Should -BeTrue
            @($result[0].ResourceTypes) | Should -Be @(
                'GraphKit.Auth.GraphAuthHost',
                'GraphKit.Auth.GraphTokenSourceProxy',
                'GraphKit.Auth.GraphTokenSourceProxy'
            )
            $result[0].SourceRejectedCount | Should -Be 2
            $result[0].CleanupObserved | Should -BeTrue
            $result[0].CleanupComplete | Should -BeTrue
            $result[0].ActiveOperations | Should -Be 0
            $result[0].OwnedResourceCount | Should -Be 0
            $result[0].FailureCount | Should -Be 0
        }
        finally {
            $job | Remove-Job -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'GraphKit HTTP client lifecycle' {
    It 'caches by connect timeout and disposes only factory entries marked as owned' {
        $state = InModuleScope GraphKit {
            New-GraphModuleLifecycleState
        }
        $owned = [System.Net.Http.HttpClient]::new()
        $injected = [System.Net.Http.HttpClient]::new()
        $calls = [System.Collections.Concurrent.ConcurrentDictionary[string, int]]::new()

        try {
            $clients = InModuleScope GraphKit -Parameters @{
                State = $state
                Owned = $owned
                Injected = $injected
                Calls = $calls
            } {
                param($State, $Owned, $Injected, $Calls)
                $factory = {
                    param([int] $ConnectTimeoutSeconds)
                    $key = [string] $ConnectTimeoutSeconds
                    $null = $Calls.AddOrUpdate($key, 1, [Func[string, int, int]] { param($k, $v) $v + 1 })
                    if ($ConnectTimeoutSeconds -eq 10) {
                        return [pscustomobject] @{ Client = $Owned; OwnedByGraphKit = $true }
                    }
                    return [pscustomobject] @{ Client = $Injected; OwnedByGraphKit = $false }
                }.GetNewClosure()

                @(
                    (Get-GraphHttpClient -State $State -ConnectTimeoutSeconds 10 -ClientFactory $factory),
                    (Get-GraphHttpClient -State $State -ConnectTimeoutSeconds 10 -ClientFactory $factory),
                    (Get-GraphHttpClient -State $State -ConnectTimeoutSeconds 30 -ClientFactory $factory)
                )
            }

            [object]::ReferenceEquals($clients[0], $clients[1]) | Should -BeTrue
            [object]::ReferenceEquals($clients[0], $clients[2]) | Should -BeFalse
            $calls['10'] | Should -Be 1
            $calls['30'] | Should -Be 1

            InModuleScope GraphKit -Parameters @{ State = $state } {
                param($State)
                Stop-GraphModule -State $State
            }

            $disposeError = try {
                $owned.CancelPendingRequests()
                $null
            }
            catch {
                $_.Exception
            }
            $disposeError | Should -Not -BeNullOrEmpty
            $disposeError.GetBaseException() | Should -BeOfType ([System.ObjectDisposedException])
            { $injected.CancelPendingRequests() } | Should -Not -Throw
        }
        finally {
            $owned.Dispose()
            $injected.Dispose()
        }
    }
}
