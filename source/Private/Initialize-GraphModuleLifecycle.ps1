<#
    Central ownership and shutdown state for one imported GraphKit module instance.

    PowerShell class methods are not reliable synchronization boundaries across
    runspaces. Lifecycle admission, cancellation convergence and cleanup ownership
    therefore live in one small compiled state object. PowerShell functions retain
    the existing private command surface used by the sender and tests.

    Shutdown has two independent gates: every operation lease must drain, and every
    cancellation callback must finish. Cleanup starts asynchronously only after both
    gates close. Module removal waits for CleanupDone only up to its caller-provided
    deadline; a blocking or reentrant Dispose therefore cannot wedge OnRemove.
#>

$script:GraphKitModuleLifecycleStateTypeName = 'GraphKit.Internal.RuntimeV1.ModuleLifecycleState'
$script:GraphKitModuleLifecycleContractMarker = 'GraphKit.ModuleLifecycle.RuntimeV1/2026-08-30.1'

function Assert-GraphModuleLifecycleTypeContract {
    [CmdletBinding()]
    [OutputType([type])]
    param(
        [Parameter(Mandatory)]
        [type] $Type
    )

    $issues = [System.Collections.Generic.List[string]]::new()
    if ($Type.FullName -cne $script:GraphKitModuleLifecycleStateTypeName) {
        $issues.Add(
            "type name '$($Type.FullName)' does not match '$($script:GraphKitModuleLifecycleStateTypeName)'"
        )
    }
    if (-not $Type.IsPublic -or -not $Type.IsSealed) {
        $issues.Add('the lifecycle state must be a public sealed type')
    }
    if ($null -eq $Type.GetConstructor([type[]] @())) {
        $issues.Add('a public parameterless constructor is required')
    }

    $publicStatic = [System.Reflection.BindingFlags]'Public, Static'
    $markerProperty = $Type.GetProperty('ContractMarker', $publicStatic)
    if (
        $null -eq $markerProperty -or
        $markerProperty.PropertyType -ne [string] -or
        $null -eq $markerProperty.GetMethod -or
        -not $markerProperty.GetMethod.IsPublic -or
        -not $markerProperty.GetMethod.IsStatic
    ) {
        $issues.Add('public static string ContractMarker is missing')
    }
    else {
        try {
            $actualMarker = [string] $markerProperty.GetValue($null)
            if ($actualMarker -cne $script:GraphKitModuleLifecycleContractMarker) {
                $issues.Add(
                    "ContractMarker '$actualMarker' does not match '$($script:GraphKitModuleLifecycleContractMarker)'"
                )
            }
        }
        catch {
            $issues.Add("ContractMarker could not be read: $($_.Exception.Message)")
        }
    }

    $publicInstance = [System.Reflection.BindingFlags]'Public, Instance'
    $requiredProperties = @(
        @{ Name = 'SyncRoot'; PropertyType = [object] }
        @{ Name = 'ShutdownCts'; PropertyType = [System.Threading.CancellationTokenSource] }
        @{ Name = 'Drained'; PropertyType = [System.Threading.ManualResetEventSlim] }
        @{ Name = 'CleanupDone'; PropertyType = [System.Threading.ManualResetEventSlim] }
        @{ Name = 'OwnedResources'; PropertyType = [System.Collections.Generic.List[System.IDisposable]] }
        @{ Name = 'HttpClients'; PropertyType = [System.Collections.Generic.Dictionary[string, object]] }
        @{ Name = 'StopRequested'; PropertyType = [bool] }
        @{ Name = 'CleanupStarted'; PropertyType = [bool] }
        @{ Name = 'CleanupComplete'; PropertyType = [bool] }
        @{ Name = 'CleanupDeferred'; PropertyType = [bool] }
        @{ Name = 'ActiveOperations'; PropertyType = [int] }
        @{ Name = 'CancellationObserved'; PropertyType = [bool] }
        @{ Name = 'CancellationTask'; PropertyType = [System.Threading.Tasks.Task] }
        @{ Name = 'CleanupTask'; PropertyType = [System.Threading.Tasks.Task] }
    )
    foreach ($requiredProperty in $requiredProperties) {
        $property = $Type.GetProperty($requiredProperty.Name, $publicInstance)
        if ($null -eq $property) {
            $issues.Add("public instance property $($requiredProperty.Name) is missing")
            continue
        }

        if ($property.PropertyType -ne $requiredProperty.PropertyType) {
            $issues.Add(
                "property $($requiredProperty.Name) has type '$($property.PropertyType.FullName)' instead of '$($requiredProperty.PropertyType.FullName)'"
            )
        }
    }

    $requiredMethods = @(
        @{ Name = 'EnterOperation'; ReturnType = 'System.Threading.CancellationToken'; Parameters = [string[]] @() }
        @{ Name = 'ExitOperation'; ReturnType = 'System.Void'; Parameters = [string[]] @() }
        @{ Name = 'RegisterOwnedResource'; ReturnType = 'System.Void'; Parameters = [string[]] @('System.IDisposable') }
        @{ Name = 'RequestStop'; ReturnType = 'System.Threading.Tasks.Task'; Parameters = [string[]] @() }
        @{ Name = 'TryScheduleCleanup'; ReturnType = 'System.Void'; Parameters = [string[]] @() }
        @{ Name = 'MarkCleanupDeferred'; ReturnType = 'System.Void'; Parameters = [string[]] @() }
        @{ Name = 'GetFailures'; ReturnType = 'System.Exception[]'; Parameters = [string[]] @() }
    )
    $publicMethods = @($Type.GetMethods($publicInstance))
    foreach ($requiredMethod in $requiredMethods) {
        $matchingMethod = @(
            $publicMethods | Where-Object {
                if ($_.Name -cne $requiredMethod.Name) {
                    return $false
                }

                $parameters = @($_.GetParameters())
                if ($parameters.Count -ne $requiredMethod.Parameters.Count) {
                    return $false
                }
                for ($index = 0; $index -lt $parameters.Count; $index++) {
                    if ($parameters[$index].ParameterType.FullName -cne $requiredMethod.Parameters[$index]) {
                        return $false
                    }
                }
                return $true
            }
        ) | Select-Object -First 1

        if ($null -eq $matchingMethod) {
            $issues.Add("public instance method $($requiredMethod.Name) has a missing or incompatible parameter list")
            continue
        }
        if ($matchingMethod.ReturnType.FullName -cne $requiredMethod.ReturnType) {
            $issues.Add(
                "method $($requiredMethod.Name) returns '$($matchingMethod.ReturnType.FullName)' instead of '$($requiredMethod.ReturnType)'"
            )
        }
    }

    if ($issues.Count -gt 0) {
        throw [System.InvalidOperationException]::new(
            "The loaded GraphKit module lifecycle type is incompatible with the required ABI contract: " +
            ($issues -join '; ')
        )
    }

    return $Type
}

$existingLifecycleType = $script:GraphKitModuleLifecycleStateTypeName -as [type]
if ($null -ne $existingLifecycleType) {
    $script:GraphKitModuleLifecycleStateType = Assert-GraphModuleLifecycleTypeContract -Type $existingLifecycleType
}
else {
    try {
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace GraphKit.Internal.RuntimeV1
{
public sealed class ModuleLifecycleState
{
    public static string ContractMarker
    {
        get { return "GraphKit.ModuleLifecycle.RuntimeV1/2026-08-30.1"; }
    }

    private readonly object _stateSync = new object();
    private readonly object _syncRoot = new object();
    private readonly List<IDisposable> _ownedResources = new List<IDisposable>();
    private readonly Dictionary<string, object> _httpClients =
        new Dictionary<string, object>(StringComparer.Ordinal);
    private readonly List<Exception> _failures = new List<Exception>();

    private bool _stopRequested;
    private bool _cleanupStarted;
    private bool _cleanupComplete;
    private bool _cleanupDeferred;
    private bool _cancellationObserved;
    private int _activeOperations;
    private Task _cancellationTask;
    private Task _cleanupTask;

    public ModuleLifecycleState()
    {
        ShutdownCts = new CancellationTokenSource();
        Drained = new ManualResetEventSlim(true);
        CleanupDone = new ManualResetEventSlim(false);
    }

    // The HTTP-client cache has its own lock because its factory is PowerShell
    // code and can block. Lifecycle cancellation must never wait for that lock.
    public object SyncRoot { get { return _syncRoot; } }
    public CancellationTokenSource ShutdownCts { get; private set; }
    public ManualResetEventSlim Drained { get; private set; }
    public ManualResetEventSlim CleanupDone { get; private set; }
    public List<IDisposable> OwnedResources { get { return _ownedResources; } }
    public Dictionary<string, object> HttpClients { get { return _httpClients; } }

    public bool StopRequested
    {
        get { lock (_stateSync) { return _stopRequested; } }
    }

    public bool CleanupStarted
    {
        get { lock (_stateSync) { return _cleanupStarted; } }
    }

    public bool CleanupComplete
    {
        get { lock (_stateSync) { return _cleanupComplete; } }
    }

    public bool CleanupDeferred
    {
        get { lock (_stateSync) { return _cleanupDeferred; } }
    }

    public int ActiveOperations
    {
        get { lock (_stateSync) { return _activeOperations; } }
    }

    public bool CancellationObserved
    {
        get { lock (_stateSync) { return _cancellationObserved; } }
    }

    public Task CancellationTask
    {
        get { lock (_stateSync) { return _cancellationTask; } }
    }

    public Task CleanupTask
    {
        get { lock (_stateSync) { return _cleanupTask; } }
    }

    public CancellationToken EnterOperation()
    {
        lock (_stateSync)
        {
            if (_stopRequested || _cleanupStarted)
            {
                throw new ObjectDisposedException(
                    "GraphKit",
                    "The GraphKit module is stopping and cannot start another operation.");
            }

            checked { _activeOperations++; }
            if (_activeOperations == 1) Drained.Reset();
            return ShutdownCts.Token;
        }
    }

    public void ExitOperation()
    {
        lock (_stateSync)
        {
            if (_activeOperations <= 0)
            {
                throw new InvalidOperationException(
                    "GraphKit module lifecycle operation count would become negative.");
            }

            _activeOperations--;
            if (_activeOperations == 0)
            {
                Drained.Set();
                TryScheduleCleanupNoLock();
            }
        }
    }

    public void RegisterOwnedResource(IDisposable resource)
    {
        if (resource == null) throw new ArgumentNullException("resource");

        lock (_stateSync)
        {
            if (_stopRequested || _cleanupStarted)
            {
                throw new ObjectDisposedException(
                    "GraphKit",
                    "The GraphKit module stopped before the owned resource could be registered.");
            }

            foreach (IDisposable existing in _ownedResources)
            {
                if (Object.ReferenceEquals(existing, resource)) return;
            }
            _ownedResources.Add(resource);
        }
    }

    public Task RequestStop()
    {
        lock (_stateSync)
        {
            if (!_stopRequested)
            {
                _stopRequested = true;
                try
                {
                    // CancelAsync marks the token cancelled synchronously but runs
                    // arbitrary callbacks asynchronously.
                    _cancellationTask = ShutdownCts.CancelAsync();
                }
                catch (Exception ex)
                {
                    AddFailureNoLock(ex);
                    _cancellationTask = Task.CompletedTask;
                    _cancellationObserved = true;
                }

                if (!_cancellationObserved)
                {
                    Task continuation = _cancellationTask.ContinueWith(
                        completed => CancellationCompleted(completed),
                        CancellationToken.None,
                        TaskContinuationOptions.ExecuteSynchronously,
                        TaskScheduler.Default);
                    GC.KeepAlive(continuation);
                }
            }

            TryScheduleCleanupNoLock();
            return _cancellationTask;
        }
    }

    public void TryScheduleCleanup()
    {
        lock (_stateSync) { TryScheduleCleanupNoLock(); }
    }

    public void MarkCleanupDeferred()
    {
        lock (_stateSync) { _cleanupDeferred = true; }
    }

    public Exception[] GetFailures()
    {
        lock (_stateSync) { return _failures.ToArray(); }
    }

    private void CancellationCompleted(Task completed)
    {
        lock (_stateSync)
        {
            try
            {
                if (completed.IsFaulted && completed.Exception != null)
                {
                    foreach (Exception failure in completed.Exception.Flatten().InnerExceptions)
                    {
                        AddFailureNoLock(failure);
                    }
                }
                else if (completed.IsCanceled)
                {
                    AddFailureNoLock(new TaskCanceledException(
                        "GraphKit module cancellation callbacks did not complete."));
                }
            }
            catch (Exception ex)
            {
                AddFailureNoLock(ex);
            }
            finally
            {
                // This is deliberately distinct from Task.IsCompleted. Cleanup
                // may start only after this observer has recorded terminal state.
                _cancellationObserved = true;
                TryScheduleCleanupNoLock();
            }
        }
    }

    private void TryScheduleCleanupNoLock()
    {
        if (!_stopRequested || _cleanupStarted || _activeOperations != 0 ||
            _cancellationTask == null || !_cancellationObserved)
        {
            return;
        }

        _cleanupStarted = true;
        IDisposable[] resources = _ownedResources.ToArray();
        _ownedResources.Clear();

        // Disposal never runs on the Stop, OnRemove, cancellation-callback, or
        // final-operation thread. A blocking/reentrant resource can delay only
        // this cleanup task; the caller observes the bounded CleanupDone wait.
        _cleanupTask = Task.Run(() => DisposeResources(resources));
    }

    private void DisposeResources(IDisposable[] resources)
    {
        try
        {
            lock (_syncRoot) { _httpClients.Clear(); }

            for (int index = resources.Length - 1; index >= 0; index--)
            {
                try { resources[index].Dispose(); }
                catch (Exception ex) { AddFailure(ex); }
            }
        }
        catch (Exception ex)
        {
            AddFailure(ex);
        }
        finally
        {
            lock (_stateSync) { _cleanupComplete = true; }
            CleanupDone.Set();
        }
    }

    private void AddFailure(Exception failure)
    {
        lock (_stateSync) { AddFailureNoLock(failure); }
    }

    private void AddFailureNoLock(Exception failure)
    {
        if (failure != null) _failures.Add(failure);
    }
}
}
'@

        $loadedLifecycleType = $script:GraphKitModuleLifecycleStateTypeName -as [type]
        if ($null -eq $loadedLifecycleType) {
            throw [System.TypeLoadException]::new(
                "Add-Type completed without loading '$($script:GraphKitModuleLifecycleStateTypeName)'."
            )
        }
        $script:GraphKitModuleLifecycleStateType = Assert-GraphModuleLifecycleTypeContract -Type $loadedLifecycleType
    }
    catch {
        $addTypeFailure = $_
        $racedLifecycleType = $script:GraphKitModuleLifecycleStateTypeName -as [type]
        if ($null -eq $racedLifecycleType) {
            throw
        }

        # Concurrent imports can both observe the type as absent before one
        # Add-Type wins. Suppress only that race and only after validating the
        # exact namespace, ABI marker and callable member surface.
        try {
            $script:GraphKitModuleLifecycleStateType =
                Assert-GraphModuleLifecycleTypeContract -Type $racedLifecycleType
        }
        catch {
            throw $addTypeFailure
        }
    }
}

function New-GraphModuleLifecycleState {
    [CmdletBinding()]
    [OutputType([object])]
    param()

    $state = [System.Activator]::CreateInstance($script:GraphKitModuleLifecycleStateType)
    $state.PSObject.TypeNames.Insert(0, 'GraphKit.ModuleLifecycleState')
    return $state
}

function Enter-GraphModuleOperation {
    [CmdletBinding()]
    [OutputType([System.Threading.CancellationToken])]
    param(
        [object] $State = $script:GraphKitModuleLifecycle
    )

    if ($null -eq $State) {
        throw [System.InvalidOperationException]::new('GraphKit module lifecycle state is unavailable.')
    }
    try {
        return $State.EnterOperation()
    }
    catch {
        if ($null -ne $_.Exception.InnerException) {
            throw $_.Exception.InnerException
        }
        throw
    }
}

function Exit-GraphModuleOperation {
    [CmdletBinding()]
    param(
        [object] $State = $script:GraphKitModuleLifecycle
    )

    if ($null -eq $State) {
        throw [System.InvalidOperationException]::new('GraphKit module lifecycle state is unavailable.')
    }
    $State.ExitOperation()
}

function Register-GraphModuleOwnedResource {
    [CmdletBinding()]
    [OutputType([System.IDisposable])]
    param(
        [Parameter(Mandatory)]
        [System.IDisposable] $Resource,

        [Parameter(Mandatory)]
        [bool] $OwnedByGraphKit,

        [object] $State = $script:GraphKitModuleLifecycle
    )

    if (-not $OwnedByGraphKit) {
        return $Resource
    }
    if ($null -eq $State) {
        throw [System.InvalidOperationException]::new('GraphKit module lifecycle state is unavailable.')
    }

    # Ownership transfers only if this call returns. A refused registration
    # deliberately leaves disposal with its caller.
    try {
        $State.RegisterOwnedResource($Resource)
    }
    catch {
        if ($null -ne $_.Exception.InnerException) {
            throw $_.Exception.InnerException
        }
        throw
    }
    return $Resource
}

function Complete-GraphModuleCleanup {
    [CmdletBinding()]
    param(
        [object] $State = $script:GraphKitModuleLifecycle
    )

    if ($null -eq $State) {
        return
    }
    $State.TryScheduleCleanup()
}

function Stop-GraphModule {
    [CmdletBinding()]
    param(
        [object] $State = $script:GraphKitModuleLifecycle,

        [ValidateRange(0, 600000)]
        [int] $DrainTimeoutMilliseconds = 5000
    )

    if ($null -eq $State) {
        return
    }

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $requestFailure = $null
    try {
        $null = $State.RequestStop()
    }
    catch {
        $requestFailure = $_.Exception
    }

    $remaining = [Math]::Max(0, $DrainTimeoutMilliseconds - [int] $watch.ElapsedMilliseconds)
    $cleanupObserved = $State.CleanupDone.Wait($remaining)
    $watch.Stop()

    if (-not $cleanupObserved) {
        $State.MarkCleanupDeferred()
        Write-Warning (
            "GraphKit shutdown did not complete within $DrainTimeoutMilliseconds ms. " +
            "$($State.ActiveOperations) active operation(s) remain; cancellation callbacks or " +
            'owned-resource disposal may also still be running. Cleanup will continue asynchronously.'
        )
    }

    $failures = [System.Collections.Generic.List[System.Exception]]::new()
    if ($null -ne $requestFailure) {
        $failures.Add($requestFailure)
    }
    foreach ($failure in [System.Exception[]] $State.GetFailures()) {
        $failures.Add($failure)
    }

    if ($failures.Count -gt 0) {
        throw [System.AggregateException]::new(
            'GraphKit module shutdown encountered one or more failures.',
            $failures.ToArray()
        )
    }
}

$script:GraphKitModuleLifecycle = New-GraphModuleLifecycleState
$graphKitLifecycleForRemoval = $script:GraphKitModuleLifecycle
$stopGraphModuleForRemoval = Get-Command -Name Stop-GraphModule -CommandType Function

# Exactly one removal hook owns module cleanup. Process-wide token flights are
# intentionally untouched and may outlive any one imported module instance.
$ExecutionContext.SessionState.Module.OnRemove = {
    & $stopGraphModuleForRemoval -State $graphKitLifecycleForRemoval
}.GetNewClosure()
