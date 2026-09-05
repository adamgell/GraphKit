BeforeAll {
    $script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    # ThreadJob readiness includes runspace startup and a full module import. Keep that
    # scheduler-sensitive setup bound separate from the tighter operation/deadlock gates.
    $script:Task7ThreadJobReadyTimeoutMilliseconds = 15000
    $builtCandidates = @(
        Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'output/module/GraphKit') `
            -Directory | Sort-Object Name -Descending
    )
    if ($builtCandidates.Count -eq 0) {
        throw 'GraphKit is not packed. Run ./build.ps1 -Tasks pack before this file.'
    }
    $script:BuiltManifest = Join-Path $builtCandidates[0].FullName 'GraphKit.psd1'
    Import-Module $script:BuiltManifest -Force -ErrorAction Stop

    if ($null -eq ('GraphKit.Tests.Task7ControlledTokenSource' -as [type])) {
        $fixtureRoot = Join-Path $TestDrive 'task7-runspace-fixture'
        $fixtureOutput = Join-Path $fixtureRoot 'out'
        $offlineFeed = Join-Path $fixtureRoot 'offline-feed'
        $null = New-Item -ItemType Directory -Path $fixtureRoot, $offlineFeed -Force
        $contractsPath = [GraphKit.Auth.IGraphTokenSource].Assembly.Location
        $escapedContractsPath = [Security.SecurityElement]::Escape($contractsPath)
        Set-Content -LiteralPath (Join-Path $fixtureRoot 'Fixture.cs') `
            -NoNewline -Encoding utf8NoBOM -Value @'
using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using GraphKit.Auth;

namespace GraphKit.Tests;

// TASK7_FIXTURE_SOURCE_BEGIN
public sealed class Task7ControlledTokenSource : IGraphTokenSource
{
    public const string ContractMarker = "GraphKit.Task7.RunspaceFixture/3";
    public const string ContractSourceSha256 =
        "5ecbcb30fa3cd49fdea9c179263ae7953d37a3085356a4f6d3cdd439fe5afe61";
    private readonly object _gate = new();
    private readonly string _token;
    private readonly string _fingerprint;
    private readonly string? _verifiedTenantId;
    private readonly string _generation;
    private readonly CountdownEvent _entered;
    private readonly ManualResetEventSlim _release;
    private readonly bool _suffixByForce;
    private readonly ConcurrentQueue<bool> _forceFlags = new();
    private readonly ConcurrentDictionary<GraphTokenResult, byte> _ownedResults = new();
    private readonly ConcurrentDictionary<bool, GraphTokenResult> _resultsByForce = new();
    private GraphTokenResult? _current;
    private int _acquireCount;
    private int _adoptCount;
    private int _disposeCount;
    private int _disposed;

    public Task7ControlledTokenSource(
        string token,
        string fingerprint,
        string? verifiedTenantId,
        string generation,
        CountdownEvent entered,
        ManualResetEventSlim release,
        bool suffixByForce)
    {
        _token = token;
        _fingerprint = fingerprint;
        _verifiedTenantId = verifiedTenantId;
        _generation = generation;
        _entered = entered;
        _release = release;
        _suffixByForce = suffixByForce;
    }

    public int AcquireCount => Volatile.Read(ref _acquireCount);
    public int SemanticAdoptionCount => Volatile.Read(ref _adoptCount);
    public int DisposeCount => Volatile.Read(ref _disposeCount);
    public bool CanRefresh => true;
    public string AuthMode => "Certificate";
    public string Audience => "https://graph.microsoft.com/";
    public string? ClientId => "00000000-0000-0000-0000-000000000072";
    public DateTimeOffset ExpiresOn { get; private set; }
    public string? VerifiedTenantId { get; private set; }
    public string CredentialGeneration => _generation;
    public bool[] ForceFlags => _forceFlags.ToArray();
    public GraphTokenResult? CurrentResult
    {
        get { lock (_gate) { return _current; } }
    }

    public GraphTokenResult? ResultForForce(bool forceRefresh) =>
        _resultsByForce.TryGetValue(forceRefresh, out var result) ? result : null;

    public GraphTokenResult Acquire(bool forceRefresh, CancellationToken cancellation)
    {
        if (Volatile.Read(ref _disposed) != 0)
            throw new ObjectDisposedException(nameof(Task7ControlledTokenSource));
        cancellation.ThrowIfCancellationRequested();
        Interlocked.Increment(ref _acquireCount);
        _forceFlags.Enqueue(forceRefresh);
        _entered.Signal();
        _release.Wait(cancellation);
        cancellation.ThrowIfCancellationRequested();

        string suffix = _suffixByForce ? (forceRefresh ? "-forced" : "-ordinary") : string.Empty;
        var result = new GraphTokenResult
        {
            AccessToken = _token + suffix,
            ExpiresOnUtc = new DateTimeOffset(2099, 7, 1, 0, 0, 0, TimeSpan.Zero),
            ReceivedOnUtc = new DateTimeOffset(2026, 8, 31, 12, 0, 0, TimeSpan.Zero),
            TokenType = "Bearer",
            Scopes = new[] { "https://graph.microsoft.com/.default" },
            VerifiedTenantId = _verifiedTenantId,
            TokenFingerprint = _fingerprint + suffix,
            CredentialGeneration = _generation
        };
        _ownedResults.TryAdd(result, 0);
        _resultsByForce[forceRefresh] = result;
        lock (_gate)
        {
            _current = result;
            ExpiresOn = result.ExpiresOnUtc;
            VerifiedTenantId = result.VerifiedTenantId;
        }
        return result;
    }

    public void AdoptSharedResult(GraphTokenResult result, bool forceRefresh)
    {
        if (Volatile.Read(ref _disposed) != 0)
            throw new ObjectDisposedException(nameof(Task7ControlledTokenSource));
        if (!string.Equals(result.CredentialGeneration, _generation, StringComparison.Ordinal))
            throw new InvalidOperationException("Task 7 controlled source rejected a foreign generation.");
        if (!_ownedResults.ContainsKey(result)) Interlocked.Increment(ref _adoptCount);
        _resultsByForce[forceRefresh] = result;
        lock (_gate)
        {
            _current = result;
            ExpiresOn = result.ExpiresOnUtc;
            VerifiedTenantId = result.VerifiedTenantId;
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
            Interlocked.Increment(ref _disposeCount);
    }
}

public sealed class Task7OfflineHandler : HttpMessageHandler
{
    private int _sendCount;
    private int _disposeCount;
    public int SendCount => Volatile.Read(ref _sendCount);
    public int DisposeCount => Volatile.Read(ref _disposeCount);
    public ConcurrentQueue<string> AccessTokens { get; } = new();
    public ConcurrentQueue<string> RequestEvidence { get; } = new();

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Interlocked.Increment(ref _sendCount);
        string token = request.Headers.Authorization?.Parameter ?? string.Empty;
        AccessTokens.Enqueue(token);
        RequestEvidence.Enqueue((request.RequestUri?.AbsolutePath ?? string.Empty) + "|" + token);
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) Interlocked.Increment(ref _disposeCount);
        base.Dispose(disposing);
    }
}
// TASK7_FIXTURE_SOURCE_END
'@
        Set-Content -LiteralPath (Join-Path $fixtureRoot 'Fixture.csproj') `
            -NoNewline -Encoding utf8NoBOM -Value @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <AssemblyName>GraphKit.Task7.RunspaceFixture</AssemblyName>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <Deterministic>true</Deterministic>
    <DebugType>none</DebugType>
  </PropertyGroup>
  <ItemGroup>
    <Reference Include="GraphKit.Auth.Contracts">
      <HintPath>$escapedContractsPath</HintPath>
      <Private>false</Private>
    </Reference>
  </ItemGroup>
</Project>
"@
        $restoreOutput = & dotnet restore (Join-Path $fixtureRoot 'Fixture.csproj') `
            --source $offlineFeed --nologo --verbosity quiet 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Task 7 offline fixture restore failed: $($restoreOutput | Out-String)"
        }
        $buildOutput = & dotnet build (Join-Path $fixtureRoot 'Fixture.csproj') `
            -c Release -o $fixtureOutput --no-restore --nologo --verbosity quiet 2>&1
        $fixtureAssembly = Join-Path $fixtureOutput 'GraphKit.Task7.RunspaceFixture.dll'
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $fixtureAssembly -PathType Leaf)) {
            throw "Task 7 controlled fixture build failed: $($buildOutput | Out-String)"
        }
        $fixtureStream = [IO.MemoryStream]::new(
            [IO.File]::ReadAllBytes($fixtureAssembly), $false)
        try {
            $null = [Runtime.Loader.AssemblyLoadContext]::Default.LoadFromStream($fixtureStream)
        }
        finally {
            $fixtureStream.Dispose()
        }
    }
    $controlledType = 'GraphKit.Tests.Task7ControlledTokenSource' -as [type]
    $contractField = if ($null -ne $controlledType) {
        $controlledType.GetField('ContractMarker')
    }
    else {
        $null
    }
    if ($null -eq $contractField -or
        [string] $contractField.GetRawConstantValue() -cne
            'GraphKit.Task7.RunspaceFixture/3') {
        throw 'The process-global Task 7 runspace fixture has an incompatible identity or contract.'
    }
    $sourceShaField = $controlledType.GetField('ContractSourceSha256')
    $fixtureFileText = [IO.File]::ReadAllText(
        (Join-Path $PSScriptRoot 'GraphKitAuthRunspace.Tests.ps1'))
    $fixtureBeginMarker = '// TASK7_FIXTURE_SOURCE_BEGIN'
    $fixtureEndMarker = '// TASK7_FIXTURE_SOURCE_END'
    $fixtureBegin = $fixtureFileText.IndexOf(
        $fixtureBeginMarker, [StringComparison]::Ordinal)
    $fixtureEnd = $fixtureFileText.IndexOf(
        $fixtureEndMarker, [StringComparison]::Ordinal)
    if ($fixtureBegin -lt 0 -or $fixtureEnd -lt $fixtureBegin) {
        throw 'The Task 7 runspace fixture source-digest boundaries are missing.'
    }
    $fixtureBody = $fixtureFileText.Substring(
        $fixtureBegin,
        ($fixtureEnd + $fixtureEndMarker.Length) - $fixtureBegin)
    $normalizedFixtureBody = [regex]::Replace(
        $fixtureBody,
        '(?s)(ContractSourceSha256\s*=\s*\r?\n\s*")[0-9a-f]{64}(";)',
        [Text.RegularExpressions.MatchEvaluator] {
            param($Match)
            $Match.Groups[1].Value + ('0' * 64) + $Match.Groups[2].Value
        })
    $normalizedFixtureBody = $normalizedFixtureBody -replace "`r`n?", "`n"
    $computedFixtureSha = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData(
            [Text.Encoding]::UTF8.GetBytes($normalizedFixtureBody)))
    $computedFixtureSha = $computedFixtureSha.ToLowerInvariant()
    if ($null -eq $sourceShaField -or
        [string] $sourceShaField.GetRawConstantValue() -cne $computedFixtureSha) {
        throw (
            'The process-global Task 7 runspace fixture source digest is stale. ' +
            'Run this test file in a fresh PowerShell process after updating its derived digest.'
        )
    }

    $script:FixedBearerChild = {
        param($Manifest, $HolderKey)
        $module = $null
        $state = $null
        $childHost = $null
        $holder = $null
        $source = $null
        $result = $null
        $cleanupObserved = $false
        $initialHostOnly = $false
        $preRemovalHostOnly = $false
        $removeSucceeded = $false
        $moduleAbsent = $false
        $stopRequested = $false
        $cleanupComplete = $false
        $activeOperations = -1
        $ownedResourceCount = -1
        $failureCount = -1
        $cleanupError = $null
        $outcome = $null
        try {
            $module = Import-Module $Manifest -Force -PassThru -ErrorAction Stop
            $childCapture = & $module {
                $owned = @($script:GraphKitModuleLifecycle.OwnedResources)
                [pscustomobject] @{
                    State = $script:GraphKitModuleLifecycle
                    Host = $script:GraphKitAuthHost
                    HostOnly =
                        $owned.Count -eq 1 -and
                        [object]::ReferenceEquals($owned[0], $script:GraphKitAuthHost)
                }
            }
            $state = $childCapture.State
            $childHost = $childCapture.Host
            $initialHostOnly = [bool] $childCapture.HostOnly
            $childCapture = $null
            $holder = [AppDomain]::CurrentDomain.GetData($HolderKey)
            if ($null -eq $holder) { throw 'Task 7 parent holder was unavailable.' }
            $source = $holder.Source
            $holder.ObservedSources.Enqueue([object] $source)
            $null = $holder.Ready.Signal()
            $holder.Go.Wait()

            $result = $source.Acquire($false, [Threading.CancellationToken]::None)
            $holder.Results.Enqueue([object] $result)
            $forceRefused = $false
            try {
                $null = $source.Acquire($true, [Threading.CancellationToken]::None)
            }
            catch [GraphKit.Auth.GraphAuthException] {
                $forceRefused =
                    $_.Exception.GetType().FullName -ceq 'GraphKit.Auth.GraphAuthException' -and
                    $_.Exception.Code -ceq 'provider_failure' -and
                    $_.Exception.Category -ceq 'Provider' -and
                    $_.Exception.Message -ceq `
                        'The isolated GraphKit.Auth provider could not complete the requested operation.'
            }
            $outcome = [pscustomobject] @{
                Success = $true
                Token = [string] $result.AccessToken
                ForceRefused = $forceRefused
                ErrorText = $null
            }
        }
        catch {
            $outcome = [pscustomobject] @{
                Success = $false
                Token = $null
                ForceRefused = $false
                ErrorText = ($_ | Out-String)
            }
        }
        finally {
            if ($null -ne $module) {
                try {
                    $preRemovalHostOnly = [bool] (& $module {
                        param($ExpectedHost)
                        $owned = @($script:GraphKitModuleLifecycle.OwnedResources)
                        $owned.Count -eq 1 -and
                            [object]::ReferenceEquals($owned[0], $ExpectedHost)
                    } $childHost)
                    Remove-Module -ModuleInfo $module -Force -ErrorAction Stop
                    $removeSucceeded = $true
                }
                catch {
                    $cleanupError = ($_ | Out-String)
                }
            }
            $cleanupObserved = $null -ne $state -and $state.WaitForCleanup(5000)
            $moduleAbsent = $null -eq (Get-Module -Name GraphKit)
            if ($null -ne $state) {
                $stopRequested = [bool] $state.StopRequested
                $cleanupComplete = [bool] $state.CleanupComplete
                $activeOperations = [int] $state.ActiveOperations
                $ownedResourceCount = [int] $state.OwnedResources.Count
                $failureCount = @($state.GetFailures()).Count
            }
            $result = $null
            $source = $null
            $holder = $null
            $childHost = $null
            $state = $null
            $module = $null
        }
        if ($null -eq $outcome) {
            $outcome = [pscustomobject] @{
                Success = $false; Token = $null; ForceRefused = $false
                ErrorText = 'Task 7 fixed-bearer child produced no outcome.'
            }
        }
        if (-not [string]::IsNullOrEmpty($cleanupError)) {
            $outcome.Success = $false
            $outcome.ErrorText = $cleanupError
        }
        $outcome | Add-Member NoteProperty InitialHostOnly $initialHostOnly
        $outcome | Add-Member NoteProperty PreRemovalHostOnly $preRemovalHostOnly
        $outcome | Add-Member NoteProperty RemoveSucceeded $removeSucceeded
        $outcome | Add-Member NoteProperty ModuleAbsent $moduleAbsent
        $outcome | Add-Member NoteProperty CleanupObserved $cleanupObserved
        $outcome | Add-Member NoteProperty StopRequested $stopRequested
        $outcome | Add-Member NoteProperty CleanupComplete $cleanupComplete
        $outcome | Add-Member NoteProperty ActiveOperations $activeOperations
        $outcome | Add-Member NoteProperty OwnedResourceCount $ownedResourceCount
        $outcome | Add-Member NoteProperty FailureCount $failureCount
        return $outcome
    }

    $script:ControlledSenderChild = {
        param($Manifest, $HolderKey, [int] $ContextIndex, [bool] $ForceRefresh)
        $module = $null
        $state = $null
        $childHost = $null
        $holder = $null
        $context = $null
        $source = $null
        $current = $null
        $cleanupObserved = $false
        $initialHostOnly = $false
        $preRemovalHostOnly = $false
        $removeSucceeded = $false
        $moduleAbsent = $false
        $stopRequested = $false
        $cleanupComplete = $false
        $activeOperations = -1
        $ownedResourceCount = -1
        $failureCount = -1
        $cleanupError = $null
        $outcome = $null
        try {
            $module = Import-Module $Manifest -Force -PassThru -ErrorAction Stop
            $childCapture = & $module {
                $owned = @($script:GraphKitModuleLifecycle.OwnedResources)
                [pscustomobject] @{
                    State = $script:GraphKitModuleLifecycle
                    Host = $script:GraphKitAuthHost
                    HostOnly =
                        $owned.Count -eq 1 -and
                        [object]::ReferenceEquals($owned[0], $script:GraphKitAuthHost)
                }
            }
            $state = $childCapture.State
            $childHost = $childCapture.Host
            $initialHostOnly = [bool] $childCapture.HostOnly
            $childCapture = $null
            $holder = [AppDomain]::CurrentDomain.GetData($HolderKey)
            if ($null -eq $holder) { throw 'Task 7 controlled holder was unavailable.' }
            $context = $holder.Contexts[$ContextIndex]
            $source = $holder.Sources[$ContextIndex]
            $holder.ObservedSources.Enqueue([object] $source)
            $null = $holder.Ready.Signal()
            $holder.Go.Wait()
            $transport = & $module {
                param($Context, $Source, $Client, [bool] $ForceRefresh, [int] $RequestIndex)
                $clientFactory = {
                    param([int] $ConnectTimeoutSeconds)
                    $null = $ConnectTimeoutSeconds
                    [pscustomobject] @{
                        Client = $Client
                        OwnedByGraphKit = $false
                    }
                }.GetNewClosure()
                Send-GraphHttpRequest `
                    -Uri ([uri] ("https://graph.microsoft.com/v1.0/task7-offline/{0}" -f $RequestIndex)) `
                    -Method GET `
                    -CredentialPolicy GraphBearer `
                    -ExpectedAuthority ([uri] 'https://graph.microsoft.com') `
                    -TokenSource $Source `
                    -TokenAcquisitionKey ([string] $Context.AcquisitionCacheKey) `
                    -ForceRefresh:$ForceRefresh `
                    -LifecycleState $script:GraphKitModuleLifecycle `
                    -HttpClientFactory $clientFactory `
                    -TimeoutConnectionSeconds 5 `
                    -TimeoutHeadersSeconds 5 `
                    -TimeoutBodySeconds 5
            } $context $source $holder.Client $ForceRefresh $ContextIndex
            $current = $source.ResultForForce($ForceRefresh)
            if ($null -eq $current) {
                throw 'Task 7 controlled source had no exact force-partition result after the sender returned.'
            }
            $holder.Results.Enqueue([object] $current)
            $outcome = [pscustomobject] @{
                Success = $true
                StatusCode = [int] $transport.StatusCode
                Token = [string] $current.AccessToken
                Fingerprint = [string] $current.TokenFingerprint
                Proof = [string] $current.VerifiedTenantId
                Generation = [string] $current.CredentialGeneration
                ContextIndex = $ContextIndex
                ForceRefresh = $ForceRefresh
                ErrorText = $null
            }
        }
        catch {
            $outcome = [pscustomobject] @{
                Success = $false
                StatusCode = 0
                Token = $null
                Fingerprint = $null
                Proof = $null
                Generation = $null
                ContextIndex = $ContextIndex
                ForceRefresh = $ForceRefresh
                ErrorText = ($_ | Out-String)
            }
        }
        finally {
            if ($null -ne $module) {
                try {
                    $preRemovalHostOnly = [bool] (& $module {
                        param($ExpectedHost)
                        $owned = @($script:GraphKitModuleLifecycle.OwnedResources)
                        $owned.Count -eq 1 -and
                            [object]::ReferenceEquals($owned[0], $ExpectedHost)
                    } $childHost)
                    Remove-Module -ModuleInfo $module -Force -ErrorAction Stop
                    $removeSucceeded = $true
                }
                catch {
                    $cleanupError = ($_ | Out-String)
                }
            }
            $cleanupObserved = $null -ne $state -and $state.WaitForCleanup(5000)
            $moduleAbsent = $null -eq (Get-Module -Name GraphKit)
            if ($null -ne $state) {
                $stopRequested = [bool] $state.StopRequested
                $cleanupComplete = [bool] $state.CleanupComplete
                $activeOperations = [int] $state.ActiveOperations
                $ownedResourceCount = [int] $state.OwnedResources.Count
                $failureCount = @($state.GetFailures()).Count
            }
            $current = $null
            $source = $null
            $context = $null
            $holder = $null
            $childHost = $null
            $state = $null
            $module = $null
        }
        if ($null -eq $outcome) {
            $outcome = [pscustomobject] @{
                Success = $false; StatusCode = 0; Token = $null
                Fingerprint = $null; Proof = $null; Generation = $null
                ContextIndex = $ContextIndex; ForceRefresh = $ForceRefresh
                ErrorText = 'Task 7 controlled child produced no outcome.'
            }
        }
        if (-not [string]::IsNullOrEmpty($cleanupError)) {
            $outcome.Success = $false
            $outcome.ErrorText = $cleanupError
        }
        $outcome | Add-Member NoteProperty InitialHostOnly $initialHostOnly
        $outcome | Add-Member NoteProperty PreRemovalHostOnly $preRemovalHostOnly
        $outcome | Add-Member NoteProperty RemoveSucceeded $removeSucceeded
        $outcome | Add-Member NoteProperty ModuleAbsent $moduleAbsent
        $outcome | Add-Member NoteProperty CleanupObserved $cleanupObserved
        $outcome | Add-Member NoteProperty StopRequested $stopRequested
        $outcome | Add-Member NoteProperty CleanupComplete $cleanupComplete
        $outcome | Add-Member NoteProperty ActiveOperations $activeOperations
        $outcome | Add-Member NoteProperty OwnedResourceCount $ownedResourceCount
        $outcome | Add-Member NoteProperty FailureCount $failureCount
        return $outcome
    }

    $script:LegacyContainmentChild = {
        param($Manifest, $HolderKey)
        $module = $null
        $state = $null
        $childHost = $null
        $holder = $null
        $source = $null
        $cleanupObserved = $false
        $initialHostOnly = $false
        $preRemovalHostOnly = $false
        $removeSucceeded = $false
        $moduleAbsent = $false
        $stopRequested = $false
        $cleanupComplete = $false
        $activeOperations = -1
        $ownedResourceCount = -1
        $failureCount = -1
        $cleanupError = $null
        $outcome = $null
        try {
            $module = Import-Module $Manifest -Force -PassThru -ErrorAction Stop
            $childCapture = & $module {
                $owned = @($script:GraphKitModuleLifecycle.OwnedResources)
                [pscustomobject] @{
                    State = $script:GraphKitModuleLifecycle
                    Host = $script:GraphKitAuthHost
                    HostOnly =
                        $owned.Count -eq 1 -and
                        [object]::ReferenceEquals($owned[0], $script:GraphKitAuthHost)
                }
            }
            $state = $childCapture.State
            $childHost = $childCapture.Host
            $initialHostOnly = [bool] $childCapture.HostOnly
            $childCapture = $null
            $holder = [AppDomain]::CurrentDomain.GetData($HolderKey)
            if ($null -eq $holder) { throw 'Task 7 legacy holder was unavailable.' }
            $source = $holder.Source
            $holder.ObservedSources.Enqueue([object] $source)
            $null = $holder.Ready.Signal()
            $holder.Go.Wait()
            $caught = $null
            try {
                $null = & $module {
                    param($Context, $Source, $Client)
                    $clientFactory = {
                        param([int] $ConnectTimeoutSeconds)
                        $null = $ConnectTimeoutSeconds
                        [pscustomobject] @{ Client = $Client; OwnedByGraphKit = $false }
                    }.GetNewClosure()
                    Send-GraphHttpRequest `
                        -Uri ([uri] 'https://graph.microsoft.com/v1.0/task7-offline') `
                        -Method GET `
                        -CredentialPolicy GraphBearer `
                        -ExpectedAuthority ([uri] 'https://graph.microsoft.com') `
                        -TokenSource $Source `
                        -TokenAcquisitionKey ([string] $Context.AcquisitionCacheKey) `
                        -LifecycleState $script:GraphKitModuleLifecycle `
                        -HttpClientFactory $clientFactory
                } $holder.Context $source $holder.Client
            }
            catch {
                $caught = $_.Exception
            }
            if ($null -eq $caught) {
                throw 'Task 7 legacy cross-runspace sender unexpectedly succeeded.'
            }
            $root = $caught
            while ($null -ne $root.InnerException) { $root = $root.InnerException }
            $outcome = [pscustomobject] @{
                Success = $true
                Rejected =
                    $root.GetType().FullName -ceq 'System.InvalidOperationException' -and
                    $root.Message -ceq (
                        'This legacy PowerShell token source is bound to the runspace where its context was created. ' +
                        'Cross-runspace context use is disabled because PowerShell-class token acquisition can hang; ' +
                        'the compiled GraphKit.Auth token source is required for that contract.'
                    )
                FailureType = $root.GetType().FullName
                FailureMessage = $root.Message
                ErrorText = $null
            }
        }
        catch {
            $outcome = [pscustomobject] @{
                Success = $false
                Rejected = $false
                FailureType = $null
                FailureMessage = $null
                ErrorText = ($_ | Out-String)
            }
        }
        finally {
            if ($null -ne $module) {
                try {
                    $preRemovalHostOnly = [bool] (& $module {
                        param($ExpectedHost)
                        $owned = @($script:GraphKitModuleLifecycle.OwnedResources)
                        $owned.Count -eq 1 -and
                            [object]::ReferenceEquals($owned[0], $ExpectedHost)
                    } $childHost)
                    Remove-Module -ModuleInfo $module -Force -ErrorAction Stop
                    $removeSucceeded = $true
                }
                catch {
                    $cleanupError = ($_ | Out-String)
                }
            }
            $cleanupObserved = $null -ne $state -and $state.WaitForCleanup(5000)
            $moduleAbsent = $null -eq (Get-Module -Name GraphKit)
            if ($null -ne $state) {
                $stopRequested = [bool] $state.StopRequested
                $cleanupComplete = [bool] $state.CleanupComplete
                $activeOperations = [int] $state.ActiveOperations
                $ownedResourceCount = [int] $state.OwnedResources.Count
                $failureCount = @($state.GetFailures()).Count
            }
            $source = $null
            $holder = $null
            $childHost = $null
            $state = $null
            $module = $null
        }
        if ($null -eq $outcome) {
            $outcome = [pscustomobject] @{
                Success = $false; Rejected = $false; FailureType = $null
                FailureMessage = $null
                ErrorText = 'Task 7 legacy child produced no outcome.'
            }
        }
        if (-not [string]::IsNullOrEmpty($cleanupError)) {
            $outcome.Success = $false
            $outcome.ErrorText = $cleanupError
        }
        $outcome | Add-Member NoteProperty InitialHostOnly $initialHostOnly
        $outcome | Add-Member NoteProperty PreRemovalHostOnly $preRemovalHostOnly
        $outcome | Add-Member NoteProperty RemoveSucceeded $removeSucceeded
        $outcome | Add-Member NoteProperty ModuleAbsent $moduleAbsent
        $outcome | Add-Member NoteProperty CleanupObserved $cleanupObserved
        $outcome | Add-Member NoteProperty StopRequested $stopRequested
        $outcome | Add-Member NoteProperty CleanupComplete $cleanupComplete
        $outcome | Add-Member NoteProperty ActiveOperations $activeOperations
        $outcome | Add-Member NoteProperty OwnedResourceCount $ownedResourceCount
        $outcome | Add-Member NoteProperty FailureCount $failureCount
        return $outcome
    }

    function New-Task7ControlledContext {
        param(
            [Parameter(Mandatory)] $Source,
            [Parameter(Mandatory)] [string] $AcquisitionKey,
            [Parameter(Mandatory)] [guid] $TenantId
        )
        return [pscustomobject] @{
            PSTypeName = 'GraphKit.Context'
            TenantId = $TenantId
            GraphBaseUri = [uri] 'https://graph.microsoft.com'
            TokenSource = $Source
            AcquisitionCacheKey = $AcquisitionKey
        }
    }

    function Get-Task7OuterFlightSnapshot {
        param(
            [Parameter(Mandatory)] [string] $AcquisitionKey,
            [Parameter(Mandatory)] [bool] $ForceRefresh
        )
        return InModuleScope GraphKit -Parameters @{
            AcquisitionKey = $AcquisitionKey
            ForceRefresh = $ForceRefresh
        } {
            param($AcquisitionKey, $ForceRefresh)
            $key = Get-GraphTokenFlightKey -AcquisitionKey $AcquisitionKey `
                -ForceRefresh:$ForceRefresh
            $flight = [GraphTokenFlight] $null
            $exists = [GraphTokenFlightRegistry]::Flights.TryGetValue($key, [ref] $flight)
            [pscustomobject] @{
                Key = $key
                Exists = $exists
                WaiterCount = if ($exists) {
                    [int] (Get-GraphTokenFlightWaiterCount -Flight $flight)
                }
                else {
                    -1
                }
                RegistryCount = [GraphTokenFlightRegistry]::Flights.Count
            }
        }
    }

    function Get-Task7OuterFlightRegistryCount {
        return InModuleScope GraphKit { [GraphTokenFlightRegistry]::Flights.Count }
    }

    function Complete-Task7ChildJobs {
        param(
            [Parameter(Mandatory)] [object[]] $Jobs,
            [Parameter(Mandatory)] [int] $ExpectedCount
        )
        $completed = @($Jobs | Wait-Job -Timeout 10)
        $null = $completed.Count | Should -Be $ExpectedCount
        $outcomes = @($Jobs | Receive-Job -ErrorAction Stop)
        $null = $outcomes.Count | Should -Be $ExpectedCount
        return $outcomes
    }

    function Assert-Task7ChildCleanup {
        param([Parameter(Mandatory)] [object[]] $Outcomes)

        foreach ($outcome in $Outcomes) {
            $outcome.InitialHostOnly | Should -BeTrue
            $outcome.PreRemovalHostOnly | Should -BeTrue
            $outcome.RemoveSucceeded | Should -BeTrue
            $outcome.ModuleAbsent | Should -BeTrue
            $outcome.CleanupObserved | Should -BeTrue
            $outcome.StopRequested | Should -BeTrue
            $outcome.CleanupComplete | Should -BeTrue
            $outcome.ActiveOperations | Should -Be 0
            $outcome.OwnedResourceCount | Should -Be 0
            $outcome.FailureCount | Should -Be 0
        }
    }

    function Remove-Task7ChildJobs {
        param([object[]] $Jobs)
        if ($null -eq $Jobs -or $Jobs.Count -eq 0) {
            return
        }
        $null = @($Jobs | Wait-Job -Timeout 10)
        foreach ($job in $Jobs) {
            Remove-Job $job -Force -ErrorAction SilentlyContinue
        }
    }
}

AfterAll {
    Remove-Module GraphKit -Force -ErrorAction SilentlyContinue
    $script:FixedBearerChild = $null
    $script:ControlledSenderChild = $null
    $script:LegacyContainmentChild = $null
    $script:BuiltManifest = $null
}

Describe 'GraphKit.Auth exact parent-source thread-runspace use' -Tag Concurrency {
    It 'uses one public compiled fixed-bearer source by exact reference in two children' {
        [GraphKit.Tests.Task7ControlledTokenSource].Assembly.Location |
            Should -BeNullOrEmpty
        $storePath = Join-Path $TestDrive 'task7-fixed-bearer-profiles.json'
        $store = [ordered] @{
            SchemaVersion = 1
            Profiles = @(
                [ordered] @{
                    ProfileId = 'task7-fixed-bearer'
                    Name = 'Task 7 synthetic fixed bearer'
                    Kind = 'lab'
                    TenantId = '00000000-0000-0000-0000-000000000071'
                    ClientId = $null
                    AuthMethod = 'BearerToken'
                    Environment = 'Global'
                    Credential = [ordered] @{
                        Token = 'task7-synthetic-fixed-bearer-token'
                        Version = 'task7-inline-v1'
                    }
                }
            )
        }
        [IO.File]::WriteAllText(
            $storePath,
            (ConvertTo-Json $store -Depth 20),
            [Text.UTF8Encoding]::new($false)
        )
        $context = Get-GraphContext -ProfileId task7-fixed-bearer -StorePath $storePath
        $source = $context.TokenSource
        $holderKey = 'GraphKit.Task7.FixedBearer.' + [guid]::NewGuid().ToString('N')
        $ready = [Threading.CountdownEvent]::new(2)
        $go = [Threading.ManualResetEventSlim]::new($false)
        $observed = [Collections.Concurrent.ConcurrentQueue[object]]::new()
        $results = [Collections.Concurrent.ConcurrentQueue[object]]::new()
        $holder = [pscustomobject] @{
            Context = $context
            Source = $source
            Ready = $ready
            Go = $go
            ObservedSources = $observed
            Results = $results
        }
        $jobs = @()
        [AppDomain]::CurrentDomain.SetData($holderKey, $holder)
        try {
            $jobs = @(
                1..2 | ForEach-Object {
                    Start-ThreadJob -ScriptBlock $script:FixedBearerChild `
                        -ArgumentList $script:BuiltManifest, $holderKey
                }
            )
            $ready.Wait($script:Task7ThreadJobReadyTimeoutMilliseconds) | Should -BeTrue
            $go.Set()
            $outcomes = Complete-Task7ChildJobs -Jobs $jobs -ExpectedCount 2
            @($outcomes | Where-Object { -not $_.Success }).Count | Should -Be 0
            Assert-Task7ChildCleanup -Outcomes $outcomes
            @($outcomes | ForEach-Object Token) | Should -Be @(
                'task7-synthetic-fixed-bearer-token',
                'task7-synthetic-fixed-bearer-token'
            )
            @($outcomes | Where-Object { -not $_.ForceRefused }).Count | Should -Be 0

            $observedSources = @($observed.ToArray())
            $observedSources.Count | Should -Be 2
            foreach ($observedSource in $observedSources) {
                [object]::ReferenceEquals($source, $observedSource) | Should -BeTrue
            }
            $actualResults = @($results.ToArray())
            $actualResults.Count | Should -Be 2
            [object]::ReferenceEquals($actualResults[0], $actualResults[1]) | Should -BeTrue
        }
        finally {
            $go.Set()
            $null = @($jobs | Wait-Job -Timeout 10)
            foreach ($job in $jobs) {
                Remove-Job $job -Force -ErrorAction SilentlyContinue
            }
            [AppDomain]::CurrentDomain.SetData($holderKey, $null)
            $holder = $null
            $context = $null
            $source = $null
            $observed = $null
            $results = $null
            if (Test-Path -LiteralPath $storePath -PathType Leaf) {
                Remove-Item -LiteralPath $storePath -Force
            }
            $ready.Dispose()
            $go.Dispose()
        }
    }

    It 'keeps distinct controlled tenant sources isolated when providers release together' {
        $entered = [Threading.CountdownEvent]::new(2)
        $release = [Threading.ManualResetEventSlim]::new($false)
        $ready = [Threading.CountdownEvent]::new(2)
        $go = [Threading.ManualResetEventSlim]::new($false)
        $sourceA = [GraphKit.Tests.Task7ControlledTokenSource]::new(
            'task7-tenant-a-token', 'task7-tenant-a-fingerprint', 'task7-tenant-a-proof',
            'task7-generation-a', $entered, $release, $false)
        $sourceB = [GraphKit.Tests.Task7ControlledTokenSource]::new(
            'task7-tenant-b-token', 'task7-tenant-b-fingerprint', 'task7-tenant-b-proof',
            'task7-generation-b', $entered, $release, $false)
        $keySuffix = [guid]::NewGuid().ToString('N')
        $contexts = [object[]] @(
            (New-Task7ControlledContext -Source $sourceA `
                -AcquisitionKey ('task7-key-a-' + $keySuffix) `
                -TenantId ([guid] '00000000-0000-0000-0000-000000000073')),
            (New-Task7ControlledContext -Source $sourceB `
                -AcquisitionKey ('task7-key-b-' + $keySuffix) `
                -TenantId ([guid] '00000000-0000-0000-0000-000000000074'))
        )
        $handler = [GraphKit.Tests.Task7OfflineHandler]::new()
        $client = [Net.Http.HttpClient]::new($handler, $false)
        $observed = [Collections.Concurrent.ConcurrentQueue[object]]::new()
        $results = [Collections.Concurrent.ConcurrentQueue[object]]::new()
        $holderKey = 'GraphKit.Task7.Distinct.' + [guid]::NewGuid().ToString('N')
        $holder = [pscustomobject] @{
            Contexts = $contexts
            Sources = [object[]] @($sourceA, $sourceB)
            Client = $client
            Ready = $ready
            Go = $go
            ObservedSources = $observed
            Results = $results
        }
        $jobs = @()
        [AppDomain]::CurrentDomain.SetData($holderKey, $holder)
        try {
            $jobs = @(
                Start-ThreadJob -ScriptBlock $script:ControlledSenderChild `
                    -ArgumentList $script:BuiltManifest, $holderKey, 0, $false
                Start-ThreadJob -ScriptBlock $script:ControlledSenderChild `
                    -ArgumentList $script:BuiltManifest, $holderKey, 1, $false
            )
            $ready.Wait($script:Task7ThreadJobReadyTimeoutMilliseconds) | Should -BeTrue
            $go.Set()
            $entered.Wait(5000) | Should -BeTrue
            $release.Set()
            $outcomes = Complete-Task7ChildJobs -Jobs $jobs -ExpectedCount 2

            @($outcomes | Where-Object { -not $_.Success }).Count | Should -Be 0
            Assert-Task7ChildCleanup -Outcomes $outcomes
            $outcomeA = @($outcomes | Where-Object ContextIndex -EQ 0)
            $outcomeB = @($outcomes | Where-Object ContextIndex -EQ 1)
            $outcomeA.Count | Should -Be 1
            $outcomeB.Count | Should -Be 1
            @(
                $outcomeA[0].Token,
                $outcomeA[0].Fingerprint,
                $outcomeA[0].Proof,
                $outcomeA[0].Generation
            ) | Should -Be @(
                'task7-tenant-a-token',
                'task7-tenant-a-fingerprint',
                'task7-tenant-a-proof',
                'task7-generation-a'
            )
            @(
                $outcomeB[0].Token,
                $outcomeB[0].Fingerprint,
                $outcomeB[0].Proof,
                $outcomeB[0].Generation
            ) | Should -Be @(
                'task7-tenant-b-token',
                'task7-tenant-b-fingerprint',
                'task7-tenant-b-proof',
                'task7-generation-b'
            )
            $sourceA.AcquireCount | Should -Be 1
            $sourceB.AcquireCount | Should -Be 1
            $sourceA.SemanticAdoptionCount | Should -Be 0
            $sourceB.SemanticAdoptionCount | Should -Be 0
            [object]::ReferenceEquals($sourceA.CurrentResult, $sourceB.CurrentResult) |
                Should -BeFalse
            @($handler.RequestEvidence.ToArray() | Sort-Object) | Should -Be @(
                '/v1.0/task7-offline/0|task7-tenant-a-token',
                '/v1.0/task7-offline/1|task7-tenant-b-token'
            )
            $handler.SendCount | Should -Be 2
            Get-Task7OuterFlightRegistryCount | Should -Be 0

            $observedSources = @($observed.ToArray())
            $observedSources.Count | Should -Be 2
            @($observedSources | Where-Object {
                [object]::ReferenceEquals($_, $sourceA)
            }).Count | Should -Be 1
            @($observedSources | Where-Object {
                [object]::ReferenceEquals($_, $sourceB)
            }).Count | Should -Be 1
            $actualResults = @($results.ToArray())
            $actualResults.Count | Should -Be 2
            @($actualResults | Where-Object {
                [object]::ReferenceEquals($_, $sourceA.ResultForForce($false))
            }).Count | Should -Be 1
            @($actualResults | Where-Object {
                [object]::ReferenceEquals($_, $sourceB.ResultForForce($false))
            }).Count | Should -Be 1
        }
        finally {
            $release.Set()
            $go.Set()
            Remove-Task7ChildJobs -Jobs $jobs
            [AppDomain]::CurrentDomain.SetData($holderKey, $null)
            $holder = $null
            $contexts = $null
            $observed = $null
            $results = $null
            $sourceA.Dispose()
            $sourceB.Dispose()
            $client.Dispose()
            $handler.Dispose()
            $entered.Dispose()
            $release.Dispose()
            $ready.Dispose()
            $go.Dispose()
        }
    }

    It 'collapses two controlled sources on one outer key with one exact follower adoption' {
        $entered = [Threading.CountdownEvent]::new(1)
        $release = [Threading.ManualResetEventSlim]::new($false)
        $ready = [Threading.CountdownEvent]::new(2)
        $go = [Threading.ManualResetEventSlim]::new($false)
        $sourceA = [GraphKit.Tests.Task7ControlledTokenSource]::new(
            'task7-shared-token', 'task7-shared-fingerprint', 'task7-shared-proof',
            'task7-shared-generation', $entered, $release, $false)
        $sourceB = [GraphKit.Tests.Task7ControlledTokenSource]::new(
            'task7-shared-token', 'task7-shared-fingerprint', 'task7-shared-proof',
            'task7-shared-generation', $entered, $release, $false)
        $sharedKey = 'task7-shared-key-' + [guid]::NewGuid().ToString('N')
        $contexts = [object[]] @(
            (New-Task7ControlledContext -Source $sourceA -AcquisitionKey $sharedKey `
                -TenantId ([guid] '00000000-0000-0000-0000-000000000075')),
            (New-Task7ControlledContext -Source $sourceB -AcquisitionKey $sharedKey `
                -TenantId ([guid] '00000000-0000-0000-0000-000000000075'))
        )
        $handler = [GraphKit.Tests.Task7OfflineHandler]::new()
        $client = [Net.Http.HttpClient]::new($handler, $false)
        $observed = [Collections.Concurrent.ConcurrentQueue[object]]::new()
        $results = [Collections.Concurrent.ConcurrentQueue[object]]::new()
        $holderKey = 'GraphKit.Task7.Shared.' + [guid]::NewGuid().ToString('N')
        $holder = [pscustomobject] @{
            Contexts = $contexts
            Sources = [object[]] @($sourceA, $sourceB)
            Client = $client
            Ready = $ready
            Go = $go
            ObservedSources = $observed
            Results = $results
        }
        $jobs = @()
        [AppDomain]::CurrentDomain.SetData($holderKey, $holder)
        try {
            $jobs = @(
                Start-ThreadJob -ScriptBlock $script:ControlledSenderChild `
                    -ArgumentList $script:BuiltManifest, $holderKey, 0, $false
                Start-ThreadJob -ScriptBlock $script:ControlledSenderChild `
                    -ArgumentList $script:BuiltManifest, $holderKey, 1, $false
            )
            $ready.Wait($script:Task7ThreadJobReadyTimeoutMilliseconds) | Should -BeTrue
            $go.Set()
            $entered.Wait(5000) | Should -BeTrue
            $followerObserved = [Threading.SpinWait]::SpinUntil(
                [Func[bool]] {
                    (Get-Task7OuterFlightSnapshot `
                        -AcquisitionKey $sharedKey -ForceRefresh $false).WaiterCount -eq 1
                },
                5000
            )
            $release.Set()
            $outcomes = Complete-Task7ChildJobs -Jobs $jobs -ExpectedCount 2

            $followerObserved | Should -BeTrue -Because `
                'one caller must be inside the exact outer follower wait before release'
            @($outcomes | Where-Object { -not $_.Success }).Count | Should -Be 0
            Assert-Task7ChildCleanup -Outcomes $outcomes
            $sources = @($sourceA, $sourceB)
            $leaders = @($sources | Where-Object AcquireCount -EQ 1)
            $followers = @($sources | Where-Object AcquireCount -EQ 0)
            $leaders.Count | Should -Be 1
            $followers.Count | Should -Be 1
            $leaders[0].SemanticAdoptionCount | Should -Be 0
            $followers[0].SemanticAdoptionCount | Should -Be 1
            [object]::ReferenceEquals($sourceA.CurrentResult, $sourceB.CurrentResult) |
                Should -BeTrue
            $actualResults = @($results.ToArray())
            $actualResults.Count | Should -Be 2
            [object]::ReferenceEquals($actualResults[0], $actualResults[1]) | Should -BeTrue
            @($outcomes | ForEach-Object Token) | Should -Be @(
                'task7-shared-token', 'task7-shared-token'
            )
            $observedSources = @($observed.ToArray())
            $observedSources.Count | Should -Be 2
            @($observedSources | Where-Object {
                [object]::ReferenceEquals($_, $sourceA)
            }).Count | Should -Be 1
            @($observedSources | Where-Object {
                [object]::ReferenceEquals($_, $sourceB)
            }).Count | Should -Be 1
            $handler.SendCount | Should -Be 2
            Get-Task7OuterFlightRegistryCount | Should -Be 0
        }
        finally {
            $release.Set()
            $go.Set()
            Remove-Task7ChildJobs -Jobs $jobs
            [AppDomain]::CurrentDomain.SetData($holderKey, $null)
            $holder = $null
            $contexts = $null
            $observed = $null
            $results = $null
            $sourceA.Dispose()
            $sourceB.Dispose()
            $client.Dispose()
            $handler.Dispose()
            $entered.Dispose()
            $release.Dispose()
            $ready.Dispose()
            $go.Dispose()
        }
    }

    It 'keeps ordinary and forced outer flights simultaneously partitioned' {
        $entered = [Threading.CountdownEvent]::new(2)
        $release = [Threading.ManualResetEventSlim]::new($false)
        $ready = [Threading.CountdownEvent]::new(2)
        $go = [Threading.ManualResetEventSlim]::new($false)
        $unrelatedEntered = [Threading.CountdownEvent]::new(1)
        $unrelatedRelease = [Threading.ManualResetEventSlim]::new($false)
        $source = [GraphKit.Tests.Task7ControlledTokenSource]::new(
            'task7-partition-token', 'task7-partition-fingerprint', 'task7-partition-proof',
            'task7-partition-generation', $entered, $release, $true)
        $unrelated = [GraphKit.Tests.Task7ControlledTokenSource]::new(
            'task7-unrelated-token', 'task7-unrelated-fingerprint', 'task7-unrelated-proof',
            'task7-unrelated-generation', $unrelatedEntered, $unrelatedRelease, $false)
        $partitionKey = 'task7-partition-key-' + [guid]::NewGuid().ToString('N')
        $context = New-Task7ControlledContext -Source $source -AcquisitionKey $partitionKey `
            -TenantId ([guid] '00000000-0000-0000-0000-000000000076')
        $handler = [GraphKit.Tests.Task7OfflineHandler]::new()
        $client = [Net.Http.HttpClient]::new($handler, $false)
        $observed = [Collections.Concurrent.ConcurrentQueue[object]]::new()
        $results = [Collections.Concurrent.ConcurrentQueue[object]]::new()
        $holderKey = 'GraphKit.Task7.Partition.' + [guid]::NewGuid().ToString('N')
        $holder = [pscustomobject] @{
            Contexts = [object[]] @($context, $context)
            Sources = [object[]] @($source, $source)
            Client = $client
            Ready = $ready
            Go = $go
            ObservedSources = $observed
            Results = $results
        }
        $jobs = @()
        [AppDomain]::CurrentDomain.SetData($holderKey, $holder)
        try {
            $jobs = @(
                Start-ThreadJob -ScriptBlock $script:ControlledSenderChild `
                    -ArgumentList $script:BuiltManifest, $holderKey, 0, $false
                Start-ThreadJob -ScriptBlock $script:ControlledSenderChild `
                    -ArgumentList $script:BuiltManifest, $holderKey, 1, $true
            )
            $ready.Wait($script:Task7ThreadJobReadyTimeoutMilliseconds) | Should -BeTrue
            $go.Set()
            $entered.Wait(5000) | Should -BeTrue
            $ordinarySnapshot = Get-Task7OuterFlightSnapshot `
                -AcquisitionKey $partitionKey -ForceRefresh $false
            $forcedSnapshot = Get-Task7OuterFlightSnapshot `
                -AcquisitionKey $partitionKey -ForceRefresh $true
            $release.Set()
            $outcomes = Complete-Task7ChildJobs -Jobs $jobs -ExpectedCount 2

            $ordinarySnapshot.Exists | Should -BeTrue
            $forcedSnapshot.Exists | Should -BeTrue
            $ordinarySnapshot.Key | Should -Not -BeExactly $forcedSnapshot.Key
            $ordinarySnapshot.RegistryCount | Should -Be 2
            $forcedSnapshot.RegistryCount | Should -Be 2
            $source.AcquireCount | Should -Be 2
            @($source.ForceFlags | Sort-Object) | Should -Be @($false, $true)
            $ordinaryOutcome = @($outcomes | Where-Object { -not $_.ForceRefresh })
            $forcedOutcome = @($outcomes | Where-Object ForceRefresh)
            $ordinaryOutcome.Count | Should -Be 1
            $forcedOutcome.Count | Should -Be 1
            @(
                $ordinaryOutcome[0].Token,
                $ordinaryOutcome[0].Fingerprint,
                $ordinaryOutcome[0].Proof,
                $ordinaryOutcome[0].Generation
            ) | Should -Be @(
                'task7-partition-token-ordinary',
                'task7-partition-fingerprint-ordinary',
                'task7-partition-proof',
                'task7-partition-generation'
            )
            @(
                $forcedOutcome[0].Token,
                $forcedOutcome[0].Fingerprint,
                $forcedOutcome[0].Proof,
                $forcedOutcome[0].Generation
            ) | Should -Be @(
                'task7-partition-token-forced',
                'task7-partition-fingerprint-forced',
                'task7-partition-proof',
                'task7-partition-generation'
            )
            $actualResults = @($results.ToArray())
            $actualResults.Count | Should -Be 2
            [object]::ReferenceEquals($actualResults[0], $actualResults[1]) | Should -BeFalse
            @($actualResults | Where-Object {
                [object]::ReferenceEquals($_, $source.ResultForForce($false))
            }).Count | Should -Be 1
            @($actualResults | Where-Object {
                [object]::ReferenceEquals($_, $source.ResultForForce($true))
            }).Count | Should -Be 1
            @($handler.RequestEvidence.ToArray() | Sort-Object) | Should -Be @(
                '/v1.0/task7-offline/0|task7-partition-token-ordinary',
                '/v1.0/task7-offline/1|task7-partition-token-forced'
            )
            $observedSources = @($observed.ToArray())
            $observedSources.Count | Should -Be 2
            foreach ($observedSource in $observedSources) {
                [object]::ReferenceEquals($observedSource, $source) | Should -BeTrue
            }
            $handler.SendCount | Should -Be 2
            $unrelated.AcquireCount | Should -Be 0
            $unrelated.SemanticAdoptionCount | Should -Be 0
            $unrelated.CurrentResult | Should -BeNullOrEmpty
            Get-Task7OuterFlightRegistryCount | Should -Be 0
            Assert-Task7ChildCleanup -Outcomes $outcomes
        }
        finally {
            $release.Set()
            $unrelatedRelease.Set()
            $go.Set()
            Remove-Task7ChildJobs -Jobs $jobs
            [AppDomain]::CurrentDomain.SetData($holderKey, $null)
            $holder = $null
            $context = $null
            $observed = $null
            $results = $null
            $source.Dispose()
            $unrelated.Dispose()
            $client.Dispose()
            $handler.Dispose()
            $entered.Dispose()
            $release.Dispose()
            $ready.Dispose()
            $go.Dispose()
            $unrelatedEntered.Dispose()
            $unrelatedRelease.Dispose()
        }
    }

    It 'contains a legacy source before it can enter or wait on an outer flight' {
        $storePath = Join-Path $TestDrive 'task7-legacy-profiles.json'
        $store = [ordered] @{
            SchemaVersion = 1
            Profiles = @(
                [ordered] @{
                    ProfileId = 'task7-legacy-bearer'
                    Name = 'Task 7 legacy synthetic bearer'
                    Kind = 'lab'
                    TenantId = '00000000-0000-0000-0000-000000000077'
                    ClientId = $null
                    AuthMethod = 'BearerToken'
                    Environment = 'Global'
                    Credential = [ordered] @{
                        Token = 'task7-legacy-synthetic-token'
                        Version = 'task7-legacy-v1'
                    }
                }
            )
        }
        [IO.File]::WriteAllText(
            $storePath,
            (ConvertTo-Json $store -Depth 20),
            [Text.UTF8Encoding]::new($false)
        )
        $factoryCalls = [Collections.Concurrent.ConcurrentQueue[bool]]::new()
        $legacyFactory = {
            $factoryCalls.Enqueue($true)
            throw 'Task 7 bearer factory must remain unused.'
        }.GetNewClosure()
        $context = Get-GraphContext -ProfileId task7-legacy-bearer `
            -StorePath $storePath -MsalFactory $legacyFactory
        $source = $context.TokenSource
        $source.GetType().BaseType.Name | Should -BeExactly 'GraphTokenSourceBase'
        $seed = $null
        $handler = [GraphKit.Tests.Task7OfflineHandler]::new()
        $client = [Net.Http.HttpClient]::new($handler, $false)
        $ready = [Threading.CountdownEvent]::new(1)
        $go = [Threading.ManualResetEventSlim]::new($false)
        $observed = [Collections.Concurrent.ConcurrentQueue[object]]::new()
        $holderKey = 'GraphKit.Task7.Legacy.' + [guid]::NewGuid().ToString('N')
        $holder = [pscustomobject] @{
            Context = $context
            Source = $source
            Client = $client
            Ready = $ready
            Go = $go
            ObservedSources = $observed
        }
        $jobs = @()
        [AppDomain]::CurrentDomain.SetData($holderKey, $holder)
        try {
            $seed = InModuleScope GraphKit -Parameters @{
                AcquisitionKey = [string] $context.AcquisitionCacheKey
            } {
                param($AcquisitionKey)
                $key = Get-GraphTokenFlightKey `
                    -AcquisitionKey $AcquisitionKey -ForceRefresh:$false
                $flight = [GraphTokenFlight]::new()
                if (-not [GraphTokenFlightRegistry]::Flights.TryAdd($key, $flight)) {
                    throw 'Task 7 could not seed the exact incomplete compatibility flight.'
                }
                [pscustomobject] @{ Key = $key; Flight = [object] $flight }
            }
            $jobs = @(
                Start-ThreadJob -ScriptBlock $script:LegacyContainmentChild `
                    -ArgumentList $script:BuiltManifest, $holderKey
            )
            $ready.Wait($script:Task7ThreadJobReadyTimeoutMilliseconds) | Should -BeTrue
            $go.Set()
            $outcomes = Complete-Task7ChildJobs -Jobs $jobs -ExpectedCount 1
            $outcomes[0].Success | Should -BeTrue
            $outcomes[0].Rejected | Should -BeTrue
            Assert-Task7ChildCleanup -Outcomes $outcomes
            $handler.SendCount | Should -Be 0
            $factoryCalls.Count | Should -Be 0
            $observedSources = @($observed.ToArray())
            $observedSources.Count | Should -Be 1
            [object]::ReferenceEquals($source, $observedSources[0]) | Should -BeTrue
            $seedState = InModuleScope GraphKit -Parameters @{
                Key = $seed.Key
                ExpectedFlight = $seed.Flight
            } {
                param($Key, $ExpectedFlight)
                $flight = [GraphTokenFlight] $null
                $exists = [GraphTokenFlightRegistry]::Flights.TryGetValue($Key, [ref] $flight)
                $waiterProperty = if ($exists) {
                    $flight.PSObject.Properties['WaiterCount']
                }
                else {
                    $null
                }
                [pscustomobject] @{
                    Exists = $exists
                    SameFlight = $exists -and [object]::ReferenceEquals($ExpectedFlight, $flight)
                    IsCompleted = $exists -and $flight.Completion.Task.IsCompleted
                    HasWaiterCount = $null -ne $waiterProperty
                    WaiterCount = if ($null -ne $waiterProperty) {
                        [int] (Get-GraphTokenFlightWaiterCount -Flight $flight)
                    }
                    else {
                        -1
                    }
                }
            }
            $seedState.Exists | Should -BeTrue
            $seedState.SameFlight | Should -BeTrue
            $seedState.IsCompleted | Should -BeFalse
            $seedState.HasWaiterCount | Should -BeTrue
            $seedState.WaiterCount | Should -Be 0
        }
        finally {
            $go.Set()
            Remove-Task7ChildJobs -Jobs $jobs
            [AppDomain]::CurrentDomain.SetData($holderKey, $null)
            if ($null -ne $seed) {
                InModuleScope GraphKit -Parameters @{
                    Key = $seed.Key
                    Flight = $seed.Flight
                } {
                    param($Key, $Flight)
                    if (Remove-GraphTokenFlightIfCurrent -Key $Key -Flight $Flight) {
                        $null = $Flight.Completion.TrySetResult($null)
                    }
                }
            }
            $holder = $null
            $context = $null
            $source = $null
            $factoryCalls = $null
            $legacyFactory = $null
            $observed = $null
            $client.Dispose()
            $handler.Dispose()
            $ready.Dispose()
            $go.Dispose()
            if (Test-Path -LiteralPath $storePath -PathType Leaf) {
                Remove-Item -LiteralPath $storePath -Force
            }
        }
    }

    It 'removes the owning module, rejects exact-source reuse, and collects its provider context' {
        $storePath = Join-Path $TestDrive (
            'task7-owning-profiles-' + [guid]::NewGuid().ToString('N') + '.json')
        $job = Start-ThreadJob -ScriptBlock {
            param($Manifest, $StorePath)

            function Invoke-Task7OwningLifecycleProbe {
                param($ManifestPath, $ProfileStorePath)

                $module = $null
                $context = $null
                $source = $null
                $capture = $null
                $state = $null
                $authHost = $null
                $weak = $null
                $moduleRemoved = $false
                try {
                    $store = [ordered] @{
                        SchemaVersion = 1
                        Profiles = @(
                            [ordered] @{
                                ProfileId = 'task7-owning-fixed-bearer'
                                Name = 'Task 7 owning synthetic bearer'
                                Kind = 'lab'
                                TenantId = '00000000-0000-0000-0000-000000000078'
                                ClientId = $null
                                AuthMethod = 'BearerToken'
                                Environment = 'Global'
                                Credential = [ordered] @{
                                    Token = 'task7-owning-synthetic-fixed-bearer-token'
                                    Version = 'task7-owning-v1'
                                }
                            }
                        )
                    }
                    [IO.File]::WriteAllText(
                        $ProfileStorePath,
                        (ConvertTo-Json $store -Depth 20),
                        [Text.UTF8Encoding]::new($false)
                    )
                    $store = $null

                    $module = Import-Module $ManifestPath -Force -PassThru -ErrorAction Stop
                    $context = Get-GraphContext -ProfileId task7-owning-fixed-bearer `
                        -StorePath $ProfileStorePath
                    $source = $context.TokenSource
                    $capture = & $module {
                        param($ExpectedSource)
                        $owned = @($script:GraphKitModuleLifecycle.OwnedResources)
                        [pscustomobject] @{
                            State = $script:GraphKitModuleLifecycle
                            Host = $script:GraphKitAuthHost
                            Weak = $script:GraphKitAuthHost.LoadContextWeakReference
                            ExactRegistration =
                                $owned.Count -eq 2 -and
                                [object]::ReferenceEquals($owned[0], $script:GraphKitAuthHost) -and
                                [object]::ReferenceEquals($owned[1], $ExpectedSource)
                            ResourceTypes = @(
                                $owned | ForEach-Object { $_.GetType().FullName }
                            )
                        }
                    } $source
                    $state = $capture.State
                    $authHost = $capture.Host
                    $weak = $capture.Weak
                    $exactRegistration = [bool] $capture.ExactRegistration
                    $resourceTypes = [string[]] @($capture.ResourceTypes)
                    $capture = $null

                    Remove-Module -ModuleInfo $module -Force -ErrorAction Stop
                    $moduleRemoved = $true
                    $cleanupObserved = $state.WaitForCleanup(5000)
                    $cleanupComplete = [bool] $state.CleanupComplete
                    $activeOperations = [int] $state.ActiveOperations
                    $ownedResourceCount = [int] $state.OwnedResources.Count
                    $failureCount = @($state.GetFailures()).Count

                    $rejected = $false
                    $rejectionType = $null
                    try {
                        $null = $source.Acquire(
                            $false,
                            [Threading.CancellationToken]::None)
                    }
                    catch [ObjectDisposedException] {
                        $rejected = $true
                        $rejectionType = $_.Exception.GetType().FullName
                    }

                    $source = $null
                    $context = $null
                    $module = $null
                    $authHost = $null
                    $state = $null

                    return [pscustomobject] @{
                        WeakReference = $weak
                        ExactRegistration = $exactRegistration
                        ResourceTypes = $resourceTypes
                        ModuleRemoved = $moduleRemoved
                        CleanupObserved = $cleanupObserved
                        CleanupComplete = $cleanupComplete
                        ActiveOperations = $activeOperations
                        OwnedResourceCount = $ownedResourceCount
                        FailureCount = $failureCount
                        SourceRejected = $rejected
                        RejectionType = $rejectionType
                    }
                }
                finally {
                    if ($null -ne $module -and -not $moduleRemoved) {
                        Remove-Module -ModuleInfo $module -Force -ErrorAction SilentlyContinue
                    }
                    $capture = $null
                    $source = $null
                    $context = $null
                    $module = $null
                    $authHost = $null
                    $state = $null
                    $weak = $null
                    if (Test-Path -LiteralPath $ProfileStorePath -PathType Leaf) {
                        Remove-Item -LiteralPath $ProfileStorePath -Force
                    }
                }
            }

            $probe = Invoke-Task7OwningLifecycleProbe `
                -ManifestPath $Manifest -ProfileStorePath $StorePath
            $weak = $probe.WeakReference
            for ($attempt = 0; $attempt -lt 30 -and $weak.IsAlive; $attempt++) {
                [GC]::Collect()
                [GC]::WaitForPendingFinalizers()
                [GC]::Collect()
            }
            [pscustomobject] @{
                ExactRegistration = $probe.ExactRegistration
                ResourceTypes = $probe.ResourceTypes
                ModuleRemoved = $probe.ModuleRemoved
                CleanupObserved = $probe.CleanupObserved
                CleanupComplete = $probe.CleanupComplete
                ActiveOperations = $probe.ActiveOperations
                OwnedResourceCount = $probe.OwnedResourceCount
                FailureCount = $probe.FailureCount
                SourceRejected = $probe.SourceRejected
                RejectionType = $probe.RejectionType
                ProviderContextCollected = -not $weak.IsAlive
            }
            $weak = $null
            $probe = $null
        } -ArgumentList $script:BuiltManifest, $storePath

        try {
            $completed = @($job | Wait-Job -Timeout 10)
            $completed.Count | Should -Be 1
            $job.State | Should -BeExactly 'Completed'
            $result = @($job | Receive-Job -ErrorAction Stop)
            $result.Count | Should -Be 1
            $result[0].ExactRegistration | Should -BeTrue
            @($result[0].ResourceTypes) | Should -Be @(
                'GraphKit.Auth.GraphAuthHost',
                'GraphKit.Auth.GraphTokenSourceProxy'
            )
            $result[0].ModuleRemoved | Should -BeTrue
            $result[0].CleanupObserved | Should -BeTrue
            $result[0].CleanupComplete | Should -BeTrue
            $result[0].ActiveOperations | Should -Be 0
            $result[0].OwnedResourceCount | Should -Be 0
            $result[0].FailureCount | Should -Be 0
            $result[0].SourceRejected | Should -BeTrue
            $result[0].RejectionType | Should -BeExactly 'System.ObjectDisposedException'
            $result[0].ProviderContextCollected | Should -BeTrue
        }
        finally {
            if ($null -ne $job) {
                $null = @($job | Wait-Job -Timeout 10)
                Remove-Job $job -Force -ErrorAction SilentlyContinue
            }
            $job = $null
            if (Test-Path -LiteralPath $storePath -PathType Leaf) {
                Remove-Item -LiteralPath $storePath -Force
            }
        }
    }
}
