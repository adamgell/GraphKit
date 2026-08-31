BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $script:contractsPath = Join-Path $script:repoRoot 'src/GraphKit.Auth/GraphKit.Auth.Contracts/bin/Release/net8.0/GraphKit.Auth.Contracts.dll'

    function New-GraphKitAuthContractsFixtureAssembly {
        param(
            [Parameter(Mandatory)] [string] $Root,
            [Parameter(Mandatory)] [string] $Marker
        )

        $null = New-Item -ItemType Directory -Path $Root -Force
        $sourcePath = Join-Path $Root 'Contracts.cs'
        $projectPath = Join-Path $Root 'GraphKit.Auth.Contracts.csproj'
        $outputPath = Join-Path $Root 'out'
        $assemblyPath = Join-Path $outputPath 'GraphKit.Auth.Contracts.dll'
        Set-Content -LiteralPath $sourcePath -NoNewline -Encoding utf8NoBOM -Value @"
using System.Threading;

namespace GraphKit.Auth
{
    public sealed class GraphTokenResult { }

    public interface IGraphTokenSource
    {
        GraphTokenResult Acquire(bool forceRefresh, CancellationToken cancellation);
    }

    public static class GraphAuthHost
    {
        public const string ContractMarker = "$Marker";
    }
}
"@
        Set-Content -LiteralPath $projectPath -NoNewline -Encoding utf8NoBOM -Value @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <AssemblyName>GraphKit.Auth.Contracts</AssemblyName>
    <RootNamespace>GraphKit.Auth</RootNamespace>
    <Nullable>enable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <Deterministic>true</Deterministic>
    <DebugType>none</DebugType>
  </PropertyGroup>
</Project>
'@

        $compilerOutput = & dotnet build $projectPath -c Release -o $outputPath --nologo --verbosity quiet 2>&1
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $assemblyPath -PathType Leaf)) {
            throw "The GraphKit.Auth contracts fixture did not compile: $($compilerOutput | Out-String)"
        }
        return $assemblyPath
    }

    function Invoke-GraphKitAuthContractsCandidateProbe {
        param(
            [Parameter(Mandatory)] [string] $CandidatePath,
            [string] $PreloadPath
        )

        $probePath = Join-Path $TestDrive ('Probe-Contracts-' + [guid]::NewGuid().ToString('N') + '.ps1')
        Set-Content -LiteralPath $probePath -NoNewline -Encoding utf8NoBOM -Value @'
param(
    [Parameter(Mandatory)] [string] $CandidatePath,
    [string] $PreloadPath
)
$ErrorActionPreference = 'Stop'
$candidate = (Resolve-Path -LiteralPath $CandidatePath).ProviderPath

if (-not [string]::IsNullOrEmpty($PreloadPath)) {
    $null = [System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath(
        (Resolve-Path -LiteralPath $PreloadPath).ProviderPath
    )
}

$stream = [System.IO.File]::OpenRead($candidate)
try {
    $peReader = [System.Reflection.PortableExecutable.PEReader]::new($stream)
    try {
        if (-not $peReader.HasMetadata) { throw "The contracts candidate '$candidate' has no managed metadata." }
        $metadata = [System.Reflection.Metadata.PEReaderExtensions]::GetMetadataReader($peReader)
        $assemblyDefinition = $metadata.GetAssemblyDefinition()
        $candidateName = $metadata.GetString($assemblyDefinition.Name)
        $moduleDefinition = $metadata.GetModuleDefinition()
        $candidateMvid = $metadata.GetGuid($moduleDefinition.Mvid)
    }
    finally {
        $peReader.Dispose()
    }
}
finally {
    $stream.Dispose()
}

if ($candidateName -cne 'GraphKit.Auth.Contracts') {
    throw "The contracts candidate has assembly name '$candidateName', not 'GraphKit.Auth.Contracts'."
}

$alreadyLoaded = @(
    [System.Runtime.Loader.AssemblyLoadContext]::Default.Assemblies |
        Where-Object { $_.GetName().Name -ceq $candidateName }
)
if ($alreadyLoaded.Count -ne 0) {
    $locations = @($alreadyLoaded | ForEach-Object { if ($_.Location) { $_.Location } else { '<no location>' } }) -join ', '
    throw "Default ALC already contains '$candidateName' from $locations; refusing candidate '$candidate'."
}

$candidateSha256 = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
$assembly = [System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath($candidate)
$loadedLocation = [System.IO.Path]::GetFullPath($assembly.Location)
$loadedSha256 = (Get-FileHash -LiteralPath $loadedLocation -Algorithm SHA256).Hash.ToLowerInvariant()
$loadedMvid = $assembly.ManifestModule.ModuleVersionId
$matchingLoaded = @(
    [System.Runtime.Loader.AssemblyLoadContext]::Default.Assemblies |
        Where-Object { $_.GetName().Name -ceq $candidateName }
)
if ($matchingLoaded.Count -ne 1 -or -not [object]::ReferenceEquals($assembly, $matchingLoaded[0])) {
    throw "Default ALC did not retain exactly the candidate '$candidate'."
}
if ($loadedLocation -cne $candidate) {
    throw "Default ALC loaded '$loadedLocation' instead of exact candidate '$candidate'."
}
if ($loadedSha256 -cne $candidateSha256) {
    throw "Loaded contracts bytes do not match candidate '$candidate'."
}
if ($loadedMvid -ne $candidateMvid) {
    throw "Loaded contracts MVID '$loadedMvid' does not match candidate MVID '$candidateMvid'."
}

$seen = [System.Collections.Generic.HashSet[System.Type]]::new()
function Add-SignatureType {
    param([System.Type] $Type)

    if ($null -eq $Type -or -not $seen.Add($Type)) { return }
    if ($Type.HasElementType) { Add-SignatureType -Type $Type.GetElementType() }
    foreach ($argument in $Type.GetGenericArguments()) { Add-SignatureType -Type $argument }
    if ($Type.IsGenericParameter) {
        foreach ($constraint in $Type.GetGenericParameterConstraints()) {
            Add-SignatureType -Type $constraint
        }
    }
}

$bindingFlags = [System.Reflection.BindingFlags]'Public,Instance,Static'
foreach ($type in $assembly.GetExportedTypes()) {
    Add-SignatureType -Type $type
    Add-SignatureType -Type $type.BaseType
    foreach ($interface in $type.GetInterfaces()) { Add-SignatureType -Type $interface }
    foreach ($member in $type.GetMembers($bindingFlags)) {
        Add-SignatureType -Type $member.DeclaringType
        if ($member -is [System.Reflection.MethodInfo]) {
            Add-SignatureType -Type $member.ReturnType
            foreach ($argument in $member.GetGenericArguments()) { Add-SignatureType -Type $argument }
            foreach ($parameter in $member.GetParameters()) { Add-SignatureType -Type $parameter.ParameterType }
        }
        elseif ($member -is [System.Reflection.ConstructorInfo]) {
            foreach ($parameter in $member.GetParameters()) { Add-SignatureType -Type $parameter.ParameterType }
        }
        elseif ($member -is [System.Reflection.PropertyInfo]) {
            Add-SignatureType -Type $member.PropertyType
            foreach ($parameter in $member.GetIndexParameters()) { Add-SignatureType -Type $parameter.ParameterType }
        }
        elseif ($member -is [System.Reflection.FieldInfo]) {
            Add-SignatureType -Type $member.FieldType
        }
        elseif ($member -is [System.Reflection.EventInfo]) {
            Add-SignatureType -Type $member.EventHandlerType
        }
    }
}

$leaks = @(
    $seen | Where-Object {
        [string] $_.FullName -like '*Microsoft.Identity.Client*' -or
        [string] $_.Assembly.FullName -like '*Microsoft.Identity.Client*'
    } | ForEach-Object { "$($_.Assembly.FullName)|$($_.FullName)" }
)
$hostType = $assembly.GetType('GraphKit.Auth.GraphAuthHost', $true, $false)
$sourceType = $assembly.GetType('GraphKit.Auth.IGraphTokenSource', $true, $false)
[pscustomobject]@{
    CandidatePath     = $candidate
    LoadedLocation    = $loadedLocation
    CandidateSha256   = $candidateSha256
    LoadedSha256      = $loadedSha256
    CandidateMvid     = $candidateMvid.ToString('D')
    LoadedMvid        = $loadedMvid.ToString('D')
    ContractMarker    = $hostType.GetField('ContractMarker').GetRawConstantValue()
    AcquireReturnType = $sourceType.GetMethod('Acquire').ReturnType.FullName
    Leaks             = [object[]] $leaks
} | ConvertTo-Json -Compress -Depth 4
'@

        $arguments = @('-NoLogo', '-NoProfile', '-File', $probePath, '-CandidatePath', $CandidatePath)
        if (-not [string]::IsNullOrEmpty($PreloadPath)) {
            $arguments += @('-PreloadPath', $PreloadPath)
        }
        $raw = & pwsh @arguments 2>&1
        $exitCode = $LASTEXITCODE
        $json = @($raw | Where-Object { $_ -is [string] -and $_.TrimStart().StartsWith('{') }) | Select-Object -Last 1
        [pscustomobject] @{
            ExitCode = $exitCode
            Data     = if ($json) { $json | ConvertFrom-Json } else { $null }
            Output   = ($raw | Out-String).Trim()
        }
    }

    function New-GraphKitAuthProviderFixtureAssembly {
        param(
            [Parameter(Mandatory)] [string] $Root,
            [string] $AssemblyName = 'GraphKit.Auth',
            [string] $AssemblyVersion = '1.0.0.0',
            [string] $AdditionalReferencePath,
            [string] $PublicSurfaceDeclaration
        )

        $null = New-Item -ItemType Directory -Path $Root -Force
        $sourcePath = Join-Path $Root 'Provider.cs'
        $projectPath = Join-Path $Root 'Provider.csproj'
        $escapedContractsPath = [System.Security.SecurityElement]::Escape($script:contractsPath)
        Set-Content -LiteralPath $sourcePath -NoNewline -Encoding utf8NoBOM -Value @'
using System;
using System.IO;
using System.Threading;
using GraphKit.Auth;

namespace GraphKit.Auth;

public sealed class GraphTokenSourceFactory : IGraphTokenSourceFactory
{
    public Uri FrameworkUri => new("https://graph.microsoft.com");
    public IGraphTokenSource Create(GraphTokenRequest request) => new FixtureTokenSource(request);
    // TEST_PUBLIC_SURFACE
}

internal sealed class FixtureTokenSource : IGraphTokenSource
{
    private static readonly ManualResetEventSlim BlockedAcquireEntered = new(false);
    private static readonly ManualResetEventSlim BlockedAcquireRelease = new(false);
    private readonly GraphTokenRequest _request;
    private readonly string? _disposeMarker = Environment.GetEnvironmentVariable("GRAPHKIT_AUTH_TEST_DISPOSE_MARKER");
    private int _disposed;

    public FixtureTokenSource(GraphTokenRequest request) => _request = request;

    public bool CanRefresh => true;
    public string AuthMode => _request.AuthMode.ToString();
    public string Audience => _request.Resource.AbsoluteUri;
    public string? ClientId => _request.ClientId?.ToString("D");
    public DateTimeOffset ExpiresOn { get; private set; }
    public string? VerifiedTenantId { get; private set; }
    public string CredentialGeneration => _request.CredentialGeneration;

    public GraphTokenResult Acquire(bool forceRefresh, CancellationToken cancellation)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        cancellation.ThrowIfCancellationRequested();
        if (string.Equals(
                Environment.GetEnvironmentVariable("GRAPHKIT_AUTH_TEST_BLOCK_ACQUIRE"),
                "1",
                StringComparison.Ordinal))
        {
            BlockedAcquireEntered.Set();
            if (!BlockedAcquireRelease.Wait(TimeSpan.FromSeconds(10)))
            {
                throw new TimeoutException("The blocked provider acquisition was not released.");
            }
        }

        if (forceRefresh)
        {
            throw new GraphAuthException("fixture", "Fixture", "provider failure", TimeSpan.FromSeconds(7), "fixture-correlation");
        }

        ExpiresOn = DateTimeOffset.UtcNow.AddMinutes(5);
        return new GraphTokenResult
        {
            AccessToken = "fixture-token",
            ExpiresOnUtc = ExpiresOn,
            ReceivedOnUtc = DateTimeOffset.UtcNow,
            TokenType = "Bearer",
            Scopes = new[] { _request.Resource.AbsoluteUri + "/.default" },
            TokenFingerprint = "fixture-fingerprint",
            CredentialGeneration = _request.CredentialGeneration
        };
    }

    public void AdoptSharedResult(GraphTokenResult result, bool forceRefresh)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        ExpiresOn = result.ExpiresOnUtc;
        VerifiedTenantId = result.VerifiedTenantId;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        if (!string.IsNullOrEmpty(_disposeMarker))
        {
            File.AppendAllText(_disposeMarker, "disposed" + Environment.NewLine);
        }

        if (string.Equals(
                Environment.GetEnvironmentVariable("GRAPHKIT_AUTH_TEST_DISPOSE_FAILURE"),
                "1",
                StringComparison.Ordinal))
        {
            throw new ProviderOwnedDisposeException();
        }
    }

    internal static bool WaitForBlockedAcquire(TimeSpan timeout) =>
        BlockedAcquireEntered.Wait(timeout);

    internal static void ReleaseBlockedAcquire() => BlockedAcquireRelease.Set();
}

internal sealed class ProviderOwnedDisposeException : Exception
{
    internal const string ForbiddenMessage = "isolated-provider-disposal-sensitive-detail";

    internal ProviderOwnedDisposeException()
        : base(ForbiddenMessage, new ProviderOwnedInnerException())
    {
        Data["isolated-provider-data"] = new ProviderOwnedData();
    }
}

internal sealed class ProviderOwnedInnerException : Exception
{
    internal ProviderOwnedInnerException()
        : base("isolated-provider-inner-sensitive-detail")
    {
    }
}

internal sealed class ProviderOwnedData
{
    public override string ToString() => "isolated-provider-data-sensitive-detail";
}
'@
        if (-not [string]::IsNullOrWhiteSpace($PublicSurfaceDeclaration)) {
            $providerSource = Get-Content -LiteralPath $sourcePath -Raw
            Set-Content -LiteralPath $sourcePath -NoNewline -Encoding utf8NoBOM -Value (
                $providerSource.Replace('// TEST_PUBLIC_SURFACE', $PublicSurfaceDeclaration)
            )
        }
        $additionalReference = if ([string]::IsNullOrWhiteSpace($AdditionalReferencePath)) {
            ''
        }
        else {
            $escapedAdditionalReferencePath = [System.Security.SecurityElement]::Escape($AdditionalReferencePath)
            @"
    <Reference Include="AdditionalFixtureReference">
      <HintPath>$escapedAdditionalReferencePath</HintPath>
      <Private>true</Private>
    </Reference>
"@
        }
        Set-Content -LiteralPath $projectPath -NoNewline -Encoding utf8NoBOM -Value @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <AssemblyName>$AssemblyName</AssemblyName>
    <AssemblyVersion>$AssemblyVersion</AssemblyVersion>
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
$additionalReference
  </ItemGroup>
</Project>
"@

        $outputPath = Join-Path $Root 'out'
        $compilerOutput = & dotnet build $projectPath -c Release -o $outputPath --nologo --verbosity quiet 2>&1
        $assemblyPath = Join-Path $outputPath "$AssemblyName.dll"
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $assemblyPath -PathType Leaf)) {
            throw "The GraphKit.Auth provider fixture did not compile: $($compilerOutput | Out-String)"
        }
        return $assemblyPath
    }

    function New-SystemImpostorFixtureAssembly {
        param([Parameter(Mandatory)] [string] $Root)

        $null = New-Item -ItemType Directory -Path $Root -Force
        $sourcePath = Join-Path $Root 'Counterfeit.cs'
        $projectPath = Join-Path $Root 'System.Impostor.csproj'
        $outputPath = Join-Path $Root 'out'
        Set-Content -LiteralPath $sourcePath -NoNewline -Encoding utf8NoBOM -Value @'
namespace System.Impostor;

public sealed class Counterfeit
{
}
'@
        Set-Content -LiteralPath $projectPath -NoNewline -Encoding utf8NoBOM -Value @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <AssemblyName>System.Impostor</AssemblyName>
    <AssemblyVersion>1.0.0.0</AssemblyVersion>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <Deterministic>true</Deterministic>
    <DebugType>none</DebugType>
  </PropertyGroup>
</Project>
'@
        $compilerOutput = & dotnet build $projectPath -c Release -o $outputPath --nologo --verbosity quiet 2>&1
        $assemblyPath = Join-Path $outputPath 'System.Impostor.dll'
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $assemblyPath -PathType Leaf)) {
            throw "The System.Impostor fixture did not compile: $($compilerOutput | Out-String)"
        }
        return $assemblyPath
    }

    function New-GraphKitAuthRuntimeHarnessAssembly {
        param([Parameter(Mandatory)] [string] $Root)

        $null = New-Item -ItemType Directory -Path $Root -Force
        $sourcePath = Join-Path $Root 'RuntimeHarness.cs'
        $projectPath = Join-Path $Root 'RuntimeHarness.csproj'
        $outputPath = Join-Path $Root 'out'
        $escapedContractsPath = [System.Security.SecurityElement]::Escape($script:contractsPath)
        Set-Content -LiteralPath $sourcePath -NoNewline -Encoding utf8NoBOM -Value @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Loader;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using GraphKit.Auth;

public static class GraphKitAuthRuntimeHarness
{
    public static string ConcurrentDispose(
        GraphAuthHost host,
        IGraphTokenSource source,
        string disposeMarker)
    {
        BindingFlags privateInstance = BindingFlags.Instance | BindingFlags.NonPublic;
        var shutdown = (CancellationTokenSource)(typeof(GraphAuthHost)
            .GetField("_shutdown", privateInstance)?.GetValue(host)
            ?? throw new InvalidOperationException("Host shutdown source was not found."));
        var stateField = typeof(GraphAuthHost).GetField("_state", privateInstance)
            ?? throw new InvalidOperationException("Host state field was not found.");
        Type proxyType = source.GetType();
        var innerField = proxyType.GetField("_inner", privateInstance)
            ?? throw new InvalidOperationException("Proxy inner field was not found.");
        var ownerField = proxyType.GetField("_owner", privateInstance)
            ?? throw new InvalidOperationException("Proxy owner field was not found.");

        using var ownerReachedCancel = new ManualResetEventSlim(false);
        using var releaseOwner = new ManualResetEventSlim(false);
        using var nonOwnerStarted = new ManualResetEventSlim(false);
        using CancellationTokenRegistration registration = shutdown.Token.Register(() =>
        {
            ownerReachedCancel.Set();
            if (!releaseOwner.Wait(TimeSpan.FromSeconds(5)))
            {
                throw new TimeoutException("The concurrent-dispose owner was not released.");
            }
        });

        Task owner = Task.Factory.StartNew(
            host.Dispose,
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);
        if (!ownerReachedCancel.Wait(TimeSpan.FromSeconds(5)))
        {
            throw new TimeoutException("The shutdown owner did not reach cancellation.");
        }

        Task nonOwner = Task.Factory.StartNew(
            () =>
            {
                nonOwnerStarted.Set();
                host.Dispose();
            },
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);
        if (!nonOwnerStarted.Wait(TimeSpan.FromSeconds(5)))
        {
            throw new TimeoutException("The non-owner dispose caller did not start.");
        }

        bool nonOwnerCompletedBeforeRelease = nonOwner.Wait(TimeSpan.FromMilliseconds(500));
        int stateBeforeRelease = (int)(stateField.GetValue(host)
            ?? throw new InvalidOperationException("Host state was null."));
        releaseOwner.Set();
        if (!Task.WaitAll(new[] { owner, nonOwner }, TimeSpan.FromSeconds(5)))
        {
            throw new TimeoutException("Concurrent GraphAuthHost.Dispose calls did not finish within the bounded deadline.");
        }

        int disposeCount = File.Exists(disposeMarker)
            ? File.ReadAllLines(disposeMarker).Length
            : 0;
        return JsonSerializer.Serialize(new
        {
            NonOwnerCompletedBeforeRelease = nonOwnerCompletedBeforeRelease,
            StateBeforeRelease = stateBeforeRelease,
            DisposeCount = disposeCount,
            ProxyInnerCleared = innerField.GetValue(source) is null,
            ProxyOwnerCleared = ownerField.GetValue(source) is null
        });
    }

    public static string BlockedCancellationCallback(
        GraphAuthHost host,
        IGraphTokenSource source,
        string disposeMarker)
    {
        BindingFlags privateInstance = BindingFlags.Instance | BindingFlags.NonPublic;
        var shutdown = (CancellationTokenSource)(typeof(GraphAuthHost)
            .GetField("_shutdown", privateInstance)?.GetValue(host)
            ?? throw new InvalidOperationException("Host shutdown source was not found."));
        var stateField = typeof(GraphAuthHost).GetField("_state", privateInstance)
            ?? throw new InvalidOperationException("Host state field was not found.");
        var shutdownTaskField = typeof(GraphAuthHost).GetField("_shutdownTask", privateInstance)
            ?? throw new InvalidOperationException("Host shutdown-task field was not found.");
        Type proxyType = source.GetType();
        var innerField = proxyType.GetField("_inner", privateInstance)
            ?? throw new InvalidOperationException("Proxy inner field was not found.");
        var ownerField = proxyType.GetField("_owner", privateInstance)
            ?? throw new InvalidOperationException("Proxy owner field was not found.");
        object inner = innerField.GetValue(source)
            ?? throw new InvalidOperationException("Proxy inner source was not found.");
        BindingFlags providerControlFlags = BindingFlags.Static | BindingFlags.NonPublic;
        MethodInfo waitForAcquire = inner.GetType().GetMethod(
            "WaitForBlockedAcquire",
            providerControlFlags)
            ?? throw new InvalidOperationException("Provider acquire wait control was not found.");
        MethodInfo releaseAcquire = inner.GetType().GetMethod(
            "ReleaseBlockedAcquire",
            providerControlFlags)
            ?? throw new InvalidOperationException("Provider acquire release control was not found.");

        Task acquire = Task.Factory.StartNew(
            () => source.Acquire(false, CancellationToken.None),
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);
        if (waitForAcquire.Invoke(null, new object[] { TimeSpan.FromSeconds(5) }) is not true)
        {
            releaseAcquire.Invoke(null, null);
            throw new TimeoutException("The provider acquisition did not enter its blocked section.");
        }

        using var callbackEntered = new ManualResetEventSlim(false);
        using var releaseCallback = new ManualResetEventSlim(false);
        bool completionPlaceholderPublishedBeforeCallback = false;
        bool reentrantDisposeReturned = false;
        using CancellationTokenRegistration registration = shutdown.Token.Register(() =>
        {
            callbackEntered.Set();
            completionPlaceholderPublishedBeforeCallback =
                shutdownTaskField.GetValue(host) is Task;
            host.Dispose();
            reentrantDisposeReturned = true;
            if (!releaseCallback.Wait(TimeSpan.FromSeconds(10)))
            {
                throw new TimeoutException("The blocked cancellation callback was not released.");
            }
        });

        Task? owner = null;
        Task? nonOwner = null;
        bool ownerCompletedBeforeCallbackRelease;
        bool nonOwnerCompletedBeforeCallbackRelease;
        long ownerElapsedMilliseconds;
        int stateWhileCallbackBlocked;
        int disposeCountWhileCallbackBlocked;
        bool proxyInnerPresentWhileCallbackBlocked;
        bool proxyOwnerPresentWhileCallbackBlocked;
        bool loadContextAliveWhileCallbackBlocked;
        try
        {
            var ownerTimer = Stopwatch.StartNew();
            owner = Task.Factory.StartNew(
                host.Dispose,
                CancellationToken.None,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default);
            if (!callbackEntered.Wait(TimeSpan.FromSeconds(5)))
            {
                throw new TimeoutException("The cancellation callback did not begin.");
            }

            ownerCompletedBeforeCallbackRelease = owner.Wait(TimeSpan.FromSeconds(2));
            ownerElapsedMilliseconds = ownerTimer.ElapsedMilliseconds;
            stateWhileCallbackBlocked = (int)(stateField.GetValue(host)
                ?? throw new InvalidOperationException("Host state was null."));
            disposeCountWhileCallbackBlocked = File.Exists(disposeMarker)
                ? File.ReadAllLines(disposeMarker).Length
                : 0;
            proxyInnerPresentWhileCallbackBlocked = innerField.GetValue(source) is not null;
            proxyOwnerPresentWhileCallbackBlocked = ownerField.GetValue(source) is not null;
            loadContextAliveWhileCallbackBlocked = host.LoadContextWeakReference.IsAlive;

            nonOwner = Task.Factory.StartNew(
                host.Dispose,
                CancellationToken.None,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default);
            nonOwnerCompletedBeforeCallbackRelease = nonOwner.Wait(TimeSpan.FromSeconds(2));
        }
        finally
        {
            releaseCallback.Set();
        }

        bool proxyClearedBeforeAcquireRelease = SpinWait.SpinUntil(
            () => innerField.GetValue(source) is null && ownerField.GetValue(source) is null,
            TimeSpan.FromSeconds(5));
        int disposeCountWhileAcquireBlocked = File.Exists(disposeMarker)
            ? File.ReadAllLines(disposeMarker).Length
            : 0;
        releaseAcquire.Invoke(null, null);

        Task[] tasks = new[]
        {
            owner ?? throw new InvalidOperationException("Owner task was not created."),
            nonOwner ?? throw new InvalidOperationException("Non-owner task was not created."),
            acquire
        };
        if (!Task.WaitAll(tasks, TimeSpan.FromSeconds(5)))
        {
            throw new TimeoutException("Blocked-callback shutdown did not finish after both releases.");
        }

        host.Dispose();
        int finalDisposeCount = File.Exists(disposeMarker)
            ? File.ReadAllLines(disposeMarker).Length
            : 0;
        return JsonSerializer.Serialize(new
        {
            OwnerCompletedBeforeCallbackRelease = ownerCompletedBeforeCallbackRelease,
            NonOwnerCompletedBeforeCallbackRelease = nonOwnerCompletedBeforeCallbackRelease,
            OwnerElapsedMilliseconds = ownerElapsedMilliseconds,
            CompletionPlaceholderPublishedBeforeCallback = completionPlaceholderPublishedBeforeCallback,
            ReentrantDisposeReturned = reentrantDisposeReturned,
            StateWhileCallbackBlocked = stateWhileCallbackBlocked,
            DisposeCountWhileCallbackBlocked = disposeCountWhileCallbackBlocked,
            ProxyInnerPresentWhileCallbackBlocked = proxyInnerPresentWhileCallbackBlocked,
            ProxyOwnerPresentWhileCallbackBlocked = proxyOwnerPresentWhileCallbackBlocked,
            LoadContextAliveWhileCallbackBlocked = loadContextAliveWhileCallbackBlocked,
            ProxyClearedBeforeAcquireRelease = proxyClearedBeforeAcquireRelease,
            DisposeCountWhileAcquireBlocked = disposeCountWhileAcquireBlocked,
            FinalDisposeCount = finalDisposeCount,
            ProxyInnerCleared = innerField.GetValue(source) is null,
            ProxyOwnerCleared = ownerField.GetValue(source) is null
        });
    }

    public static string ImmediateDisposalFailure(
        GraphAuthHost host,
        IGraphTokenSource source,
        string disposeMarker)
    {
        BindingFlags privateInstance = BindingFlags.Instance | BindingFlags.NonPublic;
        Type hostType = typeof(GraphAuthHost);
        Type proxyType = source.GetType();
        var innerField = proxyType.GetField("_inner", privateInstance)
            ?? throw new InvalidOperationException("Proxy inner field was not found.");
        var ownerField = proxyType.GetField("_owner", privateInstance)
            ?? throw new InvalidOperationException("Proxy owner field was not found.");
        WeakReference weakReference = host.LoadContextWeakReference;

        string firstFailure = CaptureFailure(host.Dispose);
        Task shutdownTask = (Task)(hostType.GetField("_shutdownTask", privateInstance)?.GetValue(host)
            ?? throw new InvalidOperationException("Host shutdown task was not published."));
        string taskFailure = DescribeFailure(shutdownTask.Exception);
        string repeatedFailure = CaptureFailure(host.Dispose);

        ForceCollection(weakReference);
        return JsonSerializer.Serialize(new
        {
            FirstFailure = firstFailure,
            TaskFailure = taskFailure,
            RepeatedFailure = repeatedFailure,
            DisposeCount = File.Exists(disposeMarker)
                ? File.ReadAllLines(disposeMarker).Length
                : 0,
            ProxyInnerCleared = innerField.GetValue(source) is null,
            ProxyOwnerCleared = ownerField.GetValue(source) is null,
            HostProviderReferencesCleared = HostProviderReferencesAreCleared(host, privateInstance),
            LoadContextAliveWhileHostAndTaskReferenced = weakReference.IsAlive
        });
    }

    public static string DeferredDisposalFailure(
        GraphAuthHost host,
        IGraphTokenSource source,
        string disposeMarker)
    {
        BindingFlags privateInstance = BindingFlags.Instance | BindingFlags.NonPublic;
        WeakReference weakReference = host.LoadContextWeakReference;
        object deferred = RunDeferredDisposal(host, source, privateInstance);

        Task shutdownTask = (Task)(typeof(GraphAuthHost)
            .GetField("_shutdownTask", privateInstance)?.GetValue(host)
            ?? throw new InvalidOperationException("Host shutdown task was not published."));
        if (!SpinWait.SpinUntil(() => shutdownTask.IsCompleted, TimeSpan.FromSeconds(5)))
        {
            throw new TimeoutException("Deferred shutdown completion was not published after the acquisition left.");
        }

        string laterFailure = CaptureFailure(host.Dispose);
        string repeatedFailure = CaptureFailure(host.Dispose);
        string taskFailure = DescribeFailure(shutdownTask.Exception);
        Type proxyType = source.GetType();
        var innerField = proxyType.GetField("_inner", privateInstance)
            ?? throw new InvalidOperationException("Proxy inner field was not found.");
        var retiredInnerField = proxyType.GetField("_retiredInner", privateInstance)
            ?? throw new InvalidOperationException("Proxy retired-inner field was not found.");
        var ownerField = proxyType.GetField("_owner", privateInstance)
            ?? throw new InvalidOperationException("Proxy owner field was not found.");

        ForceCollection(weakReference);
        return JsonSerializer.Serialize(new
        {
            Deferred = deferred,
            LaterFailure = laterFailure,
            RepeatedFailure = repeatedFailure,
            TaskFailure = taskFailure,
            DisposeCount = File.Exists(disposeMarker)
                ? File.ReadAllLines(disposeMarker).Length
                : 0,
            ProxyInnerCleared = innerField.GetValue(source) is null,
            ProxyRetiredInnerCleared = retiredInnerField.GetValue(source) is null,
            ProxyOwnerCleared = ownerField.GetValue(source) is null,
            HostProviderReferencesCleared = HostProviderReferencesAreCleared(host, privateInstance),
            LoadContextAliveWhileHostAndTaskReferenced = weakReference.IsAlive
        });
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static object RunDeferredDisposal(
        GraphAuthHost host,
        IGraphTokenSource source,
        BindingFlags privateInstance)
    {
        Type proxyType = source.GetType();
        var innerField = proxyType.GetField("_inner", privateInstance)
            ?? throw new InvalidOperationException("Proxy inner field was not found.");
        var retiredInnerField = proxyType.GetField("_retiredInner", privateInstance)
            ?? throw new InvalidOperationException("Proxy retired-inner field was not found.");
        object inner = innerField.GetValue(source)
            ?? throw new InvalidOperationException("Proxy inner source was not found.");
        BindingFlags providerControlFlags = BindingFlags.Static | BindingFlags.NonPublic;
        MethodInfo waitForAcquire = inner.GetType().GetMethod(
            "WaitForBlockedAcquire",
            providerControlFlags)
            ?? throw new InvalidOperationException("Provider acquire wait control was not found.");
        MethodInfo releaseAcquire = inner.GetType().GetMethod(
            "ReleaseBlockedAcquire",
            providerControlFlags)
            ?? throw new InvalidOperationException("Provider acquire release control was not found.");

        Task<GraphTokenResult> acquire = Task.Factory.StartNew(
            () => source.Acquire(false, CancellationToken.None),
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);
        if (waitForAcquire.Invoke(null, new object[] { TimeSpan.FromSeconds(5) }) is not true)
        {
            releaseAcquire.Invoke(null, null);
            throw new TimeoutException("The provider acquisition did not enter its blocked section.");
        }

        Task owner = Task.Factory.StartNew(
            host.Dispose,
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);
        bool ownerReturnedWithinDeadline = owner.Wait(TimeSpan.FromSeconds(2));
        bool retiredInnerPresentWhileAcquireBlocked =
            SpinWait.SpinUntil(
                () => retiredInnerField.GetValue(source) is not null,
                TimeSpan.FromSeconds(5));
        bool loadContextAliveWhileAcquireBlocked = host.LoadContextWeakReference.IsAlive;
        releaseAcquire.Invoke(null, null);
        string acquireFailure = CaptureTaskFailure(acquire);
        if (!owner.Wait(TimeSpan.FromSeconds(5)))
        {
            throw new TimeoutException("The initial bounded Dispose caller did not return.");
        }

        return new
        {
            OwnerReturnedWithinDeadline = ownerReturnedWithinDeadline,
            RetiredInnerPresentWhileAcquireBlocked = retiredInnerPresentWhileAcquireBlocked,
            LoadContextAliveWhileAcquireBlocked = loadContextAliveWhileAcquireBlocked,
            AcquireFailure = acquireFailure
        };
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static string CaptureTaskFailure(Task task)
    {
        try
        {
            task.GetAwaiter().GetResult();
            return string.Empty;
        }
        catch (Exception exception)
        {
            return DescribeFailure(exception);
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static string CaptureFailure(Action action)
    {
        try
        {
            action();
            return string.Empty;
        }
        catch (Exception exception)
        {
            return DescribeFailure(exception);
        }
    }

    private static string DescribeFailure(Exception? exception)
    {
        if (exception is null)
        {
            return string.Empty;
        }

        var description = new StringBuilder();
        AppendFailure(exception, description, new HashSet<Exception>());
        return description.ToString();
    }

    private static void AppendFailure(
        Exception exception,
        StringBuilder description,
        HashSet<Exception> visited)
    {
        if (!visited.Add(exception))
        {
            return;
        }

        Type type = exception.GetType();
        description.Append("type=").Append(type.FullName)
            .Append(";assembly=").Append(type.Assembly.GetName().Name)
            .Append(";alc=").Append(AssemblyLoadContext.GetLoadContext(type.Assembly)?.Name)
            .Append(";message=").Append(exception.Message)
            .Append(";stack=").Append(exception.StackTrace)
            .Append(";dataCount=").Append(exception.Data.Count);
        if (exception is GraphAuthException graphAuthException)
        {
            description.Append(";code=").Append(graphAuthException.Code)
                .Append(";category=").Append(graphAuthException.Category)
                .Append(";correlation=").Append(graphAuthException.CorrelationId)
                .Append(";retryAfter=").Append(graphAuthException.RetryAfter);
        }

        foreach (DictionaryEntry item in exception.Data)
        {
            description.Append(";dataKeyType=").Append(item.Key?.GetType().AssemblyQualifiedName)
                .Append(";dataKey=").Append(item.Key)
                .Append(";dataValueType=").Append(item.Value?.GetType().AssemblyQualifiedName)
                .Append(";dataValue=").Append(item.Value);
        }

        description.AppendLine();
        if (exception is AggregateException aggregate)
        {
            foreach (Exception inner in aggregate.InnerExceptions)
            {
                AppendFailure(inner, description, visited);
            }
        }
        else if (exception.InnerException is not null)
        {
            AppendFailure(exception.InnerException, description, visited);
        }
    }

    private static bool HostProviderReferencesAreCleared(
        GraphAuthHost host,
        BindingFlags privateInstance)
    {
        Type hostType = typeof(GraphAuthHost);
        return hostType.GetField("_factory", privateInstance)?.GetValue(host) is null &&
            hostType.GetField("_factoryType", privateInstance)?.GetValue(host) is null &&
            hostType.GetField("_providerAssembly", privateInstance)?.GetValue(host) is null &&
            hostType.GetField("_loadContext", privateInstance)?.GetValue(host) is null;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ForceCollection(WeakReference weakReference)
    {
        for (int attempt = 0; attempt < 30 && weakReference.IsAlive; attempt++)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }
    }
}
'@
        Set-Content -LiteralPath $projectPath -NoNewline -Encoding utf8NoBOM -Value @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <AssemblyName>GraphKit.Auth.RuntimeHarness</AssemblyName>
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
        $compilerOutput = & dotnet build $projectPath -c Release -o $outputPath --nologo --verbosity quiet 2>&1
        $assemblyPath = Join-Path $outputPath 'GraphKit.Auth.RuntimeHarness.dll'
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $assemblyPath -PathType Leaf)) {
            throw "The GraphKit.Auth runtime harness did not compile: $($compilerOutput | Out-String)"
        }
        return $assemblyPath
    }

    function New-GraphKitAuthAbiMutationAssembly {
        param(
            [Parameter(Mandatory)] [string] $Root,
            [Parameter(Mandatory)] [ValidateSet('EnumUnderlyingByte', 'CorrelationIdNonNullable')] [string] $Mutation
        )

        $null = New-Item -ItemType Directory -Path $Root -Force
        $sourceRoot = Join-Path $script:repoRoot 'src/GraphKit.Auth/GraphKit.Auth.Contracts'
        foreach ($sourceName in @('Contracts.cs', 'GraphAuthHost.cs', 'GraphAuthLoadContext.cs', 'GraphTokenSourceProxy.cs')) {
            Copy-Item -LiteralPath (Join-Path $sourceRoot $sourceName) -Destination (Join-Path $Root $sourceName)
        }

        $contractsSourcePath = Join-Path $Root 'Contracts.cs'
        $contractsSource = Get-Content -LiteralPath $contractsSourcePath -Raw
        $mutatedSource = switch ($Mutation) {
            'EnumUnderlyingByte' {
                $contractsSource.Replace(
                    'public enum GraphAuthMode',
                    'public enum GraphAuthMode : byte')
            }
            'CorrelationIdNonNullable' {
                $contractsSource.Replace(
                    'string? correlationId)',
                    'string correlationId)')
            }
        }
        $mutatedSource | Should -Not -BeExactly $contractsSource -Because "the '$Mutation' fixture must alter the ABI source"
        Set-Content -LiteralPath $contractsSourcePath -NoNewline -Encoding utf8NoBOM -Value $mutatedSource

        $projectPath = Join-Path $Root 'GraphKit.Auth.Contracts.csproj'
        $outputPath = Join-Path $Root 'out'
        $assemblyPath = Join-Path $outputPath 'GraphKit.Auth.Contracts.dll'
        Set-Content -LiteralPath $projectPath -NoNewline -Encoding utf8NoBOM -Value @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <AssemblyName>GraphKit.Auth.Contracts</AssemblyName>
    <RootNamespace>GraphKit.Auth</RootNamespace>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <NoWarn>CS8625</NoWarn>
    <Deterministic>true</Deterministic>
    <DebugType>none</DebugType>
  </PropertyGroup>
</Project>
'@

        $compilerOutput = & dotnet build $projectPath -c Release -o $outputPath --nologo --verbosity quiet 2>&1
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $assemblyPath -PathType Leaf)) {
            throw "The GraphKit.Auth ABI mutation fixture did not compile: $($compilerOutput | Out-String)"
        }
        return $assemblyPath
    }

    function Invoke-GraphKitAuthAbiSurfaceProbe {
        param([Parameter(Mandatory)] [string] $ContractsPath)

        $probePath = Join-Path $TestDrive ('Probe-AbiSurface-' + [guid]::NewGuid().ToString('N') + '.ps1')
        Set-Content -LiteralPath $probePath -NoNewline -Encoding utf8NoBOM -Value @'
param([Parameter(Mandatory)] [string] $ContractsPath)
$ErrorActionPreference = 'Stop'
$assembly = [System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath(
    (Resolve-Path -LiteralPath $ContractsPath).ProviderPath
)

function Get-TypeDisplayName {
    param([Parameter(Mandatory)] [Type] $Type)
    if ($Type.IsArray) {
        return "$(Get-TypeDisplayName -Type $Type.GetElementType())[]"
    }
    if ($Type.IsGenericType) {
        $definition = $Type.GetGenericTypeDefinition().FullName
        $definition = $definition.Substring(0, $definition.IndexOf('`'))
        $arguments = @($Type.GetGenericArguments() | ForEach-Object { Get-TypeDisplayName -Type $_ }) -join ','
        return "$definition<$arguments>"
    }
    return $Type.FullName
}

function Get-ParameterDisplay {
    param([Parameter(Mandatory)] [System.Reflection.ParameterInfo] $Parameter)
    "$(Get-TypeDisplayName -Type $Parameter.ParameterType) $($Parameter.Name)"
}

function Get-NullabilityDisplay {
    param([System.Reflection.NullabilityInfo] $Info)
    if ($null -eq $Info) { return '<none>' }

    $display = "$($Info.ReadState)/$($Info.WriteState)"
    if ($null -ne $Info.ElementType) {
        $display += ";element=$(Get-NullabilityDisplay -Info $Info.ElementType)"
    }
    if ($Info.GenericTypeArguments.Count -ne 0) {
        $arguments = @($Info.GenericTypeArguments | ForEach-Object { Get-NullabilityDisplay -Info $_ }) -join ','
        $display += ";arguments=[$arguments]"
    }
    return $display
}

function Get-ModifierDisplay {
    param([AllowEmptyCollection()] [Type[]] $Modifiers)
    return '[' + (@($Modifiers | ForEach-Object FullName | Sort-Object) -join ',') + ']'
}

function Get-CallableId {
    param([Parameter(Mandatory)] [System.Reflection.MethodBase] $Callable)
    $parameters = @($Callable.GetParameters() | ForEach-Object { Get-TypeDisplayName -Type $_.ParameterType }) -join ','
    $name = if ($Callable -is [System.Reflection.ConstructorInfo]) { '.ctor' } else { $Callable.Name }
    return "$($Callable.DeclaringType.FullName)::$name($parameters)"
}

function Get-DefaultDisplay {
    param([Parameter(Mandatory)] [System.Reflection.ParameterInfo] $Parameter)
    if (-not $Parameter.HasDefaultValue) { return '<none>' }
    if ($null -eq $Parameter.DefaultValue) { return '<null>' }
    if ($Parameter.DefaultValue -is [string]) {
        return '"' + ([string] $Parameter.DefaultValue).Replace('"', '\"') + '"'
    }
    if ($Parameter.DefaultValue -is [char]) {
        return "'$($Parameter.DefaultValue)'"
    }
    if ($Parameter.DefaultValue -is [bool]) {
        return ([string] $Parameter.DefaultValue).ToLowerInvariant()
    }
    return [Convert]::ToString($Parameter.DefaultValue, [Globalization.CultureInfo]::InvariantCulture)
}

function Add-ParameterMetadata {
    param(
        [Parameter(Mandatory)] [string] $OwnerKind,
        [Parameter(Mandatory)] [string] $OwnerId,
        [Parameter(Mandatory)] [System.Reflection.ParameterInfo] $Parameter
    )

    $direction = if ($Parameter.IsOut) {
        'out'
    }
    elseif ($Parameter.ParameterType.IsByRef -and $Parameter.IsIn) {
        'in'
    }
    elseif ($Parameter.ParameterType.IsByRef) {
        'ref'
    }
    else {
        'value'
    }
    $isParams = $Parameter.IsDefined([ParamArrayAttribute], $false).ToString().ToLowerInvariant()
    $isOptional = $Parameter.IsOptional.ToString().ToLowerInvariant()
    $hasDefault = $Parameter.HasDefaultValue.ToString().ToLowerInvariant()
    $requiredModifiers = Get-ModifierDisplay -Modifiers $Parameter.GetRequiredCustomModifiers()
    $optionalModifiers = Get-ModifierDisplay -Modifiers $Parameter.GetOptionalCustomModifiers()
    $nullability = Get-NullabilityDisplay -Info $nullabilityContext.Create($Parameter)
    $lines.Add(
        "PARAMETER-META|$OwnerKind|$OwnerId|$($Parameter.Position)|$($Parameter.Name)|" +
        "$(Get-TypeDisplayName -Type $Parameter.ParameterType)|direction=$direction|params=$isParams|" +
        "optional=$isOptional|hasDefault=$hasDefault|default=$(Get-DefaultDisplay -Parameter $Parameter)|" +
        "requiredMods=$requiredModifiers|optionalMods=$optionalModifiers|nullable=$nullability")
}

function Add-GenericParameterMetadata {
    param(
        [Parameter(Mandatory)] [string] $OwnerKind,
        [Parameter(Mandatory)] [string] $OwnerId,
        [AllowEmptyCollection()] [Type[]] $GenericParameters
    )

    foreach ($parameter in @($GenericParameters | Where-Object IsGenericParameter | Sort-Object GenericParameterPosition)) {
        $constraints = '[' + (@($parameter.GetGenericParameterConstraints() | ForEach-Object { Get-TypeDisplayName -Type $_ } | Sort-Object) -join ',') + ']'
        $lines.Add(
            "GENERIC-PARAMETER|$OwnerKind|$OwnerId|$($parameter.GenericParameterPosition)|" +
            "$($parameter.Name)|attributes=$($parameter.GenericParameterAttributes)|constraints=$constraints")
    }
}

$lines = [Collections.Generic.List[string]]::new()
$flags = [Reflection.BindingFlags]'Public,Instance,Static,DeclaredOnly'
$nullabilityContext = [System.Reflection.NullabilityInfoContext]::new()
foreach ($type in @($assembly.GetExportedTypes() | Sort-Object FullName)) {
    $kind = if ($type.IsEnum) { 'enum' } elseif ($type.IsInterface) { 'interface' } elseif ($type.IsAbstract) { 'abstract-class' } elseif ($type.IsSealed) { 'sealed-class' } else { 'class' }
    $baseType = if ($null -eq $type.BaseType) { '' } else { Get-TypeDisplayName -Type $type.BaseType }
    $interfaces = @($type.GetInterfaces() | ForEach-Object { Get-TypeDisplayName -Type $_ } | Sort-Object) -join ','
    $lines.Add("TYPE|$($type.FullName)|$kind|$baseType|$interfaces")
    $isStaticType = ($type.IsAbstract -and $type.IsSealed -and -not $type.IsEnum).ToString().ToLowerInvariant()
    $enumUnderlying = if ($type.IsEnum) { Get-TypeDisplayName -Type ([Enum]::GetUnderlyingType($type)) } else { '<none>' }
    $genericParameters = @($type.GetGenericArguments() | Where-Object IsGenericParameter)
    $lines.Add("TYPE-META|$($type.FullName)|staticType=$isStaticType|enumUnderlying=$enumUnderlying|genericArity=$($genericParameters.Count)")
    Add-GenericParameterMetadata -OwnerKind TYPE -OwnerId $type.FullName -GenericParameters $genericParameters

    if ($type.IsEnum) {
        foreach ($name in [Enum]::GetNames($type)) {
            $value = [Convert]::ToInt64([Enum]::Parse($type, $name))
            $lines.Add("ENUM|$($type.FullName)|$name=$value")
        }
    }

    foreach ($constructor in @($type.GetConstructors($flags) | Sort-Object { $_.ToString() })) {
        $parameters = @($constructor.GetParameters() | ForEach-Object { Get-ParameterDisplay -Parameter $_ }) -join ','
        $lines.Add("CTOR|$($type.FullName)|($parameters)")
        $ownerId = Get-CallableId -Callable $constructor
        $lines.Add("MEMBER-META|CTOR|$ownerId|static=false|genericArity=0")
        foreach ($parameter in $constructor.GetParameters()) {
            Add-ParameterMetadata -OwnerKind CTOR -OwnerId $ownerId -Parameter $parameter
        }
    }

    foreach ($property in @($type.GetProperties($flags) | Sort-Object Name)) {
        $accessors = [Collections.Generic.List[string]]::new()
        if ($null -ne $property.GetMethod -and $property.GetMethod.IsPublic) { $accessors.Add('get') }
        if ($null -ne $property.SetMethod -and $property.SetMethod.IsPublic) {
            $isInit = @($property.SetMethod.ReturnParameter.GetRequiredCustomModifiers() | Where-Object FullName -eq 'System.Runtime.CompilerServices.IsExternalInit').Count -ne 0
            $accessors.Add($(if ($isInit) { 'init' } else { 'set' }))
        }
        $isRequired = @($property.GetCustomAttributesData() | Where-Object AttributeType -EQ ([System.Runtime.CompilerServices.RequiredMemberAttribute])).Count -ne 0
        if ($isRequired) { $accessors.Add('required') }
        $lines.Add("PROPERTY|$($type.FullName)|$($property.Name)|$(Get-TypeDisplayName -Type $property.PropertyType)|$($accessors -join ',')")
        $propertyAccessor = if ($null -ne $property.GetGetMethod($true)) { $property.GetGetMethod($true) } else { $property.GetSetMethod($true) }
        $propertyIsStatic = $propertyAccessor.IsStatic.ToString().ToLowerInvariant()
        $propertyNullability = Get-NullabilityDisplay -Info $nullabilityContext.Create($property)
        $indexParameters = @($property.GetIndexParameters())
        $setter = $property.GetSetMethod($true)
        $setterRequiredModifiers = if ($null -eq $setter) { '<none>' } else { Get-ModifierDisplay -Modifiers $setter.ReturnParameter.GetRequiredCustomModifiers() }
        $setterOptionalModifiers = if ($null -eq $setter) { '<none>' } else { Get-ModifierDisplay -Modifiers $setter.ReturnParameter.GetOptionalCustomModifiers() }
        $propertyOwnerId = "$($type.FullName)::$($property.Name)"
        $lines.Add(
            "PROPERTY-META|$propertyOwnerId|static=$propertyIsStatic|nullable=$propertyNullability|" +
            "indexCount=$($indexParameters.Count)|setterRequiredMods=$setterRequiredModifiers|setterOptionalMods=$setterOptionalModifiers")
        foreach ($parameter in $indexParameters) {
            Add-ParameterMetadata -OwnerKind INDEX -OwnerId $propertyOwnerId -Parameter $parameter
        }
    }

    foreach ($method in @($type.GetMethods($flags) | Where-Object { -not $_.IsSpecialName -or $_.Name.StartsWith('op_') } | Sort-Object Name, { $_.ToString() })) {
        $parameters = @($method.GetParameters() | ForEach-Object { Get-ParameterDisplay -Parameter $_ }) -join ','
        $lines.Add("METHOD|$($type.FullName)|$($method.Name)|($parameters)->$(Get-TypeDisplayName -Type $method.ReturnType)")
        $ownerId = Get-CallableId -Callable $method
        $methodGenericParameters = @($method.GetGenericArguments() | Where-Object IsGenericParameter)
        $lines.Add("MEMBER-META|METHOD|$ownerId|static=$($method.IsStatic.ToString().ToLowerInvariant())|genericArity=$($methodGenericParameters.Count)")
        Add-GenericParameterMetadata -OwnerKind METHOD -OwnerId $ownerId -GenericParameters $methodGenericParameters
        foreach ($parameter in $method.GetParameters()) {
            Add-ParameterMetadata -OwnerKind METHOD -OwnerId $ownerId -Parameter $parameter
        }
        $returnParameter = $method.ReturnParameter
        $lines.Add(
            "RETURN-META|METHOD|$ownerId|$(Get-TypeDisplayName -Type $method.ReturnType)|" +
            "requiredMods=$(Get-ModifierDisplay -Modifiers $returnParameter.GetRequiredCustomModifiers())|" +
            "optionalMods=$(Get-ModifierDisplay -Modifiers $returnParameter.GetOptionalCustomModifiers())|" +
            "nullable=$(Get-NullabilityDisplay -Info $nullabilityContext.Create($returnParameter))")
    }

    foreach ($event in @($type.GetEvents($flags) | Sort-Object Name)) {
        $accessors = [Collections.Generic.List[string]]::new()
        if ($null -ne $event.AddMethod -and $event.AddMethod.IsPublic) { $accessors.Add('add') }
        if ($null -ne $event.RemoveMethod -and $event.RemoveMethod.IsPublic) { $accessors.Add('remove') }
        $lines.Add("EVENT|$($type.FullName)|$($event.Name)|$(Get-TypeDisplayName -Type $event.EventHandlerType)|$($accessors -join ',')")
        $eventAccessor = if ($null -ne $event.AddMethod) { $event.AddMethod } else { $event.RemoveMethod }
        $lines.Add(
            "EVENT-META|$($type.FullName)::$($event.Name)|static=$($eventAccessor.IsStatic.ToString().ToLowerInvariant())|" +
            "nullable=$(Get-NullabilityDisplay -Info $nullabilityContext.Create($event))")
    }

    foreach ($field in @($type.GetFields($flags) | Where-Object { -not $type.IsEnum } | Sort-Object Name)) {
        $literal = if ($field.IsLiteral) { [string] $field.GetRawConstantValue() } else { '' }
        $lines.Add("FIELD|$($type.FullName)|$($field.Name)|$(Get-TypeDisplayName -Type $field.FieldType)|$literal")
        $lines.Add(
            "FIELD-META|$($type.FullName)::$($field.Name)|static=$($field.IsStatic.ToString().ToLowerInvariant())|" +
            "nullable=$(Get-NullabilityDisplay -Info $nullabilityContext.Create($field))")
    }
}
@($lines | Sort-Object) | ConvertTo-Json -Compress
'@
        $raw = & pwsh -NoLogo -NoProfile -File $probePath -ContractsPath $ContractsPath 2>&1
        $exitCode = $LASTEXITCODE
        $json = @($raw | Where-Object { $_ -is [string] -and $_.TrimStart().StartsWith('[') }) | Select-Object -Last 1
        [pscustomobject]@{
            ExitCode = $exitCode
            Data = if ($json) { @($json | ConvertFrom-Json) } else { @() }
            Output = ($raw | Out-String).Trim()
        }
    }

    function Invoke-GraphKitAuthRuntimeProbe {
        param(
            [Parameter(Mandatory)] [string] $ContractsPath,
            [string] $PayloadRoot,
            [Parameter(Mandatory)] [ValidateSet('Validation', 'Lifecycle', 'ProviderFailure', 'VersionMismatch', 'IncompatibleDefault', 'HostLoadFailure', 'ConcurrentDispose', 'BlockedCancellationCallback', 'ImmediateDisposalFailure', 'DeferredDisposalFailure', 'SamePathReplacement')] [string] $Scenario,
            [string] $DisposeMarker,
            [string] $ReplacementContractsPath,
            [string] $PreloadPath,
            [string] $HarnessPath
        )

        $probePath = Join-Path $TestDrive ('Probe-Runtime-' + [guid]::NewGuid().ToString('N') + '.ps1')
        Set-Content -LiteralPath $probePath -NoNewline -Encoding utf8NoBOM -Value @'
param(
    [Parameter(Mandatory)] [string] $ContractsPath,
    [string] $PayloadRoot,
    [Parameter(Mandatory)] [string] $Scenario,
    [string] $DisposeMarker,
    [string] $ReplacementContractsPath,
    [string] $PreloadPath,
    [string] $HarnessPath
)
$ErrorActionPreference = 'Stop'
$null = [System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath(
    (Resolve-Path -LiteralPath $ContractsPath).ProviderPath
)
if (-not [string]::IsNullOrWhiteSpace($PreloadPath)) {
    $null = [System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath(
        (Resolve-Path -LiteralPath $PreloadPath).ProviderPath
    )
}
if (-not [string]::IsNullOrWhiteSpace($HarnessPath)) {
    $null = [System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath(
        (Resolve-Path -LiteralPath $HarnessPath).ProviderPath
    )
}

function New-ValidRequest {
    return [GraphKit.Auth.GraphTokenRequest]::new(
        'Global',
        [guid] '00000000-0000-0000-0000-000000000001',
        [uri] 'https://login.microsoftonline.com',
        [uri] 'https://graph.microsoft.com',
        $null,
        [GraphKit.Auth.GraphAuthMode]::BearerToken,
        [GraphKit.Auth.FixedBearerCredential]::new('fixture-bearer'),
        'generation-1'
    )
}

function Get-Rejection {
    param([scriptblock] $Action)
    try {
        $null = & $Action
        return $null
    }
    catch {
        return $_.Exception.GetBaseException().Message
    }
}

switch ($Scenario) {
    'Validation' {
        $emptySecret = [Security.SecureString]::new()
        $invalidCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new()
        $cases = [ordered]@{}
        $cases.EmptyEnvironment = Get-Rejection { [GraphKit.Auth.GraphTokenRequest]::new('', [guid]'00000000-0000-0000-0000-000000000001', [uri]'https://login.microsoftonline.com', [uri]'https://graph.microsoft.com', $null, [GraphKit.Auth.GraphAuthMode]::BearerToken, [GraphKit.Auth.FixedBearerCredential]::new('token'), 'g1') }
        $cases.EmptyTenant = Get-Rejection { [GraphKit.Auth.GraphTokenRequest]::new('Global', [guid]::Empty, [uri]'https://login.microsoftonline.com', [uri]'https://graph.microsoft.com', $null, [GraphKit.Auth.GraphAuthMode]::BearerToken, [GraphKit.Auth.FixedBearerCredential]::new('token'), 'g1') }
        $cases.HttpAuthority = Get-Rejection { [GraphKit.Auth.GraphTokenRequest]::new('Global', [guid]'00000000-0000-0000-0000-000000000001', [uri]'http://login.microsoftonline.com', [uri]'https://graph.microsoft.com', $null, [GraphKit.Auth.GraphAuthMode]::BearerToken, [GraphKit.Auth.FixedBearerCredential]::new('token'), 'g1') }
        $cases.RelativeResource = Get-Rejection { [GraphKit.Auth.GraphTokenRequest]::new('Global', [guid]'00000000-0000-0000-0000-000000000001', [uri]'/relative', $null, $null, [GraphKit.Auth.GraphAuthMode]::BearerToken, [GraphKit.Auth.FixedBearerCredential]::new('token'), 'g1') }
        $cases.MissingClientId = Get-Rejection { [GraphKit.Auth.GraphTokenRequest]::new('Global', [guid]'00000000-0000-0000-0000-000000000001', [uri]'https://login.microsoftonline.com', [uri]'https://graph.microsoft.com', $null, [GraphKit.Auth.GraphAuthMode]::ClientSecret, [GraphKit.Auth.ClientSecretCredential]::new($emptySecret, $false), 'g1') }
        $cases.UnexpectedClientId = Get-Rejection { [GraphKit.Auth.GraphTokenRequest]::new('Global', [guid]'00000000-0000-0000-0000-000000000001', [uri]'https://login.microsoftonline.com', [uri]'https://graph.microsoft.com', [guid]'00000000-0000-0000-0000-000000000002', [GraphKit.Auth.GraphAuthMode]::ManagedIdentity, [GraphKit.Auth.ManagedIdentityCredential]::new($null), 'g1') }
        $cases.Discriminator = Get-Rejection { [GraphKit.Auth.GraphTokenRequest]::new('Global', [guid]'00000000-0000-0000-0000-000000000001', [uri]'https://login.microsoftonline.com', [uri]'https://graph.microsoft.com', $null, [GraphKit.Auth.GraphAuthMode]::BearerToken, [GraphKit.Auth.ManagedIdentityCredential]::new($null), 'g1') }
        $cases.PublicOnlyCertificate = Get-Rejection { [GraphKit.Auth.CertificateCredential]::new($invalidCertificate, $false) }
        $cases.EmptySecret = Get-Rejection { [GraphKit.Auth.ClientSecretCredential]::new($emptySecret, $false) }
        $cases.InvalidManagedIdentity = Get-Rejection { [GraphKit.Auth.ManagedIdentityCredential]::new('not-a-guid') }
        $cases.EmptyBearer = Get-Rejection { [GraphKit.Auth.FixedBearerCredential]::new(' ') }
        $cases.EmptyGeneration = Get-Rejection { [GraphKit.Auth.GraphTokenRequest]::new('Global', [guid]'00000000-0000-0000-0000-000000000001', [uri]'https://login.microsoftonline.com', [uri]'https://graph.microsoft.com', $null, [GraphKit.Auth.GraphAuthMode]::BearerToken, [GraphKit.Auth.FixedBearerCredential]::new('token'), ' ') }
        $cases.InvalidShutdownTimeout = Get-Rejection { [GraphKit.Auth.GraphAuthHost]::new('/graphkit-auth-missing-payload', [version]'1.0.0.0', [timespan]::Zero) }
        $requestType = [GraphKit.Auth.GraphTokenRequest]
        $resultType = [GraphKit.Auth.GraphTokenResult]
        [pscustomobject]@{
            Cases = $cases
            RequestSetters = @($requestType.GetProperties() | Where-Object { $null -ne $_.SetMethod }).Count
            VerifiedTenantIdSettable = $null -ne $resultType.GetProperty('VerifiedTenantId').SetMethod
        } | ConvertTo-Json -Compress -Depth 5
    }
    'Lifecycle' {
        $env:GRAPHKIT_AUTH_TEST_DISPOSE_MARKER = $DisposeMarker
        $authHost = [GraphKit.Auth.GraphAuthHost]::new($PayloadRoot, [version]'1.0.0.0', [timespan]::FromSeconds(2))
        $weakReference = $authHost.LoadContextWeakReference
        $first = $authHost.CreateSource((New-ValidRequest))
        $acquired = $first.Acquire($false, [Threading.CancellationToken]::None)
        $first.Dispose()
        $first.Dispose()
        $firstRejected = $null -ne (Get-Rejection { $first.Acquire($false, [Threading.CancellationToken]::None) })
        $second = $authHost.CreateSource((New-ValidRequest))
        $authHost.Dispose()
        $secondRejected = $null -ne (Get-Rejection { $second.Acquire($false, [Threading.CancellationToken]::None) })
        $createRejected = $null -ne (Get-Rejection { $authHost.CreateSource((New-ValidRequest)) })
        $first = $null
        $second = $null
        $authHost = $null
        for ($i = 0; $i -lt 20 -and $weakReference.IsAlive; $i++) {
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            [GC]::Collect()
        }
        [pscustomobject]@{
            AccessToken = $acquired.AccessToken
            FirstRejected = $firstRejected
            SecondRejected = $secondRejected
            CreateRejected = $createRejected
            DisposeCount = @(Get-Content -LiteralPath $DisposeMarker).Count
            LoadContextAlive = $weakReference.IsAlive
        } | ConvertTo-Json -Compress
    }
    'ProviderFailure' {
        $authHost = [GraphKit.Auth.GraphAuthHost]::new($PayloadRoot, [version]'1.0.0.0', [timespan]::FromSeconds(2))
        $source = $authHost.CreateSource((New-ValidRequest))
        try {
            $null = $source.Acquire($true, [Threading.CancellationToken]::None)
            throw 'The provider fixture did not fail.'
        }
        catch [GraphKit.Auth.GraphAuthException] {
            [pscustomobject]@{
                Type = $_.Exception.GetType().FullName
                Code = $_.Exception.Code
                Category = $_.Exception.Category
                Message = $_.Exception.Message
                RetryAfterSeconds = $_.Exception.RetryAfter.TotalSeconds
                CorrelationId = $_.Exception.CorrelationId
                InnerIsNull = $null -eq $_.Exception.InnerException
            } | ConvertTo-Json -Compress
        }
        finally {
            $source.Dispose()
            $authHost.Dispose()
        }
    }
    'VersionMismatch' {
        $message = Get-Rejection { [GraphKit.Auth.GraphAuthHost]::new($PayloadRoot, [version]'9.0.0.0', [timespan]::FromSeconds(2)) }
        [pscustomobject]@{ Message = $message } | ConvertTo-Json -Compress
    }
    'IncompatibleDefault' {
        $message = Get-Rejection { [GraphKit.Auth.GraphAuthHost]::new($PayloadRoot, [version]'1.0.0.0', [timespan]::FromSeconds(2)) }
        [pscustomobject]@{ Message = $message } | ConvertTo-Json -Compress
    }
    'HostLoadFailure' {
        $message = Get-Rejection { [GraphKit.Auth.GraphAuthHost]::new($PayloadRoot, [version]'1.0.0.0', [timespan]::FromSeconds(2)) }
        [pscustomobject]@{ Message = $message } | ConvertTo-Json -Compress
    }
    'ConcurrentDispose' {
        $env:GRAPHKIT_AUTH_TEST_DISPOSE_MARKER = $DisposeMarker
        $authHost = [GraphKit.Auth.GraphAuthHost]::new($PayloadRoot, [version]'1.0.0.0', [timespan]::FromSeconds(5))
        $source = $authHost.CreateSource((New-ValidRequest))
        $weakReference = $authHost.LoadContextWeakReference
        $data = [GraphKitAuthRuntimeHarness]::ConcurrentDispose($authHost, $source, $DisposeMarker) | ConvertFrom-Json
        for ($i = 0; $i -lt 30 -and $weakReference.IsAlive; $i++) {
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            [GC]::Collect()
        }
        $data | Add-Member -NotePropertyName LoadContextAlive -NotePropertyValue $weakReference.IsAlive
        $data | ConvertTo-Json -Compress
    }
    'BlockedCancellationCallback' {
        $env:GRAPHKIT_AUTH_TEST_DISPOSE_MARKER = $DisposeMarker
        $env:GRAPHKIT_AUTH_TEST_BLOCK_ACQUIRE = '1'
        $authHost = [GraphKit.Auth.GraphAuthHost]::new(
            $PayloadRoot,
            [version]'1.0.0.0',
            [timespan]::FromMilliseconds(125))
        $source = $authHost.CreateSource((New-ValidRequest))
        $weakReference = $authHost.LoadContextWeakReference
        $data = [GraphKitAuthRuntimeHarness]::BlockedCancellationCallback(
            $authHost,
            $source,
            $DisposeMarker) | ConvertFrom-Json
        for ($i = 0; $i -lt 30 -and $weakReference.IsAlive; $i++) {
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            [GC]::Collect()
        }
        $data | Add-Member -NotePropertyName LoadContextAlive -NotePropertyValue $weakReference.IsAlive
        $data | ConvertTo-Json -Compress
    }
    'ImmediateDisposalFailure' {
        $env:GRAPHKIT_AUTH_TEST_DISPOSE_MARKER = $DisposeMarker
        $env:GRAPHKIT_AUTH_TEST_DISPOSE_FAILURE = '1'
        $authHost = [GraphKit.Auth.GraphAuthHost]::new(
            $PayloadRoot,
            [version]'1.0.0.0',
            [timespan]::FromSeconds(2))
        $source = $authHost.CreateSource((New-ValidRequest))
        [GraphKitAuthRuntimeHarness]::ImmediateDisposalFailure(
            $authHost,
            $source,
            $DisposeMarker)
    }
    'DeferredDisposalFailure' {
        $env:GRAPHKIT_AUTH_TEST_DISPOSE_MARKER = $DisposeMarker
        $env:GRAPHKIT_AUTH_TEST_DISPOSE_FAILURE = '1'
        $env:GRAPHKIT_AUTH_TEST_BLOCK_ACQUIRE = '1'
        $authHost = [GraphKit.Auth.GraphAuthHost]::new(
            $PayloadRoot,
            [version]'1.0.0.0',
            [timespan]::FromMilliseconds(125))
        $source = $authHost.CreateSource((New-ValidRequest))
        [GraphKitAuthRuntimeHarness]::DeferredDisposalFailure(
            $authHost,
            $source,
            $DisposeMarker)
    }
    'SamePathReplacement' {
        $residentMvid = [GraphKit.Auth.GraphAuthHost].Assembly.ManifestModule.ModuleVersionId.ToString('D')
        [IO.File]::Copy(
            (Resolve-Path -LiteralPath $ReplacementContractsPath).ProviderPath,
            (Resolve-Path -LiteralPath $ContractsPath).ProviderPath,
            $true
        )
        $message = Get-Rejection {
            $replacementHost = [GraphKit.Auth.GraphAuthHost]::new($PayloadRoot, [version]'1.0.0.0', [timespan]::FromSeconds(2))
            $replacementHost.Dispose()
        }
        [pscustomobject]@{
            Message = $message
            ResidentMvid = $residentMvid
        } | ConvertTo-Json -Compress
    }
}
'@

        $arguments = @(
            '-NoLogo', '-NoProfile', '-File', $probePath,
            '-ContractsPath', $ContractsPath,
            '-Scenario', $Scenario
        )
        if ($PayloadRoot) { $arguments += @('-PayloadRoot', $PayloadRoot) }
        if ($DisposeMarker) { $arguments += @('-DisposeMarker', $DisposeMarker) }
        if ($ReplacementContractsPath) { $arguments += @('-ReplacementContractsPath', $ReplacementContractsPath) }
        if ($PreloadPath) { $arguments += @('-PreloadPath', $PreloadPath) }
        if ($HarnessPath) { $arguments += @('-HarnessPath', $HarnessPath) }
        $raw = & pwsh @arguments 2>&1
        $exitCode = $LASTEXITCODE
        $json = @($raw | Where-Object { $_ -is [string] -and $_.TrimStart().StartsWith('{') }) | Select-Object -Last 1
        [pscustomobject]@{
            ExitCode = $exitCode
            Data = if ($json) { $json | ConvertFrom-Json } else { $null }
            Output = ($raw | Out-String).Trim()
        }
    }

    $script:contractsInspection = if (Test-Path -LiteralPath $script:contractsPath -PathType Leaf) {
        Invoke-GraphKitAuthContractsCandidateProbe -CandidatePath $script:contractsPath
    }
    else {
        $null
    }
}

Describe 'GraphKit.Auth ABI v1 contract' -Tag 'Unit' {
    It 'rejects a stale same-simple-name default-ALC assembly instead of accepting it as the candidate' {
        $stalePath = New-GraphKitAuthContractsFixtureAssembly -Root (Join-Path $TestDrive 'stale-contracts') -Marker 'GraphKit.Auth.Abi/1'
        $candidatePath = New-GraphKitAuthContractsFixtureAssembly -Root (Join-Path $TestDrive 'candidate-contracts') -Marker 'GraphKit.Auth.Abi/999'
        (Get-FileHash -LiteralPath $stalePath -Algorithm SHA256).Hash |
            Should -Not -Be (Get-FileHash -LiteralPath $candidatePath -Algorithm SHA256).Hash

        $result = Invoke-GraphKitAuthContractsCandidateProbe -CandidatePath $candidatePath -PreloadPath $stalePath

        $result.ExitCode | Should -Not -Be 0 -Because 'a different preloaded assembly must never satisfy candidate inspection'
        $result.Output | Should -Match '(?s)Default ALC already contains.*refusing candidate'
    }

    It 'binds a fresh synthetic candidate by exact location bytes and MVID' {
        $candidatePath = New-GraphKitAuthContractsFixtureAssembly -Root (Join-Path $TestDrive 'fresh-contracts') -Marker 'GraphKit.Auth.Abi/1'

        $result = Invoke-GraphKitAuthContractsCandidateProbe -CandidatePath $candidatePath

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $resolvedCandidate = (Resolve-Path -LiteralPath $candidatePath).ProviderPath
        $candidateSha256 = (Get-FileHash -LiteralPath $candidatePath -Algorithm SHA256).Hash.ToLowerInvariant()
        $result.Data.CandidatePath | Should -BeExactly $resolvedCandidate
        $result.Data.LoadedLocation | Should -BeExactly $resolvedCandidate
        $result.Data.CandidateSha256 | Should -BeExactly $candidateSha256
        $result.Data.LoadedSha256 | Should -BeExactly $candidateSha256
        $result.Data.LoadedMvid | Should -BeExactly $result.Data.CandidateMvid
        $result.Data.ContractMarker | Should -Be 'GraphKit.Auth.Abi/1'
        $result.Data.AcquireReturnType | Should -Be 'GraphKit.Auth.GraphTokenResult'
        @($result.Data.Leaks) | Should -BeNullOrEmpty
    }

    It 'loads the exact contract candidate with the ABI marker and Acquire result' {
        $script:contractsPath | Should -Exist -Because 'Task 3 must build the dependency-free GraphKit.Auth contract assembly'

        $script:contractsInspection.ExitCode | Should -Be 0 -Because $script:contractsInspection.Output
        $resolvedCandidate = (Resolve-Path -LiteralPath $script:contractsPath).ProviderPath
        $candidateSha256 = (Get-FileHash -LiteralPath $script:contractsPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $script:contractsInspection.Data.CandidatePath | Should -BeExactly $resolvedCandidate
        $script:contractsInspection.Data.LoadedLocation | Should -BeExactly $resolvedCandidate
        $script:contractsInspection.Data.CandidateSha256 | Should -BeExactly $candidateSha256
        $script:contractsInspection.Data.LoadedSha256 | Should -BeExactly $candidateSha256
        $script:contractsInspection.Data.CandidateMvid | Should -Match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        $script:contractsInspection.Data.LoadedMvid | Should -BeExactly $script:contractsInspection.Data.CandidateMvid
        $script:contractsInspection.Data.ContractMarker | Should -Be 'GraphKit.Auth.Abi/1'
        $script:contractsInspection.Data.AcquireReturnType | Should -Be 'GraphKit.Auth.GraphTokenResult'
    }

    It 'keeps Microsoft.Identity.Client out of every public candidate signature' {
        $script:contractsPath | Should -Exist -Because 'the public GraphKit.Auth surface can only be inspected after Task 3 builds it'

        $script:contractsInspection.ExitCode | Should -Be 0 -Because $script:contractsInspection.Output
        @($script:contractsInspection.Data.Leaks) | Should -BeNullOrEmpty -Because 'no MSAL type may cross the GraphKit-owned ABI boundary'
    }

    It 'rejects an enum underlying-type mutation through the literal ABI-v1 gate' {
        $mutatedPath = New-GraphKitAuthAbiMutationAssembly `
            -Root (Join-Path $TestDrive 'abi-enum-byte') -Mutation EnumUnderlyingByte

        $rejection = try {
            Assert-GraphKitAuthAbiV1Surface -ContractsPath $mutatedPath
            $null
        }
        catch {
            $_.Exception.Message
        }

        $rejection | Should -Match 'enumUnderlying=System\.Int32'
        $rejection | Should -Match 'enumUnderlying=System\.Byte' `
            -Because 'the literal ABI gate must distinguish the frozen Int32 enum from an otherwise identical byte enum'
    }

    It 'rejects a nullable-reference mutation through the literal ABI-v1 gate' {
        $mutatedPath = New-GraphKitAuthAbiMutationAssembly `
            -Root (Join-Path $TestDrive 'abi-correlation-nonnullable') -Mutation CorrelationIdNonNullable

        $rejection = try {
            Assert-GraphKitAuthAbiV1Surface -ContractsPath $mutatedPath
            $null
        }
        catch {
            $_.Exception.Message
        }

        $rejection | Should -Match 'correlationId.*nullable=Nullable/Nullable'
        $rejection | Should -Match 'correlationId.*nullable=NotNull/NotNull' `
            -Because 'the literal ABI gate must distinguish a non-null correlationId parameter from the frozen nullable parameter'
    }

    BeforeAll {
        function Assert-GraphKitAuthAbiV1Surface {
            param([Parameter(Mandatory)] [string] $ContractsPath)

        $expectedSurface = @(
            'CTOR|GraphKit.Auth.CertificateCredential|(System.Security.Cryptography.X509Certificates.X509Certificate2 certificate,System.Boolean ownsMaterial)'
            'CTOR|GraphKit.Auth.ClientSecretCredential|(System.Security.SecureString secret,System.Boolean ownsMaterial)'
            'CTOR|GraphKit.Auth.FixedBearerCredential|(System.String accessToken)'
            'CTOR|GraphKit.Auth.GraphAuthException|(System.String code,System.String category,System.String message,System.Nullable<System.TimeSpan> retryAfter,System.String correlationId)'
            'CTOR|GraphKit.Auth.GraphAuthHost|(System.String payloadRoot,System.Version expectedProviderVersion,System.TimeSpan shutdownTimeout)'
            'CTOR|GraphKit.Auth.GraphAuthHost|(System.String payloadRoot,System.Version expectedProviderVersion)'
            'CTOR|GraphKit.Auth.GraphTokenRequest|(System.String environment,System.Guid tenantId,System.Uri authority,System.Uri resource,System.Nullable<System.Guid> clientId,GraphKit.Auth.GraphAuthMode authMode,GraphKit.Auth.GraphCredential credential,System.String credentialGeneration)'
            'CTOR|GraphKit.Auth.GraphTokenResult|()'
            'CTOR|GraphKit.Auth.ManagedIdentityCredential|(System.String userAssignedClientId)'
            'ENUM|GraphKit.Auth.GraphAuthMode|BearerToken=3'
            'ENUM|GraphKit.Auth.GraphAuthMode|Certificate=0'
            'ENUM|GraphKit.Auth.GraphAuthMode|ClientSecret=1'
            'ENUM|GraphKit.Auth.GraphAuthMode|ManagedIdentity=2'
            'FIELD|GraphKit.Auth.GraphAuthHost|ContractMarker|System.String|GraphKit.Auth.Abi/1'
            'METHOD|GraphKit.Auth.GraphAuthHost|CreateSource|(GraphKit.Auth.GraphTokenRequest request)->GraphKit.Auth.IGraphTokenSource'
            'METHOD|GraphKit.Auth.GraphAuthHost|Dispose|()->System.Void'
            'METHOD|GraphKit.Auth.IGraphTokenSource|Acquire|(System.Boolean forceRefresh,System.Threading.CancellationToken cancellation)->GraphKit.Auth.GraphTokenResult'
            'METHOD|GraphKit.Auth.IGraphTokenSource|AdoptSharedResult|(GraphKit.Auth.GraphTokenResult result,System.Boolean forceRefresh)->System.Void'
            'METHOD|GraphKit.Auth.IGraphTokenSourceFactory|Create|(GraphKit.Auth.GraphTokenRequest request)->GraphKit.Auth.IGraphTokenSource'
            'PROPERTY|GraphKit.Auth.CertificateCredential|Certificate|System.Security.Cryptography.X509Certificates.X509Certificate2|get'
            'PROPERTY|GraphKit.Auth.CertificateCredential|OwnsMaterial|System.Boolean|get'
            'PROPERTY|GraphKit.Auth.ClientSecretCredential|OwnsMaterial|System.Boolean|get'
            'PROPERTY|GraphKit.Auth.ClientSecretCredential|Secret|System.Security.SecureString|get'
            'PROPERTY|GraphKit.Auth.FixedBearerCredential|AccessToken|System.String|get'
            'PROPERTY|GraphKit.Auth.GraphAuthException|Category|System.String|get'
            'PROPERTY|GraphKit.Auth.GraphAuthException|Code|System.String|get'
            'PROPERTY|GraphKit.Auth.GraphAuthException|CorrelationId|System.String|get'
            'PROPERTY|GraphKit.Auth.GraphAuthException|RetryAfter|System.Nullable<System.TimeSpan>|get'
            'PROPERTY|GraphKit.Auth.GraphAuthHost|LoadContextWeakReference|System.WeakReference|get'
            'PROPERTY|GraphKit.Auth.GraphTokenRequest|AuthMode|GraphKit.Auth.GraphAuthMode|get'
            'PROPERTY|GraphKit.Auth.GraphTokenRequest|Authority|System.Uri|get'
            'PROPERTY|GraphKit.Auth.GraphTokenRequest|ClientId|System.Nullable<System.Guid>|get'
            'PROPERTY|GraphKit.Auth.GraphTokenRequest|Credential|GraphKit.Auth.GraphCredential|get'
            'PROPERTY|GraphKit.Auth.GraphTokenRequest|CredentialGeneration|System.String|get'
            'PROPERTY|GraphKit.Auth.GraphTokenRequest|Environment|System.String|get'
            'PROPERTY|GraphKit.Auth.GraphTokenRequest|Resource|System.Uri|get'
            'PROPERTY|GraphKit.Auth.GraphTokenRequest|TenantId|System.Guid|get'
            'PROPERTY|GraphKit.Auth.GraphTokenResult|AccessToken|System.String|get,init,required'
            'PROPERTY|GraphKit.Auth.GraphTokenResult|CredentialGeneration|System.String|get,init,required'
            'PROPERTY|GraphKit.Auth.GraphTokenResult|ExpiresOnUtc|System.DateTimeOffset|get,init'
            'PROPERTY|GraphKit.Auth.GraphTokenResult|ReceivedOnUtc|System.DateTimeOffset|get,init'
            'PROPERTY|GraphKit.Auth.GraphTokenResult|Scopes|System.String[]|get,init,required'
            'PROPERTY|GraphKit.Auth.GraphTokenResult|TokenFingerprint|System.String|get,init,required'
            'PROPERTY|GraphKit.Auth.GraphTokenResult|TokenType|System.String|get,init,required'
            'PROPERTY|GraphKit.Auth.GraphTokenResult|VerifiedTenantId|System.String|get,set'
            'PROPERTY|GraphKit.Auth.IGraphTokenSource|Audience|System.String|get'
            'PROPERTY|GraphKit.Auth.IGraphTokenSource|AuthMode|System.String|get'
            'PROPERTY|GraphKit.Auth.IGraphTokenSource|CanRefresh|System.Boolean|get'
            'PROPERTY|GraphKit.Auth.IGraphTokenSource|ClientId|System.String|get'
            'PROPERTY|GraphKit.Auth.IGraphTokenSource|CredentialGeneration|System.String|get'
            'PROPERTY|GraphKit.Auth.IGraphTokenSource|ExpiresOn|System.DateTimeOffset|get'
            'PROPERTY|GraphKit.Auth.IGraphTokenSource|VerifiedTenantId|System.String|get'
            'PROPERTY|GraphKit.Auth.ManagedIdentityCredential|UserAssignedClientId|System.String|get'
            'TYPE|GraphKit.Auth.CertificateCredential|sealed-class|GraphKit.Auth.GraphCredential|'
            'TYPE|GraphKit.Auth.ClientSecretCredential|sealed-class|GraphKit.Auth.GraphCredential|'
            'TYPE|GraphKit.Auth.FixedBearerCredential|sealed-class|GraphKit.Auth.GraphCredential|'
            'TYPE|GraphKit.Auth.GraphAuthException|sealed-class|System.Exception|System.Runtime.Serialization.ISerializable'
            'TYPE|GraphKit.Auth.GraphAuthHost|sealed-class|System.Object|System.IDisposable'
            'TYPE|GraphKit.Auth.GraphAuthMode|enum|System.Enum|System.IComparable,System.IConvertible,System.IFormattable,System.ISpanFormattable'
            'TYPE|GraphKit.Auth.GraphCredential|abstract-class|System.Object|'
            'TYPE|GraphKit.Auth.GraphTokenRequest|sealed-class|System.Object|'
            'TYPE|GraphKit.Auth.GraphTokenResult|sealed-class|System.Object|'
            'TYPE|GraphKit.Auth.IGraphTokenSource|interface||System.IDisposable'
            'TYPE|GraphKit.Auth.IGraphTokenSourceFactory|interface||'
            'TYPE|GraphKit.Auth.ManagedIdentityCredential|sealed-class|GraphKit.Auth.GraphCredential|'
            'FIELD-META|GraphKit.Auth.GraphAuthHost::ContractMarker|static=true|nullable=NotNull/NotNull'
            'MEMBER-META|CTOR|GraphKit.Auth.CertificateCredential::.ctor(System.Security.Cryptography.X509Certificates.X509Certificate2,System.Boolean)|static=false|genericArity=0'
            'MEMBER-META|CTOR|GraphKit.Auth.ClientSecretCredential::.ctor(System.Security.SecureString,System.Boolean)|static=false|genericArity=0'
            'MEMBER-META|CTOR|GraphKit.Auth.FixedBearerCredential::.ctor(System.String)|static=false|genericArity=0'
            'MEMBER-META|CTOR|GraphKit.Auth.GraphAuthException::.ctor(System.String,System.String,System.String,System.Nullable<System.TimeSpan>,System.String)|static=false|genericArity=0'
            'MEMBER-META|CTOR|GraphKit.Auth.GraphAuthHost::.ctor(System.String,System.Version,System.TimeSpan)|static=false|genericArity=0'
            'MEMBER-META|CTOR|GraphKit.Auth.GraphAuthHost::.ctor(System.String,System.Version)|static=false|genericArity=0'
            'MEMBER-META|CTOR|GraphKit.Auth.GraphTokenRequest::.ctor(System.String,System.Guid,System.Uri,System.Uri,System.Nullable<System.Guid>,GraphKit.Auth.GraphAuthMode,GraphKit.Auth.GraphCredential,System.String)|static=false|genericArity=0'
            'MEMBER-META|CTOR|GraphKit.Auth.GraphTokenResult::.ctor()|static=false|genericArity=0'
            'MEMBER-META|CTOR|GraphKit.Auth.ManagedIdentityCredential::.ctor(System.String)|static=false|genericArity=0'
            'MEMBER-META|METHOD|GraphKit.Auth.GraphAuthHost::CreateSource(GraphKit.Auth.GraphTokenRequest)|static=false|genericArity=0'
            'MEMBER-META|METHOD|GraphKit.Auth.GraphAuthHost::Dispose()|static=false|genericArity=0'
            'MEMBER-META|METHOD|GraphKit.Auth.IGraphTokenSource::Acquire(System.Boolean,System.Threading.CancellationToken)|static=false|genericArity=0'
            'MEMBER-META|METHOD|GraphKit.Auth.IGraphTokenSource::AdoptSharedResult(GraphKit.Auth.GraphTokenResult,System.Boolean)|static=false|genericArity=0'
            'MEMBER-META|METHOD|GraphKit.Auth.IGraphTokenSourceFactory::Create(GraphKit.Auth.GraphTokenRequest)|static=false|genericArity=0'
            'PARAMETER-META|CTOR|GraphKit.Auth.CertificateCredential::.ctor(System.Security.Cryptography.X509Certificates.X509Certificate2,System.Boolean)|0|certificate|System.Security.Cryptography.X509Certificates.X509Certificate2|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|CTOR|GraphKit.Auth.CertificateCredential::.ctor(System.Security.Cryptography.X509Certificates.X509Certificate2,System.Boolean)|1|ownsMaterial|System.Boolean|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|CTOR|GraphKit.Auth.ClientSecretCredential::.ctor(System.Security.SecureString,System.Boolean)|0|secret|System.Security.SecureString|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|CTOR|GraphKit.Auth.ClientSecretCredential::.ctor(System.Security.SecureString,System.Boolean)|1|ownsMaterial|System.Boolean|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|CTOR|GraphKit.Auth.FixedBearerCredential::.ctor(System.String)|0|accessToken|System.String|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|CTOR|GraphKit.Auth.GraphAuthException::.ctor(System.String,System.String,System.String,System.Nullable<System.TimeSpan>,System.String)|0|code|System.String|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|CTOR|GraphKit.Auth.GraphAuthException::.ctor(System.String,System.String,System.String,System.Nullable<System.TimeSpan>,System.String)|1|category|System.String|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|CTOR|GraphKit.Auth.GraphAuthException::.ctor(System.String,System.String,System.String,System.Nullable<System.TimeSpan>,System.String)|2|message|System.String|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|CTOR|GraphKit.Auth.GraphAuthException::.ctor(System.String,System.String,System.String,System.Nullable<System.TimeSpan>,System.String)|3|retryAfter|System.Nullable<System.TimeSpan>|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=Nullable/Nullable'
            'PARAMETER-META|CTOR|GraphKit.Auth.GraphAuthException::.ctor(System.String,System.String,System.String,System.Nullable<System.TimeSpan>,System.String)|4|correlationId|System.String|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=Nullable/Nullable'
            'PARAMETER-META|CTOR|GraphKit.Auth.GraphAuthHost::.ctor(System.String,System.Version,System.TimeSpan)|0|payloadRoot|System.String|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|CTOR|GraphKit.Auth.GraphAuthHost::.ctor(System.String,System.Version,System.TimeSpan)|1|expectedProviderVersion|System.Version|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|CTOR|GraphKit.Auth.GraphAuthHost::.ctor(System.String,System.Version,System.TimeSpan)|2|shutdownTimeout|System.TimeSpan|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|CTOR|GraphKit.Auth.GraphAuthHost::.ctor(System.String,System.Version)|0|payloadRoot|System.String|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|CTOR|GraphKit.Auth.GraphAuthHost::.ctor(System.String,System.Version)|1|expectedProviderVersion|System.Version|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|CTOR|GraphKit.Auth.GraphTokenRequest::.ctor(System.String,System.Guid,System.Uri,System.Uri,System.Nullable<System.Guid>,GraphKit.Auth.GraphAuthMode,GraphKit.Auth.GraphCredential,System.String)|0|environment|System.String|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|CTOR|GraphKit.Auth.GraphTokenRequest::.ctor(System.String,System.Guid,System.Uri,System.Uri,System.Nullable<System.Guid>,GraphKit.Auth.GraphAuthMode,GraphKit.Auth.GraphCredential,System.String)|1|tenantId|System.Guid|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|CTOR|GraphKit.Auth.GraphTokenRequest::.ctor(System.String,System.Guid,System.Uri,System.Uri,System.Nullable<System.Guid>,GraphKit.Auth.GraphAuthMode,GraphKit.Auth.GraphCredential,System.String)|2|authority|System.Uri|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|CTOR|GraphKit.Auth.GraphTokenRequest::.ctor(System.String,System.Guid,System.Uri,System.Uri,System.Nullable<System.Guid>,GraphKit.Auth.GraphAuthMode,GraphKit.Auth.GraphCredential,System.String)|3|resource|System.Uri|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|CTOR|GraphKit.Auth.GraphTokenRequest::.ctor(System.String,System.Guid,System.Uri,System.Uri,System.Nullable<System.Guid>,GraphKit.Auth.GraphAuthMode,GraphKit.Auth.GraphCredential,System.String)|4|clientId|System.Nullable<System.Guid>|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=Nullable/Nullable'
            'PARAMETER-META|CTOR|GraphKit.Auth.GraphTokenRequest::.ctor(System.String,System.Guid,System.Uri,System.Uri,System.Nullable<System.Guid>,GraphKit.Auth.GraphAuthMode,GraphKit.Auth.GraphCredential,System.String)|5|authMode|GraphKit.Auth.GraphAuthMode|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|CTOR|GraphKit.Auth.GraphTokenRequest::.ctor(System.String,System.Guid,System.Uri,System.Uri,System.Nullable<System.Guid>,GraphKit.Auth.GraphAuthMode,GraphKit.Auth.GraphCredential,System.String)|6|credential|GraphKit.Auth.GraphCredential|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|CTOR|GraphKit.Auth.GraphTokenRequest::.ctor(System.String,System.Guid,System.Uri,System.Uri,System.Nullable<System.Guid>,GraphKit.Auth.GraphAuthMode,GraphKit.Auth.GraphCredential,System.String)|7|credentialGeneration|System.String|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|CTOR|GraphKit.Auth.ManagedIdentityCredential::.ctor(System.String)|0|userAssignedClientId|System.String|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=Nullable/Nullable'
            'PARAMETER-META|METHOD|GraphKit.Auth.GraphAuthHost::CreateSource(GraphKit.Auth.GraphTokenRequest)|0|request|GraphKit.Auth.GraphTokenRequest|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|METHOD|GraphKit.Auth.IGraphTokenSource::Acquire(System.Boolean,System.Threading.CancellationToken)|0|forceRefresh|System.Boolean|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|METHOD|GraphKit.Auth.IGraphTokenSource::Acquire(System.Boolean,System.Threading.CancellationToken)|1|cancellation|System.Threading.CancellationToken|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|METHOD|GraphKit.Auth.IGraphTokenSource::AdoptSharedResult(GraphKit.Auth.GraphTokenResult,System.Boolean)|0|result|GraphKit.Auth.GraphTokenResult|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|METHOD|GraphKit.Auth.IGraphTokenSource::AdoptSharedResult(GraphKit.Auth.GraphTokenResult,System.Boolean)|1|forceRefresh|System.Boolean|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PARAMETER-META|METHOD|GraphKit.Auth.IGraphTokenSourceFactory::Create(GraphKit.Auth.GraphTokenRequest)|0|request|GraphKit.Auth.GraphTokenRequest|direction=value|params=false|optional=false|hasDefault=false|default=<none>|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'PROPERTY-META|GraphKit.Auth.CertificateCredential::Certificate|static=false|nullable=NotNull/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.CertificateCredential::OwnsMaterial|static=false|nullable=NotNull/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.ClientSecretCredential::OwnsMaterial|static=false|nullable=NotNull/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.ClientSecretCredential::Secret|static=false|nullable=NotNull/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.FixedBearerCredential::AccessToken|static=false|nullable=NotNull/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.GraphAuthException::Category|static=false|nullable=NotNull/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.GraphAuthException::Code|static=false|nullable=NotNull/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.GraphAuthException::CorrelationId|static=false|nullable=Nullable/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.GraphAuthException::RetryAfter|static=false|nullable=Nullable/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.GraphAuthHost::LoadContextWeakReference|static=false|nullable=NotNull/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.GraphTokenRequest::AuthMode|static=false|nullable=NotNull/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.GraphTokenRequest::Authority|static=false|nullable=NotNull/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.GraphTokenRequest::ClientId|static=false|nullable=Nullable/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.GraphTokenRequest::Credential|static=false|nullable=NotNull/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.GraphTokenRequest::CredentialGeneration|static=false|nullable=NotNull/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.GraphTokenRequest::Environment|static=false|nullable=NotNull/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.GraphTokenRequest::Resource|static=false|nullable=NotNull/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.GraphTokenRequest::TenantId|static=false|nullable=NotNull/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.GraphTokenResult::AccessToken|static=false|nullable=NotNull/NotNull|indexCount=0|setterRequiredMods=[System.Runtime.CompilerServices.IsExternalInit]|setterOptionalMods=[]'
            'PROPERTY-META|GraphKit.Auth.GraphTokenResult::CredentialGeneration|static=false|nullable=NotNull/NotNull|indexCount=0|setterRequiredMods=[System.Runtime.CompilerServices.IsExternalInit]|setterOptionalMods=[]'
            'PROPERTY-META|GraphKit.Auth.GraphTokenResult::ExpiresOnUtc|static=false|nullable=NotNull/NotNull|indexCount=0|setterRequiredMods=[System.Runtime.CompilerServices.IsExternalInit]|setterOptionalMods=[]'
            'PROPERTY-META|GraphKit.Auth.GraphTokenResult::ReceivedOnUtc|static=false|nullable=NotNull/NotNull|indexCount=0|setterRequiredMods=[System.Runtime.CompilerServices.IsExternalInit]|setterOptionalMods=[]'
            'PROPERTY-META|GraphKit.Auth.GraphTokenResult::Scopes|static=false|nullable=NotNull/NotNull;element=NotNull/NotNull|indexCount=0|setterRequiredMods=[System.Runtime.CompilerServices.IsExternalInit]|setterOptionalMods=[]'
            'PROPERTY-META|GraphKit.Auth.GraphTokenResult::TokenFingerprint|static=false|nullable=NotNull/NotNull|indexCount=0|setterRequiredMods=[System.Runtime.CompilerServices.IsExternalInit]|setterOptionalMods=[]'
            'PROPERTY-META|GraphKit.Auth.GraphTokenResult::TokenType|static=false|nullable=NotNull/NotNull|indexCount=0|setterRequiredMods=[System.Runtime.CompilerServices.IsExternalInit]|setterOptionalMods=[]'
            'PROPERTY-META|GraphKit.Auth.GraphTokenResult::VerifiedTenantId|static=false|nullable=Nullable/Nullable|indexCount=0|setterRequiredMods=[]|setterOptionalMods=[]'
            'PROPERTY-META|GraphKit.Auth.IGraphTokenSource::Audience|static=false|nullable=NotNull/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.IGraphTokenSource::AuthMode|static=false|nullable=NotNull/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.IGraphTokenSource::CanRefresh|static=false|nullable=NotNull/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.IGraphTokenSource::ClientId|static=false|nullable=Nullable/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.IGraphTokenSource::CredentialGeneration|static=false|nullable=NotNull/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.IGraphTokenSource::ExpiresOn|static=false|nullable=NotNull/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.IGraphTokenSource::VerifiedTenantId|static=false|nullable=Nullable/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'PROPERTY-META|GraphKit.Auth.ManagedIdentityCredential::UserAssignedClientId|static=false|nullable=Nullable/Unknown|indexCount=0|setterRequiredMods=<none>|setterOptionalMods=<none>'
            'RETURN-META|METHOD|GraphKit.Auth.GraphAuthHost::CreateSource(GraphKit.Auth.GraphTokenRequest)|GraphKit.Auth.IGraphTokenSource|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'RETURN-META|METHOD|GraphKit.Auth.GraphAuthHost::Dispose()|System.Void|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'RETURN-META|METHOD|GraphKit.Auth.IGraphTokenSource::Acquire(System.Boolean,System.Threading.CancellationToken)|GraphKit.Auth.GraphTokenResult|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'RETURN-META|METHOD|GraphKit.Auth.IGraphTokenSource::AdoptSharedResult(GraphKit.Auth.GraphTokenResult,System.Boolean)|System.Void|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'RETURN-META|METHOD|GraphKit.Auth.IGraphTokenSourceFactory::Create(GraphKit.Auth.GraphTokenRequest)|GraphKit.Auth.IGraphTokenSource|requiredMods=[]|optionalMods=[]|nullable=NotNull/NotNull'
            'TYPE-META|GraphKit.Auth.CertificateCredential|staticType=false|enumUnderlying=<none>|genericArity=0'
            'TYPE-META|GraphKit.Auth.ClientSecretCredential|staticType=false|enumUnderlying=<none>|genericArity=0'
            'TYPE-META|GraphKit.Auth.FixedBearerCredential|staticType=false|enumUnderlying=<none>|genericArity=0'
            'TYPE-META|GraphKit.Auth.GraphAuthException|staticType=false|enumUnderlying=<none>|genericArity=0'
            'TYPE-META|GraphKit.Auth.GraphAuthHost|staticType=false|enumUnderlying=<none>|genericArity=0'
            'TYPE-META|GraphKit.Auth.GraphAuthMode|staticType=false|enumUnderlying=System.Int32|genericArity=0'
            'TYPE-META|GraphKit.Auth.GraphCredential|staticType=false|enumUnderlying=<none>|genericArity=0'
            'TYPE-META|GraphKit.Auth.GraphTokenRequest|staticType=false|enumUnderlying=<none>|genericArity=0'
            'TYPE-META|GraphKit.Auth.GraphTokenResult|staticType=false|enumUnderlying=<none>|genericArity=0'
            'TYPE-META|GraphKit.Auth.IGraphTokenSource|staticType=false|enumUnderlying=<none>|genericArity=0'
            'TYPE-META|GraphKit.Auth.IGraphTokenSourceFactory|staticType=false|enumUnderlying=<none>|genericArity=0'
            'TYPE-META|GraphKit.Auth.ManagedIdentityCredential|staticType=false|enumUnderlying=<none>|genericArity=0'
        ) | Sort-Object

        $result = Invoke-GraphKitAuthAbiSurfaceProbe -ContractsPath $ContractsPath
        $differences = @(Compare-Object -ReferenceObject $expectedSurface -DifferenceObject @($result.Data) -SyncWindow 10000)

        if ($result.ExitCode -ne 0) {
            throw "The ABI-v1 surface probe failed: $($result.Output)"
        }
        if ($differences.Count -ne 0) {
            $differenceText = @($differences | ForEach-Object {
                "$($_.SideIndicator) $($_.InputObject)"
            }) -join "`n"
            throw "ABI-v1 is literal, not inferred from the candidate:`n$differenceText"
        }
        }
    }

    It 'matches the literal ABI-v1 public surface without extra exported types or members' {
        { Assert-GraphKitAuthAbiV1Surface -ContractsPath $script:contractsPath } |
            Should -Not -Throw
    }
}

Describe 'GraphKit.Auth ABI v1 validation and lifetime' -Tag 'Unit' {
    It 'rejects malformed request and credential data before provider load and keeps the request immutable' {
        $result = Invoke-GraphKitAuthRuntimeProbe -ContractsPath $script:contractsPath -Scenario Validation

        $result.ExitCode | Should -Be 0 -Because $result.Output
        foreach ($case in $result.Data.Cases.PSObject.Properties) {
            $case.Value | Should -Not -BeNullOrEmpty -Because "the '$($case.Name)' invalid input must fail before a provider loads"
        }
        $result.Data.RequestSetters | Should -Be 0
        $result.Data.VerifiedTenantIdSettable | Should -BeTrue
    }

    It 'owns default-context proxies, rejects use after disposal, and unloads the provider context' {
        $payloadRoot = Join-Path $TestDrive 'valid-provider'
        $providerPath = New-GraphKitAuthProviderFixtureAssembly -Root $payloadRoot
        Copy-Item -LiteralPath $script:contractsPath -Destination (Join-Path $payloadRoot 'out/GraphKit.Auth.Contracts.dll')
        $disposeMarker = Join-Path $TestDrive 'dispose-marker.txt'

        $result = Invoke-GraphKitAuthRuntimeProbe -ContractsPath (Join-Path $payloadRoot 'out/GraphKit.Auth.Contracts.dll') `
            -PayloadRoot (Split-Path -Parent $providerPath) -Scenario Lifecycle -DisposeMarker $disposeMarker

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Data.AccessToken | Should -BeExactly 'fixture-token'
        $result.Data.FirstRejected | Should -BeTrue
        $result.Data.SecondRejected | Should -BeTrue
        $result.Data.CreateRejected | Should -BeTrue
        $result.Data.DisposeCount | Should -Be 2 -Because 'one explicitly disposed and one host-owned source must each dispose exactly once'
        $result.Data.LoadContextAlive | Should -BeFalse
    }

    It 'keeps one shutdown owner under concurrent Dispose callers and releases every collectible reference' {
        $payloadRoot = Join-Path $TestDrive 'concurrent-dispose-provider'
        $providerPath = New-GraphKitAuthProviderFixtureAssembly -Root $payloadRoot
        Copy-Item -LiteralPath $script:contractsPath -Destination (Join-Path $payloadRoot 'out/GraphKit.Auth.Contracts.dll')
        $harnessPath = New-GraphKitAuthRuntimeHarnessAssembly -Root (Join-Path $TestDrive 'runtime-harness')
        $disposeMarker = Join-Path $TestDrive 'concurrent-dispose-marker.txt'

        $result = Invoke-GraphKitAuthRuntimeProbe -ContractsPath (Join-Path $payloadRoot 'out/GraphKit.Auth.Contracts.dll') `
            -PayloadRoot (Split-Path -Parent $providerPath) -Scenario ConcurrentDispose `
            -DisposeMarker $disposeMarker -HarnessPath $harnessPath

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Data.NonOwnerCompletedBeforeRelease | Should -BeFalse -Because 'only the shutdown owner may progress finalization while it is disposing sources'
        $result.Data.StateBeforeRelease | Should -Be 1 -Because 'a non-owner must not move the host beyond the owner-disposal phase'
        $result.Data.DisposeCount | Should -Be 1 -Because 'the single host-owned source must be disposed exactly once'
        $result.Data.ProxyInnerCleared | Should -BeTrue
        $result.Data.ProxyOwnerCleared | Should -BeTrue
        $result.Data.LoadContextAlive | Should -BeFalse
    }

    It 'returns within the shutdown deadline while a cancellation callback is blocked and finishes safely after release' {
        $payloadRoot = Join-Path $TestDrive 'blocked-callback-provider'
        $providerPath = New-GraphKitAuthProviderFixtureAssembly -Root $payloadRoot
        Copy-Item -LiteralPath $script:contractsPath -Destination (Join-Path $payloadRoot 'out/GraphKit.Auth.Contracts.dll')
        $harnessPath = New-GraphKitAuthRuntimeHarnessAssembly -Root (Join-Path $TestDrive 'blocked-callback-harness')
        $disposeMarker = Join-Path $TestDrive 'blocked-callback-dispose-marker.txt'

        $result = Invoke-GraphKitAuthRuntimeProbe -ContractsPath (Join-Path $payloadRoot 'out/GraphKit.Auth.Contracts.dll') `
            -PayloadRoot (Split-Path -Parent $providerPath) -Scenario BlockedCancellationCallback `
            -DisposeMarker $disposeMarker -HarnessPath $harnessPath

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Data.OwnerCompletedBeforeCallbackRelease | Should -BeTrue -Because 'a synchronous cancellation callback must not defeat the configured host timeout'
        $result.Data.NonOwnerCompletedBeforeCallbackRelease | Should -BeTrue -Because 'concurrent Dispose callers share the same bounded shutdown deadline'
        $result.Data.OwnerElapsedMilliseconds | Should -BeLessThan 2000
        $result.Data.CompletionPlaceholderPublishedBeforeCallback | Should -BeTrue
        $result.Data.ReentrantDisposeReturned | Should -BeTrue `
            -Because 'a cancellation callback that reenters Dispose must observe the one published completion and return within the same bounded deadline'
        $result.Data.StateWhileCallbackBlocked | Should -Be 1
        $result.Data.DisposeCountWhileCallbackBlocked | Should -Be 0
        $result.Data.ProxyInnerPresentWhileCallbackBlocked | Should -BeTrue
        $result.Data.ProxyOwnerPresentWhileCallbackBlocked | Should -BeTrue
        $result.Data.LoadContextAliveWhileCallbackBlocked | Should -BeTrue
        $result.Data.ProxyClearedBeforeAcquireRelease | Should -BeTrue
        $result.Data.DisposeCountWhileAcquireBlocked | Should -Be 0 -Because 'an active proxy operation must retain its provider source until it leaves'
        $result.Data.FinalDisposeCount | Should -Be 1
        $result.Data.ProxyInnerCleared | Should -BeTrue
        $result.Data.ProxyOwnerCleared | Should -BeTrue
        $result.Data.LoadContextAlive | Should -BeFalse
    }

    It 'sanitizes an immediate provider disposal failure without rooting the collectible context' {
        $payloadRoot = Join-Path $TestDrive 'immediate-disposal-failure-provider'
        $providerPath = New-GraphKitAuthProviderFixtureAssembly -Root $payloadRoot
        Copy-Item -LiteralPath $script:contractsPath -Destination (Join-Path $payloadRoot 'out/GraphKit.Auth.Contracts.dll')
        $harnessPath = New-GraphKitAuthRuntimeHarnessAssembly -Root (Join-Path $TestDrive 'immediate-disposal-failure-harness')
        $disposeMarker = Join-Path $TestDrive 'immediate-disposal-failure-marker.txt'

        $result = Invoke-GraphKitAuthRuntimeProbe -ContractsPath (Join-Path $payloadRoot 'out/GraphKit.Auth.Contracts.dll') `
            -PayloadRoot (Split-Path -Parent $providerPath) -Scenario ImmediateDisposalFailure `
            -DisposeMarker $disposeMarker -HarnessPath $harnessPath

        $result.ExitCode | Should -Be 0 -Because $result.Output
        foreach ($failure in @($result.Data.FirstFailure, $result.Data.TaskFailure, $result.Data.RepeatedFailure)) {
            $failure | Should -Match 'type=GraphKit\.Auth\.GraphAuthException'
            $failure | Should -Match 'code=provider_disposal_failed;category=ProviderLifecycle'
            $failure | Should -Not -Match 'ProviderOwned|isolated-provider|Microsoft\.Identity'
            $failure | Should -Not -Match 'dataCount=[1-9]'
        }
        $result.Data.DisposeCount | Should -Be 1
        $result.Data.ProxyInnerCleared | Should -BeTrue
        $result.Data.ProxyOwnerCleared | Should -BeTrue
        $result.Data.HostProviderReferencesCleared | Should -BeTrue
        $result.Data.LoadContextAliveWhileHostAndTaskReferenced | Should -BeFalse `
            -Because 'the disposed host and its faulted task may retain only default-context sanitized failures'
    }

    It 'reports a deferred provider disposal failure through the shared shutdown completion after the active call drains' {
        $payloadRoot = Join-Path $TestDrive 'deferred-disposal-failure-provider'
        $providerPath = New-GraphKitAuthProviderFixtureAssembly -Root $payloadRoot
        Copy-Item -LiteralPath $script:contractsPath -Destination (Join-Path $payloadRoot 'out/GraphKit.Auth.Contracts.dll')
        $harnessPath = New-GraphKitAuthRuntimeHarnessAssembly -Root (Join-Path $TestDrive 'deferred-disposal-failure-harness')
        $disposeMarker = Join-Path $TestDrive 'deferred-disposal-failure-marker.txt'

        $result = Invoke-GraphKitAuthRuntimeProbe -ContractsPath (Join-Path $payloadRoot 'out/GraphKit.Auth.Contracts.dll') `
            -PayloadRoot (Split-Path -Parent $providerPath) -Scenario DeferredDisposalFailure `
            -DisposeMarker $disposeMarker -HarnessPath $harnessPath

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Data.Deferred.OwnerReturnedWithinDeadline | Should -BeTrue
        $result.Data.Deferred.RetiredInnerPresentWhileAcquireBlocked | Should -BeTrue
        $result.Data.Deferred.LoadContextAliveWhileAcquireBlocked | Should -BeTrue
        $result.Data.Deferred.AcquireFailure | Should -BeNullOrEmpty `
            -Because 'deferred provider disposal failure belongs to the shared host shutdown channel, not the completed acquisition'
        foreach ($failure in @($result.Data.LaterFailure, $result.Data.RepeatedFailure, $result.Data.TaskFailure)) {
            $failure | Should -Match 'type=GraphKit\.Auth\.GraphAuthException'
            $failure | Should -Match 'code=provider_disposal_failed;category=ProviderLifecycle'
            $failure | Should -Not -Match 'ProviderOwned|isolated-provider|Microsoft\.Identity'
            $failure | Should -Not -Match 'dataCount=[1-9]'
        }
        $result.Data.DisposeCount | Should -Be 1
        $result.Data.ProxyInnerCleared | Should -BeTrue
        $result.Data.ProxyRetiredInnerCleared | Should -BeTrue
        $result.Data.ProxyOwnerCleared | Should -BeTrue
        $result.Data.HostProviderReferencesCleared | Should -BeTrue
        $result.Data.LoadContextAliveWhileHostAndTaskReferenced | Should -BeFalse
    }

    It 'rejects same-path contracts bytes that no longer match the resident default-context assembly' {
        $fixtureRoot = Join-Path $TestDrive 'same-path-replacement'
        $providerPath = New-GraphKitAuthProviderFixtureAssembly -Root (Join-Path $fixtureRoot 'provider')
        $payloadRoot = Split-Path -Parent $providerPath
        $payloadContractsPath = Join-Path $payloadRoot 'GraphKit.Auth.Contracts.dll'
        Copy-Item -LiteralPath $script:contractsPath -Destination $payloadContractsPath
        $replacementPath = New-GraphKitAuthContractsFixtureAssembly `
            -Root (Join-Path $fixtureRoot 'replacement-contracts') -Marker 'GraphKit.Auth.Abi/999'
        (Get-FileHash -LiteralPath $payloadContractsPath -Algorithm SHA256).Hash |
            Should -Not -Be (Get-FileHash -LiteralPath $replacementPath -Algorithm SHA256).Hash

        $result = Invoke-GraphKitAuthRuntimeProbe -ContractsPath $payloadContractsPath `
            -PayloadRoot $payloadRoot -Scenario SamePathReplacement -ReplacementContractsPath $replacementPath

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Data.Message | Should -Match 'fresh PowerShell process'
        $result.Data.Message | Should -Match '(?i)contracts.*(identity|MVID|resident|candidate)'
    }

    It 'rejects a counterfeit System-prefixed assembly from a provider public signature' {
        $fixtureRoot = Join-Path $TestDrive 'counterfeit-system-provider'
        $impostorPath = New-SystemImpostorFixtureAssembly -Root (Join-Path $fixtureRoot 'impostor')
        $providerPath = New-GraphKitAuthProviderFixtureAssembly -Root (Join-Path $fixtureRoot 'provider') `
            -AdditionalReferencePath $impostorPath `
            -PublicSurfaceDeclaration 'public System.Impostor.Counterfeit Counterfeit => new();'
        $payloadRoot = Split-Path -Parent $providerPath
        $payloadContractsPath = Join-Path $payloadRoot 'GraphKit.Auth.Contracts.dll'
        $payloadImpostorPath = Join-Path $payloadRoot 'System.Impostor.dll'
        Copy-Item -LiteralPath $script:contractsPath -Destination $payloadContractsPath
        $payloadImpostorPath | Should -Exist -Because 'the counterfeit dependency must be physically available to exercise loader trust'

        $result = Invoke-GraphKitAuthRuntimeProbe -ContractsPath $payloadContractsPath `
            -PayloadRoot $payloadRoot -Scenario HostLoadFailure -PreloadPath $payloadImpostorPath

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Data.Message | Should -Match '(?i)(counterfeit|only framework|trusted platform|public surface)'
    }

    It 'accepts a proven same-object case alias but still resolves the physical payload root' {
        $fixtureRoot = Join-Path $TestDrive 'case-alias-provider'
        $providerPath = New-GraphKitAuthProviderFixtureAssembly -Root $fixtureRoot
        $payloadRoot = Split-Path -Parent $providerPath
        $payloadContractsPath = Join-Path $payloadRoot 'GraphKit.Auth.Contracts.dll'
        Copy-Item -LiteralPath $script:contractsPath -Destination $payloadContractsPath

        $parent = Split-Path -Parent $payloadRoot
        $leaf = Split-Path -Leaf $payloadRoot
        $aliasLeaf = $leaf.ToUpperInvariant()
        if ($aliasLeaf -ceq $leaf) {
            $aliasLeaf = $leaf.ToLowerInvariant()
        }
        $aliasRoot = Join-Path $parent $aliasLeaf
        $actualEntries = @(Get-ChildItem -LiteralPath $parent -Directory | Where-Object Name -CEQ $leaf)
        $actualEntries.Count | Should -Be 1 -Because 'the fresh fixture parent must contain exactly one physical payload directory'

        if (Test-Path -LiteralPath $aliasRoot -PathType Container) {
            $sentinelName = 'same-object-sentinel.txt'
            Set-Content -LiteralPath (Join-Path $payloadRoot $sentinelName) -Value 'same-object' -NoNewline
            (Get-Content -LiteralPath (Join-Path $aliasRoot $sentinelName) -Raw) |
                Should -BeExactly 'same-object' -Because 'the filesystem, not an OS-name assumption, must prove the alias is the same object'

            $result = Invoke-GraphKitAuthRuntimeProbe -ContractsPath $payloadContractsPath `
                -PayloadRoot $aliasRoot -Scenario HostLoadFailure

            $result.ExitCode | Should -Be 0 -Because $result.Output
            $result.Data.Message | Should -BeNullOrEmpty -Because 'a case spelling for the same physical payload must not be treated as a second package'
        }
        else {
            $aliasRoot | Should -Not -Exist -Because 'case-sensitive filesystems correctly have no same-object alias to exercise'
        }
    }

    It 'preserves GraphAuthException failures without catching and relabeling them' {
        $payloadRoot = Join-Path $TestDrive 'failing-provider'
        $providerPath = New-GraphKitAuthProviderFixtureAssembly -Root $payloadRoot
        Copy-Item -LiteralPath $script:contractsPath -Destination (Join-Path $payloadRoot 'out/GraphKit.Auth.Contracts.dll')

        $result = Invoke-GraphKitAuthRuntimeProbe -ContractsPath (Join-Path $payloadRoot 'out/GraphKit.Auth.Contracts.dll') `
            -PayloadRoot (Split-Path -Parent $providerPath) -Scenario ProviderFailure

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Data.Type | Should -BeExactly 'GraphKit.Auth.GraphAuthException'
        $result.Data.Code | Should -BeExactly 'fixture'
        $result.Data.Category | Should -BeExactly 'Fixture'
        $result.Data.Message | Should -BeExactly 'provider failure'
        $result.Data.RetryAfterSeconds | Should -Be 7
        $result.Data.CorrelationId | Should -BeExactly 'fixture-correlation'
        $result.Data.InnerIsNull | Should -BeTrue
    }

    It 'rejects a provider whose assembly version is not the declared package version' {
        $payloadRoot = Join-Path $TestDrive 'wrong-version-provider'
        $providerPath = New-GraphKitAuthProviderFixtureAssembly -Root $payloadRoot -AssemblyVersion '1.0.0.0'
        Copy-Item -LiteralPath $script:contractsPath -Destination (Join-Path $payloadRoot 'out/GraphKit.Auth.Contracts.dll')

        $result = Invoke-GraphKitAuthRuntimeProbe -ContractsPath (Join-Path $payloadRoot 'out/GraphKit.Auth.Contracts.dll') `
            -PayloadRoot (Split-Path -Parent $providerPath) -Scenario VersionMismatch

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Data.Message | Should -Match 'version'
        $result.Data.Message | Should -Match '9\.0\.0\.0'
    }

    It 'gives fresh-PowerShell guidance when the default context contains a different contracts copy' {
        $payloadRoot = Join-Path $TestDrive 'incompatible-default-contracts'
        $providerPath = New-GraphKitAuthProviderFixtureAssembly -Root $payloadRoot
        Copy-Item -LiteralPath $script:contractsPath -Destination (Join-Path $payloadRoot 'out/GraphKit.Auth.Contracts.dll')

        $result = Invoke-GraphKitAuthRuntimeProbe -ContractsPath $script:contractsPath `
            -PayloadRoot (Split-Path -Parent $providerPath) -Scenario IncompatibleDefault

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Data.Message | Should -Match 'fresh PowerShell process'
        $result.Data.Message | Should -Match 'contracts'
    }

    It 'rejects a provider file whose assembly name is not GraphKit.Auth' {
        $fixtureRoot = Join-Path $TestDrive 'wrong-name-provider'
        $wrongProviderPath = New-GraphKitAuthProviderFixtureAssembly -Root $fixtureRoot -AssemblyName 'Wrong.Auth'
        $payloadRoot = Join-Path $fixtureRoot 'payload'
        $null = New-Item -ItemType Directory -Path $payloadRoot -Force
        Copy-Item -LiteralPath $script:contractsPath -Destination (Join-Path $payloadRoot 'GraphKit.Auth.Contracts.dll')
        Copy-Item -LiteralPath $wrongProviderPath -Destination (Join-Path $payloadRoot 'GraphKit.Auth.dll')

        $result = Invoke-GraphKitAuthRuntimeProbe -ContractsPath (Join-Path $payloadRoot 'GraphKit.Auth.Contracts.dll') `
            -PayloadRoot $payloadRoot -Scenario HostLoadFailure

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Data.Message | Should -Match "provider assembly 'Wrong.Auth'"
        $result.Data.Message | Should -Match "not 'GraphKit.Auth'"
    }
}
