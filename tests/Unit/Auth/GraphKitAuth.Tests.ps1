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
            [string] $AssemblyVersion = '1.0.0.0'
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
    public IGraphTokenSource Create(GraphTokenRequest request) => new FixtureTokenSource(request);
}

internal sealed class FixtureTokenSource : IGraphTokenSource
{
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
    }
}
'@
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

    function Invoke-GraphKitAuthRuntimeProbe {
        param(
            [Parameter(Mandatory)] [string] $ContractsPath,
            [string] $PayloadRoot,
            [Parameter(Mandatory)] [ValidateSet('Validation', 'Lifecycle', 'ProviderFailure', 'VersionMismatch', 'IncompatibleDefault', 'HostLoadFailure')] [string] $Scenario,
            [string] $DisposeMarker
        )

        $probePath = Join-Path $TestDrive ('Probe-Runtime-' + [guid]::NewGuid().ToString('N') + '.ps1')
        Set-Content -LiteralPath $probePath -NoNewline -Encoding utf8NoBOM -Value @'
param(
    [Parameter(Mandatory)] [string] $ContractsPath,
    [string] $PayloadRoot,
    [Parameter(Mandatory)] [string] $Scenario,
    [string] $DisposeMarker
)
$ErrorActionPreference = 'Stop'
$null = [System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath(
    (Resolve-Path -LiteralPath $ContractsPath).ProviderPath
)

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
        & $Action
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
}
'@

        $arguments = @(
            '-NoLogo', '-NoProfile', '-File', $probePath,
            '-ContractsPath', $ContractsPath,
            '-Scenario', $Scenario
        )
        if ($PayloadRoot) { $arguments += @('-PayloadRoot', $PayloadRoot) }
        if ($DisposeMarker) { $arguments += @('-DisposeMarker', $DisposeMarker) }
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
