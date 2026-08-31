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
