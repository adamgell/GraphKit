$requiredGraphKitAuthFiles = @(
    'GraphKit.Auth.Contracts.dll'
    'GraphKit.Auth.dll'
    'GraphKit.Auth.deps.json'
    'Microsoft.Identity.Client.dll'
    'Microsoft.IdentityModel.Abstractions.dll'
)

$graphKitAuthArchiveAliasCases = @(
    @{ Kind = 'portable case alias'; Entries = @(
        'Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll'
        'assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll'
    ) }
    @{ Kind = 'separator alias'; Entries = @(
        'Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll'
        'Assemblies\GraphKit.Auth\GraphKit.Auth.Contracts.dll'
    ) }
    @{ Kind = 'duplicate exact path'; Entries = @(
        'Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll'
        'Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll'
    ) }
    @{ Kind = 'Unicode normalization alias'; Entries = @(
        "Assemblies/GraphKit.Auth/probé.dll"
        "Assemblies/GraphKit.Auth/probe$([char]0x0301).dll"
    ) }
)

$windowsAclMutationCases = if ($IsWindows) {
    @(
        @{ Kind = 'extra principal' }
        @{ Kind = 'unprotected DACL' }
        @{ Kind = 'inherited ACE' }
        @{ Kind = 'missing owner read rights' }
    )
}
else {
    @()
}

$windowsInitialAccessCases = if ($IsWindows) { @(@{}) } else { @() }
$unixInitialAccessCases = if ($IsWindows) { @() } else { @(@{}) }
$unixRootAliasCases = if ($IsWindows) { @() } else {
    @(@{ RootKind = 'auth' }, @{ RootKind = 'capture' }, @{ RootKind = 'stage' })
}
$windowsRootAliasCases = if ($IsWindows) {
    @(@{ RootKind = 'auth' }, @{ RootKind = 'capture' }, @{ RootKind = 'stage' })
}
else { @() }
$portableRootAliasCases = @(
    @{ RootKind = 'auth'; AliasName = 'graphkit.auth' }
    @{ RootKind = 'capture'; AliasName = 'Capture' }
    @{ RootKind = 'stage'; AliasName = 'Stage' }
)
$portableVersionAliasCases = @(
    @{
        Kind = 'case'
        ExpectedName = '0.4.0-r8.fixture.version-alias'
        AliasName = '0.4.0-r8.fixture.VERSION-ALIAS'
    }
    @{
        Kind = 'NFC'
        ExpectedName = '0.4.0-r8.fixture.vérsion-alias'
        AliasName = '0.4.0-r8.fixture.vérsion-alias'.Normalize([Text.NormalizationForm]::FormD)
    }
)
$linuxAtomicRenameCases = if ($IsLinux) { @(@{}) } else { @() }
$linuxCaseSensitiveStageAliasCases = if ($IsLinux) { @(@{}) } else { @() }

BeforeAll {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $script:requiredGraphKitAuthFiles = @(
        'GraphKit.Auth.Contracts.dll'
        'GraphKit.Auth.dll'
        'GraphKit.Auth.deps.json'
        'Microsoft.Identity.Client.dll'
        'Microsoft.IdentityModel.Abstractions.dll'
    )
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:taskPath = Join-Path $script:repoRoot '.build/GraphKitAuth.tasks.ps1'
    if (Test-Path -LiteralPath $script:taskPath -PathType Leaf) {
        . $script:taskPath -SkipTaskRegistration
    }

    $script:sourceManifest = Import-PowerShellDataFile -Path (Join-Path $script:repoRoot 'source/GraphKit.psd1')
    $script:baseVersion = [string] $script:sourceManifest.ModuleVersion
    $script:builtModuleRoot = Join-Path $script:repoRoot "output/module/GraphKit/$script:baseVersion"
    $script:builtManifestPath = Join-Path $script:builtModuleRoot 'GraphKit.psd1'
    $script:fullVersion = $null
    $script:packagePath = $null
    $script:stagePath = $null
    $script:packageEntries = @()

    if (Test-Path -LiteralPath $script:builtManifestPath -PathType Leaf) {
        $builtManifest = Import-PowerShellDataFile -Path $script:builtManifestPath
        $prerelease = [string] $builtManifest.PrivateData.PSData.Prerelease
        $script:fullVersion = if ([string]::IsNullOrWhiteSpace($prerelease)) { $script:baseVersion } else { "$script:baseVersion-$prerelease" }
        $script:packagePath = Join-Path $script:repoRoot "output/GraphKit.$script:fullVersion.nupkg"
        $stageVersionRoot = Join-Path $script:repoRoot "output/GraphKit.Auth/stage/$script:fullVersion"
        if (Test-Path -LiteralPath $stageVersionRoot -PathType Container) {
            $stageDirectories = @(Get-ChildItem -LiteralPath $stageVersionRoot -Directory -Force)
            if ($stageDirectories.Count -eq 1) { $script:stagePath = $stageDirectories[0].FullName }
        }
    }
    if ($script:packagePath -and (Test-Path -LiteralPath $script:packagePath -PathType Leaf)) {
        $archive = [IO.Compression.ZipFile]::OpenRead($script:packagePath)
        try { $script:packageEntries = @($archive.Entries) } finally { $archive.Dispose() }
    }

    function Assert-GraphKitAuthStageCommands {
        foreach ($commandName in @(
            'New-GraphKitAuthSealedStage'
            'Test-GraphKitAuthSealedStage'
            'Invoke-GraphKitAuthPrepareClean'
        )) {
            if (-not (Get-Command -Name $commandName -CommandType Function -ErrorAction SilentlyContinue)) {
                throw "Task 5 staging command '$commandName' is not implemented."
            }
        }
    }

    function Assert-GraphKitAuthArchivePaths {
        param([Parameter(Mandatory)] [string[]] $Entries)
        $portable = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $normalized = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($entryPath in $Entries) {
            $segments = @($entryPath -split '/')
            if ([string]::IsNullOrWhiteSpace($entryPath) -or [IO.Path]::IsPathRooted($entryPath) -or
                $entryPath -match '^[A-Za-z]:' -or $entryPath.IndexOf('\') -ge 0 -or
                $segments -contains '' -or $segments -contains '.' -or $segments -contains '..') {
                throw "Unsafe GraphKit.Auth archive entry '$entryPath'."
            }
            if (-not $portable.Add($entryPath)) { throw "Duplicate or portable-case GraphKit.Auth archive entry '$entryPath'." }
            if (-not $normalized.Add($entryPath.Normalize([Text.NormalizationForm]::FormC))) {
                throw "Unicode-normalization GraphKit.Auth archive alias '$entryPath'."
            }
        }
    }

    function Get-GraphKitAuthArchiveHash {
        param([string] $PackagePath, [string] $EntryPath)
        $archive = [IO.Compression.ZipFile]::OpenRead($PackagePath)
        try {
            $matches = @($archive.Entries | Where-Object FullName -CEQ $EntryPath)
            if ($matches.Count -ne 1) { throw "Expected one '$EntryPath' archive entry." }
            $stream = $matches[0].Open()
            try {
                $sha = [Security.Cryptography.SHA256]::Create()
                try { return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() }
                finally { $sha.Dispose() }
            }
            finally { $stream.Dispose() }
        }
        finally { $archive.Dispose() }
    }

    function Set-GraphKitAuthTestStageWritable {
        param([Parameter(Mandatory)] [string] $StagePath)
        $payloadPath = Join-Path $StagePath 'payload'
        $versionPath = Split-Path $StagePath -Parent
        if ($IsWindows) {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
            foreach ($directoryPath in @($versionPath, $StagePath, $payloadPath)) {
                $acl = Get-Acl -LiteralPath $directoryPath
                $acl.SetAccessRuleProtection($true, $false)
                $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                    $identity, [Security.AccessControl.FileSystemRights]::FullControl,
                    [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit,
                    [Security.AccessControl.PropagationFlags]::None,
                    [Security.AccessControl.AccessControlType]::Allow)
                $acl.SetAccessRule($rule)
                Set-Acl -LiteralPath $directoryPath -AclObject $acl
            }
            Get-ChildItem -LiteralPath $StagePath -File -Recurse -Force | ForEach-Object { $_.IsReadOnly = $false }
        }
        else {
            & chmod 0700 $versionPath $StagePath $payloadPath
            if ($LASTEXITCODE -ne 0) { throw 'Could not open the stage fixture for mutation.' }
            Get-ChildItem -LiteralPath $StagePath -File -Recurse -Force | ForEach-Object { & chmod 0600 $_.FullName }
            if ($LASTEXITCODE -ne 0) { throw 'Could not open the stage files for mutation.' }
        }
    }

    function Set-GraphKitAuthTestStageSealed {
        param(
            [Parameter(Mandatory)] [string] $StagePath,
            [string] $LeaveWritablePath
        )
        Initialize-GraphKitAuthStageCapture
        $leave = if ([string]::IsNullOrWhiteSpace($LeaveWritablePath)) {
            $null
        }
        else {
            [IO.Path]::GetFullPath($LeaveWritablePath)
        }
        foreach ($file in @(Get-ChildItem -LiteralPath $StagePath -File -Recurse -Force)) {
            if ($null -ne $leave -and [IO.Path]::GetFullPath($file.FullName) -ceq $leave) { continue }
            if ($file.LinkType -in @('SymbolicLink','Junction')) { continue }
            $script:GraphKitAuthStageCaptureType::SetOwnerOnly($file.FullName, $false, $false)
        }
        foreach ($directory in @(
            Get-ChildItem -LiteralPath $StagePath -Directory -Recurse -Force |
                Where-Object { $_.LinkType -notin @('SymbolicLink','Junction') } |
                Sort-Object { $_.FullName.Length } -Descending
        )) {
            $script:GraphKitAuthStageCaptureType::SetOwnerOnly($directory.FullName, $true, $false)
        }
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly($StagePath, $true, $false)
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly((Split-Path $StagePath -Parent), $true, $false)
    }

    function Get-GraphKitAuthTestDirectorySecurity {
        param([Parameter(Mandatory)][string] $Path)
        if ($IsWindows) { return (Get-Acl -LiteralPath $Path).Sddl }
        return [int][IO.File]::GetUnixFileMode($Path)
    }

    function Set-GraphKitAuthTestTreeWritable {
        param([Parameter(Mandatory)][string] $Path)
        if (-not (Test-Path -LiteralPath $Path)) { return }
        if ($IsWindows) {
            Get-ChildItem -LiteralPath $Path -File -Recurse -Force -ErrorAction SilentlyContinue |
                ForEach-Object { $_.IsReadOnly = $false }
            foreach ($directory in @(Get-ChildItem -LiteralPath $Path -Directory -Recurse -Force -ErrorAction SilentlyContinue |
                Sort-Object { $_.FullName.Length } -Descending) + @(Get-Item -LiteralPath $Path -Force)) {
                $script:GraphKitAuthStageCaptureType::SetOwnerOnly($directory.FullName, $true, $true)
            }
        }
        else {
            & chmod -R u+rwX $Path
            if ($LASTEXITCODE -ne 0) { throw "Could not make test tree '$Path' writable." }
        }
    }

    function New-GraphKitAuthStageFixture {
        param([Parameter(Mandatory)] [string] $Name)
        Assert-GraphKitAuthStageCommands
        if (-not $script:stagePath) { throw 'The packed candidate has no sealed source stage to use as fixture input.' }
        $fixtureOutput = Join-Path $TestDrive ("stage-fixture-$Name-" + [guid]::NewGuid().ToString('N'))
        New-GraphKitAuthSealedStage -OutputRoot $fixtureOutput `
            -FullVersion ("0.4.0-r8.fixture.$Name." + [guid]::NewGuid().ToString('N')) `
            -PayloadSourceRoot (Join-Path $script:stagePath 'payload')
    }

    function Invoke-GraphKitAuthStageMutation {
        param([string] $Kind, [string] $StagePath)
        Set-GraphKitAuthTestStageWritable -StagePath $StagePath
        $payloadPath = Join-Path $StagePath 'payload'
        $targetPath = Join-Path $payloadPath 'GraphKit.Auth.dll'
        switch ($Kind) {
            'missing' { [IO.File]::Delete($targetPath) }
            'extra' { [IO.File]::WriteAllText((Join-Path $payloadPath 'extra.dll'), 'extra') }
            'renamed' { [IO.File]::Move($targetPath, (Join-Path $payloadPath 'GraphKit.Auth.renamed.dll')) }
            'writable' { if ($IsWindows) { (Get-Item $targetPath).IsReadOnly = $false } else { & chmod 0600 $targetPath } }
            'byte-mutated' { [IO.File]::WriteAllText($targetPath, 'mutated') }
            'byte-identical-replaced' {
                $bytes = [IO.File]::ReadAllBytes($targetPath)
                $replacement = Join-Path $payloadPath ('.replacement-' + [guid]::NewGuid().ToString('N'))
                [IO.File]::WriteAllBytes($replacement, $bytes)
                [IO.File]::Delete($targetPath)
                [IO.File]::Move($replacement, $targetPath)
            }
            'hard-link' {
                $outsideLink = Join-Path $TestDrive ('GraphKit.Auth.hardlink-' + [guid]::NewGuid().ToString('N') + '.dll')
                $null = New-Item -ItemType HardLink -Path $outsideLink -Target $targetPath -ErrorAction Stop
            }
            'escaped-link' {
                $outsidePath = Join-Path $TestDrive ('outside-' + [guid]::NewGuid().ToString('N') + '.dll')
                [IO.File]::WriteAllText($outsidePath, 'outside'); [IO.File]::Delete($targetPath)
                $null = New-Item -ItemType SymbolicLink -Path $targetPath -Target $outsidePath -ErrorAction Stop
            }
            'case-alias' {
                $temporary = Join-Path $payloadPath ('.case-' + [guid]::NewGuid().ToString('N'))
                [IO.File]::Move($targetPath, $temporary)
                [IO.File]::Move($temporary, (Join-Path $payloadPath 'graphkit.auth.dll'))
            }
            'separator-alias' {
                if ($IsWindows) {
                    $manifestPath = Join-Path $StagePath 'manifest.json'
                    [IO.File]::WriteAllText($manifestPath, ([IO.File]::ReadAllText($manifestPath).Replace('payload/GraphKit.Auth.dll', 'payload\GraphKit.Auth.dll')))
                }
                else {
                    [IO.File]::Copy($targetPath, [IO.Path]::Combine(
                        $payloadPath, 'GraphKit.Auth\GraphKit.Auth.dll'))
                }
            }
            'unicode-alias' {
                [IO.File]::Copy($targetPath, (Join-Path $payloadPath "probé.dll"))
                try { [IO.File]::Copy($targetPath, (Join-Path $payloadPath "probe$([char]0x0301).dll")) }
                catch [IO.IOException] {
                    # APFS commonly aliases composed and decomposed names. The first extra
                    # file is still a zero-skip normalization mutation for stage validation.
                }
            }
            'platform-directory-alias' {
                $outsidePayload = Join-Path $TestDrive ('payload-alias-target-' + [guid]::NewGuid().ToString('N'))
                $null = New-Item -ItemType Directory -Path $outsidePayload
                foreach ($file in @(Get-ChildItem -LiteralPath $payloadPath -File -Force)) {
                    [IO.File]::Copy($file.FullName, (Join-Path $outsidePayload $file.Name))
                }
                Remove-Item -LiteralPath $payloadPath -Recurse -Force
                $kind = if ($IsWindows) { 'Junction' } else { 'SymbolicLink' }
                $null = New-Item -ItemType $kind -Path $payloadPath -Target $outsidePayload -ErrorAction Stop
            }
            default { throw "Unknown mutation '$Kind'." }
        }
        $leaveWritable = if ($Kind -ceq 'writable') { $targetPath } else { $null }
        Set-GraphKitAuthTestStageSealed -StagePath $StagePath -LeaveWritablePath $leaveWritable
    }

    function Set-GraphKitAuthWindowsAclMutation {
        param(
            [Parameter(Mandatory)] [string] $StagePath,
            [Parameter(Mandatory)] [string] $Kind
        )
        if (-not $IsWindows) { throw 'Windows ACL mutations are Windows-only.' }
        $payloadPath = Join-Path $StagePath 'payload'
        $targetPath = Join-Path $payloadPath 'GraphKit.Auth.dll'
        $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $worldSid = [Security.Principal.SecurityIdentifier]::new(
            [Security.Principal.WellKnownSidType]::WorldSid, $null)
        switch ($Kind) {
            'extra principal' {
                $acl = Get-Acl -LiteralPath $targetPath
                $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                    $worldSid, [Security.AccessControl.FileSystemRights]::Read,
                    [Security.AccessControl.AccessControlType]::Allow))
                Set-Acl -LiteralPath $targetPath -AclObject $acl
            }
            'unprotected DACL' {
                $acl = Get-Acl -LiteralPath $targetPath
                $acl.SetAccessRuleProtection($false, $false)
                Set-Acl -LiteralPath $targetPath -AclObject $acl
            }
            'inherited ACE' {
                $parentAcl = Get-Acl -LiteralPath $payloadPath
                $parentAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                    $worldSid, [Security.AccessControl.FileSystemRights]::Read,
                    [Security.AccessControl.InheritanceFlags]::ObjectInherit,
                    [Security.AccessControl.PropagationFlags]::None,
                    [Security.AccessControl.AccessControlType]::Allow))
                Set-Acl -LiteralPath $payloadPath -AclObject $parentAcl
                $acl = Get-Acl -LiteralPath $targetPath
                $acl.SetAccessRuleProtection($false, $false)
                Set-Acl -LiteralPath $targetPath -AclObject $acl
            }
            'missing owner read rights' {
                $acl = Get-Acl -LiteralPath $targetPath
                $acl.PurgeAccessRules($currentSid)
                $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                    $currentSid, [Security.AccessControl.FileSystemRights]::ReadAttributes,
                    [Security.AccessControl.AccessControlType]::Allow))
                Set-Acl -LiteralPath $targetPath -AclObject $acl
            }
            default { throw "Unknown Windows ACL mutation '$Kind'." }
        }
    }

    function Invoke-GraphKitAuthSealedPayloadProbe {
        param([Parameter(Mandatory)] [string] $PayloadRoot)
        $probePath = Join-Path $TestDrive ('Probe-GraphKitAuthPackage-' + [guid]::NewGuid().ToString('N') + '.ps1')
        $defaultMsalPath = Join-Path $script:repoRoot `
            'output/RequiredModules/Microsoft.Graph.Authentication/2.38.1/Dependencies/Core/Microsoft.Identity.Client.dll'
        if (-not (Test-Path -LiteralPath $defaultMsalPath -PathType Leaf)) {
            throw "The package probe prerequisite '$defaultMsalPath' is missing."
        }
        Set-Content -LiteralPath $probePath -NoNewline -Encoding utf8NoBOM -Value @'
param(
    [Parameter(Mandatory)] [string] $PayloadRoot,
    [Parameter(Mandatory)] [string] $DefaultMsalPath
)
$ErrorActionPreference = 'Stop'
$defaultContext = [Runtime.Loader.AssemblyLoadContext]::Default
$defaultMsalAssembly = $defaultContext.LoadFromAssemblyPath(
    (Resolve-Path -LiteralPath $DefaultMsalPath).ProviderPath)
$defaultMsalBeforeMvid = $defaultMsalAssembly.ManifestModule.ModuleVersionId
$defaultMsalBeforeLocation = $defaultMsalAssembly.Location
Add-Type -TypeDefinition @"
using System;
using System.Reflection;

public static class GraphKitAuthPackageProbeInspector
{
    public static int ReadAcquireCount(object source)
    {
        const BindingFlags Flags = BindingFlags.Instance | BindingFlags.NonPublic;
        object inner = source.GetType().GetField("_inner", Flags)?.GetValue(source)
            ?? throw new InvalidOperationException("The package source proxy has no provider inner source.");
        object client = inner.GetType().GetField("_client", Flags)?.GetValue(inner)
            ?? throw new InvalidOperationException("The provider source has no authentication client.");
        PropertyInfo property = client.GetType().GetProperty("AcquireCount", Flags)
            ?? throw new InvalidOperationException("The provider client has no acquisition counter.");
        return (int)(property.GetValue(client)
            ?? throw new InvalidOperationException("The provider acquisition counter is null."));
    }
}
"@
$contracts = [Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath(
    (Resolve-Path -LiteralPath (Join-Path $PayloadRoot 'GraphKit.Auth.Contracts.dll')).ProviderPath)
function Get-PackageAssemblyEvidence {
    param([Parameter(Mandatory)][Reflection.Assembly] $Assembly)
    $identity = $Assembly.GetName()
    $location = [IO.Path]::GetFullPath($Assembly.Location)
    $sha256 = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($location))).ToLowerInvariant()
    return [pscustomobject]@{
        Identity = "$($identity.Name), Version=$($identity.Version)"
        Location = $location
        Mvid = $Assembly.ManifestModule.ModuleVersionId.ToString('D')
        Sha256 = $sha256
    }
}
function Invoke-PackageRuntimeBoundary {
    param(
        [string] $Root,
        [Reflection.Assembly] $DefaultMsalAssembly
    )
    $rsa = [Security.Cryptography.RSA]::Create(2048)
    try {
        $certificateRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=GraphKit package probe',$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $certificate = $certificateRequest.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1),[DateTimeOffset]::UtcNow.AddMinutes(5))
        $credential = [GraphKit.Auth.CertificateCredential]::new($certificate,$true)
        $request = [GraphKit.Auth.GraphTokenRequest]::new('Global',[guid]'00000000-0000-0000-0000-000000000001',[uri]'https://login.microsoftonline.com',[uri]'https://graph.microsoft.com',[Nullable[guid]][guid]'00000000-0000-0000-0000-000000000002',[GraphKit.Auth.GraphAuthMode]::Certificate,$credential,'package-probe')
        $authHost = [GraphKit.Auth.GraphAuthHost]::new($Root,[version]'1.0.0.0',[timespan]::FromSeconds(2))
        $source = $authHost.CreateSource($request)
        $weakReference = $authHost.LoadContextWeakReference
        $providerAssembly = [GraphKit.Auth.GraphAuthHost].GetField('_providerAssembly',[Reflection.BindingFlags]'Instance,NonPublic').GetValue($authHost)
        $providerContext = [Runtime.Loader.AssemblyLoadContext]::GetLoadContext($providerAssembly)
        $providerMsalAssemblies = @($providerContext.Assemblies | Where-Object { $_.GetName().Name -ceq 'Microsoft.Identity.Client' })
        if ($providerMsalAssemblies.Count -ne 1) {
            throw "The provider context contained $($providerMsalAssemblies.Count) Microsoft.Identity.Client assemblies."
        }
        $providerMsal = $providerMsalAssemblies[0]
        $providerIdentityModelAssemblies = @($providerContext.Assemblies | Where-Object {
            $_.GetName().Name -ceq 'Microsoft.IdentityModel.Abstractions'
        })
        if ($providerIdentityModelAssemblies.Count -ne 1) {
            throw "The provider context contained $($providerIdentityModelAssemblies.Count) Microsoft.IdentityModel.Abstractions assemblies."
        }
        $providerIdentityModel = $providerIdentityModelAssemblies[0]
        $names = @($providerContext.Assemblies | ForEach-Object { $_.GetName().Name } | Sort-Object -Unique)
        $canRefresh = $source.CanRefresh
        $providerMsalDistinctFromDefault = -not [object]::ReferenceEquals($providerMsal, $DefaultMsalAssembly)
        $providerMsalContextName = $providerContext.Name
        $providerMsalContextCollectible = $providerContext.IsCollectible
        $providerAcquireCount = [GraphKitAuthPackageProbeInspector]::ReadAcquireCount($source)
        $providerEvidence = Get-PackageAssemblyEvidence -Assembly $providerAssembly
        $providerMsalEvidence = Get-PackageAssemblyEvidence -Assembly $providerMsal
        $providerIdentityModelEvidence = Get-PackageAssemblyEvidence -Assembly $providerIdentityModel
        $providerIdentityModel = $null
        $providerIdentityModelAssemblies = $null
        $providerMsal = $null
        $providerMsalAssemblies = $null
        $providerContext = $null
        $providerAssembly = $null
        $source.Dispose()
        $source = $null
        $authHost.Dispose()
        $authHost = $null
        return [pscustomobject]@{
            WeakReference = $weakReference
            CollectibleAssemblies = $names
            CanRefresh = $canRefresh
            ProviderMsalDistinctFromDefault = $providerMsalDistinctFromDefault
            ProviderMsalContextName = $providerMsalContextName
            ProviderMsalContextCollectible = $providerMsalContextCollectible
            ProviderAcquireCount = $providerAcquireCount
            ProviderIdentity = $providerEvidence.Identity
            ProviderLocation = $providerEvidence.Location
            ProviderMvid = $providerEvidence.Mvid
            ProviderSha256 = $providerEvidence.Sha256
            ProviderMsalIdentity = $providerMsalEvidence.Identity
            ProviderMsalLocation = $providerMsalEvidence.Location
            ProviderMsalMvid = $providerMsalEvidence.Mvid
            ProviderMsalSha256 = $providerMsalEvidence.Sha256
            ProviderIdentityModelIdentity = $providerIdentityModelEvidence.Identity
            ProviderIdentityModelLocation = $providerIdentityModelEvidence.Location
            ProviderIdentityModelMvid = $providerIdentityModelEvidence.Mvid
            ProviderIdentityModelSha256 = $providerIdentityModelEvidence.Sha256
        }
    }
    finally {
        if ($null -ne $source) { try { $source.Dispose() } catch {} }
        if ($null -ne $authHost) { try { $authHost.Dispose() } catch {} }
        $rsa.Dispose()
    }

}
$runtime = Invoke-PackageRuntimeBoundary -Root $PayloadRoot -DefaultMsalAssembly $defaultMsalAssembly
for ($i=0; $i -lt 30 -and $runtime.WeakReference.IsAlive; $i++) { [GC]::Collect(); [GC]::WaitForPendingFinalizers(); [GC]::Collect() }
$contractsLoaded = @([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'GraphKit.Auth.Contracts' })
$defaultMsalAfter = @([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {
    $_.GetName().Name -ceq 'Microsoft.Identity.Client' -and
    [Runtime.Loader.AssemblyLoadContext]::GetLoadContext($_) -eq $defaultContext
})
$defaultMsalReferenceUnchanged = $defaultMsalAfter.Count -eq 1 -and
    [object]::ReferenceEquals($defaultMsalAfter[0], $defaultMsalAssembly)
[pscustomobject]@{
    ContractsCount = $contractsLoaded.Count
    ContractsContext = [Runtime.Loader.AssemblyLoadContext]::GetLoadContext($contractsLoaded[0]).Name
    CollectibleAssemblies = $runtime.CollectibleAssemblies
    DefaultMsalPreloaded = $null -ne $defaultMsalAssembly
    DefaultMsalReferenceUnchanged = $defaultMsalReferenceUnchanged
    DefaultMsalMvidUnchanged = $defaultMsalReferenceUnchanged -and
        $defaultMsalAfter[0].ManifestModule.ModuleVersionId -eq $defaultMsalBeforeMvid
    DefaultMsalLocationUnchanged = $defaultMsalReferenceUnchanged -and
        $defaultMsalAfter[0].Location -ceq $defaultMsalBeforeLocation
    DefaultMsalUnchanged = $defaultMsalReferenceUnchanged -and
        $defaultMsalAfter[0].ManifestModule.ModuleVersionId -eq $defaultMsalBeforeMvid -and
        $defaultMsalAfter[0].Location -ceq $defaultMsalBeforeLocation
    ProviderMsalDistinctFromDefault = $runtime.ProviderMsalDistinctFromDefault
    ProviderMsalContextName = $runtime.ProviderMsalContextName
    ProviderMsalContextCollectible = $runtime.ProviderMsalContextCollectible
    ProviderAcquireCount = $runtime.ProviderAcquireCount
    ProviderIdentity = $runtime.ProviderIdentity
    ProviderLocation = $runtime.ProviderLocation
    ProviderMvid = $runtime.ProviderMvid
    ProviderSha256 = $runtime.ProviderSha256
    ProviderMsalIdentity = $runtime.ProviderMsalIdentity
    ProviderMsalMvid = $runtime.ProviderMsalMvid
    ProviderMsalLocation = $runtime.ProviderMsalLocation
    ProviderMsalSha256 = $runtime.ProviderMsalSha256
    ProviderIdentityModelIdentity = $runtime.ProviderIdentityModelIdentity
    ProviderIdentityModelLocation = $runtime.ProviderIdentityModelLocation
    ProviderIdentityModelMvid = $runtime.ProviderIdentityModelMvid
    ProviderIdentityModelSha256 = $runtime.ProviderIdentityModelSha256
    CanRefresh = $runtime.CanRefresh
    LoadContextAlive = $runtime.WeakReference.IsAlive
} | ConvertTo-Json -Compress
'@
        $raw = & pwsh -NoLogo -NoProfile -File $probePath -PayloadRoot $PayloadRoot `
            -DefaultMsalPath $defaultMsalPath 2>&1
        $json = @($raw | Where-Object { $_ -is [string] -and $_.TrimStart().StartsWith('{') }) | Select-Object -Last 1
        [pscustomobject]@{ ExitCode=$LASTEXITCODE; Data=if ($json) { $json | ConvertFrom-Json } else { $null }; Output=($raw | Out-String).Trim() }
    }
}

Describe 'GraphKit.Auth sealed staging implementation' -Tag 'QA' {
    It 'provides the private build task and native capture helper' {
        Test-Path -LiteralPath $script:taskPath -PathType Leaf | Should -BeTrue
        $taskSource = Get-Content -LiteralPath $script:taskPath -Raw
        $helperPath = Join-Path $script:repoRoot 'scripts/private/GraphKit.AuthStageCapture.cs'
        Test-Path -LiteralPath $helperPath -PathType Leaf | Should -BeTrue
        $helperSource = Get-Content -LiteralPath $helperPath -Raw
        $helperSource | Should -Match 'EntryPoint = "fstat\$INODE64"'
        $helperSource | Should -Match 'Architecture\.X64 => fstat_inode64\('
        $taskSource | Should -Match 'if \(\$LASTEXITCODE -ne 1\)' `
            -Because 'only git check-ignore exit 1 proves the unrelated sentinel is not ignored'
        { Assert-GraphKitAuthStageCommands } | Should -Not -Throw
    }

    It 'refuses an existing full-version stage without changing its bytes' {
        Assert-GraphKitAuthStageCommands
        $fixtureOutput = Join-Path $TestDrive ('stage-existing-' + [guid]::NewGuid().ToString('N'))
        $fixtureVersion = '0.4.0-r8.fixture.existing'
        try {
            $first = New-GraphKitAuthSealedStage -OutputRoot $fixtureOutput -FullVersion $fixtureVersion -PayloadSourceRoot (Join-Path $script:stagePath 'payload')
            $before = (Get-FileHash -LiteralPath (Join-Path $first.StagePath 'manifest.json') -Algorithm SHA256).Hash
            { New-GraphKitAuthSealedStage -OutputRoot $fixtureOutput -FullVersion $fixtureVersion -PayloadSourceRoot (Join-Path $script:stagePath 'payload') } | Should -Throw '*already exists*'
            (Get-FileHash -LiteralPath (Join-Path $first.StagePath 'manifest.json') -Algorithm SHA256).Hash | Should -BeExactly $before
        }
        finally {
            Invoke-GraphKitAuthPrepareClean -OutputRoot $fixtureOutput | Out-Null
        }
    }

    It 'refuses to unseal a forged prior stage and leaves it in place' {
        $fixture = New-GraphKitAuthStageFixture -Name 'forged-clean'
        try {
            Set-GraphKitAuthTestStageWritable -StagePath $fixture.StagePath
            $manifestPath = Join-Path $fixture.StagePath 'manifest.json'
            [IO.File]::WriteAllText($manifestPath, '{"forged":true}')
            Set-GraphKitAuthTestStageSealed -StagePath $fixture.StagePath

            { Invoke-GraphKitAuthPrepareClean -OutputRoot (Split-Path (Split-Path (Split-Path $fixture.StagePath -Parent) -Parent) -Parent) } |
                Should -Throw '*manifest digest does not match*'
            Test-Path -LiteralPath $fixture.StagePath -PathType Container | Should -BeTrue
            (Get-Content -LiteralPath $manifestPath -Raw) | Should -BeExactly '{"forged":true}'
        }
        finally {
            Set-GraphKitAuthTestStageWritable -StagePath $fixture.StagePath
        }
    }

    It 'rejects a sealed stage after <Kind> mutation' -ForEach @(
        @{ Kind='missing'; ExpectedDiagnostic='payload closure is not exact' }
        @{ Kind='extra'; ExpectedDiagnostic='payload closure is not exact' }
        @{ Kind='renamed'; ExpectedDiagnostic='payload closure is not exact' }
        @{ Kind='writable'; ExpectedDiagnostic='payload evidence failed' }
        @{ Kind='byte-mutated'; ExpectedDiagnostic='payload evidence failed' }
        @{ Kind='byte-identical-replaced'; ExpectedDiagnostic='payload evidence failed' }
        @{ Kind='hard-link'; ExpectedDiagnostic='payload evidence failed' }
        @{ Kind='escaped-link'; ExpectedDiagnostic='not the required no-follow regular file|without following a link|without following a reparse point' }
        @{ Kind='case-alias'; ExpectedDiagnostic='payload closure is not exact' }
        @{ Kind='separator-alias'; ExpectedDiagnostic='manifest digest does not match|unsafe or non-NFC name' }
        @{ Kind='unicode-alias'; ExpectedDiagnostic='unsafe or non-NFC name|portable alias|payload closure is not exact' }
        @{ Kind='platform-directory-alias'; ExpectedDiagnostic='not the required no-follow directory|without following a link|without following a reparse point' }
    ) {
        $fixture = New-GraphKitAuthStageFixture -Name $Kind
        try {
            Invoke-GraphKitAuthStageMutation -Kind $Kind -StagePath $fixture.StagePath
            $failure = $null
            try { $null = Test-GraphKitAuthSealedStage -StagePath $fixture.StagePath -FullVersion $fixture.FullVersion }
            catch { $failure = $_.Exception.Message }
            $failure | Should -Match $ExpectedDiagnostic
            $failure | Should -Not -Match 'version, envelope, or manifest is writable'
        }
        finally {
            Set-GraphKitAuthTestStageWritable -StagePath $fixture.StagePath
        }
    }

    It 'accepts an unmutated fixture after its exact sealed permissions are restored' {
        $fixture = New-GraphKitAuthStageFixture -Name 'resealed-control'
        try {
            Set-GraphKitAuthTestStageWritable -StagePath $fixture.StagePath
            Set-GraphKitAuthTestStageSealed -StagePath $fixture.StagePath

            { Test-GraphKitAuthSealedStage -StagePath $fixture.StagePath -FullVersion $fixture.FullVersion } |
                Should -Not -Throw
        }
        finally {
            Invoke-GraphKitAuthPrepareClean -OutputRoot (
                Split-Path (Split-Path (Split-Path $fixture.StagePath -Parent) -Parent) -Parent) | Out-Null
        }
    }

    It 'rejects a manifest hard link without an extra stage entry masking link count' {
        $fixture = New-GraphKitAuthStageFixture -Name 'manifest-hard-link'
        try {
            Set-GraphKitAuthTestStageWritable -StagePath $fixture.StagePath
            $manifestPath = Join-Path $fixture.StagePath 'manifest.json'
            $outsideLink = Join-Path $TestDrive ('manifest-hard-link-' + [guid]::NewGuid().ToString('N') + '.json')
            $null = New-Item -ItemType HardLink -Path $outsideLink -Target $manifestPath -ErrorAction Stop
            Set-GraphKitAuthTestStageSealed -StagePath $fixture.StagePath

            { Test-GraphKitAuthSealedStage -StagePath $fixture.StagePath -FullVersion $fixture.FullVersion } |
                Should -Throw '*manifest is not link-count one*'
        }
        finally {
            Set-GraphKitAuthTestStageWritable -StagePath $fixture.StagePath
        }
    }

    It 'allows exactly one atomic same-version creator after both candidates reach the install barrier' {
        Assert-GraphKitAuthStageCommands
        $fixtureOutput = Join-Path $TestDrive ('stage-concurrent-' + [guid]::NewGuid().ToString('N'))
        $fixtureVersion = '0.4.0-r8.fixture.concurrent'
        $barrierKey = 'GraphKit.Task5.StageBarrier.' + [guid]::NewGuid().ToString('N')
        $barrier = [Threading.Barrier]::new(2)
        [AppDomain]::CurrentDomain.SetData($barrierKey, $barrier)
        $workers = @()
        try {
            foreach ($workerId in 1..2) {
                $worker = [PowerShell]::Create()
                $null = $worker.AddScript({
                    param($TaskPath, $OutputRoot, $Version, $PayloadRoot, $BarrierKey, $WorkerId)
                    $ErrorActionPreference = 'Stop'
                    . $TaskPath -SkipTaskRegistration
                    try {
                        $stage = New-GraphKitAuthSealedStage -OutputRoot $OutputRoot `
                            -FullVersion $Version -PayloadSourceRoot $PayloadRoot `
                            -AfterVersionDestinationCheck {
                                $shared = [AppDomain]::CurrentDomain.GetData($BarrierKey)
                                if (-not $shared.SignalAndWait([TimeSpan]::FromSeconds(30))) {
                                    throw 'The same-version install barrier timed out.'
                                }
                            }
                        [pscustomobject]@{ Worker = $WorkerId; Succeeded = $true; StagePath = $stage.StagePath; Error = $null }
                    }
                    catch {
                        [pscustomobject]@{ Worker = $WorkerId; Succeeded = $false; StagePath = $null; Error = $_.Exception.Message }
                    }
                }).AddArgument($script:taskPath).AddArgument($fixtureOutput).AddArgument($fixtureVersion).
                    AddArgument((Join-Path $script:stagePath 'payload')).AddArgument($barrierKey).AddArgument($workerId)
                $workers += [pscustomobject]@{ PowerShell = $worker; Async = $worker.BeginInvoke() }
            }
            $results = @($workers | ForEach-Object { @($_.PowerShell.EndInvoke($_.Async)) })
            $resultSummary = $results | ConvertTo-Json -Depth 4 -Compress
            @($results | Where-Object Succeeded).Count | Should -Be 1 -Because $resultSummary
            @($results | Where-Object { -not $_.Succeeded }).Count | Should -Be 1
            $loser = @($results | Where-Object { -not $_.Succeeded })[0]
            $loser.Error | Should -Match 'atomic destination collision'
            $loser.Error | Should -Not -Match 'ambiguous cleanup|changed identity|resealing was refused|barrier timed out'
            $versionRoot = Join-Path $fixtureOutput "GraphKit.Auth/stage/$fixtureVersion"
            $entries = @([IO.Directory]::EnumerateFileSystemEntries($versionRoot))
            $entries.Count | Should -Be 1
            { Test-GraphKitAuthSealedStage -StagePath $entries[0] -FullVersion $fixtureVersion } |
                Should -Not -Throw
            @([IO.Directory]::EnumerateFileSystemEntries((Join-Path $fixtureOutput 'GraphKit.Auth/capture'))).Count |
                Should -Be 0
            @([IO.Directory]::EnumerateFileSystemEntries((Join-Path $fixtureOutput 'GraphKit.Auth/stage')) |
                Where-Object { [IO.Path]::GetFileName($_) -cne $fixtureVersion }).Count | Should -Be 0
        }
        finally {
            foreach ($worker in $workers) { $worker.PowerShell.Dispose() }
            $barrier.Dispose()
            [AppDomain]::CurrentDomain.SetData($barrierKey, $null)
            if (Test-Path -LiteralPath (Join-Path $fixtureOutput 'GraphKit.Auth/stage')) {
                Invoke-GraphKitAuthPrepareClean -OutputRoot $fixtureOutput | Out-Null
            }
        }
    }

    It 'preserves an identity-ambiguous losing install candidate without changing the winning version' {
        Assert-GraphKitAuthStageCommands
        $fixtureOutput = Join-Path $TestDrive ('stage-ambiguous-loser-' + [guid]::NewGuid().ToString('N'))
        $fixtureVersion = '0.4.0-r8.fixture.ambiguous-loser'
        $stageRoot = Join-Path $fixtureOutput 'GraphKit.Auth/stage'
        try {
            $winner = New-GraphKitAuthSealedStage -OutputRoot $fixtureOutput `
                -FullVersion $fixtureVersion -PayloadSourceRoot (Join-Path $script:stagePath 'payload')
            $winningManifestHash = (Get-FileHash -LiteralPath $winner.ManifestPath -Algorithm SHA256).Hash

            {
                New-GraphKitAuthSealedStage -OutputRoot $fixtureOutput `
                    -FullVersion $fixtureVersion -PayloadSourceRoot (Join-Path $script:stagePath 'payload') `
                    -BeforeVersionInstall {
                        param($temporaryVersionRoot)
                        $candidateEntries = @([IO.Directory]::EnumerateFileSystemEntries($temporaryVersionRoot))
                        if ($candidateEntries.Count -ne 1) {
                            throw 'The ambiguous-loser fixture did not receive one digest envelope.'
                        }
                        Set-GraphKitAuthTestStageWritable -StagePath $candidateEntries[0]
                        [IO.File]::WriteAllText(
                            (Join-Path $candidateEntries[0] 'payload/GraphKit.Auth.dll'),
                            'identity-ambiguous losing candidate')
                        Set-GraphKitAuthTestStageSealed -StagePath $candidateEntries[0]
                    }
            } | Should -Throw '*ambiguous cleanup was refused*'

            (Get-FileHash -LiteralPath $winner.ManifestPath -Algorithm SHA256).Hash |
                Should -BeExactly $winningManifestHash
            { Test-GraphKitAuthSealedStage -StagePath $winner.StagePath -FullVersion $fixtureVersion } |
                Should -Not -Throw
            $installRoots = @([IO.Directory]::EnumerateFileSystemEntries($stageRoot) | Where-Object {
                [IO.Path]::GetFileName($_).StartsWith('.install-', [StringComparison]::Ordinal)
            })
            $installRoots.Count | Should -Be 1
            $loserVersions = @([IO.Directory]::EnumerateFileSystemEntries($installRoots[0]))
            $loserVersions.Count | Should -Be 1
            [IO.Path]::GetFileName($loserVersions[0]) | Should -BeExactly $fixtureVersion
            $loserDigests = @([IO.Directory]::EnumerateFileSystemEntries($loserVersions[0]))
            $loserDigests.Count | Should -Be 1
            (Get-Content -LiteralPath (Join-Path $loserDigests[0] 'payload/GraphKit.Auth.dll') -Raw) |
                Should -BeExactly 'identity-ambiguous losing candidate'
            @([IO.Directory]::EnumerateFileSystemEntries((Join-Path $fixtureOutput 'GraphKit.Auth/capture'))).Count |
                Should -Be 0
        }
        finally {
            if (Test-Path -LiteralPath $stageRoot -PathType Container) {
                foreach ($installRoot in @([IO.Directory]::EnumerateFileSystemEntries($stageRoot) | Where-Object {
                    [IO.Path]::GetFileName($_).StartsWith('.install-', [StringComparison]::Ordinal)
                })) {
                    foreach ($file in @(Get-ChildItem -LiteralPath $installRoot -File -Recurse -Force)) {
                        $script:GraphKitAuthStageCaptureType::SetOwnerOnly($file.FullName, $false, $true)
                    }
                    foreach ($directory in @(Get-ChildItem -LiteralPath $installRoot -Directory -Recurse -Force |
                        Sort-Object { $_.FullName.Length } -Descending)) {
                        $script:GraphKitAuthStageCaptureType::SetOwnerOnly($directory.FullName, $true, $true)
                    }
                    $script:GraphKitAuthStageCaptureType::SetOwnerOnly($installRoot, $true, $true)
                    Remove-Item -LiteralPath $installRoot -Recurse -Force
                }
                Invoke-GraphKitAuthPrepareClean -OutputRoot $fixtureOutput | Out-Null
            }
        }
    }

    It 'preserves an ambiguous install wrapper after <MutationKind> before cleanup' -ForEach @(
        @{ MutationKind = 'unexpected sibling' }
        @{ MutationKind = 'wrapper replacement' }
    ) {
        Assert-GraphKitAuthStageCommands
        $fixtureOutput = Join-Path $TestDrive ('stage-wrapper-cleanup-' + [guid]::NewGuid().ToString('N'))
        $fixtureVersion = '0.4.0-r8.fixture.wrapper-cleanup'
        $stageRoot = Join-Path $fixtureOutput 'GraphKit.Auth/stage'
        try {
            $failure = $null
            try {
                $null = New-GraphKitAuthSealedStage -OutputRoot $fixtureOutput `
                    -FullVersion $fixtureVersion -PayloadSourceRoot (Join-Path $script:stagePath 'payload') `
                    -BeforeVersionInstall {
                        param($temporaryVersionRoot)
                        $installRoot = Split-Path $temporaryVersionRoot -Parent
                        $digestEntries = @([IO.Directory]::EnumerateFileSystemEntries($temporaryVersionRoot))
                        if ($digestEntries.Count -ne 1) { throw 'The wrapper-cleanup fixture expected one digest.' }
                        $script:GraphKitAuthStageCaptureType::SetOwnerOnly($temporaryVersionRoot, $true, $true)
                        if ($MutationKind -ceq 'unexpected sibling') {
                            $sibling = Join-Path $temporaryVersionRoot 'retained-unexpected-sibling'
                            $null = $script:GraphKitAuthStageCaptureType::CreateDirectoryOwnerOnly(
                                $temporaryVersionRoot, 'retained-unexpected-sibling')
                            $write = $script:GraphKitAuthStageCaptureType::WriteFileCreateNew(
                                $sibling, 'caller-owned.bin',
                                [Text.UTF8Encoding]::new($false).GetBytes('retained unexpected sibling'), $true)
                            $script:GraphKitAuthStageCaptureType::SetOwnerOnly(
                                $write.Destination.PhysicalPath, $false, $false)
                            $script:GraphKitAuthStageCaptureType::SetOwnerOnly($sibling, $true, $false)
                            $script:GraphKitAuthStageCaptureType::SetOwnerOnly($temporaryVersionRoot, $true, $false)
                        }
                        else {
                            $script:GraphKitAuthStageCaptureType::SetOwnerOnly($installRoot, $true, $true)
                            $backup = Join-Path $installRoot 'retained-original-wrapper'
                            [IO.Directory]::Move($temporaryVersionRoot, $backup)
                            $null = $script:GraphKitAuthStageCaptureType::CreateDirectoryOwnerOnly(
                                $installRoot, $fixtureVersion)
                            $replacement = Join-Path $installRoot $fixtureVersion
                            $digestName = [IO.Path]::GetFileName($digestEntries[0])
                            $digestSource = Join-Path $backup $digestName
                            $digestDestination = Join-Path $replacement $digestName
                            Set-GraphKitAuthTestStageWritable -StagePath $digestSource
                            [IO.Directory]::Move($digestSource, $digestDestination)
                            Set-GraphKitAuthTestStageSealed -StagePath $digestDestination
                            $write = $script:GraphKitAuthStageCaptureType::WriteFileCreateNew(
                                $backup, 'caller-owned.bin',
                                [Text.UTF8Encoding]::new($false).GetBytes('retained original wrapper'), $true)
                            $script:GraphKitAuthStageCaptureType::SetOwnerOnly(
                                $write.Destination.PhysicalPath, $false, $false)
                            $script:GraphKitAuthStageCaptureType::SetOwnerOnly($backup, $true, $false)
                            $script:GraphKitAuthStageCaptureType::SetOwnerOnly($replacement, $true, $false)
                        }
                        throw "injected $MutationKind before install"
                    }
            }
            catch { $failure = $_.Exception.Message }

            $failure | Should -Match 'ambiguous cleanup was refused'
            $failure | Should -Match ([regex]::Escape("injected $MutationKind before install"))
            if ($MutationKind -ceq 'unexpected sibling') {
                $failure | Should -Match 'temporary version wrapper closure is not exact'
            }
            else {
                $failure | Should -Match 'temporary version wrapper changed identity'
            }
            $installRoots = @([IO.Directory]::EnumerateFileSystemEntries($stageRoot) | Where-Object {
                [IO.Path]::GetFileName($_).StartsWith('.install-', [StringComparison]::Ordinal)
            })
            $installRoots.Count | Should -Be 1
            $retained = @(Get-ChildItem -LiteralPath $installRoots[0] -Filter 'caller-owned.bin' -File -Recurse -Force)
            $retained.Count | Should -Be 1
            (Get-Content -LiteralPath $retained[0].FullName -Raw) | Should -Match '^retained '
        }
        finally {
            Set-GraphKitAuthTestTreeWritable -Path $fixtureOutput
            Remove-Item -LiteralPath $fixtureOutput -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'removes only an identity-bound partial stage candidate after source link rejection' {
        Assert-GraphKitAuthStageCommands
        $fixtureRoot = Join-Path $TestDrive ('stage-partial-source-' + [guid]::NewGuid().ToString('N'))
        $fixtureOutput = Join-Path $fixtureRoot 'output'
        $source = Join-Path $fixtureRoot 'source'
        $null = New-Item -ItemType Directory -Path $source, $fixtureOutput -Force
        foreach ($name in $script:requiredGraphKitAuthFiles) {
            Copy-Item -LiteralPath (Join-Path $script:stagePath "payload/$name") `
                -Destination (Join-Path $source $name)
        }
        $outsideLink = Join-Path $fixtureRoot 'contracts-second-link.dll'
        $null = New-Item -ItemType HardLink -Path $outsideLink `
            -Target (Join-Path $source 'GraphKit.Auth.Contracts.dll') -ErrorAction Stop
        try {
            $failure = $null
            try {
                $null = New-GraphKitAuthSealedStage -OutputRoot $fixtureOutput `
                    -FullVersion '0.4.0-r8.fixture.partial-source' -PayloadSourceRoot $source
            }
            catch { $failure = $_.Exception.Message }
            $failure | Should -Match "capture source or destination 'GraphKit.Auth.Contracts.dll' is not link-count one"
            $failure | Should -Not -Match 'ambiguous cleanup|Original failure'
            @([IO.Directory]::EnumerateFileSystemEntries(
                (Join-Path $fixtureOutput 'GraphKit.Auth/capture'))).Count | Should -Be 0
            @([IO.Directory]::EnumerateFileSystemEntries(
                (Join-Path $fixtureOutput 'GraphKit.Auth/stage'))).Count | Should -Be 0
        }
        finally {
            if (Test-Path -LiteralPath $fixtureOutput) {
                Remove-Item -LiteralPath $fixtureOutput -Recurse -Force
            }
        }
    }

    It 'removes identity-bound owned state after injected <FailureKind> creation failure' -ForEach @(
        @{ FailureKind = 'capture payload' }
        @{ FailureKind = 'temporary install root' }
    ) {
        Assert-GraphKitAuthStageCommands
        $fixtureOutput = Join-Path $TestDrive ('stage-initialization-failure-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $fixtureOutput
        $failure = $null
        try {
            $null = New-GraphKitAuthSealedStage -OutputRoot $fixtureOutput `
                -FullVersion ('0.4.0-r8.fixture.initialization-' + $FailureKind.Replace(' ', '-')) `
                -PayloadSourceRoot (Join-Path $script:stagePath 'payload') `
                -AfterOwnedDirectoryCreate {
                    param($kind)
                    if ($kind -ceq $FailureKind) {
                        throw "injected $kind creation failure"
                    }
                }
        }
        catch { $failure = $_.Exception.Message }

        $failure | Should -Match ([regex]::Escape("injected $FailureKind creation failure"))
        $failure | Should -Not -Match 'ambiguous cleanup|Original failure'
        foreach ($rootName in @('capture','stage')) {
            $root = Join-Path $fixtureOutput "GraphKit.Auth/$rootName"
            if (Test-Path -LiteralPath $root -PathType Container) {
                @([IO.Directory]::EnumerateFileSystemEntries($root)).Count | Should -Be 0
            }
        }
    }

    It 'creates <DirectoryKind> with exact owner-only initial directory access' -ForEach @(
        @{ DirectoryKind = 'auth root' }
        @{ DirectoryKind = 'capture root' }
        @{ DirectoryKind = 'stage root' }
        @{ DirectoryKind = 'capture envelope' }
        @{ DirectoryKind = 'capture payload' }
        @{ DirectoryKind = 'temporary install root' }
        @{ DirectoryKind = 'temporary version root' }
    ) {
        Assert-GraphKitAuthStageCommands
        $fixtureOutput = Join-Path $TestDrive ('stage-initial-directory-access-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $fixtureOutput
        if (-not $IsWindows) { & chmod 0755 $fixtureOutput }
        $observed = [Collections.Generic.List[object]]::new()
        try {
            $fixture = New-GraphKitAuthSealedStage -OutputRoot $fixtureOutput `
                -FullVersion ('0.4.0-r8.fixture.initial-directory-' + $DirectoryKind.Replace(' ', '-')) `
                -PayloadSourceRoot (Join-Path $script:stagePath 'payload') `
                -AfterOwnedDirectoryCreate {
                    param($kind, $path, $initialEvidence)
                    if ($kind -ceq $DirectoryKind) { $observed.Add($initialEvidence) }
                }

            $observed.Count | Should -Be 1
            if ($IsWindows) {
                $observed[0].OwnerSid | Should -BeExactly $observed[0].CurrentIdentitySid
                $observed[0].AccessRulesProtected | Should -BeTrue
                $observed[0].HasInheritedAccessRules | Should -BeFalse
                $observed[0].ExactWritableOwnerOnlyDirectoryAccess | Should -BeTrue
            }
            else {
                $observed[0].UnixMode | Should -Be 0x1C0
            }
        }
        finally {
            Set-GraphKitAuthTestTreeWritable -Path $fixtureOutput
            Remove-Item -LiteralPath $fixtureOutput -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'refuses to claim a widened existing <RootKind> authority root without changing it' -ForEach @(
        @{ RootKind = 'auth' }
        @{ RootKind = 'capture' }
        @{ RootKind = 'stage' }
    ) {
        Assert-GraphKitAuthStageCommands
        $fixtureOutput = Join-Path $TestDrive ('stage-existing-root-policy-' + [guid]::NewGuid().ToString('N'))
        $baseline = New-GraphKitAuthSealedStage -OutputRoot $fixtureOutput `
            -FullVersion ('0.4.0-r8.fixture.existing-root-baseline-' + $RootKind) `
            -PayloadSourceRoot (Join-Path $script:stagePath 'payload')
        $authRoot = Split-Path (Split-Path (Split-Path $baseline.StagePath -Parent) -Parent) -Parent
        $roots = [ordered]@{
            auth = $authRoot
            capture = Join-Path $authRoot 'capture'
            stage = Join-Path $authRoot 'stage'
        }
        $target = $roots[$RootKind]
        $marker = Join-Path $target 'caller-owned-marker.bin'
        $markerBytes = [Text.UTF8Encoding]::new($false).GetBytes("caller-owned-$RootKind")
        $null = $script:GraphKitAuthStageCaptureType::WriteFileCreateNew(
            $target, 'caller-owned-marker.bin', $markerBytes, $false)
        if ($IsWindows) {
            $acl = Get-Acl -LiteralPath $target
            $acl.SetAccessRuleProtection($false, $false)
            Set-Acl -LiteralPath $target -AclObject $acl
        }
        else {
            & chmod 0755 $target
            if ($LASTEXITCODE -ne 0) { throw "Could not widen the existing $RootKind authority root." }
        }
        $evidenceBefore = [ordered]@{}
        $securityBefore = [ordered]@{}
        $entriesBefore = [ordered]@{}
        foreach ($entry in $roots.GetEnumerator()) {
            $evidenceBefore[$entry.Key] = $script:GraphKitAuthStageCaptureType::InspectDirectory(
                (Split-Path $entry.Value -Parent), [IO.Path]::GetFileName($entry.Value))
            $securityBefore[$entry.Key] = Get-GraphKitAuthTestDirectorySecurity -Path $entry.Value
            $entriesBefore[$entry.Key] = @([IO.Directory]::EnumerateFileSystemEntries($entry.Value) |
                ForEach-Object { [IO.Path]::GetFileName($_) } | Sort-Object)
        }
        $markerHash = (Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash
        try {
            $failure = $null
            try {
                $null = New-GraphKitAuthSealedStage -OutputRoot $fixtureOutput `
                    -FullVersion ('0.4.0-r8.fixture.existing-root-candidate-' + $RootKind) `
                    -PayloadSourceRoot (Join-Path $script:stagePath 'payload')
            }
            catch { $failure = $_.Exception.Message }

            $failure | Should -Match ([regex]::Escape("$RootKind root") + '.*exact current-owner-only writable.*before reuse')
            foreach ($entry in $roots.GetEnumerator()) {
                $current = $script:GraphKitAuthStageCaptureType::InspectDirectory(
                    (Split-Path $entry.Value -Parent), [IO.Path]::GetFileName($entry.Value))
                $current.NativeIdentity | Should -BeExactly $evidenceBefore[$entry.Key].NativeIdentity
                $current.PhysicalPath | Should -BeExactly $evidenceBefore[$entry.Key].PhysicalPath
                (Get-GraphKitAuthTestDirectorySecurity -Path $entry.Value) |
                    Should -BeExactly $securityBefore[$entry.Key]
                @([IO.Directory]::EnumerateFileSystemEntries($entry.Value) |
                    ForEach-Object { [IO.Path]::GetFileName($_) } | Sort-Object) |
                    Should -BeExactly $entriesBefore[$entry.Key]
            }
            (Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash | Should -BeExactly $markerHash
        }
        finally {
            Set-GraphKitAuthTestTreeWritable -Path $fixtureOutput
            Remove-Item -LiteralPath $fixtureOutput -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'creates the build authority root atomically before mutable build children' {
        Assert-GraphKitAuthStageCommands
        $fixtureOutput = Join-Path $TestDrive ('build-authority-root-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $fixtureOutput
        $observed = [Collections.Generic.List[object]]::new()
        try {
            $evidence = Initialize-GraphKitAuthBuildAuthorityRoot -OutputRoot $fixtureOutput `
                -AfterChildInspection {
                    param($kind, $path, $initialEvidence)
                    $observed.Add([pscustomobject]@{ Kind=$kind; Evidence=$initialEvidence })
                }
            $observed.Count | Should -Be 2
            (@($observed.Kind) -join '|') | Should -BeExactly 'build auth root|build capture root'
            foreach ($item in $observed) {
                $script:GraphKitAuthStageCaptureType::HasInitialOwnerOnlyDirectoryAccess($item.Evidence) |
                    Should -BeTrue
            }
            $script:GraphKitAuthStageCaptureType::HasInitialOwnerOnlyDirectoryAccess($evidence) |
                Should -BeTrue
            $taskSource = Get-Content -LiteralPath $script:taskPath -Raw
            $initializeIndex = $taskSource.IndexOf('Initialize-GraphKitAuthBuildAuthorityRoot -OutputRoot')
            $firstMutableChildIndex = $taskSource.IndexOf('[IO.Directory]::CreateDirectory($resultRoot)')
            $initializeIndex | Should -BeGreaterOrEqual 0
            $initializeIndex | Should -BeLessThan $firstMutableChildIndex
        }
        finally {
            Set-GraphKitAuthTestTreeWritable -Path $fixtureOutput
            Remove-Item -LiteralPath $fixtureOutput -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'leaves an exact Prepare-authorized topology after failure immediately following build authority initialization' {
        Assert-GraphKitAuthStageCommands
        $fixtureOutput = Join-Path $TestDrive ('build-authority-failure-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $fixtureOutput
        $failure = $null
        try {
            try {
                $null = Initialize-GraphKitAuthBuildAuthorityRoot -OutputRoot $fixtureOutput
                throw 'injected failure after build authority initialization'
            }
            catch { $failure = $_.Exception.Message }

            $failure | Should -BeExactly 'injected failure after build authority initialization'
            $authRoot = Join-Path $fixtureOutput 'GraphKit.Auth'
            $captureRoot = Join-Path $authRoot 'capture'
            $authEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory(
                $fixtureOutput, 'GraphKit.Auth')
            $captureEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory(
                $authRoot, 'capture')
            $script:GraphKitAuthStageCaptureType::HasInitialOwnerOnlyDirectoryAccess($authEvidence) |
                Should -BeTrue
            $script:GraphKitAuthStageCaptureType::HasInitialOwnerOnlyDirectoryAccess($captureEvidence) |
                Should -BeTrue
            @([IO.Directory]::EnumerateFileSystemEntries($captureRoot)).Count | Should -Be 0
            { Invoke-GraphKitAuthPrepareClean -OutputRoot $fixtureOutput } | Should -Not -Throw
            @(Invoke-GraphKitAuthPrepareClean -OutputRoot $fixtureOutput).Count | Should -Be 0
        }
        finally {
            Set-GraphKitAuthTestTreeWritable -Path $fixtureOutput
            Remove-Item -LiteralPath $fixtureOutput -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'rejects a portable <RootKind> root alias before changing its bytes or permissions' -ForEach $portableRootAliasCases {
        Assert-GraphKitAuthStageCommands
        $fixtureOutput = Join-Path $TestDrive ('stage-portable-root-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $fixtureOutput
        $authRoot = Join-Path $fixtureOutput 'GraphKit.Auth'
        $aliasParent = switch ($RootKind) {
            'auth' { $fixtureOutput }
            'capture' {
                $null = New-Item -ItemType Directory -Path $authRoot
                $script:GraphKitAuthStageCaptureType::SetOwnerOnly($authRoot, $true, $true)
                $authRoot
            }
            'stage' {
                $null = New-Item -ItemType Directory -Path (Join-Path $authRoot 'capture') -Force
                $script:GraphKitAuthStageCaptureType::SetOwnerOnly($authRoot, $true, $true)
                $script:GraphKitAuthStageCaptureType::SetOwnerOnly(
                    (Join-Path $authRoot 'capture'), $true, $true)
                $authRoot
            }
        }
        $requestedName = switch ($RootKind) {
            'auth' { 'GraphKit.Auth' }
            'capture' { 'capture' }
            'stage' { 'stage' }
        }
        $null = New-Item -ItemType Directory -Path (Join-Path $aliasParent $AliasName)
        $aliasEntry = @([IO.Directory]::EnumerateFileSystemEntries($aliasParent) | Where-Object {
            [IO.Path]::GetFileName($_).Normalize([Text.NormalizationForm]::FormC).Equals(
                $requestedName.Normalize([Text.NormalizationForm]::FormC),
                [StringComparison]::OrdinalIgnoreCase)
        })[0]
        $marker = Join-Path $aliasEntry 'caller-owned.txt'
        [IO.File]::WriteAllText($marker, 'caller-owned-portable-root')
        if (-not $IsWindows) { & chmod 0755 $aliasEntry }
        $securityBefore = Get-GraphKitAuthTestDirectorySecurity -Path $aliasEntry
        $hashBefore = (Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash
        try {
            $failure = $null
            try {
                $null = New-GraphKitAuthSealedStage -OutputRoot $fixtureOutput `
                    -FullVersion ("0.4.0-r8.fixture.portable-root-$RootKind") `
                    -PayloadSourceRoot (Join-Path $script:stagePath 'payload')
            }
            catch { $failure = $_.Exception.Message }

            $failure | Should -Match 'portable alias'
            (Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash | Should -BeExactly $hashBefore
            (Get-GraphKitAuthTestDirectorySecurity -Path $aliasEntry) | Should -BeExactly $securityBefore
            @([IO.Directory]::EnumerateFileSystemEntries($aliasEntry) | ForEach-Object {
                [IO.Path]::GetFileName($_)
            }) | Should -BeExactly @('caller-owned.txt')
        }
        finally {
            Set-GraphKitAuthTestTreeWritable -Path $fixtureOutput
            Remove-Item -LiteralPath $fixtureOutput -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'rejects a portable <Kind> version alias before atomic install without changing it' -ForEach $portableVersionAliasCases {
        Assert-GraphKitAuthStageCommands
        $fixtureOutput = Join-Path $TestDrive ('stage-portable-version-' + [guid]::NewGuid().ToString('N'))
        $stageRoot = Join-Path $fixtureOutput 'GraphKit.Auth/stage'
        $captureRoot = Join-Path $fixtureOutput 'GraphKit.Auth/capture'
        $null = New-Item -ItemType Directory -Path $stageRoot, $captureRoot -Force
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly((Join-Path $fixtureOutput 'GraphKit.Auth'), $true, $true)
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly($captureRoot, $true, $true)
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly($stageRoot, $true, $true)
        $null = New-Item -ItemType Directory -Path (Join-Path $stageRoot $AliasName)
        $aliasEntry = @([IO.Directory]::EnumerateFileSystemEntries($stageRoot) | Where-Object {
            [IO.Path]::GetFileName($_).Normalize([Text.NormalizationForm]::FormC).Equals(
                $ExpectedName.Normalize([Text.NormalizationForm]::FormC),
                [StringComparison]::OrdinalIgnoreCase)
        })[0]
        $marker = Join-Path $aliasEntry 'caller-owned.txt'
        [IO.File]::WriteAllText($marker, 'caller-owned-portable-version')
        if (-not $IsWindows) { & chmod 0755 $aliasEntry }
        $securityBefore = Get-GraphKitAuthTestDirectorySecurity -Path $aliasEntry
        $hashBefore = (Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash
        try {
            $failure = $null
            try {
                $null = New-GraphKitAuthSealedStage -OutputRoot $fixtureOutput `
                    -FullVersion $ExpectedName -PayloadSourceRoot (Join-Path $script:stagePath 'payload')
            }
            catch { $failure = $_.Exception.Message }

            $failure | Should -Match 'portable alias|stage version .* already exists\.$'
            $failure | Should -Not -Match 'MoveDirectoryCreateNew|atomically install|already exists or won'
            (Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash | Should -BeExactly $hashBefore
            (Get-GraphKitAuthTestDirectorySecurity -Path $aliasEntry) | Should -BeExactly $securityBefore
            @([IO.Directory]::EnumerateFileSystemEntries($aliasEntry) | ForEach-Object {
                [IO.Path]::GetFileName($_)
            }) | Should -BeExactly @('caller-owned.txt')
            @([IO.Directory]::EnumerateFileSystemEntries($captureRoot)).Count | Should -Be 0
            @([IO.Directory]::EnumerateFileSystemEntries($stageRoot)).Count | Should -Be 1
        }
        finally {
            Set-GraphKitAuthTestTreeWritable -Path $fixtureOutput
            Remove-Item -LiteralPath $fixtureOutput -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'refuses Prepare when the capture root retains an unverified entry without changing it' {
        Assert-GraphKitAuthStageCommands
        Initialize-GraphKitAuthStageCapture
        $fixtureOutput = Join-Path $TestDrive ('stage-prepare-capture-' + [guid]::NewGuid().ToString('N'))
        $authRoot = Join-Path $fixtureOutput 'GraphKit.Auth'
        $captureRoot = Join-Path $authRoot 'capture'
        $null = New-Item -ItemType Directory -Path $captureRoot -Force
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly($authRoot, $true, $true)
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly($captureRoot, $true, $true)
        $marker = Join-Path $captureRoot 'retained-ambiguous.bin'
        [IO.File]::WriteAllText($marker, 'retained-ambiguous-capture')
        $captureBefore = $script:GraphKitAuthStageCaptureType::InspectDirectory($authRoot, 'capture')
        $securityBefore = Get-GraphKitAuthTestDirectorySecurity -Path $captureRoot
        $hashBefore = (Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash
        try {
            { Invoke-GraphKitAuthPrepareClean -OutputRoot $fixtureOutput } |
                Should -Throw '*capture root*empty*'
            $captureAfter = $script:GraphKitAuthStageCaptureType::InspectDirectory($authRoot, 'capture')
            $captureAfter.NativeIdentity | Should -BeExactly $captureBefore.NativeIdentity
            $captureAfter.PhysicalPath | Should -BeExactly $captureBefore.PhysicalPath
            (Get-GraphKitAuthTestDirectorySecurity -Path $captureRoot) | Should -BeExactly $securityBefore
            (Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash | Should -BeExactly $hashBefore
        }
        finally {
            Set-GraphKitAuthTestTreeWritable -Path $fixtureOutput
            Remove-Item -LiteralPath $fixtureOutput -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'refuses Prepare when the <RootKind> authority root is not exact owner-only writable' -ForEach @(
        @{ RootKind = 'auth' }
        @{ RootKind = 'capture' }
        @{ RootKind = 'stage' }
    ) {
        $fixture = New-GraphKitAuthStageFixture -Name ('prepare-root-policy-' + $RootKind)
        $authRoot = Split-Path (Split-Path (Split-Path $fixture.StagePath -Parent) -Parent) -Parent
        $outputRoot = Split-Path $authRoot -Parent
        $roots = [ordered]@{
            auth = $authRoot
            capture = Join-Path $authRoot 'capture'
            stage = Join-Path $authRoot 'stage'
        }
        $target = $roots[$RootKind]
        if ($IsWindows) {
            $acl = Get-Acl -LiteralPath $target
            $acl.SetAccessRuleProtection($false, $false)
            Set-Acl -LiteralPath $target -AclObject $acl
        }
        else {
            & chmod 0755 $target
            if ($LASTEXITCODE -ne 0) { throw "Could not widen the $RootKind authority root fixture." }
        }
        $evidenceBefore = [ordered]@{}
        $securityBefore = [ordered]@{}
        foreach ($entry in $roots.GetEnumerator()) {
            $parent = Split-Path $entry.Value -Parent
            $name = [IO.Path]::GetFileName($entry.Value)
            $evidenceBefore[$entry.Key] = $script:GraphKitAuthStageCaptureType::InspectDirectory($parent, $name)
            $securityBefore[$entry.Key] = Get-GraphKitAuthTestDirectorySecurity -Path $entry.Value
        }
        $manifestHashBefore = (Get-FileHash -LiteralPath $fixture.ManifestPath -Algorithm SHA256).Hash
        $versionSecurityBefore = Get-GraphKitAuthTestDirectorySecurity -Path (Split-Path $fixture.StagePath -Parent)
        try {
            { Invoke-GraphKitAuthPrepareClean -OutputRoot $outputRoot } |
                Should -Throw "*Prepare $RootKind root*owner-only writable*"
            foreach ($entry in $roots.GetEnumerator()) {
                $current = $script:GraphKitAuthStageCaptureType::InspectDirectory(
                    (Split-Path $entry.Value -Parent), [IO.Path]::GetFileName($entry.Value))
                $current.NativeIdentity | Should -BeExactly $evidenceBefore[$entry.Key].NativeIdentity
                $current.PhysicalPath | Should -BeExactly $evidenceBefore[$entry.Key].PhysicalPath
                (Get-GraphKitAuthTestDirectorySecurity -Path $entry.Value) |
                    Should -BeExactly $securityBefore[$entry.Key]
            }
            (Get-FileHash -LiteralPath $fixture.ManifestPath -Algorithm SHA256).Hash |
                Should -BeExactly $manifestHashBefore
            (Get-GraphKitAuthTestDirectorySecurity -Path (Split-Path $fixture.StagePath -Parent)) |
                Should -BeExactly $versionSecurityBefore
        }
        finally {
            Set-GraphKitAuthTestTreeWritable -Path $outputRoot
            Remove-Item -LiteralPath $outputRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'rejects a portable collision in a complete directory-name set' {
        { Assert-GraphKitAuthPortableNameSet -Names @('release-v1', 'RELEASE-V1') `
            -Kind 'stage version namespace' } | Should -Throw '*portable alias*'
    }

    It 'refuses two independently valid portable-alias versions before changing either' -ForEach $linuxCaseSensitiveStageAliasCases -AllowNullOrEmptyForEach {
        $fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('stage-prepare-version-alias-' + [guid]::NewGuid().ToString('N'))
        $outputA = Join-Path $fixtureRoot 'output-a'
        $outputB = Join-Path $fixtureRoot 'output-b'
        $lowerVersion = '0.4.0-r8.fixture.prepare-alias'
        $upperVersion = '0.4.0-r8.fixture.PREPARE-ALIAS'
        try {
            $first = New-GraphKitAuthSealedStage -OutputRoot $outputA -FullVersion $lowerVersion `
                -PayloadSourceRoot (Join-Path $script:stagePath 'payload')
            $second = New-GraphKitAuthSealedStage -OutputRoot $outputB -FullVersion $upperVersion `
                -PayloadSourceRoot (Join-Path $script:stagePath 'payload')
            $stageRootA = Join-Path $outputA 'GraphKit.Auth/stage'
            $stageRootB = Join-Path $outputB 'GraphKit.Auth/stage'
            $versionRootA = Split-Path $first.StagePath -Parent
            $versionRootB = Split-Path $second.StagePath -Parent
            $movedVersionRootB = Join-Path $stageRootA $upperVersion
            try {
                $script:GraphKitAuthStageCaptureType::SetOwnerOnly($stageRootA, $true, $true)
                $script:GraphKitAuthStageCaptureType::SetOwnerOnly($stageRootB, $true, $true)
                # Linux Directory.Move probes both version directories in addition to their
                # rename parents. Temporarily restore owner-write on those sealed wrappers,
                # then reseal them before the assertions inspect either candidate.
                $script:GraphKitAuthStageCaptureType::SetOwnerOnly($versionRootA, $true, $true)
                $script:GraphKitAuthStageCaptureType::SetOwnerOnly($versionRootB, $true, $true)
                [IO.Directory]::Move($versionRootB, $movedVersionRootB)
            }
            finally {
                if (Test-Path -LiteralPath $versionRootA -PathType Container) {
                    $script:GraphKitAuthStageCaptureType::SetOwnerOnly($versionRootA, $true, $false)
                }
                if (Test-Path -LiteralPath $versionRootB -PathType Container) {
                    $script:GraphKitAuthStageCaptureType::SetOwnerOnly($versionRootB, $true, $false)
                }
                if (Test-Path -LiteralPath $movedVersionRootB -PathType Container) {
                    $script:GraphKitAuthStageCaptureType::SetOwnerOnly($movedVersionRootB, $true, $false)
                }
                if (Test-Path -LiteralPath $stageRootA -PathType Container) {
                    # Prepare owns mutations beneath this authority root, so the fixture
                    # must leave the parent writable while both candidate versions remain sealed.
                    $script:GraphKitAuthStageCaptureType::SetOwnerOnly($stageRootA, $true, $true)
                }
                if (Test-Path -LiteralPath $stageRootB -PathType Container) {
                    $script:GraphKitAuthStageCaptureType::SetOwnerOnly($stageRootB, $true, $false)
                }
            }
            $movedSecondStage = Join-Path $movedVersionRootB ([IO.Path]::GetFileName($second.StagePath))
            { Test-GraphKitAuthSealedStage -StagePath $first.StagePath -FullVersion $lowerVersion } |
                Should -Not -Throw
            { Test-GraphKitAuthSealedStage -StagePath $movedSecondStage -FullVersion $upperVersion } |
                Should -Not -Throw
            $versionPaths = @($versionRootA, (Split-Path $movedSecondStage -Parent))
            $securityBefore = @($versionPaths | ForEach-Object {
                Get-GraphKitAuthTestDirectorySecurity -Path $_
            })
            $hashesBefore = @($first.ManifestPath, (Join-Path $movedSecondStage 'manifest.json') | ForEach-Object {
                (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash
            })

            { Invoke-GraphKitAuthPrepareClean -OutputRoot $outputA } |
                Should -Throw '*stage version namespace*portable alias*'
            for ($index = 0; $index -lt $versionPaths.Count; $index++) {
                (Get-GraphKitAuthTestDirectorySecurity -Path $versionPaths[$index]) |
                    Should -BeExactly $securityBefore[$index]
            }
            @($first.ManifestPath, (Join-Path $movedSecondStage 'manifest.json') | ForEach-Object {
                (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash
            }) | Should -BeExactly $hashesBefore
        }
        finally {
            Set-GraphKitAuthTestTreeWritable -Path $fixtureRoot
            Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'handles unavailable Linux renameat2 as actionable fail-closed without a fallback' {
        $helper = Get-Content -LiteralPath (
            Join-Path $script:repoRoot 'scripts/private/GraphKit.AuthStageCapture.cs') -Raw
        $helper | Should -Match 'catch\s*\(EntryPointNotFoundException'
        $helper | Should -Match 'ENOSYS|errno\s*==\s*38'
        $helper | Should -Match 'renameat2[^\r\n]*unavailable[^\r\n]*no fallback'

        Initialize-GraphKitAuthStageCapture
        $normalizer = $script:GraphKitAuthStageCaptureType.GetMethod(
            'NormalizeWindowsPhysicalPath',
            [Reflection.BindingFlags]'NonPublic, Static')
        $normalizer | Should -Not -BeNullOrEmpty
        $normalizer.Invoke($null, [object[]] @('\\?\UNC\server\share\file.bin')) |
            Should -BeExactly '\\server\share\file.bin'
        $normalizer.Invoke($null, [object[]] @('\\?\C:\repo\file.bin')) |
            Should -BeExactly 'C:\repo\file.bin'
    }

    It 'reports an existing atomic destination as a collision and changes neither directory' {
        Initialize-GraphKitAuthStageCapture
        $root = Join-Path $TestDrive ('atomic-destination-collision-' + [guid]::NewGuid().ToString('N'))
        $source = Join-Path $root 'source-version'
        $destination = Join-Path $root 'final-version'
        $null = New-Item -ItemType Directory -Path $source, $destination -Force
        [IO.File]::WriteAllText((Join-Path $source 'source.bin'), 'source-unchanged')
        [IO.File]::WriteAllText((Join-Path $destination 'destination.bin'), 'destination-unchanged')
        $sourceBefore = $script:GraphKitAuthStageCaptureType::InspectDirectory($root, 'source-version')
        $destinationBefore = $script:GraphKitAuthStageCaptureType::InspectDirectory($root, 'final-version')
        $sourceHash = (Get-FileHash -LiteralPath (Join-Path $source 'source.bin') -Algorithm SHA256).Hash
        $destinationHash = (Get-FileHash -LiteralPath (Join-Path $destination 'destination.bin') -Algorithm SHA256).Hash

        { $script:GraphKitAuthStageCaptureType::MoveDirectoryCreateNew($source, $destination) } |
            Should -Throw '*atomic destination collision*'

        $sourceAfter = $script:GraphKitAuthStageCaptureType::InspectDirectory($root, 'source-version')
        $destinationAfter = $script:GraphKitAuthStageCaptureType::InspectDirectory($root, 'final-version')
        $sourceAfter.NativeIdentity | Should -BeExactly $sourceBefore.NativeIdentity
        $destinationAfter.NativeIdentity | Should -BeExactly $destinationBefore.NativeIdentity
        (Get-FileHash -LiteralPath (Join-Path $source 'source.bin') -Algorithm SHA256).Hash |
            Should -BeExactly $sourceHash
        (Get-FileHash -LiteralPath (Join-Path $destination 'destination.bin') -Algorithm SHA256).Hash |
            Should -BeExactly $destinationHash
    }

    It 'leaves source and destination unchanged when injected Linux renameat2 is unavailable' -ForEach $linuxAtomicRenameCases -AllowNullOrEmptyForEach {
        Initialize-GraphKitAuthStageCapture
        $root = Join-Path $TestDrive ('linux-renameat2-unavailable-' + [guid]::NewGuid().ToString('N'))
        $source = Join-Path $root 'source-version'
        $destination = Join-Path $root 'final-version'
        $null = New-Item -ItemType Directory -Path $source -Force
        $marker = Join-Path $source 'marker.bin'
        [IO.File]::WriteAllText($marker, 'atomic-source-unchanged')
        $sourceBefore = $script:GraphKitAuthStageCaptureType::InspectDirectory($root, 'source-version')
        $hashBefore = (Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash

        { $script:GraphKitAuthStageCaptureType::MoveDirectoryCreateNew($source, $destination, $true) } |
            Should -Throw '*Linux renameat2*unavailable*no fallback*'

        Test-Path -LiteralPath $destination | Should -BeFalse
        $sourceAfter = $script:GraphKitAuthStageCaptureType::InspectDirectory($root, 'source-version')
        $sourceAfter.NativeIdentity | Should -BeExactly $sourceBefore.NativeIdentity
        $sourceAfter.PhysicalPath | Should -BeExactly $sourceBefore.PhysicalPath
        (Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash | Should -BeExactly $hashBefore
    }

    It 'rejects an existing Unix <RootKind> symlink root without touching its target' -ForEach $unixRootAliasCases -AllowNullOrEmptyForEach {
        Assert-GraphKitAuthStageCommands
        $fixtureRoot = Join-Path $TestDrive ('stage-symlink-root-' + [guid]::NewGuid().ToString('N'))
        $fixtureOutput = Join-Path $fixtureRoot 'output'
        $external = Join-Path $fixtureRoot 'external'
        $null = New-Item -ItemType Directory -Path $fixtureOutput, $external -Force
        $marker = Join-Path $external 'caller-owned.txt'
        [IO.File]::WriteAllText($marker, 'caller-owned')
        & chmod 0755 $external
        $modeBefore = [IO.File]::GetUnixFileMode($external)
        $hashBefore = (Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash
        $authRoot = Join-Path $fixtureOutput 'GraphKit.Auth'
        $linkPath = switch ($RootKind) {
            'auth' { $authRoot }
            'capture' {
                $null = New-Item -ItemType Directory -Path $authRoot
                $script:GraphKitAuthStageCaptureType::SetOwnerOnly($authRoot, $true, $true)
                Join-Path $authRoot 'capture'
            }
            'stage' {
                $null = New-Item -ItemType Directory -Path (Join-Path $authRoot 'capture') -Force
                $script:GraphKitAuthStageCaptureType::SetOwnerOnly($authRoot, $true, $true)
                $script:GraphKitAuthStageCaptureType::SetOwnerOnly(
                    (Join-Path $authRoot 'capture'), $true, $true)
                Join-Path $authRoot 'stage'
            }
        }
        $null = New-Item -ItemType SymbolicLink -Path $linkPath -Target $external
        try {
            { New-GraphKitAuthSealedStage -OutputRoot $fixtureOutput -FullVersion "0.4.0-r8.fixture.symlink-$RootKind" `
                -PayloadSourceRoot (Join-Path $script:stagePath 'payload') } | Should -Throw '*without following*'

            (Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash | Should -BeExactly $hashBefore
            [IO.File]::GetUnixFileMode($external) | Should -Be $modeBefore
            @([IO.Directory]::EnumerateFileSystemEntries($external) | ForEach-Object { [IO.Path]::GetFileName($_) }) |
                Should -BeExactly @('caller-owned.txt')
        }
        finally {
            $stageItem = Get-Item -LiteralPath (Join-Path $authRoot 'stage') -Force -ErrorAction SilentlyContinue
            if ($null -ne $stageItem -and $stageItem.LinkType -notin @('SymbolicLink','Junction')) {
                Invoke-GraphKitAuthPrepareClean -OutputRoot $fixtureOutput | Out-Null
            }
            & chmod -R u+rwX $external
            [IO.File]::SetUnixFileMode($external, $modeBefore)
        }
    }

    It 'rejects an existing Windows <RootKind> junction root without touching its target' -ForEach $windowsRootAliasCases -AllowNullOrEmptyForEach {
        Assert-GraphKitAuthStageCommands
        $fixtureRoot = Join-Path $TestDrive ('stage-junction-root-' + [guid]::NewGuid().ToString('N'))
        $fixtureOutput = Join-Path $fixtureRoot 'output'
        $external = Join-Path $fixtureRoot 'external'
        $null = New-Item -ItemType Directory -Path $fixtureOutput, $external -Force
        $marker = Join-Path $external 'caller-owned.txt'
        [IO.File]::WriteAllText($marker, 'caller-owned')
        $aclBefore = (Get-Acl -LiteralPath $external).Sddl
        $hashBefore = (Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash
        $authRoot = Join-Path $fixtureOutput 'GraphKit.Auth'
        $linkPath = switch ($RootKind) {
            'auth' { $authRoot }
            'capture' {
                $null = New-Item -ItemType Directory -Path $authRoot
                $script:GraphKitAuthStageCaptureType::SetOwnerOnly($authRoot, $true, $true)
                Join-Path $authRoot 'capture'
            }
            'stage' {
                $null = New-Item -ItemType Directory -Path (Join-Path $authRoot 'capture') -Force
                $script:GraphKitAuthStageCaptureType::SetOwnerOnly($authRoot, $true, $true)
                $script:GraphKitAuthStageCaptureType::SetOwnerOnly(
                    (Join-Path $authRoot 'capture'), $true, $true)
                Join-Path $authRoot 'stage'
            }
        }
        $null = New-Item -ItemType Junction -Path $linkPath -Target $external
        try {
            { New-GraphKitAuthSealedStage -OutputRoot $fixtureOutput -FullVersion "0.4.0-r8.fixture.junction-$RootKind" `
                -PayloadSourceRoot (Join-Path $script:stagePath 'payload') } | Should -Throw '*without following*'

            (Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash | Should -BeExactly $hashBefore
            (Get-Acl -LiteralPath $external).Sddl | Should -BeExactly $aclBefore
            @([IO.Directory]::EnumerateFileSystemEntries($external) | ForEach-Object { [IO.Path]::GetFileName($_) }) |
                Should -BeExactly @('caller-owned.txt')
        }
        finally {
            $stageItem = Get-Item -LiteralPath (Join-Path $authRoot 'stage') -Force -ErrorAction SilentlyContinue
            if ($null -ne $stageItem -and $stageItem.LinkType -notin @('SymbolicLink','Junction')) {
                Invoke-GraphKitAuthPrepareClean -OutputRoot $fixtureOutput | Out-Null
            }
        }
    }

    It 'returns create-new initial-access evidence for the sealed manifest' {
        $fixture = New-GraphKitAuthStageFixture -Name 'manifest-initial'
        try {
            $fixture.PSObject.Properties.Name | Should -Contain 'ManifestInitialEvidence'
            $fixture.ManifestInitialEvidence.IsRegularFile | Should -BeTrue
            if ($IsWindows) {
                $fixture.ManifestInitialEvidence.OwnerOnlyAccess | Should -BeTrue
                $fixture.ManifestInitialEvidence.OwnerSid |
                    Should -BeExactly $fixture.ManifestInitialEvidence.CurrentIdentitySid
            }
            else {
                $fixture.ManifestInitialEvidence.UnixMode | Should -Be 0x180
            }
        }
        finally {
            Invoke-GraphKitAuthPrepareClean -OutputRoot (
                Split-Path (Split-Path (Split-Path $fixture.StagePath -Parent) -Parent) -Parent) | Out-Null
        }
    }

    It 'does not call wrong-owner Windows evidence owner-only at initial creation' {
        Initialize-GraphKitAuthStageCapture
        $evidence = [Activator]::CreateInstance($script:GraphKitAuthStageCaptureType.Assembly.GetType(
            $script:GraphKitAuthStageCaptureType.Namespace + '.GraphKitAuthPathEvidence'))
        $evidence.OwnerOnlyAccess = $true
        $evidence.OwnerSid = 'S-1-5-21-111'
        $evidence.CurrentIdentitySid = 'S-1-5-21-222'

        $script:GraphKitAuthStageCaptureType::HasInitialOwnerOnlyAccess($evidence) | Should -BeFalse
    }

    It 'records link count one for regular files but not directories' {
        Assert-GraphKitAuthStageCommands
        $verified = Test-GraphKitAuthSealedStage -StagePath $script:stagePath -FullVersion $script:fullVersion
        @($verified.Manifest.files).Count | Should -Be 5
        @($verified.Manifest.files | Where-Object linkCount -NE 1).Count | Should -Be 0
        $verified.Manifest.manifest.linkCount | Should -Be 1
        $verified.Manifest.directories.envelope.PSObject.Properties.Name | Should -Not -Contain 'linkCount'
        $verified.Manifest.directories.payload.PSObject.Properties.Name | Should -Not -Contain 'linkCount'
    }

    It 'restores every inherited process Git configuration value after a partial scope failure' {
        $before = @(Get-ChildItem Env: | Where-Object Name -Like 'GIT_CONFIG_*' | Sort-Object Name |
            ForEach-Object { "$($_.Name)=$($_.Value)" })
        $patterns = 1..5 | ForEach-Object { "/task5-exact-fixture-$_.dll" }
        { Enable-GraphKitAuthAbiTestGitExcludes -RepositoryRoot $script:repoRoot -Patterns $patterns `
            -AfterFirstEnvironmentWrite { throw 'injected partial environment failure' } } |
            Should -Throw '*injected partial environment failure*'
        $after = @(Get-ChildItem Env: | Where-Object Name -Like 'GIT_CONFIG_*' | Sort-Object Name |
            ForEach-Object { "$($_.Name)=$($_.Value)" })
        ($after -join '|') | Should -BeExactly ($before -join '|')
    }

    It 'does not delete a pre-existing projection path when cleanup has no fixture state' {
        $root = Join-Path $TestDrive ('projection-null-state-' + [guid]::NewGuid().ToString('N'))
        $preexisting = Join-Path $root 'src/GraphKit.Auth/GraphKit.Auth/bin/Release/net8.0/GraphKit.Auth.dll'
        $null = New-Item -ItemType Directory -Path (Split-Path $preexisting -Parent) -Force
        [IO.File]::WriteAllText($preexisting, 'caller-owned')
        $script:GraphKitAuthAbiFixtureState = $null

        { Remove-GraphKitAuthAbiTestFixture -RepositoryRoot $root } | Should -Not -Throw

        Test-Path -LiteralPath $preexisting -PathType Leaf | Should -BeTrue
        [IO.File]::ReadAllText($preexisting) | Should -BeExactly 'caller-owned'
    }

    It 'removes recorded empty projection directories after setup fails before a file is copied' {
        $root = Join-Path $TestDrive ('projection-directory-state-' + [guid]::NewGuid().ToString('N'))
        $bin = Join-Path $root 'src/GraphKit.Auth/GraphKit.Auth/bin'
        $release = Join-Path $bin 'Release'
        $destination = Join-Path $release 'net8.0'
        $null = [IO.Directory]::CreateDirectory($destination)
        $createdDirectories = [Collections.Generic.List[string]]::new()
        foreach ($directory in @($bin, $release, $destination)) {
            $createdDirectories.Add($directory)
        }
        $script:GraphKitAuthAbiFixtureState = [pscustomobject]@{
            BaselineState = $null
            StatusBefore = @()
            CreatedPaths = [Collections.Generic.List[string]]::new()
            CreatedDirectories = $createdDirectories
            Completed = $false
            ExpectedEvidence = [ordered]@{}
        }

        { Remove-GraphKitAuthAbiTestFixture -RepositoryRoot $root } | Should -Not -Throw

        Test-Path -LiteralPath $bin | Should -BeFalse
    }

    It 'deletes only a recorded projection and preserves an unrecorded partial materialization' {
        Initialize-GraphKitAuthStageCapture
        $root = Join-Path $TestDrive ('projection-partial-state-' + [guid]::NewGuid().ToString('N'))
        $source = Join-Path $root 'source'
        $destination = Join-Path $root 'src/GraphKit.Auth/GraphKit.Auth/bin/Release/net8.0'
        $null = New-Item -ItemType Directory -Path $source, $destination -Force
        [IO.File]::WriteAllBytes((Join-Path $source 'GraphKit.Auth.dll'), [byte[]](1..32))
        $copy = $script:GraphKitAuthStageCaptureType::CopyFileCreateNew(
            $source, 'GraphKit.Auth.dll', $destination, 'GraphKit.Auth.dll')
        $recorded = Join-Path $destination 'GraphKit.Auth.dll'
        $unrecorded = Join-Path $destination 'GraphKit.Auth.deps.json'
        [IO.File]::WriteAllText($unrecorded, 'partial-unregistered')
        $created = [Collections.Generic.List[string]]::new()
        $created.Add($recorded)
        $script:GraphKitAuthAbiFixtureState = [pscustomobject]@{
            BaselineState = $null
            StatusBefore = @()
            CreatedPaths = $created
            Completed = $false
            ExpectedEvidence = [ordered]@{ $recorded = $copy.Destination }
        }

        { Remove-GraphKitAuthAbiTestFixture -RepositoryRoot $root } | Should -Throw '*non-empty projected parent*'

        Test-Path -LiteralPath $recorded -PathType Leaf | Should -BeFalse
        Test-Path -LiteralPath $unrecorded -PathType Leaf | Should -BeTrue
        [IO.File]::ReadAllText($unrecorded) | Should -BeExactly 'partial-unregistered'
    }

    It 'declares and consumes the exact Windows owner-only ACL evidence schema' {
        $helper = Get-Content -LiteralPath (
            Join-Path $script:repoRoot 'scripts/private/GraphKit.AuthStageCapture.cs') -Raw
        $task = Get-Content -LiteralPath $script:taskPath -Raw
        Get-Command Set-GraphKitAuthWindowsAclMutation -CommandType Function -ErrorAction Stop |
            Should -Not -BeNullOrEmpty
        foreach ($property in @(
            'OwnerSid', 'CurrentIdentitySid', 'AccessRulesProtected',
            'HasInheritedAccessRules', 'ExactOwnerOnlyAccess'
        )) {
            $helper | Should -Match ([regex]::Escape($property + ' { get; init; }'))
            $task | Should -Match ([regex]::Escape('$Evidence.' + $property))
        }
        $helper | Should -Match 'directory \? FileSystemRights\.ReadAndExecute : FileSystemRights\.Read'
        $helper | Should -Match 'InheritanceFlags\.None'
    }

    It 'orders owner-only parent security before child creation and records initial child access' {
        $helper = Get-Content -LiteralPath (
            Join-Path $script:repoRoot 'scripts/private/GraphKit.AuthStageCapture.cs') -Raw
        $task = Get-Content -LiteralPath $script:taskPath -Raw
        $helper | Should -Match ([regex]::Escape('DestinationInitial { get; init; }'))
        $helper | Should -Match ([regex]::Escape('OwnerOnlyAccess { get; init; }'))
        $helper | Should -Match ([regex]::Escape(
            'options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite'))
        $helper | Should -Match 'writable.*ContainerInherit.*ObjectInherit'
        $newStage = [regex]::Match($task,
            '(?ms)^function New-GraphKitAuthSealedStage \{.*?^\}').Value
        $captureRootSecure = $newStage.IndexOf("-ChildName 'capture' -Kind 'capture root'")
        $captureSecure = $newStage.IndexOf('-ChildName $runId -Kind ''capture envelope''')
        $payloadSecure = $newStage.IndexOf("-ChildName 'payload' -Kind 'capture payload'")
        $captureRootSecure | Should -BeGreaterOrEqual 0
        $captureSecure | Should -BeGreaterThan $captureRootSecure
        $payloadSecure | Should -BeGreaterThan $captureSecure
        $initializer = [regex]::Match($task,
            '(?ms)^function Initialize-GraphKitAuthOwnerDirectory \{.*?^\}').Value
        $inspectBefore = $initializer.IndexOf('InspectDirectory($parent, $ChildName)')
        $validateExisting = $initializer.LastIndexOf('HasInitialOwnerOnlyDirectoryAccess($before)')
        $postCreateMutation = $initializer.IndexOf('SetOwnerOnly($child, $true, $true)')
        $inspectAfter = $initializer.LastIndexOf('InspectDirectory($parent, $ChildName)')
        $inspectBefore | Should -BeGreaterOrEqual 0
        $validateExisting | Should -BeGreaterThan $inspectBefore
        $postCreateMutation | Should -Be -1
        $inspectAfter | Should -BeGreaterThan $validateExisting
    }

    It 'requires initial owner-only access only for the sealed capture copy call' {
        $helper = Get-Content -LiteralPath (
            Join-Path $script:repoRoot 'scripts/private/GraphKit.AuthStageCapture.cs') -Raw
        $task = Get-Content -LiteralPath $script:taskPath -Raw
        $helper | Should -Match 'bool requireInitialOwnerOnly\s*=\s*false'
        $trueCalls = @([regex]::Matches($task,
            '(?s)CopyFileCreateNew\([^;]+?,\s*\$true\s*\)'))
        $trueCalls.Count | Should -Be 1
        $newStage = [regex]::Match($task,
            '(?ms)^function New-GraphKitAuthSealedStage \{.*?^\}').Value
        $newStage | Should -Match '(?s)CopyFileCreateNew\([^;]+?,\s*\$true\s*\)'
    }

    It 'creates a Unix child as mode 0600 beneath a pre-secured mode 0700 parent' -ForEach $unixInitialAccessCases -AllowNullOrEmptyForEach {
        Initialize-GraphKitAuthStageCapture
        $root = Join-Path $TestDrive ('unix-initial-access-' + [guid]::NewGuid().ToString('N'))
        $source = Join-Path $root 'source'
        $destination = Join-Path $root 'destination'
        $null = New-Item -ItemType Directory -Path $source, $destination -Force
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly($destination, $true, $true)
        [IO.File]::WriteAllBytes((Join-Path $source 'candidate.dll'), [byte[]](1..32))

        $copy = $script:GraphKitAuthStageCaptureType::CopyFileCreateNew(
            $source, 'candidate.dll', $destination, 'candidate.dll')

        $parentEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory($root, 'destination')
        $parentEvidence.UnixMode | Should -Be 0x1C0
        $copy.DestinationInitial.UnixMode | Should -Be 0x180
        $copy.Destination.UnixMode | Should -Be 0x180
    }

    It 'creates a Windows child with only current-identity access before explicit reseal' -ForEach $windowsInitialAccessCases -AllowNullOrEmptyForEach {
        Initialize-GraphKitAuthStageCapture
        $root = Join-Path $TestDrive ('windows-initial-access-' + [guid]::NewGuid().ToString('N'))
        $source = Join-Path $root 'source'
        $destination = Join-Path $root 'destination'
        $null = New-Item -ItemType Directory -Path $source, $destination -Force
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly($destination, $true, $true)
        [IO.File]::WriteAllBytes((Join-Path $source 'candidate.dll'), [byte[]](1..32))

        $copy = $script:GraphKitAuthStageCaptureType::CopyFileCreateNew(
            $source, 'candidate.dll', $destination, 'candidate.dll')

        $copy.DestinationInitial.OwnerOnlyAccess | Should -BeTrue
        $copy.DestinationInitial.CurrentIdentitySid |
            Should -BeExactly ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    }

    It 'allows an ordinary Windows inherited-ACL copy only when the sealed initial gate is false' -ForEach $windowsInitialAccessCases -AllowNullOrEmptyForEach {
        Initialize-GraphKitAuthStageCapture
        $root = Join-Path $TestDrive ('windows-scoped-initial-gate-' + [guid]::NewGuid().ToString('N'))
        $source = Join-Path $root 'source'
        $destination = Join-Path $root 'ordinary'
        $sealedDestination = Join-Path $root 'sealed-required'
        $null = New-Item -ItemType Directory -Path $source, $destination, $sealedDestination -Force
        [IO.File]::WriteAllBytes((Join-Path $source 'candidate.dll'), [byte[]](1..32))
        $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $worldSid = [Security.Principal.SecurityIdentifier]::new(
            [Security.Principal.WellKnownSidType]::WorldSid, $null)
        foreach ($directory in @($destination, $sealedDestination)) {
            $acl = Get-Acl -LiteralPath $directory
            $acl.SetAccessRuleProtection($true, $false)
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $currentSid, [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit,
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow))
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $worldSid, [Security.AccessControl.FileSystemRights]::Read,
                [Security.AccessControl.InheritanceFlags]::ObjectInherit,
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow))
            Set-Acl -LiteralPath $directory -AclObject $acl
        }

        { $script:GraphKitAuthStageCaptureType::CopyFileCreateNew(
            $source, 'candidate.dll', $destination, 'candidate.dll', $false) } | Should -Not -Throw
        { $script:GraphKitAuthStageCaptureType::CopyFileCreateNew(
            $source, 'candidate.dll', $sealedDestination, 'candidate.dll', $true) } | Should -Throw '*owner-only*'
    }

    It 'rejects a sealed stage after Windows ACL <Kind> mutation' -ForEach $windowsAclMutationCases -AllowNullOrEmptyForEach {
        $fixture = New-GraphKitAuthStageFixture -Name ('windows-acl-' + $Kind.Replace(' ', '-'))
        Set-GraphKitAuthWindowsAclMutation -StagePath $fixture.StagePath -Kind $Kind
        { Test-GraphKitAuthSealedStage -StagePath $fixture.StagePath -FullVersion $fixture.FullVersion } |
            Should -Throw
    }

    It 'rejects a Windows permission record whose owner is not the current identity' -ForEach $(
        if ($IsWindows) { @(@{}) } else { @() }
    ) -AllowNullOrEmptyForEach {
        $fixture = New-GraphKitAuthStageFixture -Name 'windows-wrong-owner-evidence'
        $evidence = $script:GraphKitAuthStageCaptureType::InspectFile($fixture.StagePath, 'manifest.json')
        $mutated = $evidence | Select-Object *
        $mutated.OwnerSid = [Security.Principal.SecurityIdentifier]::new(
            [Security.Principal.WellKnownSidType]::WorldSid, $null).Value
        (Test-GraphKitAuthSealedPermission -Evidence $mutated -Directory $false) | Should -BeFalse
    }

    It 'rejects a projected file after <Kind> without deleting it' -ForEach @(
        @{ Kind = 'byte mutation' }
        @{ Kind = 'replacement' }
        @{ Kind = 'hard link' }
    ) {
        Initialize-GraphKitAuthStageCapture
        $root = Join-Path $TestDrive ("projection-$($Kind.Replace(' ', '-'))-" + [guid]::NewGuid().ToString('N'))
        $source = Join-Path $root 'source'
        $destination = Join-Path $root 'destination'
        $null = New-Item -ItemType Directory -Path $source, $destination -Force
        [IO.File]::WriteAllBytes((Join-Path $source 'candidate.dll'), [byte[]](1..32))
        $copy = $script:GraphKitAuthStageCaptureType::CopyFileCreateNew($source, 'candidate.dll', $destination, 'candidate.dll')
        { Assert-GraphKitAuthAbiProjectedFileEvidence -RepositoryRoot $root `
            -RelativePath 'destination/candidate.dll' -Expected $copy.Destination } | Should -Not -Throw
        $candidate = Join-Path $destination 'candidate.dll'
        switch ($Kind) {
            'byte mutation' { [IO.File]::WriteAllBytes($candidate, [byte[]](33..64)) }
            'replacement' {
                $replacement = Join-Path $destination 'replacement.dll'
                [IO.File]::WriteAllBytes($replacement, [byte[]](1..32))
                [IO.File]::Move($replacement, $candidate, $true)
            }
            'hard link' {
                $null = New-Item -ItemType HardLink -Path (Join-Path $destination 'candidate.link.dll') `
                    -Target $candidate -ErrorAction Stop
            }
        }
        { Assert-GraphKitAuthAbiProjectedFileEvidence -RepositoryRoot $root `
            -RelativePath 'destination/candidate.dll' -Expected $copy.Destination } | Should -Throw
        Test-Path -LiteralPath $candidate -PathType Leaf | Should -BeTrue
    }
}

Describe 'Packed GraphKit.Auth boundary' -Tag 'QA' {
    It 'rejects an exact path set containing a <Kind>' -ForEach $graphKitAuthArchiveAliasCases {
        { Assert-GraphKitAuthArchivePaths -Entries $Entries } | Should -Throw
    }

    It 'keeps source RequiredAssemblies empty and builds exactly the contracts prerequisite' {
        @($script:sourceManifest.RequiredAssemblies | Where-Object { $null -ne $_ }).Count | Should -Be 0
        $built = Import-PowerShellDataFile -LiteralPath $script:builtManifestPath
        (@($built.RequiredAssemblies | Where-Object { $null -ne $_ }) -join '|') |
            Should -BeExactly 'Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll'
    }

    It 'contains exactly the fixed five-file GraphKit.Auth subtree in build and archive' {
        $script:packagePath | Should -Exist
        $builtPaths = @(Get-ChildItem -LiteralPath (Join-Path $script:builtModuleRoot 'Assemblies/GraphKit.Auth') -File -Force | ForEach-Object Name | Sort-Object)
        $archivePaths = @($script:packageEntries.FullName | Where-Object { $_ -like 'Assemblies/GraphKit.Auth/*' } | ForEach-Object { $_.Substring('Assemblies/GraphKit.Auth/'.Length) } | Sort-Object)
        $expected = @($script:requiredGraphKitAuthFiles | Sort-Object)
        ($builtPaths -join '|') | Should -BeExactly ($expected -join '|')
        ($archivePaths -join '|') | Should -BeExactly ($expected -join '|')
        { Assert-GraphKitAuthArchivePaths -Entries @($script:packageEntries.FullName) } | Should -Not -Throw
    }

    It 'matches every sealed payload digest in the built module and archive' {
        Assert-GraphKitAuthStageCommands
        $verified = Test-GraphKitAuthSealedStage -StagePath $script:stagePath -FullVersion $script:fullVersion
        foreach ($file in @($verified.Manifest.files)) {
            $name = Split-Path ([string] $file.path) -Leaf
            (Get-FileHash -LiteralPath (Join-Path $script:builtModuleRoot "Assemblies/GraphKit.Auth/$name") -Algorithm SHA256).Hash.ToLowerInvariant() | Should -BeExactly ([string] $file.sha256) -Because $name
            Get-GraphKitAuthArchiveHash -PackagePath $script:packagePath -EntryPath "Assemblies/GraphKit.Auth/$name" | Should -BeExactly ([string] $file.sha256) -Because $name
        }
    }

    It 'constructs from the reverified sealed payload and unloads its private runtime' {
        Assert-GraphKitAuthStageCommands
        $verified = Test-GraphKitAuthSealedStage -StagePath $script:stagePath -FullVersion $script:fullVersion
        $result = Invoke-GraphKitAuthSealedPayloadProbe -PayloadRoot $verified.PayloadPath
        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Data.ContractsCount | Should -Be 1
        $result.Data.ContractsContext | Should -BeExactly 'Default'
        $result.Data.DefaultMsalPreloaded | Should -BeTrue
        $result.Data.DefaultMsalReferenceUnchanged | Should -BeTrue
        $result.Data.DefaultMsalMvidUnchanged | Should -BeTrue
        $result.Data.DefaultMsalLocationUnchanged | Should -BeTrue
        $result.Data.ProviderMsalDistinctFromDefault | Should -BeTrue
        $result.Data.ProviderMsalContextCollectible | Should -BeTrue
        $result.Data.ProviderMsalContextName | Should -Match '^GraphKit\.Auth/[0-9a-f]{32}$'
        $result.Data.ProviderAcquireCount | Should -Be 0
        (@($result.Data.CollectibleAssemblies | Sort-Object) -join '|') |
            Should -BeExactly 'GraphKit.Auth|Microsoft.Identity.Client|Microsoft.IdentityModel.Abstractions'
        $manifestByName = @{}
        foreach ($record in @($verified.Manifest.files)) {
            $manifestByName[[IO.Path]::GetFileName([string]$record.path)] = $record
        }
        foreach ($assembly in @(
            @{ Prefix='Provider'; Name='GraphKit.Auth.dll'; Identity='GraphKit.Auth, Version=1.0.0.0' }
            @{ Prefix='ProviderMsal'; Name='Microsoft.Identity.Client.dll'; Identity='Microsoft.Identity.Client, Version=4.82.1.0' }
            @{ Prefix='ProviderIdentityModel'; Name='Microsoft.IdentityModel.Abstractions.dll'; Identity='Microsoft.IdentityModel.Abstractions, Version=8.14.0.0' }
        )) {
            $expectedLocation = [IO.Path]::GetFullPath((Join-Path $verified.PayloadPath $assembly.Name))
            $result.Data.("$($assembly.Prefix)Location") | Should -BeExactly $expectedLocation
            $result.Data.("$($assembly.Prefix)Identity") | Should -BeExactly $assembly.Identity
            $result.Data.("$($assembly.Prefix)Sha256") |
                Should -BeExactly ([string]$manifestByName[$assembly.Name].sha256)
            $result.Data.("$($assembly.Prefix)Mvid") | Should -Match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        }
        $result.Data.DefaultMsalUnchanged | Should -BeTrue
        $result.Data.CanRefresh | Should -BeTrue
        $result.Data.LoadContextAlive | Should -BeFalse
    }
}

Describe 'GraphKit.Auth exact-source CI contract' -Tag 'QA' {
    BeforeAll { $script:ci = Get-Content -LiteralPath (Join-Path $script:repoRoot '.github/workflows/ci.yml') -Raw }
    It 'covers all six exact operating-system and PowerShell patch rows' {
        foreach ($os in @('windows-latest','ubuntu-latest','macos-latest')) { $script:ci | Should -Match ([regex]::Escape($os)) }
        foreach ($version in @('7.4.19','7.6.5')) { $script:ci | Should -Match ([regex]::Escape("'$version'")) }
    }
    It 'selects and asserts the exact event repository and SHA before SDK setup or restore' {
        $script:ci | Should -Match '(?m)^\s*branches:\s*\[main,\s*''codex/\*\*''\]\s*$'
        $script:ci | Should -Match '(?m)^\s*pull_request:\s*$'
        $script:ci | Should -Match '(?m)^\s*workflow_dispatch:\s*$'
        $script:ci | Should -Match 'github\.event\.pull_request\.head\.repo\.full_name'
        $script:ci | Should -Match 'github\.event\.pull_request\.head\.sha'
        $script:ci | Should -Match 'github\.repository'
        $script:ci | Should -Match 'github\.sha'
        $script:ci | Should -Match '(?m)^\s*fetch-depth:\s*0\s*$'
        $script:ci | Should -Match 'git rev-parse HEAD'
        $script:ci | Should -Match 'StringComparison\]::Ordinal'
        $checkoutIndex=$script:ci.IndexOf('uses: actions/checkout@v4'); $assertIndex=$script:ci.IndexOf('name: Assert exact source revision'); $setupIndex=$script:ci.IndexOf('uses: actions/setup-dotnet@v4'); $restoreIndex=$script:ci.IndexOf('name: Resolve build dependencies')
        $checkoutIndex | Should -BeGreaterOrEqual 0
        $assertIndex | Should -BeGreaterThan $checkoutIndex
        $setupIndex | Should -BeGreaterThan $assertIndex
        $restoreIndex | Should -BeGreaterThan $setupIndex
    }
    It 'uses one exact SDK setup and asserts the complete running PowerShell version' {
        @([regex]::Matches($script:ci,'uses:\s*actions/setup-dotnet@v4')).Count | Should -Be 1
        $script:ci | Should -Match 'dotnet-version:\s*''10\.0\.400'''
        $script:ci | Should -Match '\$PSVersionTable\.PSVersion\.ToString\(\)'
        $script:ci | Should -Not -Match 'expectedMajorMinor|actualMajorMinor'
        $script:ci | Should -Match 'Build_GraphKitAuth'
    }
}
