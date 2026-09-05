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
        "Assemblies/GraphKit.Auth/prob$([char]0x00E9).dll"
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
        ExpectedName = "0.4.0-r8.fixture.v$([char]0x00E9)rsion-alias"
        AliasName = ("0.4.0-r8.fixture.v$([char]0x00E9)rsion-alias").Normalize([Text.NormalizationForm]::FormD)
    }
)
$linuxAtomicRenameCases = if ($IsLinux) { @(@{}) } else { @() }
$linuxCaseSensitiveStageAliasCases = if ($IsLinux) { @(@{}) } else { @() }

BeforeAll {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if (-not ('GraphKitAuthPackageLinkFixture' -as [type])) {
        Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices;

public static class GraphKitAuthPackageLinkFixture
{
    private const int SymbolicLinkFlagAllowUnprivilegedCreate = 0x2;

    public static void CreateHardLink(string linkPath, string existingPath)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("The native package hard-link fixture is Windows-only.");
        if (!CreateHardLinkW(ToExtendedWindowsPath(linkPath), ToExtendedWindowsPath(existingPath), IntPtr.Zero))
            throw new IOException($"Native package hard-link creation failed (Win32 {Marshal.GetLastWin32Error()}).");
    }

    public static void CreateFileSymbolicLink(string linkPath, string targetPath)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("The native package symbolic-link fixture is Windows-only.");
        if (!CreateSymbolicLinkW(ToExtendedWindowsPath(linkPath), ToExtendedWindowsPath(targetPath),
                SymbolicLinkFlagAllowUnprivilegedCreate))
            throw new IOException($"Native package symbolic-link creation failed (Win32 {Marshal.GetLastWin32Error()}).");
    }

    public static bool IsReparsePoint(string path)
    {
        return (File.GetAttributes(ToExtendedWindowsPath(path)) & FileAttributes.ReparsePoint) != 0;
    }

    private static string ToExtendedWindowsPath(string path)
    {
        string fullPath = Path.GetFullPath(path);
        if (fullPath.StartsWith(@"\\?\", StringComparison.Ordinal)) return fullPath;
        if (fullPath.StartsWith(@"\\", StringComparison.Ordinal))
            return @"\\?\UNC\" + fullPath.Substring(2);
        return @"\\?\" + fullPath;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern bool CreateHardLinkW(
        string fileName, string existingFileName, IntPtr securityAttributes);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern bool CreateSymbolicLinkW(
        string symbolicFileName, string targetFileName, int flags);
}
"@
    }
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
            $archiveMatches = @($archive.Entries | Where-Object FullName -CEQ $EntryPath)
            if ($archiveMatches.Count -ne 1) { throw "Expected one '$EntryPath' archive entry." }
            $stream = $archiveMatches[0].Open()
            try {
                $sha = [Security.Cryptography.SHA256]::Create()
                try { return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() }
                finally { $sha.Dispose() }
            }
            finally { $stream.Dispose() }
        }
        finally { $archive.Dispose() }
    }

    function Test-GraphKitAuthTestAclMutationSafe {
        param([Parameter(Mandatory)] $Item)
        return [string]::IsNullOrEmpty([string] $Item.LinkType) -and
            (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)
    }

    function New-GraphKitAuthTestHardLink {
        param(
            [Parameter(Mandatory)][string] $LinkPath,
            [Parameter(Mandatory)][string] $TargetPath
        )
        if ($IsWindows) {
            [GraphKitAuthPackageLinkFixture]::CreateHardLink($LinkPath, $TargetPath)
        }
        else {
            $null = New-Item -ItemType HardLink -Path $LinkPath -Target $TargetPath `
                -ErrorAction Stop
        }
    }

    function New-GraphKitAuthTestFileSymbolicLink {
        param(
            [Parameter(Mandatory)][string] $LinkPath,
            [Parameter(Mandatory)][string] $TargetPath
        )
        if ($IsWindows) {
            [GraphKitAuthPackageLinkFixture]::CreateFileSymbolicLink($LinkPath, $TargetPath)
        }
        else {
            $null = New-Item -ItemType SymbolicLink -Path $LinkPath -Target $TargetPath `
                -ErrorAction Stop
        }
    }

    function Remove-GraphKitAuthTestMutationArtifacts {
        param(
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [Collections.Generic.List[object]] $Artifacts
        )
        for ($index = $Artifacts.Count - 1; $index -ge 0; $index--) {
            $artifact = $Artifacts[$index]
            if (-not [bool] $artifact.Created) { continue }
            $path = [string] $artifact.Path
            $isDirectory = [bool] $artifact.Directory
            $isLink = [bool] $artifact.Link
            $restorePath = [string] $artifact.RestorePath
            if ($isLink) {
                $parent = [IO.Path]::GetDirectoryName($path)
                if ($IsWindows) {
                    Set-GraphKitAuthTestWindowsPathWritable -Path $parent -Directory $true
                    if (-not [string]::IsNullOrWhiteSpace($restorePath)) {
                        Set-GraphKitAuthTestWindowsPathWritable -Path $path -Directory $false
                    }
                }
                else {
                    Set-GraphKitAuthTestUnixPathWritable -Path $parent -Directory $true
                }
                if ($isDirectory) { [IO.Directory]::Delete($path, $false) }
                else { [IO.File]::Delete($path) }
                if (-not [string]::IsNullOrWhiteSpace($restorePath)) {
                    $script:GraphKitAuthStageCaptureType::SetOwnerOnly(
                        $restorePath, $false, $false)
                }
            }
            elseif ($isDirectory) {
                if ([IO.Directory]::Exists($path)) {
                    Set-GraphKitAuthTestTreeWritable -Path $path
                    [IO.Directory]::Delete($path, $true)
                }
            }
            elseif ([IO.File]::Exists($path)) {
                if ($IsWindows) {
                    Set-GraphKitAuthTestWindowsPathWritable -Path $path -Directory $false
                }
                [IO.File]::Delete($path)
            }
        }
        $Artifacts.Clear()
    }

    function Set-GraphKitAuthTestStageWritable {
        param([Parameter(Mandatory)] [string] $StagePath)
        $versionPath = Split-Path $StagePath -Parent
        $stageItem = Get-Item -LiteralPath $StagePath -Force -ErrorAction Stop
        $versionItem = Get-Item -LiteralPath $versionPath -Force -ErrorAction Stop
        if (-not (Test-GraphKitAuthTestAclMutationSafe -Item $stageItem) -or
            -not (Test-GraphKitAuthTestAclMutationSafe -Item $versionItem)) {
            throw 'GraphKit.Auth test stage cleanup refused a link or reparse root.'
        }
        $items = @(
            Get-ChildItem -LiteralPath $StagePath -Recurse -Force -ErrorAction Stop |
                Sort-Object { $_.FullName.Length } -Descending
        ) + @($stageItem, $versionItem)
        if (@($items | Where-Object {
            -not (Test-GraphKitAuthTestAclMutationSafe -Item $_)
        }).Count -gt 0) {
            throw 'GraphKit.Auth test stage cleanup refused a link or reparse entry.'
        }
        foreach ($item in $items) {
            $directory = [bool] $item.PSIsContainer
            if ($IsWindows) {
                Set-GraphKitAuthTestWindowsPathWritable `
                    -Path $item.FullName -Directory $directory
            }
            else {
                Set-GraphKitAuthTestUnixPathWritable -Path $item.FullName `
                    -Directory $directory -Exact
            }
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

    function Set-GraphKitAuthTestWindowsPathWritable {
        param(
            [Parameter(Mandatory)][string] $Path,
            [Parameter(Mandatory)][bool] $Directory
        )
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $security = if ($Directory) {
            [Security.AccessControl.DirectorySecurity]::new()
        }
        else {
            [Security.AccessControl.FileSecurity]::new()
        }
        $security.SetAccessRuleProtection($true, $false)
        # Every descendant is transitioned explicitly by the bounded cleanup walkers.
        # A propagating ACE here could follow an in-tree hard-link name and mutate the
        # caller-owned file object outside the requested tree.
        $inheritance = [Security.AccessControl.InheritanceFlags]::None
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
        if ($Directory) {
            [IO.FileSystemAclExtensions]::SetAccessControl(
                [IO.DirectoryInfo]::new($Path), $security)
        }
        else {
            [IO.FileSystemAclExtensions]::SetAccessControl(
                [IO.FileInfo]::new($Path), $security)
            $attributes = [IO.File]::GetAttributes($Path)
            if (($attributes -band [IO.FileAttributes]::ReadOnly) -ne 0) {
                $writableAttributes = [IO.FileAttributes](
                    [int]$attributes -band (-bnot [int][IO.FileAttributes]::ReadOnly))
                [IO.File]::SetAttributes(
                    $Path,
                    $(if ([int]$writableAttributes -eq 0) {
                        [IO.FileAttributes]::Normal
                    }
                    else { $writableAttributes }))
            }
        }
    }

    function Set-GraphKitAuthTestUnixPathWritable {
        param(
            [Parameter(Mandatory)][string] $Path,
            [Parameter(Mandatory)][bool] $Directory,
            [switch] $Exact
        )
        $required = [IO.UnixFileMode]::UserRead -bor
            [IO.UnixFileMode]::UserWrite
        $current = if ($Exact) {
            [IO.UnixFileMode]::None
        }
        else {
            [IO.File]::GetUnixFileMode($Path)
        }
        $anyExecute = [IO.UnixFileMode]::UserExecute -bor
            [IO.UnixFileMode]::GroupExecute -bor
            [IO.UnixFileMode]::OtherExecute
        if ($Directory -or (([int] $current -band [int] $anyExecute) -ne 0)) {
            $required = $required -bor [IO.UnixFileMode]::UserExecute
        }
        [IO.File]::SetUnixFileMode(
            $Path, [IO.UnixFileMode]([int] $current -bor [int] $required))
    }

    function Set-GraphKitAuthTestTreeWritable {
        param([Parameter(Mandatory)][string] $Path)
        if (-not (Test-Path -LiteralPath $Path)) { return }
        $rootItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (-not (Test-GraphKitAuthTestAclMutationSafe -Item $rootItem)) {
            throw 'GraphKit.Auth test tree cleanup refused a link or reparse root.'
        }
        $items = @(
            Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction Stop |
                Sort-Object { $_.FullName.Length } -Descending
        ) + @($rootItem)
        if (@($items | Where-Object {
            -not (Test-GraphKitAuthTestAclMutationSafe -Item $_)
        }).Count -gt 0) {
            throw 'GraphKit.Auth test tree cleanup refused a link or reparse entry.'
        }
        foreach ($item in $items) {
            $directory = [bool] $item.PSIsContainer
            if ($IsWindows) {
                Set-GraphKitAuthTestWindowsPathWritable `
                    -Path $item.FullName -Directory $directory
            }
            else {
                Set-GraphKitAuthTestUnixPathWritable -Path $item.FullName `
                    -Directory $directory
            }
        }
    }

    function New-GraphKitAuthStageFixture {
        param([Parameter(Mandatory)] [string] $Name)
        Assert-GraphKitAuthStageCommands
        if (-not $script:stagePath) { throw 'The packed candidate has no sealed source stage to use as fixture input.' }
        $fixtureOutput = Join-Path $TestDrive ("stage-fixture-$Name-" + [guid]::NewGuid().ToString('N'))
        try {
            $fixture = New-GraphKitAuthSealedStage -OutputRoot $fixtureOutput `
                -FullVersion ("0.4.0-r8.fixture.$Name." + [guid]::NewGuid().ToString('N')) `
                -PayloadSourceRoot (Join-Path $script:stagePath 'payload')
            $fixture | Add-Member -NotePropertyName TestOutputRoot -NotePropertyValue $fixtureOutput
            return $fixture
        }
        catch {
            $primaryFailure = $_
            try { Remove-GraphKitAuthTestFixtureOutputRoot -OutputRoot $fixtureOutput }
            catch {
                throw [AggregateException]::new(
                    'GraphKit.Auth stage fixture creation and bounded cleanup both failed.',
                    [Exception[]]@($primaryFailure.Exception, $_.Exception))
            }
            throw $primaryFailure
        }
    }

    function Resolve-GraphKitAuthTestFixtureOutputRoot {
        param([Parameter(Mandatory)][string] $OutputRoot)
        $outputRoot = [IO.Path]::GetFullPath($OutputRoot)
        $testDriveRoot = [IO.Path]::GetFullPath([string] $TestDrive).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar)
        $comparison = if ($IsWindows) {
            [StringComparison]::OrdinalIgnoreCase
        }
        else { [StringComparison]::Ordinal }
        if (-not [string]::Equals(
            [IO.Path]::GetDirectoryName($outputRoot), $testDriveRoot, $comparison) -or
            [IO.Path]::GetFileName($outputRoot) -notmatch '^stage-fixture-.+-[0-9a-f]{32}$') {
            throw 'GraphKit.Auth test stage cleanup refused a non-fixture output root.'
        }
        return $outputRoot
    }

    function Assert-GraphKitAuthTestPhysicalFixtureTree {
        param([Parameter(Mandatory)][string] $OutputRoot)
        if (-not [IO.Directory]::Exists($OutputRoot)) { return }
        $rootItem = Get-Item -LiteralPath $OutputRoot -Force -ErrorAction Stop
        if (-not (Test-GraphKitAuthTestAclMutationSafe -Item $rootItem)) {
            throw 'GraphKit.Auth test stage cleanup refused a link or reparse root.'
        }
        $items = @(
            Get-ChildItem -LiteralPath $OutputRoot -Recurse -Force -ErrorAction Stop
        ) + @($rootItem)
        if (@($items | Where-Object {
            -not (Test-GraphKitAuthTestAclMutationSafe -Item $_)
        }).Count -gt 0) {
            throw 'GraphKit.Auth test stage cleanup refused a link or reparse entry.'
        }
    }

    function Remove-GraphKitAuthTestFixtureOutputRoot {
        param([Parameter(Mandatory)][string] $OutputRoot)
        $outputRoot = Resolve-GraphKitAuthTestFixtureOutputRoot -OutputRoot $OutputRoot
        if ([IO.Directory]::Exists($outputRoot)) {
            Assert-GraphKitAuthTestPhysicalFixtureTree -OutputRoot $outputRoot
            Set-GraphKitAuthTestTreeWritable -Path $outputRoot
            [IO.Directory]::Delete($outputRoot, $true)
        }
    }

    function Remove-GraphKitAuthTestStageFixture {
        param([Parameter(Mandatory)] $Fixture)
        $outputRoot = Resolve-GraphKitAuthTestFixtureOutputRoot `
            -OutputRoot ([string] $Fixture.TestOutputRoot)
        $stagePath = [IO.Path]::GetFullPath([string] $Fixture.StagePath)
        $fullVersion = [string] $Fixture.FullVersion
        $manifestSha256 = [string] $Fixture.ManifestSha256
        Assert-GraphKitAuthSafeSegment -Value $fullVersion -Kind 'test fixture full version'
        if ($manifestSha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'GraphKit.Auth test stage cleanup refused an invalid manifest digest.'
        }
        $expectedStagePath = [IO.Path]::GetFullPath([IO.Path]::Combine(
            $outputRoot,
            'GraphKit.Auth',
            'stage',
            $fullVersion,
            $manifestSha256))
        $comparison = if ($IsWindows) {
            [StringComparison]::OrdinalIgnoreCase
        }
        else { [StringComparison]::Ordinal }
        if (-not [string]::Equals($stagePath, $expectedStagePath, $comparison)) {
            throw 'GraphKit.Auth test stage cleanup refused a mismatched stage path.'
        }
        Assert-GraphKitAuthTestPhysicalFixtureTree -OutputRoot $outputRoot
        if ([IO.Directory]::Exists($stagePath)) {
            Set-GraphKitAuthTestStageWritable -StagePath $stagePath
        }
        Remove-GraphKitAuthTestFixtureOutputRoot -OutputRoot $outputRoot
    }

    function Invoke-GraphKitAuthStageMutation {
        param(
            [string] $Kind,
            [string] $StagePath,
            [Parameter(Mandatory)]
            [AllowEmptyCollection()]
            [Collections.Generic.List[object]] $CleanupArtifacts
        )
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
                $linkArtifact = [pscustomobject]@{
                    Path = $outsideLink; Directory = $false; Link = $true
                    RestorePath = $targetPath; Created = $false
                }
                $CleanupArtifacts.Add($linkArtifact) | Out-Null
                New-GraphKitAuthTestHardLink -LinkPath $outsideLink -TargetPath $targetPath
                $linkArtifact.Created = $true
                $linked = $script:GraphKitAuthStageCaptureType::InspectFile(
                    $payloadPath, 'GraphKit.Auth.dll')
                if ([long] $linked.LinkCount -ne 2) {
                    throw 'The package hard-link fixture did not establish an exact two-link file.'
                }
            }
            'escaped-link' {
                $outsidePath = Join-Path $TestDrive ('outside-' + [guid]::NewGuid().ToString('N') + '.dll')
                $outsideArtifact = [pscustomobject]@{
                    Path = $outsidePath; Directory = $false; Link = $false
                    RestorePath = $null; Created = $false
                }
                $CleanupArtifacts.Add($outsideArtifact) | Out-Null
                $outsideStream = $null
                try {
                    $outsideStream = [IO.File]::Open(
                        $outsidePath, [IO.FileMode]::CreateNew,
                        [IO.FileAccess]::Write, [IO.FileShare]::None)
                    $outsideArtifact.Created = $true
                    $outsideBytes = [Text.Encoding]::UTF8.GetBytes('outside')
                    $outsideStream.Write($outsideBytes, 0, $outsideBytes.Length)
                }
                finally {
                    if ($null -ne $outsideStream) { $outsideStream.Dispose() }
                }
                [IO.File]::Delete($targetPath)
                $linkArtifact = [pscustomobject]@{
                    Path = $targetPath; Directory = $false; Link = $true
                    RestorePath = $null; Created = $false
                }
                $CleanupArtifacts.Add($linkArtifact) | Out-Null
                New-GraphKitAuthTestFileSymbolicLink -LinkPath $targetPath -TargetPath $outsidePath
                $linkArtifact.Created = $true
                if ($IsWindows) {
                    if (-not [GraphKitAuthPackageLinkFixture]::IsReparsePoint($targetPath)) {
                        throw 'The package symbolic-link fixture did not create a reparse point.'
                    }
                }
                elseif ((Get-Item -LiteralPath $targetPath -Force).LinkType -ne 'SymbolicLink') {
                    throw 'The package symbolic-link fixture did not create a symbolic link.'
                }
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
                [IO.File]::Copy($targetPath, (Join-Path $payloadPath "prob$([char]0x00E9).dll"))
                try { [IO.File]::Copy($targetPath, (Join-Path $payloadPath "probe$([char]0x0301).dll")) }
                catch [IO.IOException] {
                    # APFS commonly aliases composed and decomposed names. The first extra
                    # file is still a zero-skip normalization mutation for stage validation.
                }
            }
            'platform-directory-alias' {
                $outsidePayload = Join-Path $TestDrive ('payload-alias-target-' + [guid]::NewGuid().ToString('N'))
                $outsideArtifact = [pscustomobject]@{
                    Path = $outsidePayload; Directory = $true; Link = $false
                    RestorePath = $null; Created = $false
                }
                $CleanupArtifacts.Add($outsideArtifact) | Out-Null
                $null = New-Item -ItemType Directory -Path $outsidePayload -ErrorAction Stop
                $outsideArtifact.Created = $true
                foreach ($file in @(Get-ChildItem -LiteralPath $payloadPath -File -Force)) {
                    [IO.File]::Copy($file.FullName, (Join-Path $outsidePayload $file.Name))
                }
                Remove-Item -LiteralPath $payloadPath -Recurse -Force
                $kind = if ($IsWindows) { 'Junction' } else { 'SymbolicLink' }
                $linkArtifact = [pscustomobject]@{
                    Path = $payloadPath; Directory = $true; Link = $true
                    RestorePath = $null; Created = $false
                }
                $CleanupArtifacts.Add($linkArtifact) | Out-Null
                $null = New-Item -ItemType $kind -Path $payloadPath -Target $outsidePayload -ErrorAction Stop
                $linkArtifact.Created = $true
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
        $helperSource | Should -Match 'EntryPoint = "__fxstat"' `
            -Because 'glibc before 2.33 exposes the compatibility fstat symbol instead of public fstat'
        $helperSource | Should -Match '(?s)catch \(EntryPointNotFoundException\s+\w+\).*?fxstat\(' `
            -Because 'Linux stage capture must fall back only when the modern libc symbol is absent'
        $taskSource | Should -Match 'if \(\$LASTEXITCODE -ne 1\)' `
            -Because 'only git check-ignore exit 1 proves the unrelated sentinel is not ignored'
        { Assert-GraphKitAuthStageCommands } | Should -Not -Throw

        $fixtureRoot = Join-Path $TestDrive ('quarantine-' + [guid]::NewGuid().ToString('N'))
        $generatedRoot = Join-Path $fixtureRoot 'src/GraphKit.Auth/GraphKit.Auth/bin'
        $quarantine = $null
        try {
            $null = [IO.Directory]::CreateDirectory($generatedRoot)
            [IO.File]::WriteAllText((Join-Path $generatedRoot 'generated.dll'), 'fixture')

            $quarantine = Invoke-GraphKitAuthLiteralQuarantine -RepositoryRoot $fixtureRoot

            $relativeQuarantine = [IO.Path]::GetRelativePath(
                [IO.Path]::GetFullPath($fixtureRoot),
                [IO.Path]::GetFullPath($quarantine))
            [IO.Path]::IsPathRooted($relativeQuarantine) | Should -BeFalse
            $relativeQuarantine | Should -Not -Match '^\.\.(?:[\\/]|$)' `
                -Because 'generated roots must be renamed onto the repository volume'
            Test-Path -LiteralPath $generatedRoot | Should -BeFalse
            Test-Path -LiteralPath (
                Join-Path $quarantine 'src__GraphKit.Auth__GraphKit.Auth__bin/generated.dll') `
                -PathType Leaf | Should -BeTrue
        }
        finally {
            if ($quarantine -and (Test-Path -LiteralPath $quarantine)) {
                Remove-Item -LiteralPath $quarantine -Recurse -Force
            }
            if (Test-Path -LiteralPath $fixtureRoot) {
                Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
            }
        }

        $observed = & {
            $tasks = @{}
            function Register-GraphKitAuthTaskCapture {
                param([string] $Name, [scriptblock] $Action)
                $tasks[$Name] = $Action
            }
            Set-Alias -Name task -Value Register-GraphKitAuthTaskCapture -Scope Local

            . $script:taskPath

            $cleanupCalls = [Collections.Generic.List[string]]::new()
            function Initialize-GraphKitAuthStageCapture {}
            function Initialize-GraphKitAuthBuildAuthorityRoot {
                throw [InvalidOperationException]::new('injected primary build failure')
            }
            function New-GraphKitAuthBuildWorkRoot {
                [pscustomobject]@{ Path='fixture-work'; Name='.build-fixture'; Evidence='fixture-evidence' }
            }
            function Move-GraphKitAuthBuildWorkToQuarantine {}
            function New-GraphKitAuthTaskQuarantineRoot {
                [pscustomobject]@{ Path='fixture-work-quarantine' }
            }
            function Invoke-GraphKitAuthLiteralQuarantine {
                param([string] $RepositoryRoot)
                $cleanupCalls.Add($RepositoryRoot)
                throw [IO.IOException]::new('injected secondary quarantine failure')
            }

            $BuildRoot = Join-Path $TestDrive ('primary-failure-' + [guid]::NewGuid().ToString('N'))
            $primaryFailure = $null
            try {
                & $tasks['Build_GraphKitAuth']
            }
            catch {
                $primaryFailure = $_
            }
            $primaryCleanupCalls = $cleanupCalls.Count

            function Initialize-GraphKitAuthBuildAuthorityRoot {}
            $dotnetCalls = [Collections.Generic.List[string]]::new()
            function dotnet {
                param([Parameter(ValueFromRemainingArguments)][object[]] $Arguments)
                $call = [string] ($Arguments -join ' ')
                $dotnetCalls.Add($call)
                if ($call -ceq '--version') {
                    $global:LASTEXITCODE = 0
                    'injected diagnostic line'
                    ''
                    '10.0.400'
                    return
                }
                $global:LASTEXITCODE = 1
            }

            $lastExitCodeVariable = Get-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
            $normalizedVersionFailure = $null
            try {
                & $tasks['Build_GraphKitAuth']
            }
            catch {
                $normalizedVersionFailure = $_
            }
            finally {
                if ($null -eq $lastExitCodeVariable) {
                    Remove-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
                }
                else {
                    $global:LASTEXITCODE = $lastExitCodeVariable.Value
                }
            }

            [pscustomobject]@{
                PrimaryFailure = $primaryFailure
                PrimaryCleanupCalls = $primaryCleanupCalls
                NormalizedVersionFailure = $normalizedVersionFailure
                DotnetCalls = @($dotnetCalls)
            }
        }

        $observed.PrimaryCleanupCalls | Should -Be 1
        $observed.PrimaryFailure | Should -Not -BeNullOrEmpty
        $observed.PrimaryFailure.Exception.GetType().FullName | Should -BeExactly 'System.InvalidOperationException'
        $observed.PrimaryFailure.Exception.Message | Should -BeExactly 'injected primary build failure'
        $observed.DotnetCalls[0] | Should -BeExactly '--version'
        $observed.DotnetCalls[1] | Should -BeLike 'restore *'
        $observed.NormalizedVersionFailure.Exception.Message | Should -BeExactly 'GraphKit.Auth locked restore failed.'
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
            try {
                Invoke-GraphKitAuthPrepareClean -OutputRoot $fixtureOutput | Out-Null
            }
            finally {
                if ([IO.Directory]::Exists($fixtureOutput)) {
                    Set-GraphKitAuthTestTreeWritable -Path $fixtureOutput
                    [IO.Directory]::Delete($fixtureOutput, $true)
                }
            }
        }
    }

    It 'refuses to unseal a forged prior stage and leaves it in place' {
        $fixture = New-GraphKitAuthStageFixture -Name 'forged-clean'
        try {
            Set-GraphKitAuthTestStageWritable -StagePath $fixture.StagePath
            $manifestPath = Join-Path $fixture.StagePath 'manifest.json'
            [IO.File]::WriteAllText($manifestPath, '{"forged":true}')
            Set-GraphKitAuthTestStageSealed -StagePath $fixture.StagePath

            { Invoke-GraphKitAuthPrepareClean -OutputRoot $fixture.TestOutputRoot } |
                Should -Throw '*manifest digest does not match*'
            Test-Path -LiteralPath $fixture.StagePath -PathType Container | Should -BeTrue
            (Get-Content -LiteralPath $manifestPath -Raw) | Should -BeExactly '{"forged":true}'
        }
        finally {
            Remove-GraphKitAuthTestStageFixture -Fixture $fixture
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
        $cleanupArtifacts = [Collections.Generic.List[object]]::new()
        try {
            Invoke-GraphKitAuthStageMutation -Kind $Kind -StagePath $fixture.StagePath `
                -CleanupArtifacts $cleanupArtifacts
            $failure = $null
            try { $null = Test-GraphKitAuthSealedStage -StagePath $fixture.StagePath -FullVersion $fixture.FullVersion }
            catch { $failure = $_.Exception.Message }
            $failure | Should -Match $ExpectedDiagnostic
            $failure | Should -Not -Match 'version, envelope, or manifest is writable'
        }
        finally {
            Remove-GraphKitAuthTestMutationArtifacts -Artifacts $cleanupArtifacts
            Remove-GraphKitAuthTestStageFixture -Fixture $fixture
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
            Remove-GraphKitAuthTestStageFixture -Fixture $fixture
        }
    }

    It 'rejects a manifest hard link without an extra stage entry masking link count' {
        $fixture = New-GraphKitAuthStageFixture -Name 'manifest-hard-link'
        $cleanupArtifacts = [Collections.Generic.List[object]]::new()
        try {
            Set-GraphKitAuthTestStageWritable -StagePath $fixture.StagePath
            $manifestPath = Join-Path $fixture.StagePath 'manifest.json'
            $outsideLink = Join-Path $TestDrive ('manifest-hard-link-' + [guid]::NewGuid().ToString('N') + '.json')
            $linkArtifact = [pscustomobject]@{
                Path = $outsideLink; Directory = $false; Link = $true
                RestorePath = $manifestPath; Created = $false
            }
            $cleanupArtifacts.Add($linkArtifact) | Out-Null
            New-GraphKitAuthTestHardLink -LinkPath $outsideLink -TargetPath $manifestPath
            $linkArtifact.Created = $true
            $linked = $script:GraphKitAuthStageCaptureType::InspectFile(
                $fixture.StagePath, 'manifest.json')
            [long] $linked.LinkCount | Should -Be 2
            Set-GraphKitAuthTestStageSealed -StagePath $fixture.StagePath

            { Test-GraphKitAuthSealedStage -StagePath $fixture.StagePath -FullVersion $fixture.FullVersion } |
                Should -Throw '*manifest is not link-count one*'
        }
        finally {
            Remove-GraphKitAuthTestMutationArtifacts -Artifacts $cleanupArtifacts
            Remove-GraphKitAuthTestStageFixture -Fixture $fixture
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

    It 'leaves only recoverable authority state after injected <FailureKind> creation failure' -ForEach @(
        @{ FailureKind = 'auth root' }
        @{ FailureKind = 'capture root' }
        @{ FailureKind = 'stage root' }
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
        $authRoot = Join-Path $fixtureOutput 'GraphKit.Auth'
        Test-Path -LiteralPath $authRoot -PathType Container | Should -BeTrue
        { Invoke-GraphKitAuthPrepareClean -OutputRoot $fixtureOutput } |
            Should -Not -Throw
        foreach ($rootName in @('capture','stage')) {
            $root = Join-Path $authRoot $rootName
            if (Test-Path -LiteralPath $root -PathType Container) {
                @([IO.Directory]::EnumerateFileSystemEntries($root)).Count | Should -Be 0
            }
        }

        $recoveryVersion = '0.4.0-r8.fixture.recovery-' + $FailureKind.Replace(' ', '-')
        {
            $null = New-GraphKitAuthSealedStage -OutputRoot $fixtureOutput `
                -FullVersion $recoveryVersion `
                -PayloadSourceRoot (Join-Path $script:stagePath 'payload')
        } | Should -Not -Throw
        { Invoke-GraphKitAuthPrepareClean -OutputRoot $fixtureOutput } |
            Should -Not -Throw
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
                $observed[0].OwnerSid | Should -BeExactly $observed[0].CurrentOwnerSid
                $observed[0].CurrentIdentitySid | Should -BeExactly (
                    [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
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

    It 'creates one owner-only build workspace before routing mutable build output beneath it' {
        Assert-GraphKitAuthStageCommands
        $fixtureRoot = Join-Path $TestDrive ('build-workspace-owner-' + [guid]::NewGuid().ToString('N'))
        $fixtureOutput = Join-Path $fixtureRoot 'output'
        $null = New-Item -ItemType Directory -Path $fixtureOutput
        try {
            $null = Initialize-GraphKitAuthBuildAuthorityRoot -OutputRoot $fixtureOutput
            $runId = '1' * 48
            $workspace = New-GraphKitAuthBuildWorkRoot -OutputRoot $fixtureOutput -RunId $runId
            $authRoot = Join-Path $fixtureOutput 'GraphKit.Auth'
            $captureRoot = Join-Path $authRoot 'capture'

            $workspace.Name | Should -BeExactly ".build-$runId"
            $workspace.Path | Should -BeExactly (Join-Path $captureRoot ".build-$runId")
            $script:GraphKitAuthStageCaptureType::HasInitialOwnerOnlyDirectoryAccess(
                $workspace.Evidence) | Should -BeTrue
            $current = $script:GraphKitAuthStageCaptureType::InspectDirectory(
                $captureRoot, $workspace.Name)
            $current.NativeIdentity | Should -BeExactly $workspace.Evidence.NativeIdentity
            $current.PhysicalPath | Should -BeExactly $workspace.Evidence.PhysicalPath

            $taskSource = Get-Content -LiteralPath $script:taskPath -Raw
            $buildTaskSource = [regex]::Match(
                $taskSource,
                '(?ms)^\s*task Build_GraphKitAuth \{.*?^\s*\}\r?\n\r?\n\s*task Copy_GraphKitAuth_Into_BuiltModule'
            ).Value
            $workspaceIndex = $buildTaskSource.IndexOf(
                '$buildWork = New-GraphKitAuthBuildWorkRoot -OutputRoot')
            $resultIndex = $buildTaskSource.IndexOf(
                '$resultRoot = Join-Path $buildWork.Path ''dotnet-test''')
            $publishIndex = $buildTaskSource.IndexOf(
                '$publishRoot = Join-Path $buildWork.Path ''publish''')
            $firstMutableIndex = $buildTaskSource.IndexOf(
                '[IO.Directory]::CreateDirectory($resultRoot)')
            $workspaceIndex | Should -BeGreaterOrEqual 0
            $resultIndex | Should -BeGreaterThan $workspaceIndex
            $publishIndex | Should -BeGreaterThan $workspaceIndex
            $firstMutableIndex | Should -BeGreaterThan $workspaceIndex
            $buildTaskSource | Should -Not -Match '\$authOutput\s+["''](?:publish|dotnet-test)/\$runId' `
                -Because 'no mutable build artifact may be a top-level authority-root child'
            $finallyIndex = $buildTaskSource.LastIndexOf('finally {')
            $sourceQuarantineIndex = $buildTaskSource.IndexOf(
                'Invoke-GraphKitAuthLiteralQuarantine -RepositoryRoot $BuildRoot')
            $versionIndex = $buildTaskSource.IndexOf(
                "scripts/Get-GraphKitTrainVersion.ps1")
            $stageIndex = $buildTaskSource.IndexOf('New-GraphKitAuthSealedStage -OutputRoot')
            $workspaceQuarantineIndex = $buildTaskSource.IndexOf(
                'Move-GraphKitAuthBuildWorkToQuarantine', $finallyIndex)
            $sourceQuarantineIndex | Should -BeGreaterThan $workspaceIndex
            $versionIndex | Should -BeGreaterThan $sourceQuarantineIndex
            $stageIndex | Should -BeGreaterThan $versionIndex
            $workspaceQuarantineIndex | Should -BeGreaterThan $finallyIndex

            $normalQuarantine = Invoke-GraphKitAuthLiteralQuarantine -RepositoryRoot $fixtureRoot
            $null = Move-GraphKitAuthBuildWorkToQuarantine -BuildWork $workspace `
                -QuarantineRoot $normalQuarantine
            $createdEvidence = [Collections.Generic.List[object]]::new()
            $failedRunId = '4' * 48
            {
                New-GraphKitAuthBuildWorkRoot -OutputRoot $fixtureOutput -RunId $failedRunId `
                    -AfterCreate {
                        param($evidence)
                        $createdEvidence.Add($evidence)
                        throw 'injected workspace post-create validation failure'
                    }
            } | Should -Throw 'injected workspace post-create validation failure'
            $createdEvidence.Count | Should -Be 1
            @([IO.Directory]::EnumerateFileSystemEntries($captureRoot)).Count | Should -Be 0
            $recovered = @(Get-ChildItem -LiteralPath $fixtureOutput -Directory -Force | Where-Object {
                $_.Name -match '^GraphKit\.Auth\.quarantine-[0-9a-f]{32}$' -and
                (Test-Path -LiteralPath (Join-Path $_.FullName ".build-$failedRunId") -PathType Container)
            })
            $recovered.Count | Should -Be 1
            $recoveredEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory(
                $recovered[0].FullName, ".build-$failedRunId")
            $recoveredEvidence.NativeIdentity | Should -BeExactly $createdEvidence[0].NativeIdentity
        }
        finally {
            Set-GraphKitAuthTestTreeWritable -Path $fixtureRoot
            Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'quarantines the exact completed workspace and restores a Prepare-authorized topology' {
        Assert-GraphKitAuthStageCommands
        $fixtureRoot = Join-Path $TestDrive ('build-workspace-complete-' + [guid]::NewGuid().ToString('N'))
        $fixtureOutput = Join-Path $fixtureRoot 'output'
        $null = New-Item -ItemType Directory -Path $fixtureOutput
        try {
            $null = Initialize-GraphKitAuthBuildAuthorityRoot -OutputRoot $fixtureOutput
            $workspace = New-GraphKitAuthBuildWorkRoot -OutputRoot $fixtureOutput -RunId ('2' * 48)
            $publish = Join-Path $workspace.Path 'publish'
            $results = Join-Path $workspace.Path 'dotnet-test'
            $null = [IO.Directory]::CreateDirectory($publish)
            $null = [IO.Directory]::CreateDirectory($results)
            [IO.File]::WriteAllText((Join-Path $publish 'provider.bin'), 'provider payload')
            [IO.File]::WriteAllText((Join-Path $results 'GraphKit.Auth.trx'), 'test result')
            $publishHash = (Get-FileHash -LiteralPath (Join-Path $publish 'provider.bin') -Algorithm SHA256).Hash
            $resultHash = (Get-FileHash -LiteralPath (Join-Path $results 'GraphKit.Auth.trx') -Algorithm SHA256).Hash
            $stageVersion = '0.4.0-r8.fixture.build-workspace-complete'
            $stage = New-GraphKitAuthSealedStage -OutputRoot $fixtureOutput `
                -FullVersion $stageVersion `
                -PayloadSourceRoot (Join-Path $script:stagePath 'payload')

            $quarantine = Invoke-GraphKitAuthLiteralQuarantine -RepositoryRoot $fixtureRoot
            $moved = Move-GraphKitAuthBuildWorkToQuarantine -BuildWork $workspace `
                -QuarantineRoot $quarantine

            $moved.Evidence.NativeIdentity | Should -BeExactly $workspace.Evidence.NativeIdentity
            $moved.Path | Should -BeExactly (Join-Path $quarantine $workspace.Name)
            Test-Path -LiteralPath $workspace.Path | Should -BeFalse
            (Get-FileHash -LiteralPath (Join-Path $moved.Path 'publish/provider.bin') -Algorithm SHA256).Hash |
                Should -BeExactly $publishHash
            (Get-FileHash -LiteralPath (Join-Path $moved.Path 'dotnet-test/GraphKit.Auth.trx') -Algorithm SHA256).Hash |
                Should -BeExactly $resultHash
            $captureRoot = Join-Path $fixtureOutput 'GraphKit.Auth/capture'
            @([IO.Directory]::EnumerateFileSystemEntries($captureRoot)).Count | Should -Be 0
            $prepared = @(Invoke-GraphKitAuthPrepareClean -OutputRoot $fixtureOutput)
            $prepared.Count | Should -Be 1
            $prepared[0].StagePath | Should -BeExactly $stage.StagePath
        }
        finally {
            Set-GraphKitAuthTestTreeWritable -Path $fixtureRoot
            Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'fails closed before moving a workspace whose captured identity was replaced' {
        Assert-GraphKitAuthStageCommands
        $fixtureRoot = Join-Path $TestDrive ('build-workspace-tamper-' + [guid]::NewGuid().ToString('N'))
        $fixtureOutput = Join-Path $fixtureRoot 'output'
        $null = New-Item -ItemType Directory -Path $fixtureOutput
        try {
            $null = Initialize-GraphKitAuthBuildAuthorityRoot -OutputRoot $fixtureOutput
            $workspace = New-GraphKitAuthBuildWorkRoot -OutputRoot $fixtureOutput -RunId ('3' * 48)
            [IO.File]::WriteAllText((Join-Path $workspace.Path 'original.bin'), 'captured workspace')
            $captureRoot = Split-Path $workspace.Path -Parent
            $preserved = Join-Path $captureRoot '.preserved-original'
            $null = $script:GraphKitAuthStageCaptureType::CreateDirectoryOwnerOnly(
                $fixtureRoot, 'foreign')
            $foreignQuarantineName = 'GraphKit.Auth.quarantine-' + ('5' * 32)
            $null = $script:GraphKitAuthStageCaptureType::CreateDirectoryOwnerOnly(
                (Join-Path $fixtureRoot 'foreign'), $foreignQuarantineName)
            $foreignQuarantine = Join-Path (Join-Path $fixtureRoot 'foreign') $foreignQuarantineName
            {
                Move-GraphKitAuthBuildWorkToQuarantine -BuildWork $workspace `
                    -QuarantineRoot $foreignQuarantine
            } | Should -Throw '*not beneath the exact captured output root*'
            Test-Path -LiteralPath $workspace.Path -PathType Container | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $foreignQuarantine $workspace.Name) | Should -BeFalse

            $replacedQuarantine = Invoke-GraphKitAuthLiteralQuarantine -RepositoryRoot $fixtureRoot
            $replacedQuarantineName = [IO.Path]::GetFileName($replacedQuarantine)
            $preservedQuarantine = Join-Path $fixtureOutput '.preserved-quarantine'
            $replacedQuarantineEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory(
                $fixtureOutput, $replacedQuarantineName)
            {
                Move-GraphKitAuthBuildWorkToQuarantine -BuildWork $workspace `
                    -QuarantineRoot $replacedQuarantine -BeforeMove {
                        [IO.Directory]::Move($replacedQuarantine, $preservedQuarantine)
                        $null = $script:GraphKitAuthStageCaptureType::CreateDirectoryOwnerOnly(
                            $fixtureOutput, $replacedQuarantineName)
                    }
            } | Should -Throw '*quarantine changed identity before the move*ambiguous cleanup was refused*'
            $preservedQuarantineEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory(
                $fixtureOutput, '.preserved-quarantine')
            $preservedQuarantineEvidence.NativeIdentity |
                Should -BeExactly $replacedQuarantineEvidence.NativeIdentity
            Test-Path -LiteralPath $workspace.Path -PathType Container | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $replacedQuarantine $workspace.Name) | Should -BeFalse

            $collisionQuarantine = Invoke-GraphKitAuthLiteralQuarantine -RepositoryRoot $fixtureRoot
            $collisionDestination = $script:GraphKitAuthStageCaptureType::CreateDirectoryOwnerOnly(
                $collisionQuarantine, $workspace.Name)
            [IO.File]::WriteAllText(
                (Join-Path $collisionQuarantine "$($workspace.Name)/caller.bin"), 'caller destination')
            $sourceBeforeCollision = $script:GraphKitAuthStageCaptureType::InspectDirectory(
                $captureRoot, $workspace.Name)
            {
                Move-GraphKitAuthBuildWorkToQuarantine -BuildWork $workspace `
                    -QuarantineRoot $collisionQuarantine
            } | Should -Throw '*destination*already exists*no move was attempted*'
            $sourceAfterCollision = $script:GraphKitAuthStageCaptureType::InspectDirectory(
                $captureRoot, $workspace.Name)
            $destinationAfterCollision = $script:GraphKitAuthStageCaptureType::InspectDirectory(
                $collisionQuarantine, $workspace.Name)
            $sourceAfterCollision.NativeIdentity | Should -BeExactly $sourceBeforeCollision.NativeIdentity
            $destinationAfterCollision.NativeIdentity | Should -BeExactly $collisionDestination.NativeIdentity
            (Get-Content -LiteralPath (
                Join-Path $collisionQuarantine "$($workspace.Name)/caller.bin") -Raw) |
                Should -BeExactly 'caller destination'

            $quarantine = Invoke-GraphKitAuthLiteralQuarantine -RepositoryRoot $fixtureRoot

            {
                Move-GraphKitAuthBuildWorkToQuarantine -BuildWork $workspace `
                    -QuarantineRoot $quarantine -BeforeMove {
                        [IO.Directory]::Move($workspace.Path, $preserved)
                        $null = $script:GraphKitAuthStageCaptureType::CreateDirectoryOwnerOnly(
                            $captureRoot, $workspace.Name)
                        [IO.File]::WriteAllText(
                            (Join-Path $workspace.Path 'replacement.bin'), 'caller replacement')
                    }
            } | Should -Throw '*changed identity*ambiguous cleanup was refused*'

            $preservedEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory(
                $captureRoot, '.preserved-original')
            $preservedEvidence.NativeIdentity | Should -BeExactly $workspace.Evidence.NativeIdentity
            Test-Path -LiteralPath (Join-Path $workspace.Path 'replacement.bin') -PathType Leaf |
                Should -BeTrue
            Test-Path -LiteralPath (Join-Path $quarantine $workspace.Name) | Should -BeFalse

            $ancestorFixtureRoot = Join-Path $fixtureRoot 'ancestor-case'
            $ancestorOutput = Join-Path $ancestorFixtureRoot 'output'
            $null = [IO.Directory]::CreateDirectory($ancestorOutput)
            $null = Initialize-GraphKitAuthBuildAuthorityRoot -OutputRoot $ancestorOutput
            $ancestorWork = New-GraphKitAuthBuildWorkRoot `
                -OutputRoot $ancestorOutput -RunId ('6' * 48)
            $ancestorCapture = Split-Path $ancestorWork.Path -Parent
            $ancestorQuarantine = Invoke-GraphKitAuthLiteralQuarantine `
                -RepositoryRoot $ancestorFixtureRoot
            $ancestorQuarantineName = [IO.Path]::GetFileName($ancestorQuarantine)
            $ancestorCaptureEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectoryPath(
                $ancestorCapture)
            $ancestorQuarantineEvidence = $script:GraphKitAuthStageCaptureType::InspectDirectory(
                $ancestorOutput, $ancestorQuarantineName)
            $preservedAncestorOutput = Join-Path $ancestorFixtureRoot 'preserved-output'
            {
                Move-GraphKitAuthBuildWorkToQuarantine -BuildWork $ancestorWork `
                    -QuarantineRoot $ancestorQuarantine -BeforeMove {
                        [IO.Directory]::Move($ancestorOutput, $preservedAncestorOutput)
                        $null = $script:GraphKitAuthStageCaptureType::CreateDirectoryOwnerOnly(
                            $ancestorFixtureRoot, 'output')
                        $replacementAuth = Join-Path $ancestorOutput 'GraphKit.Auth'
                        $null = $script:GraphKitAuthStageCaptureType::CreateDirectoryOwnerOnly(
                            $ancestorOutput, 'GraphKit.Auth')
                        [IO.Directory]::Move(
                            (Join-Path $preservedAncestorOutput 'GraphKit.Auth/capture'),
                            (Join-Path $replacementAuth 'capture'))
                        [IO.Directory]::Move(
                            (Join-Path $preservedAncestorOutput $ancestorQuarantineName),
                            (Join-Path $ancestorOutput $ancestorQuarantineName))
                    }
            } | Should -Throw '*output parent changed identity before the move*ambiguous cleanup was refused*'
            $ancestorCaptureAfter = $script:GraphKitAuthStageCaptureType::InspectDirectory(
                (Join-Path $ancestorOutput 'GraphKit.Auth'), 'capture')
            $ancestorQuarantineAfter = $script:GraphKitAuthStageCaptureType::InspectDirectory(
                $ancestorOutput, $ancestorQuarantineName)
            $ancestorCaptureAfter.NativeIdentity |
                Should -BeExactly $ancestorCaptureEvidence.NativeIdentity
            $ancestorQuarantineAfter.NativeIdentity |
                Should -BeExactly $ancestorQuarantineEvidence.NativeIdentity
            Test-Path -LiteralPath $ancestorWork.Path -PathType Container | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $ancestorQuarantine $ancestorWork.Name) |
                Should -BeFalse
        }
        finally {
            Set-GraphKitAuthTestTreeWritable -Path $fixtureRoot
            Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'quarantines one partial workspace in finally without replacing the primary build failure' {
        $observed = & {
            $tasks = @{}
            function Register-GraphKitAuthTaskCapture {
                param([string] $Name, [scriptblock] $Action)
                $tasks[$Name] = $Action
            }
            Set-Alias -Name task -Value Register-GraphKitAuthTaskCapture -Scope Local
            . $script:taskPath

            $sourceQuarantines = [Collections.Generic.List[string]]::new()
            $workspaceQuarantines = [Collections.Generic.List[object]]::new()
            function Initialize-GraphKitAuthStageCapture {}
            function Initialize-GraphKitAuthBuildAuthorityRoot {}
            function New-GraphKitAuthBuildWorkRoot {
                [pscustomobject]@{ Path='fixture-work'; Name='.build-fixture'; Evidence='fixture-evidence' }
            }
            function Invoke-GraphKitAuthLiteralQuarantine {
                param([string] $RepositoryRoot)
                $sourceQuarantines.Add($RepositoryRoot)
                throw 'injected source quarantine failure'
            }
            function New-GraphKitAuthTaskQuarantineRoot {
                param([string] $OutputRoot)
                [pscustomobject]@{ Path='fixture-work-quarantine' }
            }
            function Move-GraphKitAuthBuildWorkToQuarantine {
                param($BuildWork, [string] $QuarantineRoot)
                $workspaceQuarantines.Add([pscustomobject]@{
                    BuildWork = $BuildWork
                    QuarantineRoot = $QuarantineRoot
                })
                [pscustomobject]@{ Path=(Join-Path $QuarantineRoot $BuildWork.Name) }
            }
            function dotnet {
                param([Parameter(ValueFromRemainingArguments)][object[]] $Arguments)
                if (($Arguments -join ' ') -ceq '--version') {
                    $global:LASTEXITCODE = 0
                    '10.0.400'
                    return
                }
                $global:LASTEXITCODE = 1
            }

            $BuildRoot = Join-Path $TestDrive ('build-workspace-primary-' + [guid]::NewGuid().ToString('N'))
            $failure = $null
            $lastExitCodeVariable = Get-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
            $savedWarningPreference = $WarningPreference
            try {
                $WarningPreference = 'Stop'
                try { & $tasks['Build_GraphKitAuth'] }
                catch { $failure = $_ }
            }
            finally {
                $WarningPreference = $savedWarningPreference
                if ($null -eq $lastExitCodeVariable) {
                    Remove-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
                }
                else {
                    $global:LASTEXITCODE = $lastExitCodeVariable.Value
                }
            }
            [pscustomobject]@{
                Failure = $failure
                SourceQuarantines = @($sourceQuarantines)
                WorkspaceQuarantines = @($workspaceQuarantines)
            }
        }

        $observed.Failure.Exception.Message | Should -BeExactly 'GraphKit.Auth locked restore failed.'
        $observed.SourceQuarantines.Count | Should -Be 1
        $observed.WorkspaceQuarantines.Count | Should -Be 1
        $observed.WorkspaceQuarantines[0].BuildWork.Path | Should -BeExactly 'fixture-work'
        $observed.WorkspaceQuarantines[0].QuarantineRoot |
            Should -BeExactly 'fixture-work-quarantine'
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

    It 'preserves a recoverable build authority root when capture initialization fails' {
        Assert-GraphKitAuthStageCommands
        $fixtureOutput = Join-Path $TestDrive ('build-authority-capture-failure-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $fixtureOutput
        $failure = $null
        try {
            try {
                $null = Initialize-GraphKitAuthBuildAuthorityRoot -OutputRoot $fixtureOutput `
                    -AfterChildInspection {
                        param($kind)
                        if ($kind -ceq 'build capture root') {
                            throw 'injected build capture root failure'
                        }
                    }
            }
            catch { $failure = $_.Exception.Message }

            $failure | Should -BeExactly 'injected build capture root failure'
            $authRoot = Join-Path $fixtureOutput 'GraphKit.Auth'
            Test-Path -LiteralPath $authRoot -PathType Container | Should -BeTrue
            $captureRoot = Join-Path $authRoot 'capture'
            Test-Path -LiteralPath $captureRoot -PathType Container | Should -BeTrue
            @([IO.Directory]::EnumerateFileSystemEntries($captureRoot)).Count | Should -Be 0
            { Invoke-GraphKitAuthPrepareClean -OutputRoot $fixtureOutput } |
                Should -Not -Throw
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
        $outputRoot = $fixture.TestOutputRoot
        $authRoot = Join-Path $outputRoot 'GraphKit.Auth'
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
            Remove-GraphKitAuthTestStageFixture -Fixture $fixture
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

    It 'normalizes native Windows paths and handles unavailable Linux renameat2 fail-closed' {
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
        $extender = $script:GraphKitAuthStageCaptureType.GetMethod(
            'ToExtendedWindowsPath',
            [Reflection.BindingFlags]'NonPublic, Static')
        $extender | Should -Not -BeNullOrEmpty
        $extender.Invoke($null, [object[]] @('C:\repo\file.bin')) |
            Should -BeExactly '\\?\C:\repo\file.bin'
        $extender.Invoke($null, [object[]] @('\\server\share\file.bin')) |
            Should -BeExactly '\\?\UNC\server\share\file.bin'
        $extender.Invoke($null, [object[]] @('\\?\C:\repo\file.bin')) |
            Should -BeExactly '\\?\C:\repo\file.bin'
        { $extender.Invoke($null, [object[]] @('relative\file.bin')) } |
            Should -Throw '*fully qualified Windows path*'
        { $extender.Invoke($null, [object[]] @('\\.\PhysicalDrive0')) } |
            Should -Throw '*Windows device path*'

        $linkSafetyRoot = Join-Path $TestDrive (
            'acl-link-safety-' + [guid]::NewGuid().ToString('N'))
        $targetPath = Join-Path $TestDrive (
            'acl-link-target-' + [guid]::NewGuid().ToString('N') + '.bin')
        $null = New-Item -ItemType Directory -Path $linkSafetyRoot
        try {
            $regularPath = Join-Path $linkSafetyRoot 'regular.bin'
            $hardLinkPath = Join-Path $linkSafetyRoot 'hard-link.bin'
            [IO.File]::WriteAllText($regularPath, 'regular')
            [IO.File]::WriteAllText($targetPath, 'shared')
            $null = New-Item -ItemType HardLink -Path $hardLinkPath `
                -Target $targetPath -ErrorAction Stop

            (Test-GraphKitAuthTestAclMutationSafe -Item (
                Get-Item -LiteralPath $regularPath -Force)) | Should -BeTrue
            (Test-GraphKitAuthTestAclMutationSafe -Item (
                Get-Item -LiteralPath $hardLinkPath -Force)) | Should -BeFalse
            (Test-GraphKitAuthTestAclMutationSafe -Item ([pscustomobject] @{
                LinkType = $null
                Attributes = [IO.FileAttributes]::ReparsePoint
            })) | Should -BeFalse

            if ($IsWindows) {
                $targetAclBefore = (Get-Acl -LiteralPath $targetPath).Sddl
                $targetAttributesBefore = [IO.File]::GetAttributes($targetPath)
            }
            else {
                [IO.File]::SetUnixFileMode(
                    $targetPath, [IO.UnixFileMode]::UserRead)
                $targetUnixModeBefore = [IO.File]::GetUnixFileMode($targetPath)
            }
            { Set-GraphKitAuthTestTreeWritable -Path $linkSafetyRoot } |
                Should -Throw '*refused a link or reparse entry*'
            if ($IsWindows) {
                (Get-Acl -LiteralPath $targetPath).Sddl |
                    Should -BeExactly $targetAclBefore
                [IO.File]::GetAttributes($targetPath) |
                    Should -Be $targetAttributesBefore
            }
            else {
                [IO.File]::GetUnixFileMode($targetPath) |
                    Should -Be $targetUnixModeBefore
            }

            Remove-Item -LiteralPath $linkSafetyRoot -Recurse -Force
            (Test-Path -LiteralPath $hardLinkPath) | Should -BeFalse
            (Test-Path -LiteralPath $targetPath -PathType Leaf) | Should -BeTrue
        }
        finally {
            Remove-Item -LiteralPath $linkSafetyRoot -Recurse -Force `
                -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $targetPath -Force -ErrorAction SilentlyContinue
        }

        $liveParityTestPath = Join-Path -Path $script:repoRoot `
            -ChildPath 'tests/QA/GraphKitAuthLiveParity.tests.ps1'
        $liveParityTest = Get-Content -LiteralPath $liveParityTestPath -Raw
        $liveParityTest | Should -Match (
            '(?s)IsNullOrEmpty\(\[string\]\s*\$item\.LinkType\).*?ReparsePoint')

        $aliasVersion = Join-Path $TestDrive (
            'acl-alias-version-' + [guid]::NewGuid().ToString('N'))
        $outsideStage = Join-Path $TestDrive (
            'acl-alias-target-' + [guid]::NewGuid().ToString('N'))
        $stageAlias = Join-Path $aliasVersion 'stage'
        $null = New-Item -ItemType Directory -Path $aliasVersion, (
            Join-Path $outsideStage 'payload') -Force
        try {
            $outsideSecurityBefore = if ($IsWindows) {
                (Get-Acl -LiteralPath $outsideStage).Sddl
            }
            else {
                [IO.File]::GetUnixFileMode($outsideStage)
            }
            $null = New-Item -ItemType $(if ($IsWindows) { 'Junction' } else {
                'SymbolicLink'
            }) -Path $stageAlias -Target $outsideStage -ErrorAction Stop

            { Set-GraphKitAuthTestStageWritable -StagePath $stageAlias } |
                Should -Throw '*refused a link or reparse root*'
            if ($IsWindows) {
                (Get-Acl -LiteralPath $outsideStage).Sddl |
                    Should -BeExactly $outsideSecurityBefore
            }
            else {
                [IO.File]::GetUnixFileMode($outsideStage) |
                    Should -Be $outsideSecurityBefore
            }
        }
        finally {
            Remove-Item -LiteralPath $stageAlias -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $aliasVersion -Recurse -Force `
                -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $outsideStage -Recurse -Force `
                -ErrorAction SilentlyContinue
        }
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
        $linkCreated = $false
        try {
            $null = New-Item -ItemType Junction -Path $linkPath -Target $external `
                -ErrorAction Stop
            $linkCreated = $true
            { New-GraphKitAuthSealedStage -OutputRoot $fixtureOutput -FullVersion "0.4.0-r8.fixture.junction-$RootKind" `
                -PayloadSourceRoot (Join-Path $script:stagePath 'payload') } |
                Should -Throw '*not the required no-follow directory*'

            (Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash | Should -BeExactly $hashBefore
            (Get-Acl -LiteralPath $external).Sddl | Should -BeExactly $aclBefore
            @([IO.Directory]::EnumerateFileSystemEntries($external) | ForEach-Object { [IO.Path]::GetFileName($_) }) |
                Should -BeExactly @('caller-owned.txt')
        }
        finally {
            try {
                if ($linkCreated -and [IO.Directory]::Exists($linkPath)) {
                    [IO.Directory]::Delete($linkPath, $false)
                }
            }
            finally {
                if ([IO.Directory]::Exists($fixtureRoot)) {
                    Set-GraphKitAuthTestTreeWritable -Path $fixtureRoot
                    [IO.Directory]::Delete($fixtureRoot, $true)
                }
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
                    Should -BeExactly $fixture.ManifestInitialEvidence.CurrentOwnerSid
                $fixture.ManifestInitialEvidence.CurrentIdentitySid | Should -BeExactly (
                    [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
            }
            else {
                $fixture.ManifestInitialEvidence.UnixMode | Should -Be 0x180
            }
        }
        finally {
            Remove-GraphKitAuthTestStageFixture -Fixture $fixture
        }
    }

    It 'rejects owner-mismatched initial and sealed evidence' {
        Initialize-GraphKitAuthStageCapture
        $evidence = [Activator]::CreateInstance($script:GraphKitAuthStageCaptureType.Assembly.GetType(
            $script:GraphKitAuthStageCaptureType.Namespace + '.GraphKitAuthPathEvidence'))
        $evidence.OwnerOnlyAccess = $true
        $evidence.OwnerSid = 'S-1-5-21-111'
        $evidence.CurrentIdentitySid = 'S-1-5-21-333'
        $evidence.CurrentOwnerSid = 'S-1-5-21-222'

        $script:GraphKitAuthStageCaptureType::HasInitialOwnerOnlyAccess($evidence) | Should -BeFalse
        if (-not $IsWindows) {
            $evidence.UnixMode = 0x100
            $evidence.OwnerUid = [uint32] 1
            $evidence.EffectiveUid = [uint32] 2
            (Test-GraphKitAuthSealedPermission -Evidence $evidence -Directory $false) |
                Should -BeFalse
        }
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

    It 'records a copied ABI projection before any subsequent validation' {
        $task = Get-Content -LiteralPath $script:taskPath -Raw
        $fixtureSource = [regex]::Match(
            $task,
            '(?ms)^function New-GraphKitAuthAbiTestFixture \{.*?^\}'
        ).Value
        $copyIndex = $fixtureSource.IndexOf(
            '$copy = $script:GraphKitAuthStageCaptureType::CopyFileCreateNew(')
        $createdPathIndex = $fixtureSource.IndexOf(
            '$script:GraphKitAuthAbiFixtureState.CreatedPaths.Add($destinationFile)',
            $copyIndex)
        $evidenceIndex = $fixtureSource.IndexOf(
            '$script:GraphKitAuthAbiFixtureState.ExpectedEvidence[$destinationFile] = $copy.Destination',
            $createdPathIndex)
        $validationIndex = $fixtureSource.IndexOf(
            '$manifestRecord = @($verified.Manifest.files',
            $evidenceIndex)

        $copyIndex | Should -BeGreaterOrEqual 0
        $createdPathIndex | Should -BeGreaterThan $copyIndex
        $evidenceIndex | Should -BeGreaterThan $createdPathIndex
        $validationIndex | Should -BeGreaterThan $evidenceIndex
    }

    It 'uses the platform-safe <Operation> failure policy before evidence with owner-only=<OwnerOnly>' -ForEach @(
        @{ Operation = 'copy'; OwnerOnly = $false }
        @{ Operation = 'copy'; OwnerOnly = $true }
        @{ Operation = 'write'; OwnerOnly = $false }
        @{ Operation = 'write'; OwnerOnly = $true }
    ) {
        Initialize-GraphKitAuthStageCapture
        $root = Join-Path $TestDrive (
            "$Operation-post-create-failure-$OwnerOnly-" + [guid]::NewGuid().ToString('N'))
        $source = Join-Path $root 'source'
        $destination = Join-Path $root 'destination'
        $null = New-Item -ItemType Directory -Path $source, $destination -Force
        [IO.File]::WriteAllBytes((Join-Path $source 'candidate.dll'), [byte[]](1..32))
        $captured = Join-Path $destination 'candidate.dll'
        $sourceHash = (Get-FileHash -LiteralPath (Join-Path $source 'candidate.dll') `
            -Algorithm SHA256).Hash
        $parentBefore = $script:GraphKitAuthStageCaptureType::InspectDirectoryPath($destination)

        $failure = $null
        try {
            if ($Operation -ceq 'copy') {
                $null = $script:GraphKitAuthStageCaptureType::CopyFileCreateNew(
                    $source, 'candidate.dll', $destination, 'candidate.dll',
                    $OwnerOnly, [long]::MaxValue, $true)
            }
            else {
                $null = $script:GraphKitAuthStageCaptureType::WriteFileCreateNew(
                    $destination, 'candidate.dll', [byte[]](33..64),
                    $OwnerOnly, $true)
            }
        }
        catch { $failure = $_.Exception.Message }

        $failure | Should -Match "Injected post-create $Operation failure"
        $parentAfter = $script:GraphKitAuthStageCaptureType::InspectDirectoryPath($destination)
        $parentAfter.NativeIdentity | Should -BeExactly $parentBefore.NativeIdentity
        $parentAfter.PhysicalPath | Should -BeExactly $parentBefore.PhysicalPath
        (Get-FileHash -LiteralPath (Join-Path $source 'candidate.dll') -Algorithm SHA256).Hash |
            Should -BeExactly $sourceHash
        if ($IsWindows) {
            Test-Path -LiteralPath $captured | Should -BeFalse
            $failure | Should -Not -Match 'no path deletion|zero-byte collision|explicitly recover'
        }
        else {
            Test-Path -LiteralPath $captured -PathType Leaf | Should -BeTrue
            (Get-Item -LiteralPath $captured).Length | Should -Be 0
            $failure | Should -Match 'Unix has no portable exact-handle path-deletion primitive'
            $failure | Should -Match 'did not delete any path'
            $failure | Should -Match 'explicitly recover the zero-byte collision'
        }
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

    It 'declares exact Windows ACL evidence and preserves handle-bound mutation ordering' {
        $helper = Get-Content -LiteralPath (
            Join-Path $script:repoRoot 'scripts/private/GraphKit.AuthStageCapture.cs') -Raw
        $task = Get-Content -LiteralPath $script:taskPath -Raw
        Get-Command Set-GraphKitAuthWindowsAclMutation -CommandType Function -ErrorAction Stop |
            Should -Not -BeNullOrEmpty
        foreach ($property in @(
            'OwnerSid', 'CurrentIdentitySid', 'CurrentOwnerSid', 'AccessRulesProtected',
            'HasInheritedAccessRules', 'ExactOwnerOnlyAccess'
        )) {
            $helper | Should -Match ([regex]::Escape($property + ' { get; init; }'))
            $task | Should -Match ([regex]::Escape('$Evidence.' + $property))
        }
        $helper | Should -Match (
            'FileSystemRights expectedRights\s*=\s*FileSystemRights\.ReadAndExecute\s*\|\s*FileSystemRights\.Synchronize')
        $helper | Should -Match (
            'writable\s*\?\s*FileSystemRights\.FullControl\s*:\s*FileSystemRights\.ReadAndExecute')
        $task | Should -Not -Match "'windows-owner-read'"
        $task | Should -Match (
            "permissions\.file -cne .*?'windows-owner-read-execute'")
        $helper | Should -Match 'InheritanceFlags\.None'
        $helper | Should -Match ([regex]::Escape(
            'private const uint WriteDacAccess = 0x00040000;'))
        $helper | Should -Match ([regex]::Escape(
            'private const uint WriteOwnerAccess = 0x00080000;'))
        @([regex]::Matches($helper,
            'SetOwnerOnlyWritableFile\(\s*destinationStream,\s*destinationPath\)')).Count |
            Should -Be 2
        $handleSetter = [regex]::Match($helper,
            '(?ms)^    private static void SetOwnerOnlyWritableFile\(.*?(?=^    private static )').Value
        $handleSetter | Should -Not -BeNullOrEmpty
        $handleSetter | Should -Match (
            'FileSystemAclExtensions\.SetAccessControl\(\s*stream,\s*security\)')
        $handleSetter | Should -Not -Match 'SetOwnerOnlyWindows|new FileInfo|File\.SetAttributes'
        $nativeFacts = [regex]::Match($helper,
            '(?ms)^    private static NativeFacts GetNativeFacts\(.*?(?=^    private static )').Value
        $nativeFacts | Should -Match (
            'GetWindowsPermissionFacts\(\s*handle,\s*directory,\s*info\.FileAttributes\)')
        $nativeFacts | Should -Match 'ownerUid\s*=\s*BitConverter\.ToUInt32\(stat,\s*16\)'
        $nativeFacts | Should -Match 'ownerUid\s*=\s*BitConverter\.ToUInt32\(stat,\s*24\)'
        $nativeFacts | Should -Match 'ownerUid\s*=\s*BitConverter\.ToUInt32\(stat,\s*28\)'
        $nativeFacts | Should -Match 'effectiveUid\s*=\s*geteuid\(\)'
        $permissionReader = [regex]::Match($helper,
            '(?ms)^    private static WindowsPermissionFacts GetWindowsPermissionFacts\(.*?(?=^    private static )').Value
        $permissionReader | Should -Match 'GetSecurityInfo\(\s*handle,'
        $permissionReader | Should -Match 'fileAttributes\s*&\s*FileAttributeReadOnly'
        $permissionReader | Should -Match 'GetCurrentTokenOwnerSid\(\)'
        $permissionReader | Should -Not -Match 'new DirectoryInfo|new FileInfo|File\.GetAttributes'
        $helper | Should -Match 'GetTokenInformation\(\s*identity\.Token,\s*TokenOwner'
        $openDestination = [regex]::Match($helper,
            '(?ms)^    private static FileStream OpenDestinationCreateNew\(.*?(?=^    private static )').Value
        $openDestination | Should -Match (
            'GenericRead \| GenericWrite \| DeleteAccess \| WriteDacAccess \| WriteOwnerAccess')
        $openDestination | Should -Match '(?s)CreateFileWithSecurityW\(.*?ShareRead,'
        $openDestination | Should -Match '(?s)CreateFileW\(.*?ShareRead,'
        $openDestination | Should -Not -Match 'ShareWrite|ShareDelete'
        $pathSetter = [regex]::Match($helper,
            '(?ms)^    private static void SetOwnerOnlyWindows\(.*?(?=^    private )').Value
        $pathSetter | Should -Match (
            '(?s)currentTokenOwner = GetCurrentTokenOwnerSid\(\);.*?if \(!currentOwner\.Equals\(currentTokenOwner\)\).*?throw new IOException')
        $pathSetter | Should -Match (
            'CreateOwnerOnlyWindowsSecurity\(\s*directory,\s*writable,\s*setOwner: false\)')
        $pathSetter | Should -Not -Match 'security\.SetOwner|setOwner\s*='
        $sealAttributes = $pathSetter.IndexOf('if (!directory && !writable &&')
        $applyAcl = $pathSetter.IndexOf('FileSystemAclExtensions.SetAccessControl')
        $unsealAttributes = $pathSetter.IndexOf('if (!directory && writable &&')
        $pathSetter | Should -Match (
            'FileAttributes attributes = directory \? default : File\.GetAttributes\(path\);')
        $pathSetter | Should -Match (
            '(?s)!writable.*?== 0.*?File\.SetAttributes\(\s*path,\s*\(attributes & ~FileAttributes\.Normal\) \|\s*FileAttributes\.ReadOnly\)')
        $pathSetter | Should -Match (
            '(?s)writable.*?!= 0.*?FileAttributes writableAttributes =\s*attributes & ~FileAttributes\.ReadOnly;.*?writableAttributes == 0 \? FileAttributes\.Normal : writableAttributes')
        $sealAttributes | Should -BeGreaterOrEqual 0
        $applyAcl | Should -BeGreaterThan $sealAttributes
        $unsealAttributes | Should -BeGreaterThan $applyAcl
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
        @([regex]::Matches($helper,
            'OpenDestinationCreateNew\(\s*destinationPath,\s*requireInitialOwnerOnly\)')).Count |
            Should -Be 2
        $helper | Should -Match '(?s)FileSecurity security = new\(\);.*security\.SetOwner\(owner\);.*security\.SetAccessRuleProtection\(isProtected: true, preserveInheritance: false\);.*CreateFileWithSecurityW'
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
        $parentEvidence.PSObject.Properties.Name | Should -Contain 'OwnerUid'
        $parentEvidence.PSObject.Properties.Name | Should -Contain 'EffectiveUid'
        $parentEvidence.OwnerUid | Should -Be $parentEvidence.EffectiveUid
        $wrongDirectoryOwner = [Activator]::CreateInstance($parentEvidence.GetType())
        $wrongDirectoryOwner.GetType().GetProperty('UnixMode').SetValue(
            $wrongDirectoryOwner, [int] 0x1C0)
        $wrongDirectoryOwner.GetType().GetProperty('IsDirectory').SetValue(
            $wrongDirectoryOwner, $true)
        $wrongDirectoryOwner.GetType().GetProperty('OwnerUid').SetValue(
            $wrongDirectoryOwner, [uint32] 1)
        $wrongDirectoryOwner.GetType().GetProperty('EffectiveUid').SetValue(
            $wrongDirectoryOwner, [uint32] 2)
        $script:GraphKitAuthStageCaptureType::HasInitialOwnerOnlyDirectoryAccess(
            $wrongDirectoryOwner) | Should -BeFalse
        $copy.DestinationInitial.UnixMode | Should -Be 0x180
        $copy.DestinationInitial.OwnerUid | Should -Be $copy.DestinationInitial.EffectiveUid
        $wrongFileOwner = [Activator]::CreateInstance($copy.DestinationInitial.GetType())
        $wrongFileOwner.GetType().GetProperty('UnixMode').SetValue(
            $wrongFileOwner, [int] 0x180)
        $wrongFileOwner.GetType().GetProperty('OwnerUid').SetValue(
            $wrongFileOwner, [uint32] 1)
        $wrongFileOwner.GetType().GetProperty('EffectiveUid').SetValue(
            $wrongFileOwner, [uint32] 2)
        $script:GraphKitAuthStageCaptureType::HasInitialOwnerOnlyAccess(
            $wrongFileOwner) | Should -BeFalse
        $copy.Destination.UnixMode | Should -Be 0x180
    }

    It 'creates a Windows child with current-identity access and round trips repeated seal transitions' -ForEach $windowsInitialAccessCases -AllowNullOrEmptyForEach {
        Initialize-GraphKitAuthStageCapture
        $longParent = Join-Path $TestDrive ('windows-initial-access-' + ('a' * 120))
        $root = Join-Path $longParent ('nested-' + ('b' * 120))
        $source = Join-Path $root 'source'
        $destination = Join-Path $root 'destination'
        $null = New-Item -ItemType Directory -Path $source, $destination -Force
        $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $worldSid = [Security.Principal.SecurityIdentifier]::new(
            [Security.Principal.WellKnownSidType]::WorldSid, $null)
        $acl = [Security.AccessControl.DirectorySecurity]::new()
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
        [IO.FileSystemAclExtensions]::SetAccessControl(
            [IO.DirectoryInfo]::new($destination), $acl)
        [IO.File]::WriteAllBytes((Join-Path $source 'candidate.dll'), [byte[]](1..32))

        $copy = $script:GraphKitAuthStageCaptureType::CopyFileCreateNew(
            $source, 'candidate.dll', $destination, 'candidate.dll', $true)
        $ordinaryBytes = [Text.Encoding]::UTF8.GetBytes('ordinary-long-path-write')
        $ordinaryWrite = $script:GraphKitAuthStageCaptureType::WriteFileCreateNew(
            $destination, 'ordinary.bin', $ordinaryBytes, $false)

        $copy.DestinationInitial.OwnerOnlyAccess | Should -BeTrue
        $copy.DestinationInitial.OwnerSid |
            Should -BeExactly $copy.DestinationInitial.CurrentOwnerSid
        $copy.DestinationInitial.CurrentIdentitySid | Should -BeExactly $currentSid.Value
        $copy.DestinationInitial.AccessRulesProtected | Should -BeTrue
        $copy.DestinationInitial.HasInheritedAccessRules | Should -BeFalse
        $copy.Destination.PhysicalPath.StartsWith('\\?\', [StringComparison]::Ordinal) |
            Should -BeFalse
        $ordinaryWrite.Destination.PhysicalPath.StartsWith(
            '\\?\', [StringComparison]::Ordinal) | Should -BeFalse
        $ordinaryWrite.Destination.Sha256 | Should -BeExactly (
            [Convert]::ToHexString(
                [Security.Cryptography.SHA256]::HashData($ordinaryBytes)).ToLowerInvariant())
        $ordinaryPath = Join-Path $destination 'ordinary.bin'
        $ordinaryOwner = [IO.FileSystemAclExtensions]::GetAccessControl(
            [IO.FileInfo]::new($ordinaryPath),
            [Security.AccessControl.AccessControlSections]::Owner
        ).GetOwner([Security.Principal.SecurityIdentifier]).Value
        $ordinaryWrite.Destination.OwnerSid | Should -BeExactly $ordinaryOwner
        $ordinaryWrite.Destination.CurrentOwnerSid | Should -BeExactly $ordinaryOwner
        $ordinaryWrite.Destination.CurrentIdentitySid | Should -BeExactly $currentSid.Value
        { $script:GraphKitAuthStageCaptureType::WriteFileCreateNew(
            $destination, 'ordinary.bin', $ordinaryBytes, $false) } |
            Should -Throw '*Atomic file destination collision*'

        $raceOriginalName = 'permission-original.bin'
        $raceReplacementName = 'permission-replacement.bin'
        $raceParkedName = 'permission-original-parked.bin'
        $raceOriginal = Join-Path $destination $raceOriginalName
        $raceReplacement = Join-Path $destination $raceReplacementName
        $raceParked = Join-Path $destination $raceParkedName
        $raceWrite = $script:GraphKitAuthStageCaptureType::WriteFileCreateNew(
            $destination, $raceOriginalName,
            [Text.Encoding]::UTF8.GetBytes('original-handle-object'), $true)
        [IO.File]::WriteAllText($raceReplacement, 'replacement-path-object')
        $privateStatic = [Reflection.BindingFlags]'NonPublic, Static'
        $openReadNoFollow = $script:GraphKitAuthStageCaptureType.GetMethod(
            'OpenReadNoFollow', $privateStatic)
        $getNativeFacts = $script:GraphKitAuthStageCaptureType.GetMethod(
            'GetNativeFacts', $privateStatic)
        $openReadNoFollow | Should -Not -BeNullOrEmpty
        $getNativeFacts | Should -Not -BeNullOrEmpty
        $raceHandle = $openReadNoFollow.Invoke(
            $null, [object[]] @([string] $raceOriginal, [bool] $false))
        try {
            [IO.File]::Move($raceOriginal, $raceParked)
            [IO.File]::Move($raceReplacement, $raceOriginal)
            [IO.File]::SetAttributes($raceOriginal, [IO.FileAttributes]::ReadOnly)
            $handleFacts = $getNativeFacts.Invoke(
                $null, [object[]] @(
                    [Microsoft.Win32.SafeHandles.SafeFileHandle] $raceHandle,
                    [string] $raceOriginal))
            $factsType = $handleFacts.GetType()
            $instanceNonPublic = [Reflection.BindingFlags]'Instance, NonPublic'
            $factsType.GetProperty('Identity', $instanceNonPublic).GetValue($handleFacts) |
                Should -BeExactly $raceWrite.Destination.NativeIdentity
            $factsType.GetProperty('PermissionEvidence', $instanceNonPublic).GetValue($handleFacts) |
                Should -BeExactly $raceWrite.Destination.PermissionEvidence
            $factsType.GetProperty('OwnerOnlyAccess', $instanceNonPublic).GetValue($handleFacts) |
                Should -BeTrue
            $factsType.GetProperty('FileReadOnly', $instanceNonPublic).GetValue($handleFacts) |
                Should -BeFalse
        }
        finally {
            $raceHandle.Dispose()
            if (Test-Path -LiteralPath $raceOriginal -PathType Leaf) {
                [IO.File]::SetAttributes($raceOriginal, [IO.FileAttributes]::Normal)
            }
        }
        $moveSource = $script:GraphKitAuthStageCaptureType::CreateDirectoryOwnerOnly(
            $root, 'move-source')
        $moveDestination = Join-Path $root 'move-destination'
        $script:GraphKitAuthStageCaptureType::MoveDirectoryCreateNew(
            $moveSource.PhysicalPath, $moveDestination)
        $moved = $script:GraphKitAuthStageCaptureType::InspectDirectory(
            $root, 'move-destination')
        $moved.NativeIdentity | Should -BeExactly $moveSource.NativeIdentity
        $moved.PhysicalPath.StartsWith('\\?\', [StringComparison]::Ordinal) |
            Should -BeFalse
        $captured = Join-Path $destination 'candidate.dll'
        [IO.File]::SetAttributes($captured, [IO.FileAttributes]::Archive)
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly($captured, $false, $false)
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly($captured, $false, $false)
        $sealed = $script:GraphKitAuthStageCaptureType::InspectFile($destination, 'candidate.dll')
        $sealed.OwnerSid | Should -BeExactly $sealed.CurrentOwnerSid
        $sealed.CurrentIdentitySid | Should -BeExactly $currentSid.Value
        $sealed.ExactOwnerOnlyAccess | Should -BeTrue
        $sealed.OwnerWritable | Should -BeFalse
        $sealed.FileReadOnly | Should -BeTrue
        ([IO.File]::GetAttributes($captured) -band [IO.FileAttributes]::Archive) |
            Should -Be ([IO.FileAttributes]::Archive)
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly($captured, $false, $true)
        $script:GraphKitAuthStageCaptureType::SetOwnerOnly($captured, $false, $true)
        $unsealed = $script:GraphKitAuthStageCaptureType::InspectFile($destination, 'candidate.dll')
        $unsealed.OwnerSid | Should -BeExactly $unsealed.CurrentOwnerSid
        $unsealed.CurrentIdentitySid | Should -BeExactly $currentSid.Value
        $unsealed.AccessRulesProtected | Should -BeTrue
        $unsealed.HasInheritedAccessRules | Should -BeFalse
        $unsealed.OwnerOnlyAccess | Should -BeTrue
        $unsealed.OwnerWritable | Should -BeTrue
        $unsealed.FileReadOnly | Should -BeFalse
        ([IO.File]::GetAttributes($captured) -band [IO.FileAttributes]::Archive) |
            Should -Be ([IO.FileAttributes]::Archive)
        $renamed = Join-Path $destination 'candidate-renamed.dll'
        [IO.File]::Move($captured, $renamed)
        [IO.File]::Delete($renamed)
        Test-Path -LiteralPath $renamed | Should -BeFalse
    }

    It 'preserves ordinary Windows inheritance but overrides it for a sealed copy' -ForEach $windowsInitialAccessCases -AllowNullOrEmptyForEach {
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

        $ordinary = $script:GraphKitAuthStageCaptureType::CopyFileCreateNew(
            $source, 'candidate.dll', $destination, 'candidate.dll', $false)
        $ordinary.DestinationInitial.OwnerOnlyAccess | Should -BeFalse
        $ordinary.Destination.OwnerSid | Should -BeExactly $ordinary.Destination.CurrentOwnerSid
        $ordinary.Destination.CurrentIdentitySid | Should -BeExactly $currentSid.Value
        $ordinary.Destination.AccessRulesProtected | Should -BeTrue
        $ordinary.Destination.HasInheritedAccessRules | Should -BeFalse
        $ordinary.Destination.OwnerOnlyAccess | Should -BeTrue
        $ordinary.Destination.OwnerWritable | Should -BeTrue

        $sealed = $script:GraphKitAuthStageCaptureType::CopyFileCreateNew(
            $source, 'candidate.dll', $sealedDestination, 'candidate.dll', $true)
        $script:GraphKitAuthStageCaptureType::HasInitialOwnerOnlyAccess($sealed.DestinationInitial) |
            Should -BeTrue
        $sealed.DestinationInitial.AccessRulesProtected | Should -BeTrue
        $sealed.DestinationInitial.HasInheritedAccessRules | Should -BeFalse
        $sealed.Destination.OwnerSid | Should -BeExactly $sealed.Destination.CurrentOwnerSid
        $sealed.Destination.CurrentIdentitySid | Should -BeExactly $currentSid.Value
        $sealed.Destination.AccessRulesProtected | Should -BeTrue
        $sealed.Destination.HasInheritedAccessRules | Should -BeFalse
        $sealed.Destination.OwnerOnlyAccess | Should -BeTrue
        $sealed.Destination.OwnerWritable | Should -BeTrue

        $sealedPath = Join-Path $sealedDestination 'candidate.dll'
        $sealedHash = (Get-FileHash -LiteralPath $sealedPath -Algorithm SHA256).Hash
        { $script:GraphKitAuthStageCaptureType::CopyFileCreateNew(
            $source, 'candidate.dll', $sealedDestination, 'candidate.dll', $true) } |
            Should -Throw '*destination collision*'
        (Get-FileHash -LiteralPath $sealedPath -Algorithm SHA256).Hash |
            Should -BeExactly $sealedHash
    }

    It 'rejects a sealed stage after Windows ACL <Kind> mutation' -ForEach $windowsAclMutationCases -AllowNullOrEmptyForEach {
        $fixture = New-GraphKitAuthStageFixture -Name ('windows-acl-' + $Kind.Replace(' ', '-'))
        try {
            Set-GraphKitAuthWindowsAclMutation -StagePath $fixture.StagePath -Kind $Kind
            { Test-GraphKitAuthSealedStage -StagePath $fixture.StagePath -FullVersion $fixture.FullVersion } |
                Should -Throw
        }
        finally {
            Remove-GraphKitAuthTestStageFixture -Fixture $fixture
        }
    }

    It 'rejects a Windows permission record whose owner is not the current identity' -ForEach $(
        if ($IsWindows) { @(@{}) } else { @() }
    ) -AllowNullOrEmptyForEach {
        $fixture = New-GraphKitAuthStageFixture -Name 'windows-wrong-owner-evidence'
        try {
            $evidence = $script:GraphKitAuthStageCaptureType::InspectFile($fixture.StagePath, 'manifest.json')
            $mutated = $evidence | Select-Object *
            $mutated.OwnerSid = [Security.Principal.SecurityIdentifier]::new(
                [Security.Principal.WellKnownSidType]::WorldSid, $null).Value
            (Test-GraphKitAuthSealedPermission -Evidence $mutated -Directory $false) |
                Should -BeFalse
        }
        finally {
            Remove-GraphKitAuthTestStageFixture -Fixture $fixture
        }
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
        if ($Kind -ceq 'byte mutation') {
            $aliasCleanup = [Collections.Generic.List[object]]::new()
            $physicalAncestor = Join-Path $TestDrive ('projection-physical-ancestor-' + [guid]::NewGuid().ToString('N'))
            $physicalRepository = Join-Path $physicalAncestor 'nested/repository'
            $aliasAncestor = Join-Path $TestDrive ('projection-alias-ancestor-' + [guid]::NewGuid().ToString('N'))
            try {
                $physicalArtifact = [pscustomobject]@{
                    Path = $physicalAncestor; Directory = $true; Link = $false
                    RestorePath = ''; Created = $false
                }
                $aliasCleanup.Add($physicalArtifact) | Out-Null
                $null = New-Item -ItemType Directory -Path $physicalAncestor -ErrorAction Stop
                $physicalArtifact.Created = $true
                $null = New-Item -ItemType Directory -Path (
                    Join-Path $physicalRepository 'source'), (
                    Join-Path $physicalRepository 'destination') -Force -ErrorAction Stop

                $aliasArtifact = [pscustomobject]@{
                    Path = $aliasAncestor; Directory = $true; Link = $true
                    RestorePath = ''; Created = $false
                }
                $aliasCleanup.Add($aliasArtifact) | Out-Null
                $null = New-Item -ItemType $(if ($IsWindows) { 'Junction' } else { 'SymbolicLink' }) `
                    -Path $aliasAncestor -Target $physicalAncestor -ErrorAction Stop
                $aliasArtifact.Created = $true
                $aliasRepository = Join-Path $aliasAncestor 'nested/repository'
                [IO.File]::WriteAllBytes((Join-Path $aliasRepository 'source/candidate.dll'), [byte[]](1..32))
                $aliasCopy = $script:GraphKitAuthStageCaptureType::CopyFileCreateNew(
                    (Join-Path $aliasRepository 'source'), 'candidate.dll',
                    (Join-Path $aliasRepository 'destination'), 'candidate.dll')

                { Assert-GraphKitAuthAbiProjectedFileEvidence -RepositoryRoot $aliasRepository `
                    -RelativePath 'destination/candidate.dll' -Expected $aliasCopy.Destination } |
                    Should -Not -Throw -Because (
                        'containment must compare the resolved physical repository root when an ' +
                        'otherwise physical repository has an aliased ancestor')

                $repositoryAlias = Join-Path $TestDrive (
                    'projection-repository-alias-' + [guid]::NewGuid().ToString('N'))
                $repositoryAliasArtifact = [pscustomobject]@{
                    Path = $repositoryAlias; Directory = $true; Link = $true
                    RestorePath = ''; Created = $false
                }
                $aliasCleanup.Add($repositoryAliasArtifact) | Out-Null
                $null = New-Item -ItemType $(if ($IsWindows) { 'Junction' } else { 'SymbolicLink' }) `
                    -Path $repositoryAlias -Target $physicalRepository -ErrorAction Stop
                $repositoryAliasArtifact.Created = $true
                { Assert-GraphKitAuthAbiProjectedFileEvidence -RepositoryRoot $repositoryAlias `
                    -RelativePath 'destination/candidate.dll' -Expected $aliasCopy.Destination } |
                    Should -Throw -Because 'the repository root itself must remain one no-follow directory'
            }
            finally {
                Remove-GraphKitAuthTestMutationArtifacts -Artifacts $aliasCleanup
            }
        }
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
