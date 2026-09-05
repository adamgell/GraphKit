$task8AuthModes = @(
    @{ AuthMode = 'Certificate' }
    @{ AuthMode = 'ClientSecret' }
    @{ AuthMode = 'ManagedIdentity' }
    @{ AuthMode = 'BearerToken' }
)

$task8UnsafeArchiveCases = @(
    @{ Kind = 'parent traversal'; EntryName = '../outside.ps1' }
    @{ Kind = 'absolute path'; EntryName = '/absolute.ps1' }
    @{ Kind = 'drive path'; EntryName = 'C:/absolute.ps1' }
    @{ Kind = 'backslash'; EntryName = 'Data\evil.ps1' }
    @{ Kind = 'empty segment'; EntryName = 'Data//evil.ps1' }
    @{ Kind = 'dot segment'; EntryName = 'Data/./evil.ps1' }
    @{ Kind = 'nested traversal'; EntryName = 'Data/../evil.ps1' }
)

$task8PortableArchiveSegmentCases = @(
    @{ Kind = 'alternate data stream'; EntryName = 'Data/probe.ps1:payload' }
    @{ Kind = 'reserved CON basename'; EntryName = 'Data/CON' }
    @{ Kind = 'reserved CON basename with extension'; EntryName = 'Data/con.txt' }
    @{ Kind = 'reserved NUL basename with extension'; EntryName = 'Data/NUL.ps1' }
    @{ Kind = 'reserved COM1 basename with extension'; EntryName = 'Data/Com1.json' }
    @{ Kind = 'reserved LPT9 basename with extension'; EntryName = 'Data/lpt9.bin' }
    @{ Kind = 'reserved CONIN basename'; EntryName = 'Data/CONIN$' }
    @{ Kind = 'reserved CONIN basename with extension'; EntryName = 'Data/conin$.txt' }
    @{ Kind = 'reserved CONOUT basename'; EntryName = 'Data/CONOUT$' }
    @{ Kind = 'reserved CONOUT basename with extension'; EntryName = 'Data/conout$.json' }
    @{ Kind = 'less-than character'; EntryName = 'Data/probe<one>.ps1' }
    @{ Kind = 'double-quote character'; EntryName = 'Data/probe"one.ps1' }
    @{ Kind = 'pipe character'; EntryName = 'Data/probe|one.ps1' }
    @{ Kind = 'question-mark character'; EntryName = 'Data/probe?one.ps1' }
    @{ Kind = 'asterisk character'; EntryName = 'Data/probe*one.ps1' }
    @{ Kind = 'control character'; EntryName = "Data/probe$([char]1)one.ps1" }
    @{ Kind = 'trailing dot'; EntryName = 'Data/probe.ps1.' }
    @{ Kind = 'trailing space'; EntryName = 'Data/probe.ps1 ' }
)

$task8CleanupFileMutationCases = @(
    @{ Kind = 'before writable transition'; HookKind = 'CleanupFileContentMutationBefore' }
    @{ Kind = 'after writable transition'; HookKind = 'CleanupFileContentMutationAfter' }
)

$task8PreSealMutationCases = @(
    @{ Kind = 'file content'; HookKind = 'PreSealFileMutation'; HasOutside = $false }
    @{ Kind = 'directory identity'; HookKind = 'PreSealDirectoryReplacement'; HasOutside = $true }
    @{ Kind = 'root identity'; HookKind = 'PreSealRootReplacement'; HasOutside = $true }
)

$task8CleanupContainerMutationCases = @(
    @{
        Kind = 'directory identity after writable transition'
        HookKind = 'CleanupDirectoryReplacementAfterWritable'
        Relative = 'module'
        Phase = 'AfterWritable'
    }
    @{
        Kind = 'root identity after writable transition'
        HookKind = 'CleanupRootReplacementAfterWritable'
        Relative = ''
        Phase = 'AfterWritable'
    }
    @{
        Kind = 'directory identity immediately before deletion'
        HookKind = 'CleanupDirectoryReplacementBeforeDelete'
        Relative = 'module'
        Phase = 'BeforeDelete'
    }
    @{
        Kind = 'root identity immediately before deletion'
        HookKind = 'CleanupRootReplacementBeforeDelete'
        Relative = ''
        Phase = 'BeforeDelete'
    }
)

$task8LiveProofRejectionCases = @(
    @{ Kind = 'empty context tenant'; HookKind = 'LiveContextTenantEmpty'; FailureStage = 'Context' }
    @{ Kind = 'empty target tenant'; HookKind = 'LiveTargetTenantEmpty'; FailureStage = 'Read' }
    @{ Kind = 'empty actual tenant'; HookKind = 'LiveActualTenantEmpty'; FailureStage = 'Read' }
    @{ Kind = 'empty source tenant'; HookKind = 'LiveSourceTenantEmpty'; FailureStage = 'Read' }
    @{ Kind = 'missing token fingerprint'; HookKind = 'LiveFingerprintMissing'; FailureStage = 'Read' }
    @{ Kind = 'blank token fingerprint'; HookKind = 'LiveFingerprintBlank'; FailureStage = 'Read' }
    @{ Kind = 'mismatched exposed token fingerprint'; HookKind = 'LiveFingerprintMismatch'; FailureStage = 'Read' }
    @{ Kind = 'missing credential generation'; HookKind = 'LiveGenerationMissing'; FailureStage = 'Read' }
    @{ Kind = 'blank credential generation'; HookKind = 'LiveGenerationBlank'; FailureStage = 'Read' }
    @{ Kind = 'mismatched credential generation'; HookKind = 'LiveGenerationMismatch'; FailureStage = 'Read' }
    @{ Kind = 'blank source credential generation'; HookKind = 'LiveSourceGenerationBlank'; FailureStage = 'Context' }
    @{ Kind = 'missing proof cloud'; HookKind = 'LiveCloudMissing'; FailureStage = 'Read' }
    @{ Kind = 'blank proof cloud'; HookKind = 'LiveCloudBlank'; FailureStage = 'Read' }
    @{ Kind = 'mismatched proof cloud'; HookKind = 'LiveCloudMismatch'; FailureStage = 'Read' }
    @{ Kind = 'mismatched source client scope'; HookKind = 'LiveSourceClientMismatch'; FailureStage = 'Context' }
)

$task8ArchiveAliasCases = @(
    @{ Kind = 'exact duplicate'; First = 'Data/probe.ps1'; Second = 'Data/probe.ps1' }
    @{ Kind = 'portable case collision'; First = 'Data/probe.ps1'; Second = 'data/probe.ps1' }
    @{
        Kind = 'NFC collision'
        First = "Data/probé.ps1"
        Second = "Data/probe$([char]0x0301).ps1"
    }
)

$task8ArchiveLinkCases = @(
    @{ Kind = 'Unix symbolic link'; ExternalAttributes = ((0xA000 -bor 0x1A4) -shl 16) }
    @{ Kind = 'Unix device'; ExternalAttributes = ((0x2000 -bor 0x180) -shl 16) }
    @{ Kind = 'Windows reparse point'; ExternalAttributes = 0x0400 }
    @{ Kind = 'Windows directory'; ExternalAttributes = 0x0010 }
)

$task8EvidenceMutationCases = @(
    @{ Kind = 'guid'; Value = '00000000-0000-0000-0000-000000000123' }
    @{ Kind = 'profile'; Value = 'customer-profile-sentinel' }
    @{ Kind = 'jwt'; Value = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJzZW50aW5lbCJ9.signature' }
    @{ Kind = 'bearer'; Value = 'Bearer task8-secret-sentinel' }
    @{ Kind = 'fingerprint'; Value = 'tokenFingerprint:task8-secret-sentinel' }
    @{ Kind = 'correlation'; Value = 'correlationId:00000000-0000-0000-0000-000000000123' }
    @{ Kind = 'response'; Value = 'responseBody:task8-secret-sentinel' }
    @{ Kind = 'exception'; Value = 'System.Exception: task8-secret-sentinel at /tmp/secret.ps1:1' }
    @{ Kind = 'unix-path'; Value = '/Users/task8-secret-sentinel/profile.json' }
    @{ Kind = 'windows-path'; Value = 'C:\\Users\\task8-secret-sentinel\\profile.json' }
    @{ Kind = 'unknown-nested'; Value = 'task8-secret-sentinel' }
    @{ Kind = 'string-count'; Value = 'task8-string-count-sentinel' }
)

BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:runnerPath = Join-Path $script:repoRoot 'scripts/Invoke-GraphKitAuthParity.ps1'
    $script:workerPath = Join-Path $script:repoRoot `
        'scripts/private/Invoke-GraphKitAuthParityWorker.ps1'
    $script:task8ModeNames = @('Certificate','ClientSecret','ManagedIdentity','BearerToken')

    function New-Task8SparseFile {
        param(
            [Parameter(Mandatory)][string] $Path,
            [Parameter(Mandatory)][long] $Length
        )

        if ($IsWindows) {
            $fixtureType = 'GraphKitTask8SparseFileFixtureV1' -as [type]
            if ($null -eq $fixtureType) {
                Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class GraphKitTask8SparseFileFixtureV1
{
    public const string ContractMarker = "GraphKit.Task8.SparseFileFixture/1";
    private const uint FsctlSetSparse = 0x000900C4;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle device,
        uint controlCode,
        IntPtr input,
        uint inputSize,
        IntPtr output,
        uint outputSize,
        out uint bytesReturned,
        IntPtr overlapped);

    public static void MarkSparse(SafeFileHandle handle)
    {
        uint bytesReturned;
        if (!DeviceIoControl(
            handle,
            FsctlSetSparse,
            IntPtr.Zero,
            0,
            IntPtr.Zero,
            0,
            out bytesReturned,
            IntPtr.Zero))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }
}
'@
                $fixtureType = [GraphKitTask8SparseFileFixtureV1]
            }
            if ($fixtureType::ContractMarker -cne 'GraphKit.Task8.SparseFileFixture/1') {
                throw 'A stale Task 8 sparse-file fixture type is already loaded.'
            }
        }

        $stream = [IO.FileStream]::new(
            $Path,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None)
        try {
            if ($IsWindows) {
                [GraphKitTask8SparseFileFixtureV1]::MarkSparse($stream.SafeFileHandle)
            }
            $stream.SetLength($Length)
        }
        finally {
            $stream.Dispose()
        }
    }

    function New-Task8FixturePackage {
        param(
            [Parameter(Mandatory)][string] $Name,
            [object[]] $Entries = @(
                @{
                    Path = 'GraphKit.psd1'
                    Content = "@{ RootModule = 'GraphKit.psm1'; ModuleVersion = '0.4.0'; PrivateData = @{ PSData = @{ Prerelease = 'r8.fixture' } } }"
                }
                @{ Path = 'GraphKit.psm1'; Content = '# valid Task 8 fixture module' }
            ),
            [IO.Compression.CompressionLevel] $CompressionLevel =
                [IO.Compression.CompressionLevel]::Optimal
        )

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $packagePath = Join-Path $TestDrive "$Name.nupkg"
        $stream = [IO.FileStream]::new(
            $packagePath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None)
        try {
            $archive = [IO.Compression.ZipArchive]::new(
                $stream,
                [IO.Compression.ZipArchiveMode]::Create,
                $true)
            try {
                foreach ($record in $Entries) {
                    $entry = $archive.CreateEntry(
                        [string] $record.Path,
                        $CompressionLevel)
                    if ($record.ContainsKey('ExternalAttributes')) {
                        $entry.ExternalAttributes = [int] $record.ExternalAttributes
                    }
                    $entryStream = $entry.Open()
                    try {
                        [byte[]] $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
                            [string] $record.Content)
                        if ($record.Content -is [byte[]]) {
                            $bytes = [byte[]] $record.Content
                        }
                        $entryStream.Write($bytes, 0, $bytes.Length)
                    }
                    finally {
                        $entryStream.Dispose()
                    }
                }
            }
            finally {
                $archive.Dispose()
            }
        }
        finally {
            $stream.Dispose()
        }
        return $packagePath
    }

    function Get-Task8PackedCandidate {
        $sourceManifest = Import-PowerShellDataFile -Path (Join-Path $script:repoRoot 'source/GraphKit.psd1')
        $baseVersion = [string] $sourceManifest.ModuleVersion
        $builtManifestPath = Join-Path $script:repoRoot "output/module/GraphKit/$baseVersion/GraphKit.psd1"
        if (-not (Test-Path -LiteralPath $builtManifestPath -PathType Leaf)) {
            throw 'The Task 8 package-consuming tests require a fresh pack.'
        }
        $builtManifest = Import-PowerShellDataFile -Path $builtManifestPath
        $prerelease = [string] $builtManifest.PrivateData.PSData.Prerelease
        if ([string]::IsNullOrWhiteSpace($prerelease)) {
            throw 'The Task 8 candidate must be a full prerelease build.'
        }
        $fullVersion = "$baseVersion-$prerelease"
        $packagePath = Join-Path $script:repoRoot "output/GraphKit.$fullVersion.nupkg"
        if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf)) {
            throw "The freshly packed Task 8 candidate '$fullVersion' is missing."
        }
        [pscustomobject]@{
            PackagePath = $packagePath
            PackageSha256 = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
            FullVersion = $fullVersion
        }
    }

    function Invoke-Task8RunnerProcess {
        param(
            [Parameter(Mandatory)][string] $PackagePath,
            [Parameter(Mandatory)][string] $PackageSha256,
            [Parameter(Mandatory)][string] $AuthMode,
            [switch] $DryRun,
            [string] $ProfileId,
            [string] $StorePath,
            [string] $HookKind = 'None',
            [string] $MutationValue = '',
            [switch] $OrdinaryExecution,
            [ValidateRange(1, 2)] [int] $Repeat = 1
        )

        $nonce = [guid]::NewGuid().ToString('N')
        $wrapperPath = Join-Path $TestDrive "task8-wrapper-$nonce.ps1"
        $tracePath = Join-Path $TestDrive "task8-trace-$nonce.jsonl"
        $grandchildPath = Join-Path $TestDrive "task8-grandchild-$nonce.ps1"
        [IO.File]::WriteAllText($grandchildPath, @'
param(
    [Parameter(Mandatory)][string] $HeldPath,
    [Parameter(Mandatory)][string] $ReadyPath,
    [Parameter(Mandatory)][string] $EscapeSessionText
)
$ErrorActionPreference = 'Stop'
$escapedSession = $false
if ($EscapeSessionText -ceq 'true' -and -not $IsWindows) {
    Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class GraphKitTask8EscapedSessionFixture
{
    public static void Enter()
    {
        int pid = Environment.ProcessId;
        int session = setsid();
        if (session < 0) throw new Win32Exception(Marshal.GetLastPInvokeError());
        if (session != pid || getpgid(0) != pid || getsid(0) != pid)
            throw new InvalidOperationException("Fixture session escape failed.");
    }
    [DllImport("libc", SetLastError = true)] private static extern int setsid();
    [DllImport("libc", SetLastError = true)] private static extern int getpgid(int pid);
    [DllImport("libc", SetLastError = true)] private static extern int getsid(int pid);
}
"@
    [GraphKitTask8EscapedSessionFixture]::Enter()
    $escapedSession = $true
}
$held = [IO.FileStream]::new(
    $HeldPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
try {
    $process = [Diagnostics.Process]::GetCurrentProcess()
    $readyRecord = [ordered]@{
        processId = [Environment]::ProcessId
        startTimeUtcTicks = $process.StartTime.ToUniversalTime().Ticks
        heldPath = $HeldPath
        escapedSession = $escapedSession
    } | ConvertTo-Json -Compress -Depth 3
    $readyTemporaryPath = $ReadyPath + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::WriteAllText(
            $readyTemporaryPath,
            $readyRecord,
            [Text.UTF8Encoding]::new($false))
        [IO.File]::Move($readyTemporaryPath, $ReadyPath)
    }
    finally {
        if ([IO.File]::Exists($readyTemporaryPath)) {
            [IO.File]::Delete($readyTemporaryPath)
        }
    }
    Start-Sleep -Seconds 30
}
finally { $held.Dispose() }
'@, [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($wrapperPath, @'
param(
    [Parameter(Mandatory)][string] $RunnerPath,
    [Parameter(Mandatory)][string] $PackagePath,
    [Parameter(Mandatory)][string] $PackageSha256,
    [Parameter(Mandatory)][string] $AuthMode,
    [Parameter(Mandatory)][string] $UseDryRunText,
    [string] $ProfileId,
    [string] $StorePath,
    [Parameter(Mandatory)][string] $HookKind,
    [string] $MutationValue,
    [Parameter(Mandatory)][string] $OrdinaryExecutionText,
    [Parameter(Mandatory)][int] $RepeatCount,
    [Parameter(Mandatory)][string] $TracePath,
    [Parameter(Mandatory)][string] $GrandchildPath,
    [string] $WorkerPath = '',
    [string] $InternalWorkerText = 'false'
)
$ErrorActionPreference = 'Stop'
$UseDryRun = $UseDryRunText -ceq 'true'
$UseOrdinaryExecution = $OrdinaryExecutionText -ceq 'true'
$UseInternalWorker = $InternalWorkerText -ceq 'true'
$fixturePackagePath = $PackagePath
$fixturePackageSha256 = $PackageSha256
$fixtureAuthMode = $AuthMode
$fixtureProfileId = $ProfileId
$fixtureStorePath = $StorePath

function Write-Task8Trace {
    param([Parameter(Mandatory)][string] $Event, [hashtable] $Data = @{})
    $line = [ordered]@{ event = $Event; data = $Data } | ConvertTo-Json -Compress -Depth 4
    [IO.File]::AppendAllText($TracePath, $line + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Import-Task8FixtureContractsFromPackage {
    param([Parameter(Mandatory)][string] $Path)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $stream = [IO.FileStream]::new(
        $Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $stream, [IO.Compression.ZipArchiveMode]::Read, $false)
        try {
            $entries = @($archive.Entries | Where-Object {
                $_.FullName -ceq 'Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll'
            })
            if ($entries.Count -ne 1 -or $entries[0].Length -le 0 -or
                $entries[0].Length -gt 16MB) {
                throw 'The exact package contracts fixture entry was rejected.'
            }
            $entryStream = $entries[0].Open()
            $memory = [IO.MemoryStream]::new()
            try {
                $entryStream.CopyTo($memory)
                return [Reflection.Assembly]::Load($memory.ToArray())
            }
            finally {
                $memory.Dispose()
                $entryStream.Dispose()
            }
        }
        finally { $archive.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Set-Task8FixtureOwnerWritable {
    param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][bool] $Directory)
    if ($IsWindows) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl = if ($Directory) {
            [Security.AccessControl.DirectorySecurity]::new()
        }
        else {
            [Security.AccessControl.FileSecurity]::new()
        }
        $acl.SetAccessRuleProtection($true, $false)
        $inheritance = if ($Directory) {
            [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
        }
        else { [Security.AccessControl.InheritanceFlags]::None }
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
        if ($Directory) {
            [IO.FileSystemAclExtensions]::SetAccessControl(
                [IO.DirectoryInfo]::new($Path), $acl)
        }
        else {
            [IO.FileSystemAclExtensions]::SetAccessControl(
                [IO.FileInfo]::new($Path), $acl)
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
    else {
        [IO.File]::SetUnixFileMode(
            $Path,
            $(if ($Directory) {
                [IO.UnixFileMode]'UserRead,UserWrite,UserExecute'
            }
            else { [IO.UnixFileMode]'UserRead,UserWrite' }))
    }
}

function Move-Task8FixtureDirectoryIdentityPreservingChildren {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $OutsidePath
    )
    [IO.Directory]::Move($Path, $OutsidePath)
    $null = [IO.Directory]::CreateDirectory($Path)
    foreach ($child in @([IO.Directory]::EnumerateFileSystemEntries($OutsidePath))) {
        $destination = Join-Path $Path ([IO.Path]::GetFileName($child))
        if ([IO.Directory]::Exists($child)) {
            $permission = if ($IsWindows) {
                Get-Acl -LiteralPath $child
            }
            else { [IO.File]::GetUnixFileMode($child) }
            Set-Task8FixtureOwnerWritable -Path $child -Directory $true
            [IO.Directory]::Move($child, $destination)
            if ($IsWindows) {
                Set-Acl -LiteralPath $destination -AclObject $permission
            }
            else { [IO.File]::SetUnixFileMode($destination, $permission) }
        }
        else {
            [IO.File]::Move($child, $destination)
        }
    }
}

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

public static class GraphKitTask8HardLinkFixture
{
    private const int AtFdcwd = -100;

    public static void Create(string linkPath, string existingPath)
    {
        string link = Path.GetFullPath(linkPath);
        string target = Path.GetFullPath(existingPath);
        if (OperatingSystem.IsWindows())
        {
            if (!CreateHardLinkW(ToExtendedWindowsPath(link), ToExtendedWindowsPath(target), IntPtr.Zero))
            {
                throw new IOException($"Native fixture hard-link creation failed (Win32 {Marshal.GetLastWin32Error()}).");
            }
            return;
        }
        if (linkat(AtFdcwd, target, AtFdcwd, link, 0) != 0)
        {
            throw new IOException($"Native fixture hard-link creation failed (errno {Marshal.GetLastWin32Error()}).");
        }
    }

    private static string ToExtendedWindowsPath(string path)
    {
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) return path;
        if (path.StartsWith(@"\\", StringComparison.Ordinal))
            return @"\\?\UNC\" + path.Substring(2);
        return @"\\?\" + path;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateHardLinkW(
        string fileName,
        string existingFileName,
        IntPtr securityAttributes);

    [DllImport("libc", SetLastError = true)]
    private static extern int linkat(
        int oldDirectory,
        string oldPath,
        int newDirectory,
        string newPath,
        int flags);
}

public class GraphKitTask8TokenSourceProxy : DispatchProxy
{
    public string AuthModeValue { get; set; } = "Certificate";
    public bool CanRefreshValue { get; set; } = true;
    public string VerifiedTenantIdValue { get; set; } = "00000000-0000-0000-0000-000000000111";
    public string ClientIdValue { get; set; } = "00000000-0000-0000-0000-000000000333";
    public string CredentialGenerationValue { get; set; } = "task8-fixture-generation";
    public string TokenFingerprint { get; set; } = "task8-fixture-token-fingerprint";
    public object TokenResultValue { get; set; }
    private int _acquireCallCount;

    public int AcquireCallCount { get { return Volatile.Read(ref _acquireCallCount); } }

    protected override object Invoke(MethodInfo targetMethod, object[] args)
    {
        switch (targetMethod.Name)
        {
            case "get_AuthMode": return AuthModeValue;
            case "get_CanRefresh": return CanRefreshValue;
            case "get_VerifiedTenantId": return VerifiedTenantIdValue;
            case "get_Audience": return "https://graph.microsoft.com/";
            case "get_ClientId": return ClientIdValue;
            case "get_CredentialGeneration": return CredentialGenerationValue;
            case "get_ExpiresOn": return DateTimeOffset.UtcNow.AddMinutes(5);
            case "Acquire":
                Interlocked.Increment(ref _acquireCallCount);
                return TokenResultValue ?? throw new InvalidOperationException(
                    "Task 8 proxy acquisition was not configured.");
            case "AdoptSharedResult": return null;
            case "Dispose": return null;
            default: throw new InvalidOperationException("Task 8 proxy method was not expected.");
        }
    }
}
"@

function New-Task8FixtureHardLink {
    param(
        [Parameter(Mandatory)] $State,
        [Parameter(Mandatory)][string] $RelativePath,
        [Parameter(Mandatory)][string] $LinkPath
    )
    $targetPath = Join-Path $State.RootPath (
        $RelativePath -replace '/', [IO.Path]::DirectorySeparatorChar)
    [GraphKitTask8HardLinkFixture]::Create($LinkPath, $targetPath)
    $evidenceType = $State.RootEvidence.GetType()
    $nativeType = $evidenceType.Assembly.GetType(
        $evidenceType.Namespace + '.GraphKitAuthStageCapture', $true, $false)
    $linked = $nativeType::InspectFile($State.RootPath, $RelativePath)
    if ([long]$linked.LinkCount -ne 2) {
        throw 'The native fixture did not establish an exact two-link file.'
    }
}

function New-Task8SourceProxy {
    param(
        [Parameter(Mandatory)][string] $Mode,
        [Parameter(Mandatory)][bool] $CanRefresh,
        [string] $VerifiedTenantId = '00000000-0000-0000-0000-000000000111',
        [AllowNull()][string] $ClientId = '00000000-0000-0000-0000-000000000333',
        [string] $CredentialGeneration = 'task8-fixture-generation',
        [string] $TokenFingerprint = 'task8-fixture-token-fingerprint',
        [AllowNull()] $TokenResult
    )
    $interface = [AppDomain]::CurrentDomain.GetAssemblies() |
        ForEach-Object { $_.GetType('GraphKit.Auth.IGraphTokenSource', $false, $false) } |
        Where-Object { $null -ne $_ } |
        Select-Object -First 1
    if ($null -eq $interface) { throw 'Task 8 fixture could not find the loaded token-source interface.' }
    $create = [Reflection.DispatchProxy].GetMethods([Reflection.BindingFlags]'Public,Static') |
        Where-Object { $_.Name -ceq 'Create' -and $_.IsGenericMethodDefinition } |
        Select-Object -First 1
    $source = $create.MakeGenericMethod($interface, [GraphKitTask8TokenSourceProxy]).Invoke($null, @())
    $control = [GraphKitTask8TokenSourceProxy] $source
    $control.AuthModeValue = $Mode
    $control.CanRefreshValue = $CanRefresh
    $control.VerifiedTenantIdValue = $VerifiedTenantId
    $control.ClientIdValue = $ClientId
    $control.CredentialGenerationValue = $CredentialGeneration
    $control.TokenFingerprint = $TokenFingerprint
    $control.TokenResultValue = $TokenResult
    return $source
}

$hooks = [ordered]@{
    ContractMarker = 'GraphKit.Task8.ParityTestHooks/1'
    TracePath = $TracePath
    PackageLiveHolderKey = $null
    CleanupOriginalBytes = $null
    PreSealMutationDone = $false
    CleanupContainerMutationDone = $false
}

$hooks.AfterRootCreated = {
    param($state)
    Write-Task8Trace -Event 'root-created' -Data @{ root = [string] $state.RootPath }
}.GetNewClosure()
$hooks.AfterSnapshot = {
    param($state)
    Write-Task8Trace -Event 'snapshot-created' -Data @{ snapshot = [string] $state.SnapshotPath }
}.GetNewClosure()
$hooks.AfterArchivePlan = {
    param($state, $plan)
    Write-Task8Trace -Event 'archive-plan-created' -Data @{
        recordCount = @($plan.Records).Count
    }
}.GetNewClosure()
$hooks.AfterExtraction = {
    param($state)
    Write-Task8Trace -Event 'extraction-created' -Data @{ moduleRoot = [string] $state.ModuleRoot }
}.GetNewClosure()
$hooks.AfterImport = {
    param($state)
    Write-Task8Trace -Event 'imported' -Data @{
        processId = [Environment]::ProcessId
        manifestPath = [string] $state.ImportedManifestPath
        modulePath = [string] $state.ImportedModulePath
        moduleVersion = [string] $state.ModuleVersion
    }
}.GetNewClosure()
$hooks.BeforeCleanup = {
    param($state)
    Write-Task8Trace -Event 'cleanup-started' -Data @{
        processId = [Environment]::ProcessId
        root = [string] $state.RootPath
    }
}.GetNewClosure()
$workerWrapperPath = [IO.Path]::GetFullPath($PSCommandPath)
$hooks.ConfigureWorkerStartInfo = {
    param($startInfo, $workerPath)
    $startInfo.ArgumentList.Clear()
    foreach ($argument in @(
        '-NoLogo','-NoProfile','-NonInteractive','-File',$workerWrapperPath,
        '-RunnerPath',$RunnerPath,
        '-PackagePath','unused.nupkg',
        '-PackageSha256',('0' * 64),
        '-AuthMode','Certificate',
        '-UseDryRunText','true',
        '-ProfileId','',
        '-StorePath','',
        '-HookKind',$(if ($HookKind -cin @(
            'PackageLiveSuccess','WorkerExtraBlankFrame','WorkerBomFrame',
            'WorkerSecondFrame','WorkerMissingTerminator','WorkerEmptyFrame',
            'WorkerInvalidUtf8','WorkerStderr','WorkerStdoutOverflow',
            'WorkerStderrOverflow','WorkerNonzeroExit','WorkerNoRead',
            'WorkerGrandchild','WorkerSessionEscape')) {
            $HookKind
        } else { 'None' }),
        '-MutationValue','',
        '-OrdinaryExecutionText','false',
        '-RepeatCount','1',
        '-TracePath',$TracePath,
        '-GrandchildPath',$GrandchildPath,
        '-WorkerPath',$workerPath,
        '-InternalWorkerText','true'
    )) {
        $null = $startInfo.ArgumentList.Add([string]$argument)
    }
}.GetNewClosure()
$hooks.AfterWorkerExit = {
    param($state, $workerProcessId, $workerRun)
    Write-Task8Trace -Event 'worker-exited' -Data @{
        processId = [Environment]::ProcessId
        workerProcessId = [int]$workerProcessId
        root = [string]$state.RootPath
        forcedTermination = [bool]$workerRun.ForcedTermination
        protocolValid = [bool]$workerRun.ProtocolValid
        workerState = $(if ($null -eq $workerRun.Result) { '' } else {
            [string]$workerRun.Result.state
        })
        workerFailureStage = $(if ($null -eq $workerRun.Result) { '' } else {
            [string]$workerRun.Result.failureStage
        })
        protocolFailure = [string]$workerRun.ProtocolFailure
        ownershipEstablished = [bool]$workerRun.OwnershipEstablished
        requestReleased = [bool]$workerRun.RequestReleased
        rootExitConfirmed = [bool]$workerRun.RootExitConfirmed
        treeExitConfirmed = [bool]$workerRun.TreeExitConfirmed
        streamsDrained = [bool]$workerRun.StreamsDrained
        elapsedMilliseconds = [long]$workerRun.ElapsedMilliseconds
        operationDeadlineMilliseconds = [long]$workerRun.OperationDeadlineMilliseconds
        hardDeadlineMilliseconds = [long]$workerRun.HardDeadlineMilliseconds
    }
}.GetNewClosure()
$hooks.AfterWorkerRootExit = {
    param($metadata)
    Write-Task8Trace -Event 'worker-root-exited' -Data @{
        workerProcessId = [int]$metadata.WorkerProcessId
        ownershipEstablished = [bool]$metadata.OwnershipEstablished
        requestReleased = [bool]$metadata.RequestReleased
    }
}.GetNewClosure()
$hooks.BeforeWorkerTreeTermination = {
    param($metadata)
    Write-Task8Trace -Event 'worker-tree-termination-requested' -Data @{
        workerProcessId = [int]$metadata.WorkerProcessId
        rootExitConfirmed = [bool]$metadata.RootExitConfirmed
        residualTreeDetected = [bool]$metadata.ResidualTreeDetected
    }
}.GetNewClosure()
$hooks.AfterWorkerTreeExit = {
    param($metadata)
    Write-Task8Trace -Event 'worker-tree-exit-confirmed' -Data @{
        workerProcessId = [int]$metadata.WorkerProcessId
        terminationRequested = [bool]$metadata.TerminationRequested
        residualTreeDetected = [bool]$metadata.ResidualTreeDetected
        streamsDrained = [bool]$metadata.StreamsDrained
    }
}.GetNewClosure()
$hooks.AfterWorkerProcessFailure = {
    param($failurePoint)
    Write-Task8Trace -Event 'worker-process-failure' -Data @{
        failurePoint = [string]$failurePoint
    }
}.GetNewClosure()

if ($HookKind -ceq 'PostStartSetupFailure') {
    $hooks.AfterWorkerStarted = {
        param($workerProcess)
        Write-Task8Trace -Event 'worker-setup-started' -Data @{
            processId = [int]$workerProcess.Id
        }
        throw 'The injected post-start collector setup failed.'
    }.GetNewClosure()
}
if ($HookKind -cin @('WorkerNoRead','WorkerPermanentPollFailure')) {
    $hooks.SelectWorkerTimeoutSeconds = { param($defaultSeconds) [int]3 }
}
if ($HookKind -ceq 'WorkerSessionEscape') {
    # The child receives a separate five-second readiness bound only after this
    # worker has bootstrapped and imported the candidate. Keep the collector's
    # enclosing deadline strictly larger so the parent cannot terminate the
    # original group after setsid but before readiness is published.
    $hooks.SelectWorkerTimeoutSeconds = { param($defaultSeconds) [int]15 }
}
if ($HookKind -ceq 'WorkerPermanentPollFailure') {
    $hooks.BeforeWorkerLifecyclePoll = {
        param($metadata)
        throw 'The injected lifecycle poll failed permanently.'
    }.GetNewClosure()
}
if ($HookKind -ceq 'WorkerPathMismatch') {
    $hooks.MutateWorkerRequest = {
        param($request)
        $request.state.moduleRoot = Join-Path $request.state.rootPath 'different-module'
        return $request
    }.GetNewClosure()
}
if ($HookKind -ceq 'WorkerRequestVersionMismatch') {
    $hooks.MutateWorkerRequest = {
        param($request)
        $request.moduleVersion = '0.4.0-r8.other'
        return $request
    }.GetNewClosure()
}
if ($HookKind -ceq 'WorkerRequestTrailingLf') {
    $hooks.MutateWorkerRequestJson = {
        param($json)
        return [string]$json + "`n"
    }.GetNewClosure()
}
if ($HookKind -ceq 'WorkerRequestBom') {
    $hooks.MutateWorkerRequestJson = {
        param($json)
        return [string][char]0xFEFF + [string]$json
    }.GetNewClosure()
}
if ($HookKind -ceq 'StreamSentinel') {
    $hooks.MutateWorkerRequest = {
        param($request)
        [IO.File]::WriteAllText(
            ($TracePath + '.worker-request.json'),
            ($request | ConvertTo-Json -Compress -Depth 12),
            [Text.UTF8Encoding]::new($false))
        return $request
    }.GetNewClosure()
}

$preloadedRoot = $null
$preloadedModule = $null
$script:task8PackageLiveHolderKey = $null
if ($HookKind -ceq 'PreloadedGraphKit') {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $preloadedRoot = Join-Path ([IO.Path]::GetTempPath()) ('graphkit-task8-preloaded-' + [guid]::NewGuid().ToString('N'))
    [IO.Compression.ZipFile]::ExtractToDirectory($PackagePath, $preloadedRoot)
    $preloadedModule = Import-Module (Join-Path $preloadedRoot 'GraphKit.psd1') -PassThru -Force -ErrorAction Stop
    Write-Task8Trace -Event 'preloaded' -Data @{}
}

switch ($HookKind) {
    'OversizedSource' {
        $hooks.BeforeSourceMetadata = {
            param($sourcePath)
            Write-Task8Trace -Event 'source-metadata-started' -Data @{}
        }.GetNewClosure()
        $hooks.BeforeSourceHash = {
            param($sourcePath)
            Write-Task8Trace -Event 'source-hash-started' -Data @{}
            throw 'The oversized source reached the forbidden hash boundary.'
        }.GetNewClosure()
    }
    'SnapshotCollision' {
        $hooks.AfterRootCreated = {
            param($state)
            Write-Task8Trace -Event 'root-created' -Data @{ root = [string] $state.RootPath }
            [IO.File]::WriteAllText((Join-Path $state.RootPath 'candidate.nupkg'), 'collision')
        }.GetNewClosure()
    }
    'SnapshotContentMutation' {
        $hooks.AfterSnapshot = {
            param($state)
            Write-Task8Trace -Event 'snapshot-created' -Data @{
                snapshot = [string]$state.SnapshotPath
            }
            [IO.File]::WriteAllBytes(
                $state.SnapshotPath, [IO.File]::ReadAllBytes($MutationValue))
            Write-Task8Trace -Event 'snapshot-mutated' -Data @{
                root = [string]$state.RootPath
                replacement = [string]$MutationValue
            }
        }.GetNewClosure()
    }
    'PreSealFileMutation' {
        $hooks.BeforeSealFile = {
            param($state, $relative)
            if ($hooks.PreSealMutationDone -or
                [string]$relative -cne 'module/GraphKit.psd1') {
                return
            }
            $hooks.PreSealMutationDone = $true
            $path = Join-Path $state.RootPath (
                [string]$relative -replace '/', [IO.Path]::DirectorySeparatorChar)
            $laterFileExists = [IO.File]::Exists(
                (Join-Path $state.RootPath 'module/GraphKit.psm1'))
            [IO.File]::AppendAllText($path, '# pre-seal same-identity mutation')
            Write-Task8Trace -Event 'preseal-mutated' -Data @{
                kind = $HookKind
                relative = [string]$relative
                laterFileExists = $laterFileExists
                root = [string]$state.RootPath
                outside = ''
            }
        }.GetNewClosure()
    }
    'PreSealDirectoryReplacement' {
        $hooks.BeforeSealDirectory = {
            param($state, $relative)
            if ($hooks.PreSealMutationDone -or [string]$relative -cne 'module') {
                return
            }
            $hooks.PreSealMutationDone = $true
            $path = Join-Path $state.RootPath 'module'
            $outside = Join-Path (Split-Path $state.RootPath -Parent) (
                'graphkit-task8-preseal-directory-' + [guid]::NewGuid().ToString('N'))
            Move-Task8FixtureDirectoryIdentityPreservingChildren `
                -Path $path -OutsidePath $outside
            Write-Task8Trace -Event 'preseal-mutated' -Data @{
                kind = $HookKind
                relative = [string]$relative
                root = [string]$state.RootPath
                outside = [string]$outside
            }
        }.GetNewClosure()
    }
    'PreSealRootReplacement' {
        $hooks.BeforeSealRoot = {
            param($state)
            if ($hooks.PreSealMutationDone) { return }
            $hooks.PreSealMutationDone = $true
            $outside = Join-Path (Split-Path $state.RootPath -Parent) (
                'graphkit-task8-preseal-root-' + [guid]::NewGuid().ToString('N'))
            Move-Task8FixtureDirectoryIdentityPreservingChildren `
                -Path $state.RootPath -OutsidePath $outside
            Write-Task8Trace -Event 'preseal-mutated' -Data @{
                kind = $HookKind
                relative = ''
                root = [string]$state.RootPath
                outside = [string]$outside
            }
        }.GetNewClosure()
    }
    { $_ -cin @('OutsideSentinel','WorkerGrandchild','WorkerSessionEscape') } {
        $hooks.AfterRootCreated = {
            param($state)
            Write-Task8Trace -Event 'root-created' -Data @{ root = [string] $state.RootPath }
            $outside = Join-Path (Split-Path $state.RootPath -Parent) (
                'graphkit-task8-outside-' + [guid]::NewGuid().ToString('N'))
            [IO.File]::WriteAllText($outside, 'outside-sentinel')
            Write-Task8Trace -Event 'outside-created' -Data @{ path = $outside }
        }.GetNewClosure()
    }
    { $_ -cin @('WorkerGrandchild','WorkerSessionEscape') } {
        $hooks.AfterImport = {
            param($state)
            Write-Task8Trace -Event 'imported' -Data @{
                processId = [Environment]::ProcessId
                manifestPath = [string] $state.ImportedManifestPath
                modulePath = [string] $state.ImportedModulePath
                moduleVersion = [string] $state.ModuleVersion
            }
            $heldPath = Join-Path $state.ModuleRoot `
                'Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll'
            $readyPath = $TracePath + '.grandchild-ready'
            $startInfo = [Diagnostics.ProcessStartInfo]::new()
            $startInfo.FileName = [Environment]::ProcessPath
            $startInfo.UseShellExecute = $false
            foreach ($argument in @(
                '-NoLogo','-NoProfile','-NonInteractive','-File',$GrandchildPath,
                '-HeldPath',$heldPath,'-ReadyPath',$readyPath,
                '-EscapeSessionText',$(if ($HookKind -ceq 'WorkerSessionEscape') {
                    'true'
                } else { 'false' }))) {
                $null = $startInfo.ArgumentList.Add([string]$argument)
            }
            $child = [Diagnostics.Process]::new()
            $child.StartInfo = $startInfo
            try {
                if (-not $child.Start()) {
                    throw 'The Task 8 residual-tree fixture did not start.'
                }
                $deadline = [DateTime]::UtcNow.AddSeconds(5)
                while (-not [IO.File]::Exists($readyPath) -and
                    [DateTime]::UtcNow -lt $deadline -and -not $child.HasExited) {
                    Start-Sleep -Milliseconds 10
                }
                $ready = if ([IO.File]::Exists($readyPath)) {
                    [IO.File]::ReadAllText($readyPath) |
                        ConvertFrom-Json -ErrorAction Stop
                }
                else { $null }
                $expectedEscape = $HookKind -ceq 'WorkerSessionEscape'
                if ($null -eq $ready -or $child.HasExited -or
                    @($ready.PSObject.Properties).Count -ne 4 -or
                    (@($ready.PSObject.Properties.Name | Sort-Object) -join ',') -cne
                        'escapedSession,heldPath,processId,startTimeUtcTicks' -or
                    $ready.processId.GetType() -ne [long] -or
                    [long]$ready.processId -ne [long]$child.Id -or
                    $ready.startTimeUtcTicks.GetType() -ne [long] -or
                    [long]$ready.startTimeUtcTicks -le 0 -or
                    $ready.heldPath.GetType() -ne [string] -or
                    [string]$ready.heldPath -cne $heldPath -or
                    $ready.escapedSession.GetType() -ne [bool] -or
                    [bool]$ready.escapedSession -ne $expectedEscape) {
                    try {
                        if (-not $child.HasExited) { $child.Kill($true) }
                        $null = $child.WaitForExit(5000)
                    }
                    catch {}
                    throw 'The Task 8 residual-tree fixture did not become ready.'
                }
                Write-Task8Trace -Event 'grandchild-ready' -Data @{
                    processId = [long]$ready.processId
                    startTimeUtcTicks = [long]$ready.startTimeUtcTicks
                    heldPath = [string]$ready.heldPath
                    escapedSession = [bool]$ready.escapedSession
                }
            }
            finally { $child.Dispose() }
        }.GetNewClosure()
    }
    'ExtractedMutation' {
        $hooks.BeforeImport = {
            param($state)
            $path = Join-Path $state.ModuleRoot 'GraphKit.psm1'
            Set-Task8FixtureOwnerWritable -Path $path -Directory $false
            [IO.File]::AppendAllText($path, '# mutation')
        }.GetNewClosure()
    }
    'ExtractedWritable' {
        $hooks.BeforeImport = {
            param($state)
            $path = Join-Path $state.ModuleRoot 'GraphKit.psm1'
            Set-Task8FixtureOwnerWritable -Path $path -Directory $false
        }.GetNewClosure()
    }
    { $_ -in @(
        'FinalImportContentMutation','FinalImportWritableMutation',
        'FinalImportClosureMutation','FinalImportHardLinkMutation')
    } {
        $hooks.BeforeFinalImportRecheck = {
            param($state)
            $path = Join-Path $state.ModuleRoot 'GraphKit.psm1'
            $outside = $null
            switch ($HookKind) {
                'FinalImportContentMutation' {
                    Set-Task8FixtureOwnerWritable -Path $path -Directory $false
                    [IO.File]::AppendAllText($path, '# final import content mutation')
                }
                'FinalImportWritableMutation' {
                    Set-Task8FixtureOwnerWritable -Path $path -Directory $false
                }
                'FinalImportClosureMutation' {
                    Set-Task8FixtureOwnerWritable -Path $state.ModuleRoot -Directory $true
                    [IO.File]::WriteAllText(
                        (Join-Path $state.ModuleRoot 'task8-unexpected.ps1'), 'unexpected')
                }
                'FinalImportHardLinkMutation' {
                    $outside = Join-Path (Split-Path $state.RootPath -Parent) (
                        'graphkit-task8-link-target-' + [guid]::NewGuid().ToString('N'))
                    New-Task8FixtureHardLink -State $state `
                        -RelativePath 'module/GraphKit.psm1' -LinkPath $outside
                    Write-Task8Trace -Event 'mutation-outside-created' -Data @{ path = $outside }
                }
            }
            Write-Task8Trace -Event 'final-import-mutated' -Data @{
                kind = $HookKind
                outside = [string] $outside
            }
        }.GetNewClosure()
    }
    { $_ -in @(
        'CleanupContentMutation','CleanupWritableMutation',
        'CleanupClosureMutation','CleanupHardLinkMutation')
    } {
        $hooks.BeforeCleanup = {
            param($state)
            $path = Join-Path $state.ModuleRoot 'GraphKit.psm1'
            $outside = $null
            switch ($HookKind) {
                'CleanupContentMutation' {
                    Set-Task8FixtureOwnerWritable -Path $path -Directory $false
                    [IO.File]::AppendAllText($path, '# cleanup content mutation')
                }
                'CleanupWritableMutation' {
                    Set-Task8FixtureOwnerWritable -Path $path -Directory $false
                }
                'CleanupClosureMutation' {
                    Set-Task8FixtureOwnerWritable -Path $state.ModuleRoot -Directory $true
                    [IO.File]::WriteAllText(
                        (Join-Path $state.ModuleRoot 'task8-unexpected.ps1'), 'unexpected')
                }
                'CleanupHardLinkMutation' {
                    $outside = Join-Path (Split-Path $state.RootPath -Parent) (
                        'graphkit-task8-link-target-' + [guid]::NewGuid().ToString('N'))
                    New-Task8FixtureHardLink -State $state `
                        -RelativePath 'module/GraphKit.psm1' -LinkPath $outside
                    Write-Task8Trace -Event 'mutation-outside-created' -Data @{ path = $outside }
                }
            }
            Write-Task8Trace -Event 'cleanup-mutated' -Data @{
                kind = $HookKind
                outside = [string] $outside
            }
        }.GetNewClosure()
    }
    { $_ -in @('CleanupFileContentMutationBefore','CleanupFileContentMutationAfter') } {
        $hooks.OnCleanupFile = {
            param($state, $relative, $phase, $native)
            if ([string]$relative -cne 'module/GraphKit.psm1') {
                return
            }
            $path = Join-Path $state.RootPath (
                [string]$relative -replace '/', [IO.Path]::DirectorySeparatorChar)
            if ($HookKind -ceq 'CleanupFileContentMutationBefore' -and
                [string]$phase -ceq 'AfterWritable') {
                if ($null -eq $hooks.CleanupOriginalBytes) {
                    throw 'The cleanup fixture lost its exact original bytes.'
                }
                [IO.File]::WriteAllBytes($path, [byte[]]$hooks.CleanupOriginalBytes)
                $hooks.CleanupOriginalBytes = $null
                Write-Task8Trace -Event 'cleanup-file-restored' -Data @{
                    relative = [string]$relative
                    phase = [string]$phase
                    root = [string]$state.RootPath
                }
                return
            }
            $expectedPhase = if ($HookKind -ceq 'CleanupFileContentMutationBefore') {
                'BeforeWritable'
            }
            else { 'AfterWritable' }
            if ([string]$phase -cne $expectedPhase) { return }
            if ($phase -ceq 'BeforeWritable') {
                $hooks.CleanupOriginalBytes = [IO.File]::ReadAllBytes($path)
                $native::SetOwnerOnly($path, $false, $true)
            }
            [IO.File]::AppendAllText($path, '# same-identity cleanup mutation')
            if ($phase -ceq 'BeforeWritable') {
                $native::SetOwnerOnly($path, $false, $false)
            }
            Write-Task8Trace -Event 'cleanup-file-mutated' -Data @{
                relative = [string]$relative
                phase = [string]$phase
                root = [string]$state.RootPath
            }
        }.GetNewClosure()
    }
    { $_ -in @(
        'CleanupDirectoryReplacementAfterWritable',
        'CleanupDirectoryReplacementBeforeDelete'
    ) } {
        $hooks.OnCleanupDirectory = {
            param($state, $relative, $phase, $native)
            $expectedPhase = if ($HookKind -ceq 'CleanupDirectoryReplacementBeforeDelete') {
                'BeforeDelete'
            }
            else { 'AfterWritable' }
            if ($hooks.CleanupContainerMutationDone -or
                [string]$relative -cne 'module' -or
                [string]$phase -cne $expectedPhase) {
                return
            }
            $hooks.CleanupContainerMutationDone = $true
            $path = Join-Path $state.RootPath 'module'
            $outside = Join-Path (Split-Path $state.RootPath -Parent) (
                'graphkit-task8-cleanup-directory-' + [guid]::NewGuid().ToString('N'))
            Move-Task8FixtureDirectoryIdentityPreservingChildren `
                -Path $path -OutsidePath $outside
            Write-Task8Trace -Event 'cleanup-container-mutated' -Data @{
                kind = $HookKind
                relative = [string]$relative
                phase = [string]$phase
                root = [string]$state.RootPath
                outside = [string]$outside
            }
        }.GetNewClosure()
    }
    { $_ -in @(
        'CleanupRootReplacementAfterWritable',
        'CleanupRootReplacementBeforeDelete'
    ) } {
        $hooks.OnCleanupRoot = {
            param($state, $phase, $native)
            $expectedPhase = if ($HookKind -ceq 'CleanupRootReplacementBeforeDelete') {
                'BeforeDelete'
            }
            else { 'AfterWritable' }
            if ($hooks.CleanupContainerMutationDone -or
                [string]$phase -cne $expectedPhase) {
                return
            }
            $hooks.CleanupContainerMutationDone = $true
            $outside = Join-Path (Split-Path $state.RootPath -Parent) (
                'graphkit-task8-cleanup-root-' + [guid]::NewGuid().ToString('N'))
            Move-Task8FixtureDirectoryIdentityPreservingChildren `
                -Path $state.RootPath -OutsidePath $outside
            Write-Task8Trace -Event 'cleanup-container-mutated' -Data @{
                kind = $HookKind
                relative = ''
                phase = [string]$phase
                root = [string]$state.RootPath
                outside = [string]$outside
            }
        }.GetNewClosure()
    }
    'ExtractedFileReplacement' {
        $hooks.BeforeImport = {
            param($state)
            $path = Join-Path $state.ModuleRoot 'GraphKit.psm1'
            $bytes = [IO.File]::ReadAllBytes($path)
            Set-Task8FixtureOwnerWritable -Path $state.ModuleRoot -Directory $true
            Set-Task8FixtureOwnerWritable -Path $path -Directory $false
            [IO.File]::Delete($path)
            [IO.File]::WriteAllBytes($path, $bytes)
            Write-Task8Trace -Event 'file-replaced' -Data @{}
        }.GetNewClosure()
    }
    'ExtractedHardLink' {
        $hooks.BeforeImport = {
            param($state)
            $path = Join-Path $state.ModuleRoot 'GraphKit.psm1'
            $outside = Join-Path (Split-Path $state.RootPath -Parent) (
                'graphkit-task8-link-target-' + [guid]::NewGuid().ToString('N'))
            [IO.File]::WriteAllBytes($outside, [IO.File]::ReadAllBytes($path))
            Set-Task8FixtureOwnerWritable -Path $state.ModuleRoot -Directory $true
            Set-Task8FixtureOwnerWritable -Path $path -Directory $false
            [IO.File]::Delete($path)
            $null = New-Item -ItemType HardLink -Path $path -Target $outside -ErrorAction Stop
            Write-Task8Trace -Event 'link-substituted' -Data @{ outside = $outside }
        }.GetNewClosure()
    }
    'ModuleDirectoryReplacement' {
        $hooks.BeforeImport = {
            param($state)
            $backup = $state.ModuleRoot + '.original'
            Set-Task8FixtureOwnerWritable -Path $state.RootPath -Directory $true
            Set-Task8FixtureOwnerWritable -Path $state.ModuleRoot -Directory $true
            [IO.Directory]::Move($state.ModuleRoot, $backup)
            [IO.Directory]::CreateDirectory($state.ModuleRoot) | Out-Null
            Write-Task8Trace -Event 'module-directory-replaced' -Data @{ backup = $backup }
        }.GetNewClosure()
    }
    'RootReplacement' {
        $hooks.BeforeImport = {
            param($state)
            $backup = $state.RootPath + '.original'
            Set-Task8FixtureOwnerWritable -Path $state.RootPath -Directory $true
            [IO.Directory]::Move($state.RootPath, $backup)
            [IO.Directory]::CreateDirectory($state.RootPath) | Out-Null
            Write-Task8Trace -Event 'root-replaced' -Data @{ backup = $backup; replacement = $state.RootPath }
        }.GetNewClosure()
    }
    'ExternalSeams' {
        foreach ($name in @(
            'Get-GraphContext','Get-GraphObject','Invoke-GraphOperation',
            'Get-Secret','Get-SecretInfo','Get-SecretVault','Set-Secret','Remove-Secret',
            'Test-SecretVault','Unlock-SecretVault','Register-SecretVault','Unregister-SecretVault',
            'Invoke-RestMethod','Invoke-WebRequest','Connect-MgGraph','Invoke-MgGraphRequest',
            'New-MgApplication','Update-MgApplication','Remove-MgApplication',
            'Add-MgApplicationKey','Remove-MgApplicationKey',
            'Add-MgApplicationPassword','Remove-MgApplicationPassword',
            'New-MgServicePrincipal','Update-MgServicePrincipal','Remove-MgServicePrincipal',
            'Add-MgServicePrincipalKey','Remove-MgServicePrincipalKey',
            'Add-MgServicePrincipalPassword','Remove-MgServicePrincipalPassword',
            'New-MgServicePrincipalAppRoleAssignment','Remove-MgServicePrincipalAppRoleAssignment',
            'New-MgServicePrincipalAppRoleAssignedTo','Remove-MgServicePrincipalAppRoleAssignedTo',
            'New-MgOauth2PermissionGrant','Update-MgOauth2PermissionGrant',
            'Remove-MgOauth2PermissionGrant',
            'Register-GraphTenant','Remove-GraphTenant','Install-PSResource','Install-Module',
            'Save-Module','Register-PSRepository','Connect-AzAccount','New-AzResourceGroup',
            'Remove-AzResourceGroup','New-AzUserAssignedIdentity','Remove-AzUserAssignedIdentity',
            'New-AzContainerGroup','Remove-AzContainerGroup','az'
        )) {
            Set-Item -Path "function:global:$name" -Value {
                Write-Task8Trace -Event 'forbidden-seam'
                throw 'task8-secret-sentinel'
            }.GetNewClosure()
        }
    }
    'PackageLiveSuccess' {
        $hooks.PrepareLiveModule = {
            param($module, $state, $route, $requestedProfileId, $requestedStorePath, $storePathBound)
            $tenantId = [guid] '00000000-0000-0000-0000-000000000111'
            $clientId = [guid] '00000000-0000-0000-0000-000000000333'
            $generation = 'task8-fixture-generation'
            $fingerprint = 'task8-fixture-token-fingerprint'
            $source = New-Task8SourceProxy -Mode ([string]$route.AuthMode) `
                -CanRefresh ([bool]$route.CanRefresh) -VerifiedTenantId $tenantId.ToString('D') `
                -ClientId $clientId.ToString('D') -CredentialGeneration $generation `
                -TokenFingerprint $fingerprint
            $profile = @{
                ProfileId = $requestedProfileId
                Name = 'Task 8 Fixture'
                Kind = 'lab'
                TenantId = $tenantId.ToString('D')
                Environment = 'Global'
                AuthMethod = 'Certificate'
                ClientId = $clientId.ToString('D')
                Credential = @{ VaultName = 'fixture'; CertificateName = 'fixture'; Version = 'v1' }
            }
            $holderKey = 'GraphKit.Task8.PackageLive/' + [guid]::NewGuid().ToString('N')
            $holder = [pscustomobject]@{
                Source = $source
                Profile = $profile
                TenantId = $tenantId
                Generation = $generation
                Fingerprint = $fingerprint
                Events = [Collections.Concurrent.ConcurrentQueue[object]]::new()
            }
            [AppDomain]::CurrentDomain.SetData($holderKey, $holder)
            $hooks.PackageLiveHolderKey = $holderKey
            Write-Task8Trace -Event 'prepare-live-module' -Data @{
                storePathBound = [bool]$storePathBound
            }
            & $module {
                param($key)
                $script:Task8PackageLiveHolderKey = $key
                Set-Item -Path Function:Get-GraphProfileStore -Value {
                    param([string] $StorePath)
                    $holder = [AppDomain]::CurrentDomain.GetData(
                        $script:Task8PackageLiveHolderKey)
                    $holder.Events.Enqueue([pscustomobject]@{
                        Kind = 'context-command'
                        StorePath = [string]$StorePath
                    })
                    return [pscustomobject]@{ Profiles = @($holder.Profile) }
                }
                Set-Item -Path Function:New-GraphTokenSource -Value {
                    param($Profile, $Cloud, $MsalFactory)
                    $holder = [AppDomain]::CurrentDomain.GetData(
                        $script:Task8PackageLiveHolderKey)
                    $holder.Events.Enqueue([pscustomobject]@{
                        Kind = 'source-created'
                        AuthMethod = [string]$Profile.AuthMethod
                    })
                    return $holder.Source
                }
                Set-Item -Path Function:Invoke-GraphPaging -Value {
                    param(
                        $Context, $Descriptor, $FirstPageUri, $RequestFactoryScript,
                        $TransportScript, $MaxPages, $CancellationToken, $DeadlineSeconds, $UtcNow
                    )
                    $holder = [AppDomain]::CurrentDomain.GetData(
                        $script:Task8PackageLiveHolderKey)
                    $holder.Events.Enqueue([pscustomobject]@{
                        Kind = 'read-command'
                        Type = [string]$Descriptor.Type
                        Operation = [string]$Descriptor.Operation
                        MaxPages = [int]$MaxPages
                        FirstPageAuthority = [string]$FirstPageUri.Authority
                    })
                    return [pscustomobject]@{
                        PSTypeName = 'GraphKit.OperationResult'
                        Outcome = 'Succeeded'
                        Certainty = 'Known'
                        Truncated = $false
                        PageCount = 1
                        Data = @(
                            [pscustomobject]@{ id = 'task8-package-row-1' }
                            [pscustomobject]@{ id = 'task8-package-row-2' }
                        )
                        Telemetry = @()
                        Provenance = @{
                            IdentityState = 'VerifiedForToken'
                            TenantId = $holder.TenantId
                            ActualTenantId = $holder.TenantId
                            TokenFingerprint = [string]$holder.Fingerprint
                            CredentialGeneration = [string]$holder.Generation
                            Cloud = 'Global'
                        }
                    }
                }
            } $holderKey
        }.GetNewClosure()
    }
    { $_ -like 'Live*' } {
        $hooks.GetContext = {
            param($requestedProfileId, $requestedStorePath, $route)
            $mode = [string] $route.AuthMode
            $refresh = $mode -cne 'BearerToken'
            $contextIdentityState = 'NotAcquired'
            $contextTenant = if ($HookKind -ceq 'LiveContextTenantEmpty') {
                [guid]::Empty
            }
            else { [guid] '00000000-0000-0000-0000-000000000111' }
            $contextClient = if ($mode -ceq 'BearerToken') {
                $null
            }
            else { [guid] '00000000-0000-0000-0000-000000000333' }
            $sourceClient = if ($mode -ceq 'BearerToken') {
                $null
            }
            elseif ($HookKind -ceq 'LiveSourceClientMismatch') {
                '00000000-0000-0000-0000-000000000444'
            }
            else { '00000000-0000-0000-0000-000000000333' }
            $generation = if ($HookKind -ceq 'LiveSourceGenerationBlank') {
                ''
            }
            else { 'task8-fixture-generation' }
            $sourceFingerprint = if ($HookKind -ceq 'LiveFingerprintMismatch') {
                'task8-fixture-source-fingerprint-mismatch'
            }
            else { 'task8-fixture-token-fingerprint' }
            Write-Task8Trace -Event 'context' -Data @{
                mode = $mode
                identityState = $contextIdentityState
            }
            $source = if ($HookKind -ceq 'LiveInterfaceMismatch') {
                [pscustomobject]@{ AuthMode = $mode; CanRefresh = $refresh }
            }
            else {
                New-Task8SourceProxy -Mode $(if ($HookKind -ceq 'LiveModeMismatch') { 'Certificate' } else { $mode }) `
                    -CanRefresh $(if ($HookKind -ceq 'LiveRefreshMismatch') { -not $refresh } else { $refresh }) `
                    -VerifiedTenantId $(if ($HookKind -ceq 'LiveSourceTenantMismatch') {
                        '00000000-0000-0000-0000-000000000222'
                    } elseif ($HookKind -ceq 'LiveSourceTenantEmpty') {
                        '00000000-0000-0000-0000-000000000000'
                    } else { '00000000-0000-0000-0000-000000000111' }) `
                    -ClientId $sourceClient -CredentialGeneration $generation `
                    -TokenFingerprint $sourceFingerprint
            }
            return [pscustomobject]@{
                PSTypeName = 'GraphKit.Context'
                ProfileId = $requestedProfileId
                TenantId = $contextTenant
                Cloud = 'Global'
                GraphBaseUri = [uri] 'https://graph.microsoft.com'
                ClientId = $contextClient
                TokenSource = $source
                CredentialFingerprint = $(if ([string]::IsNullOrEmpty($generation)) {
                    ''
                } else {
                    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
                        [Text.Encoding]::UTF8.GetBytes($generation))).ToLowerInvariant()
                })
                AcquisitionCacheKey = 'task8-fixture-acquisition-key'
                IdentityState = $contextIdentityState
            }
        }.GetNewClosure()
        $hooks.Read = {
            param($context, $type, $operation, $passThruResult)
            Write-Task8Trace -Event 'read' -Data @{
                type = [string] $type
                operation = [string] $operation
                passThruResult = [bool] $passThruResult
            }
            if ($HookKind -ceq 'LiveAcquisitionFailure') {
                throw [GraphKit.Auth.GraphAuthException]::new(
                    'task8_fixture_acquisition', 'Acquisition', 'task8-secret-sentinel', $null, $null)
            }
            $outcome = if ($HookKind -ceq 'LiveFailedEnvelope') { 'Failed' } else { 'Succeeded' }
            $certainty = if ($HookKind -ceq 'LiveIndeterminate') { 'Indeterminate' } else { 'Known' }
            $truncated = $HookKind -ceq 'LiveTruncated'
            $verified = $HookKind -cne 'LiveUnverified'
            $provenance = @{
                IdentityState = $(if ($verified) { 'VerifiedForToken' } else { 'NotAcquired' })
                TenantId = $(if (-not $verified) { $null } elseif (
                    $HookKind -ceq 'LiveTargetTenantMismatch') {
                    [guid] '00000000-0000-0000-0000-000000000222'
                } elseif ($HookKind -ceq 'LiveTargetTenantEmpty') {
                    [guid]::Empty
                } else { $context.TenantId })
                ActualTenantId = $(if (-not $verified) { $null } elseif (
                    $HookKind -ceq 'LiveActualTenantMismatch') {
                    [guid] '00000000-0000-0000-0000-000000000222'
                } elseif ($HookKind -ceq 'LiveActualTenantEmpty') {
                    [guid]::Empty
                } else { $context.TenantId })
                TokenFingerprint = $(if ($HookKind -ceq 'LiveFingerprintBlank') {
                    ''
                } else { 'task8-fixture-token-fingerprint' })
                CredentialGeneration = $(if ($HookKind -ceq 'LiveGenerationBlank') {
                    ''
                } elseif ($HookKind -ceq 'LiveGenerationMismatch') {
                    'task8-fixture-generation-mismatch'
                } else { 'task8-fixture-generation' })
                Cloud = $(if ($HookKind -ceq 'LiveCloudBlank') {
                    ''
                } elseif ($HookKind -ceq 'LiveCloudMismatch') {
                    'USGov'
                } else { 'Global' })
            }
            if ($HookKind -ceq 'LiveFingerprintMissing') {
                $null = $provenance.Remove('TokenFingerprint')
            }
            if ($HookKind -ceq 'LiveGenerationMissing') {
                $null = $provenance.Remove('CredentialGeneration')
            }
            if ($HookKind -ceq 'LiveCloudMissing') {
                $null = $provenance.Remove('Cloud')
            }
            return [pscustomobject]@{
                PSTypeName = 'GraphKit.OperationResult'
                Outcome = $outcome
                Certainty = $certainty
                Truncated = $truncated
                Data = @(
                    [pscustomobject]@{ id = 'task8-row-secret-1'; displayName = 'task8-secret-sentinel' }
                    [pscustomobject]@{ id = 'task8-row-secret-2'; displayName = 'task8-secret-sentinel' }
                )
                Provenance = $provenance
            }
        }.GetNewClosure()
    }
    'EnvironmentProbe' {
        Write-Task8Trace -Event 'environment-probe' -Data @{
            upperHttp = [string] $env:HTTP_PROXY
            upperHttps = [string] $env:HTTPS_PROXY
            upperAll = [string] $env:ALL_PROXY
            upperNo = [string] $env:NO_PROXY
            lowerHttp = [string] $env:http_proxy
            lowerHttps = [string] $env:https_proxy
            lowerAll = [string] $env:all_proxy
            lowerNo = [string] $env:no_proxy
        }
    }
    'StreamSentinel' {
        $hooks.AllowStreamRecords = $true
        $hooks.AfterSnapshot = {
            param($state)
            Write-Task8Trace -Event 'stream-sentinel-fired' -Data @{}
            Write-Output 'task8-secret-sentinel-success'
            Write-Warning 'task8-secret-sentinel-warning'
            Write-Verbose 'task8-secret-sentinel-verbose' -Verbose
            Write-Debug 'task8-secret-sentinel-debug' -Debug
            Write-Information 'task8-secret-sentinel-information' -InformationAction Continue
            Write-Host 'task8-secret-sentinel-host'
            Write-Error 'task8-secret-sentinel-error' -ErrorAction Continue
        }.GetNewClosure()
    }
    'EvidenceMutation' {
        $hooks.MutateEvidence = {
            param($record)
            if ($MutationValue -ceq 'task8-string-count-sentinel') {
                $record.read.rowCount = $MutationValue
            }
            elseif ($MutationValue -ceq '0.4.0-task8-secret-sentinel') {
                $record.moduleVersion = $MutationValue
            }
            elseif ($MutationValue -ceq 'task8-secret-sentinel') {
                $record.checks | Add-Member -MemberType NoteProperty -Name unknownNested -Value $MutationValue
            }
            else {
                $record | Add-Member -MemberType NoteProperty -Name forbidden -Value $MutationValue
            }
        }.GetNewClosure()
    }
}

if ($HookKind -ceq 'AbsentModulePath') {
    Remove-Item -LiteralPath Env:PSModulePath -ErrorAction SilentlyContinue
}
$beforeModulePathPresent = Test-Path -LiteralPath Env:PSModulePath
$beforeModulePath = if ($beforeModulePathPresent) { [string] $env:PSModulePath } else { $null }

try {
    $parameters = @{
        PackagePath = $PackagePath
        PackageSha256 = $PackageSha256
        AuthMode = $AuthMode
    }
    if ($UseDryRun) { $parameters.DryRun = $true }
    else {
        $parameters.ProfileId = $ProfileId
        if (-not [string]::IsNullOrEmpty($StorePath)) { $parameters.StorePath = $StorePath }
    }
    if ($UseInternalWorker) {
        # The production worker enters its own Unix session before reading stdin.
        # This wrapper is the actual test worker root, so establish the identical
        # ownership boundary before a no-read seam or before invoking the worker.
        $treeBootstrapHooks = [pscustomobject]@{
            ContractMarker = 'GraphKit.Task8.ParityTestHooks/1'
            ExportFunctionsOnly = $true
        }
        [AppDomain]::CurrentDomain.SetData(
            'GraphKit.Task8.ParityTestHooks/1', $treeBootstrapHooks)
        try {
            . $RunnerPath -PackagePath 'unused.nupkg' -PackageSha256 ('0' * 64) `
                -AuthMode Certificate -DryRun
        }
        finally {
            [AppDomain]::CurrentDomain.SetData('GraphKit.Task8.ParityTestHooks/1', $null)
        }
        Initialize-GraphKitAuthParityProcessTreeNative
        $script:GraphKitAuthParityProcessTreeType::EnterUnixWorkerSession()
        if ($HookKind -ceq 'WorkerNoRead') {
            Start-Sleep -Seconds 30
        }
        else {
            [AppDomain]::CurrentDomain.SetData(
                'GraphKit.Task8.ParityTestHooks/1', [pscustomobject] $hooks)
            if ($HookKind -cin @(
                'WorkerBomFrame','WorkerSecondFrame','WorkerMissingTerminator',
                'WorkerEmptyFrame','WorkerInvalidUtf8','WorkerStderr',
                'WorkerStdoutOverflow','WorkerStderrOverflow','WorkerNonzeroExit')) {
                $savedWriter = [Console]::Out
                $captureWriter = [IO.StringWriter]::new(
                    [Globalization.CultureInfo]::InvariantCulture)
                try {
                    [Console]::SetOut($captureWriter)
                    & $WorkerPath
                }
                finally { [Console]::SetOut($savedWriter) }
                $payloadText = $captureWriter.ToString()
                $captureWriter.Dispose()
                $utf8 = [Text.UTF8Encoding]::new($false)
                $payload = $utf8.GetBytes($payloadText)
                $outputStream = [Console]::OpenStandardOutput()
                $errorStream = [Console]::OpenStandardError()
                switch ($HookKind) {
                    'WorkerBomFrame' {
                        $outputStream.Write([byte[]]@(0xEF,0xBB,0xBF), 0, 3)
                        $outputStream.Write($payload, 0, $payload.Length)
                    }
                    'WorkerSecondFrame' {
                        $outputStream.Write($payload, 0, $payload.Length)
                        $outputStream.Write($payload, 0, $payload.Length)
                    }
                    'WorkerMissingTerminator' {
                        $unterminated = $utf8.GetBytes(
                            $payloadText.TrimEnd([char[]]@("`r","`n")))
                        $outputStream.Write($unterminated, 0, $unterminated.Length)
                    }
                    'WorkerEmptyFrame' {}
                    'WorkerInvalidUtf8' {
                        $invalid = [byte[]]@(0xFF,0x0A)
                        $outputStream.Write($invalid, 0, $invalid.Length)
                    }
                    'WorkerStderr' {
                        $outputStream.Write($payload, 0, $payload.Length)
                        $errorBytes = $utf8.GetBytes("task8-secret-sentinel`n")
                        $errorStream.Write($errorBytes, 0, $errorBytes.Length)
                    }
                    'WorkerStdoutOverflow' {
                        $overflowBytes = $utf8.GetBytes(
                            'task8-secret-sentinel' + ('x' * 66000) + "`n")
                        $outputStream.Write($overflowBytes, 0, $overflowBytes.Length)
                    }
                    'WorkerStderrOverflow' {
                        $outputStream.Write($payload, 0, $payload.Length)
                        $overflowBytes = $utf8.GetBytes(('x' * 66000) + "`n")
                        $errorStream.Write($overflowBytes, 0, $overflowBytes.Length)
                    }
                    'WorkerNonzeroExit' {
                        $outputStream.Write($payload, 0, $payload.Length)
                    }
                }
                $outputStream.Flush()
                $errorStream.Flush()
                if ($HookKind -ceq 'WorkerNonzeroExit') { exit 7 }
            }
            else {
                & $WorkerPath
            }
            if ($HookKind -ceq 'WorkerExtraBlankFrame') {
                [Console]::Out.WriteLine('')
            }
        }
    }
    elseif ($HookKind -like 'Live*') {
        $dryOutput = @(& $RunnerPath -PackagePath $fixturePackagePath `
            -PackageSha256 $fixturePackageSha256 -AuthMode $fixtureAuthMode -DryRun)
        $dryParsedState = if ($dryOutput.Count -eq 1) {
            [string]($dryOutput[0] | ConvertFrom-Json -ErrorAction Stop).state
        }
        else { '<count-mismatch>' }
        if ($dryOutput.Count -ne 1 -or
            $dryParsedState -cne 'Passed') {
            throw 'The exact package did not pass the prerequisite DryRun.'
        }
        $exportHooks = [pscustomobject]@{
            ContractMarker = 'GraphKit.Task8.ParityTestHooks/1'
            ExportFunctionsOnly = $true
        }
        [AppDomain]::CurrentDomain.SetData('GraphKit.Task8.ParityTestHooks/1', $exportHooks)
        try {
            . $RunnerPath -PackagePath 'unused.nupkg' -PackageSha256 ('a' * 64) `
                -AuthMode Certificate -DryRun
        }
        finally {
            [AppDomain]::CurrentDomain.SetData('GraphKit.Task8.ParityTestHooks/1', $null)
        }
        $null = Import-Task8FixtureContractsFromPackage -Path $fixturePackagePath
        $contracts = @([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {
            $_.GetName().Name -ceq 'GraphKit.Auth.Contracts'
        })
        if ($contracts.Count -ne 1) {
            throw 'The exact package did not load one contracts assembly for the test core.'
        }
        $diagnostics = [pscustomobject]@{
            InterfaceType = $contracts[0].GetType('GraphKit.Auth.IGraphTokenSource', $true, $false)
            ContractsAssembly = $contracts[0]
        }
        $route = New-GraphKitAuthParityRoute -Mode $fixtureAuthMode
        $core = Invoke-GraphKitAuthParityLiveCore -Route $route -Diagnostics $diagnostics `
            -ProfileId $fixtureProfileId -StorePath $fixtureStorePath `
            -StorePathBound:$(-not [string]::IsNullOrEmpty($fixtureStorePath)) `
            -GetContextAction $hooks.GetContext -ReadAction $hooks.Read
        $core | ConvertTo-Json -Compress -Depth 5
    }
    else {
        [AppDomain]::CurrentDomain.SetData(
            'GraphKit.Task8.ParityTestHooks/1', [pscustomobject] $hooks)
        for ($runIndex = 0; $runIndex -lt $RepeatCount; $runIndex++) {
            if ($UseOrdinaryExecution) { & $RunnerPath @parameters }
            else { . $RunnerPath @parameters }
            Write-Task8Trace -Event 'parent-after-run' -Data @{
                processId = [Environment]::ProcessId
                graphKitCount = @(Get-Module -Name GraphKit -All).Count
                contractsCount = @([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {
                    $_.GetName().Name -ceq 'GraphKit.Auth.Contracts'
                }).Count
            }
        }
    }
}
finally {
    [AppDomain]::CurrentDomain.SetData('GraphKit.Task8.ParityTestHooks/1', $null)
    $script:task8PackageLiveHolderKey = [string]$hooks.PackageLiveHolderKey
    if (-not [string]::IsNullOrEmpty([string]$script:task8PackageLiveHolderKey)) {
        $holder = [AppDomain]::CurrentDomain.GetData($script:task8PackageLiveHolderKey)
        if ($null -ne $holder) {
            $event = $null
            while ($holder.Events.TryDequeue([ref]$event)) {
                Write-Task8Trace -Event ([string]$event.Kind) -Data @{
                    storePath = $(if ($null -ne $event.PSObject.Properties['StorePath']) {
                        [string]$event.StorePath
                    } else { '' })
                    authMethod = $(if ($null -ne $event.PSObject.Properties['AuthMethod']) {
                        [string]$event.AuthMethod
                    } else { '' })
                    type = $(if ($null -ne $event.PSObject.Properties['Type']) {
                        [string]$event.Type
                    } else { '' })
                    operation = $(if ($null -ne $event.PSObject.Properties['Operation']) {
                        [string]$event.Operation
                    } else { '' })
                    maxPages = $(if ($null -ne $event.PSObject.Properties['MaxPages']) {
                        [int]$event.MaxPages
                    } else { 0 })
                    firstPageAuthority = $(if (
                        $null -ne $event.PSObject.Properties['FirstPageAuthority']) {
                        [string]$event.FirstPageAuthority
                    } else { '' })
                }
                $event = $null
            }
        }
        [AppDomain]::CurrentDomain.SetData($script:task8PackageLiveHolderKey, $null)
        $script:task8PackageLiveHolderKey = $null
    }
    if (-not $UseInternalWorker) {
        $modulePathPresent = Test-Path -LiteralPath Env:PSModulePath
        Write-Task8Trace -Event 'wrapper-finished' -Data @{
            modulePathRestored = ($modulePathPresent -eq $beforeModulePathPresent -and
                (-not $beforeModulePathPresent -or [string] $env:PSModulePath -ceq $beforeModulePath))
            modulePathPresent = $modulePathPresent
            graphKitLoaded = (@(Get-Module -Name GraphKit -All).Count -ne 0)
            preloadedStillLoaded = ($null -ne $preloadedModule -and
                @(Get-Module -Name GraphKit -All).Count -ne 0)
        }
    }
    if ($null -ne $preloadedModule) {
        Remove-Module -ModuleInfo $preloadedModule -Force -ErrorAction SilentlyContinue
        $preloadedModule = $null
    }
    if ($null -ne $preloadedRoot -and (Test-Path -LiteralPath $preloadedRoot)) {
        Remove-Item -LiteralPath $preloadedRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
'@, [Text.UTF8Encoding]::new($false))

        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = (Get-Command pwsh -ErrorAction Stop).Source
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        foreach ($argument in @(
            '-NoLogo','-NoProfile','-File',$wrapperPath,
            '-RunnerPath',$script:runnerPath,
            '-PackagePath',$PackagePath,
            '-PackageSha256',$PackageSha256,
            '-AuthMode',$AuthMode,
            '-UseDryRunText',([string][bool] $DryRun).ToLowerInvariant(),
            '-ProfileId',([string] $ProfileId),
            '-StorePath',([string] $StorePath),
            '-HookKind',$HookKind,
            '-MutationValue',$MutationValue,
            '-OrdinaryExecutionText',([string][bool] $OrdinaryExecution).ToLowerInvariant(),
            '-RepeatCount',([string] $Repeat),
            '-TracePath',$tracePath,
            '-GrandchildPath',$grandchildPath
        )) {
            $null = $startInfo.ArgumentList.Add([string] $argument)
        }
        $startInfo.Environment['NuGetAudit'] = 'false'
        $startInfo.Environment['HTTP_PROXY'] = 'http://127.0.0.1:1'
        $startInfo.Environment['HTTPS_PROXY'] = 'http://127.0.0.1:1'
        $startInfo.Environment['ALL_PROXY'] = 'http://127.0.0.1:1'
        $startInfo.Environment['NO_PROXY'] = 'localhost,127.0.0.1'
        $startInfo.Environment['http_proxy'] = 'http://127.0.0.1:1'
        $startInfo.Environment['https_proxy'] = 'http://127.0.0.1:1'
        $startInfo.Environment['all_proxy'] = 'http://127.0.0.1:1'
        $startInfo.Environment['no_proxy'] = 'localhost,127.0.0.1'

        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        try {
            if (-not $process.Start()) { throw 'Task 8 fresh-process runner did not start.' }
            $stdoutTask = $process.StandardOutput.ReadToEndAsync()
            $stderrTask = $process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit(60000)) {
                $process.Kill($true)
                throw 'Task 8 fresh-process runner exceeded the 60-second liveness bound.'
            }
            $stdout = $stdoutTask.GetAwaiter().GetResult()
            $stderr = $stderrTask.GetAwaiter().GetResult()
            $frames = [regex]::Matches(
                $stdout,
                '\G(?<json>\{[^\r\n]*\})(?:\r\n|\n)',
                [Text.RegularExpressions.RegexOptions]::CultureInvariant)
            $capturedLength = [long]0
            foreach ($frame in $frames) { $capturedLength += $frame.Length }
            $publicFramesValid = $frames.Count -gt 0 -and
                $capturedLength -eq $stdout.Length
            $outputLines = if ($publicFramesValid) {
                @($frames | ForEach-Object { $_.Groups['json'].Value })
            }
            else { @() }
            $parsedRecords = @()
            $parseFailed = -not $publicFramesValid
            foreach ($line in $outputLines) {
                try {
                    $parsedRecords += ConvertFrom-Task8JsonText -Json $line
                }
                catch {
                    $parseFailed = $true
                    $parsedRecords = @()
                    break
                }
            }
            $jsonCount = if ($parseFailed) { 0 } else { $parsedRecords.Count }
            $parsed = if ($jsonCount -eq 1) { $parsedRecords[0] } else { $null }
            return [pscustomobject]@{
                ExitCode = $process.ExitCode
                StdOut = $stdout
                StdErr = $stderr
                Output = $stdout + $stderr
                Data = $parsed
                DataRecords = @($parsedRecords)
                JsonCount = $jsonCount
                OutputLineCount = $outputLines.Count
                TracePath = $tracePath
            }
        }
        finally {
            $process.Dispose()
        }
    }

    function ConvertFrom-Task8JsonElement {
        param([Parameter(Mandatory)][Text.Json.JsonElement] $Element)
        switch ($Element.ValueKind) {
            Object {
                $value = [ordered]@{}
                foreach ($property in $Element.EnumerateObject()) {
                    $value[$property.Name] = ConvertFrom-Task8JsonElement -Element $property.Value
                }
                return [pscustomobject]$value
            }
            Array {
                $items = [Collections.Generic.List[object]]::new()
                foreach ($item in $Element.EnumerateArray()) {
                    $items.Add((ConvertFrom-Task8JsonElement -Element $item))
                }
                return ,$items.ToArray()
            }
            String { return [string]$Element.GetString() }
            Number {
                $integer = 0L
                if ($Element.TryGetInt64([ref]$integer)) { return $integer }
                return $Element.GetDecimal()
            }
            True { return $true }
            False { return $false }
            Null { return $null }
            default { throw "Unsupported Task 8 JSON kind '$($Element.ValueKind)'." }
        }
    }

    function ConvertFrom-Task8JsonText {
        param([Parameter(Mandatory)][string] $Json)
        $document = [Text.Json.JsonDocument]::Parse($Json)
        try { return ConvertFrom-Task8JsonElement -Element $document.RootElement }
        finally { $document.Dispose() }
    }

    function Assert-Task8ModeRecordShape {
        param(
            [Parameter(Mandatory)] $Record,
            [Parameter(Mandatory)][string] $Execution,
            [Parameter(Mandatory)][string] $AuthMode,
            [Parameter(Mandatory)][string] $PackageSha256
        )

        ($Record.PSObject.Properties.Name -join '|') | Should -BeExactly (
            'schemaVersion|execution|moduleVersion|packageSha256|authMode|state|failureStage|' +
            'failureCode|checks|adapter|read|startedUtc|completedUtc')
        $Record.schemaVersion | Should -Be 1
        $Record.execution | Should -BeExactly $Execution
        $Record.packageSha256 | Should -BeExactly $PackageSha256
        $Record.authMode | Should -BeExactly $AuthMode
        ($Record.checks.PSObject.Properties.Name -join '|') | Should -BeExactly (
            'packageDigestMatched|snapshotBound|archiveValidated|extractionSealed|exactImport|' +
            'routeMatched|contextMatched|sourceMatched|tenantProofVerified|cleanupVerified')
        @($Record.checks.PSObject.Properties.Value | Where-Object { $_ -isnot [bool] }).Count |
            Should -Be 0
        ($Record.adapter.PSObject.Properties.Name -join '|') | Should -BeExactly (
            'abiMarkerExact|contractsDefault|providerCollectibleNonDefault|msalVersionExact|' +
            'providerMsalSameContext|publicAbiExact')
        @($Record.adapter.PSObject.Properties.Value | Where-Object { $_ -isnot [bool] }).Count |
            Should -Be 0
        ($Record.read.PSObject.Properties.Name -join '|') |
            Should -BeExactly 'operation|attempted|succeeded|rowCount'
        $Record.read.operation | Should -BeExactly 'ManagedDevice.List'
        $Record.read.attempted | Should -BeOfType ([bool])
        $Record.read.succeeded | Should -BeOfType ([bool])
        [long] $Record.read.rowCount | Should -BeGreaterOrEqual 0
        $Record.startedUtc | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$'
        $Record.completedUtc | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$'
    }

    function Assert-Task8LiveCoreResult {
        param(
            [Parameter(Mandatory)] $Record,
            [Parameter(Mandatory)][string] $AuthMode,
            [Parameter(Mandatory)][string] $State,
            [Parameter(Mandatory)][string] $FailureStage,
            [Parameter(Mandatory)][string] $FailureCode
        )
        ($Record.PSObject.Properties.Name -join '|') | Should -BeExactly (
            'recordKind|authMode|state|failureStage|failureCode|contextMatched|sourceMatched|' +
            'tenantProofVerified|readAttempted|readSucceeded|rowCount')
        $Record.recordKind | Should -BeExactly 'GraphKit.Task8.LiveCoreTestResult/1'
        $Record.authMode | Should -BeExactly $AuthMode
        $Record.state | Should -BeExactly $State
        $Record.failureStage | Should -BeExactly $FailureStage
        $Record.failureCode | Should -BeExactly $FailureCode
        foreach ($name in @(
            'contextMatched','sourceMatched','tenantProofVerified','readAttempted','readSucceeded')) {
            $Record.$name | Should -BeOfType ([bool])
        }
        $Record.rowCount | Should -BeOfType ([long])
    }

    function Get-Task8TraceRecords {
        param([Parameter(Mandatory)][string] $Path)
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
        return @([IO.File]::ReadAllLines($Path) | ForEach-Object { $_ | ConvertFrom-Json -Depth 5 })
    }

    function Assert-Task8SafeFailure {
        param(
            [Parameter(Mandatory)] $Invocation,
            [Parameter(Mandatory)][string] $Stage,
            [Parameter(Mandatory)][string] $Code,
            [string] $AuthMode = 'Certificate',
            [string] $PackageSha256 = ('0' * 64)
        )
        $Invocation.ExitCode | Should -Be 0
        $Invocation.OutputLineCount | Should -Be 1
        $Invocation.JsonCount | Should -Be 1
        $Invocation.StdErr | Should -BeNullOrEmpty
        Assert-Task8ModeRecordShape -Record $Invocation.Data -Execution $(
            if ($Invocation.Data.execution -ceq 'Live') { 'Live' } else { 'DryRun' }) `
            -AuthMode $AuthMode -PackageSha256 $PackageSha256
        $Invocation.Data.state | Should -BeExactly 'Failed'
        $Invocation.Data.failureStage | Should -BeExactly $Stage
        $Invocation.Data.failureCode | Should -BeExactly $Code
    }

    function Remove-Task8ResidualFixturePath {
        param([AllowNull()][string] $Path)
        if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return }
        $full = [IO.Path]::GetFullPath($Path)
        $temp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        if (-not $full.StartsWith($temp, [StringComparison]::Ordinal) -or
            [IO.Path]::GetFileName($full) -notmatch '^graphkit-task8-') {
            throw 'Task 8 fixture cleanup refused a non-literal residual path.'
        }
        $rootItem = Get-Item -LiteralPath $full -Force -ErrorAction Stop
        if (-not [string]::IsNullOrEmpty([string] $rootItem.LinkType) -or
            ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Remove-Item -LiteralPath $full -Force -ErrorAction Stop
            return
        }
        $paths = @(
            Get-ChildItem -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue |
                Sort-Object { $_.FullName.Length } -Descending
        ) + @($rootItem)
        if ($IsWindows) {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
            foreach ($item in $paths) {
                if (-not [string]::IsNullOrEmpty([string] $item.LinkType) -or
                    ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    continue
                }
                $directory = [bool]$item.PSIsContainer
                $acl = if ($directory) {
                    [Security.AccessControl.DirectorySecurity]::new()
                }
                else {
                    [Security.AccessControl.FileSecurity]::new()
                }
                $acl.SetAccessRuleProtection($true, $false)
                $inheritance = if ($directory) {
                    [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                        [Security.AccessControl.InheritanceFlags]::ObjectInherit
                }
                else {
                    [Security.AccessControl.InheritanceFlags]::None
                }
                $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                    $identity,
                    [Security.AccessControl.FileSystemRights]::FullControl,
                    $inheritance,
                    [Security.AccessControl.PropagationFlags]::None,
                    [Security.AccessControl.AccessControlType]::Allow))
                if ($directory) {
                    [IO.FileSystemAclExtensions]::SetAccessControl(
                        [IO.DirectoryInfo]::new($item.FullName), $acl)
                }
                else {
                    [IO.FileSystemAclExtensions]::SetAccessControl(
                        [IO.FileInfo]::new($item.FullName), $acl)
                    $attributes = [IO.File]::GetAttributes($item.FullName)
                    if (($attributes -band [IO.FileAttributes]::ReadOnly) -ne 0) {
                        $writableAttributes = [IO.FileAttributes](
                            [int]$attributes -band (-bnot [int][IO.FileAttributes]::ReadOnly))
                        [IO.File]::SetAttributes(
                            $item.FullName,
                            $(if ([int]$writableAttributes -eq 0) {
                                [IO.FileAttributes]::Normal
                            }
                            else { $writableAttributes }))
                    }
                }
            }
        }
        else {
            foreach ($item in $paths) {
                if (-not [string]::IsNullOrEmpty([string] $item.LinkType) -or
                    ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    continue
                }
                $mode = [IO.File]::GetUnixFileMode($item.FullName)
                $required = [IO.UnixFileMode]::UserRead -bor
                    [IO.UnixFileMode]::UserWrite
                $anyExecute = [IO.UnixFileMode]::UserExecute -bor
                    [IO.UnixFileMode]::GroupExecute -bor
                    [IO.UnixFileMode]::OtherExecute
                if ($item.PSIsContainer -or
                    (([int] $mode -band [int] $anyExecute) -ne 0)) {
                    $required = $required -bor [IO.UnixFileMode]::UserExecute
                }
                [IO.File]::SetUnixFileMode(
                    $item.FullName,
                    [IO.UnixFileMode]([int] $mode -bor [int] $required))
            }
        }
        Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction Stop
    }

    function New-Task8ModeRecordFixture {
        param(
            [string] $AuthMode = 'Certificate',
            [string] $ModuleVersion = '0.4.0-r8.fixture',
            [string] $PackageSha256 = ('a' * 64),
            [ValidateSet('DryRun','Live')][string] $Execution = 'DryRun'
        )
        [pscustomobject][ordered]@{
            schemaVersion = [int] 1
            execution = $Execution
            moduleVersion = $ModuleVersion
            packageSha256 = $PackageSha256
            authMode = $AuthMode
            state = 'Passed'
            failureStage = 'None'
            failureCode = 'None'
            checks = [pscustomobject][ordered]@{
                packageDigestMatched = $true
                snapshotBound = $true
                archiveValidated = $true
                extractionSealed = $true
                exactImport = $true
                routeMatched = $true
                contextMatched = $Execution -ceq 'Live'
                sourceMatched = $Execution -ceq 'Live'
                tenantProofVerified = $Execution -ceq 'Live'
                cleanupVerified = $true
            }
            adapter = [pscustomobject][ordered]@{
                abiMarkerExact = $true
                contractsDefault = $true
                providerCollectibleNonDefault = $true
                msalVersionExact = $true
                providerMsalSameContext = $true
                publicAbiExact = $true
            }
            read = [pscustomobject][ordered]@{
                operation = 'ManagedDevice.List'
                attempted = $Execution -ceq 'Live'
                succeeded = $Execution -ceq 'Live'
                rowCount = [long]$(if ($Execution -ceq 'Live') { 1 } else { 0 })
            }
            startedUtc = '2026-09-01T12:00:00.0000000Z'
            completedUtc = '2026-09-01T12:00:01.0000000Z'
        }
    }

    function New-Task8FrozenArtifactFixture {
        param(
            [string] $ModuleVersion = '0.4.0-r8.fixture',
            [string] $PackageSha256 = ('a' * 64)
        )
        [pscustomobject][ordered]@{
            schemaVersion = [int] 1
            moduleVersion = $ModuleVersion
            sourceRevision = ('b' * 40)
            packageSha256 = $PackageSha256
            proofSha256 = ('c' * 64)
        }
    }

    function Invoke-Task8PrivateHelper {
        param(
            [Parameter(Mandatory)][string] $FunctionName,
            [hashtable] $Arguments = @{}
        )
        if (-not (Test-Path -LiteralPath $script:runnerPath -PathType Leaf)) {
            throw 'Task 8 private helper implementation is missing.'
        }
        $hooks = [pscustomobject]@{
            ContractMarker = 'GraphKit.Task8.ParityTestHooks/1'
            ExportFunctionsOnly = $true
        }
        [AppDomain]::CurrentDomain.SetData('GraphKit.Task8.ParityTestHooks/1', $hooks)
        try {
            . $script:runnerPath -PackagePath 'unused.nupkg' -PackageSha256 ('a' * 64) `
                -AuthMode Certificate -DryRun
            & $FunctionName @Arguments
        }
        finally {
            [AppDomain]::CurrentDomain.SetData('GraphKit.Task8.ParityTestHooks/1', $null)
        }
    }

    function Assert-Task8VerifiedGetProofControlFlow {
        param([Parameter(Mandatory)][string] $SourceRoot)

        function Get-Task8ParsedFunction {
            param(
                [Parameter(Mandatory)][string] $Path,
                [Parameter(Mandatory)][string] $Name
            )
            $tokens = $null
            $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile(
                $Path, [ref]$tokens, [ref]$errors)
            if (@($errors).Count -ne 0) {
                throw 'A Task 8 proof-control source file did not parse.'
            }
            $functions = @($ast.FindAll({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -ceq $Name
            }, $true))
            if ($functions.Count -ne 1) {
                throw 'A Task 8 proof-control function was not singular.'
            }
            return $functions[0]
        }

        $getObject = Get-Task8ParsedFunction -Path (
            Join-Path $SourceRoot 'Public/Get-GraphObject.ps1') -Name Get-GraphObject
        $transportAssignments = @($getObject.FindAll({
            param($node)
            $node -is [Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
                $node.Left.VariablePath.UserPath -ceq 'transport'
        }, $true))
        $pagingCalls = @($getObject.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -ceq 'Invoke-GraphPaging'
        }, $true))
        if ($transportAssignments.Count -ne 1 -or
            @($transportAssignments[0].FindAll({
                param($node)
                $node -is [Management.Automation.Language.CommandAst] -and
                    $node.GetCommandName() -ceq 'Invoke-GraphRetry'
            }, $true)).Count -ne 1 -or
            $pagingCalls.Count -ne 1 -or
            $pagingCalls[0].Extent.Text -cnotmatch '(?s)-TransportScript\s+\$transport\b') {
            throw 'ManagedDevice.List is not routed through the verified retry transport.'
        }

        $retry = Get-Task8ParsedFunction -Path (
            Join-Path $SourceRoot 'Private/Invoke-GraphRetry.ps1') -Name Invoke-GraphRetry
        $bindingAssignments = @($retry.FindAll({
            param($node)
            $node -is [Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left.Extent.Text -ceq '$requiresTenantBinding'
        }, $true))
        $verifyAssignments = @($retry.FindAll({
            param($node)
            $node -is [Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left.Extent.Text -ceq '$sendParams.VerifyTenantBinding'
        }, $true))
        $sendCalls = @($retry.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and
                $node.Extent.Text -cmatch '^&\s+\$send\s+@sendParams\b'
        }, $true))
        if ($bindingAssignments.Count -ne 1 -or
            $bindingAssignments[0].Extent.Text -cnotmatch
                "IdentityRequirement\s+-ceq\s+'Verified'" -or
            $verifyAssignments.Count -ne 1 -or $sendCalls.Count -ne 1 -or
            $verifyAssignments[0].Extent.StartOffset -le
                $bindingAssignments[0].Extent.StartOffset -or
            $verifyAssignments[0].Extent.EndOffset -ge $sendCalls[0].Extent.StartOffset) {
            throw 'A Verified descriptor is not bound to the sender before invocation.'
        }

        $senderFunction = Get-Task8ParsedFunction -Path (
            Join-Path $SourceRoot 'Private/Transport/Send-GraphHttpRequest.ps1') `
            -Name Send-GraphHttpRequest
        $proofCalls = @($senderFunction.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -ceq 'Confirm-GraphTenantBinding'
        }, $true))
        $physicalSends = @($senderFunction.FindAll({
            param($node)
            $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and
                $node.Member.Extent.Text -ceq 'SendAsync'
        }, $true))
        if ($proofCalls.Count -ne 1 -or $physicalSends.Count -ne 1 -or
            $proofCalls[0].Extent.EndOffset -ge $physicalSends[0].Extent.StartOffset) {
            throw 'Tenant proof is not ordered before the one physical send.'
        }
        $proofGuard = $null
        $ancestor = $proofCalls[0].Parent
        while ($null -ne $ancestor) {
            if ($ancestor -is [Management.Automation.Language.IfStatementAst] -and
                $ancestor.Extent.Text -cmatch '\$VerifyTenantBinding\b') {
                $proofGuard = $ancestor
                break
            }
            $ancestor = $ancestor.Parent
        }
        if ($null -eq $proofGuard) {
            throw 'Tenant proof is not controlled by the verified-send guard.'
        }
        return $true
    }
}

Describe 'Task 8 protected GraphKit.Auth parity runner contract' {
    It 'provides the verification-only runner at the approved literal path' {
        $script:runnerPath | Should -Exist
        $script:workerPath | Should -Exist
    }

    It 'declares the exact public parameter contract and required private helpers' {
        if (-not (Test-Path -LiteralPath $script:runnerPath -PathType Leaf)) {
            throw 'Task 8 runner and private helpers are not implemented.'
        }

        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile(
            $script:runnerPath,
            [ref] $tokens,
            [ref] $errors)
        @($errors).Count | Should -Be 0
        $workerTokens = $null
        $workerErrors = $null
        $workerAst = [Management.Automation.Language.Parser]::ParseFile(
            $script:workerPath,
            [ref] $workerTokens,
            [ref] $workerErrors)
        @($workerErrors).Count | Should -Be 0
        @($workerAst.ParamBlock.Parameters).Count | Should -Be 0

        $workerVersionGuards = @($workerAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.IfStatementAst] -and
                $node.Extent.Text -cmatch 'Get-GraphKitAuthParityFullVersion' -and
                $node.Extent.Text -cmatch '\$request\.moduleVersion\b'
        }, $true))
        $workerImports = @($workerAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -ceq 'Import-Module'
        }, $true))
        $workerVersionGuards.Count | Should -Be 1
        $workerImports.Count | Should -Be 1
        @($workerVersionGuards[0].FindAll({
            param($node)
            $node -is [Management.Automation.Language.BinaryExpressionAst] -and
                $node.Operator -eq [Management.Automation.Language.TokenKind]::Cne
        }, $true)).Count | Should -Be 1
        $workerVersionThrows = @($workerVersionGuards[0].FindAll({
            param($node)
            $node -is [Management.Automation.Language.ThrowStatementAst]
        }, $true))
        $workerVersionThrows.Count | Should -Be 1
        $workerVersionThrows[0].Extent.Text |
            Should -Match 'protected parity worker version was rejected'
        $workerVersionGuards[0].Extent.EndOffset |
            Should -BeLessThan $workerImports[0].Extent.StartOffset

        @($ast.ParamBlock.Parameters.Name.VariablePath.UserPath) -join '|' |
            Should -BeExactly 'PackagePath|PackageSha256|AuthMode|ProfileId|StorePath|DryRun'
        $functionNames = @($ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst]
        }, $true).Name)
        $functionNames | Should -Contain 'New-GraphKitAuthParityRoute'
        $functionNames | Should -Contain 'Test-GraphKitAuthParityEvidence'
        $functionNames | Should -Contain 'Invoke-GraphKitAuthParityLiveCore'
        $functionNames | Should -Contain 'Assert-GraphKitAuthParitySourceBound'
        $functionNames | Should -Contain 'Assert-GraphKitAuthParityProviderWeakReference'
        $functionNames | Should -Contain 'Get-GraphKitAuthParityPublicAbiSha256'

        $runnerText = [IO.File]::ReadAllText($script:runnerPath)
        $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
        . (Join-Path $script:repoRoot 'scripts/private/Test-GraphKitPackagePrivacy.ps1')
        $moduleManifest = Import-PowerShellDataFile -Path (
            Join-Path $script:repoRoot 'source/GraphKit.psd1')
        $allowedGuids = Get-GraphKitPackagePrivacyAllowedGuidSet `
            -ModuleGuid ([guid]$moduleManifest.GUID)
        $privacyFindings = [Collections.Generic.List[object]]::new()
        $privacyKeys = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal)
        foreach ($task8Script in @($script:runnerPath, $script:workerPath)) {
            $task8Bytes = [IO.File]::ReadAllBytes($task8Script)
            $task8Text = $strictUtf8.GetString($task8Bytes)
            if ($task8Text.Length -gt 0) {
                $task8Text[0] | Should -Not -Be ([char]0xFEFF)
            }
            Test-GraphKitPackagePrivacyText -Text $task8Text `
                -EntryName ([IO.Path]::GetRelativePath($script:repoRoot, $task8Script)) `
                -Encoding 'source-strict-utf8' -AllowedGuids $allowedGuids `
                -Findings $privacyFindings -FindingKeys $privacyKeys
        }
        $privacyFindings.Count | Should -Be 0
        $normalizedRunnerText = $runnerText.Replace("`r`n", "`n")
        $embeddedStartToken = "`$helperGzipBase64 = @'`n"
        $embeddedStart = $normalizedRunnerText.IndexOf(
            $embeddedStartToken, [StringComparison]::Ordinal)
        $embeddedStart | Should -BeGreaterOrEqual 0
        $embeddedStart += $embeddedStartToken.Length
        $embeddedEnd = $normalizedRunnerText.IndexOf(
            "`n'@", $embeddedStart, [StringComparison]::Ordinal)
        $embeddedEnd | Should -BeGreaterThan $embeddedStart
        $compressedHelper = [Convert]::FromBase64String(
            ($normalizedRunnerText.Substring($embeddedStart, $embeddedEnd - $embeddedStart) -replace '\s', ''))
        $compressedStream = [IO.MemoryStream]::new($compressedHelper, $false)
        try {
            $gzip = [IO.Compression.GZipStream]::new(
                $compressedStream, [IO.Compression.CompressionMode]::Decompress, $false)
            try {
                $reader = [IO.StreamReader]::new(
                    $gzip, [Text.UTF8Encoding]::new($false, $true), $true, 4096, $false)
                try { $embeddedHelper = $reader.ReadToEnd() }
                finally { $reader.Dispose() }
            }
            finally { $gzip.Dispose() }
        }
        finally { $compressedStream.Dispose() }
        $trackedHelperPath = Join-Path $script:repoRoot 'scripts/private/GraphKit.AuthStageCapture.cs'
        $trackedHelper = [IO.File]::ReadAllText($trackedHelperPath)
        $embeddedHelper | Should -BeExactly $trackedHelper `
            -Because 'the self-contained protected runner helper must be generated from the reviewed tracked source'

        $stateAssignmentIndex = $runnerText.IndexOf(
            '$task8State = [pscustomobject]@{', [StringComparison]::Ordinal)
        $rootPermissionCheckIndex = $runnerText.IndexOf(
            'if (-not $task8Native::HasInitialOwnerOnlyDirectoryAccess($task8RootEvidence))',
            [StringComparison]::Ordinal)
        $stateAssignmentIndex | Should -BeGreaterThan -1
        $rootPermissionCheckIndex | Should -BeGreaterThan $stateAssignmentIndex

        $hookAssignments = @($ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
                $node.Left.VariablePath.UserPath -ceq 'task8Hooks'
        }, $true))
        $hookAssignments.Count | Should -Be 1
        $hookAssignments[0].Extent.Text | Should -Match ([regex]::Escape(
            "if (`$MyInvocation.InvocationName -ceq '.')"))
        $hookCalls = @($ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -ceq 'Get-GraphKitAuthParityTestHooks'
        }, $true))
        $hookCalls.Count | Should -Be 1

        $cleanupFunction = @($ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq 'Remove-GraphKitAuthParityState'
        }, $true))
        $cleanupFunction.Count | Should -Be 1
        $cleanupText = $cleanupFunction[0].Extent.Text
        $directoryEmptyIndex = $cleanupText.IndexOf(
            'if ([IO.Directory]::EnumerateFileSystemEntries($path).GetEnumerator().MoveNext())',
            [StringComparison]::Ordinal)
        $directoryBeforeDeleteIndex = $cleanupText.IndexOf(
            "-Arguments @(`$State, `$relative, 'BeforeDelete', `$native)",
            [StringComparison]::Ordinal)
        $directoryIdentityIndex = $cleanupText.IndexOf(
            '$deleteDirectory = $native::InspectDirectory($State.RootPath, $relative)',
            [StringComparison]::Ordinal)
        $directoryDeleteIndex = $cleanupText.IndexOf(
            '[IO.Directory]::Delete($path, $false)', [StringComparison]::Ordinal)
        $directoryEmptyIndex | Should -BeGreaterOrEqual 0
        $directoryBeforeDeleteIndex | Should -BeGreaterThan $directoryEmptyIndex
        $directoryIdentityIndex | Should -BeGreaterThan $directoryBeforeDeleteIndex
        $directoryDeleteIndex | Should -BeGreaterThan $directoryIdentityIndex

        $hookFunction = @($ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq 'Invoke-GraphKitAuthParityHook'
        }, $true))
        $hookFunction.Count | Should -Be 1
        $hookFunction[0].Extent.Text | Should -Not -Match ([regex]::Escape('return $null'))

        $validationAttributes = @($ast.ParamBlock.Parameters.Attributes | Where-Object {
            $_.TypeName.FullName -in @('ValidateSet','ValidatePattern','ValidateScript')
        })
        $validationAttributes.Count | Should -Be 0
        $ast.ParamBlock.Parameters[0].Attributes.TypeName.FullName | Should -Contain 'Parameter'

        Invoke-Task8PrivateHelper -FunctionName Assert-GraphKitAuthParitySourceBound `
            -Arguments @{ Evidence = [pscustomobject]@{ Length = [long]512MB } } |
            Should -BeTrue
        {
            Invoke-Task8PrivateHelper -FunctionName Assert-GraphKitAuthParitySourceBound `
                -Arguments @{ Evidence = [pscustomobject]@{ Length = [long]512MB + 1 } }
        } | Should -Throw

        $expectedContext = [object]::new()
        $otherContext = [object]::new()
        $weak = [WeakReference]::new($expectedContext)
        Invoke-Task8PrivateHelper -FunctionName Assert-GraphKitAuthParityProviderWeakReference `
            -Arguments @{ WeakReference = $weak; ProviderContext = $expectedContext } |
            Should -BeTrue
        {
            Invoke-Task8PrivateHelper -FunctionName Assert-GraphKitAuthParityProviderWeakReference `
                -Arguments @{ WeakReference = $weak; ProviderContext = $otherContext }
        } | Should -Throw
    }

    It 'contains no provisioning, mutation, installation, Graph SDK, or Azure command in its AST' {
        $forbidden = @(
            'New-Ivy24LabApp','New-ClientServicePrincipalCBA','Register-GraphTenant',
            'Remove-GraphTenant','Set-Secret','Remove-Secret','Register-SecretVault',
            'Unregister-SecretVault','Install-PSResource','Install-Module','Save-Module',
            'Register-PSRepository','Connect-MgGraph','Invoke-MgGraphRequest','Connect-AzAccount',
            'New-MgApplication','Update-MgApplication','Remove-MgApplication',
            'Add-MgApplicationKey','Remove-MgApplicationKey',
            'Add-MgApplicationPassword','Remove-MgApplicationPassword',
            'New-MgServicePrincipal','Update-MgServicePrincipal','Remove-MgServicePrincipal',
            'Add-MgServicePrincipalKey','Remove-MgServicePrincipalKey',
            'Add-MgServicePrincipalPassword','Remove-MgServicePrincipalPassword',
            'New-MgServicePrincipalAppRoleAssignment','Remove-MgServicePrincipalAppRoleAssignment',
            'New-MgServicePrincipalAppRoleAssignedTo','Remove-MgServicePrincipalAppRoleAssignedTo',
            'New-MgOauth2PermissionGrant','Update-MgOauth2PermissionGrant',
            'Remove-MgOauth2PermissionGrant',
            'New-AzResourceGroup','Remove-AzResourceGroup','New-AzUserAssignedIdentity',
            'Remove-AzUserAssignedIdentity','New-AzContainerGroup','Remove-AzContainerGroup','az'
        )
        $commands = foreach ($task8Script in @($script:runnerPath, $script:workerPath)) {
            if (-not (Test-Path -LiteralPath $task8Script -PathType Leaf)) {
                throw 'A Task 8 verifier script AST is not implemented.'
            }
            $tokens = $null
            $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile(
                $task8Script, [ref] $tokens, [ref] $errors)
            @($errors).Count | Should -Be 0
            @($ast.FindAll({
                param($node)
                $node -is [Management.Automation.Language.CommandAst]
            }, $true) | ForEach-Object { $_.GetCommandName() } |
                Where-Object { $null -ne $_ })
        }
        @($commands | Where-Object { $_ -in $forbidden }).Count | Should -Be 0
    }

    It 'requires ManagedDevice.List to explicitly declare <AuthMode> support' -ForEach $task8AuthModes {
        $descriptor = Import-PowerShellDataFile -Path (
            Join-Path $script:repoRoot 'source/Data/Operations/ManagedDevice.List.psd1')
        @($descriptor.SupportedAuthModes) | Should -Contain $AuthMode
    }

    It 'dead-ends uppercase and lowercase proxy variables in every fresh test process' {
        $candidate = Get-Task8PackedCandidate
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate -DryRun `
            -HookKind EnvironmentProbe

        $result.ExitCode | Should -Be 0
        $result.JsonCount | Should -Be 1
        $probes = @(Get-Task8TraceRecords $result.TracePath |
            Where-Object event -eq 'environment-probe')
        $probes.Count | Should -Be 1
        $expected = [ordered]@{
            upperHttp = 'http://127.0.0.1:1'
            upperHttps = 'http://127.0.0.1:1'
            upperAll = 'http://127.0.0.1:1'
            upperNo = 'localhost,127.0.0.1'
            lowerHttp = 'http://127.0.0.1:1'
            lowerHttps = 'http://127.0.0.1:1'
            lowerAll = 'http://127.0.0.1:1'
            lowerNo = 'localhost,127.0.0.1'
        }
        foreach ($entry in $expected.GetEnumerator()) {
            $probes[0].data.($entry.Key) | Should -BeExactly $entry.Value
        }
    }
}

Describe 'Task 8 canonical GraphKit.Auth ABI gate' -Tag 'Task8Abi' {
    BeforeAll {
        function New-Task8AbiProbeAssembly {
            param(
                [string] $Name = 'GraphKit.Task8.AbiProbe',
                [version] $Version = [version]'1.0.0.0',
                [Parameter(Mandatory)][string] $InformationalVersion,
                [ValidateSet('Int32','Byte')][string] $EnumUnderlyingType = 'Int32',
                [ValidateSet('NotNull','Nullable')][string] $StringNullability = 'NotNull',
                [switch] $AddPublicMethod
            )

            $assemblyName = [Reflection.AssemblyName]::new($Name)
            $assemblyName.Version = $Version
            $assembly = [Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly(
                $assemblyName,
                [Reflection.Emit.AssemblyBuilderAccess]::RunAndCollect)
            $attributeConstructor = [Reflection.AssemblyInformationalVersionAttribute].GetConstructor(
                [type[]]@([string]))
            $assembly.SetCustomAttribute([Reflection.Emit.CustomAttributeBuilder]::new(
                $attributeConstructor,
                [object[]]@($InformationalVersion)))
            $module = $assembly.DefineDynamicModule($Name)
            $type = $module.DefineType(
                'GraphKit.Task8.AbiProbe',
                [Reflection.TypeAttributes]'Public,Sealed,Class')
            $null = $type.DefineDefaultConstructor([Reflection.MethodAttributes]::Public)

            $property = $type.DefineProperty(
                'DisplayName',
                [Reflection.PropertyAttributes]::None,
                [string],
                [type[]]@())
            $nullableAttribute = [Type]::GetType(
                'System.Runtime.CompilerServices.NullableAttribute, System.Private.CoreLib',
                $true)
            $nullableConstructor = $nullableAttribute.GetConstructor([type[]]@([byte]))
            $nullableFlag = [byte]$(if ($StringNullability -ceq 'Nullable') { 2 } else { 1 })
            $property.SetCustomAttribute([Reflection.Emit.CustomAttributeBuilder]::new(
                $nullableConstructor,
                [object[]]@($nullableFlag)))
            $getter = $type.DefineMethod(
                'get_DisplayName',
                [Reflection.MethodAttributes]'Public,SpecialName,HideBySig',
                [string],
                [type[]]@())
            $getterIl = $getter.GetILGenerator()
            $getterIl.Emit([Reflection.Emit.OpCodes]::Ldnull)
            $getterIl.Emit([Reflection.Emit.OpCodes]::Ret)
            $property.SetGetMethod($getter)

            if ($AddPublicMethod) {
                $method = $type.DefineMethod(
                    'AddedPublicMethod',
                    [Reflection.MethodAttributes]'Public,HideBySig',
                    [void],
                    [type[]]@())
                $method.GetILGenerator().Emit([Reflection.Emit.OpCodes]::Ret)
            }
            $null = $type.CreateType()

            $underlyingType = if ($EnumUnderlyingType -ceq 'Byte') { [byte] } else { [int] }
            $enum = $module.DefineEnum(
                'GraphKit.Task8.AbiProbeMode',
                [Reflection.TypeAttributes]::Public,
                $underlyingType)
            $firstValue = if ($EnumUnderlyingType -ceq 'Byte') { [byte]0 } else { [int]0 }
            $secondValue = if ($EnumUnderlyingType -ceq 'Byte') { [byte]1 } else { [int]1 }
            $null = $enum.DefineLiteral('First', $firstValue)
            $null = $enum.DefineLiteral('Second', $secondValue)
            $null = $enum.CreateType()
            return $assembly
        }

        function Get-Task8AbiProbeHash {
            param([Parameter(Mandatory)][Reflection.Assembly] $Assembly)
            Invoke-Task8PrivateHelper `
                -FunctionName Get-GraphKitAuthParityPublicAbiSha256 `
                -Arguments @{ Assembly = $Assembly }
        }
    }

    It 'projects the exact 161-record Task 7 contract surface and expected digest' {
        $sourceManifest = Import-PowerShellDataFile -Path (
            Join-Path $script:repoRoot 'source/GraphKit.psd1')
        $contractsPath = Join-Path $script:repoRoot (
            'output/module/GraphKit/{0}/Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll' -f
                [string] $sourceManifest.ModuleVersion)
        $contractsPath | Should -Exist
        $assembly = [Reflection.Assembly]::LoadFile(
            (Resolve-Path -LiteralPath $contractsPath).ProviderPath)

        $records = @(Invoke-Task8PrivateHelper `
            -FunctionName Get-GraphKitAuthParityPublicAbiRecords `
            -Arguments @{ Assembly = $assembly })
        $hash = Get-Task8AbiProbeHash -Assembly $assembly

        $records.Count | Should -Be 161
        $hash | Should -BeExactly '5b808693dfcd58c1b8b8a093caa789d8b5f9ce87f1bc57c6a1d8628077efc1f1'
    }

    It 'ignores informational version while retaining the same assembly name and version' {
        $first = New-Task8AbiProbeAssembly -InformationalVersion '1.0.0+first-commit'
        $second = New-Task8AbiProbeAssembly -InformationalVersion '1.0.0+second-commit'

        $firstHash = Get-Task8AbiProbeHash -Assembly $first
        $secondHash = Get-Task8AbiProbeHash -Assembly $second

        $firstHash | Should -Match '^[0-9a-f]{64}$'
        $secondHash | Should -BeExactly $firstHash `
            -Because 'commit-bearing informational metadata is outside the public ABI'
    }

    It 'changes the canonical hash when a public method is added' {
        $baseline = New-Task8AbiProbeAssembly -InformationalVersion '1.0.0+baseline'
        $changed = New-Task8AbiProbeAssembly -InformationalVersion '1.0.0+method' `
            -AddPublicMethod

        (Get-Task8AbiProbeHash -Assembly $changed) | Should -Not -BeExactly (
            Get-Task8AbiProbeHash -Assembly $baseline)
    }

    It 'changes the canonical hash when an enum underlying type changes' {
        $baseline = New-Task8AbiProbeAssembly -InformationalVersion '1.0.0+enum-int'
        $changed = New-Task8AbiProbeAssembly -InformationalVersion '1.0.0+enum-byte' `
            -EnumUnderlyingType Byte

        (Get-Task8AbiProbeHash -Assembly $changed) | Should -Not -BeExactly (
            Get-Task8AbiProbeHash -Assembly $baseline)
    }

    It 'changes the canonical hash when public member nullability changes' {
        $baseline = New-Task8AbiProbeAssembly -InformationalVersion '1.0.0+not-null'
        $changed = New-Task8AbiProbeAssembly -InformationalVersion '1.0.0+nullable' `
            -StringNullability Nullable

        (Get-Task8AbiProbeHash -Assembly $changed) | Should -Not -BeExactly (
            Get-Task8AbiProbeHash -Assembly $baseline)
    }

    It 'accepts only the exact neutral unsigned GraphKit.Auth.Contracts assembly identity' {
        $expected = [Reflection.AssemblyName]::new(
            'GraphKit.Auth.Contracts, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null')
        Invoke-Task8PrivateHelper `
            -FunctionName Test-GraphKitAuthParityContractsIdentity `
            -Arguments @{ Name = $expected } | Should -BeTrue

        $changedIdentities = @(
            [Reflection.AssemblyName]::new(
                'GraphKit.Auth.Contracts.Changed, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null')
            [Reflection.AssemblyName]::new(
                'GraphKit.Auth.Contracts, Version=1.0.0.1, Culture=neutral, PublicKeyToken=null')
            [Reflection.AssemblyName]::new(
                'GraphKit.Auth.Contracts, Version=1.0.0.0, Culture=en-US, PublicKeyToken=null')
            [Reflection.AssemblyName]::new(
                'GraphKit.Auth.Contracts, Version=1.0.0.0, Culture=neutral, PublicKeyToken=0011223344556677')
        )
        foreach ($identity in $changedIdentities) {
            Invoke-Task8PrivateHelper `
                -FunctionName Test-GraphKitAuthParityContractsIdentity `
                -Arguments @{ Name = $identity } | Should -BeFalse
        }
    }
}

Describe 'Task 8 guarded parameter and package binding' {
    It 'maps a missing package to one fixed artifact failure before extraction' {
        $missing = Join-Path $TestDrive 'missing.nupkg'
        $result = Invoke-Task8RunnerProcess -PackagePath $missing -PackageSha256 ('a' * 64) `
            -AuthMode Certificate -DryRun

        Assert-Task8SafeFailure -Invocation $result -Stage Artifact -Code ArtifactRejected
        @((Get-Task8TraceRecords $result.TracePath) | Where-Object event -eq 'root-created').Count |
            Should -Be 0
    }

    It 'maps an existing non-nupkg file to one fixed artifact failure before extraction' {
        $path = Join-Path $TestDrive 'candidate.zip'
        [IO.File]::WriteAllText($path, 'task8 fixture')
        $sha = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        $result = Invoke-Task8RunnerProcess -PackagePath $path -PackageSha256 $sha `
            -AuthMode Certificate -DryRun

        Assert-Task8SafeFailure -Invocation $result -Stage Artifact -Code ArtifactRejected
        @((Get-Task8TraceRecords $result.TracePath) | Where-Object event -eq 'root-created').Count |
            Should -Be 0

        $oversized = Join-Path $TestDrive 'oversized-source.nupkg'
        New-Task8SparseFile -Path $oversized -Length ([long]512MB + 1)
        $oversizedResult = Invoke-Task8RunnerProcess -PackagePath $oversized `
            -PackageSha256 ('a' * 64) -AuthMode Certificate -DryRun -HookKind OversizedSource
        Assert-Task8SafeFailure -Invocation $oversizedResult -Stage Artifact -Code ArtifactRejected
        $trace = Get-Task8TraceRecords $oversizedResult.TracePath
        @($trace | Where-Object event -eq 'source-metadata-started').Count | Should -Be 1
        @($trace | Where-Object event -eq 'source-hash-started').Count | Should -Be 0
        foreach ($eventName in @('root-created','snapshot-created','extraction-created')) {
            @($trace | Where-Object event -eq $eventName).Count | Should -Be 0
        }
    }

    It 'does not leak a malformed digest sentinel through any fresh-process stream' {
        $fixture = New-Task8FixturePackage -Name 'malformed-digest'
        $sentinel = 'task8-secret-sentinel-digest'
        $result = Invoke-Task8RunnerProcess -PackagePath $fixture -PackageSha256 $sentinel `
            -AuthMode Certificate -DryRun

        Assert-Task8SafeFailure -Invocation $result -Stage Artifact -Code ArtifactRejected
        $result.Output | Should -Not -Match ([regex]::Escape($sentinel))
        @((Get-Task8TraceRecords $result.TracePath) | Where-Object event -eq 'root-created').Count |
            Should -Be 0
    }

    It 'rejects a digest mismatch before archive extraction and never reports the unbound digest' {
        $fixture = New-Task8FixturePackage -Name 'digest-mismatch'
        $result = Invoke-Task8RunnerProcess -PackagePath $fixture -PackageSha256 ('b' * 64) `
            -AuthMode Certificate -DryRun

        Assert-Task8SafeFailure -Invocation $result -Stage Artifact -Code ArtifactRejected
        @((Get-Task8TraceRecords $result.TracePath) | Where-Object event -eq 'extraction-created').Count |
            Should -Be 0
    }

    It 'does not leak an invalid auth-mode sentinel through any fresh-process stream' {
        $fixture = New-Task8FixturePackage -Name 'invalid-mode'
        $sha = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant()
        $sentinel = 'task8-secret-sentinel-mode'
        $result = Invoke-Task8RunnerProcess -PackagePath $fixture -PackageSha256 $sha `
            -AuthMode $sentinel -DryRun

        Assert-Task8SafeFailure -Invocation $result -Stage Artifact -Code ArtifactRejected
        $result.Output | Should -Not -Match ([regex]::Escape($sentinel))
        @((Get-Task8TraceRecords $result.TracePath) | Where-Object event -eq 'root-created').Count |
            Should -Be 0
    }

    It 'does not leak an invalid live profile identifier through any fresh-process stream' {
        $fixture = New-Task8FixturePackage -Name 'invalid-profile'
        $sha = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant()
        $sentinel = 'task8-secret-sentinel/profile'
        $result = Invoke-Task8RunnerProcess -PackagePath $fixture -PackageSha256 $sha `
            -AuthMode Certificate -ProfileId $sentinel

        Assert-Task8SafeFailure -Invocation $result -Stage Artifact -Code ArtifactRejected
        $result.Data.execution | Should -BeExactly 'Live'
        $result.Output | Should -Not -Match ([regex]::Escape($sentinel))
        @((Get-Task8TraceRecords $result.TracePath) | Where-Object event -eq 'root-created').Count |
            Should -Be 0
    }
}

Describe 'Task 8 archive validation and resource bounds' {
    It 'rejects unsafe archive path <Kind> before extraction' -ForEach $task8UnsafeArchiveCases {
        $fixture = New-Task8FixturePackage -Name ("unsafe-" + [guid]::NewGuid().ToString('N')) `
            -Entries @(
                @{
                    Path = 'GraphKit.psd1'
                    Content = "@{ RootModule = 'GraphKit.psm1'; ModuleVersion = '0.4.0'; PrivateData = @{ PSData = @{ Prerelease = 'r8.fixture' } } }"
                }
                @{ Path = 'GraphKit.psm1'; Content = '# valid Task 8 fixture module' }
                @{ Path = $EntryName; Content = 'unsafe' }
            )
        $sha = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant()
        $result = Invoke-Task8RunnerProcess -PackagePath $fixture -PackageSha256 $sha `
            -AuthMode Certificate -DryRun

        Assert-Task8SafeFailure -Invocation $result -Stage Artifact -Code ArtifactRejected `
            -AuthMode Certificate -PackageSha256 $sha
        $trace = Get-Task8TraceRecords $result.TracePath
        @($trace | Where-Object event -eq 'archive-plan-created').Count | Should -Be 0
        @($trace | Where-Object event -eq 'extraction-created').Count | Should -Be 0
    }

    It 'rejects non-portable archive segment <Kind> before extraction' `
        -ForEach $task8PortableArchiveSegmentCases {
        $fixture = New-Task8FixturePackage -Name (
            'portable-segment-' + [guid]::NewGuid().ToString('N')) -Entries @(
                @{
                    Path = 'GraphKit.psd1'
                    Content = "@{ RootModule = 'GraphKit.psm1'; ModuleVersion = '0.4.0'; PrivateData = @{ PSData = @{ Prerelease = 'r8.fixture' } } }"
                }
                @{ Path = 'GraphKit.psm1'; Content = '' }
                @{ Path = $EntryName; Content = 'must-not-extract' }
            )
        $sha = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant()
        $result = Invoke-Task8RunnerProcess -PackagePath $fixture -PackageSha256 $sha `
            -AuthMode Certificate -DryRun

        Assert-Task8SafeFailure -Invocation $result -Stage Artifact -Code ArtifactRejected `
            -AuthMode Certificate -PackageSha256 $sha
        $trace = Get-Task8TraceRecords $result.TracePath
        @($trace | Where-Object event -eq 'archive-plan-created').Count | Should -Be 0
        @($trace | Where-Object event -eq 'extraction-created').Count | Should -Be 0
    }

    It 'rejects archive <Kind> aliases ordinally and portably' -ForEach $task8ArchiveAliasCases {
        $fixture = New-Task8FixturePackage -Name ("alias-" + [guid]::NewGuid().ToString('N')) `
            -Entries @(
                @{
                    Path = 'GraphKit.psd1'
                    Content = "@{ RootModule = 'GraphKit.psm1'; ModuleVersion = '0.4.0'; PrivateData = @{ PSData = @{ Prerelease = 'r8.fixture' } } }"
                }
                @{ Path = 'GraphKit.psm1'; Content = '# valid Task 8 fixture module' }
                @{ Path = $First; Content = 'first' }
                @{ Path = $Second; Content = 'second' }
            )
        $sha = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant()
        $result = Invoke-Task8RunnerProcess -PackagePath $fixture -PackageSha256 $sha `
            -AuthMode Certificate -DryRun

        Assert-Task8SafeFailure -Invocation $result -Stage Artifact -Code ArtifactRejected `
            -AuthMode Certificate -PackageSha256 $sha
        $trace = Get-Task8TraceRecords $result.TracePath
        @($trace | Where-Object event -eq 'archive-plan-created').Count | Should -Be 0
        @($trace | Where-Object event -eq 'extraction-created').Count | Should -Be 0
    }

    It 'rejects a ZIP entry encoded as <Kind>' -ForEach $task8ArchiveLinkCases {
        $fixture = New-Task8FixturePackage -Name ("link-" + [guid]::NewGuid().ToString('N')) `
            -Entries @(
                @{
                    Path = 'GraphKit.psd1'
                    Content = "@{ RootModule = 'GraphKit.psm1'; ModuleVersion = '0.4.0'; PrivateData = @{ PSData = @{ Prerelease = 'r8.fixture' } } }"
                    ExternalAttributes = $ExternalAttributes
                }
                @{ Path = 'GraphKit.psm1'; Content = '# valid Task 8 fixture module' }
            )
        $sha = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant()
        $result = Invoke-Task8RunnerProcess -PackagePath $fixture -PackageSha256 $sha `
            -AuthMode Certificate -DryRun

        Assert-Task8SafeFailure -Invocation $result -Stage Artifact -Code ArtifactRejected `
            -AuthMode Certificate -PackageSha256 $sha
        $trace = Get-Task8TraceRecords $result.TracePath
        @($trace | Where-Object event -eq 'archive-plan-created').Count | Should -Be 0
        @($trace | Where-Object event -eq 'extraction-created').Count | Should -Be 0
    }

    It 'rejects a high-ratio compressed entry before allocating its declared expansion' {
        $fixture = New-Task8FixturePackage -Name 'ratio-bomb' -Entries @(
            @{
                Path = 'GraphKit.psd1'
                Content = "@{ RootModule = 'GraphKit.psm1'; ModuleVersion = '0.4.0'; PrivateData = @{ PSData = @{ Prerelease = 'r8.fixture' } } }"
            }
            @{ Path = 'GraphKit.psm1'; Content = '# valid Task 8 fixture module' }
            @{ Path = 'Data/ratio.bin'; Content = [byte[]]::new(2MB) }
        )
        $sha = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant()
        $result = Invoke-Task8RunnerProcess -PackagePath $fixture -PackageSha256 $sha `
            -AuthMode Certificate -DryRun

        Assert-Task8SafeFailure -Invocation $result -Stage Artifact -Code ArtifactRejected `
            -AuthMode Certificate -PackageSha256 $sha
        $trace = Get-Task8TraceRecords $result.TracePath
        @($trace | Where-Object event -eq 'archive-plan-created').Count | Should -Be 0
        @($trace | Where-Object event -eq 'extraction-created').Count | Should -Be 0
    }

    It 'rejects an archive whose entry count exceeds the protected-host bound' {
        $entries = [Collections.Generic.List[object]]::new()
        $entries.Add(@{
            Path = 'GraphKit.psd1'
            Content = "@{ RootModule = 'GraphKit.psm1'; ModuleVersion = '0.4.0'; PrivateData = @{ PSData = @{ Prerelease = 'r8.fixture' } } }"
        })
        $entries.Add(@{ Path = 'GraphKit.psm1'; Content = '# valid Task 8 fixture module' })
        for ($index = 0; $index -lt 4097; $index++) {
            $entries.Add(@{ Path = "Data/entry-$index.txt"; Content = '' })
        }
        $fixture = New-Task8FixturePackage -Name 'entry-count-bomb' -Entries $entries.ToArray()
        $sha = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant()
        $result = Invoke-Task8RunnerProcess -PackagePath $fixture -PackageSha256 $sha `
            -AuthMode Certificate -DryRun

        Assert-Task8SafeFailure -Invocation $result -Stage Artifact -Code ArtifactRejected `
            -AuthMode Certificate -PackageSha256 $sha
        $trace = Get-Task8TraceRecords $result.TracePath
        @($trace | Where-Object event -eq 'archive-plan-created').Count | Should -Be 0
        @($trace | Where-Object event -eq 'extraction-created').Count | Should -Be 0
    }

    It 'rejects a source package symbolic link or reparse alias without following it' {
        $target = New-Task8FixturePackage -Name 'source-target'
        $alias = Join-Path $TestDrive 'source-alias.nupkg'
        $null = New-Item -ItemType SymbolicLink -Path $alias -Target $target -ErrorAction Stop
        $sha = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
        $result = Invoke-Task8RunnerProcess -PackagePath $alias -PackageSha256 $sha `
            -AuthMode Certificate -DryRun

        Assert-Task8SafeFailure -Invocation $result -Stage Artifact -Code ArtifactRejected
        (Test-Path -LiteralPath $target -PathType Leaf) | Should -BeTrue
        $trace = Get-Task8TraceRecords $result.TracePath
        @($trace | Where-Object event -eq 'root-created').Count | Should -Be 0
        @($trace | Where-Object event -eq 'snapshot-created').Count | Should -Be 0
    }

    It 'uses create-new semantics for the package snapshot destination' {
        $fixture = New-Task8FixturePackage -Name 'snapshot-collision'
        $sha = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant()
        $result = Invoke-Task8RunnerProcess -PackagePath $fixture -PackageSha256 $sha `
            -AuthMode Certificate -DryRun -HookKind SnapshotCollision
        $root = [string]((Get-Task8TraceRecords $result.TracePath |
            Where-Object event -eq 'root-created').data.root)
        try {
            Assert-Task8SafeFailure -Invocation $result -Stage Cleanup -Code CleanupFailed `
                -AuthMode Certificate -PackageSha256 ('0' * 64)
        }
        finally { Remove-Task8ResidualFixturePath -Path $root }
    }

    It 'rejects same-identity snapshot bytes changed to a different valid package before archive planning' {
        $fixtureEntries = @(
            @{
                Path = 'GraphKit.psd1'
                Content = "@{ RootModule = 'GraphKit.psm1'; ModuleVersion = '0.4.0'; PrivateData = @{ PSData = @{ Prerelease = 'r8.fixture' } } }"
            }
            @{ Path = 'GraphKit.psm1'; Content = '# snapshot package A' }
        )
        $replacementEntries = @(
            $fixtureEntries[0]
            @{ Path = 'GraphKit.psm1'; Content = '# snapshot package B' }
        )
        $fixture = New-Task8FixturePackage -Name 'snapshot-original' `
            -Entries $fixtureEntries -CompressionLevel NoCompression
        $replacement = New-Task8FixturePackage -Name 'snapshot-replacement' `
            -Entries $replacementEntries -CompressionLevel NoCompression
        $sha = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant()
        $replacementSha = (Get-FileHash -LiteralPath $replacement -Algorithm SHA256).
            Hash.ToLowerInvariant()
        $replacementSha | Should -Not -BeExactly $sha
        (Get-Item -LiteralPath $replacement).Length |
            Should -Be (Get-Item -LiteralPath $fixture).Length

        $result = Invoke-Task8RunnerProcess -PackagePath $fixture -PackageSha256 $sha `
            -AuthMode Certificate -DryRun -HookKind SnapshotContentMutation `
            -MutationValue $replacement
        $trace = Get-Task8TraceRecords $result.TracePath
        $root = [string]($trace | Where-Object event -eq 'root-created').data.root
        $snapshot = [string]($trace | Where-Object event -eq 'snapshot-created').data.snapshot
        try {
            Assert-Task8SafeFailure -Invocation $result -Stage Cleanup -Code CleanupFailed `
                -PackageSha256 $sha
            @($trace | Where-Object event -eq 'snapshot-mutated').Count | Should -Be 1
            @($trace | Where-Object event -eq 'archive-plan-created').Count | Should -Be 0
            @($trace | Where-Object event -eq 'extraction-created').Count | Should -Be 0
            @($trace | Where-Object event -eq 'imported').Count | Should -Be 0
            (Test-Path -LiteralPath $root -PathType Container) | Should -BeTrue
            (Test-Path -LiteralPath $snapshot -PathType Leaf) | Should -BeTrue
            (Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash.ToLowerInvariant() |
                Should -BeExactly $replacementSha
        }
        finally { Remove-Task8ResidualFixturePath -Path $root }
    }
}

Describe 'Task 8 isolated import, routing, and cleanup' {
    It 'rejects <Kind> replacement during the writable extraction window before adoption' `
        -ForEach $task8PreSealMutationCases {
        $fixture = New-Task8FixturePackage -Name (
            'preseal-' + $HookKind.ToLowerInvariant() + '-' + [guid]::NewGuid().ToString('N'))
        $sha = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant()
        $result = Invoke-Task8RunnerProcess -PackagePath $fixture -PackageSha256 $sha `
            -AuthMode Certificate -DryRun -HookKind $HookKind
        $trace = Get-Task8TraceRecords $result.TracePath
        $root = [string]($trace | Where-Object event -eq 'root-created').data.root
        $mutations = @($trace | Where-Object event -eq 'preseal-mutated')
        $outside = if ($mutations.Count -eq 1) {
            [string]$mutations[0].data.outside
        }
        else { $null }
        try {
            Assert-Task8SafeFailure -Invocation $result -Stage Cleanup -Code CleanupFailed `
                -PackageSha256 $sha
            $mutations.Count | Should -Be 1
            $mutations[0].data.root | Should -BeExactly $root
            if ($HookKind -ceq 'PreSealFileMutation') {
                $mutations[0].data.relative | Should -BeExactly 'module/GraphKit.psd1'
                $mutations[0].data.laterFileExists | Should -BeFalse
            }
            @($trace | Where-Object event -eq 'archive-plan-created').Count | Should -Be 1
            @($trace | Where-Object event -eq 'extraction-created').Count | Should -Be 0
            @($trace | Where-Object event -eq 'imported').Count | Should -Be 0
            (Test-Path -LiteralPath $root -PathType Container) | Should -BeTrue
            if ($HasOutside) {
                [string]::IsNullOrWhiteSpace($outside) | Should -BeFalse
                (Test-Path -LiteralPath $outside -PathType Container) | Should -BeTrue
            }
            else {
                [string]::IsNullOrEmpty($outside) | Should -BeTrue
            }
        }
        finally {
            Remove-Task8ResidualFixturePath -Path $root
            Remove-Task8ResidualFixturePath -Path $outside
        }
        if ($HasOutside) {
            (Test-Path -LiteralPath $outside) | Should -BeFalse
        }
    }

    It 'runs the exact protected DryRun route for <AuthMode> without an external seam' -ForEach $task8AuthModes {
        $candidate = Get-Task8PackedCandidate
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode $AuthMode -DryRun `
            -HookKind ExternalSeams

        $result.ExitCode | Should -Be 0
        $result.JsonCount | Should -Be 1
        $result.StdErr | Should -BeNullOrEmpty
        Assert-Task8ModeRecordShape -Record $result.Data -Execution DryRun `
            -AuthMode $AuthMode -PackageSha256 $candidate.PackageSha256
        $result.Data.state | Should -BeExactly 'Passed'
        $result.Data.failureStage | Should -BeExactly 'None'
        $result.Data.failureCode | Should -BeExactly 'None'
        $result.Data.moduleVersion | Should -BeExactly $candidate.FullVersion
        foreach ($name in @(
            'packageDigestMatched','snapshotBound','archiveValidated','extractionSealed',
            'exactImport','routeMatched','cleanupVerified'
        )) {
            $result.Data.checks.$name | Should -BeTrue
        }
        foreach ($name in @('contextMatched','sourceMatched','tenantProofVerified')) {
            $result.Data.checks.$name | Should -BeFalse
        }
        @($result.Data.adapter.PSObject.Properties.Value | Where-Object { -not $_ }).Count |
            Should -Be 0
        $result.Data.read.attempted | Should -BeFalse
        $result.Data.read.succeeded | Should -BeFalse
        $result.Data.read.rowCount | Should -Be 0
        @((Get-Task8TraceRecords $result.TracePath) | Where-Object event -eq 'forbidden-seam').Count |
            Should -Be 0
        $result.Output | Should -Not -Match ([regex]::Escape($script:repoRoot))
        $result.Output | Should -Not -Match ([regex]::Escape($TestDrive))
    }

    It 'refuses an already loaded GraphKit module without removing the caller-owned module' {
        $candidate = Get-Task8PackedCandidate
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate -DryRun `
            -HookKind PreloadedGraphKit

        Assert-Task8SafeFailure -Invocation $result -Stage Import -Code ImportRejected
        $trace = Get-Task8TraceRecords $result.TracePath
        @($trace | Where-Object event -eq 'root-created').Count | Should -Be 0
        ($trace | Where-Object event -eq 'wrapper-finished').data.preloadedStillLoaded |
            Should -BeTrue
    }

    It 'rejects an extracted-file digest mutation at the immediate pre-import recheck' {
        $candidate = Get-Task8PackedCandidate
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate -DryRun `
            -HookKind ExtractedMutation
        $root = [string]((Get-Task8TraceRecords $result.TracePath |
            Where-Object event -eq 'root-created').data.root)
        try {
            Assert-Task8SafeFailure -Invocation $result -Stage Cleanup -Code CleanupFailed `
                -PackageSha256 $candidate.PackageSha256
            (Test-Path -LiteralPath $root -PathType Container) | Should -BeTrue
        }
        finally { Remove-Task8ResidualFixturePath -Path $root }

        foreach ($hookKind in @(
            'FinalImportContentMutation','FinalImportWritableMutation',
            'FinalImportClosureMutation','FinalImportHardLinkMutation'
        )) {
            $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
                -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate -DryRun `
                -HookKind $hookKind
            $trace = Get-Task8TraceRecords $result.TracePath
            $root = [string]($trace | Where-Object event -eq 'root-created').data.root
            $outsideRecords = @($trace | Where-Object event -eq 'mutation-outside-created')
            $outsideRecords.Count | Should -Be $(if (
                $hookKind -ceq 'FinalImportHardLinkMutation') { 1 } else { 0 })
            $outside = if ($outsideRecords.Count -eq 1) {
                [string]$outsideRecords[0].data.path
            }
            else { $null }
            try {
                Assert-Task8SafeFailure -Invocation $result -Stage Cleanup -Code CleanupFailed `
                    -PackageSha256 $candidate.PackageSha256
                @($trace | Where-Object event -eq 'final-import-mutated').Count | Should -Be 1
                @($trace | Where-Object event -eq 'imported').Count | Should -Be 0
                (Test-Path -LiteralPath $root -PathType Container) | Should -BeTrue
            }
            finally {
                Remove-Task8ResidualFixturePath -Path $root
                Remove-Task8ResidualFixturePath -Path $outside
            }
            if ($null -ne $outside) {
                (Test-Path -LiteralPath $outside) | Should -BeFalse
            }
        }
    }

    It 'rejects writable extracted content at the immediate pre-import recheck' {
        $candidate = Get-Task8PackedCandidate
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate -DryRun `
            -HookKind ExtractedWritable
        $root = [string]((Get-Task8TraceRecords $result.TracePath |
            Where-Object event -eq 'root-created').data.root)
        try {
            Assert-Task8SafeFailure -Invocation $result -Stage Cleanup -Code CleanupFailed `
                -PackageSha256 $candidate.PackageSha256
            (Test-Path -LiteralPath $root -PathType Container) | Should -BeTrue
        }
        finally { Remove-Task8ResidualFixturePath -Path $root }

        foreach ($hookKind in @(
            'CleanupContentMutation','CleanupWritableMutation',
            'CleanupClosureMutation','CleanupHardLinkMutation'
        )) {
            $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
                -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate -DryRun `
                -HookKind $hookKind
            $trace = Get-Task8TraceRecords $result.TracePath
            $root = [string]($trace | Where-Object event -eq 'root-created').data.root
            $outsideRecords = @($trace | Where-Object event -eq 'mutation-outside-created')
            $outsideRecords.Count | Should -Be $(if (
                $hookKind -ceq 'CleanupHardLinkMutation') { 1 } else { 0 })
            $outside = if ($outsideRecords.Count -eq 1) {
                [string]$outsideRecords[0].data.path
            }
            else { $null }
            try {
                Assert-Task8SafeFailure -Invocation $result -Stage Cleanup -Code CleanupFailed `
                    -PackageSha256 $candidate.PackageSha256
                @($trace | Where-Object event -eq 'cleanup-mutated').Count | Should -Be 1
                @($trace | Where-Object event -eq 'imported').Count | Should -Be 1
                (Test-Path -LiteralPath $root -PathType Container) | Should -BeTrue
            }
            finally {
                Remove-Task8ResidualFixturePath -Path $root
                Remove-Task8ResidualFixturePath -Path $outside
            }
            if ($null -ne $outside) {
                (Test-Path -LiteralPath $outside) | Should -BeFalse
            }
        }
    }

    It 'refuses same-identity per-file cleanup mutation <Kind> and preserves the root' `
        -ForEach $task8CleanupFileMutationCases {
        $candidate = Get-Task8PackedCandidate
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate -DryRun `
            -HookKind $HookKind
        $trace = Get-Task8TraceRecords $result.TracePath
        $root = [string]($trace | Where-Object event -eq 'root-created').data.root
        try {
            Assert-Task8SafeFailure -Invocation $result -Stage Cleanup -Code CleanupFailed `
                -PackageSha256 $candidate.PackageSha256
            $mutations = @($trace | Where-Object event -eq 'cleanup-file-mutated')
            $mutations.Count | Should -Be 1
            $mutations[0].data.root | Should -BeExactly $root
            $mutations[0].data.relative | Should -BeExactly 'module/GraphKit.psm1'
            (Test-Path -LiteralPath $root -PathType Container) | Should -BeTrue
            (Test-Path -LiteralPath (Join-Path $root 'module/GraphKit.psm1') -PathType Leaf) |
                Should -BeTrue
        }
        finally { Remove-Task8ResidualFixturePath -Path $root }
    }

    It 'refuses <Kind> and preserves both ambiguous container identities' `
        -ForEach $task8CleanupContainerMutationCases {
        $fixture = New-Task8FixturePackage -Name (
            'cleanup-container-' + $HookKind.ToLowerInvariant() + '-' +
            [guid]::NewGuid().ToString('N'))
        $sha = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant()
        $result = Invoke-Task8RunnerProcess -PackagePath $fixture -PackageSha256 $sha `
            -AuthMode Certificate -DryRun -HookKind $HookKind
        $trace = Get-Task8TraceRecords $result.TracePath
        $root = [string]($trace | Where-Object event -eq 'root-created').data.root
        $mutations = @($trace | Where-Object event -eq 'cleanup-container-mutated')
        $outside = if ($mutations.Count -eq 1) {
            [string]$mutations[0].data.outside
        }
        else { $null }
        try {
            Assert-Task8SafeFailure -Invocation $result -Stage Cleanup -Code CleanupFailed `
                -PackageSha256 $sha
            $mutations.Count | Should -Be 1
            $mutations[0].data.phase | Should -BeExactly $Phase
            $mutations[0].data.relative | Should -BeExactly $Relative
            $mutations[0].data.root | Should -BeExactly $root
            [string]::IsNullOrWhiteSpace($outside) | Should -BeFalse
            (Test-Path -LiteralPath $root -PathType Container) | Should -BeTrue
            (Test-Path -LiteralPath $outside -PathType Container) | Should -BeTrue
            if ($Relative -ceq 'module') {
                (Test-Path -LiteralPath (Join-Path $root 'module') -PathType Container) |
                    Should -BeTrue
            }
            if ($Phase -ceq 'AfterWritable') {
                (Test-Path -LiteralPath (Join-Path $root 'module/GraphKit.psm1') -PathType Leaf) |
                    Should -BeTrue
            }
        }
        finally {
            Remove-Task8ResidualFixturePath -Path $root
            Remove-Task8ResidualFixturePath -Path $outside
        }
        (Test-Path -LiteralPath $root) | Should -BeFalse
        (Test-Path -LiteralPath $outside) | Should -BeFalse
    }

    It 'rejects a byte-identical extracted-file replacement by native identity' {
        $candidate = Get-Task8PackedCandidate
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate -DryRun `
            -HookKind ExtractedFileReplacement
        $trace = Get-Task8TraceRecords $result.TracePath
        $root = [string] ($trace | Where-Object event -eq 'root-created').data.root
        try {
            Assert-Task8SafeFailure -Invocation $result -Stage Cleanup -Code CleanupFailed `
                -PackageSha256 $candidate.PackageSha256
        }
        finally {
            Remove-Task8ResidualFixturePath -Path $root
        }
    }

    It 'rejects a hard-link substitution and never deletes its outside target' {
        $candidate = Get-Task8PackedCandidate
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate -DryRun `
            -HookKind ExtractedHardLink
        $trace = Get-Task8TraceRecords $result.TracePath
        $root = [string] ($trace | Where-Object event -eq 'root-created').data.root
        $outside = [string] ($trace | Where-Object event -eq 'link-substituted').data.outside
        try {
            Assert-Task8SafeFailure -Invocation $result -Stage Cleanup -Code CleanupFailed `
                -PackageSha256 $candidate.PackageSha256
            (Test-Path -LiteralPath $outside -PathType Leaf) | Should -BeTrue
        }
        finally {
            Remove-Task8ResidualFixturePath -Path $root
            Remove-Task8ResidualFixturePath -Path $outside
        }
    }

    It 'rejects an extracted module-directory replacement by exact identity' {
        $candidate = Get-Task8PackedCandidate
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate -DryRun `
            -HookKind ModuleDirectoryReplacement
        $trace = Get-Task8TraceRecords $result.TracePath
        $root = [string] ($trace | Where-Object event -eq 'root-created').data.root
        try {
            Assert-Task8SafeFailure -Invocation $result -Stage Cleanup -Code CleanupFailed `
                -PackageSha256 $candidate.PackageSha256
        }
        finally {
            Remove-Task8ResidualFixturePath -Path $root
        }
    }

    It 'rejects an extraction-root replacement and refuses ambiguous cleanup' {
        $candidate = Get-Task8PackedCandidate
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate -DryRun `
            -HookKind RootReplacement
        $trace = Get-Task8TraceRecords $result.TracePath
        $replacement = [string] ($trace | Where-Object event -eq 'root-replaced').data.replacement
        $backup = [string] ($trace | Where-Object event -eq 'root-replaced').data.backup
        try {
            Assert-Task8SafeFailure -Invocation $result -Stage Cleanup -Code CleanupFailed `
                -PackageSha256 $candidate.PackageSha256
            (Test-Path -LiteralPath $replacement -PathType Container) | Should -BeTrue
            (Test-Path -LiteralPath $backup -PathType Container) | Should -BeTrue
        }
        finally {
            Remove-Task8ResidualFixturePath -Path $replacement
            Remove-Task8ResidualFixturePath -Path $backup
        }
    }

    It 'isolates two sequential imports from the cleanup owner and preserves only outside siblings' {
        $candidate = Get-Task8PackedCandidate
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate -DryRun `
            -HookKind OutsideSentinel -Repeat 2
        $trace = Get-Task8TraceRecords $result.TracePath
        $roots = @($trace | Where-Object event -eq 'root-created')
        $outside = @($trace | Where-Object event -eq 'outside-created')
        $imports = @($trace | Where-Object event -eq 'imported')
        $exits = @($trace | Where-Object event -eq 'worker-exited')
        $cleanups = @($trace | Where-Object event -eq 'cleanup-started')
        $afterRuns = @($trace | Where-Object event -eq 'parent-after-run')
        try {
            $result.ExitCode | Should -Be 0
            $result.OutputLineCount | Should -Be 2
            $result.JsonCount | Should -Be 2
            $result.DataRecords.Count | Should -Be 2
            @($result.DataRecords | Where-Object state -cne 'Passed').Count | Should -Be 0
            $roots.Count | Should -Be 2
            $outside.Count | Should -Be 2
            $imports.Count | Should -Be 2
            $exits.Count | Should -Be 2
            $cleanups.Count | Should -Be 2
            $afterRuns.Count | Should -Be 2
            foreach ($index in 0..1) {
                [int]$imports[$index].data.processId |
                    Should -Not -Be ([int]$cleanups[$index].data.processId)
                [int]$exits[$index].data.workerProcessId |
                    Should -Be ([int]$imports[$index].data.processId)
                [int]$exits[$index].data.processId |
                    Should -Be ([int]$cleanups[$index].data.processId)
                [int]$cleanups[$index].data.processId |
                    Should -Be ([int]$afterRuns[$index].data.processId)
                [int]$afterRuns[$index].data.graphKitCount | Should -Be 0
                [int]$afterRuns[$index].data.contractsCount | Should -Be 0
                (Test-Path -LiteralPath ([string]$roots[$index].data.root)) | Should -BeFalse
                (Test-Path -LiteralPath ([string]$outside[$index].data.path) -PathType Leaf) |
                    Should -BeTrue
                [Array]::IndexOf($trace, $imports[$index]) |
                    Should -BeLessThan ([Array]::IndexOf($trace, $exits[$index]))
                [Array]::IndexOf($trace, $exits[$index]) |
                    Should -BeLessThan ([Array]::IndexOf($trace, $cleanups[$index]))
            }
            $finished = $trace | Where-Object event -eq 'wrapper-finished'
            $finished.data.modulePathRestored | Should -BeTrue
            $finished.data.graphKitLoaded | Should -BeFalse
        }
        finally {
            foreach ($record in $outside) {
                $outsidePath = [string]$record.data.path
                if (Test-Path -LiteralPath $outsidePath -PathType Leaf) {
                    Remove-Item -LiteralPath $outsidePath -Force
                }
            }
        }

        $absent = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate -DryRun `
            -HookKind AbsentModulePath
        $absent.JsonCount | Should -Be 1
        $absent.OutputLineCount | Should -Be 1
        $absentFinished = Get-Task8TraceRecords $absent.TracePath |
            Where-Object event -eq 'wrapper-finished'
        $absentFinished.data.modulePathRestored | Should -BeTrue
        $absentFinished.data.modulePathPresent | Should -BeFalse

        $treeRun = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate -DryRun `
            -HookKind WorkerGrandchild
        $treeTrace = Get-Task8TraceRecords $treeRun.TracePath
        $treeRoot = @($treeTrace | Where-Object event -eq 'root-created')
        $treeOutside = @($treeTrace | Where-Object event -eq 'outside-created')
        $grandchild = @($treeTrace | Where-Object event -eq 'grandchild-ready')
        $rootExit = @($treeTrace | Where-Object event -eq 'worker-root-exited')
        $termination = @($treeTrace |
            Where-Object event -eq 'worker-tree-termination-requested')
        $treeExit = @($treeTrace | Where-Object event -eq 'worker-tree-exit-confirmed')
        $authorizedExit = @($treeTrace | Where-Object event -eq 'worker-exited')
        $treeCleanup = @($treeTrace | Where-Object event -eq 'cleanup-started')
        try {
            Assert-Task8SafeFailure -Invocation $treeRun `
                -Stage Diagnostics -Code DiagnosticsRejected `
                -PackageSha256 $candidate.PackageSha256
            $treeRun.Data.checks.cleanupVerified | Should -BeTrue
            $treeRoot.Count | Should -Be 1
            $treeOutside.Count | Should -Be 1
            $grandchild.Count | Should -Be 1
            $rootExit.Count | Should -Be 1
            $termination.Count | Should -Be 1
            $treeExit.Count | Should -Be 1
            $authorizedExit.Count | Should -Be 1
            $treeCleanup.Count | Should -Be 1
            [bool]$termination[0].data.residualTreeDetected | Should -BeTrue
            [bool]$treeExit[0].data.terminationRequested | Should -BeTrue
            [bool]$treeExit[0].data.streamsDrained | Should -BeTrue
            [bool]$authorizedExit[0].data.ownershipEstablished | Should -BeTrue
            [bool]$authorizedExit[0].data.requestReleased | Should -BeTrue
            [bool]$authorizedExit[0].data.rootExitConfirmed | Should -BeTrue
            [bool]$authorizedExit[0].data.treeExitConfirmed | Should -BeTrue
            [bool]$authorizedExit[0].data.streamsDrained | Should -BeTrue
            [string]$authorizedExit[0].data.protocolFailure |
                Should -BeExactly 'ResidualTree'
            [Array]::IndexOf($treeTrace, $grandchild[0]) |
                Should -BeLessThan ([Array]::IndexOf($treeTrace, $rootExit[0]))
            [Array]::IndexOf($treeTrace, $rootExit[0]) |
                Should -BeLessThan ([Array]::IndexOf($treeTrace, $termination[0]))
            [Array]::IndexOf($treeTrace, $termination[0]) |
                Should -BeLessThan ([Array]::IndexOf($treeTrace, $treeExit[0]))
            [Array]::IndexOf($treeTrace, $treeExit[0]) |
                Should -BeLessThan ([Array]::IndexOf($treeTrace, $treeCleanup[0]))
            (Test-Path -LiteralPath ([string]$treeRoot[0].data.root)) | Should -BeFalse
            (Test-Path -LiteralPath ([string]$treeOutside[0].data.path) -PathType Leaf) |
                Should -BeTrue
            $grandchildAlive = $false
            try {
                $probe = [Diagnostics.Process]::GetProcessById(
                    [int]$grandchild[0].data.processId)
                try { $grandchildAlive = -not $probe.HasExited }
                finally { $probe.Dispose() }
            }
            catch [ArgumentException] {}
            $grandchildAlive | Should -BeFalse
        }
        finally {
            if ($grandchild.Count -eq 1) {
                try {
                    $rescue = [Diagnostics.Process]::GetProcessById(
                        [int]$grandchild[0].data.processId)
                    try {
                        if (-not $rescue.HasExited -and
                            $rescue.StartTime.ToUniversalTime().Ticks -eq
                                [long]$grandchild[0].data.startTimeUtcTicks) {
                            $rescue.Kill($true)
                            $null = $rescue.WaitForExit(5000)
                        }
                    }
                    finally { $rescue.Dispose() }
                }
                catch [ArgumentException] {}
            }
            foreach ($record in $treeOutside) {
                $outsidePath = [string]$record.data.path
                if (Test-Path -LiteralPath $outsidePath -PathType Leaf) {
                    Remove-Item -LiteralPath $outsidePath -Force
                }
            }
        }

        if (-not $IsWindows) {
            $escapeClock = [Diagnostics.Stopwatch]::StartNew()
            $escapeRun = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
                -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate -DryRun `
                -HookKind WorkerSessionEscape
            $escapeClock.Stop()
            $escapeTrace = Get-Task8TraceRecords $escapeRun.TracePath
            $escapeRoot = @($escapeTrace | Where-Object event -eq 'root-created')
            $escapeOutside = @($escapeTrace | Where-Object event -eq 'outside-created')
            $escapedChild = @($escapeTrace | Where-Object event -eq 'grandchild-ready')
            try {
                Assert-Task8SafeFailure -Invocation $escapeRun `
                    -Stage Cleanup -Code CleanupFailed `
                    -PackageSha256 $candidate.PackageSha256
                # This is an outer anti-hang ceiling, not the collector's operation
                # deadline. It includes fresh pwsh startup, package staging, archive
                # verification, extraction, and native-helper compilation.
                $escapeClock.Elapsed.TotalSeconds | Should -BeLessThan 30
                $escapeRoot.Count | Should -Be 1
                $escapeOutside.Count | Should -Be 1
                $escapedChild.Count | Should -Be 1
                [bool]$escapedChild[0].data.escapedSession | Should -BeTrue
                @($escapeTrace | Where-Object event -eq 'worker-root-exited').Count |
                    Should -Be 1
                @($escapeTrace | Where-Object event -eq 'worker-tree-exit-confirmed').Count |
                    Should -Be 0
                @($escapeTrace | Where-Object event -eq 'worker-exited').Count |
                    Should -Be 0
                @($escapeTrace | Where-Object event -eq 'cleanup-started').Count |
                    Should -Be 0
                (Test-Path -LiteralPath ([string]$escapeRoot[0].data.root) -PathType Container) |
                    Should -BeTrue
                (Test-Path -LiteralPath ([string]$escapeOutside[0].data.path) -PathType Leaf) |
                    Should -BeTrue
            }
            finally {
                if ($escapedChild.Count -eq 1) {
                    try {
                        $rescue = [Diagnostics.Process]::GetProcessById(
                            [int]$escapedChild[0].data.processId)
                        try {
                            if (-not $rescue.HasExited -and
                                $rescue.StartTime.ToUniversalTime().Ticks -eq
                                    [long]$escapedChild[0].data.startTimeUtcTicks) {
                                $rescue.Kill($true)
                                $null = $rescue.WaitForExit(5000)
                            }
                        }
                        finally { $rescue.Dispose() }
                    }
                    catch [ArgumentException] {}
                }
                foreach ($record in $escapeRoot + $escapeOutside) {
                    $path = if ($record.event -ceq 'root-created') {
                        [string]$record.data.root
                    }
                    else { [string]$record.data.path }
                    Remove-Task8ResidualFixturePath -Path $path
                }
            }
        }
    }
}

Describe 'Task 8 protected-live prerequisites' {
    It 'pins the selected Verified GET control flow from public route through proof before send' {
        $descriptor = Import-PowerShellDataFile -Path (
            Join-Path $script:repoRoot 'source/Data/Operations/ManagedDevice.List.psd1')
        [string]$descriptor.IdentityRequirement | Should -BeExactly 'Verified'
        [string]$descriptor.PagingStrategy | Should -BeExactly 'NextLink'
        Assert-Task8VerifiedGetProofControlFlow -SourceRoot (
            Join-Path $script:repoRoot 'source') | Should -BeTrue

        $mutationRoot = Join-Path $TestDrive (
            'task8-proof-control-' + [guid]::NewGuid().ToString('N'))
        $null = [IO.Directory]::CreateDirectory((Join-Path $mutationRoot 'Public'))
        $null = [IO.Directory]::CreateDirectory((Join-Path $mutationRoot 'Private/Transport'))
        $relativePaths = @(
            'Public/Get-GraphObject.ps1'
            'Private/Invoke-GraphRetry.ps1'
            'Private/Transport/Send-GraphHttpRequest.ps1'
        )
        foreach ($relative in $relativePaths) {
            [IO.File]::Copy(
                (Join-Path (Join-Path $script:repoRoot 'source') $relative),
                (Join-Path $mutationRoot $relative), $false)
        }

        $retryPath = Join-Path $mutationRoot 'Private/Invoke-GraphRetry.ps1'
        $retryOriginal = [IO.File]::ReadAllText($retryPath)
        $retryMutation = $retryOriginal.Replace(
            "([string] `$Descriptor.IdentityRequirement -ceq 'Verified')", '$false')
        $retryMutation | Should -Not -BeExactly $retryOriginal
        [IO.File]::WriteAllText($retryPath, $retryMutation, [Text.UTF8Encoding]::new($false))
        { Assert-Task8VerifiedGetProofControlFlow -SourceRoot $mutationRoot } | Should -Throw
        [IO.File]::WriteAllText($retryPath, $retryOriginal, [Text.UTF8Encoding]::new($false))

        $senderPath = Join-Path $mutationRoot 'Private/Transport/Send-GraphHttpRequest.ps1'
        $senderOriginal = [IO.File]::ReadAllText($senderPath)
        $awayMutation = $senderOriginal.Replace(
            'Confirm-GraphTenantBinding', 'Confirm-GraphTenantBindingRemoved')
        $awayMutation | Should -Not -BeExactly $senderOriginal
        [IO.File]::WriteAllText($senderPath, $awayMutation, [Text.UTF8Encoding]::new($false))
        { Assert-Task8VerifiedGetProofControlFlow -SourceRoot $mutationRoot } | Should -Throw

        $tokens = $null
        $errors = $null
        $awayAst = [Management.Automation.Language.Parser]::ParseFile(
            $senderPath, [ref]$tokens, [ref]$errors)
        @($errors).Count | Should -Be 0
        $senderFunction = @($awayAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq 'Send-GraphHttpRequest'
        }, $true))[0]
        $insertAt = $senderFunction.Body.Extent.EndOffset - 1
        $movedMutation = $awayMutation.Insert(
            $insertAt, "`n    Confirm-GraphTenantBinding`n")
        [IO.File]::WriteAllText($senderPath, $movedMutation, [Text.UTF8Encoding]::new($false))
        { Assert-Task8VerifiedGetProofControlFlow -SourceRoot $mutationRoot } | Should -Throw
        [IO.File]::WriteAllText($senderPath, $senderOriginal, [Text.UTF8Encoding]::new($false))
        Assert-Task8VerifiedGetProofControlFlow -SourceRoot $mutationRoot | Should -BeTrue
    }

    It 'runs the actual top-level Live branch through exact imported public commands' {
        $candidate = Get-Task8PackedCandidate
        $storePath = Join-Path $TestDrive 'task8-package-live-store.json'
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate `
            -ProfileId task8-fixture -StorePath $storePath -HookKind PackageLiveSuccess

        $result.ExitCode | Should -Be 0
        $result.OutputLineCount | Should -Be 1
        $result.JsonCount | Should -Be 1
        $result.StdErr | Should -BeNullOrEmpty
        Assert-Task8ModeRecordShape -Record $result.Data -Execution Live `
            -AuthMode Certificate -PackageSha256 $candidate.PackageSha256
        $result.Data.state | Should -BeExactly 'Passed'
        $result.Data.failureStage | Should -BeExactly 'None'
        $result.Data.failureCode | Should -BeExactly 'None'
        $result.Data.checks.contextMatched | Should -BeTrue
        $result.Data.checks.sourceMatched | Should -BeTrue
        $result.Data.checks.tenantProofVerified | Should -BeTrue
        $result.Data.read.attempted | Should -BeTrue
        $result.Data.read.succeeded | Should -BeTrue
        $result.Data.read.rowCount | Should -Be 2

        $trace = Get-Task8TraceRecords $result.TracePath
        $context = @($trace | Where-Object event -eq 'context-command')
        $source = @($trace | Where-Object event -eq 'source-created')
        $read = @($trace | Where-Object event -eq 'read-command')
        $context.Count | Should -Be 1
        $context[0].data.storePath | Should -BeExactly $storePath
        $source.Count | Should -Be 1
        $source[0].data.authMethod | Should -BeExactly 'Certificate'
        $read.Count | Should -Be 1
        $read[0].data.type | Should -BeExactly 'ManagedDevice'
        $read[0].data.operation | Should -BeExactly 'List'
        $read[0].data.maxPages | Should -Be 200
        $read[0].data.firstPageAuthority | Should -BeExactly 'graph.microsoft.com'
        $result.Output | Should -Not -Match (
            'task8-fixture-token-fingerprint|task8-fixture-generation|task8-package-row')
    }
}

Describe 'Task 8 injected live core and closed read evidence' {
    It 'validates the exact compiled source and performs one bounded public read for <AuthMode>' -ForEach $task8AuthModes {
        $candidate = Get-Task8PackedCandidate
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode $AuthMode `
            -ProfileId task8-fixture -HookKind LiveSuccess

        $result.ExitCode | Should -Be 0
        $result.OutputLineCount | Should -Be 1
        $result.JsonCount | Should -Be 1
        $result.StdErr | Should -BeNullOrEmpty
        Assert-Task8LiveCoreResult -Record $result.Data -AuthMode $AuthMode `
            -State Passed -FailureStage None -FailureCode None
        $result.Data.contextMatched | Should -BeTrue
        $result.Data.sourceMatched | Should -BeTrue
        $result.Data.tenantProofVerified | Should -BeTrue
        $result.Data.readAttempted | Should -BeTrue
        $result.Data.readSucceeded | Should -BeTrue
        $result.Data.rowCount | Should -Be 2
        $trace = Get-Task8TraceRecords $result.TracePath
        $contextTrace = @($trace | Where-Object event -eq 'context')
        $contextTrace.Count | Should -Be 1
        $contextTrace[0].data.identityState | Should -BeExactly 'NotAcquired'
        $read = @($trace | Where-Object event -eq 'read')
        $read.Count | Should -Be 1
        $read[0].data.type | Should -BeExactly 'ManagedDevice'
        $read[0].data.operation | Should -BeExactly 'List'
        $read[0].data.passThruResult | Should -BeTrue
        $result.Output | Should -Not -Match 'task8-row-secret|task8-secret-sentinel'
    }

    It 'rejects a source that does not implement the exact compiled interface' {
        $candidate = Get-Task8PackedCandidate
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate `
            -ProfileId task8-fixture -HookKind LiveInterfaceMismatch

        Assert-Task8LiveCoreResult -Record $result.Data -AuthMode Certificate `
            -State Failed -FailureStage Context -FailureCode ContextRejected
    }

    It 'rejects a source whose selected and reported auth modes differ' {
        $candidate = Get-Task8PackedCandidate
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode ManagedIdentity `
            -ProfileId task8-fixture -HookKind LiveModeMismatch

        Assert-Task8LiveCoreResult -Record $result.Data -AuthMode ManagedIdentity `
            -State Failed -FailureStage Context -FailureCode ContextRejected
    }

    It 'rejects a source whose refresh behavior differs from the literal route' {
        $candidate = Get-Task8PackedCandidate
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode BearerToken `
            -ProfileId task8-fixture -HookKind LiveRefreshMismatch

        Assert-Task8LiveCoreResult -Record $result.Data -AuthMode BearerToken `
            -State Failed -FailureStage Context -FailureCode ContextRejected
    }

    It 'maps a structured adapter acquisition failure without copying the exception' {
        $candidate = Get-Task8PackedCandidate
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate `
            -ProfileId task8-fixture -HookKind LiveAcquisitionFailure

        Assert-Task8LiveCoreResult -Record $result.Data -AuthMode Certificate `
            -State Failed -FailureStage Acquisition -FailureCode AcquisitionFailed
        $result.Output | Should -Not -Match 'task8_fixture_acquisition|task8-secret-sentinel|GraphAuthException'
    }

    It 'rejects a non-success read envelope' {
        $candidate = Get-Task8PackedCandidate
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate `
            -ProfileId task8-fixture -HookKind LiveFailedEnvelope

        Assert-Task8LiveCoreResult -Record $result.Data -AuthMode Certificate `
            -State Failed -FailureStage Read -FailureCode ReadFailed
    }

    It 'rejects a success envelope whose certainty is not Known' {
        $candidate = Get-Task8PackedCandidate
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate `
            -ProfileId task8-fixture -HookKind LiveIndeterminate

        Assert-Task8LiveCoreResult -Record $result.Data -AuthMode Certificate `
            -State Failed -FailureStage Read -FailureCode ReadFailed
    }

    It 'rejects a truncated paged result even when its outcome says Succeeded' {
        $candidate = Get-Task8PackedCandidate
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate `
            -ProfileId task8-fixture -HookKind LiveTruncated

        Assert-Task8LiveCoreResult -Record $result.Data -AuthMode Certificate `
            -State Failed -FailureStage Read -FailureCode ReadFailed
    }

    It 'rejects unverified and each mismatched tenant provenance component' {
        $candidate = Get-Task8PackedCandidate
        foreach ($hookKind in @(
            'LiveUnverified','LiveTargetTenantMismatch','LiveActualTenantMismatch',
            'LiveSourceTenantMismatch')) {
            $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
                -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate `
                -ProfileId task8-fixture -HookKind $hookKind

            Assert-Task8LiveCoreResult -Record $result.Data -AuthMode Certificate `
                -State Failed -FailureStage Read -FailureCode ReadFailed
        }
    }

    It 'rejects independently invalid exact live proof <Kind>' `
        -ForEach $task8LiveProofRejectionCases {
        $candidate = Get-Task8PackedCandidate
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate `
            -ProfileId task8-fixture -HookKind $HookKind

        Assert-Task8LiveCoreResult -Record $result.Data -AuthMode Certificate `
            -State Failed -FailureStage $FailureStage -FailureCode $(
                if ($FailureStage -ceq 'Context') { 'ContextRejected' } else { 'ReadFailed' })
        $result.Output | Should -Not -Match (
            'task8-fixture-token-fingerprint|task8-fixture-generation|00000000-0000-0000-0000-000000000333')
    }
}

Describe 'Task 8 evidence schema and stream guard' {
    It 'rejects a regex-valid module version containing a forbidden string directly' {
        $record = New-Task8ModeRecordFixture -ModuleVersion '0.4.0-task8-secret-sentinel'
        {
            Invoke-Task8PrivateHelper -FunctionName Test-GraphKitAuthParityEvidence `
                -Arguments @{ Record = $record }
        } | Should -Throw
    }

    It 'sanitizes a forbidden regex-valid module version in the evidence fallback' {
        $candidate = Get-Task8PackedCandidate
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate -DryRun `
            -HookKind EvidenceMutation -MutationValue '0.4.0-task8-secret-sentinel'

        Assert-Task8SafeFailure -Invocation $result -Stage Evidence -Code EvidenceRejected `
            -PackageSha256 $candidate.PackageSha256
        $result.Data.moduleVersion | Should -BeExactly '0.0.0-rejected'
        $result.Output | Should -Not -Match 'task8-secret-sentinel'
    }

    It 'rejects evidence mutation <Kind> and emits only the fixed safe evidence failure' -ForEach $task8EvidenceMutationCases {
        $candidate = Get-Task8PackedCandidate
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate -DryRun `
            -HookKind EvidenceMutation -MutationValue $Value

        Assert-Task8SafeFailure -Invocation $result -Stage Evidence -Code EvidenceRejected `
            -PackageSha256 $candidate.PackageSha256
        $result.Output | Should -Not -Match ([regex]::Escape($Value))
    }

    It 'captures success, error, warning, verbose, debug, information, and host sentinels' {
        $candidate = Get-Task8PackedCandidate
        $result = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate -DryRun `
            -HookKind StreamSentinel

        $result.ExitCode | Should -Be 0
        $result.JsonCount | Should -Be 1
        $result.Output | Should -Not -Match 'task8-secret-sentinel'
        $streamExit = @(Get-Task8TraceRecords $result.TracePath |
            Where-Object event -eq 'worker-exited')
        $streamExit.Count | Should -Be 1
        $streamExit[0].data.protocolFailure | Should -BeExactly 'None'
        $result.Data.state | Should -BeExactly 'Passed'
        @((Get-Task8TraceRecords $result.TracePath) |
            Where-Object event -eq 'stream-sentinel-fired').Count | Should -Be 1
        $requestFixturePath = $result.TracePath + '.worker-request.json'
        (Test-Path -LiteralPath $requestFixturePath -PathType Leaf) | Should -BeTrue
        $requestFixtureJson = [IO.File]::ReadAllText($requestFixturePath)
        $requestFixture = $requestFixtureJson | ConvertFrom-Json -Depth 32 -NoEnumerate
        $convertedRequest = Invoke-Task8PrivateHelper `
            -FunctionName ConvertFrom-GraphKitAuthParityWorkerState `
            -Arguments @{ Request = $requestFixture }
        [string]$convertedRequest.State.CandidateSha256 |
            Should -BeExactly $candidate.PackageSha256
        foreach ($collectionName in @(
            'expectedFiles','expectedDirectories','fileEvidence','directoryEvidence')) {
            $scalarRequest = $requestFixtureJson | ConvertFrom-Json -Depth 32 -NoEnumerate
            $scalarRequest.state.$collectionName = @(
                $scalarRequest.state.$collectionName)[0]
            {
                Invoke-Task8PrivateHelper `
                    -FunctionName ConvertFrom-GraphKitAuthParityWorkerState `
                    -Arguments @{ Request = $scalarRequest }
            } | Should -Throw
        }
        $digestMismatchRequest = $requestFixtureJson |
            ConvertFrom-Json -Depth 32 -NoEnumerate
        $digestMismatchRequest.packageSha256 = ('f' * 64)
        {
            Invoke-Task8PrivateHelper `
                -FunctionName ConvertFrom-GraphKitAuthParityWorkerState `
                -Arguments @{ Request = $digestMismatchRequest }
        } | Should -Throw
        foreach ($requestMutation in @(
            'missing-top','unknown-top','wrong-type','missing-state','wrong-path')) {
            $mutantRequest = $requestFixtureJson |
                ConvertFrom-Json -Depth 32 -NoEnumerate
            switch ($requestMutation) {
                'missing-top' {
                    $mutantRequest.PSObject.Properties.Remove('profileId')
                }
                'unknown-top' {
                    $mutantRequest | Add-Member -MemberType NoteProperty `
                        -Name unknown -Value $true
                }
                'wrong-type' { $mutantRequest.storePathBound = 'false' }
                'missing-state' {
                    $mutantRequest.state.PSObject.Properties.Remove('sealed')
                }
                'wrong-path' {
                    $mutantRequest.state.moduleRoot =
                        Join-Path $mutantRequest.state.rootPath 'different-module'
                }
            }
            {
                Invoke-Task8PrivateHelper `
                    -FunctionName ConvertFrom-GraphKitAuthParityWorkerState `
                    -Arguments @{ Request = $mutantRequest }
            } | Should -Throw
        }

        $ordinary = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate -DryRun `
            -HookKind EvidenceMutation -MutationValue task8-secret-sentinel -OrdinaryExecution
        $ordinary.OutputLineCount | Should -Be 1
        $ordinary.JsonCount | Should -Be 1
        $ordinary.Data.state | Should -BeExactly 'Passed'
        $ordinary.Data.failureStage | Should -BeExactly 'None'
        $ordinary.Data.failureCode | Should -BeExactly 'None'

        $workerProtocolCases = @(
            @{ HookKind = 'WorkerExtraBlankFrame'; ProtocolFailure = 'Frame' }
            @{ HookKind = 'WorkerBomFrame'; ProtocolFailure = 'Frame' }
            @{ HookKind = 'WorkerSecondFrame'; ProtocolFailure = 'Frame' }
            @{ HookKind = 'WorkerMissingTerminator'; ProtocolFailure = 'Frame' }
            @{ HookKind = 'WorkerEmptyFrame'; ProtocolFailure = 'Frame' }
            @{ HookKind = 'WorkerInvalidUtf8'; ProtocolFailure = 'StreamDecode' }
            @{ HookKind = 'WorkerStderr'; ProtocolFailure = 'Stderr' }
            @{ HookKind = 'WorkerStdoutOverflow'; ProtocolFailure = 'StdoutBound' }
            @{ HookKind = 'WorkerStderrOverflow'; ProtocolFailure = 'StderrBound' }
            @{ HookKind = 'WorkerNonzeroExit'; ProtocolFailure = 'ExitCode' }
            @{ HookKind = 'WorkerRequestTrailingLf'; ProtocolFailure = 'Validation' }
            @{ HookKind = 'WorkerRequestBom'; ProtocolFailure = 'Validation' }
        )
        foreach ($protocolCase in $workerProtocolCases) {
            $protocolResult = Invoke-Task8RunnerProcess `
                -PackagePath $candidate.PackagePath `
                -PackageSha256 $candidate.PackageSha256 `
                -AuthMode Certificate -DryRun -HookKind $protocolCase.HookKind
            Assert-Task8SafeFailure -Invocation $protocolResult `
                -Stage Diagnostics -Code DiagnosticsRejected `
                -PackageSha256 $candidate.PackageSha256
            $protocolResult.Output | Should -Not -Match 'task8-secret-sentinel'
            $protocolResult.Data.checks.cleanupVerified | Should -BeTrue
            $protocolExit = @(Get-Task8TraceRecords $protocolResult.TracePath |
                Where-Object event -eq 'worker-exited')
            $protocolExit.Count | Should -Be 1
            $protocolExit[0].data.protocolFailure |
                Should -BeExactly $protocolCase.ProtocolFailure
            $protocolExit[0].data.treeExitConfirmed | Should -BeTrue
            $protocolExit[0].data.streamsDrained | Should -BeTrue
        }

        $versionMismatch = Invoke-Task8RunnerProcess `
            -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 `
            -AuthMode Certificate -DryRun -HookKind WorkerRequestVersionMismatch
        Assert-Task8SafeFailure -Invocation $versionMismatch `
            -Stage Import -Code ImportRejected `
            -PackageSha256 $candidate.PackageSha256
        $versionMismatch.Data.checks.cleanupVerified | Should -BeTrue
        $versionMismatchExit = @(Get-Task8TraceRecords $versionMismatch.TracePath |
            Where-Object event -eq 'worker-exited')
        $versionMismatchExit.Count | Should -Be 1
        $versionMismatchExit[0].data.protocolFailure | Should -BeExactly 'None'
        $versionMismatchTrace = Get-Task8TraceRecords $versionMismatch.TracePath
        @($versionMismatchTrace | Where-Object event -eq 'imported').Count | Should -Be 0
        $versionMismatch.Output | Should -Not -Match '0\.4\.0-r8\.other'

        $pathMismatch = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate -DryRun `
            -HookKind WorkerPathMismatch
        Assert-Task8SafeFailure -Invocation $pathMismatch `
            -Stage Diagnostics -Code DiagnosticsRejected `
            -PackageSha256 $candidate.PackageSha256
        $pathMismatch.Data.checks.cleanupVerified | Should -BeTrue

        $postStart = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate -DryRun `
            -HookKind PostStartSetupFailure
        Assert-Task8SafeFailure -Invocation $postStart `
            -Stage Diagnostics -Code DiagnosticsRejected `
            -PackageSha256 $candidate.PackageSha256
        $postStartTrace = Get-Task8TraceRecords $postStart.TracePath
        $postStartSetup = @($postStartTrace | Where-Object event -eq 'worker-setup-started')
        $postStartExit = @($postStartTrace | Where-Object event -eq 'worker-exited')
        $postStartCleanup = @($postStartTrace | Where-Object event -eq 'cleanup-started')
        $postStartSetup.Count | Should -Be 1
        $postStartExit.Count | Should -Be 1
        $postStartCleanup.Count | Should -Be 1
        [int]$postStartExit[0].data.workerProcessId |
            Should -Be ([int]$postStartSetup[0].data.processId)
        [Array]::IndexOf($postStartTrace, $postStartExit[0]) |
            Should -BeLessThan ([Array]::IndexOf($postStartTrace, $postStartCleanup[0]))

        $noReadClock = [Diagnostics.Stopwatch]::StartNew()
        $noRead = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate -DryRun `
            -HookKind WorkerNoRead
        $noReadClock.Stop()
        Assert-Task8SafeFailure -Invocation $noRead `
            -Stage Diagnostics -Code DiagnosticsRejected `
            -PackageSha256 $candidate.PackageSha256
        $noReadClock.Elapsed.TotalSeconds | Should -BeLessThan 30
        $noRead.Data.checks.cleanupVerified | Should -BeTrue
        $noReadTrace = Get-Task8TraceRecords $noRead.TracePath
        $noReadExit = @($noReadTrace | Where-Object event -eq 'worker-exited')
        $noReadCleanup = @($noReadTrace | Where-Object event -eq 'cleanup-started')
        $noReadExit.Count | Should -Be 1
        $noReadExit[0].data.forcedTermination | Should -BeTrue
        $noReadExit[0].data.protocolFailure | Should -BeExactly 'Timeout'
        [long]$noReadExit[0].data.operationDeadlineMilliseconds | Should -Be 3000
        [long]$noReadExit[0].data.hardDeadlineMilliseconds | Should -Be 5000
        [long]$noReadExit[0].data.elapsedMilliseconds |
            Should -BeGreaterOrEqual (
                [long]$noReadExit[0].data.operationDeadlineMilliseconds)
        [long]$noReadExit[0].data.elapsedMilliseconds | Should -BeLessOrEqual 7000
        $noReadCleanup.Count | Should -Be 1
        [Array]::IndexOf($noReadTrace, $noReadExit[0]) |
            Should -BeLessThan ([Array]::IndexOf($noReadTrace, $noReadCleanup[0]))

        $pollClock = [Diagnostics.Stopwatch]::StartNew()
        $pollFailure = Invoke-Task8RunnerProcess -PackagePath $candidate.PackagePath `
            -PackageSha256 $candidate.PackageSha256 -AuthMode Certificate -DryRun `
            -HookKind WorkerPermanentPollFailure
        $pollClock.Stop()
        $pollTrace = Get-Task8TraceRecords $pollFailure.TracePath
        $pollRoot = @($pollTrace | Where-Object event -eq 'root-created')
        try {
            Assert-Task8SafeFailure -Invocation $pollFailure `
                -Stage Cleanup -Code CleanupFailed `
                -PackageSha256 $candidate.PackageSha256
            # The collector hard bound is enforced independently; this wrapper-level
            # assertion also includes process startup, staging, and native compilation.
            $pollClock.Elapsed.TotalSeconds | Should -BeLessThan 30
            $pollRoot.Count | Should -Be 1
            @($pollTrace | Where-Object event -eq 'worker-process-failure').Count |
                Should -Be 1
            @($pollTrace | Where-Object event -eq 'cleanup-started').Count | Should -Be 0
            (Test-Path -LiteralPath ([string]$pollRoot[0].data.root) -PathType Container) |
                Should -BeTrue
        }
        finally {
            foreach ($record in $pollRoot) {
                Remove-Task8ResidualFixturePath -Path ([string]$record.data.root)
            }
        }

        $runnerSource = [IO.File]::ReadAllText($script:runnerPath)
        $runnerSource | Should -Match (
            'public bool IsTreeEmpty\(\)[\s\S]*?if \(_emptyConfirmed\) return true;')
        $runnerSource | Should -Match (
            'else if \(_assigned && _ownershipEstablished && !_emptyConfirmed')

        $workerRequest = [pscustomobject]@{
            nonce = ('a' * 64)
            execution = 'DryRun'
            authMode = 'Certificate'
            packageSha256 = ('b' * 64)
            moduleVersion = '0.4.0-r8.fixture'
        }
        $workerAdapter = [ordered]@{}
        foreach ($name in @(
            'abiMarkerExact','contractsDefault','providerCollectibleNonDefault',
            'msalVersionExact','providerMsalSameContext','publicAbiExact')) {
            $workerAdapter[$name] = $true
        }
        $workerResult = [pscustomobject][ordered]@{
            recordKind = 'GraphKit.Task8.ParityWorkerResult/1'
            nonce = ('a' * 64)
            requestSha256 = ('c' * 64)
            execution = 'DryRun'
            authMode = 'Certificate'
            packageSha256 = ('b' * 64)
            moduleVersion = '0.4.0-r8.fixture'
            state = 'Passed'
            failureStage = 'None'
            failureCode = 'None'
            exactImport = $true
            adapter = [pscustomobject]$workerAdapter
            contextMatched = $false
            sourceMatched = $false
            tenantProofVerified = $false
            readAttempted = $false
            readSucceeded = $false
            rowCount = [long]0
            workerTeardownVerified = $true
        }
        Invoke-Task8PrivateHelper -FunctionName Test-GraphKitAuthParityWorkerResult `
            -Arguments @{
                Result = $workerResult
                Request = $workerRequest
                RequestSha256 = ('c' * 64)
            } | Should -BeTrue
        {
            Invoke-Task8PrivateHelper `
                -FunctionName ConvertFrom-GraphKitAuthParityWorkerJson `
                -Arguments @{
                    Json = '{"outer":{"value":1,"value":2}}'
                    MaximumBytes = [long]1024
                }
        } | Should -Throw
        foreach ($mutation in @(
            'unknown','missing','wrong-type','wrong-nonce','wrong-hash',
            'wrong-version','wrong-execution','wrong-auth','wrong-package',
            'missing-adapter','unknown-adapter','wrong-adapter-type')) {
            $mutant = $workerResult | ConvertTo-Json -Compress -Depth 5 |
                ConvertFrom-Json -Depth 5
            switch ($mutation) {
                'unknown' {
                    $mutant | Add-Member -MemberType NoteProperty `
                        -Name unknown -Value $true
                }
                'missing' { $mutant.PSObject.Properties.Remove('rowCount') }
                'wrong-type' { $mutant.exactImport = 'true' }
                'wrong-nonce' { $mutant.nonce = ('d' * 64) }
                'wrong-hash' { $mutant.requestSha256 = ('e' * 64) }
                'wrong-version' { $mutant.moduleVersion = '0.4.0-r8.other' }
                'wrong-execution' { $mutant.execution = 'Live' }
                'wrong-auth' { $mutant.authMode = 'BearerToken' }
                'wrong-package' { $mutant.packageSha256 = ('d' * 64) }
                'missing-adapter' {
                    $mutant.adapter.PSObject.Properties.Remove('publicAbiExact')
                }
                'unknown-adapter' {
                    $mutant.adapter | Add-Member -MemberType NoteProperty `
                        -Name unknown -Value $true
                }
                'wrong-adapter-type' { $mutant.adapter.publicAbiExact = 'true' }
            }
            {
                Invoke-Task8PrivateHelper `
                    -FunctionName Test-GraphKitAuthParityWorkerResult `
                    -Arguments @{
                        Result = $mutant
                        Request = $workerRequest
                        RequestSha256 = ('c' * 64)
                    }
            } | Should -Throw
        }
    }

    It 'accepts the exact in-memory mode-run scalar types and closed schema' {
        $record = New-Task8ModeRecordFixture
        Invoke-Task8PrivateHelper -FunctionName Test-GraphKitAuthParityEvidence `
            -Arguments @{ Record = $record } | Should -BeTrue
    }

    It 'rejects a string-valued in-memory row count rather than coercing it' {
        $script:runnerPath | Should -Exist
        $record = New-Task8ModeRecordFixture
        $record.read.rowCount = '0'
        {
            Invoke-Task8PrivateHelper -FunctionName Test-GraphKitAuthParityEvidence `
                -Arguments @{ Record = $record }
        } | Should -Throw
    }

    It 'accepts the exact frozen-artifact schema and scalar types' {
        $artifact = New-Task8FrozenArtifactFixture
        Invoke-Task8PrivateHelper -FunctionName Test-GraphKitAuthParityFrozenArtifact `
            -Arguments @{ Record = $artifact } | Should -BeTrue
    }

    It 'requires retention to bind four distinct modes to one artifact version and digest' {
        $artifact = New-Task8FrozenArtifactFixture
        $records = @($script:task8ModeNames | ForEach-Object {
            New-Task8ModeRecordFixture -AuthMode $_ -Execution Live
        })
        Invoke-Task8PrivateHelper -FunctionName Test-GraphKitAuthParityRetention `
            -Arguments @{ Artifact = $artifact; ModeRecords = $records } | Should -BeTrue

        $dryRuns = @($script:task8ModeNames | ForEach-Object {
            New-Task8ModeRecordFixture -AuthMode $_
        })
        {
            Invoke-Task8PrivateHelper -FunctionName Test-GraphKitAuthParityRetention `
                -Arguments @{ Artifact = $artifact; ModeRecords = $dryRuns }
        } | Should -Throw
    }

    It 'rejects duplicate retained modes even when every individual record is valid' {
        $script:runnerPath | Should -Exist
        $artifact = New-Task8FrozenArtifactFixture
        $records = @(
            New-Task8ModeRecordFixture -AuthMode Certificate -Execution Live
            New-Task8ModeRecordFixture -AuthMode ClientSecret -Execution Live
            New-Task8ModeRecordFixture -AuthMode ManagedIdentity -Execution Live
            New-Task8ModeRecordFixture -AuthMode ManagedIdentity -Execution Live
        )
        {
            Invoke-Task8PrivateHelper -FunctionName Test-GraphKitAuthParityRetention `
                -Arguments @{ Artifact = $artifact; ModeRecords = $records }
        } | Should -Throw
    }
}
