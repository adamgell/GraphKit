using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace __GRAPHKIT_AUTH_STAGE_CAPTURE_NAMESPACE__;

public sealed class GraphKitAuthPathEvidence
{
    public string RelativePath { get; init; } = string.Empty;
    public string PhysicalPath { get; init; } = string.Empty;
    public string NativeIdentity { get; init; } = string.Empty;
    public string Sha256 { get; init; } = string.Empty;
    public long Length { get; init; }
    public long LinkCount { get; init; }
    public int UnixMode { get; init; }
    public uint OwnerUid { get; init; }
    public uint EffectiveUid { get; init; }
    public string PermissionEvidence { get; init; } = string.Empty;
    public bool IsDirectory { get; init; }
    public bool IsRegularFile { get; init; }
    public bool IsReparsePoint { get; init; }
    public bool OwnerWritable { get; init; }
    public string OwnerSid { get; init; } = string.Empty;
    public string CurrentIdentitySid { get; init; } = string.Empty;
    public string CurrentOwnerSid { get; init; } = string.Empty;
    public bool AccessRulesProtected { get; init; }
    public bool HasInheritedAccessRules { get; init; }
    public bool OwnerOnlyAccess { get; init; }
    public bool ExactOwnerOnlyAccess { get; init; }
    public bool ExactWritableOwnerOnlyDirectoryAccess { get; init; }
    public bool FileReadOnly { get; init; }
}

public sealed class GraphKitAuthCopyEvidence
{
    public GraphKitAuthPathEvidence Source { get; init; } = new();
    public GraphKitAuthPathEvidence DestinationInitial { get; init; } = new();
    public GraphKitAuthPathEvidence Destination { get; init; } = new();
}

public sealed class GraphKitAuthWriteEvidence
{
    public GraphKitAuthPathEvidence DestinationInitial { get; init; } = new();
    public GraphKitAuthPathEvidence Destination { get; init; } = new();
}

public static class GraphKitAuthStageCapture
{
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint WriteDacAccess = 0x00040000;
    private const uint WriteOwnerAccess = 0x00080000;
    private const uint ShareRead = 0x00000001;
    private const uint ShareWrite = 0x00000002;
    private const uint ShareDelete = 0x00000004;
    private const uint CreateNew = 1;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagWriteThrough = 0x80000000;
    private const uint FileAttributeReadOnly = 0x00000001;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const int SeFileObject = 1;
    private const uint OwnerSecurityInformation = 0x00000001;
    private const uint DaclSecurityInformation = 0x00000004;
    private const int TokenOwner = 4;
    private const int ErrorInsufficientBuffer = 122;
    private const uint MaxTokenOwnerInformationLength = 65536;
    private const int FileDispositionInfoClass = 4;

    public static GraphKitAuthPathEvidence InspectFile(string rootPath, string relativePath)
        => Inspect(rootPath, relativePath, expectDirectory: false, hashContent: true);

    public static GraphKitAuthPathEvidence InspectFileMetadata(
        string rootPath,
        string relativePath,
        long maximumLength)
    {
        if (maximumLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumLength));
        }
        GraphKitAuthPathEvidence evidence = Inspect(
            rootPath, relativePath, expectDirectory: false, hashContent: false);
        if (evidence.Length > maximumLength)
        {
            throw new IOException($"Source '{relativePath}' exceeds its bounded inspection length.");
        }
        return evidence;
    }

    public static GraphKitAuthPathEvidence InspectDirectory(string rootPath, string relativePath)
        => Inspect(rootPath, relativePath, expectDirectory: true, hashContent: false);

    public static GraphKitAuthPathEvidence InspectDirectoryPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("A directory path is required.", nameof(path));
        }
        string fullPath = Path.GetFullPath(path);
        using SafeFileHandle handle = OpenReadNoFollow(fullPath, directory: true);
        return EvidenceFromHandle(
            handle, fullPath, string.Empty, expectDirectory: true, hashContent: false);
    }

    public static bool HasInitialOwnerOnlyAccess(GraphKitAuthPathEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        return OperatingSystem.IsWindows()
            ? evidence.OwnerOnlyAccess &&
                !string.IsNullOrWhiteSpace(evidence.OwnerSid) &&
                string.Equals(evidence.OwnerSid, evidence.CurrentOwnerSid, StringComparison.Ordinal)
            : evidence.UnixMode == 0x180 && evidence.OwnerUid == evidence.EffectiveUid;
    }

    public static bool HasInitialOwnerOnlyDirectoryAccess(GraphKitAuthPathEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        return OperatingSystem.IsWindows()
            ? evidence.IsDirectory &&
                evidence.OwnerWritable &&
                evidence.AccessRulesProtected &&
                !evidence.HasInheritedAccessRules &&
                evidence.OwnerOnlyAccess &&
                evidence.ExactWritableOwnerOnlyDirectoryAccess &&
                !string.IsNullOrWhiteSpace(evidence.OwnerSid) &&
                string.Equals(evidence.OwnerSid, evidence.CurrentOwnerSid, StringComparison.Ordinal)
            : evidence.IsDirectory && evidence.UnixMode == 0x1C0 &&
                evidence.OwnerUid == evidence.EffectiveUid;
    }

    public static GraphKitAuthPathEvidence CreateDirectoryOwnerOnly(
        string parentPath,
        string childName)
    {
        string parent = Path.GetFullPath(parentPath);
        string child = ResolveRelative(parent, childName);
        EnsureAncestors(parent, childName);
        using SafeFileHandle parentHandle = OpenReadNoFollow(parent, directory: true);
        NativeFacts parentBefore = GetNativeFacts(parentHandle, parent);
        if (!parentBefore.IsDirectory || parentBefore.IsReparsePoint)
        {
            throw new IOException("Owner-only directory creation requires one physical parent directory.");
        }

        int error;
        if (OperatingSystem.IsWindows())
        {
            DirectorySecurity security = new();
            SecurityIdentifier currentIdentity = WindowsIdentity.GetCurrent().User
                ?? throw new IOException("The current Windows identity has no SID.");
            SecurityIdentifier owner = GetCurrentTokenOwnerSid();
            security.SetOwner(owner);
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.AddAccessRule(new FileSystemAccessRule(
                currentIdentity,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
            byte[] descriptor = security.GetSecurityDescriptorBinaryForm();
            GCHandle pinnedDescriptor = GCHandle.Alloc(descriptor, GCHandleType.Pinned);
            try
            {
                SecurityAttributes attributes = new()
                {
                    Length = Marshal.SizeOf<SecurityAttributes>(),
                    SecurityDescriptor = pinnedDescriptor.AddrOfPinnedObject(),
                    InheritHandle = 0
                };
                if (!CreateDirectoryW(ToExtendedWindowsPath(child), ref attributes))
                {
                    error = Marshal.GetLastWin32Error();
                    if (error == 80 || error == 183)
                    {
                        throw new IOException(
                            $"Atomic owner-only directory destination collision: '{childName}' already exists.");
                    }
                    throw new IOException(
                        $"Could not atomically create owner-only directory '{childName}' (Win32 {error}).");
                }
            }
            finally
            {
                pinnedDescriptor.Free();
            }
        }
        else
        {
            int result = mkdirat(
                parentHandle.DangerousGetHandle().ToInt32(),
                childName,
                0x000001C0); // 0700
            if (result != 0)
            {
                error = Marshal.GetLastWin32Error();
                if (error == 17)
                {
                    throw new IOException(
                        $"Atomic owner-only directory destination collision: '{childName}' already exists.");
                }
                throw new IOException(
                    $"Could not atomically create owner-only directory '{childName}' (errno {error}).");
            }
        }

        GraphKitAuthPathEvidence initial = InspectDirectory(parent, childName);
        using SafeFileHandle reopenedParent = OpenReadNoFollow(parent, directory: true);
        NativeFacts parentAfter = GetNativeFacts(reopenedParent, parent);
        if (!parentBefore.SameObject(parentAfter))
        {
            throw new IOException("The owner-only directory parent changed during atomic creation.");
        }
        return initial;
    }

    public static byte[] ReadFile(string rootPath, string relativePath)
    {
        string fullPath = ResolveRelative(rootPath, relativePath);
        EnsureAncestors(rootPath, relativePath);
        using SafeFileHandle handle = OpenReadNoFollow(fullPath, directory: false);
        NativeFacts before = GetNativeFacts(handle, fullPath);
        if (!before.IsRegularFile || before.IsReparsePoint || before.Length > int.MaxValue)
        {
            throw new IOException($"'{relativePath}' is not one readable regular file.");
        }
        byte[] content = new byte[checked((int)before.Length)];
        long offset = 0;
        while (offset < before.Length)
        {
            int read = RandomAccess.Read(handle, content.AsSpan(checked((int)offset)), offset);
            if (read == 0)
            {
                throw new EndOfStreamException($"'{relativePath}' ended during stable-handle capture.");
            }
            offset += read;
        }
        NativeFacts after = GetNativeFacts(handle, fullPath);
        if (!before.SameObject(after) || before.Length != after.Length || before.LinkCount != after.LinkCount)
        {
            throw new IOException($"'{relativePath}' changed during stable-handle capture.");
        }
        return content;
    }

    public static GraphKitAuthCopyEvidence CopyFileCreateNew(
        string sourceRoot,
        string sourceRelativePath,
        string destinationRoot,
        string destinationRelativePath,
        bool requireInitialOwnerOnly = false,
        long maximumLength = long.MaxValue)
        => CopyFileCreateNew(
            sourceRoot,
            sourceRelativePath,
            destinationRoot,
            destinationRelativePath,
            requireInitialOwnerOnly,
            maximumLength,
            simulatePostCreateFailure: false);

    public static GraphKitAuthCopyEvidence CopyFileCreateNew(
        string sourceRoot,
        string sourceRelativePath,
        string destinationRoot,
        string destinationRelativePath,
        bool requireInitialOwnerOnly,
        long maximumLength,
        bool simulatePostCreateFailure)
    {
        string sourcePath = ResolveRelative(sourceRoot, sourceRelativePath);
        string destinationPath = ResolveRelative(destinationRoot, destinationRelativePath);
        EnsureAncestors(sourceRoot, sourceRelativePath);
        EnsureAncestors(destinationRoot, destinationRelativePath);

        using SafeFileHandle sourceHandle = OpenReadNoFollow(sourcePath, directory: false);
        NativeFacts sourceBefore = GetNativeFacts(sourceHandle, sourcePath);
        if (!sourceBefore.IsRegularFile || sourceBefore.IsReparsePoint)
        {
            throw new IOException($"Source '{sourceRelativePath}' is not one regular no-follow file.");
        }
        if (maximumLength < 0 || sourceBefore.Length > maximumLength)
        {
            throw new IOException($"Source '{sourceRelativePath}' exceeds its bounded capture length.");
        }

        using FileStream destinationStream = OpenDestinationCreateNew(
            destinationPath, requireInitialOwnerOnly);
        SafeFileHandle destinationHandle = destinationStream.SafeFileHandle;
        try
        {
            if (simulatePostCreateFailure)
            {
                RandomAccess.Write(destinationHandle, new byte[] { 0xA5 }, 0);
                RandomAccess.FlushToDisk(destinationHandle);
                throw new IOException("Injected post-create copy failure after a partial write.");
            }
            GraphKitAuthPathEvidence destinationInitial = EvidenceFromHandle(
                destinationHandle, destinationPath, destinationRelativePath, expectDirectory: false);
            if (requireInitialOwnerOnly && !HasInitialOwnerOnlyAccess(destinationInitial))
            {
                throw new IOException($"New destination '{destinationRelativePath}' did not begin with owner-only access.");
            }
            SetOwnerOnlyWritableFile(destinationStream, destinationPath);
            byte[] buffer = new byte[131072];
            long offset = 0;
            while (offset < sourceBefore.Length)
            {
                int requested = (int)Math.Min(buffer.Length, sourceBefore.Length - offset);
                int read = RandomAccess.Read(sourceHandle, buffer.AsSpan(0, requested), offset);
                if (read == 0)
                {
                    throw new EndOfStreamException($"Source '{sourceRelativePath}' ended during capture.");
                }
                if (offset > maximumLength - read)
                {
                    throw new IOException($"Source '{sourceRelativePath}' exceeded its bounded capture length.");
                }
                RandomAccess.Write(destinationHandle, buffer.AsSpan(0, read), offset);
                offset += read;
            }
            RandomAccess.FlushToDisk(destinationHandle);

            NativeFacts sourceAfter = GetNativeFacts(sourceHandle, sourcePath);
            if (!sourceBefore.SameObject(sourceAfter) || sourceBefore.Length != sourceAfter.Length)
            {
                throw new IOException($"Source '{sourceRelativePath}' changed while it was being captured.");
            }

            GraphKitAuthPathEvidence sourceEvidence = EvidenceFromHandle(
                sourceHandle, sourcePath, sourceRelativePath, expectDirectory: false);
            GraphKitAuthPathEvidence destinationEvidence = EvidenceFromHandle(
                destinationHandle, destinationPath, destinationRelativePath, expectDirectory: false);
            if (!string.Equals(sourceEvidence.Sha256, destinationEvidence.Sha256, StringComparison.Ordinal) ||
                sourceEvidence.Length != destinationEvidence.Length)
            {
                throw new IOException($"Captured destination '{destinationRelativePath}' does not match its source.");
            }

            return new GraphKitAuthCopyEvidence
            {
                Source = sourceEvidence,
                DestinationInitial = destinationInitial,
                Destination = destinationEvidence
            };
        }
        catch (Exception primaryFailure)
        {
            HandleCreateNewFailure(
                destinationHandle,
                destinationRelativePath,
                operation: "Copying",
                primaryFailure: primaryFailure);
            throw;
        }
    }

    private static void HandleCreateNewFailure(
        SafeFileHandle destinationHandle,
        string destinationRelativePath,
        string operation,
        Exception primaryFailure)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                MarkExactWindowsHandleForDeletion(destinationHandle, destinationRelativePath);
                return;
            }

            RandomAccess.SetLength(destinationHandle, 0);
            RandomAccess.FlushToDisk(destinationHandle);
        }
        catch (Exception cleanupFailure)
        {
            throw new IOException(
                $"{operation} '{destinationRelativePath}' failed and exact live-handle cleanup also failed; " +
                $"no path deletion was attempted. Cleanup failure: {cleanupFailure.Message} " +
                $"Original failure: {primaryFailure.Message}",
                new AggregateException(primaryFailure, cleanupFailure));
        }

        if (!OperatingSystem.IsWindows())
        {
            throw new IOException(
                $"{operation} '{destinationRelativePath}' failed. Unix has no portable exact-handle " +
                "path-deletion primitive, so GraphKit.Auth truncated and flushed only its exact " +
                "create-new object and did not delete any path. Inspect and explicitly recover the " +
                $"zero-byte collision. Original failure: {primaryFailure.Message}",
                primaryFailure);
        }
    }

    private static void MarkExactWindowsHandleForDeletion(
        SafeFileHandle destinationHandle,
        string destinationRelativePath)
    {
        if (!GetFileInformationByHandle(destinationHandle, out ByHandleFileInformation info))
        {
            throw new IOException(
                $"Could not inspect the exact create-new destination '{destinationRelativePath}' " +
                $"before handle-bound deletion (Win32 {Marshal.GetLastWin32Error()}).");
        }
        bool directory = (info.FileAttributes & 0x10) != 0;
        bool reparse = (info.FileAttributes & FileAttributeReparsePoint) != 0;
        if (directory || reparse || info.NumberOfLinks != 1)
        {
            throw new IOException(
                $"The exact create-new destination '{destinationRelativePath}' changed type or link count; " +
                "handle-bound deletion was refused.");
        }

        FileDispositionInfo disposition = new() { DeleteFile = 1 };
        if (!SetFileInformationByHandle(
            destinationHandle,
            FileDispositionInfoClass,
            ref disposition,
            (uint)Marshal.SizeOf<FileDispositionInfo>()))
        {
            throw new IOException(
                $"Could not mark the exact create-new destination '{destinationRelativePath}' for " +
                $"handle-bound deletion (Win32 {Marshal.GetLastWin32Error()}).");
        }
    }

    public static GraphKitAuthWriteEvidence WriteFileCreateNew(
        string destinationRoot,
        string destinationRelativePath,
        byte[] content,
        bool requireInitialOwnerOnly = false)
        => WriteFileCreateNew(
            destinationRoot,
            destinationRelativePath,
            content,
            requireInitialOwnerOnly,
            simulatePostCreateFailure: false);

    public static GraphKitAuthWriteEvidence WriteFileCreateNew(
        string destinationRoot,
        string destinationRelativePath,
        byte[] content,
        bool requireInitialOwnerOnly,
        bool simulatePostCreateFailure)
    {
        ArgumentNullException.ThrowIfNull(content);
        string destinationPath = ResolveRelative(destinationRoot, destinationRelativePath);
        EnsureAncestors(destinationRoot, destinationRelativePath);

        using FileStream destinationStream = OpenDestinationCreateNew(
            destinationPath, requireInitialOwnerOnly);
        SafeFileHandle destinationHandle = destinationStream.SafeFileHandle;
        try
        {
            if (simulatePostCreateFailure)
            {
                RandomAccess.Write(destinationHandle, new byte[] { 0xA5 }, 0);
                RandomAccess.FlushToDisk(destinationHandle);
                throw new IOException("Injected post-create write failure after a partial write.");
            }
            GraphKitAuthPathEvidence destinationInitial = EvidenceFromHandle(
                destinationHandle, destinationPath, destinationRelativePath, expectDirectory: false);
            if (requireInitialOwnerOnly && !HasInitialOwnerOnlyAccess(destinationInitial))
            {
                throw new IOException($"New destination '{destinationRelativePath}' did not begin with owner-only access.");
            }
            SetOwnerOnlyWritableFile(destinationStream, destinationPath);
            RandomAccess.Write(destinationHandle, content, 0);
            RandomAccess.FlushToDisk(destinationHandle);
            GraphKitAuthPathEvidence destination = EvidenceFromHandle(
                destinationHandle, destinationPath, destinationRelativePath, expectDirectory: false);
            string expectedHash = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
            if (destination.Length != content.LongLength ||
                !string.Equals(destination.Sha256, expectedHash, StringComparison.Ordinal))
            {
                throw new IOException($"Written destination '{destinationRelativePath}' does not match its supplied bytes.");
            }
            return new GraphKitAuthWriteEvidence
            {
                DestinationInitial = destinationInitial,
                Destination = destination
            };
        }
        catch (Exception primaryFailure)
        {
            HandleCreateNewFailure(
                destinationHandle,
                destinationRelativePath,
                operation: "Writing",
                primaryFailure: primaryFailure);
            throw;
        }
    }

    public static void SetOwnerOnly(string absolutePath, bool directory, bool writable)
    {
        string path = Path.GetFullPath(absolutePath);
        if (OperatingSystem.IsWindows())
        {
            SetOwnerOnlyWindows(path, directory, writable);
            return;
        }

        UnixFileMode mode = directory
            ? (writable
                ? UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                : UnixFileMode.UserRead | UnixFileMode.UserExecute)
            : (writable
                ? UnixFileMode.UserRead | UnixFileMode.UserWrite
                : UnixFileMode.UserRead);
        File.SetUnixFileMode(path, mode);
    }

    private static void SetOwnerOnlyWritableFile(
        FileStream stream,
        string absolutePath)
    {
        if (OperatingSystem.IsWindows())
        {
            FileSecurity security = (FileSecurity)CreateOwnerOnlyWindowsSecurity(
                directory: false, writable: true, setOwner: true);
            FileSystemAclExtensions.SetAccessControl(stream, security);
            return;
        }

        SafeFileHandle handle = stream.SafeFileHandle;
        const uint mode = 0x180u; // 0600
        if (fchmod(handle.DangerousGetHandle().ToInt32(), mode) != 0)
        {
            throw new IOException(
                $"Could not set exact-handle owner-only access on '{absolutePath}' " +
                $"(errno {Marshal.GetLastWin32Error()}).");
        }
    }

    public static void MoveDirectoryCreateNew(string sourcePath, string destinationPath)
        => MoveDirectoryCreateNew(sourcePath, destinationPath, simulateLinuxRenameUnavailable: false);

    public static void MoveDirectoryCreateNew(
        string sourcePath,
        string destinationPath,
        bool simulateLinuxRenameUnavailable)
    {
        string source = Path.GetFullPath(sourcePath);
        string destination = Path.GetFullPath(destinationPath);
        string sourceParent = Path.GetDirectoryName(source);
        string destinationParent = Path.GetDirectoryName(destination);
        if (string.IsNullOrWhiteSpace(sourceParent) || string.IsNullOrWhiteSpace(destinationParent))
        {
            throw new IOException("The atomic directory move requires physical parent directories.");
        }
        if (!string.Equals(Path.GetPathRoot(source), Path.GetPathRoot(destination),
                OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
        {
            throw new IOException("The atomic directory move must remain on one filesystem root.");
        }

        using (SafeFileHandle sourceHandle = OpenReadNoFollow(source, directory: true))
        using (SafeFileHandle sourceParentHandle = OpenReadNoFollow(sourceParent, directory: true))
        using (SafeFileHandle destinationParentHandle = OpenReadNoFollow(destinationParent, directory: true))
        {
            NativeFacts sourceFacts = GetNativeFacts(sourceHandle, source);
            NativeFacts sourceParentFacts = GetNativeFacts(sourceParentHandle, sourceParent);
            NativeFacts destinationParentFacts = GetNativeFacts(destinationParentHandle, destinationParent);
            if (!sourceFacts.IsDirectory || sourceFacts.IsReparsePoint ||
                !sourceParentFacts.IsDirectory || sourceParentFacts.IsReparsePoint ||
                !destinationParentFacts.IsDirectory || destinationParentFacts.IsReparsePoint)
            {
                throw new IOException("The atomic directory move requires physical no-follow directories.");
            }
        }

        int error;
        if (OperatingSystem.IsWindows())
        {
            if (MoveFileExW(
                ToExtendedWindowsPath(source),
                ToExtendedWindowsPath(destination),
                0))
            {
                return;
            }
            error = Marshal.GetLastWin32Error();
            if (error == 80 || error == 183)
            {
                throw new IOException(
                    $"GraphKit.Auth atomic destination collision: '{destination}' already exists; " +
                    "source and destination were not changed.");
            }
            throw new IOException($"Could not atomically install '{destination}' without replacement (Win32 {error}).");
        }

        if (OperatingSystem.IsMacOS())
        {
            int macResult = renamex_np(source, destination, 0x00000004);
            if (macResult != 0)
            {
                error = Marshal.GetLastWin32Error();
                if (error == 17)
                {
                    throw new IOException(
                        $"GraphKit.Auth atomic destination collision: '{destination}' already exists; " +
                        "source and destination were not changed.");
                }
                throw new IOException(
                    $"Could not atomically install '{destination}' with macOS renamex_np RENAME_EXCL " +
                    $"(errno {error}); no fallback was attempted.");
            }
            return;
        }

        int result;
        try
        {
            if (simulateLinuxRenameUnavailable)
            {
                throw new EntryPointNotFoundException("Injected renameat2 unavailability.");
            }
            result = renameat2(-100, source, -100, destination, 0x00000001);
        }
        catch (EntryPointNotFoundException exception)
        {
            throw new IOException(
                "Linux renameat2 RENAME_NOREPLACE is unavailable; no fallback was attempted and the destination was not mutated.",
                exception);
        }
        catch (DllNotFoundException exception)
        {
            throw new IOException(
                "Linux renameat2 RENAME_NOREPLACE is unavailable because libc could not be loaded; " +
                "no fallback was attempted and the destination was not mutated.",
                exception);
        }
        if (result != 0)
        {
            error = Marshal.GetLastWin32Error();
            if (error == 17)
            {
                throw new IOException(
                    $"GraphKit.Auth atomic destination collision: '{destination}' already exists; " +
                    "source and destination were not changed.");
            }
            if (error == 38 || error == 22) // ENOSYS or EINVAL: unavailable runtime/filesystem primitive.
            {
                throw new IOException(
                    $"Linux renameat2 RENAME_NOREPLACE is unavailable or unsupported (errno {error}); " +
                    "no fallback was attempted and the destination was not mutated.");
            }
            throw new IOException(
                $"Could not atomically install '{destination}' with Linux renameat2 RENAME_NOREPLACE " +
                $"(errno {error}); no fallback was attempted.");
        }
    }

    private static GraphKitAuthPathEvidence Inspect(
        string rootPath,
        string relativePath,
        bool expectDirectory,
        bool hashContent)
    {
        string fullPath = ResolveRelative(rootPath, relativePath);
        EnsureAncestors(rootPath, relativePath);
        using SafeFileHandle handle = OpenReadNoFollow(fullPath, expectDirectory);
        return EvidenceFromHandle(
            handle, fullPath, relativePath, expectDirectory, hashContent);
    }

    private static GraphKitAuthPathEvidence EvidenceFromHandle(
        SafeFileHandle handle,
        string fullPath,
        string relativePath,
        bool expectDirectory,
        bool hashContent = true)
    {
        NativeFacts before = GetNativeFacts(handle, fullPath);
        if (before.IsDirectory != expectDirectory ||
            (!expectDirectory && !before.IsRegularFile) ||
            before.IsReparsePoint)
        {
            throw new IOException($"'{relativePath}' is not the required no-follow {(expectDirectory ? "directory" : "regular file")}.");
        }

        string hash = string.Empty;
        if (!expectDirectory && hashContent)
        {
            hash = HashHandle(handle, before.Length);
        }

        NativeFacts after = GetNativeFacts(handle, fullPath);
        if (!before.SameObject(after) ||
            (!expectDirectory && (before.Length != after.Length || before.LinkCount != after.LinkCount)))
        {
            throw new IOException($"'{relativePath}' changed while its stable handle was inspected.");
        }

        return new GraphKitAuthPathEvidence
        {
            RelativePath = relativePath.Replace('\\', '/'),
            PhysicalPath = after.PhysicalPath,
            NativeIdentity = after.Identity,
            Sha256 = hash,
            Length = after.Length,
            LinkCount = after.LinkCount,
            UnixMode = after.UnixMode,
            OwnerUid = after.OwnerUid,
            EffectiveUid = after.EffectiveUid,
            PermissionEvidence = after.PermissionEvidence,
            IsDirectory = after.IsDirectory,
            IsRegularFile = after.IsRegularFile,
            IsReparsePoint = after.IsReparsePoint,
            OwnerWritable = after.OwnerWritable,
            OwnerSid = after.OwnerSid,
            CurrentIdentitySid = after.CurrentIdentitySid,
            CurrentOwnerSid = after.CurrentOwnerSid,
            AccessRulesProtected = after.AccessRulesProtected,
            HasInheritedAccessRules = after.HasInheritedAccessRules,
            OwnerOnlyAccess = after.OwnerOnlyAccess,
            ExactOwnerOnlyAccess = after.ExactOwnerOnlyAccess,
            ExactWritableOwnerOnlyDirectoryAccess = after.ExactWritableOwnerOnlyDirectoryAccess,
            FileReadOnly = after.FileReadOnly
        };
    }

    private static string HashHandle(SafeFileHandle handle, long length)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[131072];
        long offset = 0;
        while (offset < length)
        {
            int requested = (int)Math.Min(buffer.Length, length - offset);
            int read = RandomAccess.Read(handle, buffer.AsSpan(0, requested), offset);
            if (read == 0)
            {
                throw new EndOfStreamException("A file ended while its stable handle was being hashed.");
            }
            hash.AppendData(buffer, 0, read);
            offset += read;
        }
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private static string ResolveRelative(string rootPath, string relativePath)
    {
        if (string.IsNullOrWhiteSpace(rootPath) || string.IsNullOrWhiteSpace(relativePath))
        {
            throw new ArgumentException("Root and relative paths are required.");
        }
        if (Path.IsPathRooted(relativePath) || relativePath.Contains('\\'))
        {
            throw new IOException($"Relative path '{relativePath}' is unsafe.");
        }
        string[] segments = relativePath.Split('/');
        foreach (string segment in segments)
        {
            if (string.IsNullOrWhiteSpace(segment) || segment is "." or ".." ||
                !segment.IsNormalized(NormalizationForm.FormC))
            {
                throw new IOException($"Relative path '{relativePath}' is unsafe or not NFC-normalized.");
            }
        }

        string root = Path.GetFullPath(rootPath);
        string combined = Path.GetFullPath(Path.Combine(root, Path.Combine(segments)));
        StringComparison comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        string prefix = root.EndsWith(Path.DirectorySeparatorChar)
            ? root
            : root + Path.DirectorySeparatorChar;
        if (!combined.StartsWith(prefix, comparison))
        {
            throw new IOException($"Relative path '{relativePath}' escapes its root.");
        }
        return combined;
    }

    private static void EnsureAncestors(string rootPath, string relativePath)
    {
        string root = Path.GetFullPath(rootPath);
        using (SafeFileHandle rootHandle = OpenReadNoFollow(root, directory: true))
        {
            NativeFacts rootFacts = GetNativeFacts(rootHandle, root);
            if (!rootFacts.IsDirectory || rootFacts.IsReparsePoint)
            {
                throw new IOException($"Root '{root}' is not a physical no-follow directory.");
            }
        }

        string[] segments = relativePath.Split('/');
        string current = root;
        for (int index = 0; index < segments.Length - 1; index++)
        {
            current = Path.Combine(current, segments[index]);
            using SafeFileHandle handle = OpenReadNoFollow(current, directory: true);
            NativeFacts facts = GetNativeFacts(handle, current);
            if (!facts.IsDirectory || facts.IsReparsePoint)
            {
                throw new IOException($"Ancestor '{segments[index]}' is not one physical directory.");
            }
        }
    }

    private static SafeFileHandle OpenReadNoFollow(string fullPath, bool directory)
    {
        if (OperatingSystem.IsWindows())
        {
            SafeFileHandle handle = CreateFileW(
                ToExtendedWindowsPath(fullPath),
                GenericRead,
                ShareRead | ShareWrite | ShareDelete,
                IntPtr.Zero,
                OpenExisting,
                FileFlagOpenReparsePoint | (directory ? FileFlagBackupSemantics : 0),
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new IOException($"Could not open '{fullPath}' without following a reparse point (Win32 {error}).");
            }
            return handle;
        }

        int noFollow = OperatingSystem.IsMacOS() ? 0x00000100 : 0x00020000;
        int directoryFlag = OperatingSystem.IsMacOS() ? 0x00100000 : 0x00010000;
        int closeOnExec = OperatingSystem.IsMacOS() ? 0x01000000 : 0x00080000;
        int fd = open(fullPath, noFollow | closeOnExec | (directory ? directoryFlag : 0));
        if (fd < 0)
        {
            throw new IOException($"Could not open '{fullPath}' without following a link (errno {Marshal.GetLastWin32Error()}).");
        }
        return new SafeFileHandle((IntPtr)fd, ownsHandle: true);
    }

    private static FileStream OpenDestinationCreateNew(
        string destinationPath,
        bool requireInitialOwnerOnly)
    {
        if (OperatingSystem.IsWindows())
        {
            SafeFileHandle handle;
            if (requireInitialOwnerOnly)
            {
                FileSecurity security = new();
                SecurityIdentifier currentIdentity = WindowsIdentity.GetCurrent().User
                    ?? throw new IOException("The current Windows identity has no SID.");
                SecurityIdentifier owner = GetCurrentTokenOwnerSid();
                security.SetOwner(owner);
                security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                security.AddAccessRule(new FileSystemAccessRule(
                    currentIdentity,
                    FileSystemRights.FullControl,
                    InheritanceFlags.None,
                    PropagationFlags.None,
                    AccessControlType.Allow));
                byte[] descriptor = security.GetSecurityDescriptorBinaryForm();
                GCHandle pinnedDescriptor = GCHandle.Alloc(descriptor, GCHandleType.Pinned);
                try
                {
                    SecurityAttributes attributes = new()
                    {
                        Length = Marshal.SizeOf<SecurityAttributes>(),
                        SecurityDescriptor = pinnedDescriptor.AddrOfPinnedObject(),
                        InheritHandle = 0
                    };
                    handle = CreateFileWithSecurityW(
                        ToExtendedWindowsPath(destinationPath),
                        GenericRead | GenericWrite | DeleteAccess | WriteDacAccess | WriteOwnerAccess,
                        ShareRead,
                        ref attributes,
                        CreateNew,
                        FileAttributeNormal | FileFlagWriteThrough,
                        IntPtr.Zero);
                }
                finally
                {
                    pinnedDescriptor.Free();
                }
            }
            else
            {
                handle = CreateFileW(
                    ToExtendedWindowsPath(destinationPath),
                    GenericRead | GenericWrite | DeleteAccess | WriteDacAccess | WriteOwnerAccess,
                    ShareRead,
                    IntPtr.Zero,
                    CreateNew,
                    FileAttributeNormal | FileFlagWriteThrough,
                    IntPtr.Zero);
            }
            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                if (error == 80 || error == 183)
                {
                    throw new IOException(
                        requireInitialOwnerOnly
                            ? "Atomic owner-only file destination collision."
                            : "Atomic file destination collision.");
                }
                throw new IOException(
                    requireInitialOwnerOnly
                        ? $"Could not atomically create owner-only destination file (Win32 {error})."
                        : $"Could not atomically create destination file (Win32 {error}).");
            }
            try
            {
                return new FileStream(handle, FileAccess.ReadWrite, bufferSize: 4096, isAsync: false);
            }
            catch (Exception primaryFailure)
            {
                try
                {
                    MarkExactWindowsHandleForDeletion(
                        handle,
                        Path.GetFileName(destinationPath));
                }
                catch (Exception cleanupFailure)
                {
                    throw new IOException(
                        "Wrapping the exact Windows create-new handle failed and handle-bound " +
                        $"cleanup also failed; no path deletion was attempted. Cleanup failure: " +
                        $"{cleanupFailure.Message} Original failure: {primaryFailure.Message}",
                        new AggregateException(primaryFailure, cleanupFailure));
                }
                finally
                {
                    handle.Dispose();
                }
                throw;
            }
        }

        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.ReadWrite,
            Share = FileShare.Read,
            Options = FileOptions.WriteThrough
        };
        options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        return new FileStream(destinationPath, options);
    }

    private static NativeFacts GetNativeFacts(SafeFileHandle handle, string path)
    {
        if (OperatingSystem.IsWindows())
        {
            if (!GetFileInformationByHandle(handle, out ByHandleFileInformation info))
            {
                throw new IOException($"Could not inspect '{path}' (Win32 {Marshal.GetLastWin32Error()}).");
            }
            uint type = info.FileAttributes;
            bool directory = (type & 0x10) != 0;
            bool reparse = (type & FileAttributeReparsePoint) != 0;
            long windowsLength = ((long)info.FileSizeHigh << 32) | info.FileSizeLow;
            string identity = $"{info.VolumeSerialNumber:x8}:{info.FileIndexHigh:x8}{info.FileIndexLow:x8}";
            string physical = GetWindowsPhysicalPath(handle);
            WindowsPermissionFacts permissions = GetWindowsPermissionFacts(
                handle, directory, info.FileAttributes);
            return new NativeFacts(identity, physical, windowsLength, info.NumberOfLinks, 0, 0, 0, directory,
                !directory && !reparse, reparse, permissions.OwnerWritable, permissions.Sddl,
                permissions.OwnerSid, permissions.CurrentIdentitySid, permissions.CurrentOwnerSid,
                permissions.AccessRulesProtected,
                permissions.HasInheritedAccessRules, permissions.OwnerOnlyAccess,
                permissions.ExactOwnerOnlyAccess,
                permissions.ExactWritableOwnerOnlyDirectoryAccess,
                permissions.FileReadOnly);
        }

        byte[] stat = new byte[256];
        if (InvokeUnixFStat(handle.DangerousGetHandle().ToInt32(), stat, path) != 0)
        {
            throw new IOException($"Could not fstat '{path}' (errno {Marshal.GetLastWin32Error()}).");
        }

        ulong device;
        ulong inode;
        ulong links;
        uint mode;
        uint ownerUid;
        long length;
        if (OperatingSystem.IsMacOS())
        {
            device = BitConverter.ToUInt32(stat, 0);
            mode = BitConverter.ToUInt16(stat, 4);
            links = BitConverter.ToUInt16(stat, 6);
            inode = BitConverter.ToUInt64(stat, 8);
            ownerUid = BitConverter.ToUInt32(stat, 16);
            length = BitConverter.ToInt64(stat, 96);
        }
        else if (OperatingSystem.IsLinux() &&
            RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
        {
            // glibc's generic 64-bit Linux stat ABI (used by AArch64) places
            // mode/nlink immediately after the 64-bit device and inode fields.
            device = BitConverter.ToUInt64(stat, 0);
            inode = BitConverter.ToUInt64(stat, 8);
            mode = BitConverter.ToUInt32(stat, 16);
            links = BitConverter.ToUInt32(stat, 20);
            ownerUid = BitConverter.ToUInt32(stat, 24);
            length = BitConverter.ToInt64(stat, 48);
        }
        else if (OperatingSystem.IsLinux() &&
            RuntimeInformation.ProcessArchitecture == Architecture.X64)
        {
            device = BitConverter.ToUInt64(stat, 0);
            inode = BitConverter.ToUInt64(stat, 8);
            links = BitConverter.ToUInt64(stat, 16);
            mode = BitConverter.ToUInt32(stat, 24);
            ownerUid = BitConverter.ToUInt32(stat, 28);
            length = BitConverter.ToInt64(stat, 48);
        }
        else
        {
            throw new PlatformNotSupportedException(
                $"GraphKit.Auth stage capture does not define a native stat layout for '{RuntimeInformation.OSDescription}' on '{RuntimeInformation.ProcessArchitecture}'.");
        }
        uint fileType = mode & 0xF000;
        bool isDirectory = fileType == 0x4000;
        bool isRegular = fileType == 0x8000;
        bool isLink = fileType == 0xA000;
        int unixMode = (int)(mode & 0x0FFF);
        uint effectiveUid = geteuid();
        string unixIdentity = $"{device:x}:{inode:x}";
        string physicalPath = GetUnixPhysicalPath(path, unixIdentity, isDirectory);
        return new NativeFacts(
            unixIdentity,
            physicalPath,
            length,
            checked((long)links),
            unixMode,
            ownerUid,
            effectiveUid,
            isDirectory,
            isRegular,
            isLink,
            (unixMode & 0x80) != 0,
            Convert.ToString(unixMode, 8).PadLeft(4, '0'),
            string.Empty, string.Empty, string.Empty, false, false, false, false, false, false);
    }

    private static string GetUnixPhysicalPath(string path, string expectedIdentity, bool directory)
    {
        IntPtr resolvedPointer = realpath(path, IntPtr.Zero);
        if (resolvedPointer == IntPtr.Zero)
        {
            throw new IOException($"Could not resolve physical path '{path}' (errno {Marshal.GetLastWin32Error()}).");
        }
        string resolved;
        try
        {
            resolved = Marshal.PtrToStringUTF8(resolvedPointer)
                ?? throw new IOException($"Could not decode physical path '{path}'.");
        }
        finally
        {
            free(resolvedPointer);
        }

        using SafeFileHandle rebound = OpenReadNoFollow(path, directory);
        byte[] stat = new byte[256];
        if (InvokeUnixFStat(rebound.DangerousGetHandle().ToInt32(), stat, path) != 0)
        {
            throw new IOException($"Could not rebind physical path '{path}' (errno {Marshal.GetLastWin32Error()}).");
        }
        ulong device = OperatingSystem.IsMacOS() ? BitConverter.ToUInt32(stat, 0) : BitConverter.ToUInt64(stat, 0);
        ulong inode = BitConverter.ToUInt64(stat, 8);
        string reboundIdentity = $"{device:x}:{inode:x}";
        if (!string.Equals(expectedIdentity, reboundIdentity, StringComparison.Ordinal))
        {
            throw new IOException($"Path '{path}' changed while its physical identity was resolved.");
        }
        return resolved;
    }

    private static int InvokeUnixFStat(int descriptor, byte[] stat, string path)
    {
        try
        {
            if (OperatingSystem.IsMacOS())
            {
                return RuntimeInformation.ProcessArchitecture switch
                {
                    Architecture.Arm64 => fstat(descriptor, stat),
                    Architecture.X64 => fstat_inode64(descriptor, stat),
                    _ => throw new PlatformNotSupportedException(
                        $"GraphKit.Auth stage capture does not define a macOS fstat ABI for '{RuntimeInformation.ProcessArchitecture}'.")
                };
            }
            if (!OperatingSystem.IsLinux())
            {
                throw new PlatformNotSupportedException(
                    $"GraphKit.Auth stage capture cannot inspect Unix metadata on '{RuntimeInformation.OSDescription}'.");
            }
            try
            {
                return fstat(descriptor, stat);
            }
            catch (EntryPointNotFoundException modernException)
            {
                int compatibilityVersion = RuntimeInformation.ProcessArchitecture switch
                {
                    Architecture.X64 => 1,
                    Architecture.Arm64 => 0,
                    _ => throw new PlatformNotSupportedException(
                        $"GraphKit.Auth stage capture does not define a glibc fstat compatibility ABI for '{RuntimeInformation.ProcessArchitecture}'.",
                        modernException)
                };
                try
                {
                    return fxstat(compatibilityVersion, descriptor, stat);
                }
                catch (EntryPointNotFoundException compatibilityException)
                {
                    throw new PlatformNotSupportedException(
                        "GraphKit.Auth stage capture requires either the libc fstat or __fxstat entry point.",
                        new AggregateException(modernException, compatibilityException));
                }
            }
        }
        catch (EntryPointNotFoundException exception)
        {
            throw new PlatformNotSupportedException(
                $"GraphKit.Auth stage capture requires the libc fstat entry point to inspect '{path}'.",
                exception);
        }
    }

    private static string GetWindowsPhysicalPath(SafeFileHandle handle)
    {
        var builder = new StringBuilder(32768);
        uint length = GetFinalPathNameByHandleW(handle, builder, (uint)builder.Capacity, 0);
        if (length == 0 || length >= builder.Capacity)
        {
            throw new IOException($"Could not resolve the opened Windows path (Win32 {Marshal.GetLastWin32Error()}).");
        }
        return NormalizeWindowsPhysicalPath(builder.ToString());
    }

    private static string NormalizeWindowsPhysicalPath(string value)
    {
        const string extendedUncPrefix = @"\\?\UNC\";
        if (value.StartsWith(extendedUncPrefix, StringComparison.Ordinal))
        {
            return @"\\" + value.Substring(extendedUncPrefix.Length);
        }
        return value.StartsWith(@"\\?\", StringComparison.Ordinal) ? value.Substring(4) : value;
    }

    private static string ToExtendedWindowsPath(string value)
    {
        if (value.StartsWith(@"\\.\", StringComparison.Ordinal))
        {
            throw new IOException("A Windows device path is not permitted for native access.");
        }
        if (value.StartsWith(@"\\?\UNC\", StringComparison.Ordinal))
        {
            return value.Length > 8
                ? value
                : throw new IOException("A fully qualified Windows path is required for native access.");
        }
        if (value.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            string extendedValue = value.Substring(4);
            return IsWindowsDriveRooted(extendedValue)
                ? value
                : throw new IOException("A Windows device path is not permitted for native access.");
        }
        if (value.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return @"\\?\UNC\" + value.Substring(2);
        }
        if (IsWindowsDriveRooted(value))
        {
            return @"\\?\" + value;
        }
        throw new IOException("A fully qualified Windows path is required for native access.");
    }

    private static bool IsWindowsDriveRooted(string value) =>
        value.Length >= 3 && char.IsAsciiLetter(value[0]) &&
        value[1] == ':' && value[2] == '\\';

    private static SecurityIdentifier GetCurrentTokenOwnerSid()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        bool initialResult = GetTokenInformation(
            identity.Token,
            TokenOwner,
            IntPtr.Zero,
            0,
            out uint requiredLength);
        int initialError = Marshal.GetLastWin32Error();
        if (initialResult || initialError != ErrorInsufficientBuffer || requiredLength == 0 ||
            requiredLength > MaxTokenOwnerInformationLength)
        {
            throw new IOException(
                $"Could not determine the current Windows token owner size (Win32 {initialError}).");
        }

        IntPtr buffer = Marshal.AllocHGlobal(checked((int)requiredLength));
        try
        {
            if (!GetTokenInformation(
                identity.Token,
                TokenOwner,
                buffer,
                requiredLength,
                out uint returnedLength))
            {
                throw new IOException(
                    $"Could not read the current Windows token owner (Win32 {Marshal.GetLastWin32Error()}).");
            }
            if (returnedLength > requiredLength)
            {
                throw new IOException("The current Windows token owner exceeded its bounded buffer.");
            }
            TokenOwnerInformation owner = Marshal.PtrToStructure<TokenOwnerInformation>(buffer);
            if (owner.Owner == IntPtr.Zero)
            {
                throw new IOException("The current Windows token has no default owner SID.");
            }
            return new SecurityIdentifier(owner.Owner);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static WindowsPermissionFacts GetWindowsPermissionFacts(
        SafeFileHandle handle,
        bool directory,
        uint fileAttributes)
    {
        uint status = GetSecurityInfo(
            handle,
            SeFileObject,
            OwnerSecurityInformation | DaclSecurityInformation,
            IntPtr.Zero,
            IntPtr.Zero,
            IntPtr.Zero,
            IntPtr.Zero,
            out IntPtr descriptorPointer);
        using SafeLocalMemoryHandle descriptor = new(descriptorPointer);
        if (status != 0)
        {
            throw new IOException(
                $"Could not inspect the opened Windows object's owner and DACL (Win32 {status}).");
        }
        uint descriptorLength = GetSecurityDescriptorLength(descriptor.DangerousGetHandle());
        if (descriptorLength == 0)
        {
            throw new IOException("The opened Windows object returned an invalid security descriptor.");
        }
        byte[] descriptorBytes = new byte[checked((int)descriptorLength)];
        Marshal.Copy(descriptor.DangerousGetHandle(), descriptorBytes, 0, descriptorBytes.Length);
        FileSystemSecurity security = directory ? new DirectorySecurity() : new FileSecurity();
        security.SetSecurityDescriptorBinaryForm(
            descriptorBytes,
            AccessControlSections.Access | AccessControlSections.Owner);
        SecurityIdentifier currentIdentity = WindowsIdentity.GetCurrent().User
            ?? throw new IOException("The current Windows identity has no SID.");
        SecurityIdentifier currentTokenOwner = GetCurrentTokenOwnerSid();
        SecurityIdentifier owner = (SecurityIdentifier)security.GetOwner(typeof(SecurityIdentifier));
        AuthorizationRuleCollection rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
        FileSystemRights writeMask = FileSystemRights.WriteData | FileSystemRights.AppendData |
            FileSystemRights.WriteExtendedAttributes | FileSystemRights.WriteAttributes |
            FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.Delete |
            FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        FileSystemRights expectedRights =
            FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize;
        bool ownerWritable = false;
        bool hasInheritedAccessRules = false;
        bool ownerOnlyAccess = owner.Equals(currentTokenOwner) && rules.Count >= 1;
        bool exactOwnerOnlyAccess = security.AreAccessRulesProtected &&
            owner.Equals(currentTokenOwner) && rules.Count == 1;
        bool exactWritableOwnerOnlyDirectoryAccess = directory &&
            security.AreAccessRulesProtected && owner.Equals(currentTokenOwner) && rules.Count == 1;
        foreach (FileSystemAccessRule rule in rules)
        {
            hasInheritedAccessRules |= rule.IsInherited;
            ownerOnlyAccess &= rule.IdentityReference.Equals(currentIdentity) &&
                rule.AccessControlType == AccessControlType.Allow;
            if (rule.AccessControlType == AccessControlType.Allow && (rule.FileSystemRights & writeMask) != 0)
            {
                ownerWritable = true;
            }
            exactOwnerOnlyAccess &= rule.IdentityReference.Equals(currentIdentity) &&
                !rule.IsInherited &&
                rule.AccessControlType == AccessControlType.Allow &&
                rule.FileSystemRights == expectedRights &&
                rule.InheritanceFlags == InheritanceFlags.None &&
                rule.PropagationFlags == PropagationFlags.None;
            exactWritableOwnerOnlyDirectoryAccess &= rule.IdentityReference.Equals(currentIdentity) &&
                !rule.IsInherited &&
                rule.AccessControlType == AccessControlType.Allow &&
                rule.FileSystemRights == FileSystemRights.FullControl &&
                rule.InheritanceFlags == (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit) &&
                rule.PropagationFlags == PropagationFlags.None;
        }
        bool fileReadOnly = directory ||
            (fileAttributes & FileAttributeReadOnly) == FileAttributeReadOnly;
        return new WindowsPermissionFacts(
            security.GetSecurityDescriptorSddlForm(AccessControlSections.Access | AccessControlSections.Owner),
            ownerWritable,
            owner.Value,
            currentIdentity.Value,
            currentTokenOwner.Value,
            security.AreAccessRulesProtected,
            hasInheritedAccessRules,
            ownerOnlyAccess,
            exactOwnerOnlyAccess,
            exactWritableOwnerOnlyDirectoryAccess,
            fileReadOnly);
    }

    private static void SetOwnerOnlyWindows(string path, bool directory, bool writable)
    {
        FileSystemSecurity currentSecurity = directory
            ? FileSystemAclExtensions.GetAccessControl(
                new DirectoryInfo(path), AccessControlSections.Owner)
            : FileSystemAclExtensions.GetAccessControl(
                new FileInfo(path), AccessControlSections.Owner);
        SecurityIdentifier currentOwner = (SecurityIdentifier)currentSecurity.GetOwner(
            typeof(SecurityIdentifier));
        SecurityIdentifier currentTokenOwner = GetCurrentTokenOwnerSid();
        if (!currentOwner.Equals(currentTokenOwner))
        {
            throw new IOException(
                $"Owner-only access refused for '{path}' because its owner is not the current Windows token owner.");
        }
        FileSystemSecurity security = CreateOwnerOnlyWindowsSecurity(
            directory, writable, setOwner: false);
        FileAttributes attributes = directory ? default : File.GetAttributes(path);
        if (!directory && !writable &&
            (attributes & FileAttributes.ReadOnly) == 0)
        {
            File.SetAttributes(
                path,
                (attributes & ~FileAttributes.Normal) | FileAttributes.ReadOnly);
        }
        if (directory)
            FileSystemAclExtensions.SetAccessControl(new DirectoryInfo(path), (DirectorySecurity)security);
        else
            FileSystemAclExtensions.SetAccessControl(new FileInfo(path), (FileSecurity)security);
        if (!directory && writable &&
            (attributes & FileAttributes.ReadOnly) != 0)
        {
            FileAttributes writableAttributes = attributes & ~FileAttributes.ReadOnly;
            File.SetAttributes(
                path,
                writableAttributes == 0 ? FileAttributes.Normal : writableAttributes);
        }
    }

    private static FileSystemSecurity CreateOwnerOnlyWindowsSecurity(
        bool directory,
        bool writable,
        bool setOwner)
    {
        SecurityIdentifier currentIdentity = WindowsIdentity.GetCurrent().User
            ?? throw new IOException("The current Windows identity has no SID.");
        SecurityIdentifier owner = GetCurrentTokenOwnerSid();
        FileSystemSecurity security = directory ? new DirectorySecurity() : new FileSecurity();
        if (setOwner)
        {
            security.SetOwner(owner);
        }
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        FileSystemRights rights = writable
            ? FileSystemRights.FullControl
            : FileSystemRights.ReadAndExecute;
        InheritanceFlags inheritance = directory && writable ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None;
        security.AddAccessRule(new FileSystemAccessRule(currentIdentity, rights, inheritance,
            PropagationFlags.None, AccessControlType.Allow));
        return security;
    }

    private sealed class WindowsPermissionFacts
    {
        internal WindowsPermissionFacts(string sddl, bool ownerWritable, string ownerSid,
            string currentIdentitySid, string currentOwnerSid, bool accessRulesProtected,
            bool hasInheritedAccessRules,
            bool ownerOnlyAccess, bool exactOwnerOnlyAccess,
            bool exactWritableOwnerOnlyDirectoryAccess, bool fileReadOnly)
        {
            Sddl = sddl;
            OwnerWritable = ownerWritable;
            OwnerSid = ownerSid;
            CurrentIdentitySid = currentIdentitySid;
            CurrentOwnerSid = currentOwnerSid;
            AccessRulesProtected = accessRulesProtected;
            HasInheritedAccessRules = hasInheritedAccessRules;
            OwnerOnlyAccess = ownerOnlyAccess;
            ExactOwnerOnlyAccess = exactOwnerOnlyAccess;
            ExactWritableOwnerOnlyDirectoryAccess = exactWritableOwnerOnlyDirectoryAccess;
            FileReadOnly = fileReadOnly;
        }
        internal string Sddl { get; }
        internal bool OwnerWritable { get; }
        internal string OwnerSid { get; }
        internal string CurrentIdentitySid { get; }
        internal string CurrentOwnerSid { get; }
        internal bool AccessRulesProtected { get; }
        internal bool HasInheritedAccessRules { get; }
        internal bool OwnerOnlyAccess { get; }
        internal bool ExactOwnerOnlyAccess { get; }
        internal bool ExactWritableOwnerOnlyDirectoryAccess { get; }
        internal bool FileReadOnly { get; }
    }

    private sealed class SafeLocalMemoryHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SafeLocalMemoryHandle(IntPtr handle) : base(ownsHandle: true)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle() => LocalFree(handle) == IntPtr.Zero;
    }

    private sealed class NativeFacts
    {
        internal NativeFacts(string identity, string physicalPath, long length, long linkCount,
            int unixMode, uint ownerUid, uint effectiveUid, bool isDirectory,
            bool isRegularFile, bool isReparsePoint,
            bool ownerWritable, string permissionEvidence, string ownerSid,
            string currentIdentitySid, string currentOwnerSid, bool accessRulesProtected,
            bool hasInheritedAccessRules,
            bool ownerOnlyAccess, bool exactOwnerOnlyAccess,
            bool exactWritableOwnerOnlyDirectoryAccess, bool fileReadOnly)
        {
            Identity = identity;
            PhysicalPath = physicalPath;
            Length = length;
            LinkCount = linkCount;
            UnixMode = unixMode;
            OwnerUid = ownerUid;
            EffectiveUid = effectiveUid;
            IsDirectory = isDirectory;
            IsRegularFile = isRegularFile;
            IsReparsePoint = isReparsePoint;
            OwnerWritable = ownerWritable;
            PermissionEvidence = permissionEvidence;
            OwnerSid = ownerSid;
            CurrentIdentitySid = currentIdentitySid;
            CurrentOwnerSid = currentOwnerSid;
            AccessRulesProtected = accessRulesProtected;
            HasInheritedAccessRules = hasInheritedAccessRules;
            OwnerOnlyAccess = ownerOnlyAccess;
            ExactOwnerOnlyAccess = exactOwnerOnlyAccess;
            ExactWritableOwnerOnlyDirectoryAccess = exactWritableOwnerOnlyDirectoryAccess;
            FileReadOnly = fileReadOnly;
        }
        internal string Identity { get; }
        internal string PhysicalPath { get; }
        internal long Length { get; }
        internal long LinkCount { get; }
        internal int UnixMode { get; }
        internal uint OwnerUid { get; }
        internal uint EffectiveUid { get; }
        internal bool IsDirectory { get; }
        internal bool IsRegularFile { get; }
        internal bool IsReparsePoint { get; }
        internal bool OwnerWritable { get; }
        internal string PermissionEvidence { get; }
        internal string OwnerSid { get; }
        internal string CurrentIdentitySid { get; }
        internal string CurrentOwnerSid { get; }
        internal bool AccessRulesProtected { get; }
        internal bool HasInheritedAccessRules { get; }
        internal bool OwnerOnlyAccess { get; }
        internal bool ExactOwnerOnlyAccess { get; }
        internal bool ExactWritableOwnerOnlyDirectoryAccess { get; }
        internal bool FileReadOnly { get; }
        internal bool SameObject(NativeFacts other) =>
            string.Equals(Identity, other.Identity, StringComparison.Ordinal) &&
            string.Equals(PhysicalPath, other.PhysicalPath,
                OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime { public uint Low; public uint High; }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct FileDispositionInfo
    {
        public byte DeleteFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        public int InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenOwnerInformation
    {
        public IntPtr Owner;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public FileTime CreationTime;
        public FileTime LastAccessTime;
        public FileTime LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string fileName, uint desiredAccess, uint shareMode,
        IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle CreateFileWithSecurityW(string fileName, uint desiredAccess,
        uint shareMode, ref SecurityAttributes securityAttributes, uint creationDisposition,
        uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateDirectoryW(string path, ref SecurityAttributes securityAttributes);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation information);

    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityInfo(
        SafeFileHandle handle,
        int objectType,
        uint securityInfo,
        IntPtr ownerSid,
        IntPtr groupSid,
        IntPtr dacl,
        IntPtr sacl,
        out IntPtr securityDescriptor);

    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityDescriptorLength(IntPtr securityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr token,
        int informationClass,
        IntPtr information,
        uint informationLength,
        out uint returnLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle file,
        int fileInformationClass,
        ref FileDispositionInfo fileInformation,
        uint bufferSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path,
        uint pathLength, uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool MoveFileExW(string existingFileName, string newFileName, uint flags);

    [DllImport("libc", SetLastError = true)]
    private static extern int open(string path, int flags);

    [DllImport("libc", SetLastError = true)]
    private static extern int fchmod(int descriptor, uint mode);

    [DllImport("libc", SetLastError = true)]
    private static extern int fstat(int descriptor, [Out] byte[] stat);

    [DllImport("libc")]
    private static extern uint geteuid();

    [DllImport("libc", EntryPoint = "__fxstat", SetLastError = true)]
    private static extern int fxstat(int version, int descriptor, [Out] byte[] stat);

    [DllImport("libc", EntryPoint = "fstat$INODE64", SetLastError = true)]
    private static extern int fstat_inode64(int descriptor, [Out] byte[] stat);

    [DllImport("libc", SetLastError = true)]
    private static extern int mkdirat(int directory, string path, uint mode);

    [DllImport("libc", SetLastError = true)]
    private static extern IntPtr realpath(string path, IntPtr resolvedPath);

    [DllImport("libc", SetLastError = true)]
    private static extern int renamex_np(string from, string to, uint flags);

    [DllImport("libc", SetLastError = true)]
    private static extern int renameat2(int oldDirectory, string oldPath, int newDirectory, string newPath, uint flags);

    [DllImport("libc")]
    private static extern void free(IntPtr pointer);
}
