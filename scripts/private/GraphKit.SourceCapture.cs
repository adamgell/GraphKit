using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

#nullable enable

namespace __GRAPHKIT_SOURCE_CAPTURE_NAMESPACE__
{
    internal enum SourceEntryKind
    {
        Regular,
        Directory,
        Other
    }

    internal readonly struct SourceMetadata
    {
        internal SourceMetadata(SourceEntryKind kind, string mode, bool hasExecutableMode, string identity, long length)
        {
            Kind = kind;
            Mode = mode;
            HasExecutableMode = hasExecutableMode;
            Identity = identity;
            Length = length;
        }

        internal SourceEntryKind Kind { get; }
        internal string Mode { get; }
        internal bool HasExecutableMode { get; }
        internal string Identity { get; }
        internal long Length { get; }
    }

    public sealed class CapturedSourceFile
    {
        internal CapturedSourceFile(string mode, bool hasExecutableMode, string identity, long length, byte[] content)
        {
            Mode = mode;
            HasExecutableMode = hasExecutableMode;
            Identity = identity;
            Length = length;
            Content = content;
        }

        public string Mode { get; }
        public bool HasExecutableMode { get; }
        public string Identity { get; }
        public long Length { get; }
        public byte[] Content { get; }
    }

    public static class SourceCapture
    {
        private const long MaxSourceEntryBytes = 16L * 1024L * 1024L;

        public static string ResolveEffectiveGitMode(string? capturedMode, bool hasExecutableMode, string? indexMode)
        {
            if (!hasExecutableMode)
            {
                if (indexMode == "100644" || indexMode == "100755")
                {
                    return indexMode;
                }
                return "100644";
            }

            if (string.IsNullOrEmpty(capturedMode))
            {
                throw new ArgumentException("A handle-derived Unix mode is required.", nameof(capturedMode));
            }
            int mode;
            try
            {
                mode = Convert.ToInt32(capturedMode, 8);
            }
            catch (Exception exception) when (exception is FormatException || exception is OverflowException)
            {
                throw new ArgumentException("The handle-derived Unix mode is invalid.", nameof(capturedMode), exception);
            }
            return (mode & 0x40) != 0 ? "100755" : "100644";
        }

        public static CapturedSourceFile Capture(string repositoryRoot, string relativePath)
        {
            if (string.IsNullOrWhiteSpace(repositoryRoot))
            {
                throw new ArgumentException("A repository root is required.", nameof(repositoryRoot));
            }

            string[] segments = ValidateRelativePath(relativePath);
            string root = Path.GetFullPath(repositoryRoot);
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                ValidateWindowsRelativePathForProof(relativePath);
            }
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? CaptureWindows(root, segments)
                : CaptureUnix(root, segments);
        }

        private static string[] ValidateRelativePath(string relativePath)
        {
            if (string.IsNullOrEmpty(relativePath) || Path.IsPathRooted(relativePath) || relativePath.IndexOf('\0') >= 0)
            {
                throw new ArgumentException("The source path must be a non-empty relative Git path.", nameof(relativePath));
            }

            string[] segments = relativePath.Split('/');
            foreach (string segment in segments)
            {
                if (segment.Length == 0 || segment == "." || segment == "..")
                {
                    throw new ArgumentException("The source path contains an unsafe segment.", nameof(relativePath));
                }
            }

            return segments;
        }

        public static void ValidateWindowsRelativePathForProof(string relativePath)
        {
            if (string.IsNullOrEmpty(relativePath) || Path.IsPathRooted(relativePath) || relativePath.IndexOf('\0') >= 0)
            {
                throw new ArgumentException("The Windows proof path must be a non-empty relative Git path.", nameof(relativePath));
            }
            if (relativePath.IndexOf('\\') >= 0 || relativePath.IndexOf(':') >= 0)
            {
                throw new ArgumentException("A Windows Git source path cannot use backslashes, a drive, or an alternate data stream.", nameof(relativePath));
            }

            foreach (string segment in relativePath.Split('/'))
            {
                if (segment.Length == 0 || segment == "." || segment == ".." || segment.EndsWith(' ') || segment.EndsWith('.'))
                {
                    throw new ArgumentException("The Windows Git source path contains an unsafe or aliased segment.", nameof(relativePath));
                }
                foreach (char character in segment)
                {
                    if (character < 32)
                    {
                        throw new ArgumentException("The Windows Git source path contains a control character.", nameof(relativePath));
                    }
                }

                string stem = segment.Split('.')[0];
                if (Regex.IsMatch(stem, @"^(CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                {
                    throw new ArgumentException($"The Windows Git source path segment '{segment}' is a reserved device name.", nameof(relativePath));
                }
                if (Regex.IsMatch(segment, @"^[^ .]{1,6}~[1-9][0-9]*(?:\.[^ .]{1,3})?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                {
                    throw new ArgumentException($"The Windows Git source path segment '{segment}' is ambiguous with an 8.3 short-name alias.", nameof(relativePath));
                }
            }
        }

        private static CapturedSourceFile CaptureUnix(string root, string[] segments)
        {
            int directoryFlags = UnixNative.DirectoryOpenFlags;
            int fileFlags = UnixNative.FileOpenFlags;
            using SafeFileHandle rootHandle = UnixNative.OpenOwned(root, directoryFlags, "repository root");
            SourceMetadata rootMetadata = UnixNative.GetMetadata(rootHandle);
            if (rootMetadata.Kind != SourceEntryKind.Directory)
            {
                throw new IOException("The repository root is not a directory.");
            }

            SafeFileHandle parent = rootHandle;
            SafeFileHandle? ownedParent = null;
            try
            {
                for (int index = 0; index < segments.Length - 1; index++)
                {
                    SafeFileHandle next;
                    try
                    {
                        next = UnixNative.OpenAtOwned(parent, segments[index], directoryFlags, $"source path segment '{segments[index]}'");
                    }
                    catch (Exception exception) when (exception is Win32Exception || exception is IOException)
                    {
                        throw new IOException($"Source path segment '{segments[index]}' is a symbolic link, missing, or not a directory.", exception);
                    }

                    try
                    {
                        SourceMetadata metadata = UnixNative.GetMetadata(next);
                        if (metadata.Kind != SourceEntryKind.Directory)
                        {
                            throw new IOException($"Source path segment '{segments[index]}' is a symbolic link or not a directory.");
                        }
                    }
                    catch
                    {
                        next.Dispose();
                        throw;
                    }

                    ownedParent?.Dispose();
                    ownedParent = next;
                    parent = next;
                }

                SafeFileHandle finalHandle;
                try
                {
                    finalHandle = UnixNative.OpenAtOwned(parent, segments[^1], fileFlags, $"source entry '{segments[^1]}'");
                }
                catch (Win32Exception exception) when (exception.NativeErrorCode == UnixNative.NoSuchFileOrDirectory)
                {
                    throw new FileNotFoundException("The source entry disappeared before it could be opened.", exception);
                }
                catch (Win32Exception exception)
                {
                    throw new IOException($"Source entry '{segments[^1]}' is a symbolic link or cannot be opened without following links.", exception);
                }

                using (finalHandle)
                {
                    return CaptureVerifiedHandle(finalHandle, UnixNative.GetMetadata, segments[^1]);
                }
            }
            finally
            {
                ownedParent?.Dispose();
            }
        }

        private static CapturedSourceFile CaptureWindows(string root, string[] segments)
        {
            using SafeFileHandle rootHandle = WindowsNative.OpenRoot(root);
            SourceMetadata rootMetadata = WindowsNative.GetMetadata(rootHandle);
            if (rootMetadata.Kind != SourceEntryKind.Directory)
            {
                throw new IOException("The repository root is not a directory.");
            }
            if (WindowsNative.IsReparsePoint(rootHandle))
            {
                throw new IOException("The repository root is an unsupported reparse point.");
            }

            SafeFileHandle parent = rootHandle;
            SafeFileHandle? ownedParent = null;
            try
            {
                for (int index = 0; index < segments.Length - 1; index++)
                {
                    SafeFileHandle next = WindowsNative.OpenRelative(parent, segments[index], true);
                    try
                    {
                        if (WindowsNative.IsReparsePoint(next))
                        {
                            throw new IOException($"Source path segment '{segments[index]}' is an unsupported reparse point.");
                        }
                        if (WindowsNative.GetMetadata(next).Kind != SourceEntryKind.Directory)
                        {
                            throw new IOException($"Source path segment '{segments[index]}' is not a directory.");
                        }
                    }
                    catch
                    {
                        next.Dispose();
                        throw;
                    }

                    ownedParent?.Dispose();
                    ownedParent = next;
                    parent = next;
                }

                SafeFileHandle finalHandle;
                try
                {
                    finalHandle = WindowsNative.OpenRelative(parent, segments[^1], false);
                }
                catch (Win32Exception exception) when (exception.NativeErrorCode == WindowsNative.ErrorFileNotFound || exception.NativeErrorCode == WindowsNative.ErrorPathNotFound)
                {
                    throw new FileNotFoundException("The source entry disappeared before it could be opened.", exception);
                }

                using (finalHandle)
                {
                    if (WindowsNative.IsReparsePoint(finalHandle))
                    {
                        throw new IOException($"Source entry '{segments[^1]}' is an unsupported reparse point.");
                    }
                    return CaptureVerifiedHandle(finalHandle, WindowsNative.GetMetadata, segments[^1]);
                }
            }
            finally
            {
                ownedParent?.Dispose();
            }
        }

        private static CapturedSourceFile CaptureVerifiedHandle(
            SafeFileHandle handle,
            Func<SafeFileHandle, SourceMetadata> getMetadata,
            string displayName)
        {
            SourceMetadata before = getMetadata(handle);
            if (before.Kind != SourceEntryKind.Regular)
            {
                throw new IOException($"Source entry '{displayName}' is an unsupported special/non-regular file.");
            }
            if (before.Length < 0 || before.Length > MaxSourceEntryBytes)
            {
                throw new IOException($"Source entry '{displayName}' exceeds the 16 MiB per-entry GraphKit package-source limit; keep generated or binary assets out of package-producing source.");
            }

            byte[] content = ReadExactly(handle, before.Length);
            SourceMetadata after = getMetadata(handle);
            EnsureSameMetadata(before, after, displayName);
            byte[] confirmation = ReadExactly(handle, after.Length);
            SourceMetadata confirmed = getMetadata(handle);
            EnsureSameMetadata(after, confirmed, displayName);
            if (!BytesEqual(content, confirmation))
            {
                throw new IOException($"Source entry '{displayName}' content changed during handle confirmation.");
            }

            return new CapturedSourceFile(before.Mode, before.HasExecutableMode, before.Identity, before.Length, content);
        }

        private static byte[] ReadExactly(SafeFileHandle handle, long length)
        {
            byte[] content = new byte[(int)length];
            int offset = 0;
            while (offset < content.Length)
            {
                int read = RandomAccess.Read(handle, content.AsSpan(offset), offset);
                if (read == 0)
                {
                    throw new EndOfStreamException("The source entry ended before its handle-reported length.");
                }
                offset += read;
            }
            Span<byte> extra = stackalloc byte[1];
            if (RandomAccess.Read(handle, extra, length) != 0)
            {
                throw new IOException("The source entry grew beyond its handle-reported length.");
            }
            return content;
        }

        private static void EnsureSameMetadata(SourceMetadata expected, SourceMetadata actual, string displayName)
        {
            if (expected.Kind != actual.Kind ||
                !string.Equals(expected.Mode, actual.Mode, StringComparison.Ordinal) ||
                expected.HasExecutableMode != actual.HasExecutableMode ||
                !string.Equals(expected.Identity, actual.Identity, StringComparison.Ordinal) ||
                expected.Length != actual.Length)
            {
                throw new IOException($"Source entry '{displayName}' handle metadata changed during capture.");
            }
        }

        private static bool BytesEqual(byte[] left, byte[] right)
        {
            if (left.Length != right.Length)
            {
                return false;
            }
            for (int index = 0; index < left.Length; index++)
            {
                if (left[index] != right[index])
                {
                    return false;
                }
            }
            return true;
        }
    }

    internal static class UnixNative
    {
        private const int LinuxOpenNonBlock = 0x800;
        private const int LinuxOpenDirectory = 0x10000;
        private const int LinuxOpenNoFollow = 0x20000;
        private const int LinuxOpenCloseOnExec = 0x80000;
        private const int DarwinOpenNonBlock = 0x4;
        private const int DarwinOpenNoFollow = 0x100;
        private const int DarwinOpenDirectory = 0x100000;
        private const int DarwinOpenCloseOnExec = 0x1000000;
        private const int AtEmptyPath = 0x1000;
        private const int AtSymlinkNoFollow = 0x100;
        private const uint StatxType = 0x0001;
        private const uint StatxMode = 0x0002;
        private const uint StatxInode = 0x0100;
        private const uint StatxSize = 0x0200;
        private const uint RequiredStatxMask = StatxType | StatxMode | StatxInode | StatxSize;
        private const int FileTypeMask = 0xF000;
        private const int RegularFile = 0x8000;
        private const int Directory = 0x4000;

        internal const int NoSuchFileOrDirectory = 2;

        internal static int DirectoryOpenFlags => RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
            ? DarwinOpenNonBlock | DarwinOpenNoFollow | DarwinOpenDirectory | DarwinOpenCloseOnExec
            : LinuxOpenNonBlock | LinuxOpenNoFollow | LinuxOpenDirectory | LinuxOpenCloseOnExec;

        internal static int FileOpenFlags => RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
            ? DarwinOpenNonBlock | DarwinOpenNoFollow | DarwinOpenCloseOnExec
            : LinuxOpenNonBlock | LinuxOpenNoFollow | LinuxOpenCloseOnExec;

        [DllImport("libc", EntryPoint = "open", SetLastError = true)]
        private static extern int Open(string path, int flags);

        [DllImport("libc", EntryPoint = "openat", SetLastError = true)]
        private static extern int OpenAt(int directoryHandle, string path, int flags);

        [DllImport("libc", EntryPoint = "fstat", SetLastError = true)]
        private static extern int DarwinFStat(int handle, out DarwinStat metadata);

        [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
        private static extern int LinuxStatx(int directoryHandle, string path, int flags, uint mask, out Statx metadata);

        internal static SafeFileHandle OpenOwned(string path, int flags, string description)
        {
            int raw = Open(path, flags);
            return OwnDescriptor(raw, description);
        }

        internal static SafeFileHandle OpenAtOwned(SafeFileHandle parent, string path, int flags, string description)
        {
            bool addedReference = false;
            try
            {
                parent.DangerousAddRef(ref addedReference);
                int raw = OpenAt(parent.DangerousGetHandle().ToInt32(), path, flags);
                return OwnDescriptor(raw, description);
            }
            finally
            {
                if (addedReference)
                {
                    parent.DangerousRelease();
                }
            }
        }

        private static SafeFileHandle OwnDescriptor(int raw, string description)
        {
            if (raw < 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Cannot open {description} without following links.");
            }

            try
            {
                var owned = new SafeFileHandle((IntPtr)raw, true);
                raw = -1;
                return owned;
            }
            finally
            {
                if (raw >= 0)
                {
                    new SafeFileHandle((IntPtr)raw, true).Dispose();
                }
            }
        }

        internal static SourceMetadata GetMetadata(SafeFileHandle handle)
        {
            bool addedReference = false;
            try
            {
                handle.DangerousAddRef(ref addedReference);
                int descriptor = handle.DangerousGetHandle().ToInt32();
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    if (LinuxStatx(descriptor, string.Empty, AtEmptyPath | AtSymlinkNoFollow, RequiredStatxMask, out Statx metadata) != 0)
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "statx failed for an opened source handle.");
                    }
                    if ((metadata.Mask & RequiredStatxMask) != RequiredStatxMask)
                    {
                        throw new IOException("statx did not return the required source identity fields.");
                    }

                    int mode = metadata.Mode;
                    return new SourceMetadata(
                        GetKind(mode),
                        ToGitMode(mode),
                        true,
                        $"linux:{metadata.DeviceMajor:x8}:{metadata.DeviceMinor:x8}:{metadata.Inode:x16}",
                        checked((long)metadata.Size));
                }

                if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    if (DarwinFStat(descriptor, out DarwinStat metadata) != 0)
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "fstat failed for an opened source handle.");
                    }
                    int mode = metadata.Mode;
                    return new SourceMetadata(
                        GetKind(mode),
                        ToGitMode(mode),
                        true,
                        $"darwin:{unchecked((uint)metadata.Device):x8}:{metadata.Inode:x16}",
                        metadata.Size);
                }

                throw new PlatformNotSupportedException("Root-anchored source capture is unavailable on this Unix platform.");
            }
            finally
            {
                if (addedReference)
                {
                    handle.DangerousRelease();
                }
            }
        }

        private static SourceEntryKind GetKind(int mode)
        {
            return (mode & FileTypeMask) switch
            {
                RegularFile => SourceEntryKind.Regular,
                Directory => SourceEntryKind.Directory,
                _ => SourceEntryKind.Other
            };
        }

        private static string ToGitMode(int mode)
        {
            return Convert.ToString(mode, 8).PadLeft(6, '0');
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StatxTimestamp
        {
            internal long Seconds;
            internal uint Nanoseconds;
            internal int Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Statx
        {
            internal uint Mask;
            internal uint BlockSize;
            internal ulong Attributes;
            internal uint LinkCount;
            internal uint UserId;
            internal uint GroupId;
            internal ushort Mode;
            internal ushort Padding;
            internal ulong Inode;
            internal ulong Size;
            internal ulong Blocks;
            internal ulong AttributesMask;
            internal StatxTimestamp AccessTime;
            internal StatxTimestamp BirthTime;
            internal StatxTimestamp ChangeTime;
            internal StatxTimestamp ModificationTime;
            internal uint RDeviceMajor;
            internal uint RDeviceMinor;
            internal uint DeviceMajor;
            internal uint DeviceMinor;
            internal ulong MountId;
            internal uint DirectIoMemoryAlignment;
            internal uint DirectIoOffsetAlignment;
            internal ulong Spare0;
            internal ulong Spare1;
            internal ulong Spare2;
            internal ulong Spare3;
            internal ulong Spare4;
            internal ulong Spare5;
            internal ulong Spare6;
            internal ulong Spare7;
            internal ulong Spare8;
            internal ulong Spare9;
            internal ulong Spare10;
            internal ulong Spare11;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DarwinTimespec
        {
            internal long Seconds;
            internal long Nanoseconds;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DarwinStat
        {
            internal int Device;
            internal ushort Mode;
            internal ushort LinkCount;
            internal ulong Inode;
            internal uint UserId;
            internal uint GroupId;
            internal int SpecialDevice;
            internal DarwinTimespec AccessTime;
            internal DarwinTimespec ModificationTime;
            internal DarwinTimespec ChangeTime;
            internal DarwinTimespec BirthTime;
            internal long Size;
            internal long Blocks;
            internal int BlockSize;
            internal uint Flags;
            internal uint Generation;
            internal int Spare;
            internal long QSpare0;
            internal long QSpare1;
        }
    }

    internal static class WindowsNative
    {
        private const uint FileReadData = 0x0001;
        private const uint FileListDirectory = 0x0001;
        private const uint FileReadAttributes = 0x0080;
        private const uint Synchronize = 0x00100000;
        private const uint GenericRead = 0x80000000;
        private const uint ShareRead = 0x00000001;
        private const uint ShareWrite = 0x00000002;
        private const uint ShareDelete = 0x00000004;
        private const uint OpenExisting = 3;
        private const uint FileDirectoryFile = 0x00000001;
        private const uint FileSynchronousIoNonAlert = 0x00000020;
        private const uint FileNonDirectoryFile = 0x00000040;
        private const uint FileOpenReparsePoint = 0x00200000;
        private const uint FileFlagBackupSemantics = 0x02000000;
        private const uint FileAttributeReparsePoint = 0x00000400;
        private const uint FileAttributeDirectory = 0x00000010;
        private const uint FileOpen = 1;
        private const uint FileNameNormalized = 0;

        internal const int ErrorFileNotFound = 2;
        internal const int ErrorPathNotFound = 3;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out ByHandleFileInformation information);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(
            SafeFileHandle handle,
            StringBuilder path,
            uint pathLength,
            uint flags);

        [DllImport("ntdll.dll")]
        private static extern int NtCreateFile(
            out IntPtr fileHandle,
            uint desiredAccess,
            ref ObjectAttributes objectAttributes,
            out IoStatusBlock ioStatusBlock,
            IntPtr allocationSize,
            uint fileAttributes,
            uint shareAccess,
            uint createDisposition,
            uint createOptions,
            IntPtr eaBuffer,
            uint eaLength);

        [DllImport("ntdll.dll")]
        private static extern uint RtlNtStatusToDosError(int status);

        internal static SafeFileHandle OpenRoot(string root)
        {
            SafeFileHandle handle = CreateFileW(
                root,
                FileReadAttributes | Synchronize,
                ShareRead | ShareWrite | ShareDelete,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics | FileOpenReparsePoint,
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error, "Cannot open the repository root without following reparse points.");
            }
            return handle;
        }

        internal static SafeFileHandle OpenRelative(SafeFileHandle parent, string segment, bool directory)
        {
            IntPtr nameBuffer = IntPtr.Zero;
            IntPtr unicodeStringPointer = IntPtr.Zero;
            bool addedReference = false;
            IntPtr raw = IntPtr.Zero;
            try
            {
                nameBuffer = Marshal.StringToHGlobalUni(segment);
                var unicodeString = new UnicodeString
                {
                    Length = checked((ushort)(segment.Length * 2)),
                    MaximumLength = checked((ushort)((segment.Length + 1) * 2)),
                    Buffer = nameBuffer
                };
                unicodeStringPointer = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
                Marshal.StructureToPtr(unicodeString, unicodeStringPointer, false);
                parent.DangerousAddRef(ref addedReference);
                var attributes = new ObjectAttributes
                {
                    Length = Marshal.SizeOf<ObjectAttributes>(),
                    RootDirectory = parent.DangerousGetHandle(),
                    ObjectName = unicodeStringPointer,
                    Attributes = 0
                };
                uint access = FileReadAttributes | Synchronize | (directory ? FileListDirectory : GenericRead | FileReadData);
                uint options = FileOpenReparsePoint | FileSynchronousIoNonAlert | (directory ? FileDirectoryFile : FileNonDirectoryFile);
                int status = NtCreateFile(
                    out raw,
                    access,
                    ref attributes,
                    out _,
                    IntPtr.Zero,
                    0,
                    ShareRead | ShareWrite | ShareDelete,
                    FileOpen,
                    options,
                    IntPtr.Zero,
                    0);
                if (status < 0)
                {
                    int error = unchecked((int)RtlNtStatusToDosError(status));
                    throw new Win32Exception(error, $"Cannot open source path segment '{segment}' relative to its verified parent handle.");
                }

                var owned = new SafeFileHandle(raw, true);
                raw = IntPtr.Zero;
                try
                {
                    EnsureExactOpenedSegment(owned, segment);
                    return owned;
                }
                catch
                {
                    owned.Dispose();
                    throw;
                }
            }
            finally
            {
                if (raw != IntPtr.Zero && raw != new IntPtr(-1))
                {
                    new SafeFileHandle(raw, true).Dispose();
                }
                if (addedReference)
                {
                    parent.DangerousRelease();
                }
                if (unicodeStringPointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(unicodeStringPointer);
                }
                if (nameBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(nameBuffer);
                }
            }
        }

        private static void EnsureExactOpenedSegment(SafeFileHandle handle, string requestedSegment)
        {
            var path = new StringBuilder(512);
            uint length = GetFinalPathNameByHandleW(handle, path, checked((uint)path.Capacity), FileNameNormalized);
            if (length == 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot query the exact name of an opened source path segment.");
            }
            if (length >= path.Capacity)
            {
                path = new StringBuilder(checked((int)length + 1));
                length = GetFinalPathNameByHandleW(handle, path, checked((uint)path.Capacity), FileNameNormalized);
                if (length == 0 || length >= path.Capacity)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot query the exact name of an opened source path segment.");
                }
            }

            string fullPath = path.ToString().TrimEnd('\\', '/');
            int separator = Math.Max(fullPath.LastIndexOf('\\'), fullPath.LastIndexOf('/'));
            string openedSegment = separator >= 0 ? fullPath.Substring(separator + 1) : fullPath;
            if (!string.Equals(openedSegment, requestedSegment, StringComparison.Ordinal))
            {
                throw new IOException($"Source path segment '{requestedSegment}' resolved to alias or differently-cased name '{openedSegment}'.");
            }
        }

        internal static bool IsReparsePoint(SafeFileHandle handle)
        {
            return (GetInformation(handle).FileAttributes & FileAttributeReparsePoint) != 0;
        }

        internal static SourceMetadata GetMetadata(SafeFileHandle handle)
        {
            ByHandleFileInformation information = GetInformation(handle);
            bool reparsePoint = (information.FileAttributes & FileAttributeReparsePoint) != 0;
            bool directory = (information.FileAttributes & FileAttributeDirectory) != 0;
            long length = directory ? 0 : ((long)information.FileSizeHigh << 32) | information.FileSizeLow;
            string identity = $"windows:{information.VolumeSerialNumber:x8}:{information.FileIndexHigh:x8}{information.FileIndexLow:x8}";
            return new SourceMetadata(
                reparsePoint ? SourceEntryKind.Other : directory ? SourceEntryKind.Directory : SourceEntryKind.Regular,
                information.FileAttributes.ToString("x8"),
                false,
                identity,
                length);
        }

        private static ByHandleFileInformation GetInformation(SafeFileHandle handle)
        {
            if (!GetFileInformationByHandle(handle, out ByHandleFileInformation information))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot read metadata from an opened source handle.");
            }
            return information;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UnicodeString
        {
            internal ushort Length;
            internal ushort MaximumLength;
            internal IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ObjectAttributes
        {
            internal int Length;
            internal IntPtr RootDirectory;
            internal IntPtr ObjectName;
            internal uint Attributes;
            internal IntPtr SecurityDescriptor;
            internal IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IoStatusBlock
        {
            internal IntPtr Status;
            internal UIntPtr Information;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileTime
        {
            internal uint Low;
            internal uint High;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation
        {
            internal uint FileAttributes;
            internal FileTime CreationTime;
            internal FileTime LastAccessTime;
            internal FileTime LastWriteTime;
            internal uint VolumeSerialNumber;
            internal uint FileSizeHigh;
            internal uint FileSizeLow;
            internal uint NumberOfLinks;
            internal uint FileIndexHigh;
            internal uint FileIndexLow;
        }
    }
}
