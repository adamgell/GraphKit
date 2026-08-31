using System.Reflection;
using System.Runtime.Loader;

namespace GraphKit.Auth;

internal sealed class GraphAuthLoadContext : AssemblyLoadContext
{
    internal const string ProviderAssemblyName = "GraphKit.Auth";
    internal const string ProviderFileName = "GraphKit.Auth.dll";
    internal const string ContractsAssemblyName = "GraphKit.Auth.Contracts";
    internal const string ContractsFileName = "GraphKit.Auth.Contracts.dll";

    private readonly AssemblyDependencyResolver _resolver;
    private readonly Assembly _contractsAssembly;
    private readonly string _physicalPayloadRoot;
    private readonly string _providerPath;
    private readonly Version _expectedProviderVersion;

    internal GraphAuthLoadContext(
        string payloadRoot,
        string providerPath,
        Version expectedProviderVersion,
        Assembly contractsAssembly)
        : base($"GraphKit.Auth/{Guid.NewGuid():N}", isCollectible: true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(payloadRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(providerPath);
        ArgumentNullException.ThrowIfNull(expectedProviderVersion);
        ArgumentNullException.ThrowIfNull(contractsAssembly);

        _physicalPayloadRoot = PhysicalPath.ResolveExistingDirectory(payloadRoot);
        _providerPath = PhysicalPath.RequireFileInsideRoot(providerPath, _physicalPayloadRoot);
        _expectedProviderVersion = expectedProviderVersion;
        _contractsAssembly = contractsAssembly;

        ValidateProviderIdentity(_providerPath);
        _resolver = new AssemblyDependencyResolver(_providerPath);
    }

    internal Assembly LoadProviderAssembly()
    {
        Assembly provider = LoadFromAssemblyPath(_providerPath);
        ValidateProviderIdentity(provider.GetName());
        if (!ReferenceEquals(GetLoadContext(provider), this))
        {
            throw new FileLoadException(
                $"Provider '{provider.FullName}' did not load into the declared GraphKit.Auth collectible context.",
                _providerPath);
        }

        return provider;
    }

    protected override Assembly? Load(AssemblyName assemblyName)
    {
        ArgumentNullException.ThrowIfNull(assemblyName);
        AssemblyName contractsIdentity = _contractsAssembly.GetName();
        if (string.Equals(
                assemblyName.Name,
                ContractsAssemblyName,
                StringComparison.Ordinal))
        {
            if (!AssemblyIdentity.EqualsExactReference(assemblyName, contractsIdentity))
            {
                throw new FileLoadException(
                    $"Provider requested incompatible contracts identity '{assemblyName.FullName}'. " +
                    $"The default context contains '{contractsIdentity.FullName}'. Start a fresh PowerShell process with one GraphKit.Auth ABI.");
            }

            if (!ReferenceEquals(GetLoadContext(_contractsAssembly), Default))
            {
                throw new FileLoadException(
                    "GraphKit.Auth.Contracts must be loaded in the default AssemblyLoadContext.");
            }

            return _contractsAssembly;
        }

        string? resolvedPath = _resolver.ResolveAssemblyToPath(assemblyName);
        if (resolvedPath is null)
        {
            if (AssemblyIdentity.IsFrameworkAssembly(assemblyName))
            {
                return null;
            }

            throw new FileNotFoundException(
                $"The isolated GraphKit.Auth dependency '{assemblyName.FullName}' is absent from the declared payload root.",
                assemblyName.Name);
        }

        string physicalPath = PhysicalPath.RequireFileInsideRoot(resolvedPath, _physicalPayloadRoot);
        AssemblyName resolvedIdentity = AssemblyName.GetAssemblyName(physicalPath);
        if (string.Equals(
                resolvedIdentity.Name,
                ContractsAssemblyName,
                StringComparison.Ordinal))
        {
            throw new FileLoadException(
                $"Refusing a second GraphKit.Auth.Contracts copy at '{physicalPath}'. " +
                "The provider must use the exact default-context contracts assembly.",
                physicalPath);
        }

        if (!AssemblyIdentity.EqualsExactReference(assemblyName, resolvedIdentity))
        {
            throw new FileLoadException(
                $"Dependency resolver returned '{resolvedIdentity.FullName}' for requested identity '{assemblyName.FullName}'.",
                physicalPath);
        }

        return LoadFromAssemblyPath(physicalPath);
    }

    protected override nint LoadUnmanagedDll(string unmanagedDllName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(unmanagedDllName);
        string? resolvedPath = _resolver.ResolveUnmanagedDllToPath(unmanagedDllName);
        if (resolvedPath is null)
        {
            throw new DllNotFoundException(
                $"The isolated GraphKit.Auth native dependency '{unmanagedDllName}' is absent from the declared payload root.");
        }

        string physicalPath = PhysicalPath.RequireFileInsideRoot(resolvedPath, _physicalPayloadRoot);
        return LoadUnmanagedDllFromPath(physicalPath);
    }

    private void ValidateProviderIdentity(string providerPath)
    {
        AssemblyName identity = AssemblyName.GetAssemblyName(providerPath);
        ValidateProviderIdentity(identity);
    }

    private void ValidateProviderIdentity(AssemblyName identity)
    {
        if (!string.Equals(identity.Name, ProviderAssemblyName, StringComparison.Ordinal))
        {
            throw new FileLoadException(
                $"The GraphKit.Auth payload contains provider assembly '{identity.Name}', not '{ProviderAssemblyName}'.",
                _providerPath);
        }

        if (identity.Version != _expectedProviderVersion)
        {
            throw new FileLoadException(
                $"The GraphKit.Auth provider version '{identity.Version}' does not match declared version '{_expectedProviderVersion}'.",
                _providerPath);
        }
    }
}

internal static class AssemblyIdentity
{
    internal static bool EqualsExactReference(AssemblyName requested, AssemblyName actual)
    {
        return string.Equals(requested.Name, actual.Name, StringComparison.Ordinal) &&
            requested.Version == actual.Version &&
            string.Equals(
                requested.CultureName ?? string.Empty,
                actual.CultureName ?? string.Empty,
                StringComparison.Ordinal) &&
            requested.GetPublicKeyToken().AsSpan().SequenceEqual(actual.GetPublicKeyToken());
    }

    internal static bool IsFrameworkAssembly(AssemblyName identity)
    {
        string name = identity.Name ?? string.Empty;
        return name is "mscorlib" or "netstandard" or "Microsoft.CSharp" or "System" or "System.Private.CoreLib" ||
            name.StartsWith("System.", StringComparison.Ordinal);
    }
}

internal static class PhysicalPath
{
    internal static string ResolveExistingDirectory(string path)
    {
        string fullPath = Path.GetFullPath(path);
        if (!Directory.Exists(fullPath))
        {
            throw new DirectoryNotFoundException(
                $"The declared GraphKit.Auth payload root '{fullPath}' does not exist.");
        }

        return ResolveExistingPath(fullPath);
    }

    internal static string RequireFileInsideRoot(string filePath, string physicalRoot)
    {
        string fullPath = Path.GetFullPath(filePath);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException(
                $"The declared GraphKit.Auth payload file '{fullPath}' does not exist.",
                fullPath);
        }

        string resolvedPath = ResolveExistingPath(fullPath);
        string resolvedRoot = ResolveExistingDirectory(physicalRoot);
        if (!IsDescendant(resolvedPath, resolvedRoot))
        {
            throw new FileLoadException(
                $"GraphKit.Auth payload file '{fullPath}' resolves physically outside declared root '{resolvedRoot}'.",
                fullPath);
        }

        return resolvedPath;
    }

    private static string ResolveExistingPath(string path)
    {
        string fullPath = Path.GetFullPath(path);
        string? pathRoot = Path.GetPathRoot(fullPath);
        if (string.IsNullOrEmpty(pathRoot))
        {
            throw new IOException($"Path '{fullPath}' has no filesystem root.");
        }

        string current = pathRoot;
        string remainder = fullPath[pathRoot.Length..];
        string[] components = remainder.Split(
            [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
            StringSplitOptions.RemoveEmptyEntries);

        foreach (string component in components)
        {
            current = Path.Combine(current, component);
            FileSystemInfo info = Directory.Exists(current)
                ? new DirectoryInfo(current)
                : new FileInfo(current);
            if (!info.Exists)
            {
                throw new FileNotFoundException(
                    $"Cannot resolve physical path because '{current}' does not exist.",
                    current);
            }

            FileSystemInfo? target = info.ResolveLinkTarget(returnFinalTarget: true);
            if (target is not null)
            {
                current = Path.GetFullPath(target.FullName);
            }
        }

        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(current));
    }

    private static bool IsDescendant(string candidate, string root)
    {
        StringComparison comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        string normalizedRoot = Path.TrimEndingDirectorySeparator(root);
        if (string.Equals(candidate, normalizedRoot, comparison))
        {
            return false;
        }

        string prefix = normalizedRoot + Path.DirectorySeparatorChar;
        return candidate.StartsWith(prefix, comparison);
    }
}
