using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;

namespace GraphKit.Auth;

public sealed class GraphAuthHost : IDisposable
{
    public const string ContractMarker = "GraphKit.Auth.Abi/1";

    private const string ExpectedContractMarker = "GraphKit.Auth.Abi/1";
    private const string FactoryTypeName = "GraphKit.Auth.GraphTokenSourceFactory";
    private static readonly TimeSpan DefaultShutdownTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan MaximumShutdownTimeout = TimeSpan.FromMinutes(2);

    private readonly object _gate = new();
    private readonly HashSet<GraphTokenSourceProxy> _sources = [];
    private readonly CancellationTokenSource _shutdown = new();
    private readonly ManualResetEventSlim _drained = new(initialState: true);
    private readonly TimeSpan _shutdownTimeout;
    private IGraphTokenSourceFactory? _factory;
    private GraphAuthLoadContext? _loadContext;
    private Assembly? _providerAssembly;
    private Type? _factoryType;
    private int _activeOperations;
    private int _state;

    public GraphAuthHost(string payloadRoot, Version expectedProviderVersion)
        : this(payloadRoot, expectedProviderVersion, DefaultShutdownTimeout)
    {
    }

    public GraphAuthHost(
        string payloadRoot,
        Version expectedProviderVersion,
        TimeSpan shutdownTimeout)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(payloadRoot);
        ArgumentNullException.ThrowIfNull(expectedProviderVersion);
        if (shutdownTimeout <= TimeSpan.Zero || shutdownTimeout > MaximumShutdownTimeout)
        {
            throw new ArgumentOutOfRangeException(
                nameof(shutdownTimeout),
                shutdownTimeout,
                $"The GraphKit.Auth shutdown timeout must be greater than zero and no more than {MaximumShutdownTimeout}.");
        }

        _shutdownTimeout = shutdownTimeout;
        string physicalRoot = PhysicalPath.ResolveExistingDirectory(payloadRoot);
        Assembly contractsAssembly = ValidateDefaultContractsAssembly(physicalRoot);
        string providerPath = Path.Combine(physicalRoot, GraphAuthLoadContext.ProviderFileName);
        GraphAuthLoadContext loadContext = new(
            physicalRoot,
            providerPath,
            expectedProviderVersion,
            contractsAssembly);
        LoadContextWeakReference = new WeakReference(loadContext, trackResurrection: false);

        try
        {
            Assembly providerAssembly = loadContext.LoadProviderAssembly();
            Type factoryType = ValidateProvider(providerAssembly, loadContext, contractsAssembly);
            object? factoryObject = Activator.CreateInstance(factoryType);
            if (factoryObject is not IGraphTokenSourceFactory factory)
            {
                throw new InvalidOperationException(
                    $"Provider factory '{FactoryTypeName}' did not implement the exact default-context " +
                    $"'{typeof(IGraphTokenSourceFactory).AssemblyQualifiedName}' contract.");
            }

            _loadContext = loadContext;
            _providerAssembly = providerAssembly;
            _factoryType = factoryType;
            _factory = factory;
        }
        catch
        {
            loadContext.Unload();
            throw;
        }
    }

    public WeakReference LoadContextWeakReference { get; }

    public IGraphTokenSource CreateSource(GraphTokenRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        lock (_gate)
        {
            ThrowIfStopping();
            IGraphTokenSourceFactory factory = _factory ??
                throw new ObjectDisposedException(nameof(GraphAuthHost));
            IGraphTokenSource source = factory.Create(request) ??
                throw new InvalidOperationException("The GraphKit.Auth provider factory returned a null token source.");

            try
            {
                ValidateProviderSource(source);
                GraphTokenSourceProxy proxy = new(this, source);
                _sources.Add(proxy);
                return proxy;
            }
            catch
            {
                source.Dispose();
                throw;
            }
        }
    }

    public void Dispose()
    {
        List<Exception>? failures = null;
        bool ownsShutdown = Interlocked.CompareExchange(ref _state, 1, 0) == 0;
        if (ownsShutdown)
        {
            _shutdown.Cancel();
            GraphTokenSourceProxy[] sources;
            lock (_gate)
            {
                sources = [.. _sources];
            }

            foreach (GraphTokenSourceProxy source in sources)
            {
                try
                {
                    source.Dispose();
                }
                catch (Exception exception)
                {
                    failures ??= [];
                    failures.Add(exception);
                }
            }
        }

        if (Volatile.Read(ref _state) == 1)
        {
            _drained.Wait(_shutdownTimeout);
            TryFinalizeUnload();
        }

        if (failures is not null)
        {
            throw new AggregateException(
                "One or more GraphKit.Auth provider sources failed while the host was shutting down.",
                failures);
        }
    }

    internal GraphAuthOperationLease EnterOperation(CancellationToken callerCancellation)
    {
        ThrowIfStopping();
        int active = Interlocked.Increment(ref _activeOperations);
        if (active == 1)
        {
            _drained.Reset();
        }

        if (Volatile.Read(ref _state) != 0)
        {
            ExitOperation();
            throw new ObjectDisposedException(nameof(GraphAuthHost));
        }

        try
        {
            CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(
                callerCancellation,
                _shutdown.Token);
            return new GraphAuthOperationLease(this, linked);
        }
        catch
        {
            ExitOperation();
            throw;
        }
    }

    internal void Unregister(GraphTokenSourceProxy source)
    {
        lock (_gate)
        {
            _sources.Remove(source);
        }
    }

    private static Assembly ValidateDefaultContractsAssembly(string physicalPayloadRoot)
    {
        Assembly contractsAssembly = typeof(GraphAuthHost).Assembly;
        AssemblyLoadContext? loadContext = AssemblyLoadContext.GetLoadContext(contractsAssembly);
        if (!ReferenceEquals(loadContext, AssemblyLoadContext.Default))
        {
            throw IncompatibleContracts(
                $"'{contractsAssembly.FullName}' is loaded in '{loadContext?.Name ?? "<unknown>"}' instead of the default context.");
        }

        AssemblyName loadedIdentity = contractsAssembly.GetName();
        if (!string.Equals(
                loadedIdentity.Name,
                GraphAuthLoadContext.ContractsAssemblyName,
                StringComparison.Ordinal))
        {
            throw IncompatibleContracts(
                $"the loaded contracts assembly is named '{loadedIdentity.Name}'.");
        }

        if (!string.Equals(ContractMarker, ExpectedContractMarker, StringComparison.Ordinal))
        {
            throw IncompatibleContracts(
                $"the loaded contract marker is '{ContractMarker}', not '{ExpectedContractMarker}'.");
        }

        string candidatePath = Path.Combine(
            physicalPayloadRoot,
            GraphAuthLoadContext.ContractsFileName);
        string physicalCandidate = PhysicalPath.RequireFileInsideRoot(
            candidatePath,
            physicalPayloadRoot);
        if (string.IsNullOrEmpty(contractsAssembly.Location))
        {
            throw IncompatibleContracts("the loaded contracts assembly has no physical location.");
        }

        string physicalLoaded;
        try
        {
            physicalLoaded = PhysicalPath.RequireFileInsideRoot(
                contractsAssembly.Location,
                physicalPayloadRoot);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            throw IncompatibleContracts(
                $"the loaded contracts location is not the declared package candidate: {exception.Message}");
        }
        StringComparison pathComparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        if (!string.Equals(physicalLoaded, physicalCandidate, pathComparison))
        {
            throw IncompatibleContracts(
                $"the default context contains contracts from '{physicalLoaded}', not package candidate '{physicalCandidate}'.");
        }

        AssemblyName candidateIdentity = AssemblyName.GetAssemblyName(physicalCandidate);
        if (!AssemblyIdentity.EqualsExactReference(loadedIdentity, candidateIdentity) ||
            !FilesHaveSameSha256(physicalLoaded, physicalCandidate))
        {
            throw IncompatibleContracts(
                $"the loaded contracts identity or bytes do not match package candidate '{physicalCandidate}'.");
        }

        return contractsAssembly;
    }

    private static Type ValidateProvider(
        Assembly providerAssembly,
        GraphAuthLoadContext loadContext,
        Assembly contractsAssembly)
    {
        if (!ReferenceEquals(AssemblyLoadContext.GetLoadContext(providerAssembly), loadContext))
        {
            throw new InvalidOperationException(
                "GraphKit.Auth provider assembly escaped its declared collectible load context.");
        }

        Type? factoryType = providerAssembly.GetType(
            FactoryTypeName,
            throwOnError: false,
            ignoreCase: false);
        if (factoryType is null ||
            !factoryType.IsClass ||
            factoryType.IsAbstract ||
            !factoryType.IsPublic ||
            factoryType.GetConstructor(Type.EmptyTypes) is null ||
            !typeof(IGraphTokenSourceFactory).IsAssignableFrom(factoryType) ||
            !ReferenceEquals(factoryType.Assembly, providerAssembly))
        {
            throw new InvalidOperationException(
                $"Provider must expose public concrete factory '{FactoryTypeName}' with a public parameterless constructor " +
                "and the exact default-context IGraphTokenSourceFactory interface.");
        }

        ValidateProviderPublicSurface(providerAssembly, contractsAssembly);
        return factoryType;
    }

    private static void ValidateProviderPublicSurface(
        Assembly providerAssembly,
        Assembly contractsAssembly)
    {
        foreach (Type exportedType in providerAssembly.GetExportedTypes())
        {
            ValidateSignatureType(exportedType.BaseType, providerAssembly, contractsAssembly);
            foreach (Type interfaceType in exportedType.GetInterfaces())
            {
                ValidateSignatureType(interfaceType, providerAssembly, contractsAssembly);
            }

            const BindingFlags flags =
                BindingFlags.Public |
                BindingFlags.Instance |
                BindingFlags.Static |
                BindingFlags.DeclaredOnly;
            foreach (MemberInfo member in exportedType.GetMembers(flags))
            {
                switch (member)
                {
                    case MethodInfo method:
                        ValidateSignatureType(method.ReturnType, providerAssembly, contractsAssembly);
                        foreach (ParameterInfo parameter in method.GetParameters())
                        {
                            ValidateSignatureType(parameter.ParameterType, providerAssembly, contractsAssembly);
                        }

                        break;
                    case ConstructorInfo constructor:
                        foreach (ParameterInfo parameter in constructor.GetParameters())
                        {
                            ValidateSignatureType(parameter.ParameterType, providerAssembly, contractsAssembly);
                        }

                        break;
                    case PropertyInfo property:
                        ValidateSignatureType(property.PropertyType, providerAssembly, contractsAssembly);
                        break;
                    case FieldInfo field:
                        ValidateSignatureType(field.FieldType, providerAssembly, contractsAssembly);
                        break;
                    case EventInfo eventInfo:
                        ValidateSignatureType(eventInfo.EventHandlerType, providerAssembly, contractsAssembly);
                        break;
                }
            }
        }
    }

    private static void ValidateSignatureType(
        Type? type,
        Assembly providerAssembly,
        Assembly contractsAssembly)
    {
        if (type is null || type.IsGenericParameter)
        {
            return;
        }

        if (type.HasElementType)
        {
            ValidateSignatureType(type.GetElementType(), providerAssembly, contractsAssembly);
            return;
        }

        foreach (Type argument in type.GetGenericArguments())
        {
            ValidateSignatureType(argument, providerAssembly, contractsAssembly);
        }

        Assembly typeAssembly = type.Assembly;
        if (ReferenceEquals(typeAssembly, contractsAssembly) ||
            AssemblyIdentity.IsFrameworkAssembly(typeAssembly.GetName()))
        {
            return;
        }

        string detail = ReferenceEquals(typeAssembly, providerAssembly)
            ? "a provider-owned type"
            : $"type '{type.FullName}' from '{typeAssembly.FullName}'";
        throw new InvalidOperationException(
            $"Provider public surface exposes {detail}; only framework and exact GraphKit.Auth contract types may cross the boundary.");
    }

    private void ValidateProviderSource(IGraphTokenSource source)
    {
        Assembly? providerAssembly = Volatile.Read(ref _providerAssembly);
        GraphAuthLoadContext? loadContext = Volatile.Read(ref _loadContext);
        Type sourceType = source.GetType();
        if (providerAssembly is null ||
            loadContext is null ||
            !ReferenceEquals(sourceType.Assembly, providerAssembly) ||
            !ReferenceEquals(AssemblyLoadContext.GetLoadContext(sourceType.Assembly), loadContext) ||
            !typeof(IGraphTokenSource).IsAssignableFrom(sourceType))
        {
            throw new InvalidOperationException(
                "The GraphKit.Auth factory returned a source outside the exact provider/load-context/interface boundary.");
        }
    }

    private static bool FilesHaveSameSha256(string firstPath, string secondPath)
    {
        using FileStream first = File.OpenRead(firstPath);
        using FileStream second = File.OpenRead(secondPath);
        byte[] firstHash = SHA256.HashData(first);
        byte[] secondHash = SHA256.HashData(second);
        return CryptographicOperations.FixedTimeEquals(firstHash, secondHash);
    }

    private static InvalidOperationException IncompatibleContracts(string detail)
    {
        return new InvalidOperationException(
            $"GraphKit.Auth cannot use the contracts assembly already loaded in this process because {detail} " +
            "Start a fresh PowerShell process and import only the intended GraphKit package.");
    }

    private void ThrowIfStopping()
    {
        if (Volatile.Read(ref _state) != 0)
        {
            throw new ObjectDisposedException(
                nameof(GraphAuthHost),
                "The GraphKit.Auth host is shutting down and cannot accept new work.");
        }
    }

    private void ExitOperation()
    {
        if (Interlocked.Decrement(ref _activeOperations) == 0)
        {
            _drained.Set();
            if (Volatile.Read(ref _state) == 1)
            {
                TryFinalizeUnload();
            }
        }
    }

    private void TryFinalizeUnload()
    {
        if (Volatile.Read(ref _activeOperations) != 0 ||
            Interlocked.CompareExchange(ref _state, 2, 1) != 1)
        {
            return;
        }

        GraphAuthLoadContext? loadContext;
        lock (_gate)
        {
            _sources.Clear();
            _factory = null;
            _factoryType = null;
            _providerAssembly = null;
            loadContext = _loadContext;
            _loadContext = null;
        }

        loadContext?.Unload();
        _shutdown.Dispose();
    }

    internal sealed class GraphAuthOperationLease : IDisposable
    {
        private GraphAuthHost? _owner;
        private CancellationTokenSource? _linkedCancellation;

        internal GraphAuthOperationLease(
            GraphAuthHost owner,
            CancellationTokenSource linkedCancellation)
        {
            _owner = owner;
            _linkedCancellation = linkedCancellation;
        }

        internal CancellationToken Cancellation =>
            Volatile.Read(ref _linkedCancellation)?.Token ??
            throw new ObjectDisposedException(nameof(GraphAuthOperationLease));

        public void Dispose()
        {
            CancellationTokenSource? linked = Interlocked.Exchange(
                ref _linkedCancellation,
                null);
            GraphAuthHost? owner = Interlocked.Exchange(ref _owner, null);
            if (owner is null)
            {
                return;
            }

            linked?.Dispose();
            owner.ExitOperation();
        }
    }
}
