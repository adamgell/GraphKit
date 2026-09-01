using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.Loader;

namespace GraphKit.Auth;

public sealed class GraphAuthHost : IDisposable
{
    public const string ContractMarker = "GraphKit.Auth.Abi/1";

    private const string ExpectedContractMarker = "GraphKit.Auth.Abi/1";
    private const string FactoryTypeName = "GraphKit.Auth.GraphTokenSourceFactory";
    private const int Running = 0;
    private const int ShutdownOwnerDisposingSources = 1;
    private const int SourcesDisposedAwaitingDrain = 2;
    private const int Finalized = 3;
    private static readonly TimeSpan DefaultShutdownTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan MaximumShutdownTimeout = TimeSpan.FromMinutes(2);
    private static readonly ConditionalWeakTable<object, object> ConsumedOwnedMaterials = new();
    private static readonly object ConsumedMaterialMarker = new();

    private readonly object _gate = new();
    private readonly HashSet<GraphTokenSourceProxy> _sources = [];
    private readonly List<GraphAuthException> _sourceDisposalFailures = [];
    private readonly CancellationTokenSource _shutdown = new();
    private readonly ManualResetEventSlim _drained = new(initialState: true);
    private readonly ManualResetEventSlim _shutdownCompleted = new(initialState: false);
    private readonly TaskCompletionSource<GraphAuthException?> _finalizationCompletion =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TimeSpan _shutdownTimeout;
    private IGraphTokenSourceFactory? _factory;
    private GraphAuthLoadContext? _loadContext;
    private Assembly? _providerAssembly;
    private Type? _factoryType;
    private Task? _shutdownTask;
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
            object? factoryObject;
            try
            {
                factoryObject = Activator.CreateInstance(factoryType);
            }
            catch (Exception exception)
            {
                throw ProviderBoundaryFailure.Recreate(
                    exception,
                    CancellationToken.None,
                    "provider_construction_failed",
                    "Provider");
            }

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

        IDisposable? acceptedMaterial = GetOwnedMaterial(request.Credential);
        if (acceptedMaterial is not null)
        {
            try
            {
                ConsumedOwnedMaterials.Add(acceptedMaterial, ConsumedMaterialMarker);
            }
            catch (ArgumentException)
            {
                throw new GraphAuthException(
                    "credential_material_consumed",
                    "CredentialOwnership",
                    "The owned credential material has already been transferred to an authentication source.",
                    retryAfter: null,
                    correlationId: null);
            }
        }

        bool providerFactoryInvoked = false;
        try
        {
            lock (_gate)
            {
                ThrowIfStopping();
                IGraphTokenSourceFactory factory = _factory ??
                    throw new ObjectDisposedException(nameof(GraphAuthHost));
                IGraphTokenSource? source;
                try
                {
                    providerFactoryInvoked = true;
                    source = factory.Create(request);
                }
                catch (Exception exception)
                {
                    throw ProviderBoundaryFailure.Recreate(
                        exception,
                        CancellationToken.None,
                        "provider_construction_failed",
                        "Provider");
                }

                if (source is null)
                {
                    throw new InvalidOperationException(
                        "The GraphKit.Auth provider factory returned a null token source.");
                }

                try
                {
                    ValidateProviderSource(source);
                    GraphTokenSourceProxy proxy = new(this, source);
                    _sources.Add(proxy);
                    return proxy;
                }
                catch
                {
                    try
                    {
                        source.Dispose();
                    }
                    catch
                    {
                        throw CreateProviderDisposalFailure();
                    }

                    throw;
                }
            }
        }
        catch
        {
            if (acceptedMaterial is not null && !providerFactoryInvoked)
            {
                try
                {
                    acceptedMaterial.Dispose();
                }
                catch
                {
                    throw new GraphAuthException(
                        "credential_material_cleanup_failed",
                        "CredentialOwnership",
                        "GraphKit.Auth could not clean up credential material after source construction was rejected before provider entry.",
                        retryAfter: null,
                        correlationId: null);
                }
            }

            throw;
        }
    }

    private static IDisposable? GetOwnedMaterial(GraphCredential credential)
    {
        return credential switch
        {
            CertificateCredential { OwnsMaterial: true } certificate => certificate.Certificate,
            ClientSecretCredential { OwnsMaterial: true } secret => secret.Secret,
            _ => null
        };
    }

    public void Dispose()
    {
        Task shutdownTask = GetOrStartShutdown();
        try
        {
            if (!shutdownTask.Wait(_shutdownTimeout))
            {
                return;
            }
        }
        catch (AggregateException)
        {
        }

        shutdownTask.GetAwaiter().GetResult();
    }

    private Task GetOrStartShutdown()
    {
        TaskCompletionSource<object?> shutdownCompletion;
        Task shutdownTask;
        lock (_gate)
        {
            if (_shutdownTask is not null)
            {
                return _shutdownTask;
            }

            shutdownCompletion = new TaskCompletionSource<object?>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            shutdownTask = shutdownCompletion.Task;
            _shutdownTask = shutdownTask;
            Volatile.Write(ref _state, ShutdownOwnerDisposingSources);
            _ = shutdownTask.ContinueWith(
                static completed => _ = completed.Exception,
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted |
                    TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }

        Task worker = Task.Run(() => RunShutdownAsync(shutdownCompletion));
        _ = worker.ContinueWith(
            static completed => _ = completed.Exception,
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted |
                TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
        return shutdownTask;
    }

    private async Task RunShutdownAsync(TaskCompletionSource<object?> shutdownCompletion)
    {
        List<GraphAuthException> failures = [];
        try
        {
            try
            {
                await _shutdown.CancelAsync().ConfigureAwait(false);
            }
            catch
            {
                failures.Add(CreateCancellationFailure());
            }

            GraphTokenSourceProxy[] sources;
            lock (_gate)
            {
                sources = [.. _sources];
            }

            Task<GraphAuthException?>[] disposalTasks =
                [.. sources.Select(static source => source.DisposeForHostAsync())];
            await Task.WhenAll(disposalTasks).ConfigureAwait(false);

            lock (_gate)
            {
                failures.AddRange(_sourceDisposalFailures);
                _sourceDisposalFailures.Clear();
            }

            Volatile.Write(ref _state, SourcesDisposedAwaitingDrain);
            TryFinalizeUnload();
            GraphAuthException? finalizationFailure =
                await _finalizationCompletion.Task.ConfigureAwait(false);
            if (finalizationFailure is not null)
            {
                failures.Add(finalizationFailure);
            }
        }
        catch
        {
            failures.Add(CreateHostShutdownFailure());
        }
        finally
        {
            if (failures.Count == 0)
            {
                shutdownCompletion.TrySetResult(null);
            }
            else if (failures.Count == 1)
            {
                shutdownCompletion.TrySetException(failures[0]);
            }
            else
            {
                shutdownCompletion.TrySetException(
                    new AggregateException(
                        "Multiple GraphKit.Auth cancellation, provider-disposal, or host-finalization failures occurred while the host was shutting down.",
                        failures));
            }
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

        if (Volatile.Read(ref _state) != Running)
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

    internal void CompleteSourceDisposal(
        GraphTokenSourceProxy source,
        GraphAuthException? failure)
    {
        lock (_gate)
        {
            _sources.Remove(source);
            if (failure is not null)
            {
                _sourceDisposalFailures.Add(failure);
            }
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
        if (!string.Equals(physicalLoaded, physicalCandidate, StringComparison.Ordinal))
        {
            throw IncompatibleContracts(
                $"the default context contains contracts from '{physicalLoaded}', not package candidate '{physicalCandidate}'.");
        }

        (AssemblyName CandidateIdentity, Guid CandidateMvid) candidateMetadata;
        try
        {
            candidateMetadata = ReadManagedAssemblyMetadata(physicalCandidate);
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or IOException or UnauthorizedAccessException)
        {
            throw IncompatibleContracts(
                $"package candidate '{physicalCandidate}' cannot be inspected as a managed contracts assembly: {exception.Message}");
        }

        Guid loadedMvid = contractsAssembly.ManifestModule.ModuleVersionId;
        if (!AssemblyIdentity.EqualsExactReference(
                loadedIdentity,
                candidateMetadata.CandidateIdentity) ||
            loadedMvid != candidateMetadata.CandidateMvid)
        {
            throw IncompatibleContracts(
                $"the resident contracts identity or MVID does not match package candidate '{physicalCandidate}' " +
                $"(resident MVID '{loadedMvid:D}', candidate MVID '{candidateMetadata.CandidateMvid:D}').");
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
            AssemblyIdentity.IsTrustedPlatformAssembly(typeAssembly))
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

    private static (AssemblyName Identity, Guid ModuleVersionId) ReadManagedAssemblyMetadata(
        string assemblyPath)
    {
        using FileStream stream = new(
            assemblyPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read);
        using PEReader peReader = new(stream, PEStreamOptions.LeaveOpen);
        if (!peReader.HasMetadata)
        {
            throw new BadImageFormatException(
                $"Assembly candidate '{assemblyPath}' has no managed metadata.");
        }

        MetadataReader metadata = peReader.GetMetadataReader();
        AssemblyDefinition assemblyDefinition = metadata.GetAssemblyDefinition();
        AssemblyName identity = new(metadata.GetString(assemblyDefinition.Name))
        {
            Version = assemblyDefinition.Version,
            CultureName = assemblyDefinition.Culture.IsNil
                ? null
                : metadata.GetString(assemblyDefinition.Culture)
        };
        if (!assemblyDefinition.PublicKey.IsNil)
        {
            identity.SetPublicKey(metadata.GetBlobBytes(assemblyDefinition.PublicKey));
        }

        ModuleDefinition moduleDefinition = metadata.GetModuleDefinition();
        return (identity, metadata.GetGuid(moduleDefinition.Mvid));
    }

    private static InvalidOperationException IncompatibleContracts(string detail)
    {
        return new InvalidOperationException(
            $"GraphKit.Auth cannot use the contracts assembly already loaded in this process because {detail} " +
            "Start a fresh PowerShell process and import only the intended GraphKit package.");
    }

    private void ThrowIfStopping()
    {
        if (Volatile.Read(ref _state) != Running)
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
            if (Volatile.Read(ref _state) == SourcesDisposedAwaitingDrain)
            {
                TryFinalizeUnload();
            }
        }
    }

    private void TryFinalizeUnload()
    {
        if (Volatile.Read(ref _activeOperations) != 0 ||
            Interlocked.CompareExchange(
                ref _state,
                Finalized,
                SourcesDisposedAwaitingDrain) != SourcesDisposedAwaitingDrain)
        {
            return;
        }

        GraphAuthException? failure = null;
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

        try
        {
            loadContext?.Unload();
        }
        catch
        {
            failure = CreateHostShutdownFailure();
        }

        try
        {
            _shutdown.Dispose();
        }
        catch
        {
            failure ??= CreateHostShutdownFailure();
        }
        finally
        {
            _shutdownCompleted.Set();
            _finalizationCompletion.TrySetResult(failure);
        }
    }

    private static GraphAuthException CreateCancellationFailure()
    {
        return new GraphAuthException(
            "shutdown_callback_failed",
            "HostLifecycle",
            "A GraphKit.Auth shutdown cancellation callback failed.",
            retryAfter: null,
            correlationId: null);
    }

    private static GraphAuthException CreateProviderDisposalFailure()
    {
        return new GraphAuthException(
            "provider_disposal_failed",
            "ProviderLifecycle",
            "The isolated GraphKit.Auth provider failed while disposing a token source.",
            retryAfter: null,
            correlationId: null);
    }

    private static GraphAuthException CreateHostShutdownFailure()
    {
        return new GraphAuthException(
            "host_shutdown_failed",
            "HostLifecycle",
            "GraphKit.Auth could not finish shutting down its isolated provider context.",
            retryAfter: null,
            correlationId: null);
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
