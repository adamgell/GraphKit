using System.Globalization;

namespace GraphKit.Auth;

internal interface ITokenClient : IDisposable
{
    GraphTokenResult Acquire(bool forceRefresh, CancellationToken cancellation);
}

internal sealed class GraphTokenSource : IGraphTokenSource
{
    private readonly object _cacheGate = new();
    private readonly object _flightGate = new();
    private readonly Func<DateTimeOffset> _utcNow;
    private readonly Action<IDisposable> _disposeMaterial;
    private readonly CancellationTokenSource _disposalCancellation = new();
    private readonly ManualResetEventSlim _operationsDrained = new(initialState: true);
    private readonly string _authMode;
    private readonly string _audience;
    private readonly string? _clientId;
    private readonly string _credentialGeneration;
    private ITokenClient? _client;
    private GraphCredential? _credentialReference;
    private IDisposable? _ownedMaterial;
    private string? _fixedBearer;
    private GraphTokenResult? _cachedResult;
    private bool _cachedResultWasForceRefresh;
    private TokenFlight? _ordinaryFlight;
    private TokenFlight? _forcedFlight;
    private int _activeOperations;
    private int _disposeState;

    internal GraphTokenSource(
        GraphTokenRequest request,
        ITokenClient? client,
        Func<DateTimeOffset> utcNow,
        Action<IDisposable>? disposeMaterial = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        _utcNow = utcNow ?? throw new ArgumentNullException(nameof(utcNow));
        _disposeMaterial = disposeMaterial ?? (static material => material.Dispose());
        bool fixedBearer = request.AuthMode == GraphAuthMode.BearerToken;
        if (fixedBearer != (client is null))
        {
            throw new ArgumentException(
                fixedBearer
                    ? "A fixed-bearer source must not construct an authentication client."
                    : "A refreshable source requires exactly one authentication client.",
                nameof(client));
        }

        _authMode = request.AuthMode.ToString();
        _audience = request.Resource.AbsoluteUri;
        _clientId = request.AuthMode == GraphAuthMode.ManagedIdentity
            ? ((ManagedIdentityCredential)request.Credential).UserAssignedClientId
            : request.ClientId?.ToString("D");
        _credentialGeneration = request.CredentialGeneration;
        _client = client;
        _credentialReference = request.Credential;
        _ownedMaterial = GraphTokenSourceFactory.GetTransferredMaterial(request.Credential);
        if (request.Credential is FixedBearerCredential bearer)
        {
            _fixedBearer = bearer.AccessToken;
        }
    }

    public bool CanRefresh => Read(() => _client is not null);

    public string AuthMode => Read(() => _authMode);

    public string Audience => Read(() => _audience);

    public string? ClientId => Read(() => _clientId);

    public DateTimeOffset ExpiresOn => Read(() =>
    {
        lock (_cacheGate)
        {
            return _cachedResult?.ExpiresOnUtc ?? DateTimeOffset.MinValue;
        }
    });

    public string? VerifiedTenantId => Read(() =>
    {
        lock (_cacheGate)
        {
            return _cachedResult?.VerifiedTenantId;
        }
    });

    public string CredentialGeneration => Read(() => _credentialGeneration);

    internal int OrdinaryFlightWaiterCount
    {
        get
        {
            lock (_flightGate)
            {
                return _ordinaryFlight?.WaiterCount ?? 0;
            }
        }
    }

    internal bool HasCachedResult => Volatile.Read(ref _cachedResult) is not null;

    internal bool HasClientReference => Volatile.Read(ref _client) is not null;

    internal bool HasCredentialReference =>
        Volatile.Read(ref _credentialReference) is not null ||
        Volatile.Read(ref _fixedBearer) is not null ||
        Volatile.Read(ref _ownedMaterial) is not null;

    public GraphTokenResult Acquire(
        bool forceRefresh,
        CancellationToken cancellation)
    {
        using OperationLease operation = BeginOperation(cancellation);
        if (_client is null)
        {
            return AcquireFixedBearer(forceRefresh, operation.Cancellation);
        }

        if (!forceRefresh && TryGetValidCachedResult(out GraphTokenResult? cached))
        {
            return cached!;
        }

        return AcquireRefreshable(forceRefresh, cancellation, operation.Cancellation);
    }

    public void AdoptSharedResult(GraphTokenResult result, bool forceRefresh)
    {
        using OperationLease operation = BeginOperation(CancellationToken.None);
        ArgumentNullException.ThrowIfNull(result);
        ValidateGeneration(result);
        CacheResult(result, forceRefresh);
    }

    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _disposeState, 1, 0) != 0)
        {
            return;
        }

        try
        {
            _disposalCancellation.Cancel();
        }
        catch
        {
            // Cancellation callbacks are provider implementation details. Cleanup
            // continues and only a sanitized lifecycle failure may cross the ABI.
        }

        _operationsDrained.Wait();

        ITokenClient? client = Interlocked.Exchange(ref _client, null);
        IDisposable? ownedMaterial = Interlocked.Exchange(ref _ownedMaterial, null);
        Interlocked.Exchange(ref _credentialReference, null);
        Interlocked.Exchange(ref _fixedBearer, null);
        lock (_cacheGate)
        {
            _cachedResult = null;
            _cachedResultWasForceRefresh = false;
        }

        lock (_flightGate)
        {
            _ordinaryFlight = null;
            _forcedFlight = null;
        }

        bool cleanupFailed = false;
        try
        {
            client?.Dispose();
        }
        catch
        {
            cleanupFailed = true;
        }

        if (ownedMaterial is not null)
        {
            try
            {
                _disposeMaterial(ownedMaterial);
            }
            catch
            {
                cleanupFailed = true;
            }
        }

        _disposalCancellation.Dispose();
        _operationsDrained.Dispose();
        Volatile.Write(ref _disposeState, 2);

        if (cleanupFailed)
        {
            throw new GraphAuthException(
                "provider_disposal_failed",
                "ProviderLifecycle",
                "The isolated authentication provider failed while disposing a token source.",
                retryAfter: null,
                correlationId: null);
        }
    }

    private GraphTokenResult AcquireFixedBearer(
        bool forceRefresh,
        CancellationToken cancellation)
    {
        cancellation.ThrowIfCancellationRequested();
        if (forceRefresh)
        {
            throw new InvalidOperationException(
                "A fixed bearer token cannot be refreshed. Supply a new token source instead.");
        }

        lock (_cacheGate)
        {
            if (_cachedResult is not null)
            {
                return _cachedResult;
            }

            string bearer = _fixedBearer ??
                throw new ObjectDisposedException(nameof(GraphTokenSource));
            _cachedResult = TokenResultFactory.Create(
                bearer,
                DateTimeOffset.MinValue,
                _utcNow(),
                MsalTokenClient.GetScope(_audience),
                _credentialGeneration);
            return _cachedResult;
        }
    }

    private GraphTokenResult AcquireRefreshable(
        bool forceRefresh,
        CancellationToken callerCancellation,
        CancellationToken operationCancellation)
    {
        while (true)
        {
            TokenFlight flight;
            bool leader;
            lock (_flightGate)
            {
                ref TokenFlight? slot = ref forceRefresh
                    ? ref _forcedFlight
                    : ref _ordinaryFlight;
                if (slot is null || slot.Completion.Task.IsCompleted)
                {
                    slot = new TokenFlight();
                    leader = true;
                }
                else
                {
                    leader = false;
                }

                flight = slot;
                flight.AddWaiter();
            }

            try
            {
                if (leader)
                {
                    ExecuteFlight(
                        flight,
                        forceRefresh,
                        callerCancellation,
                        operationCancellation);
                }

                try
                {
                    return flight.Completion.Task
                        .WaitAsync(operationCancellation)
                        .GetAwaiter()
                        .GetResult();
                }
                catch (OperationCanceledException) when (
                    !leader &&
                    !operationCancellation.IsCancellationRequested &&
                    flight.LeaderCallerWasCancelled)
                {
                    RemoveFlightIfCurrent(flight, forceRefresh);
                    continue;
                }
            }
            finally
            {
                flight.RemoveWaiter();
            }
        }
    }

    private void ExecuteFlight(
        TokenFlight flight,
        bool forceRefresh,
        CancellationToken callerCancellation,
        CancellationToken operationCancellation)
    {
        try
        {
            GraphTokenResult result;
            try
            {
                ITokenClient client = Volatile.Read(ref _client) ??
                    throw new ObjectDisposedException(nameof(GraphTokenSource));
                result = client.Acquire(forceRefresh, operationCancellation) ??
                    throw new InvalidOperationException(
                        "The isolated authentication client returned no token result.");
            }
            catch (OperationCanceledException exception)
            {
                flight.LeaderCallerWasCancelled = callerCancellation.IsCancellationRequested;
                flight.Completion.TrySetException(exception);
                return;
            }
            catch (GraphAuthException exception)
            {
                flight.Completion.TrySetException(exception);
                return;
            }
            catch (Exception exception)
            {
                flight.Completion.TrySetException(
                    ProviderFailureSanitizer.Create(exception, "provider_failure", "Provider"));
                return;
            }

            try
            {
                ValidateGeneration(result);
                CacheResult(result, forceRefresh);
                flight.Completion.TrySetResult(result);
            }
            catch (InvalidOperationException exception)
            {
                flight.Completion.TrySetException(exception);
            }
        }
        finally
        {
            RemoveFlightIfCurrent(flight, forceRefresh);
        }
    }

    private void RemoveFlightIfCurrent(TokenFlight flight, bool forceRefresh)
    {
        lock (_flightGate)
        {
            ref TokenFlight? slot = ref forceRefresh
                ? ref _forcedFlight
                : ref _ordinaryFlight;
            if (ReferenceEquals(slot, flight))
            {
                slot = null;
            }
        }
    }

    private bool TryGetValidCachedResult(out GraphTokenResult? result)
    {
        lock (_cacheGate)
        {
            result = _cachedResult;
            if (result is null || result.ExpiresOnUtc <= DateTimeOffset.MinValue)
            {
                result = null;
                return false;
            }

            DateTimeOffset refreshAt = result.ExpiresOnUtc - GetRefreshSkew(result);
            if (refreshAt > _utcNow())
            {
                return true;
            }

            result = null;
            return false;
        }
    }

    private static TimeSpan GetRefreshSkew(GraphTokenResult result)
    {
        double lifetimeSeconds = result.ReceivedOnUtc > DateTimeOffset.MinValue
            ? Math.Max(0, (result.ExpiresOnUtc - result.ReceivedOnUtc).TotalSeconds)
            : 0;
        double baseSeconds = Math.Min(300, Math.Max(60, lifetimeSeconds * 0.1));
        double spreadSeconds = 0;
        string fingerprint = result.TokenFingerprint;
        if (fingerprint.Length >= 2 &&
            byte.TryParse(
                fingerprint.AsSpan(0, 2),
                NumberStyles.HexNumber,
                CultureInfo.InvariantCulture,
                out byte bucket))
        {
            spreadSeconds = baseSeconds * 0.1 * (bucket / 255d);
        }

        return TimeSpan.FromSeconds(baseSeconds + spreadSeconds);
    }

    private void CacheResult(GraphTokenResult result, bool forceRefresh)
    {
        lock (_cacheGate)
        {
            GraphTokenResult? current = _cachedResult;
            bool replace = current is null || result.ReceivedOnUtc > current.ReceivedOnUtc;
            if (!replace &&
                current is not null &&
                result.ReceivedOnUtc == current.ReceivedOnUtc)
            {
                replace = (forceRefresh && !_cachedResultWasForceRefresh) ||
                    (forceRefresh == _cachedResultWasForceRefresh &&
                        result.ExpiresOnUtc > current.ExpiresOnUtc);
            }

            if (replace)
            {
                _cachedResult = result;
                _cachedResultWasForceRefresh = forceRefresh;
            }
        }
    }

    private void ValidateGeneration(GraphTokenResult result)
    {
        if (!string.Equals(
                result.CredentialGeneration,
                _credentialGeneration,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Refusing a token result from a different credential generation.");
        }
    }

    private TResult Read<TResult>(Func<TResult> read)
    {
        ThrowIfDisposed();
        return read();
    }

    private OperationLease BeginOperation(CancellationToken callerCancellation)
    {
        ThrowIfDisposed();
        int active = Interlocked.Increment(ref _activeOperations);
        if (active == 1)
        {
            _operationsDrained.Reset();
        }

        try
        {
            ThrowIfDisposed();
            CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(
                callerCancellation,
                _disposalCancellation.Token);
            return new OperationLease(this, linked);
        }
        catch
        {
            ExitOperation();
            throw;
        }
    }

    private void ExitOperation()
    {
        if (Interlocked.Decrement(ref _activeOperations) == 0)
        {
            _operationsDrained.Set();
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref _disposeState) != 0,
            this);
    }

    private sealed class TokenFlight
    {
        private int _waiterCount;

        internal TaskCompletionSource<GraphTokenResult> Completion { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        internal bool LeaderCallerWasCancelled { get; set; }

        internal int WaiterCount => Volatile.Read(ref _waiterCount);

        internal void AddWaiter() => Interlocked.Increment(ref _waiterCount);

        internal void RemoveWaiter() => Interlocked.Decrement(ref _waiterCount);
    }

    private sealed class OperationLease : IDisposable
    {
        private GraphTokenSource? _owner;
        private CancellationTokenSource? _linkedCancellation;

        internal OperationLease(
            GraphTokenSource owner,
            CancellationTokenSource linkedCancellation)
        {
            _owner = owner;
            _linkedCancellation = linkedCancellation;
        }

        internal CancellationToken Cancellation =>
            Volatile.Read(ref _linkedCancellation)?.Token ??
            throw new ObjectDisposedException(nameof(OperationLease));

        public void Dispose()
        {
            CancellationTokenSource? linked = Interlocked.Exchange(
                ref _linkedCancellation,
                null);
            GraphTokenSource? owner = Interlocked.Exchange(ref _owner, null);
            if (owner is null)
            {
                return;
            }

            linked?.Dispose();
            owner.ExitOperation();
        }
    }
}
