namespace GraphKit.Auth;

internal sealed class GraphTokenSourceProxy : IGraphTokenSource
{
    private IGraphTokenSource? _inner;
    private IGraphTokenSource? _retiredInner;
    private GraphAuthHost? _owner;
    private int _activeOperations;
    private int _disposeState;
    private int _hostNotificationState;

    internal GraphTokenSourceProxy(
        GraphAuthHost owner,
        IGraphTokenSource inner)
    {
        _owner = owner ?? throw new ArgumentNullException(nameof(owner));
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    public bool CanRefresh => Read(source => source.CanRefresh);

    public string AuthMode => Read(source => source.AuthMode);

    public string Audience => Read(source => source.Audience);

    public string? ClientId => Read(source => source.ClientId);

    public DateTimeOffset ExpiresOn => Read(source => source.ExpiresOn);

    public string? VerifiedTenantId => Read(source => source.VerifiedTenantId);

    public string CredentialGeneration => Read(source => source.CredentialGeneration);

    public GraphTokenResult Acquire(
        bool forceRefresh,
        CancellationToken cancellation)
    {
        using ProxyOperation operation = BeginOperation(cancellation);
        return operation.Inner.Acquire(forceRefresh, operation.Cancellation);
    }

    public void AdoptSharedResult(GraphTokenResult result, bool forceRefresh)
    {
        using ProxyOperation operation = BeginOperation(CancellationToken.None);
        operation.Inner.AdoptSharedResult(result, forceRefresh);
    }

    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _disposeState, 1, 0) != 0)
        {
            return;
        }

        GraphAuthHost? owner = Interlocked.Exchange(ref _owner, null);
        IGraphTokenSource? inner = Interlocked.Exchange(ref _inner, null);
        Volatile.Write(ref _retiredInner, inner);
        try
        {
            DisposeRetiredInnerWhenIdle();
        }
        finally
        {
            if (owner is not null &&
                Interlocked.CompareExchange(ref _hostNotificationState, 1, 0) == 0)
            {
                owner.Unregister(this);
            }
        }
    }

    private TResult Read<TResult>(Func<IGraphTokenSource, TResult> reader)
    {
        using ProxyOperation operation = BeginOperation(CancellationToken.None);
        return reader(operation.Inner);
    }

    private ProxyOperation BeginOperation(CancellationToken callerCancellation)
    {
        if (Volatile.Read(ref _disposeState) != 0)
        {
            throw new ObjectDisposedException(nameof(GraphTokenSourceProxy));
        }

        GraphAuthHost owner = Volatile.Read(ref _owner) ??
            throw new ObjectDisposedException(nameof(GraphTokenSourceProxy));
        GraphAuthHost.GraphAuthOperationLease hostLease = owner.EnterOperation(
            callerCancellation);
        Interlocked.Increment(ref _activeOperations);
        try
        {
            if (Volatile.Read(ref _disposeState) != 0)
            {
                throw new ObjectDisposedException(nameof(GraphTokenSourceProxy));
            }

            IGraphTokenSource inner = Volatile.Read(ref _inner) ??
                throw new ObjectDisposedException(nameof(GraphTokenSourceProxy));
            return new ProxyOperation(this, inner, hostLease);
        }
        catch
        {
            try
            {
                ExitOperation();
            }
            finally
            {
                hostLease.Dispose();
            }

            throw;
        }
    }

    private void ExitOperation()
    {
        if (Interlocked.Decrement(ref _activeOperations) == 0)
        {
            DisposeRetiredInnerWhenIdle();
        }
    }

    private void DisposeRetiredInnerWhenIdle()
    {
        if (Volatile.Read(ref _disposeState) == 0 ||
            Volatile.Read(ref _activeOperations) != 0)
        {
            return;
        }

        Interlocked.Exchange(ref _retiredInner, null)?.Dispose();
    }

    private sealed class ProxyOperation : IDisposable
    {
        private GraphTokenSourceProxy? _proxy;
        private GraphAuthHost.GraphAuthOperationLease? _hostLease;

        internal ProxyOperation(
            GraphTokenSourceProxy proxy,
            IGraphTokenSource inner,
            GraphAuthHost.GraphAuthOperationLease hostLease)
        {
            _proxy = proxy;
            Inner = inner;
            _hostLease = hostLease;
        }

        internal IGraphTokenSource Inner { get; }

        internal CancellationToken Cancellation =>
            Volatile.Read(ref _hostLease)?.Cancellation ??
            throw new ObjectDisposedException(nameof(ProxyOperation));

        public void Dispose()
        {
            GraphTokenSourceProxy? proxy = Interlocked.Exchange(ref _proxy, null);
            GraphAuthHost.GraphAuthOperationLease? hostLease = Interlocked.Exchange(
                ref _hostLease,
                null);
            if (proxy is null)
            {
                return;
            }

            try
            {
                proxy.ExitOperation();
            }
            finally
            {
                hostLease?.Dispose();
            }
        }
    }
}
