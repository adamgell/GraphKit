namespace GraphKit.Auth;

internal sealed class GraphTokenSourceProxy : IGraphTokenSource
{
    private readonly TaskCompletionSource<GraphAuthException?> _disposalCompletion =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private IGraphTokenSource? _inner;
    private IGraphTokenSource? _retiredInner;
    private GraphAuthHost? _owner;
    private WeakReference<GraphAuthHost>? _retirementOwner;
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
        Task<GraphAuthException?> completion = StartDisposal();
        if (completion.IsCompletedSuccessfully &&
            completion.Result is GraphAuthException failure)
        {
            throw failure;
        }
    }

    internal Task<GraphAuthException?> DisposeForHostAsync() => StartDisposal();

    private Task<GraphAuthException?> StartDisposal()
    {
        if (Interlocked.CompareExchange(ref _disposeState, 1, 0) != 0)
        {
            return _disposalCompletion.Task;
        }

        GraphAuthHost? owner = Interlocked.Exchange(ref _owner, null);
        if (owner is not null)
        {
            Volatile.Write(ref _retirementOwner, new WeakReference<GraphAuthHost>(owner));
        }

        IGraphTokenSource? inner = Interlocked.Exchange(ref _inner, null);
        Volatile.Write(ref _retiredInner, inner);
        DisposeRetiredInnerWhenIdle();
        return _disposalCompletion.Task;
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

        IGraphTokenSource? retired = Interlocked.Exchange(ref _retiredInner, null);
        if (retired is null)
        {
            return;
        }

        GraphAuthException? failure = null;
        try
        {
            retired.Dispose();
        }
        catch
        {
            failure = CreateProviderDisposalFailure();
        }

        NotifyHost(failure);
        _disposalCompletion.TrySetResult(failure);
    }

    private void NotifyHost(GraphAuthException? failure)
    {
        WeakReference<GraphAuthHost>? retirementOwner = Interlocked.Exchange(
            ref _retirementOwner,
            null);
        if (Interlocked.CompareExchange(ref _hostNotificationState, 1, 0) != 0 ||
            retirementOwner is null ||
            !retirementOwner.TryGetTarget(out GraphAuthHost? owner))
        {
            return;
        }

        owner.CompleteSourceDisposal(this, failure);
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
