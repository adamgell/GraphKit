namespace GraphKit.Auth;

public sealed class GraphTokenSourceFactory : IGraphTokenSourceFactory
{
    private readonly Func<GraphTokenRequest, Func<DateTimeOffset>, ITokenClient> _clientFactory;
    private readonly Func<DateTimeOffset> _utcNow;
    private readonly Action<IDisposable> _disposeMaterial;

    public GraphTokenSourceFactory()
        : this(
            static (request, utcNow) => MsalTokenClient.Create(request, utcNow),
            static () => DateTimeOffset.UtcNow,
            static material => material.Dispose())
    {
    }

    internal GraphTokenSourceFactory(
        Func<GraphTokenRequest, Func<DateTimeOffset>, ITokenClient> clientFactory,
        Func<DateTimeOffset> utcNow,
        Action<IDisposable>? disposeMaterial = null)
    {
        _clientFactory = clientFactory ?? throw new ArgumentNullException(nameof(clientFactory));
        _utcNow = utcNow ?? throw new ArgumentNullException(nameof(utcNow));
        _disposeMaterial = disposeMaterial ?? (static material => material.Dispose());
    }

    public IGraphTokenSource Create(GraphTokenRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        IDisposable? transferredMaterial = GetTransferredMaterial(request.Credential);
        ITokenClient? client = null;
        try
        {
            if (request.AuthMode != GraphAuthMode.BearerToken)
            {
                client = _clientFactory(request, _utcNow) ??
                    throw new InvalidOperationException(
                        "The isolated authentication client factory returned no client.");
            }

            var source = new GraphTokenSource(
                request,
                client,
                _utcNow,
                _disposeMaterial);
            client = null;
            transferredMaterial = null;
            return source;
        }
        catch (OperationCanceledException)
        {
            CleanupFailedTransfer(client, transferredMaterial);
            throw;
        }
        catch (GraphAuthException)
        {
            CleanupFailedTransfer(client, transferredMaterial);
            throw;
        }
        catch (Exception exception)
        {
            CleanupFailedTransfer(client, transferredMaterial);
            throw ProviderFailureSanitizer.Create(exception, "provider_construction_failed", "Provider");
        }
    }

    private void CleanupFailedTransfer(
        ITokenClient? client,
        IDisposable? transferredMaterial)
    {
        bool cleanupFailed = false;
        try
        {
            client?.Dispose();
        }
        catch
        {
            cleanupFailed = true;
        }

        if (transferredMaterial is not null)
        {
            try
            {
                _disposeMaterial(transferredMaterial);
            }
            catch
            {
                cleanupFailed = true;
            }
        }

        if (cleanupFailed)
        {
            throw new GraphAuthException(
                "provider_construction_cleanup_failed",
                "ProviderLifecycle",
                "The isolated authentication provider could not clean up a failed source construction.",
                retryAfter: null,
                correlationId: null);
        }
    }

    internal static IDisposable? GetTransferredMaterial(GraphCredential credential)
    {
        return credential switch
        {
            CertificateCredential { OwnsMaterial: true } certificate => certificate.Certificate,
            ClientSecretCredential { OwnsMaterial: true } secret => secret.Secret,
            _ => null
        };
    }
}
