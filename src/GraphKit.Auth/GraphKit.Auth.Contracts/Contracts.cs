using System.Security;
using System.Security.Cryptography.X509Certificates;

namespace GraphKit.Auth;

public enum GraphAuthMode
{
    Certificate,
    ClientSecret,
    ManagedIdentity,
    BearerToken
}

public abstract class GraphCredential
{
    private protected GraphCredential()
    {
    }
}

public sealed class CertificateCredential : GraphCredential
{
    public CertificateCredential(X509Certificate2 certificate, bool ownsMaterial)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if (!certificate.HasPrivateKey)
        {
            throw new ArgumentException(
                "The certificate must contain a private key so it can sign a client assertion.",
                nameof(certificate));
        }

        Certificate = certificate;
        OwnsMaterial = ownsMaterial;
    }

    public X509Certificate2 Certificate { get; }

    public bool OwnsMaterial { get; }
}

public sealed class ClientSecretCredential : GraphCredential
{
    public ClientSecretCredential(SecureString secret, bool ownsMaterial)
    {
        ArgumentNullException.ThrowIfNull(secret);
        if (secret.Length == 0)
        {
            throw new ArgumentException("The client secret must not be empty.", nameof(secret));
        }

        Secret = secret;
        OwnsMaterial = ownsMaterial;
    }

    public SecureString Secret { get; }

    public bool OwnsMaterial { get; }
}

public sealed class ManagedIdentityCredential : GraphCredential
{
    public ManagedIdentityCredential(string? userAssignedClientId)
    {
        if (userAssignedClientId is null)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(userAssignedClientId) ||
            !Guid.TryParse(userAssignedClientId, out Guid clientId) ||
            clientId == Guid.Empty)
        {
            throw new ArgumentException(
                "A user-assigned managed-identity client id must be a non-empty GUID.",
                nameof(userAssignedClientId));
        }

        UserAssignedClientId = clientId.ToString("D");
    }

    public string? UserAssignedClientId { get; }
}

public sealed class FixedBearerCredential : GraphCredential
{
    public FixedBearerCredential(string accessToken)
    {
        AccessToken = RequireText(accessToken, nameof(accessToken));
    }

    public string AccessToken { get; }

    private static string RequireText(string value, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(value, parameterName);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("The fixed bearer token must not be empty.", parameterName);
        }

        return value;
    }
}

public sealed class GraphTokenRequest
{
    public GraphTokenRequest(
        string environment,
        Guid tenantId,
        Uri authority,
        Uri resource,
        Guid? clientId,
        GraphAuthMode authMode,
        GraphCredential credential,
        string credentialGeneration)
    {
        Environment = RequireText(environment, nameof(environment));
        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("The tenant id must be a non-empty GUID.", nameof(tenantId));
        }

        TenantId = tenantId;
        Authority = RequireHttpsAbsoluteUri(authority, nameof(authority));
        Resource = RequireHttpsAbsoluteUri(resource, nameof(resource));
        ArgumentNullException.ThrowIfNull(credential);
        CredentialGeneration = RequireText(credentialGeneration, nameof(credentialGeneration));

        ValidateMode(authMode, clientId, credential);
        ClientId = clientId;
        AuthMode = authMode;
        Credential = credential;
    }

    public string Environment { get; }

    public Guid TenantId { get; }

    public Uri Authority { get; }

    public Uri Resource { get; }

    public Guid? ClientId { get; }

    public GraphAuthMode AuthMode { get; }

    public GraphCredential Credential { get; }

    public string CredentialGeneration { get; }

    private static string RequireText(string value, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(value, parameterName);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"{parameterName} must not be empty.", parameterName);
        }

        return value;
    }

    private static Uri RequireHttpsAbsoluteUri(Uri value, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(value, parameterName);
        if (!value.IsAbsoluteUri ||
            !string.Equals(value.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrEmpty(value.Host) ||
            !string.IsNullOrEmpty(value.UserInfo))
        {
            throw new ArgumentException(
                $"{parameterName} must be an absolute HTTPS URI with a host and no user information.",
                parameterName);
        }

        return value;
    }

    private static void ValidateMode(
        GraphAuthMode authMode,
        Guid? clientId,
        GraphCredential credential)
    {
        bool expectsApplicationClient =
            authMode is GraphAuthMode.Certificate or GraphAuthMode.ClientSecret;

        if (expectsApplicationClient)
        {
            if (!clientId.HasValue || clientId.Value == Guid.Empty)
            {
                throw new ArgumentException(
                    $"Auth mode '{authMode}' requires a non-empty application client id.",
                    nameof(clientId));
            }
        }
        else if (clientId.HasValue)
        {
            throw new ArgumentException(
                $"Auth mode '{authMode}' must not declare an application client id; its credential carries any identity selector.",
                nameof(clientId));
        }

        bool discriminatorMatches = authMode switch
        {
            GraphAuthMode.Certificate => credential is CertificateCredential,
            GraphAuthMode.ClientSecret => credential is ClientSecretCredential,
            GraphAuthMode.ManagedIdentity => credential is ManagedIdentityCredential,
            GraphAuthMode.BearerToken => credential is FixedBearerCredential,
            _ => false
        };

        if (!discriminatorMatches)
        {
            throw new ArgumentException(
                $"Credential type '{credential.GetType().Name}' does not match auth mode '{authMode}'.",
                nameof(credential));
        }
    }
}

public sealed class GraphTokenResult
{
    public required string AccessToken { get; init; }

    public DateTimeOffset ExpiresOnUtc { get; init; }

    public DateTimeOffset ReceivedOnUtc { get; init; }

    public required string TokenType { get; init; }

    public required string[] Scopes { get; init; }

    public string? VerifiedTenantId { get; set; }

    public required string TokenFingerprint { get; init; }

    public required string CredentialGeneration { get; init; }
}

public sealed class GraphAuthException : Exception
{
    public GraphAuthException(
        string code,
        string category,
        string message,
        TimeSpan? retryAfter,
        string? correlationId)
        : base(RequireText(message, nameof(message)))
    {
        Code = RequireText(code, nameof(code));
        Category = RequireText(category, nameof(category));
        if (retryAfter < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(retryAfter),
                retryAfter,
                "RetryAfter must not be negative.");
        }

        RetryAfter = retryAfter;
        CorrelationId = string.IsNullOrWhiteSpace(correlationId) ? null : correlationId;
    }

    public string Code { get; }

    public string Category { get; }

    public TimeSpan? RetryAfter { get; }

    public string? CorrelationId { get; }

    private static string RequireText(string value, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(value, parameterName);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"{parameterName} must not be empty.", parameterName);
        }

        return value;
    }
}

public interface IGraphTokenSource : IDisposable
{
    bool CanRefresh { get; }

    string AuthMode { get; }

    string Audience { get; }

    string? ClientId { get; }

    DateTimeOffset ExpiresOn { get; }

    string? VerifiedTenantId { get; }

    string CredentialGeneration { get; }

    GraphTokenResult Acquire(bool forceRefresh, CancellationToken cancellation);

    void AdoptSharedResult(GraphTokenResult result, bool forceRefresh);
}

public interface IGraphTokenSourceFactory
{
    IGraphTokenSource Create(GraphTokenRequest request);
}
