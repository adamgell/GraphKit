using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.AppConfig;

namespace GraphKit.Auth;

internal sealed class MsalTokenClient : ITokenClient
{
    private readonly Func<DateTimeOffset> _utcNow;
    private readonly string _scope;
    private readonly string _credentialGeneration;
    private IConfidentialClientApplication? _confidentialApplication;
    private IManagedIdentityApplication? _managedIdentityApplication;
    private int _acquireCount;
    private int _disposeState;

    private MsalTokenClient(
        IConfidentialClientApplication application,
        string authority,
        string scope,
        string credentialGeneration,
        Func<DateTimeOffset> utcNow)
    {
        _confidentialApplication = application;
        Authority = authority;
        _scope = scope;
        _credentialGeneration = credentialGeneration;
        _utcNow = utcNow;
        ApplicationKind = "ConfidentialClientApplication";
    }

    private MsalTokenClient(
        IManagedIdentityApplication application,
        string? managedIdentityClientId,
        string scope,
        string credentialGeneration,
        Func<DateTimeOffset> utcNow)
    {
        _managedIdentityApplication = application;
        ManagedIdentityClientId = managedIdentityClientId;
        _scope = scope;
        _credentialGeneration = credentialGeneration;
        _utcNow = utcNow;
        ApplicationKind = "ManagedIdentityApplication";
    }

    internal string? Authority { get; }

    internal string Scope => _scope;

    internal string? ManagedIdentityClientId { get; }

    internal string ApplicationKind { get; }

    internal int AcquireCount => Volatile.Read(ref _acquireCount);

    internal object ApplicationIdentity =>
        (object?)Volatile.Read(ref _confidentialApplication) ??
        Volatile.Read(ref _managedIdentityApplication) ??
        throw new ObjectDisposedException(nameof(MsalTokenClient));

    internal static MsalTokenClient Create(
        GraphTokenRequest request,
        Func<DateTimeOffset> utcNow)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(utcNow);
        string scope = GetScope(request.Resource.AbsoluteUri);

        try
        {
            return request.AuthMode switch
            {
                GraphAuthMode.Certificate => CreateCertificate(request, scope, utcNow),
                GraphAuthMode.ClientSecret => CreateClientSecret(request, scope, utcNow),
                GraphAuthMode.ManagedIdentity => CreateManagedIdentity(request, scope, utcNow),
                GraphAuthMode.BearerToken => throw new InvalidOperationException(
                    "A fixed bearer token must not construct an authentication client."),
                _ => throw new InvalidOperationException("The authentication mode is unsupported.")
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (GraphAuthException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw ProviderFailureSanitizer.Create(
                exception,
                "provider_construction_failed",
                "Provider",
                utcNow);
        }
    }

    public GraphTokenResult Acquire(
        bool forceRefresh,
        CancellationToken cancellation)
    {
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref _disposeState) != 0,
            this);
        Interlocked.Increment(ref _acquireCount);

        try
        {
            AuthenticationResult result;
            IConfidentialClientApplication? confidential =
                Volatile.Read(ref _confidentialApplication);
            if (confidential is not null)
            {
                result = confidential
                    .AcquireTokenForClient([_scope])
                    .WithForceRefresh(forceRefresh)
                    .ExecuteAsync(cancellation)
                    .GetAwaiter()
                    .GetResult();
            }
            else
            {
                IManagedIdentityApplication managed =
                    Volatile.Read(ref _managedIdentityApplication) ??
                    throw new ObjectDisposedException(nameof(MsalTokenClient));
                result = managed
                    .AcquireTokenForManagedIdentity(_scope)
                    .WithForceRefresh(forceRefresh)
                    .ExecuteAsync(cancellation)
                    .GetAwaiter()
                    .GetResult();
            }

            return TokenResultFactory.Create(
                result.AccessToken,
                result.ExpiresOn,
                _utcNow(),
                result.Scopes,
                _credentialGeneration);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (GraphAuthException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw ProviderFailureSanitizer.Create(
                exception,
                "provider_failure",
                "Provider",
                _utcNow);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposeState, 1) != 0)
        {
            return;
        }

        Interlocked.Exchange(ref _confidentialApplication, null);
        Interlocked.Exchange(ref _managedIdentityApplication, null);
    }

    internal static string GetScope(string resource)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(resource);
        string normalized = resource.TrimEnd('/');
        const string suffix = "/.default";
        while (normalized.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[..^suffix.Length].TrimEnd('/');
        }

        return normalized + suffix;
    }

    private static MsalTokenClient CreateCertificate(
        GraphTokenRequest request,
        string scope,
        Func<DateTimeOffset> utcNow)
    {
        var credential = (CertificateCredential)request.Credential;
        string authority = GetTenantAuthority(request);
        IConfidentialClientApplication application = ConfidentialClientApplicationBuilder
            .Create(request.ClientId!.Value.ToString("D"))
            .WithAuthority(authority)
            .WithCertificate(credential.Certificate)
            .Build();
        return new MsalTokenClient(
            application,
            authority,
            scope,
            request.CredentialGeneration,
            utcNow);
    }

    private static MsalTokenClient CreateClientSecret(
        GraphTokenRequest request,
        string scope,
        Func<DateTimeOffset> utcNow)
    {
        var credential = (ClientSecretCredential)request.Credential;
        string authority = GetTenantAuthority(request);
        nint secretPointer = Marshal.SecureStringToGlobalAllocUnicode(credential.Secret);
        try
        {
            string secret = Marshal.PtrToStringUni(secretPointer) ??
                throw new InvalidOperationException(
                    "The transferred client secret could not be read.");
            IConfidentialClientApplication application = ConfidentialClientApplicationBuilder
                .Create(request.ClientId!.Value.ToString("D"))
                .WithAuthority(authority)
                .WithClientSecret(secret)
                .Build();
            return new MsalTokenClient(
                application,
                authority,
                scope,
                request.CredentialGeneration,
                utcNow);
        }
        finally
        {
            Marshal.ZeroFreeGlobalAllocUnicode(secretPointer);
        }
    }

    private static MsalTokenClient CreateManagedIdentity(
        GraphTokenRequest request,
        string scope,
        Func<DateTimeOffset> utcNow)
    {
        var credential = (ManagedIdentityCredential)request.Credential;
        ManagedIdentityId identity = credential.UserAssignedClientId is null
            ? ManagedIdentityId.SystemAssigned
            : ManagedIdentityId.WithUserAssignedClientId(credential.UserAssignedClientId);
        IManagedIdentityApplication application = ManagedIdentityApplicationBuilder
            .Create(identity)
            .Build();
        return new MsalTokenClient(
            application,
            credential.UserAssignedClientId,
            scope,
            request.CredentialGeneration,
            utcNow);
    }

    private static string GetTenantAuthority(GraphTokenRequest request)
    {
        return request.Authority.AbsoluteUri.TrimEnd('/') + "/" +
            request.TenantId.ToString("D");
    }
}

internal static class TokenResultFactory
{
    internal static GraphTokenResult Create(
        string accessToken,
        DateTimeOffset expiresOnUtc,
        DateTimeOffset receivedOnUtc,
        string scope,
        string credentialGeneration) =>
        Create(
            accessToken,
            expiresOnUtc,
            receivedOnUtc,
            [scope],
            credentialGeneration);

    internal static GraphTokenResult Create(
        string accessToken,
        DateTimeOffset expiresOnUtc,
        DateTimeOffset receivedOnUtc,
        IEnumerable<string> scopes,
        string credentialGeneration)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);
        ArgumentNullException.ThrowIfNull(scopes);
        string[] grantedScopes = [.. scopes];
        byte[] bearerBytes = Encoding.UTF8.GetBytes(accessToken);
        try
        {
            string fingerprint = Convert.ToHexString(SHA256.HashData(bearerBytes))
                .ToLowerInvariant();
            return new GraphTokenResult
            {
                AccessToken = accessToken,
                ExpiresOnUtc = expiresOnUtc,
                ReceivedOnUtc = receivedOnUtc,
                TokenType = "Bearer",
                Scopes = grantedScopes,
                VerifiedTenantId = null,
                TokenFingerprint = fingerprint,
                CredentialGeneration = credentialGeneration
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bearerBytes);
        }
    }
}

internal static class ProviderFailureSanitizer
{
    internal static GraphAuthException Create(
        Exception exception,
        string defaultCode,
        string defaultCategory,
        Func<DateTimeOffset>? utcNow = null)
    {
        ArgumentNullException.ThrowIfNull(exception);
        if (exception is GraphAuthException graphAuthException)
        {
            return graphAuthException;
        }

        string code = defaultCode;
        string category = defaultCategory;
        string? correlationId = null;
        TimeSpan? retryAfter = null;
        if (exception is MsalException msalException)
        {
            code = string.IsNullOrWhiteSpace(msalException.ErrorCode)
                ? "authentication_failed"
                : msalException.ErrorCode;
            correlationId = string.IsNullOrWhiteSpace(msalException.CorrelationId)
                ? null
                : msalException.CorrelationId;
            category = msalException switch
            {
                MsalUiRequiredException => "UiRequired",
                MsalServiceException => "Service",
                MsalClientException => "Client",
                _ => "Authentication"
            };

            if (msalException is MsalServiceException serviceException)
            {
                retryAfter = GetRetryAfter(
                    serviceException,
                    utcNow ?? (static () => DateTimeOffset.UtcNow));
            }
        }

        return new GraphAuthException(
            code,
            category,
            "The isolated authentication provider could not complete token acquisition.",
            retryAfter,
            correlationId);
    }

    private static TimeSpan? GetRetryAfter(
        MsalServiceException exception,
        Func<DateTimeOffset> utcNow)
    {
        if (exception.Headers?.RetryAfter is null)
        {
            return null;
        }

        TimeSpan? retryAfter = exception.Headers.RetryAfter.Delta;
        if (retryAfter is null && exception.Headers.RetryAfter.Date is DateTimeOffset date)
        {
            retryAfter = date - utcNow();
        }

        if (retryAfter < TimeSpan.Zero)
        {
            return TimeSpan.Zero;
        }

        return retryAfter;
    }
}
