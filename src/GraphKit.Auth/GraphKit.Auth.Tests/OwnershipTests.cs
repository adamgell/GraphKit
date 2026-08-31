using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Identity.Client;
using Xunit;

namespace GraphKit.Auth.Tests;

public sealed class OwnershipTests
{
    private static readonly DateTimeOffset InitialNow =
        new(2026, 8, 31, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void PublicFactoryCreatesAllModesWithoutAcquiringAndNeverBuildsMsalForBearer()
    {
        var clock = new GraphTokenSourceTests.FakeClock(InitialNow);
        var constructedModes = new List<GraphAuthMode>();
        var clients = new List<GraphTokenSourceTests.FakeTokenClient>();
        var factory = new GraphTokenSourceFactory(
            (request, _) =>
            {
                constructedModes.Add(request.AuthMode);
                var client = GraphTokenSourceTests.FakeTokenClient.Sequence(
                    GraphTokenSourceTests.Result(
                        request.AuthMode.ToString(),
                        InitialNow,
                        InitialNow.AddHours(1)));
                clients.Add(client);
                return client;
            },
            clock.GetUtcNow);
        using X509Certificate2 certificate = CertificateFixture.Create();
        GraphTokenRequest[] requests =
        [
            CertificateRequest(certificate, ownsMaterial: false),
            GraphTokenSourceTests.SecretRequest(),
            ManagedIdentityRequest(null),
            GraphTokenSourceTests.BearerRequest("fixed")
        ];

        IGraphTokenSource[] sources = requests.Select(factory.Create).ToArray();
        try
        {
            Assert.Equal(
                new[]
                {
                    GraphAuthMode.Certificate,
                    GraphAuthMode.ClientSecret,
                    GraphAuthMode.ManagedIdentity
                },
                constructedModes);
            Assert.Equal(3, clients.Count);
            Assert.All(clients, client => Assert.Equal(0, client.AcquireCount));
            Assert.Equal(4, sources.Distinct(ReferenceEqualityComparer.Instance).Count());
            Assert.Equal(
                new[] { "Certificate", "ClientSecret", "ManagedIdentity", "BearerToken" },
                sources.Select(source => source.AuthMode));
        }
        finally
        {
            foreach (IGraphTokenSource source in sources)
            {
                source.Dispose();
            }
        }
    }

    [Fact]
    public void PublicProviderSurfaceContainsOnlyTheParameterlessFactory()
    {
        Type[] exported = typeof(GraphTokenSourceFactory).Assembly.GetExportedTypes();

        Type factory = Assert.Single(exported);
        Assert.Equal("GraphKit.Auth.GraphTokenSourceFactory", factory.FullName);
        Assert.NotNull(factory.GetConstructor(Type.EmptyTypes));
        Assert.Contains(typeof(IGraphTokenSourceFactory), factory.GetInterfaces());
        Assert.Equal(new Version(1, 0, 0, 0), factory.Assembly.GetName().Version);
    }

    [Fact]
    public void FactoryCreatesOneRealMsalApplicationPerRefreshableSource()
    {
        var clock = new GraphTokenSourceTests.FakeClock(InitialNow);
        using X509Certificate2 certificate = CertificateFixture.Create();
        using System.Security.SecureString secret =
            GraphTokenSourceTests.SecureStringFixture.Create("fixture-secret");
        GraphTokenRequest[] requests =
        [
            CertificateRequest(certificate, ownsMaterial: false),
            GraphTokenSourceTests.SecretRequest(new ClientSecretCredential(secret, false)),
            ManagedIdentityRequest(null),
            ManagedIdentityRequest("00000000-0000-0000-0000-000000000099")
        ];

        var clients = requests
            .Select(request => MsalTokenClient.Create(request, clock.GetUtcNow))
            .ToArray();
        try
        {
            Assert.Equal(4, clients.Select(client => client.ApplicationIdentity).Distinct().Count());
            Assert.All(clients, client => Assert.Equal(0, client.AcquireCount));
            Assert.Equal(
                new[]
                {
                    "ConfidentialClientApplication",
                    "ConfidentialClientApplication",
                    "ManagedIdentityApplication",
                    "ManagedIdentityApplication"
                },
                clients.Select(client => client.ApplicationKind));
        }
        finally
        {
            foreach (MsalTokenClient client in clients)
            {
                client.Dispose();
            }
        }
    }

    [Fact]
    public void ConfidentialAuthorityAppendsTenantAndScopeHasExactlyOneDefaultSuffix()
    {
        var clock = new GraphTokenSourceTests.FakeClock(InitialNow);
        using X509Certificate2 certificate = CertificateFixture.Create();
        GraphTokenRequest request = CertificateRequest(
            certificate,
            ownsMaterial: false,
            authority: "https://login.microsoftonline.com/",
            resource: "https://graph.microsoft.com/.default");
        using MsalTokenClient client = MsalTokenClient.Create(request, clock.GetUtcNow);

        Assert.Equal(
            "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000001",
            client.Authority);
        Assert.Equal("https://graph.microsoft.com/.default", client.Scope);
    }

    [Fact]
    public void ManagedIdentityUsesSystemOrUserAssignedSelector()
    {
        var clock = new GraphTokenSourceTests.FakeClock(InitialNow);
        using MsalTokenClient system = MsalTokenClient.Create(
            ManagedIdentityRequest(null),
            clock.GetUtcNow);
        using MsalTokenClient user = MsalTokenClient.Create(
            ManagedIdentityRequest("00000000-0000-0000-0000-000000000099"),
            clock.GetUtcNow);

        Assert.Null(system.ManagedIdentityClientId);
        Assert.Equal(
            "00000000-0000-0000-0000-000000000099",
            user.ManagedIdentityClientId);
        Assert.Equal("https://graph.microsoft.com/.default", system.Scope);
    }

    [Theory]
    [InlineData(GraphAuthMode.Certificate)]
    [InlineData(GraphAuthMode.ClientSecret)]
    public void OwnedCredentialMaterialIsDisposedExactlyOnce(GraphAuthMode mode)
    {
        var clock = new GraphTokenSourceTests.FakeClock(InitialNow);
        using X509Certificate2 certificate = CertificateFixture.Create();
        using System.Security.SecureString secret =
            GraphTokenSourceTests.SecureStringFixture.Create("fixture-secret");
        GraphTokenRequest request = mode == GraphAuthMode.Certificate
            ? CertificateRequest(certificate, ownsMaterial: true)
            : GraphTokenSourceTests.SecretRequest(new ClientSecretCredential(secret, true));
        int disposalCount = 0;
        IDisposable? disposedMaterial = null;
        var factory = new GraphTokenSourceFactory(
            (_, _) => GraphTokenSourceTests.FakeTokenClient.Sequence(
                GraphTokenSourceTests.Result("unused", InitialNow, InitialNow.AddHours(1))),
            clock.GetUtcNow,
            material =>
            {
                disposedMaterial = material;
                Interlocked.Increment(ref disposalCount);
                material.Dispose();
            });
        IGraphTokenSource source = factory.Create(request);

        source.Dispose();
        source.Dispose();

        Assert.Equal(1, disposalCount);
        Assert.Same(
            mode == GraphAuthMode.Certificate ? certificate : secret,
            disposedMaterial);
    }

    [Theory]
    [InlineData(GraphAuthMode.Certificate)]
    [InlineData(GraphAuthMode.ClientSecret)]
    public void CallerOwnedCredentialMaterialIsNeverDisposed(GraphAuthMode mode)
    {
        var clock = new GraphTokenSourceTests.FakeClock(InitialNow);
        using X509Certificate2 certificate = CertificateFixture.Create();
        using System.Security.SecureString secret =
            GraphTokenSourceTests.SecureStringFixture.Create("fixture-secret");
        GraphTokenRequest request = mode == GraphAuthMode.Certificate
            ? CertificateRequest(certificate, ownsMaterial: false)
            : GraphTokenSourceTests.SecretRequest(new ClientSecretCredential(secret, false));
        int disposalCount = 0;
        var factory = new GraphTokenSourceFactory(
            (_, _) => GraphTokenSourceTests.FakeTokenClient.Sequence(
                GraphTokenSourceTests.Result("unused", InitialNow, InitialNow.AddHours(1))),
            clock.GetUtcNow,
            _ => Interlocked.Increment(ref disposalCount));

        using IGraphTokenSource source = factory.Create(request);

        Assert.Equal(0, disposalCount);
        Assert.True(certificate.HasPrivateKey);
        Assert.True(secret.Length > 0);
    }

    [Fact]
    public void FactoryFailureDisposesOnlyTransferredMaterial()
    {
        var clock = new GraphTokenSourceTests.FakeClock(InitialNow);
        using X509Certificate2 owned = CertificateFixture.Create();
        using X509Certificate2 callerOwned = CertificateFixture.Create();
        var disposed = new List<IDisposable>();
        var factory = new GraphTokenSourceFactory(
            (_, _) => throw new InvalidOperationException("factory-sensitive-detail"),
            clock.GetUtcNow,
            material =>
            {
                disposed.Add(material);
                material.Dispose();
            });

        GraphAuthException ownedFailure = Assert.Throws<GraphAuthException>(() =>
            factory.Create(CertificateRequest(owned, ownsMaterial: true)));
        GraphAuthException callerFailure = Assert.Throws<GraphAuthException>(() =>
            factory.Create(CertificateRequest(callerOwned, ownsMaterial: false)));

        Assert.Single(disposed);
        Assert.Same(owned, disposed[0]);
        Assert.DoesNotContain("factory-sensitive-detail", ownedFailure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("factory-sensitive-detail", callerFailure.Message, StringComparison.Ordinal);
        Assert.True(callerOwned.HasPrivateKey);
    }

    [Fact]
    public async Task DisposalWaitsForActiveAcquisitionBeforeDisposingOwnedMaterial()
    {
        var clock = new GraphTokenSourceTests.FakeClock(InitialNow);
        using X509Certificate2 certificate = CertificateFixture.Create();
        using var entered = new ManualResetEventSlim(false);
        using var release = new ManualResetEventSlim(false);
        var order = new List<string>();
        var client = new GraphTokenSourceTests.FakeTokenClient((_, _) =>
        {
            entered.Set();
            release.Wait();
            lock (order)
            {
                order.Add("acquire-complete");
            }

            return GraphTokenSourceTests.Result("token", InitialNow, InitialNow.AddHours(1));
        });
        var source = new GraphTokenSource(
            CertificateRequest(certificate, ownsMaterial: true),
            client,
            clock.GetUtcNow,
            material =>
            {
                lock (order)
                {
                    order.Add("material-disposed");
                }

                material.Dispose();
            });
        Task<GraphTokenResult> acquire = Task.Run(() =>
            source.Acquire(false, CancellationToken.None));
        Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));

        Task dispose = Task.Run(source.Dispose);
        Assert.NotSame(dispose, await Task.WhenAny(dispose, Task.Delay(100)));
        release.Set();
        await Task.WhenAll(acquire, dispose);

        Assert.Equal(new[] { "acquire-complete", "material-disposed" }, order);
    }

    [Fact]
    public void MsalFailureIsConvertedToSanitizedGraphAuthException()
    {
        const string sensitive = "msal-sensitive-token-or-secret";
        var clock = new GraphTokenSourceTests.FakeClock(InitialNow);
        var msal = new MsalServiceException("temporarily_unavailable", sensitive);
        msal.Data["provider-object"] = new ProviderOwnedObject();
        var client = new GraphTokenSourceTests.FakeTokenClient((_, _) => throw msal);
        using var source = new GraphTokenSource(
            GraphTokenSourceTests.SecretRequest(),
            client,
            clock.GetUtcNow);

        GraphAuthException failure = Assert.Throws<GraphAuthException>(() =>
            source.Acquire(false, CancellationToken.None));

        Assert.Equal("temporarily_unavailable", failure.Code);
        Assert.Equal("Service", failure.Category);
        Assert.DoesNotContain(sensitive, failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("Msal", failure.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Null(failure.InnerException);
        Assert.Empty(failure.Data);
        Assert.All(
            failure.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance),
            property => Assert.DoesNotContain(
                "Microsoft.Identity.Client",
                property.PropertyType.AssemblyQualifiedName ?? string.Empty,
                StringComparison.Ordinal));
        string publicValues = string.Join(
            "|",
            failure.GetType()
                .GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .Where(property => property.GetIndexParameters().Length == 0)
                .Select(property => property.GetValue(failure)?.ToString()));
        Assert.DoesNotContain("Microsoft.Identity.Client", publicValues, StringComparison.Ordinal);
        Assert.DoesNotContain(nameof(ProviderOwnedObject), publicValues, StringComparison.Ordinal);
        Assert.DoesNotContain(sensitive, publicValues, StringComparison.Ordinal);
    }

    [Fact]
    public void FrameworkCancellationRemainsOperationCanceledException()
    {
        var clock = new GraphTokenSourceTests.FakeClock(InitialNow);
        var client = new GraphTokenSourceTests.FakeTokenClient((_, cancellation) =>
            throw new OperationCanceledException(cancellation));
        using var source = new GraphTokenSource(
            GraphTokenSourceTests.SecretRequest(),
            client,
            clock.GetUtcNow);

        Assert.Throws<OperationCanceledException>(() =>
            source.Acquire(false, CancellationToken.None));
    }

    [Fact]
    public void ProviderOwnedFailureIsSanitizedWithoutLeakingItsTypeOrData()
    {
        var clock = new GraphTokenSourceTests.FakeClock(InitialNow);
        var providerFailure = new ProviderOwnedException();
        var client = new GraphTokenSourceTests.FakeTokenClient((_, _) => throw providerFailure);
        using var source = new GraphTokenSource(
            GraphTokenSourceTests.SecretRequest(),
            client,
            clock.GetUtcNow);

        GraphAuthException failure = Assert.Throws<GraphAuthException>(() =>
            source.Acquire(false, CancellationToken.None));

        Assert.Equal("provider_failure", failure.Code);
        Assert.Equal("Provider", failure.Category);
        Assert.Null(failure.InnerException);
        Assert.Empty(failure.Data);
        Assert.DoesNotContain(nameof(ProviderOwnedException), failure.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("provider-sensitive-detail", failure.ToString(), StringComparison.Ordinal);
    }

    private static GraphTokenRequest CertificateRequest(
        X509Certificate2 certificate,
        bool ownsMaterial,
        string authority = "https://login.microsoftonline.com",
        string resource = "https://graph.microsoft.com")
    {
        return new GraphTokenRequest(
            "Global",
            Guid.Parse("00000000-0000-0000-0000-000000000001"),
            new Uri(authority),
            new Uri(resource),
            Guid.Parse("00000000-0000-0000-0000-000000000002"),
            GraphAuthMode.Certificate,
            new CertificateCredential(certificate, ownsMaterial),
            "generation-1");
    }

    private static GraphTokenRequest ManagedIdentityRequest(string? userAssignedClientId)
    {
        return new GraphTokenRequest(
            "Global",
            Guid.Parse("00000000-0000-0000-0000-000000000001"),
            new Uri("https://login.microsoftonline.com"),
            new Uri("https://graph.microsoft.com/"),
            null,
            GraphAuthMode.ManagedIdentity,
            new ManagedIdentityCredential(userAssignedClientId),
            "generation-1");
    }

    private sealed class ProviderOwnedObject
    {
    }

    private sealed class ProviderOwnedException : Exception
    {
        internal ProviderOwnedException()
            : base("provider-sensitive-detail", new InvalidOperationException("inner-sensitive-detail"))
        {
            Data["provider-data"] = new ProviderOwnedObject();
        }
    }

    private static class CertificateFixture
    {
        internal static X509Certificate2 Create()
        {
            using RSA rsa = RSA.Create(2048);
            var request = new CertificateRequest(
                "CN=GraphKit.Auth deterministic unit test",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            return request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(1));
        }
    }
}
