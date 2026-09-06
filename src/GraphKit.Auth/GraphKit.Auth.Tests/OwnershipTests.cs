using System.Net.Http.Headers;
using System.Reflection;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Identity.Client;
using Xunit;

namespace GraphKit.Auth.Tests;

public sealed class OwnershipTests
{
    private const string CleanupFailureDataKey =
        "GraphKit.Auth.ProviderConstructionCleanupFailed";
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
        ConstructorInfo constructor = Assert.Single(factory.GetConstructors(
            BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly));
        Assert.Empty(constructor.GetParameters());
        MethodInfo create = Assert.Single(factory.GetMethods(
            BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly));
        Assert.Equal(nameof(IGraphTokenSourceFactory.Create), create.Name);
        ParameterInfo parameter = Assert.Single(create.GetParameters());
        Assert.Equal(typeof(GraphTokenRequest), parameter.ParameterType);
        Assert.Equal(typeof(IGraphTokenSource), create.ReturnType);
        Assert.False(create.IsStatic);
        Assert.Empty(factory.GetFields(
            BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly));
        Assert.Empty(factory.GetProperties(
            BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly));
        Assert.Empty(factory.GetEvents(
            BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly));
        Assert.Equal(new[] { typeof(IGraphTokenSourceFactory) }, factory.GetInterfaces());
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

        FieldInfo confidential = typeof(MsalTokenClient).GetField(
            "_confidentialApplication",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        FieldInfo managed = typeof(MsalTokenClient).GetField(
            "_managedIdentityApplication",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        Assert.All(clients, client =>
        {
            Assert.Null(confidential.GetValue(client));
            Assert.Null(managed.GetValue(client));
            Assert.Throws<ObjectDisposedException>(() => _ = client.ApplicationIdentity);
        });
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

        IGraphTokenSource source = factory.Create(request);
        source.Dispose();

        Assert.Equal(0, disposalCount);
        Assert.True(certificate.HasPrivateKey);
        Assert.True(secret.Length > 0);

        using IGraphTokenSource reused = factory.Create(request);
        reused.Dispose();
        Assert.Equal(0, disposalCount);
        Assert.True(certificate.HasPrivateKey);
        Assert.True(secret.Length > 0);
    }

    [Theory]
    [InlineData(GraphAuthMode.Certificate)]
    [InlineData(GraphAuthMode.ClientSecret)]
    public void OwnedCredentialMaterialCannotBeTransferredTwiceAcrossFactories(GraphAuthMode mode)
    {
        var clock = new GraphTokenSourceTests.FakeClock(InitialNow);
        using X509Certificate2 certificate = CertificateFixture.Create();
        using SecureString secret = GraphTokenSourceTests.SecureStringFixture.Create("fixture-secret");
        GraphTokenRequest firstRequest = OwnedRequest(mode, certificate, secret);
        GraphTokenRequest duplicateRequest = OwnedRequest(mode, certificate, secret);
        int disposalCount = 0;
        GraphTokenSourceFactory CreateFactory() => new(
            (_, _) => GraphTokenSourceTests.FakeTokenClient.Sequence(
                GraphTokenSourceTests.Result("unused", InitialNow, InitialNow.AddHours(1))),
            clock.GetUtcNow,
            material =>
            {
                Interlocked.Increment(ref disposalCount);
                material.Dispose();
            });
        var firstFactory = CreateFactory();
        var secondFactory = CreateFactory();
        IGraphTokenSource first = firstFactory.Create(firstRequest);

        GraphAuthException duplicate = Assert.Throws<GraphAuthException>(() =>
            secondFactory.Create(duplicateRequest));
        first.Dispose();
        first.Dispose();

        Assert.Equal("credential_material_consumed", duplicate.Code);
        Assert.Equal("CredentialOwnership", duplicate.Category);
        Assert.Equal(1, disposalCount);
    }

    [Theory]
    [InlineData(GraphAuthMode.Certificate)]
    [InlineData(GraphAuthMode.ClientSecret)]
    public async Task ConcurrentOwnedCredentialReuseHasOneWinnerAndOneDisposal(GraphAuthMode mode)
    {
        var clock = new GraphTokenSourceTests.FakeClock(InitialNow);
        using X509Certificate2 certificate = CertificateFixture.Create();
        using SecureString secret = GraphTokenSourceTests.SecureStringFixture.Create("fixture-secret");
        GraphTokenRequest firstRequest = OwnedRequest(mode, certificate, secret);
        GraphTokenRequest duplicateRequest = OwnedRequest(mode, certificate, secret);
        using var entered = new ManualResetEventSlim(false);
        using var release = new ManualResetEventSlim(false);
        int disposalCount = 0;
        GraphTokenSourceFactory CreateFactory() => new(
            (_, _) =>
            {
                entered.Set();
                release.Wait();
                return GraphTokenSourceTests.FakeTokenClient.Sequence(
                    GraphTokenSourceTests.Result("unused", InitialNow, InitialNow.AddHours(1)));
            },
            clock.GetUtcNow,
            material =>
            {
                Interlocked.Increment(ref disposalCount);
                material.Dispose();
            });
        var firstFactory = CreateFactory();
        var secondFactory = CreateFactory();

        Task<CreateOutcome> first = Task.Run(() => CaptureCreate(firstFactory, firstRequest));
        Task<CreateOutcome>? second = null;
        Exception? observationFailure = null;
        bool duplicateRejectedBeforeWinnerCompleted = false;
        try
        {
            Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
            second = Task.Run(() => CaptureCreate(secondFactory, duplicateRequest));
            _ = await second.WaitAsync(TimeSpan.FromSeconds(5));
            duplicateRejectedBeforeWinnerCompleted = !first.IsCompleted;
        }
        catch (Exception exception)
        {
            observationFailure = exception;
        }
        finally
        {
            release.Set();
        }

        var pending = second is null ? new[] { first } : new[] { first, second };
        CreateOutcome[] outcomes = await Task.WhenAll(pending).WaitAsync(TimeSpan.FromSeconds(5));
        foreach (IGraphTokenSource source in outcomes
            .Where(outcome => outcome.Source is not null)
            .Select(outcome => outcome.Source!))
        {
            source.Dispose();
        }

        if (observationFailure is not null)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo
                .Capture(observationFailure)
                .Throw();
        }

        Assert.True(duplicateRejectedBeforeWinnerCompleted);
        Assert.Single(outcomes, outcome => outcome.Source is not null);
        GraphAuthException failure = Assert.Single(outcomes
            .Where(outcome => outcome.Failure is not null)
            .Select(outcome => outcome.Failure!));
        Assert.Equal("credential_material_consumed", failure.Code);
        Assert.Equal(1, disposalCount);
    }

    [Theory]
    [InlineData(GraphAuthMode.Certificate)]
    [InlineData(GraphAuthMode.ClientSecret)]
    public void FailedOwnedTransferRemainsConsumedAndIsDisposedExactlyOnce(GraphAuthMode mode)
    {
        var clock = new GraphTokenSourceTests.FakeClock(InitialNow);
        using X509Certificate2 certificate = CertificateFixture.Create();
        using SecureString secret = GraphTokenSourceTests.SecureStringFixture.Create("fixture-secret");
        GraphTokenRequest firstRequest = OwnedRequest(mode, certificate, secret);
        GraphTokenRequest duplicateRequest = OwnedRequest(mode, certificate, secret);
        int disposalCount = 0;
        Action<IDisposable> dispose = material =>
        {
            Interlocked.Increment(ref disposalCount);
            material.Dispose();
        };
        var failingFactory = new GraphTokenSourceFactory(
            (_, _) => throw new InvalidOperationException("construction failure"),
            clock.GetUtcNow,
            dispose);
        var retryFactory = new GraphTokenSourceFactory(
            (_, _) => GraphTokenSourceTests.FakeTokenClient.Sequence(
                GraphTokenSourceTests.Result("unused", InitialNow, InitialNow.AddHours(1))),
            clock.GetUtcNow,
            dispose);

        GraphAuthException construction = Assert.Throws<GraphAuthException>(() =>
            failingFactory.Create(firstRequest));
        GraphAuthException reused = Assert.Throws<GraphAuthException>(() =>
            retryFactory.Create(duplicateRequest));

        Assert.Equal("provider_construction_failed", construction.Code);
        Assert.Equal("credential_material_consumed", reused.Code);
        Assert.Equal(1, disposalCount);
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
    public void CleanupFailureDoesNotReplaceSanitizedConstructionFailure()
    {
        var clock = new GraphTokenSourceTests.FakeClock(InitialNow);
        using X509Certificate2 owned = CertificateFixture.Create();
        var factory = new GraphTokenSourceFactory(
            (_, _) => throw new InvalidOperationException("construction-sensitive-detail"),
            clock.GetUtcNow,
            _ => throw new InvalidOperationException("cleanup-sensitive-detail"));

        GraphAuthException failure = Assert.Throws<GraphAuthException>(() =>
            factory.Create(CertificateRequest(owned, ownsMaterial: true)));

        Assert.Equal("provider_construction_failed", failure.Code);
        Assert.Equal("Provider", failure.Category);
        Assert.True(failure.Data[CleanupFailureDataKey] is true);
        Assert.DoesNotContain("construction-sensitive-detail", failure.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("cleanup-sensitive-detail", failure.ToString(), StringComparison.Ordinal);
        failure.Data["provider-owned-data"] = new ProviderOwnedObject();

        Exception boundaryFailure = RecreateAtProviderBoundary(failure);
        GraphAuthException boundaryGraphFailure = Assert.IsType<GraphAuthException>(boundaryFailure);
        Assert.Equal("provider_construction_failed", boundaryGraphFailure.Code);
        Assert.Equal("Provider", boundaryGraphFailure.Category);
        Assert.True(boundaryFailure.Data[CleanupFailureDataKey] is true);
        Assert.Single(boundaryFailure.Data);
    }

    [Fact]
    public void CleanupFailureDoesNotReplaceConstructionCancellation()
    {
        var clock = new GraphTokenSourceTests.FakeClock(InitialNow);
        using X509Certificate2 owned = CertificateFixture.Create();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var expected = new OperationCanceledException(
            "construction-sensitive-detail",
            cancellation.Token);
        var factory = new GraphTokenSourceFactory(
            (_, _) => throw expected,
            clock.GetUtcNow,
            _ => throw new InvalidOperationException("cleanup-sensitive-detail"));

        OperationCanceledException failure = Assert.Throws<OperationCanceledException>(() =>
            factory.Create(CertificateRequest(owned, ownsMaterial: true)));

        Assert.Same(expected, failure);
        Assert.True(failure.Data[CleanupFailureDataKey] is true);

        Exception boundaryFailure = RecreateAtProviderBoundary(failure);
        Assert.IsType<OperationCanceledException>(boundaryFailure);
        Assert.True(boundaryFailure.Data[CleanupFailureDataKey] is true);
    }

    [Fact]
    public void CleanupFailureDoesNotReplaceGraphAuthConstructionFailure()
    {
        var clock = new GraphTokenSourceTests.FakeClock(InitialNow);
        using X509Certificate2 owned = CertificateFixture.Create();
        var expected = new GraphAuthException(
            "fixture_failure",
            "Fixture",
            "fixture-safe-message",
            retryAfter: null,
            correlationId: null);
        var factory = new GraphTokenSourceFactory(
            (_, _) => throw expected,
            clock.GetUtcNow,
            _ => throw new InvalidOperationException("cleanup-sensitive-detail"));

        GraphAuthException failure = Assert.Throws<GraphAuthException>(() =>
            factory.Create(CertificateRequest(owned, ownsMaterial: true)));

        Assert.Same(expected, failure);
        Assert.True(failure.Data[CleanupFailureDataKey] is true);

        Exception boundaryFailure = RecreateAtProviderBoundary(failure);
        GraphAuthException boundaryGraphFailure = Assert.IsType<GraphAuthException>(boundaryFailure);
        Assert.Equal("fixture_failure", boundaryGraphFailure.Code);
        Assert.Equal("Fixture", boundaryGraphFailure.Category);
        Assert.True(boundaryFailure.Data[CleanupFailureDataKey] is true);
    }

    [Theory]
    [InlineData(GraphAuthMode.Certificate)]
    [InlineData(GraphAuthMode.ClientSecret)]
    public async Task DisposalCancelsAndDrainsActiveAcquisitionBeforeOwnedMaterial(
        GraphAuthMode mode)
    {
        var clock = new GraphTokenSourceTests.FakeClock(InitialNow);
        using X509Certificate2 certificate = CertificateFixture.Create();
        using SecureString secret = GraphTokenSourceTests.SecureStringFixture.Create("fixture-secret");
        using var entered = new ManualResetEventSlim(false);
        using var emergencyRelease = new ManualResetEventSlim(false);
        var order = new List<string>();
        var client = new GraphTokenSourceTests.FakeTokenClient((_, cancellation) =>
        {
            lock (order)
            {
                order.Add("acquire-entered");
            }
            entered.Set();

            try
            {
                int completed = WaitHandle.WaitAny(
                    new[] { cancellation.WaitHandle, emergencyRelease.WaitHandle });
                if (completed == 1)
                {
                    throw new OperationCanceledException(
                        "Task 7 fixture emergency release ended a blocked acquisition.");
                }
                lock (order)
                {
                    order.Add("cancellation-observed");
                }
                cancellation.ThrowIfCancellationRequested();
                throw new InvalidOperationException("Task 7 acquisition resumed without cancellation.");
            }
            finally
            {
                lock (order)
                {
                    order.Add("acquire-exited");
                }
            }
        });
        var source = new GraphTokenSource(
            OwnedRequest(mode, certificate, secret),
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
        Task<GraphTokenResult>? acquire = null;
        Task? dispose = null;
        try
        {
            acquire = Task.Run(() =>
                source.Acquire(false, CancellationToken.None));
            Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));

            dispose = Task.Run(source.Dispose);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                await acquire.WaitAsync(TimeSpan.FromSeconds(5)));
            await dispose.WaitAsync(TimeSpan.FromSeconds(5));

            Assert.Equal(
                new[]
                {
                    "acquire-entered",
                    "cancellation-observed",
                    "acquire-exited",
                    "material-disposed"
                },
                order);
            Assert.Equal(1, client.AcquireCount);
            Assert.Equal(1, client.DisposeCount);
        }
        finally
        {
            emergencyRelease.Set();
            dispose ??= Task.Run(source.Dispose);
            await ObserveBoundedAsync(acquire);
            await ObserveBoundedAsync(dispose);
        }

        static async Task ObserveBoundedAsync(Task? task)
        {
            if (task is null)
            {
                return;
            }

            try
            {
                await task.WaitAsync(TimeSpan.FromSeconds(5));
            }
            catch
            {
                // The owning assertions above validate the normal outcome. This
                // cleanup observer only prevents a failed mutation from leaking.
            }
        }
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
    public void MsalFailureMapsCorrelationAndDeltaRetryAfter()
    {
        var clock = new GraphTokenSourceTests.FakeClock(InitialNow);
        var msal = ServiceFailure(
            new RetryConditionHeaderValue(TimeSpan.FromSeconds(17)),
            "safe-correlation-123");

        GraphAuthException failure = AcquireFailure(msal, clock);

        Assert.Equal("safe-correlation-123", failure.CorrelationId);
        Assert.Equal(TimeSpan.FromSeconds(17), failure.RetryAfter);
    }

    [Fact]
    public void MsalFailureMapsDateRetryAfterUsingTheInjectedClock()
    {
        var clock = new GraphTokenSourceTests.FakeClock(InitialNow);
        var msal = ServiceFailure(
            new RetryConditionHeaderValue(InitialNow.AddMinutes(4)),
            correlationId: null);

        GraphAuthException failure = AcquireFailure(msal, clock);

        Assert.Equal(TimeSpan.FromMinutes(4), failure.RetryAfter);
    }

    [Fact]
    public void MsalFailureClampsPastDateRetryAfterToZero()
    {
        var clock = new GraphTokenSourceTests.FakeClock(InitialNow);
        var msal = ServiceFailure(
            new RetryConditionHeaderValue(InitialNow.AddMinutes(-1)),
            correlationId: null);

        GraphAuthException failure = AcquireFailure(msal, clock);

        Assert.Equal(TimeSpan.Zero, failure.RetryAfter);
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

    private static GraphTokenRequest OwnedRequest(
        GraphAuthMode mode,
        X509Certificate2 certificate,
        SecureString secret)
    {
        return mode == GraphAuthMode.Certificate
            ? CertificateRequest(certificate, ownsMaterial: true)
            : GraphTokenSourceTests.SecretRequest(new ClientSecretCredential(secret, true));
    }

    private static CreateOutcome CaptureCreate(
        GraphTokenSourceFactory factory,
        GraphTokenRequest request)
    {
        try
        {
            return new CreateOutcome(factory.Create(request), null);
        }
        catch (GraphAuthException exception)
        {
            return new CreateOutcome(null, exception);
        }
    }

    private static Exception RecreateAtProviderBoundary(Exception failure)
    {
        Type boundaryType = typeof(GraphAuthHost).Assembly.GetType(
            "GraphKit.Auth.ProviderBoundaryFailure",
            throwOnError: true)!;
        MethodInfo recreate = boundaryType.GetMethod(
            "Recreate",
            BindingFlags.Static | BindingFlags.NonPublic) ??
            throw new InvalidOperationException("ProviderBoundaryFailure.Recreate was not found.");
        return (Exception)(recreate.Invoke(
            null,
            [failure, CancellationToken.None, "provider_construction_failed", "Provider"]) ??
            throw new InvalidOperationException("ProviderBoundaryFailure.Recreate returned null."));
    }

    private static MsalServiceException ServiceFailure(
        RetryConditionHeaderValue retryAfter,
        string? correlationId)
    {
        var exception = new MsalServiceException(
            "temporarily_unavailable",
            "msal-sensitive-detail")
        {
            CorrelationId = correlationId
        };
        var response = new HttpResponseMessage();
        response.Headers.RetryAfter = retryAfter;
        exception.Headers = response.Headers;
        return exception;
    }

    private static GraphAuthException AcquireFailure(
        MsalServiceException exception,
        GraphTokenSourceTests.FakeClock clock)
    {
        using var source = new GraphTokenSource(
            GraphTokenSourceTests.SecretRequest(),
            new GraphTokenSourceTests.FakeTokenClient((_, _) => throw exception),
            clock.GetUtcNow);
        return Assert.Throws<GraphAuthException>(() =>
            source.Acquire(false, CancellationToken.None));
    }

    private sealed record CreateOutcome(
        IGraphTokenSource? Source,
        GraphAuthException? Failure);

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
