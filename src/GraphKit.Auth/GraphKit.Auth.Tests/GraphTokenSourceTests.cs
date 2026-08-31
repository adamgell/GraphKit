using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace GraphKit.Auth.Tests;

public sealed class GraphTokenSourceTests
{
    private static readonly DateTimeOffset InitialNow =
        new(2026, 8, 31, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void ConstructionDoesNotAcquireAToken()
    {
        var clock = new FakeClock(InitialNow);
        var client = new FakeTokenClient((_, _) =>
            throw new InvalidOperationException("acquisition must remain lazy"));

        using var source = CreateRefreshableSource(client, clock);

        Assert.Equal(0, client.AcquireCount);
        Assert.Equal(DateTimeOffset.MinValue, source.ExpiresOn);
        Assert.Null(source.VerifiedTenantId);
    }

    [Fact]
    public void OrdinaryAcquireReusesAValidCachedResult()
    {
        var clock = new FakeClock(InitialNow);
        var client = FakeTokenClient.Sequence(
            Result("first", InitialNow, InitialNow.AddHours(1)),
            Result("unexpected", InitialNow.AddMinutes(1), InitialNow.AddHours(2)));
        using var source = CreateRefreshableSource(client, clock);

        GraphTokenResult first = source.Acquire(false, CancellationToken.None);
        clock.Advance(TimeSpan.FromMinutes(10));
        GraphTokenResult second = source.Acquire(false, CancellationToken.None);

        Assert.Same(first, second);
        Assert.Equal("first", second.AccessToken);
        Assert.Equal(1, client.AcquireCount);
    }

    [Theory]
    [InlineData(600, 60)]
    [InlineData(3600, 300)]
    [InlineData(7200, 300)]
    public void AdaptiveRefreshUsesTheBoundedLifetimeSkew(
        int lifetimeSeconds,
        int expectedBaseSkewSeconds)
    {
        var clock = new FakeClock(InitialNow);
        GraphTokenResult first = Result(
            "adaptive",
            InitialNow,
            InitialNow.AddSeconds(lifetimeSeconds));
        var client = FakeTokenClient.Sequence(
            first,
            Result("refreshed", InitialNow.AddSeconds(1), InitialNow.AddHours(4)));
        using var source = CreateRefreshableSource(client, clock);

        source.Acquire(false, CancellationToken.None);
        double spread = EarlySpreadSeconds(first.TokenFingerprint, expectedBaseSkewSeconds);
        clock.UtcNow = first.ExpiresOnUtc
            .AddSeconds(-(expectedBaseSkewSeconds + spread))
            .AddMilliseconds(-1);
        Assert.Equal("adaptive", source.Acquire(false, CancellationToken.None).AccessToken);

        clock.UtcNow = first.ExpiresOnUtc
            .AddSeconds(-(expectedBaseSkewSeconds + spread))
            .AddMilliseconds(1);
        Assert.Equal("refreshed", source.Acquire(false, CancellationToken.None).AccessToken);
        Assert.Equal(2, client.AcquireCount);
    }

    [Fact]
    public void FingerprintDerivedSpreadRefreshesEarlierAndDeterministically()
    {
        var clock = new FakeClock(InitialNow);
        GraphTokenResult first = Result("spread-token", InitialNow, InitialNow.AddMinutes(10));
        var client = FakeTokenClient.Sequence(
            first,
            Result("replacement", InitialNow.AddSeconds(1), InitialNow.AddHours(1)));
        using var source = CreateRefreshableSource(client, clock);

        source.Acquire(false, CancellationToken.None);
        double spread = EarlySpreadSeconds(first.TokenFingerprint, 60);
        Assert.InRange(spread, 0, 6);
        clock.UtcNow = first.ExpiresOnUtc.AddSeconds(-(60 + spread));

        Assert.Equal("replacement", source.Acquire(false, CancellationToken.None).AccessToken);
    }

    [Fact]
    public void ForcedRefreshReplacesAnOlderCachedResult()
    {
        var clock = new FakeClock(InitialNow);
        var client = FakeTokenClient.Sequence(
            Result("first", InitialNow, InitialNow.AddHours(1)),
            Result("second", InitialNow.AddSeconds(1), InitialNow.AddHours(2)));
        using var source = CreateRefreshableSource(client, clock);

        Assert.Equal("first", source.Acquire(false, CancellationToken.None).AccessToken);
        Assert.Equal("second", source.Acquire(true, CancellationToken.None).AccessToken);
        Assert.Equal("second", source.Acquire(false, CancellationToken.None).AccessToken);
        Assert.Equal(new[] { false, true }, client.ForceRefreshValues);
    }

    [Fact]
    public async Task OrdinaryAndForcedAcquisitionsUseSeparateFlights()
    {
        var clock = new FakeClock(InitialNow);
        using var release = new ManualResetEventSlim(false);
        using var twoEntered = new CountdownEvent(2);
        var client = new FakeTokenClient((force, cancellation) =>
        {
            twoEntered.Signal();
            release.Wait(cancellation);
            return Result(
                force ? "forced" : "ordinary",
                InitialNow,
                InitialNow.AddHours(force ? 2 : 1));
        });
        using var source = CreateRefreshableSource(client, clock);

        Task<GraphTokenResult> ordinary = Task.Run(() =>
            source.Acquire(false, CancellationToken.None));
        Task<GraphTokenResult> forced = Task.Run(() =>
            source.Acquire(true, CancellationToken.None));

        Assert.True(twoEntered.Wait(TimeSpan.FromSeconds(5)));
        Assert.Equal(2, client.AcquireCount);
        release.Set();
        GraphTokenResult[] results = await Task.WhenAll(ordinary, forced);

        Assert.Contains(results, result => result.AccessToken == "ordinary");
        Assert.Contains(results, result => result.AccessToken == "forced");
    }

    [Fact]
    public void SameTickForcedResultWinsOverOrdinaryAdoption()
    {
        var clock = new FakeClock(InitialNow);
        using var source = CreateRefreshableSource(
            FakeTokenClient.Sequence(Result("unused", InitialNow, InitialNow.AddHours(1))),
            clock);
        GraphTokenResult forced = Result("forced", InitialNow, InitialNow.AddMinutes(5));
        GraphTokenResult ordinary = Result("ordinary", InitialNow, InitialNow.AddHours(2));

        source.AdoptSharedResult(forced, true);
        source.AdoptSharedResult(ordinary, false);

        Assert.Equal("forced", source.Acquire(false, CancellationToken.None).AccessToken);
    }

    [Fact]
    public void SameTickSameModePrefersTheLaterExpiry()
    {
        var clock = new FakeClock(InitialNow);
        using var source = CreateRefreshableSource(
            FakeTokenClient.Sequence(Result("unused", InitialNow, InitialNow.AddHours(1))),
            clock);

        source.AdoptSharedResult(Result("short", InitialNow, InitialNow.AddMinutes(10)), false);
        source.AdoptSharedResult(Result("long", InitialNow, InitialNow.AddHours(2)), false);

        Assert.Equal("long", source.Acquire(false, CancellationToken.None).AccessToken);
    }

    [Fact]
    public void NewerAcquisitionOrderWinsAcrossModes()
    {
        var clock = new FakeClock(InitialNow);
        using var source = CreateRefreshableSource(
            FakeTokenClient.Sequence(Result("unused", InitialNow, InitialNow.AddHours(1))),
            clock);
        source.AdoptSharedResult(Result("forced", InitialNow, InitialNow.AddHours(2)), true);
        source.AdoptSharedResult(
            Result("newer", InitialNow.AddTicks(1), InitialNow.AddHours(1)),
            false);

        Assert.Equal("newer", source.Acquire(false, CancellationToken.None).AccessToken);
    }

    [Fact]
    public async Task ConcurrentCallersShareOneAcquisition()
    {
        var clock = new FakeClock(InitialNow);
        using var entered = new ManualResetEventSlim(false);
        using var release = new ManualResetEventSlim(false);
        var client = new FakeTokenClient((_, cancellation) =>
        {
            entered.Set();
            release.Wait(cancellation);
            return Result("shared", InitialNow, InitialNow.AddHours(1));
        });
        using var source = CreateRefreshableSource(client, clock);

        Task<GraphTokenResult>[] callers = Enumerable.Range(0, 12)
            .Select(_ => Task.Run(() => source.Acquire(false, CancellationToken.None)))
            .ToArray();
        Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
        Assert.True(SpinWait.SpinUntil(
            () => source.OrdinaryFlightWaiterCount == callers.Length,
            TimeSpan.FromSeconds(5)));
        release.Set();
        GraphTokenResult[] results = await Task.WhenAll(callers);

        Assert.Equal(1, client.AcquireCount);
        Assert.All(results, result => Assert.Equal("shared", result.AccessToken));
    }

    [Fact]
    public async Task FailedAcquisitionFansOutAndACompletedFailureCanRetry()
    {
        var clock = new FakeClock(InitialNow);
        using var entered = new ManualResetEventSlim(false);
        using var release = new ManualResetEventSlim(false);
        var attempt = 0;
        var client = new FakeTokenClient((_, cancellation) =>
        {
            int current = Interlocked.Increment(ref attempt);
            if (current == 1)
            {
                entered.Set();
                release.Wait(cancellation);
                throw new GraphAuthException(
                    "fixture_failure",
                    "Fixture",
                    "safe fixture failure",
                    null,
                    null);
            }

            return Result("recovered", InitialNow.AddSeconds(1), InitialNow.AddHours(1));
        });
        using var source = CreateRefreshableSource(client, clock);

        Task<GraphTokenResult>[] callers = Enumerable.Range(0, 8)
            .Select(_ => Task.Run(() => source.Acquire(false, CancellationToken.None)))
            .ToArray();
        Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
        Assert.True(SpinWait.SpinUntil(
            () => source.OrdinaryFlightWaiterCount == callers.Length,
            TimeSpan.FromSeconds(5)));
        release.Set();

        GraphAuthException[] failures = await Task.WhenAll(callers.Select(async caller =>
            await Assert.ThrowsAsync<GraphAuthException>(async () => await caller)));
        Assert.All(failures, failure => Assert.Equal("fixture_failure", failure.Code));
        Assert.Equal(1, client.AcquireCount);
        Assert.Equal("recovered", source.Acquire(false, CancellationToken.None).AccessToken);
        Assert.Equal(2, client.AcquireCount);
    }

    [Fact]
    public async Task CancellingAFollowerDoesNotPoisonTheLiveLeader()
    {
        var clock = new FakeClock(InitialNow);
        using var entered = new ManualResetEventSlim(false);
        using var release = new ManualResetEventSlim(false);
        var client = new FakeTokenClient((_, cancellation) =>
        {
            entered.Set();
            release.Wait(cancellation);
            return Result("leader-result", InitialNow, InitialNow.AddHours(1));
        });
        using var source = CreateRefreshableSource(client, clock);
        Task<GraphTokenResult> leader = Task.Run(() =>
            source.Acquire(false, CancellationToken.None));
        Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
        using var followerCancellation = new CancellationTokenSource();
        Task<GraphTokenResult> follower = Task.Run(() =>
            source.Acquire(false, followerCancellation.Token));
        Assert.True(SpinWait.SpinUntil(
            () => source.OrdinaryFlightWaiterCount == 2,
            TimeSpan.FromSeconds(5)));

        followerCancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await follower);
        release.Set();

        Assert.Equal("leader-result", (await leader).AccessToken);
        Assert.Equal(1, client.AcquireCount);
    }

    [Fact]
    public async Task CancelledLeaderDoesNotPoisonALiveFollower()
    {
        var clock = new FakeClock(InitialNow);
        using var firstEntered = new ManualResetEventSlim(false);
        var attempt = 0;
        var client = new FakeTokenClient((_, cancellation) =>
        {
            int current = Interlocked.Increment(ref attempt);
            if (current == 1)
            {
                firstEntered.Set();
                cancellation.WaitHandle.WaitOne();
                cancellation.ThrowIfCancellationRequested();
            }

            return Result("replacement", InitialNow.AddSeconds(1), InitialNow.AddHours(1));
        });
        using var source = CreateRefreshableSource(client, clock);
        using var leaderCancellation = new CancellationTokenSource();
        Task<GraphTokenResult> leader = Task.Run(() =>
            source.Acquire(false, leaderCancellation.Token));
        Assert.True(firstEntered.Wait(TimeSpan.FromSeconds(5)));
        Task<GraphTokenResult> follower = Task.Run(() =>
            source.Acquire(false, CancellationToken.None));
        Assert.True(SpinWait.SpinUntil(
            () => source.OrdinaryFlightWaiterCount == 2,
            TimeSpan.FromSeconds(5)));

        leaderCancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await leader);
        Assert.Equal("replacement", (await follower).AccessToken);
        Assert.Equal(2, client.AcquireCount);
    }

    [Fact]
    public void CompletedCancelledFlightCanRetry()
    {
        var clock = new FakeClock(InitialNow);
        var attempt = 0;
        var client = new FakeTokenClient((_, cancellation) =>
        {
            if (Interlocked.Increment(ref attempt) == 1)
            {
                cancellation.WaitHandle.WaitOne();
                cancellation.ThrowIfCancellationRequested();
            }

            return Result("retried", InitialNow.AddSeconds(1), InitialNow.AddHours(1));
        });
        using var source = CreateRefreshableSource(client, clock);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        Assert.ThrowsAny<OperationCanceledException>(() =>
            source.Acquire(false, cancellation.Token));
        Assert.Equal("retried", source.Acquire(false, CancellationToken.None).AccessToken);
        Assert.Equal(2, client.AcquireCount);
    }

    [Fact]
    public void AcquiredResultFromAnotherGenerationIsRejected()
    {
        var clock = new FakeClock(InitialNow);
        var client = FakeTokenClient.Sequence(
            Result("wrong", InitialNow, InitialNow.AddHours(1), generation: "generation-2"));
        using var source = CreateRefreshableSource(client, clock);

        InvalidOperationException failure = Assert.Throws<InvalidOperationException>(() =>
            source.Acquire(false, CancellationToken.None));

        Assert.Contains("credential generation", failure.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(DateTimeOffset.MinValue, source.ExpiresOn);
    }

    [Fact]
    public void AdoptedResultFromAnotherGenerationIsRejected()
    {
        var clock = new FakeClock(InitialNow);
        using var source = CreateRefreshableSource(
            FakeTokenClient.Sequence(Result("unused", InitialNow, InitialNow.AddHours(1))),
            clock);

        InvalidOperationException failure = Assert.Throws<InvalidOperationException>(() =>
            source.AdoptSharedResult(
                Result("wrong", InitialNow, InitialNow.AddHours(1), generation: "generation-2"),
                false));

        Assert.Contains("credential generation", failure.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AdoptionCarriesTenantProofAndExpiryIntoSourceState()
    {
        var clock = new FakeClock(InitialNow);
        using var source = CreateRefreshableSource(
            FakeTokenClient.Sequence(Result("unused", InitialNow, InitialNow.AddHours(1))),
            clock);
        GraphTokenResult adopted = Result("adopted", InitialNow, InitialNow.AddHours(2));
        adopted.VerifiedTenantId = "verified-tenant";

        source.AdoptSharedResult(adopted, false);

        Assert.Equal(adopted.ExpiresOnUtc, source.ExpiresOn);
        Assert.Equal("verified-tenant", source.VerifiedTenantId);
        Assert.Same(adopted, source.Acquire(false, CancellationToken.None));
    }

    [Fact]
    public void FixedBearerCachesOneExplicitResultAndCannotRefresh()
    {
        var clock = new FakeClock(InitialNow);
        GraphTokenRequest request = BearerRequest("fixed-bearer");
        using var source = new GraphTokenSource(request, client: null, clock.GetUtcNow);

        GraphTokenResult first = source.Acquire(false, CancellationToken.None);
        clock.Advance(TimeSpan.FromDays(1));
        GraphTokenResult second = source.Acquire(false, CancellationToken.None);

        Assert.False(source.CanRefresh);
        Assert.Equal("BearerToken", source.AuthMode);
        Assert.Null(source.ClientId);
        Assert.Equal(DateTimeOffset.MinValue, first.ExpiresOnUtc);
        Assert.Equal(InitialNow, first.ReceivedOnUtc);
        Assert.Equal(new[] { "https://graph.microsoft.com/.default" }, first.Scopes);
        Assert.Equal(Fingerprint("fixed-bearer"), first.TokenFingerprint);
        Assert.Same(first, second);
        Assert.Throws<InvalidOperationException>(() =>
            source.Acquire(true, CancellationToken.None));
    }

    [Fact]
    public void FixedBearerHonorsFrameworkCancellationBeforeReturningTheToken()
    {
        using var source = new GraphTokenSource(
            BearerRequest("fixed-bearer"),
            client: null,
            new FakeClock(InitialNow).GetUtcNow);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        Assert.ThrowsAny<OperationCanceledException>(() =>
            source.Acquire(false, cancellation.Token));
    }

    [Fact]
    public void SourceIdentityComesOnlyFromTheImmutableRequest()
    {
        var clock = new FakeClock(InitialNow);
        GraphTokenRequest request = SecretRequest();
        using var source = new GraphTokenSource(
            request,
            FakeTokenClient.Sequence(Result("token", InitialNow, InitialNow.AddHours(1))),
            clock.GetUtcNow);

        Assert.True(source.CanRefresh);
        Assert.Equal("ClientSecret", source.AuthMode);
        Assert.Equal("https://graph.microsoft.com/", source.Audience);
        Assert.Equal(request.ClientId?.ToString("D"), source.ClientId);
        Assert.Equal("generation-1", source.CredentialGeneration);
    }

    [Fact]
    public void SourceRejectsEveryUseAfterDisposalAndClearsReferences()
    {
        var clock = new FakeClock(InitialNow);
        var client = FakeTokenClient.Sequence(
            Result("cached", InitialNow, InitialNow.AddHours(1)));
        var source = CreateRefreshableSource(client, clock);
        source.Acquire(false, CancellationToken.None);

        source.Dispose();
        source.Dispose();

        Assert.Throws<ObjectDisposedException>(() => _ = source.CanRefresh);
        Assert.Throws<ObjectDisposedException>(() =>
            source.Acquire(false, CancellationToken.None));
        Assert.Throws<ObjectDisposedException>(() =>
            source.AdoptSharedResult(Result("later", InitialNow, InitialNow.AddHours(2)), false));
        Assert.False(source.HasCachedResult);
        Assert.False(source.HasClientReference);
        Assert.False(source.HasCredentialReference);
        Assert.Equal(1, client.DisposeCount);
    }

    [Fact]
    public void ProviderWritesNoTokenOrSecretToConsoleOrTrace()
    {
        const string secretValue = "never-write-this-secret";
        const string tokenValue = "never-write-this-token";
        var clock = new FakeClock(InitialNow);
        using var source = new GraphTokenSource(
            BearerRequest(tokenValue),
            client: null,
            clock.GetUtcNow);
        using var consoleOutput = new StringWriter();
        using var consoleError = new StringWriter();
        TextWriter originalOutput = Console.Out;
        TextWriter originalError = Console.Error;
        try
        {
            Console.SetOut(consoleOutput);
            Console.SetError(consoleError);
            source.Acquire(false, CancellationToken.None);
            _ = new ClientSecretCredential(SecureStringFixture.Create(secretValue), false);
        }
        finally
        {
            Console.SetOut(originalOutput);
            Console.SetError(originalError);
        }

        string emitted = consoleOutput + consoleError.ToString();
        Assert.DoesNotContain(secretValue, emitted, StringComparison.Ordinal);
        Assert.DoesNotContain(tokenValue, emitted, StringComparison.Ordinal);
        Assert.Equal(string.Empty, emitted);
    }

    private static GraphTokenSource CreateRefreshableSource(
        ITokenClient client,
        FakeClock clock)
    {
        return new GraphTokenSource(SecretRequest(), client, clock.GetUtcNow);
    }

    internal static GraphTokenRequest SecretRequest(
        ClientSecretCredential? credential = null,
        string generation = "generation-1")
    {
        return new GraphTokenRequest(
            "Global",
            Guid.Parse("00000000-0000-0000-0000-000000000001"),
            new Uri("https://login.microsoftonline.com"),
            new Uri("https://graph.microsoft.com"),
            Guid.Parse("00000000-0000-0000-0000-000000000002"),
            GraphAuthMode.ClientSecret,
            credential ?? new ClientSecretCredential(SecureStringFixture.Create("fixture-secret"), false),
            generation);
    }

    internal static GraphTokenRequest BearerRequest(string token)
    {
        return new GraphTokenRequest(
            "Global",
            Guid.Parse("00000000-0000-0000-0000-000000000001"),
            new Uri("https://login.microsoftonline.com"),
            new Uri("https://graph.microsoft.com/"),
            null,
            GraphAuthMode.BearerToken,
            new FixedBearerCredential(token),
            "generation-1");
    }

    internal static GraphTokenResult Result(
        string token,
        DateTimeOffset received,
        DateTimeOffset expires,
        string generation = "generation-1")
    {
        return new GraphTokenResult
        {
            AccessToken = token,
            ExpiresOnUtc = expires,
            ReceivedOnUtc = received,
            TokenType = "Bearer",
            Scopes = ["https://graph.microsoft.com/.default"],
            TokenFingerprint = Fingerprint(token),
            CredentialGeneration = generation
        };
    }

    internal static string Fingerprint(string token)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)))
            .ToLowerInvariant();
    }

    private static double EarlySpreadSeconds(string fingerprint, double baseSkewSeconds)
    {
        int bucket = Convert.ToInt32(fingerprint[..2], 16);
        return baseSkewSeconds * 0.1 * (bucket / 255d);
    }

    internal sealed class FakeClock(DateTimeOffset utcNow)
    {
        internal DateTimeOffset UtcNow { get; set; } = utcNow;

        internal DateTimeOffset GetUtcNow() => UtcNow;

        internal void Advance(TimeSpan duration) => UtcNow += duration;
    }

    internal sealed class FakeTokenClient(
        Func<bool, CancellationToken, GraphTokenResult> acquire) : ITokenClient
    {
        private readonly ConcurrentQueue<bool> _forceRefreshValues = new();
        private int _acquireCount;
        private int _disposeCount;

        internal int AcquireCount => Volatile.Read(ref _acquireCount);

        internal int DisposeCount => Volatile.Read(ref _disposeCount);

        internal bool[] ForceRefreshValues => _forceRefreshValues.ToArray();

        public GraphTokenResult Acquire(bool forceRefresh, CancellationToken cancellation)
        {
            Interlocked.Increment(ref _acquireCount);
            _forceRefreshValues.Enqueue(forceRefresh);
            return acquire(forceRefresh, cancellation);
        }

        public void Dispose() => Interlocked.Increment(ref _disposeCount);

        internal static FakeTokenClient Sequence(params GraphTokenResult[] results)
        {
            var queue = new ConcurrentQueue<GraphTokenResult>(results);
            return new FakeTokenClient((_, _) =>
                queue.TryDequeue(out GraphTokenResult? result)
                    ? result
                    : throw new InvalidOperationException("No fake token result remains."));
        }
    }

    internal static class SecureStringFixture
    {
        internal static System.Security.SecureString Create(string value)
        {
            var secure = new System.Security.SecureString();
            foreach (char character in value)
            {
                secure.AppendChar(character);
            }

            secure.MakeReadOnly();
            return secure;
        }
    }
}
