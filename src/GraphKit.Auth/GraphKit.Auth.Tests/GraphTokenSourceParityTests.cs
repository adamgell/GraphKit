using System.Collections.Concurrent;
using System.Globalization;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;

namespace GraphKit.Auth.Tests;

public sealed class GraphTokenSourceParityTests
{
    private const string Runner = "xunit-compiled";
    private const string MatrixSha256 =
        "c6953120ea3a29966acabf671a193e7ff51b38d561fb0028a2a585177dea0eb0";
    private static readonly DateTimeOffset InjectedNow =
        DateTimeOffset.Parse(
            "2026-08-31T12:00:00+00:00",
            CultureInfo.InvariantCulture,
            DateTimeStyles.None);

    public static IEnumerable<object[]> SemanticRows =>
        ParityMatrix.LoadFixture().Rows.Select(static row => new object[] { row });

    public static IEnumerable<object[]> MalformedCases =>
        ParityMatrix.MalformedCaseIds.Select(static id => new object[] { id });

    [Theory]
    [MemberData(nameof(SemanticRows))]
    public async Task CompiledRunnerMatchesLiteralMatrix(ParityRow row)
    {
        ParityMatrix matrix = ParityMatrix.LoadFixture();
        Assert.Equal(MatrixSha256, matrix.Sha256);
        Assert.Equal(16, matrix.Rows.Count);
        Assert.Equal(16, matrix.Rows.Select(static candidate => candidate.Id).Distinct().Count());
        Assert.Contains(row.Id, ParityMatrix.RequiredRowIds, StringComparer.Ordinal);
        Assert.Equal(Runner, row.Runners[0]);
        Assert.Equal("pester-legacy", row.Runners[1]);

        ExpectedParity expected = row.ExpectedByRunner[Runner];
        ActualParity actual = await RunCompiledAsync(row);

        Assert.Equal(expected.CanRefresh, actual.CanRefresh);
        Assert.Equal(expected.AuthMode, actual.AuthMode);
        Assert.Equal(expected.Audience, actual.Audience);
        Assert.Equal(expected.ClientId, actual.ClientId);
        Assert.Equal(expected.CredentialGeneration, actual.CredentialGeneration);
        Assert.Equal(expected.SourceExpiresOnUtc.Literal, FormatTimestamp(actual.SourceExpiresOnUtc));
        Assert.Equal(expected.SourceVerifiedTenantId, actual.SourceVerifiedTenantId);
        Assert.Equal(expected.TokenSequence, actual.Results.Select(static result => result.AccessToken));
        Assert.Equal(
            expected.ExpiriesOnUtc.Select(static timestamp => timestamp.Literal),
            actual.Results.Select(static result => FormatTimestamp(result.ExpiresOnUtc)));
        Assert.Equal(expected.TokenTypes, actual.Results.Select(static result => result.TokenType));
        Assert.Equal(
            expected.OrderedScopes.Select(static scopes => string.Join('\u001f', scopes)),
            actual.Results.Select(static result => string.Join('\u001f', result.Scopes)));
        Assert.Equal(expected.TenantProofs, actual.Results.Select(static result => result.VerifiedTenantId));
        Assert.Equal(expected.Fingerprints, actual.Results.Select(static result => result.TokenFingerprint));
        Assert.Equal(expected.Generations, actual.Results.Select(static result => result.CredentialGeneration));
        AssertReceivedTimeRule(expected.ReceivedTimeRule, row, actual.Results);
        Assert.Equal(expected.ApplicationConstructionCount, actual.ApplicationConstructionCount);
        Assert.Equal(expected.ProviderAcquisitionCount, actual.ProviderAcquisitionCount);
        Assert.Equal(expected.ForceFlags, actual.ForceFlags);
        AssertReferenceIdentity(expected.ReferenceIdentity, actual.Results, actual.AdoptedResult);
        Assert.Equal(expected.FailureKind, actual.FailureKind);
        Assert.Equal(expected.CacheState, actual.CacheState);
        Assert.Equal(expected.FinalFlightRegistryCount, actual.FinalFlightRegistryCount);
    }

    [Theory]
    [MemberData(nameof(MalformedCases))]
    public void CompiledLoaderRejectsMalformedCaseIndependently(string mutationId)
    {
        string valid = File.ReadAllText(ParityMatrix.FixturePath, Encoding.UTF8);
        string malformed = ParityMatrix.Mutate(valid, mutationId);

        InvalidDataException failure = Assert.Throws<InvalidDataException>(() =>
            ParityMatrix.Parse(malformed));

        string expectedDiagnostic = mutationId switch
        {
            "duplicate-row-id" => "duplicate row id",
            "missing-required-property" => "missing required property",
            "invalid-runner-call-layer" => "invalid runner call layer",
            "missing-runner-expectation" => "missing required property 'pester-legacy'",
            _ => mutationId
        };
        Assert.Contains(expectedDiagnostic, failure.Message, StringComparison.Ordinal);
    }

    private static async Task<ActualParity> RunCompiledAsync(ParityRow row)
    {
        AssertDeclarativeInputContract(row);
        var clock = new GraphTokenSourceTests.FakeClock(InjectedNow);
        var applications = 0;
        var attempt = 0;
        using var entered = new ManualResetEventSlim(false);
        using var release = new ManualResetEventSlim(false);
        var queue = new ConcurrentQueue<GraphTokenResult>(
            GetScenarioTokens(row).Zip(
                row.Input.ExpiresOnUtc,
                (token, expiry) => Result(token, expiry.Value, InjectedNow, "task7-generation")));
        var client = new GraphTokenSourceTests.FakeTokenClient((forceRefresh, cancellation) =>
        {
            int current = Interlocked.Increment(ref attempt);
            if (row.Id == "acquisition-failure-fanout-retry" && current == 1)
            {
                entered.Set();
                release.Wait(cancellation);
                if (!queue.TryDequeue(out _))
                {
                    throw new InvalidOperationException("No Task 7 failure attempt remains.");
                }
                throw new GraphAuthException(
                    "task7_failure",
                    "Fixture",
                    "safe task7 acquisition failure",
                    retryAfter: null,
                    correlationId: null);
            }

            cancellation.ThrowIfCancellationRequested();
            if (!queue.TryDequeue(out GraphTokenResult? result))
            {
                throw new InvalidOperationException("No Task 7 compiled parity result remains.");
            }

            return result;
        });
        var owned = new List<IDisposable>();
        GraphTokenRequest request = CreateRequest(row, owned);
        var factory = new GraphTokenSourceFactory(
            (_, _) =>
            {
                Interlocked.Increment(ref applications);
                return client;
            },
            clock.GetUtcNow);
        GraphTokenSource source = Assert.IsType<GraphTokenSource>(factory.Create(request));
        var results = new List<GraphTokenResult>();
        GraphTokenResult? adopted = null;
        string? failureKind = null;
        try
        {
            switch (row.Id)
            {
                case "construction-certificate":
                case "construction-client-secret":
                case "construction-managed-identity":
                case "construction-bearer-token":
                    break;

                case "ordinary-cache-hit":
                case "expired-result-refresh":
                case "ordinary-forced-ordinary":
                case "fingerprint-certificate":
                case "fingerprint-client-secret":
                case "fingerprint-managed-identity":
                case "fingerprint-bearer-token":
                    foreach (bool forceRefresh in row.Input.ForceFlags)
                    {
                        results.Add(source.Acquire(forceRefresh, CancellationToken.None));
                    }
                    break;

                case "acquisition-failure-fanout-retry":
                    bool initialForceRefresh = row.Input.ForceFlags[0];
                    Task<GraphTokenResult>[] callers = Enumerable.Range(0, 4)
                        .Select(_ => Task.Run(() =>
                            source.Acquire(initialForceRefresh, CancellationToken.None)))
                        .ToArray();
                    bool leaderEntered = entered.Wait(TimeSpan.FromSeconds(5));
                    bool allWaitersObserved = leaderEntered && SpinWait.SpinUntil(
                        () => source.OrdinaryFlightWaiterCount == callers.Length,
                        TimeSpan.FromSeconds(5));
                    release.Set();
                    GraphAuthException[] failures = await Task.WhenAll(callers.Select(async caller =>
                        await Assert.ThrowsAsync<GraphAuthException>(async () => await caller)))
                        .WaitAsync(TimeSpan.FromSeconds(5));
                    Assert.True(leaderEntered);
                    Assert.True(allWaitersObserved);
                    Assert.All(failures, static failure => Assert.Equal("task7_failure", failure.Code));
                    failureKind = "AcquisitionFailure";
                    results.Add(source.Acquire(row.Input.ForceFlags[1], CancellationToken.None));
                    break;

                case "caller-cancellation-no-cache":
                    using (var cancellation = new CancellationTokenSource())
                    {
                        if (row.Input.CancelCaller)
                        {
                            cancellation.Cancel();
                        }
                        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Task.Run(() =>
                            source.Acquire(row.Input.ForceFlags[0], cancellation.Token)));
                    }
                    failureKind = "Canceled";
                    break;

                case "fixed-bearer-cache-force-refusal":
                    results.Add(source.Acquire(row.Input.ForceFlags[0], CancellationToken.None));
                    results.Add(source.Acquire(row.Input.ForceFlags[1], CancellationToken.None));
                    Assert.Throws<InvalidOperationException>(() =>
                        source.Acquire(row.Input.ForceFlags[2], CancellationToken.None));
                    failureKind = "RefreshRefused";
                    break;

                case "adoption-generation-mismatch":
                    adopted = AdoptedResult(row.Input);
                    Assert.Throws<InvalidOperationException>(() =>
                        source.AdoptSharedResult(adopted, row.Input.ForceFlags[0]));
                    failureKind = "GenerationMismatch";
                    break;

                case "adoption-valid":
                    adopted = AdoptedResult(row.Input);
                    source.AdoptSharedResult(adopted, row.Input.ForceFlags[0]);
                    results.Add(source.Acquire(row.Input.ForceFlags[0], CancellationToken.None));
                    break;

                default:
                    throw new InvalidOperationException($"Unhandled Task 7 parity row '{row.Id}'.");
            }

            return new ActualParity(
                source.CanRefresh,
                source.AuthMode,
                source.Audience,
                source.ClientId,
                source.CredentialGeneration,
                source.ExpiresOn,
                source.VerifiedTenantId,
                results,
                adopted,
                applications,
                client.AcquireCount,
                client.ForceRefreshValues,
                failureKind,
                source.HasCachedResult ? "Populated" : "Empty",
                CountSourceFlights(source));
        }
        finally
        {
            release.Set();
            source.Dispose();
            foreach (IDisposable material in owned)
            {
                material.Dispose();
            }
        }
    }

    private static GraphTokenRequest CreateRequest(ParityRow row, List<IDisposable> owned)
    {
        GraphAuthMode mode = Enum.Parse<GraphAuthMode>(row.AuthMode, ignoreCase: false);
        GraphCredential credential;
        Guid? clientId;
        switch (mode)
        {
            case GraphAuthMode.Certificate:
                X509Certificate2 certificate = CreateCertificate();
                owned.Add(certificate);
                credential = new CertificateCredential(certificate, ownsMaterial: false);
                clientId = Guid.Parse("00000000-0000-0000-0000-000000000002");
                break;
            case GraphAuthMode.ClientSecret:
                SecureString secret = GraphTokenSourceTests.SecureStringFixture.Create("task7-secret");
                owned.Add(secret);
                credential = new ClientSecretCredential(secret, ownsMaterial: false);
                clientId = Guid.Parse("00000000-0000-0000-0000-000000000002");
                break;
            case GraphAuthMode.ManagedIdentity:
                credential = new ManagedIdentityCredential(
                    "00000000-0000-0000-0000-000000000003");
                clientId = null;
                break;
            case GraphAuthMode.BearerToken:
                credential = new FixedBearerCredential(GetScenarioTokens(row)[0]);
                clientId = null;
                break;
            default:
                throw new InvalidOperationException($"Unhandled Task 7 auth mode '{mode}'.");
        }

        return new GraphTokenRequest(
            "Global",
            Guid.Parse("00000000-0000-0000-0000-000000000001"),
            new Uri("https://login.microsoftonline.com"),
            new Uri("https://graph.microsoft.com"),
            clientId,
            mode,
            credential,
            "task7-generation");
    }

    private static IReadOnlyList<string> GetScenarioTokens(ParityRow row) =>
        row.Scenario == "fingerprint"
            ? [row.Input.FingerprintInput!]
            : row.Input.Tokens;

    private static void AssertDeclarativeInputContract(ParityRow row)
    {
        Assert.Equal(row.Id == "caller-cancellation-no-cache", row.Input.CancelCaller);

        bool fingerprintScenario = row.Scenario == "fingerprint";
        Assert.Equal(fingerprintScenario, row.Input.FingerprintInput is not null);
        if (fingerprintScenario)
        {
            Assert.False(string.IsNullOrEmpty(row.Input.FingerprintInput));
            Assert.Equal(row.Input.FingerprintInput, Assert.Single(row.Input.Tokens));
        }

        bool[] forceFlags = row.Id switch
        {
            "construction-certificate" or
            "construction-client-secret" or
            "construction-managed-identity" or
            "construction-bearer-token" => [],
            "ordinary-cache-hit" or
            "expired-result-refresh" or
            "acquisition-failure-fanout-retry" => [false, false],
            "ordinary-forced-ordinary" => [false, true, false],
            "caller-cancellation-no-cache" or
            "fingerprint-certificate" or
            "fingerprint-client-secret" or
            "fingerprint-managed-identity" or
            "fingerprint-bearer-token" or
            "adoption-generation-mismatch" or
            "adoption-valid" => [false],
            "fixed-bearer-cache-force-refusal" => [false, false, true],
            _ => throw new InvalidOperationException(
                $"Unhandled Task 7 input contract row '{row.Id}'.")
        };
        Assert.Equal(forceFlags, row.Input.ForceFlags);

        if (row.Id == "acquisition-failure-fanout-retry")
        {
            Assert.Equal(["task7-failure", "task7-recovered"], row.Input.Tokens);
            Assert.Equal(
                ["2099-04-01T00:00:00+00:00", "2099-04-01T00:00:00+00:00"],
                row.Input.ExpiresOnUtc.Select(static expiry => expiry.Literal));
        }
    }

    private static X509Certificate2 CreateCertificate()
    {
        using RSA rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=GraphKit.Auth Task 7 parity",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
    }

    private static GraphTokenResult Result(
        string token,
        DateTimeOffset expiry,
        DateTimeOffset received,
        string generation,
        string? tenantProof = null)
    {
        GraphTokenResult result = TokenResultFactory.Create(
            token,
            expiry,
            received,
            "https://graph.microsoft.com/.default",
            generation);
        result.VerifiedTenantId = tenantProof;
        return result;
    }

    private static GraphTokenResult AdoptedResult(ParityInput input)
    {
        return Result(
            input.AdoptToken!,
            input.AdoptExpiresOnUtc!.Value.Value,
            input.AdoptReceivedOnUtc!.Value.Value,
            input.AdoptGeneration!,
            input.AdoptTenantProof);
    }

    private static int CountSourceFlights(GraphTokenSource source)
    {
        const System.Reflection.BindingFlags flags =
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic;
        return new[] { "_ordinaryFlight", "_forcedFlight" }
            .Count(name => typeof(GraphTokenSource).GetField(name, flags)!.GetValue(source) is not null);
    }

    private static void AssertReceivedTimeRule(
        string rule,
        ParityRow row,
        IReadOnlyList<GraphTokenResult> results)
    {
        switch (rule)
        {
            case "None":
                Assert.Empty(results);
                break;
            case "InjectedClock":
                Assert.All(results, static result => Assert.Equal(InjectedNow, result.ReceivedOnUtc));
                break;
            case "LiteralAdopted":
                Assert.All(results, result => Assert.Equal(
                    row.Input.AdoptReceivedOnUtc!.Value.Literal,
                    FormatTimestamp(result.ReceivedOnUtc)));
                break;
            default:
                throw new InvalidOperationException($"Unexpected compiled received-time rule '{rule}'.");
        }
    }

    private static string FormatTimestamp(DateTimeOffset value) =>
        value.ToString("yyyy-MM-dd'T'HH:mm:sszzz", CultureInfo.InvariantCulture);

    private static void AssertReferenceIdentity(
        string rule,
        IReadOnlyList<GraphTokenResult> results,
        GraphTokenResult? adopted)
    {
        switch (rule)
        {
            case "None":
                Assert.Empty(results);
                break;
            case "Single":
                Assert.Single(results);
                break;
            case "AllSame":
                Assert.NotEmpty(results);
                Assert.All(results, result => Assert.Same(results[0], result));
                break;
            case "AllDistinct":
                Assert.Equal(results.Count, results.Distinct(ReferenceEqualityComparer.Instance).Count());
                break;
            case "SecondAndThirdSame":
                Assert.Equal(3, results.Count);
                Assert.NotSame(results[0], results[1]);
                Assert.Same(results[1], results[2]);
                break;
            case "AdoptedAndReturnedSame":
                Assert.NotNull(adopted);
                Assert.Single(results);
                Assert.Same(adopted, results[0]);
                break;
            default:
                throw new InvalidOperationException($"Unexpected reference rule '{rule}'.");
        }
    }

    private sealed record ActualParity(
        bool CanRefresh,
        string AuthMode,
        string Audience,
        string? ClientId,
        string CredentialGeneration,
        DateTimeOffset SourceExpiresOnUtc,
        string? SourceVerifiedTenantId,
        IReadOnlyList<GraphTokenResult> Results,
        GraphTokenResult? AdoptedResult,
        int ApplicationConstructionCount,
        int ProviderAcquisitionCount,
        IReadOnlyList<bool> ForceFlags,
        string? FailureKind,
        string CacheState,
        int FinalFlightRegistryCount);
}

public sealed record ParityRow(
    string Id,
    string[] Runners,
    string Scenario,
    string AuthMode,
    IReadOnlyDictionary<string, string> CallLayerByRunner,
    ParityInput Input,
    IReadOnlyDictionary<string, ExpectedParity> ExpectedByRunner)
{
    public override string ToString() => Id;
}

public sealed record ParityInput(
    string[] Tokens,
    ExactTimestamp[] ExpiresOnUtc,
    bool[] ForceFlags,
    bool CancelCaller,
    string? FingerprintInput,
    string? AdoptToken,
    string? AdoptGeneration,
    ExactTimestamp? AdoptReceivedOnUtc,
    ExactTimestamp? AdoptExpiresOnUtc,
    string? AdoptTenantProof);

public sealed record ExpectedParity(
    bool CanRefresh,
    string AuthMode,
    string Audience,
    string? ClientId,
    string CredentialGeneration,
    ExactTimestamp SourceExpiresOnUtc,
    string? SourceVerifiedTenantId,
    string[] TokenSequence,
    ExactTimestamp[] ExpiriesOnUtc,
    string[] TokenTypes,
    string[][] OrderedScopes,
    string?[] TenantProofs,
    string[] Fingerprints,
    string[] Generations,
    string ReceivedTimeRule,
    int ApplicationConstructionCount,
    int ProviderAcquisitionCount,
    bool[] ForceFlags,
    string ReferenceIdentity,
    string? FailureKind,
    string CacheState,
    int FinalFlightRegistryCount);

public readonly record struct ExactTimestamp(string Literal, DateTimeOffset Value);

public sealed class ParityMatrix
{
    private const int SchemaVersion = 1;
    private static readonly string[] RootFields = ["schemaVersion", "rowCount", "rows"];
    private static readonly string[] RowFields =
        ["id", "runners", "scenario", "authMode", "callLayerByRunner", "input", "expectedByRunner"];
    private static readonly string[] InputFields =
    [
        "tokens", "expiresOnUtc", "forceFlags", "cancelCaller", "fingerprintInput",
        "adoptToken", "adoptGeneration", "adoptReceivedOnUtc", "adoptExpiresOnUtc",
        "adoptTenantProof"
    ];
    private static readonly string[] ExpectedFields =
    [
        "canRefresh", "authMode", "audience", "clientId", "credentialGeneration",
        "sourceExpiresOnUtc", "sourceVerifiedTenantId", "tokenSequence", "expiriesOnUtc",
        "tokenTypes", "orderedScopes", "tenantProofs", "fingerprints", "generations",
        "receivedTimeRule", "applicationConstructionCount", "providerAcquisitionCount",
        "forceFlags", "referenceIdentity", "failureKind", "cacheState",
        "finalFlightRegistryCount"
    ];
    private static readonly IReadOnlyDictionary<string, (string Scenario, string Mode, string XunitLayer, string PesterLayer)>
        RowContracts = new Dictionary<string, (string, string, string, string)>(StringComparer.Ordinal)
        {
            ["construction-certificate"] = ("construction", "Certificate", "construction-only", "construction-only"),
            ["construction-client-secret"] = ("construction", "ClientSecret", "construction-only", "construction-only"),
            ["construction-managed-identity"] = ("construction", "ManagedIdentity", "construction-only", "construction-only"),
            ["construction-bearer-token"] = ("construction", "BearerToken", "construction-only", "construction-only"),
            ["ordinary-cache-hit"] = ("cache-hit", "Certificate", "direct-source", "direct-source"),
            ["expired-result-refresh"] = ("expiry-refresh", "ClientSecret", "direct-source", "direct-source"),
            ["ordinary-forced-ordinary"] = ("force-partition", "ManagedIdentity", "direct-source", "direct-source"),
            ["acquisition-failure-fanout-retry"] = ("failure-fanout-retry", "Certificate", "compiled-internal-source-flight", "legacy-production-outer-keyed-flight"),
            ["caller-cancellation-no-cache"] = ("caller-cancellation", "ClientSecret", "direct-source", "direct-source"),
            ["fixed-bearer-cache-force-refusal"] = ("fixed-bearer", "BearerToken", "direct-source", "direct-source"),
            ["fingerprint-certificate"] = ("fingerprint", "Certificate", "direct-source", "direct-source"),
            ["fingerprint-client-secret"] = ("fingerprint", "ClientSecret", "direct-source", "direct-source"),
            ["fingerprint-managed-identity"] = ("fingerprint", "ManagedIdentity", "direct-source", "direct-source"),
            ["fingerprint-bearer-token"] = ("fingerprint", "BearerToken", "direct-source", "direct-source"),
            ["adoption-generation-mismatch"] = ("adoption-mismatch", "Certificate", "direct-source", "direct-source"),
            ["adoption-valid"] = ("adoption-valid", "ManagedIdentity", "direct-source", "direct-source")
        };

    public static readonly string[] RequiredRowIds = RowContracts.Keys.ToArray();
    public static readonly string[] MalformedCaseIds =
    [
        "unsupported-schema-version",
        "incorrect-row-count",
        "duplicate-row-id",
        "missing-required-row-id",
        "unknown-property",
        "missing-required-property",
        "duplicate-json-property",
        "invalid-runner-call-layer",
        "missing-runner-expectation"
    ];

    private ParityMatrix(string sha256, IReadOnlyList<ParityRow> rows)
    {
        Sha256 = sha256;
        Rows = rows;
    }

    public string Sha256 { get; }

    public IReadOnlyList<ParityRow> Rows { get; }

    public static string FixturePath => Path.Combine(
        AppContext.BaseDirectory,
        "Fixtures",
        "GraphKitAuthParityCases.json");

    public static ParityMatrix LoadFixture()
    {
        byte[] bytes = File.ReadAllBytes(FixturePath);
        return Parse(Encoding.UTF8.GetString(bytes),
            Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant());
    }

    public static ParityMatrix Parse(string json) =>
        Parse(json, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json))).ToLowerInvariant());

    public static string Mutate(string validJson, string mutationId)
    {
        if (mutationId == "duplicate-json-property")
        {
            return validJson.Replace(
                "\"schemaVersion\": 1,",
                "\"schemaVersion\": 1, \"schemaVersion\": 1,",
                StringComparison.Ordinal);
        }

        JsonNode root = JsonNode.Parse(validJson) ?? throw new InvalidDataException("mutation source is null");
        JsonObject rootObject = root.AsObject();
        JsonArray rows = rootObject["rows"]!.AsArray();
        switch (mutationId)
        {
            case "unsupported-schema-version":
                rootObject["schemaVersion"] = 2;
                break;
            case "incorrect-row-count":
                rootObject["rowCount"] = 15;
                break;
            case "duplicate-row-id":
                rows[1]!["id"] = rows[0]!["id"]!.GetValue<string>();
                break;
            case "missing-required-row-id":
                rows[0]!["id"] = "replacement-row-id";
                break;
            case "unknown-property":
                rows[0]!["unexpected"] = true;
                break;
            case "missing-required-property":
                rows[0]!.AsObject().Remove("scenario");
                break;
            case "invalid-runner-call-layer":
                rows[0]!["callLayerByRunner"]!["xunit-compiled"] = "direct-source";
                break;
            case "missing-runner-expectation":
                rows[0]!["expectedByRunner"]!.AsObject().Remove("pester-legacy");
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(mutationId), mutationId, "Unknown malformed case.");
        }

        return root.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }

    private static ParityMatrix Parse(string json, string sha256)
    {
        string mutationHint = DetectMutationHint(json);
        try
        {
            using JsonDocument document = JsonDocument.Parse(json, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow
            });
            JsonElement root = document.RootElement;
            RequireKind(root, JsonValueKind.Object, "root");
            RejectDuplicateProperties(root, "root");
            RequireExactFields(root, RootFields, "root");
            RequireInt(root, "schemaVersion", SchemaVersion);
            RequireInt(root, "rowCount", 16);
            JsonElement rowsElement = RequireProperty(root, "rows", JsonValueKind.Array);
            if (rowsElement.GetArrayLength() != 16)
            {
                throw new InvalidDataException("rows must contain exactly 16 items");
            }

            var rows = new List<ParityRow>(16);
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonElement element in rowsElement.EnumerateArray())
            {
                RequireKind(element, JsonValueKind.Object, "row");
                RejectDuplicateProperties(element, "row");
                RequireExactFields(element, RowFields, "row");
                string id = RequireString(element, "id");
                if (!seen.Add(id))
                {
                    throw new InvalidDataException($"duplicate row id '{id}'");
                }

                if (!RowContracts.TryGetValue(id, out var contract))
                {
                    throw new InvalidDataException($"unknown row id '{id}'");
                }

                string[] runners = RequireStringArray(element, "runners");
                if (!runners.SequenceEqual(["xunit-compiled", "pester-legacy"], StringComparer.Ordinal))
                {
                    throw new InvalidDataException($"row '{id}' has an invalid runner set or order");
                }

                string scenario = RequireString(element, "scenario");
                string authMode = RequireString(element, "authMode");
                if (!string.Equals(scenario, contract.Scenario, StringComparison.Ordinal) ||
                    !string.Equals(authMode, contract.Mode, StringComparison.Ordinal))
                {
                    throw new InvalidDataException($"row '{id}' scenario or auth mode is invalid");
                }

                JsonElement layers = RequireProperty(element, "callLayerByRunner", JsonValueKind.Object);
                RejectDuplicateProperties(layers, $"row '{id}' callLayerByRunner");
                RequireExactFields(layers, ["xunit-compiled", "pester-legacy"], $"row '{id}' callLayerByRunner");
                var callLayers = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["xunit-compiled"] = RequireString(layers, "xunit-compiled"),
                    ["pester-legacy"] = RequireString(layers, "pester-legacy")
                };
                if (!string.Equals(callLayers["xunit-compiled"], contract.XunitLayer, StringComparison.Ordinal) ||
                    !string.Equals(callLayers["pester-legacy"], contract.PesterLayer, StringComparison.Ordinal))
                {
                    throw new InvalidDataException($"row '{id}' has an invalid runner call layer");
                }

                ParityInput input = ParseInput(RequireProperty(element, "input", JsonValueKind.Object), id);
                IReadOnlyDictionary<string, ExpectedParity> expected = ParseExpectedByRunner(
                    RequireProperty(element, "expectedByRunner", JsonValueKind.Object), id);
                rows.Add(new ParityRow(id, runners, scenario, authMode, callLayers, input, expected));
            }

            string? missing = RequiredRowIds.FirstOrDefault(id => !seen.Contains(id));
            if (missing is not null)
            {
                throw new InvalidDataException($"missing required row id '{missing}'");
            }

            return new ParityMatrix(sha256, rows);
        }
        catch (Exception exception) when (exception is JsonException or InvalidDataException)
        {
            throw new InvalidDataException($"{mutationHint}: {exception.Message}", exception);
        }
    }

    private static ParityInput ParseInput(JsonElement input, string id)
    {
        RejectDuplicateProperties(input, $"row '{id}' input");
        RequireExactFields(input, InputFields, $"row '{id}' input");
        return new ParityInput(
            RequireStringArray(input, "tokens"),
            RequireDateArray(input, "expiresOnUtc"),
            RequireBoolArray(input, "forceFlags"),
            RequireBoolean(input, "cancelCaller"),
            RequireNullableString(input, "fingerprintInput"),
            RequireNullableString(input, "adoptToken"),
            RequireNullableString(input, "adoptGeneration"),
            RequireNullableDate(input, "adoptReceivedOnUtc"),
            RequireNullableDate(input, "adoptExpiresOnUtc"),
            RequireNullableString(input, "adoptTenantProof"));
    }

    private static IReadOnlyDictionary<string, ExpectedParity> ParseExpectedByRunner(
        JsonElement expectedByRunner,
        string id)
    {
        RejectDuplicateProperties(expectedByRunner, $"row '{id}' expectedByRunner");
        RequireExactFields(
            expectedByRunner,
            ["xunit-compiled", "pester-legacy"],
            $"row '{id}' expectedByRunner");
        return new Dictionary<string, ExpectedParity>(StringComparer.Ordinal)
        {
            ["xunit-compiled"] = ParseExpected(
                RequireProperty(expectedByRunner, "xunit-compiled", JsonValueKind.Object),
                id,
                "xunit-compiled"),
            ["pester-legacy"] = ParseExpected(
                RequireProperty(expectedByRunner, "pester-legacy", JsonValueKind.Object),
                id,
                "pester-legacy")
        };
    }

    private static ExpectedParity ParseExpected(JsonElement value, string id, string runner)
    {
        string location = $"row '{id}' expectedByRunner.{runner}";
        RejectDuplicateProperties(value, location);
        RequireExactFields(value, ExpectedFields, location);
        return new ExpectedParity(
            RequireBoolean(value, "canRefresh"),
            RequireString(value, "authMode"),
            RequireString(value, "audience"),
            RequireNullableString(value, "clientId"),
            RequireString(value, "credentialGeneration"),
            RequireDate(value, "sourceExpiresOnUtc"),
            RequireNullableString(value, "sourceVerifiedTenantId"),
            RequireStringArray(value, "tokenSequence"),
            RequireDateArray(value, "expiriesOnUtc"),
            RequireStringArray(value, "tokenTypes"),
            RequireStringMatrix(value, "orderedScopes"),
            RequireNullableStringArray(value, "tenantProofs"),
            RequireStringArray(value, "fingerprints"),
            RequireStringArray(value, "generations"),
            RequireString(value, "receivedTimeRule"),
            RequireNonNegativeInt(value, "applicationConstructionCount"),
            RequireNonNegativeInt(value, "providerAcquisitionCount"),
            RequireBoolArray(value, "forceFlags"),
            RequireString(value, "referenceIdentity"),
            RequireNullableString(value, "failureKind"),
            RequireString(value, "cacheState"),
            RequireNonNegativeInt(value, "finalFlightRegistryCount"));
    }

    private static string DetectMutationHint(string json)
    {
        if (json.Contains("\"schemaVersion\": 2", StringComparison.Ordinal)) return "unsupported-schema-version";
        if (json.Contains("\"rowCount\": 15", StringComparison.Ordinal)) return "incorrect-row-count";
        if (json.Contains("replacement-row-id", StringComparison.Ordinal)) return "missing-required-row-id";
        if (json.Contains("\"unexpected\"", StringComparison.Ordinal)) return "unknown-property";
        if (json.Contains("\"schemaVersion\": 1, \"schemaVersion\"", StringComparison.Ordinal)) return "duplicate-json-property";
        return "malformed-matrix";
    }

    private static void RejectDuplicateProperties(JsonElement element, string location)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new InvalidDataException($"{location} has duplicate JSON property '{property.Name}'");
                }

                RejectDuplicateProperties(property.Value, $"{location}.{property.Name}");
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            int index = 0;
            foreach (JsonElement item in element.EnumerateArray())
            {
                RejectDuplicateProperties(item, $"{location}[{index++}]");
            }
        }
    }

    private static void RequireExactFields(JsonElement element, string[] expected, string location)
    {
        string[] actual = element.EnumerateObject().Select(static property => property.Name).ToArray();
        string? unknown = actual.FirstOrDefault(name => !expected.Contains(name, StringComparer.Ordinal));
        if (unknown is not null)
        {
            throw new InvalidDataException($"{location} has unknown property '{unknown}'");
        }

        string? missing = expected.FirstOrDefault(name => !actual.Contains(name, StringComparer.Ordinal));
        if (missing is not null)
        {
            throw new InvalidDataException($"{location} is missing required property '{missing}'");
        }
    }

    private static JsonElement RequireProperty(JsonElement element, string name, JsonValueKind kind)
    {
        if (!element.TryGetProperty(name, out JsonElement value) || value.ValueKind != kind)
        {
            throw new InvalidDataException($"property '{name}' must be {kind}");
        }

        return value;
    }

    private static void RequireKind(JsonElement element, JsonValueKind kind, string location)
    {
        if (element.ValueKind != kind)
        {
            throw new InvalidDataException($"{location} must be {kind}");
        }
    }

    private static void RequireInt(JsonElement element, string name, int expected)
    {
        JsonElement value = RequireProperty(element, name, JsonValueKind.Number);
        if (!value.TryGetInt32(out int actual) || actual != expected)
        {
            throw new InvalidDataException($"property '{name}' must equal {expected}");
        }
    }

    private static int RequireNonNegativeInt(JsonElement element, string name)
    {
        JsonElement value = RequireProperty(element, name, JsonValueKind.Number);
        if (!value.TryGetInt32(out int actual) || actual < 0)
        {
            throw new InvalidDataException($"property '{name}' must be a non-negative integer");
        }

        return actual;
    }

    private static string RequireString(JsonElement element, string name)
    {
        JsonElement value = RequireProperty(element, name, JsonValueKind.String);
        string? result = value.GetString();
        if (string.IsNullOrEmpty(result))
        {
            throw new InvalidDataException($"property '{name}' must be a non-empty string");
        }

        return result;
    }

    private static string? RequireNullableString(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out JsonElement value))
        {
            throw new InvalidDataException($"property '{name}' is required");
        }

        if (value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(value.GetString()))
        {
            throw new InvalidDataException($"property '{name}' must be null or a non-empty string");
        }

        return value.GetString();
    }

    private static bool RequireBoolean(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out JsonElement value) ||
            value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw new InvalidDataException($"property '{name}' must be boolean");
        }

        return value.GetBoolean();
    }

    private static ExactTimestamp RequireDate(JsonElement element, string name)
    {
        string value = RequireString(element, name);
        return ParseDate(value, $"property '{name}'");
    }

    private static ExactTimestamp? RequireNullableDate(JsonElement element, string name)
    {
        string? value = RequireNullableString(element, name);
        if (value is null) return null;
        return ParseDate(value, $"property '{name}'");
    }

    private static string[] RequireStringArray(JsonElement element, string name)
    {
        JsonElement array = RequireProperty(element, name, JsonValueKind.Array);
        return array.EnumerateArray().Select((item, index) =>
        {
            if (item.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(item.GetString()))
            {
                throw new InvalidDataException($"property '{name}[{index}]' must be a non-empty string");
            }
            return item.GetString()!;
        }).ToArray();
    }

    private static string?[] RequireNullableStringArray(JsonElement element, string name)
    {
        JsonElement array = RequireProperty(element, name, JsonValueKind.Array);
        return array.EnumerateArray().Select((item, index) =>
        {
            if (item.ValueKind == JsonValueKind.Null) return null;
            if (item.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(item.GetString()))
            {
                throw new InvalidDataException($"property '{name}[{index}]' must be null or a non-empty string");
            }
            return item.GetString();
        }).ToArray();
    }

    private static bool[] RequireBoolArray(JsonElement element, string name)
    {
        JsonElement array = RequireProperty(element, name, JsonValueKind.Array);
        return array.EnumerateArray().Select((item, index) =>
        {
            if (item.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            {
                throw new InvalidDataException($"property '{name}[{index}]' must be boolean");
            }
            return item.GetBoolean();
        }).ToArray();
    }

    private static ExactTimestamp[] RequireDateArray(JsonElement element, string name)
    {
        JsonElement array = RequireProperty(element, name, JsonValueKind.Array);
        return array.EnumerateArray().Select((item, index) =>
        {
            if (item.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(item.GetString()))
            {
                throw new InvalidDataException(
                    $"property '{name}[{index}]' must be an exact invariant timestamp");
            }
            return ParseDate(item.GetString()!, $"property '{name}[{index}]'");
        }).ToArray();
    }

    private static ExactTimestamp ParseDate(string literal, string location)
    {
        const string format = "yyyy-MM-dd'T'HH:mm:sszzz";
        if (literal.Length != 25 ||
            !literal.EndsWith("+00:00", StringComparison.Ordinal) ||
            !DateTimeOffset.TryParseExact(
                literal,
                format,
                CultureInfo.InvariantCulture,
                DateTimeStyles.None,
                out DateTimeOffset parsed))
        {
            throw new InvalidDataException(
                $"{location} must use exact yyyy-MM-ddTHH:mm:ss+00:00 timestamp syntax");
        }

        return new ExactTimestamp(literal, parsed);
    }

    private static string[][] RequireStringMatrix(JsonElement element, string name)
    {
        JsonElement array = RequireProperty(element, name, JsonValueKind.Array);
        return array.EnumerateArray().Select((item, index) =>
        {
            if (item.ValueKind != JsonValueKind.Array)
            {
                throw new InvalidDataException($"property '{name}[{index}]' must be an array");
            }
            return item.EnumerateArray().Select((nested, nestedIndex) =>
            {
                if (nested.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(nested.GetString()))
                {
                    throw new InvalidDataException($"property '{name}[{index}][{nestedIndex}]' must be a non-empty string");
                }
                return nested.GetString()!;
            }).ToArray();
        }).ToArray();
    }
}
