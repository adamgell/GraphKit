# GraphKit Phase 1 Core Implementation Plan

> **For agentic workers:** this plan is executed by parallel worker subagents (orchestrated fan-out). Each slice below is a self-contained assignment; the contracts section is binding across slices. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement GraphKit phase 1 (Core) — descriptor catalog, immutable contexts, token sources, owned transport, semantics-aware retry, scoped throttling, URI security, paging, batch — per the approved design spec.

**Architecture:** Descriptor-driven operation metadata governs every request. Contexts are immutable runtime values owning an `IGraphTokenSource`. A GraphKit-owned `HttpClient` (no redirects, no cookies, no hidden retry handler) is the sole transport; a retry engine consuming normalized `GraphTransportResult` records with injected Send/UtcNow/Delay/Jitter owns replay decisions. Throttle state is scoped (coarse + leaf gates) with AIMD admission control.

**Tech Stack:** PowerShell 7.4+, Pester 6 (dash assertions), Sampler/ModuleBuilder build, MSAL.NET via `Microsoft.Graph.Authentication` (late-bound, never `Connect-MgGraph`).

**Source of truth:** `docs/superpowers/specs/2026-08-14-graphkit-design.md`. Where this plan and the spec conflict, the spec wins.

---

## Binding build rules (all slices)

1. ModuleBuilder concatenates `source/Private/` first (alphabetical within it), then `source/Public/`, into one `.psm1`. The build regenerates `FunctionsToExport` from `source/Public/`.
2. **Never use a class type in a `param()` constraint of a function in a different file.** Classes defined in one file may sort after a consumer file at parse time. Cross-file class usage only inside function bodies.
3. Classes that must relate (interface + implementations) live in ONE file together.
4. Every file in `source/Public/` MUST be an advanced function with complete comment-based help: `.SYNOPSIS`, `.DESCRIPTION` (>40 chars), ≥1 `.EXAMPLE` whose text contains the function name and is > name+10 chars, and a `.PARAMETER` block per parameter (>25 chars each). `tests/QA/module.tests.ps1` enforces this and requires a `<Name>.Tests.ps1` for every exported function.
5. PSScriptAnalyzer-clean (default rules).
6. Pester 6 style: dash assertions (`Should -BeTrue`), `Should-Invoke`/`Should-NotInvoke` (never `Assert-MockCalled`), default mock that throws registered before filtered mocks, per-file `BeforeAll` imports GraphKit, no experimental global mocks, no Pester parallelism.
7. Prefer `PSCustomObject` records with `PSTypeName` over public classes; classes only where this plan says so.
8. Never log/return bearer tokens, secrets, or raw query values in telemetry. Query sanitization: parameter names and explicitly value-safe OData values only; `$filter`, `$search`, and caller values always redacted.
9. Only edit files your slice owns (file lists below are exhaustive). Do not run builds, full test suites, formatters, or linters — the orchestrator runs all gates.

## Cross-slice contracts (binding)

### Descriptor shape (slice 1 produces; slices 3-5 consume)

Normalized descriptor hashtable (fields always present, from spec normative example):

```
SchemaVersion(1), Type, Operation, OperationKind(Collection|Singleton|Action|LongRunningJob|Binary|Scalar|NoContent|Delta),
HandlerStrategyId, ApiVersion(v1.0|beta), Stability(Stable|DualVersion|BetaPreferred|BetaOnly), BetaReason(null unless Beta*),
Method, PathTemplate, RequestBodyKind, ResponseKind, PagingStrategy(None|NextLink), RequiredPagingHeaders(@()),
DeduplicationKey(null|string), SupportsAll(bool), SupportsDelta(bool), ReplayPolicy(Safe|Conditional|Reconciliable|NeverReplay),
Condition(null unless Conditional), Reconciliation(null unless Reconciliable), AdvancedQuery(@{Supported; ConsistencyLevel?; Count?; AllowedOperators?}),
Concurrency(@{Mode(None|ETag|Header); Header; Required; AllowWildcard}), CredentialPolicy(GraphBearer|None), AllowedHosts(@()),
RedirectPolicy(None|SafeGetOnly), IdentityRequirement(Verified|AllowUnverifiedRead), ResourceFamily, ThrottleClass(Read|Write),
SupportedAuthModes(@()), RequiredPermissions(@()), RequiredLicense(@()), SupportedClouds(@())
```

### Envelope (slice 3 owns; slices 4-5 consume)

`PSCustomObject`, PSTypeName `GraphKit.OperationResult`:

| Field | Content |
| --- | --- |
| `Data` | rows array (or empty) |
| `Outcome` | `Succeeded` \| `Failed` \| `DeadlineExpired` \| `Cancelled` |
| `Certainty` | `Known` \| `Indeterminate` |
| `Telemetry` | array of per-attempt records (see transport slice) |
| `Provenance` | hashtable: `ProfileId`, `TenantId` (null when unverified), `ApiVersion`, `ResourceFamily`, `RetrievedUtc`, `IdentityState`, `ActualTenantId` (null unless verified) |

### Retry engine (slice 3 implements; slice 5 calls)

```powershell
Invoke-GraphRetry -Context <GraphKit.Context> -Descriptor <hashtable> -Uri <[uri]> -Method <string> `
    -Headers <hashtable> -Body <object|$null> -CancellationToken <CancellationToken> `
    [-Injections <hashtable with Send, UtcNow, Delay, Jitter keys>] `
    [-MaxAttempts <int = 5>] [-DeadlineSeconds <int = 300>]
```
Returns exactly one `GraphKit.OperationResult`. It calls `Send` once per attempt (default `Send-GraphHttpRequest`), acquires tokens via `$Context.TokenSource.Acquire($forceRefresh, $ct)`, enforces the tenant-binding gate on mutating sends, consults throttle gates via the throttle contract below, and never throws for transport-level outcomes.

### Throttle (slice 4 implements; slice 3 calls exactly these)

```powershell
New-GraphThrottleScope -Context -Descriptor            # -> @{CoarseKey; LeafKey; ThrottleClass; ResourceFamily; Cloud; TenantId; ClientId}
Wait-GraphThrottleGate -Scope <hashtable>              # waits strictest cooldown; acquires AIMD admission; -> admission record
Complete-GraphThrottleGate -Admission <record>         # releases admission; on success: additive increase
Update-GraphThrottleState -Scope <hashtable> -Qualified <bool> -RetryAfterSeconds <int> -StatusCode <int>
```
Coarse key: `Cloud|TenantId|ClientId|Read|Write`. Leaf key: coarse + `|ResourceFamily`. Token acquisition scope is separate (`Authority|Resource|AuthMode`) and used only by the token source single-flight layer. State is module-scoped, thread-safe (ConcurrentDictionary), never persisted. `New-GraphThrottleScope` for acquisition: `New-GraphThrottleScope -Acquisition -Context`.

### Token source (slice 2 implements; slice 3 consumes via `$Context.TokenSource`)

PowerShell classes CANNOT declare new interfaces (only implement existing .NET ones), so v1 realizes the spec's `IGraphTokenSource` contract as an **abstract base class `GraphTokenSourceBase`** (PowerShell abstract class: abstract `Acquire`, shared single-flight/cache/metadata members) with the four concrete subclasses below, all in ONE file `source/Private/TokenSources/GraphTokenSource.ps1`. An `Assert-GraphTokenSource` helper validates any caller-injected token source against the duck contract (Acquire + metadata properties) so external sources still plug in without inheriting.

- `[GraphTokenResult] Acquire([bool]$forceRefresh, [System.Threading.CancellationToken]$cancellation)` (abstract on base; each subclass implements)
- Base provides: `CanRefresh`, metadata `AuthMode`, `Audience`, `ClientId`, `ExpiresOn`, `VerifiedTenantId`, `CredentialGeneration`, in-memory token cache, and single-flight acquisition per canonical tuple
- `GraphTokenResult` class: `AccessToken, ExpiresOnUtc, TokenType, Scopes, VerifiedTenantId, TokenFingerprint, CredentialGeneration`. `TokenFingerprint` = SHA-256 hex of the bearer; never logged/exported.
- Subclasses: `ConfidentialClientTokenSource` (MSAL late-bound, ctor takes a builder-factory scriptblock for testability), `ManagedIdentityTokenSource`, `ProviderTokenSource` (scriptblock/delegate provider, `CanRefresh = $true`), `FixedBearerTokenSource` (`CanRefresh = $false`)
- Single-flight: `Invoke-GraphTokenSingleFlight -Key <string> -AcquireScript <scriptblock>` — ConcurrentDictionary + SemaphoreSlim; failure surfaces to all waiters.
- Factory: `New-GraphTokenSource -Profile <hashtable> -Cloud <hashtable> [-MsalFactory <scriptblock>]`
- Validator: `Assert-GraphTokenSource -Source` (duck-typed contract check; actionable error naming the missing member)

### Context (slice 2 owns)

`PSCustomObject`, PSTypeName `GraphKit.Context`: `ProfileId, TenantId [guid], Cloud, GraphBaseUri [uri], ClientId (guid|null), TokenSource, CredentialFingerprint, AcquisitionCacheKey, IdentityState (VerifiedForToken|Unverified|NotAcquired)`. `New-GraphContext -Profile -StorePath` resolves **without any network call**. Cloud table: Global/China/Germany/USGov/USGovDoD → Graph base URI + authority (private `Get-GraphCloudMetadata`).

### Public command surface (files below)

`Register-GraphTenant`, `Get-GraphTenant`, `Remove-GraphTenant`, `Test-GraphTenant`, `Get-GraphContext`, `Use-GraphTenant` (slice 2); `Get-GraphOperation` (slice 1); `Invoke-GraphRequest`, `Invoke-GraphBatch` (slice 5). All accept `-Context` or `-ProfileId` (never display `Name` as selector).

---

## Slice ownership matrix

### Slice 1 — Descriptor catalog (gate 1.2)

**Files (create/modify):**
- `source/Private/Operations/Import-GraphOperationDescriptor.ps1` — loader + validator + cross-field rules + SchemaVersion refusal
- `source/Private/Operations/GraphHandlerStrategyRegistry.ps1` — `Register-GraphHandlerStrategy`, `Resolve-GraphHandlerStrategy` (closed registry, kind-prefix validated: `Collection.Default`, `Action.Default`, `Reconciliation.StableExternalKey`, `LongRunningJob.PollStatus` are the only v1 IDs)
- `source/Private/Operations/Get-GraphOperationInternal.ps1` — catalog resolver; loads all `Data/Operations/*.psd1` once per session into a script-scoped cache; supports `-Type`, `-Operation`, `-List`
- `source/Public/Get-GraphOperation.ps1` — public wrapper (full CBH + test file)
- `source/Data/Operations/MobileApp.Assign.psd1` — update to FULL schema (add `RequiredPagingHeaders`, `DeduplicationKey`, `SupportsAll`, `SupportsDelta`, `Condition`, `RedirectPolicy`, `IdentityRequirement`, full `Concurrency` block)
- `source/Data/Operations/ManagedDevice.List.psd1` — NEW: Collection, GET `/deviceManagement/managedDevices`, PagingStrategy NextLink, RequiredPagingHeaders `@()`, DeduplicationKey `id`, SupportsAll/Sync… (`$false`/`$false`), ReplayPolicy Safe, ThrottleClass Read, ResourceFamily `Intune.ManagedDevices`, `DeviceManagementManagedDevices.Read.All`, SupportedClouds Global/USGov/USGovDoD, IdentityRequirement Verified
- `source/Data/Operations/DeviceReport.Export.psd1` — NEW: LongRunningJob, POST `/deviceManagement/reports/exportJobs`, HandlerStrategyId `LongRunningJob.PollStatus`, ReplayPolicy Safe, ThrottleClass Write, ResourceFamily `Intune.Reporting`, ResponseKind Json
- `tests/Unit/Operations/*.tests.ps1` — incl. `Get-GraphOperation.Tests.ps1`

**Acceptance:** every invalid-descriptor rule from spec (CredentialPolicy=None needs AllowedHosts+HTTPS; Beta* needs BetaReason; Reconciliable needs Reconciliation; Conditional needs Condition; beta ApiVersion needs matching Stability; AllowUnverifiedRead requires Read+Safe+GraphBearer; NextLink requires the four paging fields) rejects with an actionable error naming file + rule. Unknown/wrong-prefix strategy IDs rejected. Catalog round-trips; three descriptors load; registry validates. Tests must NOT register strategy implementations themselves for validation — validation resolves against the closed v1 ID set.

### Slice 2 — Contexts, profile store, token sources (gate 1.3)

**Files:**
- `source/Private/Get-GraphCloudMetadata.ps1`
- `source/Private/Profiles/Get-GraphProfileStore.ps1` — read + SchemaVersion refusal + backup reporting
- `source/Private/Profiles/Save-GraphProfileStore.ps1` — atomic (temp in same dir + fsync + rename), previous generation retained as `.bak`, interprocess lock (FileStream FileShare.None with bounded retry) around read-modify-write
- `source/Private/Profiles/New-GraphProfileId.ps1`? NO — keep surface minimal: validation helper `Test-GraphProfileId` (regex `^[a-z0-9][a-z0-9-]{0,63}$`)
- `source/Private/TokenSources/GraphTokenSource.ps1` — interface, result class, 4 sources, single-flight, factory (ONE file)
- `source/Public/Get-GraphContext.ps1` (+ supports injected `X509Certificate2` / token provider; rejects persisting injected material)
- `source/Public/Register-GraphTenant.ps1` — discriminated credential shapes per spec table; validates ProfileId/Kind/TenantId/ClientId/Environment; `Kind=customer` taxonomy check via injectable adapter (default: no-op with comment unless CDW adapter exists — tests inject stub)
- `source/Public/Get-GraphTenant.ps1`, `source/Public/Remove-GraphTenant.ps1`, `source/Public/Test-GraphTenant.ps1`, `source/Public/Use-GraphTenant.ps1`
- `tests/Unit/Profiles/*.tests.ps1`, `tests/Unit/TokenSources/*.tests.ps1` + `<Name>.Tests.ps1` for every public command

**Acceptance:** `Get-GraphContext` resolves with zero network calls (test injects an MSAL factory that throws if invoked); four auth modes produce sources with correct `CanRefresh`/metadata; store is atomic + locked + refuses newer SchemaVersion with actionable error; single-flight collapses N concurrent acquires for the same canonical tuple to one acquisition (stub provider counts calls); canonical tuple key normalization (GUID case, host case, scope order).

### Slice 3 — Transport, retry engine, envelope (gate 1.4)

**Files:**
- `source/Private/Transport/GraphTransportResult.ps1` — the class from the spec (StatusCode, Headers, Body, RequestId, TransportException, ResponseReceived)
- `source/Private/Transport/Send-GraphHttpRequest.ps1` — module/session-scoped HttpClient + SocketsHttpHandler (AllowAutoRedirect=false, UseCookies=false, PooledConnectionLifetime=5min, ConnectTimeout); split connection/header/body timeouts via linked CancellationTokenSource; bearer attach per-message (never default headers); tenant-binding gate for mutating sends (`VerifiedTenantId -eq TargetTenantId` when `-VerifyTenantBinding`, else hard error before send); one attempt = exactly one physical send
- `source/Private/Get-GraphRetryDecision.ps1` — ReplayPolicy × attempt-certainty matrix; 401 force-refresh-once; 2xx+Retry-After → success+pace; 409 known-transient inner codes; never replay ambiguous POST
- `source/Private/Get-GraphRetryDelay.ps1` — hostile Retry-After parser (spec's ordered rules: multiple header values; whole-value delta-seconds; HTTP-date with `Date`-header reference; malformed comma lists last; `x-ms-retry-after-ms` separate; clamp negatives/excess; record malformed), jittered exponential fallback
- `source/Private/Invoke-GraphRetry.ps1` — attempt loop with injected Send/UtcNow/Delay/Jitter, monotonic deadline (Stopwatch), cancellation, throttle-gate calls per the throttle contract, telemetry accumulation, envelope construction
- `source/Private/Transport/New-GraphTelemetry.ps1` — per-attempt sanitized record: logical op id, client/request ids, response Date, x-ms-ags-diagnostic, sanitized URI (query values redacted per rule 8), attempt#, delay+source, throttle state, batch subrequest id, per-attempt outcome/certainty, structural Graph error code chain
- `source/Formats/GraphKit.Format.ps1xml` — add `GraphKit.OperationResult` default view (Outcome, Certainty, Tenant, ApiVersion, Data rows count)
- `tests/Unit/Transport/*.tests.ps1`, `tests/Adapter/*.tests.ps1` (HttpListener loopback through the REAL `Send-GraphHttpRequest`)

**Acceptance:** virtual-clock suite asserts exact requested delays, delay-source precedence, no replay after 202+Retry-After, no replay of ambiguous POST (Failed+Indeterminate), one refresh after 401, no loop on second 401, deadline expiry mid-throttle, cancellation, and that every attempt calls Send exactly once. Loopback tests assert: no auto-redirect, `GraphBearer` only to exact cloud authority, `None` never carries Authorization, split timeouts each fire, cancellation aborts in-flight, one send per attempt, query strings absent from telemetry, malformed Retry-After handled, duplicate headers/empty body/mid-response close normalized. Envelope shape matches the contract exactly (field names above).

### Slice 4 — Scoped throttle + AIMD (gate 1.7)

**Files:**
- `source/Private/GraphThrottleCoordinator.ps1` — module-scoped class instance: ConcurrentDictionary of scope state (CooldownUntil, MaxConcurrent, InFlight), AIMD (qualified 429/503 → MaxConcurrent=1 + cooldown; success → additive increase to tunable cap), thread-safe
- `source/Private/Get-GraphThrottleScope.ps1` — scope computation per contract (coarse + leaf + acquisition mode)
- `source/Private/Wait-GraphThrottleGate.ps1`, `source/Private/Complete-GraphThrottleGate.ps1`, `source/Private/Update-GraphThrottleState.ps1` — per contract signatures
- `tests/Unit/Throttle/*.tests.ps1`, `tests/Concurrency/*.tests.ps1`

**Acceptance:** unit tests with virtual time: unqualified 429/503 update coarse gate only; qualified updates leaf; strictest cooldown wins; cross-tenant isolation (Tenant B unaffected by Tenant A cooldown); AIMD cut/restore. Concurrency tests: REAL runspaces (serial at Pester level, barriers, controlled transport) prove only intended number proceed, all observe scoped cooldown, Tenant B unblocked while Tenant A throttled.

### Slice 5 — URI security, paging, public request surface, batch (gate 1.5)

**Files:**
- `source/Private/Resolve-GraphUri.ps1` — PathTemplate + parameter substitution, query option validation against `AdvancedQuery`, reject unsupported options rather than pass through
- `source/Private/Test-GraphNextLinkAuthority.ps1` — https + exact cloud authority match before any token attach
- `source/Private/Test-GraphCredentialPolicy.ps1` — GraphBearer: HTTPS + exact authority; None: allowlist + HTTPS; hard error naming offending authority (active under `-Raw` too)
- `source/Private/Invoke-GraphPaging.ps1` — NextLink loop: opaque nextLink, authority-validated per hop, required headers repeated per page, empty page with nextLink continues, dedup by DeduplicationKey, page cap, per-page retry via Invoke-GraphRetry, aggregates Data + per-page telemetry
- `source/Private/Invoke-GraphHandlerStrategy.ps1` — executes registered strategy (`Collection.Default`, `Action.Default`, `Reconciliation.StableExternalKey`, `LongRunningJob.PollStatus`) with `($Context, $Descriptor, $Parameters, $Transport)` (+ `$IntendedState` for reconciliation); registers the four v1 strategies at import; handlers use only injected transport delegates
- `source/Public/Invoke-GraphRequest.ps1` — orchestrates: resolve descriptor + context, validate credential policy, run strategy/retry, warn-once-per-session for BetaPreferred, stamp provenance, return ONE envelope per logical operation
- `source/Public/Invoke-GraphBatch.ps1` — read-only by default: ordered per-subrequest envelopes, 424 dependency reporting with blocking id, retry only failed retryable `Safe` subrequests, never replay successful write subrequests, single batch transport call
- `tests/Unit/Pipeline/*.tests.ps1` + `<Name>.Tests.ps1` files

**Acceptance:** nextLink authority validation blocks hostile hosts even under `-Raw`; redirects surfaced as non-success for mutating methods; `SafeGetOnly` follows only validated HTTPS hops within allowlist; `None` policy never carries Authorization (asserted on wire); query stripped from telemetry; paging handles empty-page-with-nextLink and repeats required headers; batch state machine matches spec; envelope-per-subrequest ordered.

## Slices NOT in wave 1 (later waves)

- Auth/vault resolution, tenant-proof call, MSAL import guard, single-flight integration gate (1.6)
- Get-GraphObject + completion + catalog expansion (phase 2), permissions (phase 3), export (phase 4)
- Protected smoke workflow (1.8), CI workflow + import-order matrix

## Verification (orchestrator runs)

```powershell
./build.ps1 -ResolveDependency -Tasks noop
./build.ps1 -Tasks build          # compile gates: no parse errors, manifest regenerated
./build.ps1 -Tasks test           # full deterministic suite (unit + adapter + concurrency + QA)
Invoke-Pester ./tests/New-ClientServicePrincipalCBA.Tests.ps1 -Output Detailed
```

Phase gates map: 1.2→tests/Unit/Operations, 1.3→tests/Unit/Profiles+TokenSources, 1.4→tests/Unit/Transport+tests/Adapter, 1.5→tests/Unit/Pipeline, 1.7→tests/Unit/Throttle+tests/Concurrency.
