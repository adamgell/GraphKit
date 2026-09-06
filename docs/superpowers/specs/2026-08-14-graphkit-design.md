# GraphKit — Design

- **Date:** 2026-08-14
- **Status:** Approved for planning
- **Author:** Adam Gell

**Product definition.** GraphKit is an app-only, multi-tenant Microsoft Graph execution and
analysis layer with explicit Intune/Entra operation semantics. It is not a generic Graph SDK and
not another OAuth library. That boundary is what keeps it from collapsing into the two traps
prior projects hit repeatedly: rebuilding the identity client, and pretending Graph's endpoint
behavior is more uniform than it is.

## Problem

Microsoft Graph code is spread across ~175 PowerShell files in 16 repos, with no shared
core. Four distinct problems result:

1. **Tenant switching.** Credentials live in per-customer `.cmd` launchers and scattered
   `secret.json` files. Pointing at the right tenant is manual and error-prone.
2. **Copy-pasted boilerplate.** Token acquisition, paging, and error handling are
   reimplemented per script.
3. **Discovery.** Finding the script that already does a thing means searching 16 repos.
4. **Inconsistent output.** Each script exports differently, so results cannot be composed
   or filed as evidence without hand-work.

Current fragmentation, measured:

| Pattern | Files |
| --- | --- |
| `Connect-MgGraph` (SDK) | 61 |
| raw `client_credentials` REST | 44 |
| `Az.Accounts` token borrowing | 19 |
| references a `secret.json` | 117 |

### Security findings (pre-existing, not introduced by this work)

- Four live customer client secrets sit in plaintext in
  `IntuneManagement-Development/Start-WithConsole _PS7 *.cmd` (CDW workspace, Suffolk,
  UCHC, Invivoscribe). **Verified not git-tracked**, and no `secret.json` is tracked in any
  repo, so nothing has leaked. They remain plaintext on disk.
- `IntuneHealthAutomation/config/secrets.example.json` documents a `bearerTokens` array
  holding raw tokens.

Retiring both is a design requirement, not a side effect.

## Prior art

### IntuneHealthAutomation (`github.com/adamgell/IntuneHealthAutomation`, private)

A PowerShell module (`src/healthcheck.psd1` v0.2.0) implementing much of the intended core:
multi-tenant configuration with per-tenant output, certificate-based auth (`Get-CBAToken`),
bearer token and MgGraph SDK paths, `Invoke-IntuneGraphRequest` (594 lines: `@odata.nextLink`
paging, `$batch`, proactive token-expiry detection), `Invoke-ParallelGraphRequest` (318 lines),
17 schema-governed JSON report definitions, API/endpoint caching, and checkpoint/resume.

**Gaps identified:**

1. **No throttling handling.** Zero references to `429`, `503`, `Retry-After`,
   `TooManyRequests`, or backoff. The parallel path makes throttling likelier, not less.
2. **No tests.** `.github/workflows/pester-tests.yml` runs on every push, but zero
   `*.Tests.ps1` files are tracked. CI passes because it tests nothing.
3. **No `ConsistencyLevel` handling.**
4. **Declares PowerShell 7.2**, past end of support.

It is an *application*, not a *library*: ~25 module-scope `$script:` variables, coupled to
`ImportExcel` and the reporting pipeline.

### External prior art

Surveyed 2026-08-14; module versions verified against PSGallery the same day.

| Project | Version / date | Bearing on GraphKit |
| --- | --- | --- |
| **MgGraphCommunity** | 1.5.0, 2026-07-28 | Closest competitor. Pure PowerShell, direct Graph calls, **multiple simultaneous live contexts**, cert/secret/bearer, sovereign clouds, paging, batch, 429/503/504 retry. **Disqualifier for consulting use: a *global* `/beta` default** — verified in source, relative URIs go to beta and `-V1` is the opt-*down* ("Default to /beta (more surface area)"). The problem is not beta, which is where much of Intune's production surface genuinely lives; it is that the choice is process-wide and blind, so operations with a perfectly good v1.0 silently ride an interface carrying no breaking-change guarantee. Also brand new, small ecosystem, owns its own delegated PKCE/refresh security code, no SecretManagement profile lifecycle, no permission analysis, no Intune operation semantics. **Compare public API and tests against it; do not adopt.** |
| **MSGraphRequest** | 2.0.1, 2026-02-20 | By Nickolaj Andersen & Jan Ketil Skanke (MSEndpointMgr) — the most credible authors in this space. Native REST, no SDK/MSAL dependency, six auth flows, automatic paging/throttling/refresh. Exposes a *current connection*, not named immutable contexts. **Strong evidence that raw transport and app-only OAuth are commodity.** Not a replacement: no SecretManagement profiles, no operation catalog, no cross-runspace rate control, no permission analysis, no replay-safety classification. |
| **mgx** | 1.0.5, 2026-08-14 | **Best current reliability prior art.** Proactive rate limiting, circuit breaking, adaptive write pacing, connection recycling, body-read timeouts, checkpoint/resume, delta, streaming pagination, telemetry. Unusable as a foundation (PS 7.5+, depends on `Microsoft.Graph.Authentication`, compiled components, generic rather than Intune-aware) but **its pipeline architecture should be studied and borrowed**. |
| **AutoGraphPS / -SDK** | 0.44.0 / 0.32.0, Nov 2024 | The strongest design history for type-driven access: separation of connection / logical graph / type metadata / location context, URI and property completers, permission-name resolution. Its instructive lesson is that **a metadata-driven model still accumulated many special cases**. ~21 months stale; do not inherit its ADAL/MSAL-era auth architecture. |
| **Microsoft.Graph.Authentication** | 2.38.1 | **Not** used as transport — its process-global state is shared across runspaces (demonstrated below). Depended on solely to deliver MSAL.NET; `Connect-MgGraph` is never called. |
| **Maester** | current | Pester-based M365/Entra security testing. Overlaps IHA's *reporting* purpose, not GraphKit's plumbing. Evaluate before hand-building more health-check reports. |
| **IntuneManagement** (Micke-K, MIT) | — | Source of the object-type/endpoint table. The WPF UI around it is not wanted. Local copy has no LICENSE file; vendoring requires the upstream MIT text in `THIRD-PARTY-NOTICES.md`. |
| **Microsoft365DSC**, **EntraExporter**, **IntuneBackupAndRestore**, **IntuneAssignmentChecker** | — | Config-as-code, Entra export, policy backup, assignment audit respectively. Adjacent, not overlapping. |

#### What Maester's auth confirms

`Connect-Maester.ps1` (495 lines) is broad — 9 services, a separate sovereign-cloud enum per
service, explicit module import ordering to dodge bundled-DLL conflicts, scope-on-demand
switches. It is **shallow exactly where the hard problems are**: Graph auth passes straight
through to `Connect-MgGraph`; zero `client_credentials`; certificate auth only for SharePoint;
zero references to `429`, `Retry-After`, or backoff. Its `Invoke-MtGraphRequestCache` is a
hashtable keyed on absolute URI with no TTL, invalidation, or size bound.

Lifted: sovereign-cloud enums, existing-session reuse before reconnecting, scope-on-demand as a
least-privilege default. **Not** lifted: the unbounded cache.

**The consistent finding across all of the above is that token acquisition is commodity, while
throttling correctness, replay safety, and credential-boundary enforcement are not.** That is
where GraphKit's value sits — and note that none of these projects, including the official SDK,
provides a transport whose retry behavior a caller can actually own.

## Decision

Extract the plumbing from IntuneHealthAutomation into a standalone `GraphKit` module, in stages.
Build and prove GraphKit first; cut IntuneHealthAutomation over to it as separate, later work.

Rejected: big-bang refactor (invasive change to an app with no test suite), extending IHA in
place (drags ImportExcel/caching/reporting into every quick action), greenfield copy-harvest
(two Graph layers that drift).

```
GraphKit            plumbing: auth, contexts, request pipeline, operations, permissions
   ^
   |
healthcheck (IHA)   domain: reports, Excel, caching, checkpointing
```

### Tokens from MSAL.NET; transport owned by GraphKit

**This reverses the earlier decision to route requests through `Connect-MgGraph` /
`Invoke-MgGraphRequest`.** The SDK is not usable as GraphKit's transport, for a demonstrated
reason.

#### The SDK's state is process-global and shared across runspaces

Measured 2026-08-14:

```
parent runspace     : MaxRetry=7
child runspace      : MaxRetry=2      # set inside ForEach-Object -Parallel
parent after child  : MaxRetry=2      # parent mutated by the child
```

`Set-MgRequestContext` in a child runspace **mutated the parent's configuration**. SDK state
lives in .NET statics shared across runspaces in the same process. `Get-MgContext` takes no
parameters because there is exactly one connection, and that connection is equally shared.

The consequence is a correctness failure, not an inconvenience. Runspace A begins paging
Tenant A; Runspace B calls `Connect-MgGraph` for Tenant B; A's next page is issued with B's
token while A's results and telemetry still claim Tenant A. **Silent cross-tenant data
contamination in a consulting tool is the worst failure mode this module could have.**

The earlier draft asserted both "immutable contexts prevent retargeting" and "every request goes
through the process-global SDK." Those cannot both be true.

#### Three findings, one root cause

Context retargeting, retry ownership, and the timeout contract are the same problem: **the SDK
transport carries process-global mutable state GraphKit cannot own.**

- **Retry ownership.** GraphKit promises no-replay-on-ambiguity — never auto-replay a POST
  that may have committed. If the SDK's handler retries a 503 before GraphKit sees the response,
  that promise is void. `Set-MgRequestContext -MaxRetry 0` is accepted and does disable retries,
  but it is itself process-global state any runspace can change, so it can be requested and never
  guaranteed.
- **Timeouts.** `Invoke-MgGraphRequest` exposes **no** timeout or cancellation parameters;
  `Set-MgRequestContext` offers only a single SDK-wide `ClientTimeout`. The promised separate
  connection / header / body timeouts and cancellation cannot be delivered through it. Exposing
  controls that cannot interrupt the underlying operation would be a lie.

Per-symptom patches — connection leases, `MaxRetry 0`, narrowed timeout promises — all wrap
state GraphKit does not control.

#### The resolution

**MSAL.NET for token acquisition, a GraphKit-owned `HttpClient` for transport.**

`Microsoft.Identity.Client.dll` v4.82.1 already ships inside `Microsoft.Graph.Authentication`.
Using `ConfidentialClientApplicationBuilder` directly gives:

- **Per-context token acquisition with no global state.** Each GraphKit context owns its own
  token source, holding its own MSAL application instance and token cache. Two contexts cannot
  interfere, because there is nothing shared to interfere through. (The context owns an
  `IGraphTokenSource`, not a confidential client directly — see **Token sources** below. Managed
  identity uses a different MSAL builder entirely.)
- **Certificate assertion signing still handled by MSAL** — RS256, `x5t`, `jti`, validity window.
  This was the one genuine reason not to hand-roll, and it is preserved. **GraphKit writes no
  OAuth cryptography.**
- Sovereign authorities via `WithAuthority`.

Owning the `HttpClient` then delivers, by construction, what the SDK could not: sole retry
ownership, real connection/header/body timeouts with cancellation, and a non-bypassable
credential boundary on every send.

This is not a return to hand-rolled OAuth. MSAL performs the protocol and the crypto; GraphKit
performs HTTP. It is also the boundary the external reviews independently recommended for
delegated auth — it turns out to be correct for app-only as well.

**Cost accepted:** GraphKit owns one module/session-scoped `HttpClient` backed by a `SocketsHttpHandler`. The handler disables automatic redirects and cookies, uses a finite `PooledConnectionLifetime`, and never stores authorization in default headers. Contexts are immutable, non-owning values that share this transport; caller-injected certificates and token providers are never disposed by GraphKit. Module teardown disposes the shared transport after in-flight operations finish. The transport remains directly testable through the injected sender used by the virtual-clock tests.

#### MSAL sourcing and the assembly-coexistence hazard

Four MSAL versions were found coexisting on the development machine: `Az.Accounts` 4.83.1 and
4.84.0, `Microsoft.Graph.Authentication` 4.82.1, `Microsoft.PowerShell.PSResourceGet` 4.61.3.

**GraphKit must not bundle a competing copy.** In the default assembly load context the first
loaded version wins for the process, and PSResourceGet's copy is present in effectively every
session. Shipping a fifth would create precisely the DLL-ordering pain that Maester documents
working around.

Therefore:

- Declare `Microsoft.Graph.Authentication` as a required module **solely as MSAL's delivery
  vehicle**, with a pinned tested minimum version. `Connect-MgGraph` is never called.
- Bind to MSAL **late** — PowerShell resolves types at runtime, which tolerates version drift so
  long as usage stays on long-stable surface: `ConfidentialClientApplicationBuilder.Create`,
  `WithClientSecret`, `WithCertificate`, `WithAuthority`, `AcquireTokenForClient`.
- **Detect the actually-loaded MSAL version at module import** and fail immediately with an
  actionable message if it is below the tested minimum or absent. Do not discover this at first
  token acquisition inside a customer engagement.
- A QA test asserts GraphKit ships no `Microsoft.Identity.Client.dll` of its own.

**This is an accepted compatibility constraint for v1, not a sound long-term boundary.**
`Microsoft.Identity.Client.dll` is a *private implementation detail* of
`Microsoft.Graph.Authentication`. That module publishes no contract for the assembly's location,
its load timing, or its exact version, and it is free to change or drop it in any release. A
pinned minimum version on the parent module does not prove which MSAL binary is actually loaded:
in the default load context the first version to load wins for the whole process, and
PSResourceGet's older copy is present in effectively every session before GraphKit is imported.

Because contexts own an `IGraphTokenSource` rather than an MSAL client directly, replacing this
mechanism later is an **implementation change, not an interface change**. That abstraction is
what makes the interim position tolerable.

**Interim requirement.** While the transitive approach stands, CI must include an
**import-order matrix** — fresh processes importing `Az.Accounts`, `Microsoft.Graph.Authentication`,
and `Microsoft.PowerShell.PSResourceGet` in each meaningful order before GraphKit, asserting that
token acquisition still succeeds and recording which MSAL version won. A silent version change is
otherwise indistinguishable from a working configuration until a customer engagement.

### GraphKit.Auth — the end-state authentication boundary

**Status correction, 2026-08-30: active R8 gate; absent from immutable `0.3.0`.** The interim
PowerShell source was subsequently proven unsafe when a parent-created source was invoked from a
child runspace: nested PowerShell-class acquisition can hang before its method guard executes.
Post-release development therefore rejects crossed legacy sources in the public sender before
single-flight or method dispatch. That is containment, not delivery of the contract below.

The required end state is a small compiled adapter that owns the MSAL boundary outright:

`GraphKit.Auth` is the required end-state boundary. The transitive MSAL delivery contract remains
the immutable `0.3.0` behavior; a successor must not claim runspace-neutral contexts until the
isolated adapter below replaces the legacy PowerShell acquisition path.

The end-state adapter:

- References an **explicit `Microsoft.Identity.Client` package version**, resolved at build time.
- Loads that MSAL into an **isolated `AssemblyLoadContext`**, so GraphKit's version is unaffected
  by whatever `Az.Accounts`, the Graph SDK, or PSResourceGet loaded first, and GraphKit does not
  perturb theirs.
- Exposes **only GraphKit-owned request and result types**. No MSAL type crosses the boundary.
- Removes `Microsoft.Graph.Authentication` as a runtime dependency only after the v1 migration
  gate succeeds.

#### Contract

```text
GraphTokenRequest    Environment, TenantId, Authority, GraphResource/.default,
                     ClientId, AuthMode, Credential, CredentialGeneration,
                     ForceRefresh, Cancellation
GraphTokenResult     AccessToken, ExpiresOnUtc, TokenType, Scopes,
                     VerifiedTenantId, TokenFingerprint, CredentialGeneration
```

`TokenFingerprint` is a non-exported, collision-resistant fingerprint of the exact bearer
value. It is used only to bind verification and cache generations; it is never logged, exported,
or used as a credential substitute. `CredentialGeneration` changes when a vault version,
certificate, provider generation, or fixed bearer value changes.

`Credential` is a discriminated shape mirroring the profile schema: certificate (as
`X509Certificate2`, a framework type available in both contexts), client secret, managed identity
(system- or user-assigned), or caller-supplied token. Each maps to the correct MSAL builder —
`ConfidentialClientApplicationBuilder` for certificate and secret,
`ManagedIdentityApplicationBuilder` for managed identity — which is precisely why
`IGraphTokenSource` exists rather than a single client type.

One MSAL application instance per context, cached and reused: MSAL's in-memory token cache lives
on the application object, so discarding it per call would defeat caching and invite token-endpoint
throttling. MSAL applications are thread-safe; single-flight coordination per cache key stays on
the GraphKit side.

#### Costs, stated plainly

- GraphKit stops being pure PowerShell. Releases require a .NET SDK in CI and a compiled artifact
  in the package.
- Target `net8.0` — the floor matching PowerShell 7.4, forward-compatible with the .NET 10 runtime
  under 7.6. A single assembly serves both; no per-platform native build is involved.
- Debugging across an ALC boundary is harder, and type-identity mistakes surface as confusing cast
  failures rather than clear errors.
- Release complexity rises: build, package, and verify the assembly alongside the PowerShell
  module, and the QA test asserting "GraphKit ships no `Microsoft.Identity.Client.dll`" inverts to
  assert it ships exactly one, at the expected version, loaded into the expected context.

#### Migration

The swap is behind `IGraphTokenSource`, so it is additive: implement
`GraphKitAuthTokenSource` alongside the existing transitive source, run both against the same
contract tests, cut contexts over, then delete the transitive source and drop the
`Microsoft.Graph.Authentication` dependency. No public command signature changes.

**What would bring this forward:** the transitive MSAL breaking in a supported configuration, an
import-order matrix failure, or `Microsoft.Graph.Authentication` changing or removing its bundled
MSAL. Any of those turns the interim from tolerable into broken.

#### Token cache

In-memory, per context, never persisted. Client-credentials flows return no refresh token: an
expired token is replaced by reacquiring with the source credential, which is already in
SecretManagement. Persisting app-only access tokens adds theft and stale-cache risk for no gain.

Single-flight acquisition per **canonical acquisition tuple**: the first caller acquires, others
await the same result, a failure surfaces to all waiters and is not cached for long. The tuple is
`Environment | TenantId | Authority | GraphResource/.default | ClientId | AuthMode |
ManagedIdentitySelectorOrProviderIdentity | CredentialGeneration`. Normalize GUIDs, hosts,
resource/scope ordering, and case before keying. A change in any component creates a new cache
generation; no token may cross tuple boundaries.

Without single-flight, ten runspaces starting together request ten identical tokens and trigger
Entra's own throttling — Microsoft describes "loop detected" errors as that symptom. Token
acquisition therefore gets its own throttle scope, distinct from Graph request scopes.

Refresh timing uses the supported MSAL `AuthenticationResult.ExpiresOn` value, not a raw
`expires_in` field and never the JWT `exp` claim. Provider sources return their own explicit
`ExpiresOnUtc` when available. Acquisition start/completion timestamps may add conservative
skew, `min(5 min, max(60 s, 10% of lifetime))`, with a small random spread so fifteen contexts
do not all reacquire at the same instant after a bulk connect.

Wall-clock UTC governs token expiry; **monotonic elapsed time governs retry budgets and
deadlines**, so a clock change mid-session cannot extend a five-minute budget.

#### Contexts and concurrency

> **Implementation correction, 2026-08-30:** the paragraph below is the approved target contract,
> not a claim about the post-`0.3.0` legacy source. That source is same-runspace-only and fails fast
> at the sender if crossed. Creating a fresh child-runspace context can observe credential rotation
> and is not equivalent to passing one immutable context. `GraphKit.Auth` must restore and prove the
> target with real runspaces.

Because nothing is process-global, no connection coordinator, lease manager, or session
generation is required. A context is an immutable value resolved before parallel work begins and
passed into each runspace. Correctness comes from the absence of shared mutable identity state
rather than from locking around a singleton connection.

**Simultaneous low-level contexts for different tenants are supported in v1.** Each context has
its own token source, acquisition tuple, verification state, and cache generation; concurrent
requests must not share bearer values or tenant provenance. High-level cross-tenant comparison
and orchestration commands remain out of scope for v1.

### Bearer tokens are caller-owned

GraphKit may hold an externally supplied bearer token or provider but must never claim a fixed
token can refresh. A provider may refresh only through its explicit `Acquire` contract; every
replacement is treated as a new token generation and reverified before any operation that needs
tenant-bound identity. A caller-supplied expiry is honored; absence of one means an unverified
read can be attempted only when its descriptor explicitly permits it, followed by a clear
authentication failure for any operation requiring verified identity.

## Scope

### Moves into GraphKit

| Area | From |
| --- | --- |
| Tenants | `Save-/Remove-TenantConfiguration`, `New-TenantConfigurationPrompt`, `Show-TenantManagementMenu`, `Get-SecretsConfiguration` |
| Request core | `Invoke-IntuneGraphRequest`, `Invoke-ParallelGraphRequest`, `Get-GraphUrl` |
| Permissions | `Test-GraphPermissions`, `Get-TokenPermissionAnalysis`, `Get-AppRegistrationPermissions`, `Grant-IntuneAppPermissions` (~1,400 lines, generalized) |

### Retired, not moved

- `Get-CBAToken` (253 lines) → MSAL `ConfidentialClientApplicationBuilder.WithCertificate`
- `Update-AccessToken` (150 lines) → the per-context MSAL token source (**not** an SDK cache; GraphKit never holds an SDK context)
- `Set-GraphEnvironment` (65 lines) → MSAL `WithAuthority` plus per-context cloud metadata

Caller-supplied bearer tokens survive as a context-only credential. ~470 lines of token-lifecycle code stop being
maintained here.

### Stays in IntuneHealthAutomation

Report definitions and the Excel pipeline, `src/private/Processing` (28 files),
`Checkpoint-DeviceCollection`, console UI, `Invoke-IntuneHealthCheck`, and **the entire caching
layer** (~1,300 lines, entangled with checkpointing; deferred until GraphKit's pipeline is
proven).

## Components

### Repository

New private repo at `~/repo/GraphKit` → `github.com/adamgell/GraphKit`, scaffolded with
**Sampler**. Scaffolding ran 2026-08-15 by invoking the underlying Plaster template directly
with its full parameter set, into a temp directory that was then merged, because the repo
already contained `docs/`, `scripts/`, and tests.

Verified against Sampler 0.120.1 on 2026-08-14:

- **Pester 6 is compatible.** Version gates are lower-bound only (`>= 5.0.0`), and Sampler
  references none of the options v6 removed — no `CoverageGutters`, no `UseBreakpoints`, no
  `FailOnNullOrEmptyForEach`. Coverage is JaCoCo, which v6 retains.
- **`New-SampleModule` itself cannot run non-interactively.** The prompt that blocks it
  ("Will you use Git for source control?") comes from a `UseGit` Plaster template parameter
  the wrapper never exposes. Invoking the Plaster template directly with the full parameter
  set scaffolds unattended, so the earlier claim that scaffolding "must not be scripted" was
  wrong; it was corrected at scaffold time.
- The scaffold was aligned with this design rather than left at template defaults:
  `SourceDirectory = 'source'` (not `src`), PowerShell 7.4 floor (not 5.0), both runtime
  modules declared in `RequiredModules`, `build.yaml` `CopyPaths` covering `Data/` and
  `Formats/`, and `FormatsToProcess` registering `GraphKit.Format.ps1xml`. The license was
  left unset rather than asserting one on a private repo.
- Sampler pins **ModuleBuilder 3.1.8**; do not upgrade it independently.

*Recorded dissent:* external review recommended a hand-rolled InvokeBuild pipeline instead,
on the grounds that Sampler's abstraction cost (Sampler + InvokeBuild + ModuleBuilder + YAML +
imported task defaults) outweighs its benefit for a single module. Sampler was chosen anyway
because GraphKit and IntuneHealthAutomation will share release conventions, which is the
condition under which that review agreed Sampler pays for itself. Revisit if IHA does not adopt it.

```
GraphKit/
  source/
    GraphKit.psd1                    # RequiredModules: Microsoft.Graph.Authentication,
                                     #                  Microsoft.PowerShell.SecretManagement
    Public/
      Register-GraphTenant, Get-GraphTenant, Remove-GraphTenant, Test-GraphTenant
      Get-GraphContext, Use-GraphTenant
      Invoke-GraphOperation, Invoke-GraphBatch
      Get-GraphObject, Get-GraphOperation
      Test-GraphPermission, Get-GraphAppRegistrationPermission,
      Compare-GraphPermission, Grant-GraphAppPermission
      Export-GraphResult
    Private/
      Invoke-GraphRetry, Get-GraphRetryDecision, Get-GraphRetryDelay,
      Resolve-GraphUri, Test-GraphNextLinkAuthority,
      Get-GraphThrottleScope, Write-VaultEvidence
      TokenSources/  ConfidentialClient, ManagedIdentity, Provider, FixedBearer
                     (each implements IGraphTokenSource)
    Data/Operations/*.psd1
    Formats/GraphKit.Format.ps1xml
  tests/Unit, tests/Adapter, tests/Concurrency, tests/QA
  build.yaml, build.ps1, RequiredModules.psd1
  THIRD-PARTY-NOTICES.md
```

**Build note:** ModuleBuilder compiles `Public/` and `Private/` into one `.psm1` under
`output/`. Non-code assets — `Data/Operations/` and `Formats/GraphKit.Format.ps1xml` — are not
compiled and **must** be listed in `build.yaml` under `CopyPaths`, or they vanish from the built
module while looking correct in source. Common first-build failure.

`CopyPaths` only *packages* the format file. `GraphKit.Format.ps1xml` must **also** be registered
via **`FormatsToProcess`** in the manifest, or default views silently never apply. A clean-process
smoke test imports the built manifest from `output/` and asserts both that operation data loads
and that default views are registered — catching the packaging-versus-registration gap that
in-source testing cannot see.

### Profiles and contexts

A mutable "current profile" must not be the sole source of truth — a profile switch in one
runspace would silently retarget work in another.

- **Profile** — persisted non-secret metadata plus SecretManagement references.
- **Context** — an immutable runtime value resolved before asynchronous work. It owns an
  `IGraphTokenSource` reference but never stores a bearer token in the profile metadata.
- **Current context** — an interactive convenience only; it is never consulted by low-level work
  after a context has been resolved.

Formal Context contract:

| Field | Type | Notes |
| --- | --- | --- |
| `ProfileId` | string | Canonical profile identity |
| `TenantId` | GUID | Target tenant, normalized |
| `Cloud` | enum | `Global`, `China`, `Germany`, `USGov`, `USGovDoD` |
| `GraphBaseUri` | URI | Derived only from the cloud table |
| `ClientId` | GUID? | Null for fixed bearer or system-assigned managed identity when no client ID exists |
| `TokenSource` | `IGraphTokenSource` | Per-context source; owns cache/single-flight state |
| `CredentialFingerprint` | string | Non-secret credential-generation identifier, distinct from bearer fingerprint |
| `AcquisitionCacheKey` | string | Canonical tuple key; never caller-supplied |
| `IdentityState` | enum | `VerifiedForToken`, `Unverified`, or `NotAcquired` |

`IdentityState` is a summary only. Authorization decisions use the `GraphTokenResult` returned by
the current acquisition, including its `TokenFingerprint`, `CredentialGeneration`, and
`VerifiedTenantId`; verification is never treated as an immutable context fact.

Every low-level command accepts `-Context` or `-ProfileId`, resolved before entering parallel
work. `-ProfileId` accepts the canonical `ProfileId` only; display `Name` is never a selector.

```powershell
$context = Get-GraphContext -ProfileId ivy24
Get-GraphObject -Context $context -Type ManagedDevice
```

Profile metadata in `~/.graphkit/profiles.json`; secrets are keyed by `GraphKit:<ProfileId>` plus
credential slot/version under `Microsoft.PowerShell.SecretManagement`.

| Field | Notes |
| --- | --- |
| `ProfileId` | **Path-safe canonical identifier** — `^[a-z0-9][a-z0-9-]{0,63}$`. The only value ever used to build a filesystem path or select a profile. |
| `Name` | Display name and, when `Kind = customer`, the vault customer tag. **Never used as a selector or path segment.** |
| `Kind` | `customer` \| `lab` \| `internal` |
| `TenantId`, `ClientId` | Canonical GUIDs; `ClientId` may be null for fixed bearer or system-assigned managed identity. |
| `AuthMethod` | `Certificate` \| `ClientSecret` \| `BearerToken` \| `ManagedIdentity` |
| `Environment` | `Global` \| `China` \| `Germany` \| `USGov` \| `USGovDoD` |
| `Credential` | **Discriminated by `AuthMethod`** — see the persisted shapes below. |

Persisted credential shapes, one schema per `AuthMethod`:

| `AuthMethod` | Persisted |
| --- | --- |
| `ClientSecret` | Vault name, secret name, optional version |
| `Certificate` (PFX) | PFX path + vault-backed password reference |
| `Certificate` (vault material) | Vault name, certificate name, optional version |
| `Certificate` (store) | Store location, store name, lookup by thumbprint or subject — **Windows only, and declared as such** |
| `BearerToken` | Vault reference only |
| `ManagedIdentity` | Client ID for user-assigned, or nothing for system-assigned |

**Injected `X509Certificate2` objects and caller-supplied token providers are context-only and
non-persistable.** They may be passed to `Get-GraphContext` at runtime but never written to
`profiles.json`, and attempting to register one is an error rather than a silent drop.

Thumbprint-only certificate configuration is Windows-specific and must not be the sole supported
shape — the development machine is macOS.

**`Kind` governs taxonomy validation.** Only `Kind = customer` validates `Name` against the CDW
KB `SCHEMA.md` customer tag list. `ivy24` is a lab tenant and must not be a customer tag.

**Certificate material must not be thumbprint-only** — that is Windows-specific. Support at
minimum: an injected `X509Certificate2`, a PFX file with a vault-backed password, vault-backed
certificate material, and Windows cert-store lookup as an optional platform provider.

`Use-GraphTenant` **selects an immutable GraphKit context and nothing else.** There is no
"reconnection", because there is no connection: token acquisition happens per context, on demand,
through that context's own token source. Any `Get-MgContext` check would consult the
process-global SDK identity state this design exists to avoid — a leftover from an earlier draft,
removed here.

### Token sources

A context owns an `IGraphTokenSource`, not a confidential MSAL client directly. The supported
auth modes do not share one acquisition API — managed identity uses
`ManagedIdentityApplicationBuilder` / `AcquireTokenForManagedIdentity`, not
`ConfidentialClientApplicationBuilder` / `AcquireTokenForClient` — and a fixed bearer token cannot
be refreshed at all.

| Member | Contract |
| --- | --- |
| `Acquire(forceRefresh, cancellation)` | Returns a `GraphTokenResult`; `forceRefresh` bypasses the access-token cache for refreshable sources |
| `CanRefresh` | `False` for fixed bearer tokens |
| `AuthMode`, `Audience`, `ClientId`, `ExpiresOn` | Source metadata; `Audience` is the cloud-specific Graph resource with `/.default` for app-only acquisition |
| `VerifiedTenantId` | Tenant proven for the current token, or null; not valid without the current result fingerprint |
| `CredentialGeneration` | Changes whenever the underlying credential, vault version, certificate, or provider generation changes |

The token source is non-owning for caller-injected certificates and providers. GraphKit disposes
only resources it created while resolving persisted credentials.

Separate implementations for confidential-client, managed-identity, provider, and fixed-bearer.
The single `401` force-refresh applies only when `CanRefresh`; a fixed bearer token fails
immediately rather than retrying.

**Bearer tokens must be tenant-bound before they are trusted.** Commercial Graph uses the same
host for every tenant, so authority validation proves nothing about *which* tenant a token
addresses. A Tenant B token attached to a Tenant A profile would succeed against B while every
result, telemetry record, and evidence page was stamped Tenant A — the same silent cross-tenant
contamination the SDK transport was rejected for. Therefore:

- Tenant proof is bound to the **current `GraphTokenResult`**, not merely to the immutable context.
  GraphKit performs the proof call and associates `VerifiedTenantId` with that result's
  `TokenFingerprint` and `CredentialGeneration`. A refresh returning a different token invalidates
  the prior proof before any send.
- The transport acquires or receives the current result immediately before a mutating send and
  requires `GraphTokenResult.VerifiedTenantId == TargetTenantId`; it also requires the same proof
  before stamping target-tenant provenance or writing tenant-scoped evidence. A provider's claim
  that a token is valid is never proof.
- Unverified bearer contexts are rejected for permission mutation and tenant-stamped evidence.
- Unverifiable fixed bearer tokens are restricted to operations explicitly marked read-only and
  unverified; such results carry `IdentityState = Unverified`, `ActualTenantId = $null`, and cannot
  be exported as tenant-attributed evidence.
- **JWT claims are never authoritative identity** — verification comes from a Graph call made with
  the token, not from decoding it.
- Verification is cached only for the exact token fingerprint/generation. A different bearer,
  credential generation, tenant, audience, or cloud invalidates it.

**Migration is a first-class command.** `Register-GraphTenant -FromLegacyConfig` imports IHA's
`config/secrets.json` tenant array and the `Start-WithConsole *.cmd` launchers, moving secrets
into the vault so the plaintext copies can be deleted.

#### Profile store durability

`~/.graphkit/profiles.json` is the index for every tenant this tool can reach. Losing or
corrupting it is not a cosmetic failure, and a half-written file is worse than a missing one.

- **`SchemaVersion` at the root**, with explicit migrations. An older GraphKit reading a newer
  file must refuse with a clear message rather than silently ignoring fields it does not
  understand — dropping an unrecognized `Credential` shape would fall back to the wrong auth mode.
- **Atomic replacement:** write to a temporary file in the same directory, fsync, then rename over
  the original. A partial write during `Register-GraphTenant` must never leave an unparseable
  store.
- **Backup and recovery:** retain the previous generation. If the primary fails to parse, report
  the parse error and the backup's location rather than silently recreating an empty store, which
  would look like "all profiles vanished".
- **Interprocess lock** around read-modify-write. Two `pwsh` sessions registering profiles
  concurrently is ordinary — the unattended lab runner and an interactive session already do it —
  and last-writer-wins would silently discard a registration.

The vault holds the secrets; this file holds everything needed to *find* them. It is not
sensitive, but it is not disposable either.

### Operation catalog — not a type-to-endpoint table

A flat type→endpoint map is sufficient for basic collection reads and **breaks down everywhere
else**: actions, assignments, async report jobs, advanced directory queries, ETags, beta-only
operations, and non-collection responses.

The unit of behavior is **Type + Operation + API version + cloud + auth mode**, not Type.

This example is **normative**: it carries every field the pipeline reads. An earlier draft omitted
`OperationKind`, `HandlerStrategyId`, `CredentialPolicy`, `AllowedHosts`, `ResourceFamily`, and the
throttle class, which meant a loader written from it could not have driven the pipeline that
references them.

```powershell
@{
    SchemaVersion        = 1
    Type                 = 'MobileApp'
    Operation            = 'Assign'
    OperationKind        = 'Action'          # Collection|Singleton|Action|LongRunningJob|Binary|Scalar|NoContent|Delta
    HandlerStrategyId    = 'Action.Default'  # validated strategy id, never a scriptblock
    ApiVersion           = 'v1.0'
    Stability            = 'Stable'          # Stable|DualVersion|BetaPreferred|BetaOnly
    BetaReason           = $null             # required when Stability is BetaPreferred or BetaOnly
    Method               = 'POST'
    PathTemplate         = '/deviceAppManagement/mobileApps/{id}/assign'
    RequestBodyKind      = 'MobileAppAssignmentSet'
    ResponseKind         = 'NoContent'
    PagingStrategy       = 'None'
    RequiredPagingHeaders = @()
    DeduplicationKey     = $null
    SupportsAll          = $false
    SupportsDelta        = $false
    ReplayPolicy         = 'NeverReplay'     # intrinsic - see below
    Condition            = $null             # required for Conditional
    Reconciliation       = $null
    AdvancedQuery        = @{ Supported = $false }
    Concurrency          = @{ Mode = 'None'; Header = $null; Required = $false; AllowWildcard = $false }
    CredentialPolicy     = 'GraphBearer'     # GraphBearer|None
    AllowedHosts         = @()               # required and non-empty when CredentialPolicy = None
    RedirectPolicy       = 'None'            # None|SafeGetOnly
    IdentityRequirement  = 'Verified'        # Verified|AllowUnverifiedRead
    ResourceFamily       = 'Intune.MobileApps'
    ThrottleClass        = 'Write'           # Read|Write
    SupportedAuthModes   = @('Certificate','ClientSecret','ManagedIdentity')
    RequiredPermissions  = @(
        @{ Type = 'Application'; Value = 'DeviceManagementApps.ReadWrite.All' }
    )
    RequiredLicense      = @('Microsoft Intune')
    SupportedClouds      = @('Global','USGov','USGovDoD')
}
```

**Cross-field validation** runs in the loader, not at call time: `CredentialPolicy = None`
requires a non-empty `AllowedHosts` and HTTPS-only production URLs; `BetaPreferred`/`BetaOnly`
require a `BetaReason`; `ReplayPolicy = Reconciliable` requires a `Reconciliation` block;
`ReplayPolicy = Conditional` requires a `Condition` block naming the permitted method,
precondition, and response/transport cases; an `ApiVersion` of `beta` requires a matching
`Stability`. `IdentityRequirement = AllowUnverifiedRead` requires `ThrottleClass = Read`,
`ReplayPolicy = Safe`, `CredentialPolicy = GraphBearer`, and no tenant-attributed evidence.
Descriptors are versioned by `SchemaVersion` so the loader can reject or migrate rather than
silently misread.

`PagingStrategy = NextLink` additionally requires `RequiredPagingHeaders`, `DeduplicationKey`,
`SupportsAll`, and `SupportsDelta`; `Concurrency` always has `Mode`, `Header`, `Required`, and
`AllowWildcard` keys, using null/false values when `Mode = None`. The full field shapes are part
of the schema even when a descriptor does not use them.

#### Handler strategy registry

Strategy IDs follow `<OperationKind>.<StrategyName>`, for example `Collection.Default`,
`Action.Default`, and `LongRunningJob.PollStatus`. The loader resolves every ID against a closed
v1 registry before accepting a descriptor. Strategies are registered by private module code, never
from descriptor files, and receive `($Context, $Descriptor, $Parameters, $Transport)`; a
reconciliation strategy additionally receives `$IntendedState` and may use only the supplied
read delegate. Unknown IDs, wrong operation-kind prefixes, or invalid handler results fail catalog
validation. v1 registers `Collection.Default`, `Action.Default`,
`Reconciliation.StableExternalKey`, and `LongRunningJob.PollStatus`.

The earlier draft stored a single `RetrySafety` value such as `AmbiguousCommit`, which conflated
two different facts and contradicted the retry matrix below. **The same POST is not always
ambiguous.** Rejected cleanly with `429` before execution, it is safe to retry; abandoned after a
socket reset, it may have committed. One static field cannot express both.

- **`ReplayPolicy`** — an intrinsic property of the operation, stored in the descriptor:
  `Safe`, `Conditional`, `Reconciliable`, `NeverReplay`.
- **Attempt certainty** — determined at runtime from what actually happened:
  `Rejected`, `Ambiguous`, `MayHaveCommitted`, `Succeeded`.

The retry decision is a function of both. `Rejected` plus any policy other than `NeverReplay`
retries; `Ambiguous` retries only under `Safe`, reconciles under `Reconciliable`, and otherwise
surfaces `Indeterminate`.

The IntuneManagement type table remains, but only for **discovery and tab completion**. The
operation descriptor governs behavior.

`Get-GraphObject` stays generic for reads. A universal
`Set-GraphObject -Type Anything -Properties …` is explicitly **not** built — that is where the
abstraction starts lying.

#### Where a generic accessor leaks — all handled by descriptor metadata

| Leak | Handling |
| --- | --- |
| **Advanced Entra queries** need `ConsistencyLevel: eventual` *and* `$count=true`, vary by entity/property/operator, and are generally incompatible with `$expand`. In batch, the header belongs on the **subrequest**. | `AdvancedQuery` metadata. **`ConsistencyLevel` must never be a sticky global profile header** — it changes consistency semantics. |
| **Unsupported query options can fail silently** (documented by Microsoft). Directory `$expand` caps at ~20 objects, gives no continuation, and forbids nested filter/select. | Reject query options not known to be supported, rather than passing through optimistically. |
| **Temporary service workarounds** — e.g. the current Entra `$search` workaround requiring `Prefer: legacySearch=false`. | Operation-specific, versioned, contract-tested, easy to remove. Never a default profile header. |
| **API version is per operation** — a resource may have stable reads but beta-only assignment config, with different request models. | See **API version is a fact, not a mode** below. |
| **Assignments are not one model** — app `assign` actions, device-configuration assignment actions, compliance models, beta-only `configureAssignments`, filters, polymorphic targets needing `@odata.type`. | Explicit `AssignmentAction`, `AssignmentBodySchema`, `AssignmentTargetTypes`, `SupportsFilters`, replace/merge semantics. |
| **Reports are async jobs** — POST export job, poll status, retrieve download URL, fetch CSV, handle expiry. | Operation kinds: `Collection`, `Singleton`, `Action`, `LongRunningJob`, `Binary`, `Scalar`, `NoContent`, `Delta`. Do not force everything into `.value`. |
| **A GET body is not a PATCH body** — read-only fields, server-generated timestamps, derived properties, expanded relationships, fields where omitted ≠ null. | Writable-property allow-list, body schema, or transform per writable operation. |
| **ETags / concurrency** — some updates need `If-Match`, others ignore it. A retry must not silently overwrite newer tenant configuration. | `Concurrency = @{ Mode; Header; Required; AllowWildcard }`. |
| **Paging varies by resource** — page sizes differ, zero-item pages occur, not every relationship pages, custom headers must be repeated per page. | `PagingStrategy`, `RequiredPagingHeaders`, `DeduplicationKey`, `SupportsAll`, `SupportsDelta`. |
| **National-cloud availability** is per operation, not inferable from hostname. | `SupportedClouds`; completion hides or marks unsupported operations for the active profile. |
| **`$expand` is a performance trap** — ~1,000 `mobileApps` expanded with assignments exhausted SDK retries where Graph Explorer succeeded. | Query strategy in the descriptor, caller-overridable. Never auto-prefer one-shot `$expand` over paged child reads. |

**Escape hatch:** `Invoke-GraphOperation -Raw` bypasses descriptor validation entirely, so strictness
never blocks expert use.

#### API version is a fact, not a mode

**In Intune, a large and permanent share of production functionality is beta-only** — much of the
settings catalog surface, device preparation policies, driver update profiles, report export
jobs, `configureAssignments`, and much of macOS declarative management. The Intune admin center
itself calls beta. Any design that treats beta as an exceptional opt-in either cannot do real
Intune work or pushes every operator to `-Raw`, which defeats the descriptor.

So version is **not a global mode and not a user decision**. It is a per-operation property that
the descriptor records because it is true:

| `Stability` | Meaning | Version used |
| --- | --- | --- |
| `Stable` | v1.0 exists and is sufficient | `v1.0` |
| `DualVersion` | Both exist and are equivalent for this operation | `v1.0` — beta gains nothing, and can break |
| `BetaPreferred` | Both exist, but v1.0 is missing fields or behavior this operation needs | `beta`, with `BetaReason` recorded |
| `BetaOnly` | No v1.0 equivalent exists | `beta`, without ceremony or warning |

`BetaOnly` operations are used normally. Prompting or warning on them would be noise, since
there is no alternative to choose.

What the design actually guards against is *silently* riding beta where a stable equivalent
exists — which is exactly `MgGraphCommunity`'s model: one global default applied blindly to every
relative URI, including endpoints with a perfectly good v1.0. That is the defect, not beta.

Because beta carries no breaking-change guarantee, `BetaPreferred` and `BetaOnly` operations
additionally require:

- **`BetaReason`** recorded in the descriptor — so a later v1.0 promotion is a findable one-line
  change rather than an archaeology exercise.
- **Response-shape contract tests** pinning the fields the operation actually depends on, so a
  silent beta change surfaces as a test failure rather than as a broken run in a customer tenant.
- **Provenance stamped on returned objects** (`_ApiVersion`), so evidence exports record which
  surface produced a finding.
- **Warn-once per session, not per call**, when an operation is `BetaPreferred` — enough to be
  visible, not enough to be ignored.

### Request pipeline

`Invoke-GraphOperation` issues requests through a GraphKit-owned `HttpClient` using a token from
the context's `IGraphTokenSource`. **GraphKit is the sole retry owner** — there is no underlying
handler that can retry behind its back, which is what makes the replay guarantees below
enforceable rather than aspirational.

The command is named Invoke-GraphOperation, not Invoke-GraphRequest: Microsoft.Graph.Authentication,
a required module, already exports a cmdlet named Invoke-GraphRequest, and exporting the same name
would collide in every session.

A contract test asserts that **one GraphKit attempt produces exactly one physical send**.

#### The credential boundary is non-bypassable

Bearer tokens are attached by the transport, and **nothing in the pipeline can opt out of the
check** — including `-Raw`. Descriptor validation is bypassable; credential policy is not.

| Policy | Meaning |
| --- | --- |
| `GraphBearer` | Attach the current result's Graph token. Requires HTTPS and an exact match against the cloud-specific Graph authority for that context. |
| `None` | Send with no credential. Used for report downloads and any other external transfer; production URLs still require HTTPS. |

Rules:

- **`-Raw` keeps authority and credential-forwarding checks.** It bypasses descriptor and query
  validation only. An absolute URI supplied by a caller is untrusted input.
- **`@odata.nextLink` is opaque but not trusted** — validate scheme and authority before
  attaching a token.
- **Report download URLs are `None`.** Intune export jobs return SAS-signed Azure blob URLs on a
  non-Graph host. Sending them a Graph bearer token would leak it to storage; they carry their own
  signed authorization. Hosts are allowlisted per operation and must be HTTPS.
- **Redirects are disabled by default.** In v1, only `SafeGetOnly` operations may follow validated
  redirects, including credential-free downloads. Mutating methods never follow a redirect with a
  second physical send; they surface the redirect as a non-success result. Every followed hop must
  remain HTTPS, satisfy the policy, and stay within the descriptor allowlist.
- **Query strings are stripped from telemetry by default.** SAS URLs carry their signature in the
  query; logging it would persist a live credential into evidence output. Only parameter names and
  explicitly value-safe OData values are retained. `$filter`, `$search`, and caller-provided values
  are redacted.

A failure here is a hard error naming the offending authority — never a silent downgrade to an
unauthenticated request, and never a silent send.

#### Retry must be semantics-aware, not status-code-driven

**A status code alone is not sufficient to decide a retry.** The decision requires the HTTP
method, the operation's semantics, and whether the previous attempt may have committed.

**A 2xx response can carry `Retry-After`.** A production report against `sendMail` documented
`202 Accepted` *with* `Retry-After`; a client that retried on the header's presence sent
duplicate mail. Therefore:

```
Retry-After present + 2xx
    => accept success
    => update future throttle pacing
    => NEVER replay
```

`Get-GraphRetryDelay` computes a delay only *after* `Get-GraphRetryDecision` has permitted a
retry. It must never itself decide whether to retry.

**A failure response does not prove the write failed.** Microsoft's known-issues list currently
includes an operation returning `503` even though the object was created — repeating it then
yields `409 Conflict`.

This is why replay policy and attempt certainty are **two separate axes**, as defined in the
operation catalog above. The earlier draft listed both on one `RetrySafety` enum, which mixed a
fixed property of the operation with a fact discovered at runtime.

`ReplayPolicy` — intrinsic, stored in the descriptor:

| Policy | Typical operations | Meaning |
| --- | --- | --- |
| `Safe` | GET, HEAD | Replaying cannot change state |
| `Conditional` | PUT to a stable URI, DELETE, selected PATCH | Replayable only where the descriptor says so |
| `Reconciliable` | Create with a stable external key and a reliable lookup | Query for the intended result, then decide |
| `NeverReplay` | send, retire, wipe, sync, rotate | Never replay; surface the outcome |

Attempt certainty — determined at runtime:

| Certainty | Arises from |
| --- | --- |
| `Succeeded` | A 2xx response was received |
| `Rejected` | The service refused before executing, e.g. a clean `429` |
| `Ambiguous` | Timeout, connection reset, or 502/503/504 with no response body |
| `MayHaveCommitted` | Ambiguous, and a subsequent probe found evidence of partial effect |

The decision is a function of the pair. `Rejected` retries under any policy but `NeverReplay`.
`Ambiguous` retries only under `Safe`, reconciles under `Reconciliable`, and otherwise returns
`Failed` + `Indeterminate` without a replay.

Default matrix:

| Condition | GET/HEAD | PUT/DELETE | POST/PATCH/action |
| --- | --- | --- | --- |
| 429 with usable delay | Yes | Descriptor | Yes (Graph rejected it) |
| 408 / network timeout | Yes | Descriptor | **No** — commit unknown |
| 500/502/503/504 | Yes | Descriptor | **No** by default |
| 409 | No | Known transient inner errors only | Known transient inner errors only |
| 401 | Reacquire once | Same | Same |
| 403 / 404 | No | No | No |
| 2xx + `Retry-After` | Success; pace later | Success; pace later | Success; **never replay** |

A `401` triggers at most **one** forced token acquisition and one replay. A second `401` is an
audience, tenant, claims, or policy problem — not an invitation to loop.

For Intune imports, app assignments, policy creation, device actions, and Autopilot operations, a
blanket "retry all 503s" rule is unsafe.

#### `Retry-After` parsing is hostile

Graph has been observed returning malformed values such as `Retry-After: 30,120` (reported 2025
and again May 2026), which broke SDK parsers expecting a single integer. The parser must:

1. Handle multiple header values supplied as a collection.
2. Try the whole value as delta-seconds.
3. Try the whole value as an HTTP date.
4. *Only then* consider a malformed comma-separated numeric list.
5. Parse `x-ms-retry-after-ms` separately.
6. Choose a conservative valid delay (maximum is reasonable policy).
7. Clamp negative and excessive values, and record that the header was malformed.

**Never split on commas before attempting an HTTP-date parse** — valid HTTP dates contain a
comma (`Wed, 21 Oct 2015 07:28:00 GMT`).

For HTTP-date delays, compute against the response `Date` header when present. Workstation clock
skew must not shorten a server-directed delay.

Some resources return **no** retry header at all on 429, so jittered exponential backoff is a
required path, not a rare fallback. Throttling limits cannot be raised by request; for genuinely
bulk extraction the documented answer is Graph Data Connect, out of scope here.

#### Throttle state must be scoped, not global

Graph enforces overlapping service, tenant, application, tenant+application, operation, and
request-type limits, and writes are more constrained than reads. One process-wide backoff timestamp
is wrong. GraphKit uses a hierarchy:

1. **Coarse gate:** `Cloud | TenantId | ClientId | Read|Write`, coordinating limits shared across
   resource families.
2. **Leaf gate:** `Cloud | TenantId | ClientId | ResourceFamily | Read|Write`, coordinating tighter
   family limits.

Every request consults both and waits for the strictest active cooldown/admission limit. An
unqualified `429` or `503` updates the coarse gate; reliable response metadata may additionally
update a leaf gate. Tenant B remains independent of Tenant A, while two families sharing a Tenant A
client gate pause together. This is an engineering approximation of Microsoft's overlapping quota
dimensions and remains tunable.

```
Cloud | TenantId | ClientId | Read|Write
Cloud | TenantId | ClientId | ResourceFamily | Read|Write
```

Token acquisition has a separate authority/resource/auth-mode gate. Cross-process fairness remains
out of scope; the v1 tests cover both cross-tenant isolation and shared coarse-gate coordination.

**Token acquisition gets its own throttle scope.** Repeated token requests are themselves
throttled; Microsoft describes "loop detected" errors as the symptom.

#### Backoff alone oscillates — add admission control

Ten runspaces can each take a 429, sleep the same interval, wake together, and cause the next
throttle wave. Jitter softens this; it does not solve it. Add a **scoped concurrency gate with
additive-increase/multiplicative-decrease**: start conservative, cut permitted concurrency
sharply on 429/503, honor the server delay, restore gradually on success, keep separate read and
write windows, and never hard-code an observed requests-per-second as a universal limit.
(`mgx` is the current prior art worth studying here.)

**Documented coordination boundary:** runspace-shared state does not coordinate a second `pwsh`
process, another console, a CI job using the same app registration, or another consultant's
machine. Acceptable for v1 — but the module must not imply it enforces tenant-wide fairness.

#### Paging is reliability, not response parsing

- Treat `@odata.nextLink` as **opaque**, and **validate its scheme and expected Graph authority
  before attaching an `Authorization` header** (`Test-GraphNextLinkAuthority`) — a redirected or
  hostile link would otherwise receive a bearer token.
- Accept an empty page that still carries a `nextLink`.
- **Repeat required custom headers on every page** — Microsoft warns `ConsistencyLevel` is not
  carried forward automatically.
- Do not expect `@odata.count` after page one.
- Keep the last successfully consumed link separate from a retry response — Microsoft documents a
  `DirectoryPageTokenNotFoundException` case where a token returned by a retry must not be used
  as the continuation point.
- Optional dedup by stable ID. Microsoft currently documents a service issue (through
  2026-08-31) where a page returns 200, an empty collection, and a `nextLink` that restarts
  pagination with duplicates. That issue is meeting-artifact APIs, not Intune, but it disproves
  "empty means done" and "Graph never duplicates pages" as safe generic assumptions.

#### Batch needs its own state machine

Each subrequest carries its own status, headers, body, and operation ID. Handle failed
dependencies (`424`), preserve the dependency graph, retry only failed retryable subrequests,
select the longest applicable delay for the retry set, **never replay successful write
subrequests**, and never replay a whole batch after an ambiguous transport failure unless every
subrequest is `Safe`.

**v1 batch support is read-only by default.** Write batching requires operation descriptors
proving replay or reconciliation behavior.

#### Deadlines and evidence

Every operation carries a maximum attempt count, **maximum total elapsed time**, per-attempt
connection/header/body timeouts, cancellation support, and a maximum accepted server delay —
returning a structured result including an explicit "deadline expired while throttled" outcome
rather than throwing "maximum retries exceeded".

Per attempt, capture for support cases: logical operation ID, client request ID, response request
ID, response `Date`, `x-ms-ags-diagnostic`, verified tenant and profile ID (**never secrets or
bearer tokens**), endpoint family, sanitized URI, attempt number, status and a structurally
allowlisted Graph error code/inner-error chain, calculated delay and its source, current concurrency
limit, batch subrequest ID, and whether the final state is known, failed, or indeterminate.
Sanitize query values and free-form error messages before constructing telemetry; JSON export
preserves only this sanitized telemetry. Telemetry is a first-class result object, not verbose text.

### One canonical result contract

Structured outcomes and plain data rows are two different things, and mixing them on one stream
corrupts both: an ambiguous POST has **no data row** but must still carry `Indeterminate`, while
unwrapping envelopes into rows loses reliability state entirely.

There is exactly one envelope, `GraphKit.OperationResult`:

| Field | |
| --- | --- |
| `Data` | Result rows, or empty |
| `Outcome` | `Succeeded` \| `Failed` \| `DeadlineExpired` \| `Cancelled` |
| `Certainty` | `Known` \| `Indeterminate` — an ambiguous write is `Failed` + `Indeterminate` |
| `Telemetry` | Per-attempt evidence, as above |
| `Provenance` | Tenant, API version, endpoint family, retrieval time, `IdentityState`, and `ActualTenantId` when verified |

- `Invoke-GraphOperation` **always** returns exactly one envelope.
- **`Invoke-GraphBatch` returns one ordered envelope per original subrequest**, not one envelope
  for the batch. A batch routinely mixes outcomes — some subrequests succeed, some are throttled
  and retried, some fail, and a write that timed out is indeterminate. A single `Outcome` and
  `Certainty` cannot represent that, and collapsing it would either hide failures behind an
  overall success or discard the certainty of the writes that did land. Order matches the
  submitted order, and each envelope carries the subrequest's own telemetry including its
  `id`. Dependency failures (`424`) are reported against the dependent subrequest, with the
  blocking `id` recorded.
- `Get-GraphObject` projects `Data` onto the success stream for pipeline ergonomics, and **throws
  on any non-`Succeeded` outcome** so a failure can never be mistaken for an empty result. The
  envelope is available via `-PassThruResult`.
- `-PassThruResult` is an **envelope-only output mode**, not an addition to the success stream.
  Emitting rows and envelopes together would make the output shape depend on a switch, and any
  downstream `Where-Object` would then see two unrelated object types.
- `Export-GraphResult` accepts **either**, unwrapping envelopes itself. It refuses to export an
  `Indeterminate` result without `-Force`, because filing an uncertain write as evidence is
  exactly the error the certainty field exists to prevent.
- `-As Json` preserves the **full envelope** — outcome, certainty, telemetry, provenance — not
  just `Data`. Json is the format used for machine hand-off and for attaching to a support case,
  which is precisely where certainty and the diagnostic chain matter. CSV and Markdown are
  row-shaped and export `Data` only.

### Permission analysis

The common conceptual error is treating `requiredResourceAccess` as the application's
permissions. It is only what the *registration requests*. It proves neither consent nor grant.

**The subject of analysis is not the analyzer.** The app registration being examined is a
`TargetAppId` in a named customer tenant, modelled separately from the profile doing the
examining, along with its home tenant and the expected operation baseline. Conflating them is
what produces the bootstrap trap below.

`Grant-GraphAppPermission` declares `SupportsShouldProcess`, names its target tenant and
application explicitly, and is **idempotent** — it computes and applies a diff, so re-running
grants nothing already present.

Four distinct states:

1. **Configured** — `application.requiredResourceAccess` on the home application object.
2. **Application permissions granted** — locate the customer-tenant service principal by `appId`,
   inspect its app-role assignments against the Microsoft Graph service principal, resolving
   `appRoleAssignment.appRoleId` against `graphServicePrincipal.appRoles`.

**States 1 and 2 live in different tenants and need different authenticated contexts.** The
application object exists only in its home tenant; the service principal and its grants exist in
the customer tenant. A single context cannot read both for a multi-tenant app.

`Configured` is therefore tri-state: `Yes`, `No`, or **`Unknown`** when no home-tenant context is
available. Reporting `Configured = No` because the analyzer simply could not look would invert the
most consequential finding — "granted but no longer configured" and "never configured" are
opposite conclusions, and the second is what an operator acts on.
3. **Delegated grants** — `oauth2PermissionGrants`, resolving space-delimited scopes, consent
   type, principal, client and resource service principals. Separate from app-role assignments.
4. **Runtime effectiveness** — may still fail on Intune licensing, Intune RBAC scope, Entra role
   requirements, endpoint/cloud restrictions, beta availability, tenant policy, or rollout.

**A Graph permission is necessary but not sufficient.** Do not emit a single `Effective = True`.
Emit separate findings: `Configured`, `Granted`, `ExcessGranted`, `MissingGrant`,
`AuthenticationCompatible`, `RuntimePrerequisitesKnown`, `RuntimePrerequisitesSatisfied`,
`TestedSuccessfully`.

Useful findings: configured but not granted; granted but no longer configured; grant exceeds the
operation catalog; delegated grant present but profile is app-only; required operation is
beta-only; application exists only in the home tenant while the customer service principal is
missing.

**Do not treat the access token's `roles` / `scp` claims as the source of truth.** Microsoft
states Graph access tokens are resource-owned and clients must not depend on their internal
format. Token claims are optional diagnostic evidence, not the authorization inventory.

`Get-GraphTokenPermission` is therefore **not** part of the public surface. Claim inspection
survives only as an internal diagnostic helper, and its output is labelled as evidence rather
than as a grant.

**Accepted consequences of this choice** — deliberate, since correct beats fast here:

1. **Analysis costs directory round-trips**, not a free local JWT decode: resolve the customer
   service principal by `appId`, read its `appRoleAssignments`, and resolve each `appRoleId`
   against the Microsoft Graph service principal's `appRoles`. Those calls are themselves subject
   to throttling and must go through the normal request pipeline, not around it.
2. **The analyzer needs its own permissions, which creates a bootstrap problem.** Reading
   service-principal role assignments requires `Application.Read.All` or `Directory.Read.All` in
   the customer tenant. An app registration that lacks them **cannot analyze itself** — the very
   situation where an operator most wants an answer. This must fail with a specific, actionable
   error naming the missing permission and the fact that it is the analyzer's own prerequisite,
   never a bare 403, and never a silent fallback to reading the token's claims. A documented
   escape is to run the analysis under a separate read-only app registration.
3. **Graph service-principal `appRoles` should be cached per tenant for the session.** It is
   large, effectively static within a run, and resolving it once per assignment would be the
   dominant cost. This is a session-scoped read cache, unrelated to the credential cache.

### Output and evidence export

Results are `PSCustomObject` with `PSTypeName` `GraphKit.<Type>` plus `_Tenant`,
`_RetrievedUtc`, `_GraphPath`, and beta provenance where applicable.
`Formats/GraphKit.Format.ps1xml` supplies default table views.

`Export-GraphResult -As Csv | Json | Markdown | VaultEvidence`.

`VaultEvidence` must obey `SCHEMA.md`, which requires evidence pages to be summaries with
pointers to source paths, never raw exports, credentials, or PII:

1. Raw rows → `~/repo/report-exports/<ProfileId>/` — **outside the vault**.
2. Summary page → `cdw-kb/evidence/<ProfileId>/` — rollups and counts only, `sources:` pointing at
   (1), ≥2 wikilinks, correct frontmatter.
3. `customers:` is `[<Name>]` for `Kind = customer`, `[]` for lab and internal. This is the
   display name and vault tag, not the path identifier.
4. `log.md` appended, `index.md` updated.
5. **Path containment is verified, not assumed.** Only `ProfileId` builds paths, and both output
   roots are canonicalized and asserted to remain beneath their configured base before any write.
   A `Name` is free text and would otherwise let `../` or a separator escape the root.
6. **Vault evidence is built from an allowlist, not filtered by a denylist.** An earlier draft
   asserted that tenantId, clientId, secrets, and bearer tokens were absent — four known-bad
   values. That is a denylist, and it cannot catch what it was not told about: user principal
   names, device names, serial numbers, IMEIs, IP addresses, email addresses, and group
   memberships all flow through Intune results and none of them appear on that list.
   `SCHEMA.md` forbids PII in evidence pages generally, not four specific fields.

   The page is therefore constructed from a **summary DTO with a declared field set**. Raw Graph
   objects never reach the writer. Any field not on the allowlist is rejected rather than
   dropped, so a new Graph property cannot silently appear in evidence. The credential assertion
   remains as a second, independent check — belt and braces, not the primary control.

## Versions

| | |
| --- | --- |
| Manifest floor | **PowerShell 7.4** — a customer-compatibility promise, and the minimum Pester 6 supports |
| Primary development and release target | **PowerShell 7.6** |
| Test matrix | 7.4 **and** 7.6, on Windows / Ubuntu / macOS |
| Test framework | **Pester 6.1.0** (released 2026-08-11) |
| Build | **Sampler 0.120.1**, ModuleBuilder held at 3.1.8 |
| Runtime dependencies | **`Microsoft.Graph.Authentication`** (pinned minimum; MSAL delivery only, `Connect-MgGraph` never called) and **`Microsoft.PowerShell.SecretManagement`** (required for every persisted credential) |
| Operational prerequisite | A **registered SecretManagement vault extension**, validated lazily — see below. |

**Vault validation must not run at module import.** An earlier draft failed import when no vault
extension was registered, which would break managed identity, injected credentials, `Get-Help`,
operation-catalog inspection, and every CI job — none of which touch a persisted credential.
Validate only when actually resolving or mutating a vault-backed credential, and fail there with
an actionable message.

**PowerShell 7.4 is a compatibility floor, not a strategic target — it reaches end of support on
2026-11-10, 88 days from this spec.** PowerShell 7.5 reaches EOL the *same day*, so moving 7.4 →
7.5 buys nothing. **7.6 is the current LTS** (released 2026-03-18, .NET 10, supported to
2028-11-14). The local development machine runs 7.5.4 and should move to 7.6.

Raising the floor to 7.6 is a planned follow-up once customer environments allow.

## Testing

Pester 6.1.0. Tests are **committed** — zero tracked test files behind a green CI badge is itself
a defect, and IHA currently has exactly that.

### Do not unit-test the retry engine by mocking HTTP

Mocking the HTTP cmdlet or `HttpClient` directly couples tests to PowerShell's exception shape, `ErrorRecord`
internals, HTTP cmdlet parsing, and version-specific response objects. Normalize HTTP into an
internal contract first:

```powershell
class GraphTransportResult {
    [int]       $StatusCode
    [hashtable] $Headers
    [object]    $Body
    [string]    $RequestId
    [object]    $TransportException
    [bool]      $ResponseReceived
}
```

Inject four dependencies — `Send`, `UtcNow`, `Delay`, `Jitter`. In unit tests `Send` dequeues
scripted results, `UtcNow` reads a **virtual clock**, `Delay` advances that clock immediately,
and `Jitter` is deterministic. A five-minute retry scenario then runs in milliseconds while
asserting attempt counts, exact requested delays, delay-source precedence, deadline termination,
cancellation, resulting throttle state, no replay after 202, no replay of ambiguous POST, one
refresh after 401, and correct batch-subrequest selection.

### The real sender must be tested, not only the injected one

Injecting `Send` makes retry logic deterministic, but **those tests pass whether or not the actual
`HttpClient` behaves.** A sender that silently follows redirects, forwards `Authorization` to a
redirect target, ignores the split timeouts, or has a retrying handler installed underneath would
satisfy every unit test in the suite. The properties GraphKit promises about the *wire* have to be
asserted on the wire.

Adapter tests convert real responses into `GraphTransportResult`: normal JSON, 204 with no body,
binary, 429 in each `Retry-After` form, malformed `Retry-After`, a 200 batch envelope containing
inner 429s, 202 + `Retry-After`, 503 with a JSON error, HTML/plain-text gateway failures,
connection reset, and header casing.

**Loopback tests run through the built sender** — the same object the module ships, not a stand-in
— and assert:

| Property | Assertion |
| --- | --- |
| Redirects | Disabled, or every hop validated before credentials are forwarded |
| `GraphBearer` | Attaches only to the exact cloud-specific Graph authority for that context |
| `None` | **Never** carries an `Authorization` header — the report-download path |
| Timeouts | Connection, header, and body boundaries each fire independently |
| Cancellation | A cancelled token actually aborts an in-flight request |
| Send count | **One GraphKit attempt equals exactly one handler send** — proves no hidden retry handler |
| Telemetry | Query strings absent by default; a SAS-style signature never recorded |

A loopback server also covers what a mock cannot reproduce: duplicate headers, content encoding,
empty bodies, malformed header values, and mid-response connection closure.

### Token isolation must be tested across contexts

The authentication gate proves one Ivy24 acquisition. That does not prove isolation, which is the
entire reason the SDK transport was rejected. Required:

- Two contexts for **different tenants**, used concurrently, each receiving only its own token.
- Concurrent acquisitions for the **same** cache key collapse to a single token-endpoint call
  (single-flight), asserted by counting calls against a stub authority.
- A `401` force-refresh on one context does **not** invalidate or refresh another's token.
- A fixed bearer source reports `CanRefresh = false` and fails immediately on `401` rather than
  retrying.

### Concurrency tests need real runspaces

Mocks are not a substitute. A dedicated harness creates a genuine shared thread-safe throttle
object, starts several runspaces with a controlled transport, releases them through barriers, and
verifies that only the intended number proceed, that all observe the scoped cooldown, and that
**Tenant B stays unblocked while Tenant A is throttled**. These run serially at the Pester level;
the test owns its own concurrency.

### Pester 6 specifics

- **Filtered mocks no longer fall through** — the dominant break found in the Pester team's
  15-repo migration pilot. **Always register an explicit default mock that throws**
  (`throw "Unexpected live HTTP call: $Uri"`) before adding filtered behaviors.
- `Assert-MockCalled` / `Assert-VerifiableMock` removed; use `Should-Invoke` / `Should-NotInvoke`.
  Mocking a dependency module's command requires `-ModuleName GraphKit`.
- `Run.FailOnNullOrEmptyForEach` defaults on — a descriptor table that failed to load throws
  rather than silently passing zero tests.
- Discovery is per-file; each file imports GraphKit in its own `BeforeAll`.
- `-Focus` and `Set-ItResult -Pending` removed; duplicate `BeforeAll` in a block now throws.
- Use the dash-style assertions with `Should.DisableV5 = $true` to prevent drift.
- **Avoid experimental global mocks and Pester parallelism** for stateful retry/cache tests.
- PowerShell classes are awkward to redefine in-process, which can leave stale types across local
  runs. Prefer `PSCustomObject` records, a small compiled type, or fresh `pwsh` processes for
  class-focused tests. Do not create many public classes for internal tidiness.

### CI must gate on the whole Pester result

**Not `FailedCount -eq 0`.** A discovery or container failure prevents tests from running without
looking like a failed assertion — which is precisely how IHA's CI stayed green with zero tests.
Gate on: overall result, failed containers, discovery errors, total test count, an **expected
minimum count**, and failed tests.

Publishing runs once from a tested package artifact; the publish job must not rebuild
independently.

**Each matrix row installs and asserts its exact PowerShell version** rather than trusting the
runner image. A row labelled 7.4 that silently ran 7.6 would report coverage the module does not
have — and 7.4 is the declared floor, so it is the row most likely to drift.

### Build and delivery commands

The scaffold committed 2026-08-15 defines these canonical commands; CI and local verification
must call the same entry points:

| Step | Command |
| --- | --- |
| Resolve build dependencies | `./build.ps1 -ResolveDependency -Tasks noop` |
| Build | `./build.ps1 -Tasks build` (Clean, `Build_Module_ModuleBuilder`, changelog release output) |
| Deterministic tests | `./build.ps1 -Tasks test` (`Pester_Tests_Stop_On_Fail` + coverage threshold) |
| Package | `./build.ps1 -Tasks pack` (build, then `package_module_nupkg`) |
| Phase 1.1 gate | `Invoke-Pester ./tests/QA/BuiltModule.tests.ps1` against the built module in a clean `pwsh` |
| CBA script tests | `Invoke-Pester ./tests/New-ClientServicePrincipalCBA.Tests.ps1 -Output Detailed` |

The remaining delivery gates are contracts for later phases, not runnable yet:

| Gate requirement | Required contract |
| --- | --- |
| Clean install | Install GraphKit and its exact runtime dependencies into an isolated module path; file repositories do not resolve dependency metadata |
| Installed-package smoke | Fresh `pwsh` asserts exact PowerShell version, imports the installed package, and verifies operation data and default views |
| Protected live contract | A committed protected workflow/task accepts the tested package digest, installs that exact digest, performs read/mutation/cleanup, and gates promotion |
| Publication | Promote the tested `.nupkg` bytes with the package-file parameter supported by the selected PSResourceGet version; verify the published hash |
| IHA pinning | Install the exact GraphKit version on every execution host before repointing callers; use `RequiredVersion`, not a minimum |

**Gates test the installed package, never loose `output/` files.** A module that imports from
`output/` can still fail once packaged — missing `CopyPaths` assets and unregistered
`FormatsToProcess` are precisely the failures that only appear after install.

The private channel needs to be decided before the cutover gate, not during it: repository URI and
authentication, version source (GitVersion via Sampler), retention, and an integrity check —
publish the exact tested bytes and verify the installed package hash matches what CI tested.
**`RequiredVersion`, not `ModuleVersion`**, in IHA's manifest: a minimum-version pin would let an
untested GraphKit satisfy it.

## Phases

Two sequencing errors in the previous draft are corrected here. **Descriptors came after the code
that consumes them** — retry safety, throttle family, API version, response shape, permissions,
and cloud support all live in descriptor metadata, so building Core and Permissions first would
have required temporary switches and hard-coded behavior, later thrown away. And **"proven
against Ivy24" is not an executable acceptance criterion.**

Descriptors are **versioned, data-only `.psd1`** files. Behavioral fields such as reconciliation
or body transforms reference *validated strategy IDs*, never executable scriptblocks — a data
file that can execute is a code file with extra steps, and it would defeat the loader's
validation.

Core is split into independently gated increments. Each needs an exact command, an expected
artifact, and an observable pass condition before the next begins.

**1. Core**

| # | Increment | Gate |
| --- | --- | --- |
| 1.1 | Sampler scaffold and packaging | **Complete 2026-08-15** — committed scaffold plus `tests/QA/BuiltModule.tests.ps1`, which imports the built package in a clean `pwsh` and asserts views, CopyPaths assets, and dependency declarations |
| 1.2 | Descriptor schema, loader, validator, strategy registry, minimal Ivy24 descriptors | **Complete 2026-08-15** — invalid descriptors rejected with actionable errors; cross-field rules enforced; catalog round-trips |
| 1.3 | Immutable context and `IGraphTokenSource` interfaces | **Complete 2026-08-15** — contexts resolve without any network call; token-source contract covers all four auth modes |
| 1.4 | Normalized transport (`GraphTransportResult`), deadlines, retry engine | **Complete 2026-08-15** — deterministic virtual-clock + loopback tests: exact delays, delay-source precedence, no replay after 202, no replay of ambiguous POST, one GraphKit attempt equals one physical send |
| 1.5 | Paging and URI security | **Complete 2026-08-15** — authority validation active under `-Raw`; redirects disabled or per-hop validated; `None` policy never carries authorization; query stripped from telemetry |
| 1.6 | Authentication and vault providers | **Complete 2026-08-15** (deterministic parts) — vault credential resolution for all persisted shapes, tenant-proof binding cached per token fingerprint/generation, single-flight acquisition, MSAL import guard, import-order matrix; the live vault-backed Ivy24 acquisition runs in the protected environment only |
| 1.7 | Scoped throttle state and AIMD admission control | **Complete 2026-08-15** — real-runspace tests: Tenant B unblocked while Tenant A throttled |
| 1.8 | Protected Ivy24 smoke workflow | **Committed 2026-08-15** — `scripts/Invoke-GraphKitSmoke.ps1`: digest-bound, read + mutation + finally-guaranteed cleanup, `-DryRun` stub mode; live execution requires the protected environment and is not part of deterministic CI |

**Ordering rationale.** The previous sequence contradicted its own rule that contracts precede
consumers: retry (then 1.2) came before descriptors (1.3) although retry safety is descriptor
metadata, URI and cloud policy came before contexts, and gate 1.1 asserted operation data loads
before a loader existed. Descriptors and context/token contracts now come first, and every gate
tests the **installed package**, not loose files in `output/`.

**2. Operations.** **Complete 2026-08-15** — six-descriptor catalog, `Get-GraphObject` with provenance stamping, tab completion, per-type format views.

**3. Permissions.** **Complete 2026-08-15** — four-state analysis with tri-state `Configured`, bootstrap-trap error, session-scoped appRoles cache, idempotent `Grant-GraphAppPermission`.

**4. Export.** **Complete 2026-08-15** — `Export-GraphResult` (Csv/Json/Markdown/VaultEvidence), envelope-preserving Json, `-Force`-gated indeterminate export, summary-DTO allowlist evidence, verified path containment.

**5. Cutover and secret retirement — one reversible, overlapping gate.**

An earlier draft rotated the exposed secrets before repointing IntuneHealthAutomation, invalidating
credentials still in use by the `Start-WithConsole` launchers and IHA's duplicated authentication
layer. The corrected order keeps every caller working at every step and can be rolled back:

1. Inventory legacy callers — the launchers, IHA's authentication layer, any script holding a copy.
2. Import profiles into SecretManagement (strict data-only parsing of the legacy files, dry-run
   inventory, then transactional import) and verify each profile connects.
3. Publish GraphKit to a **private, versioned package channel** and pin it. Gallery publication
   stays out of scope, but the channel must exist before anything depends on it.
4. Register the private repository and install the exact GraphKit version and runtime dependencies
   on every IHA execution host; run the installed-package smoke before any caller changes.
5. Repoint each caller while **keeping the previous IHA path and package pin intact**. Record the
   previous module pin and caller wiring so one command can restore them until the rollback window
   closes.
6. Verify reads, then controlled writes, through the repointed callers.
7. Create a **second credential without revoking the first**, store it in a new immutable vault
   slot/version, and update profile references atomically. Verify every caller identifies the new
   credential generation while the old one remains valid.
8. Revoke the old credential only after the new generation is proven. Remove the plaintext sources
   with explicit operator confirmation, delete the `bearerTokens` example from
   `secrets.example.json`, reverify, then close the rollback window and delete the old IHA layer.

If any verification fails, stop and restore the previous pin/caller/vault reference. What is not
acceptable is revoking a credential or deleting a caller path while any working caller still
depends on it.

Caching remains in IntuneHealthAutomation throughout.

### CI separation

Deterministic tests (unit, adapter, concurrency, QA) run on every push across the OS and
PowerShell matrix. **Live Ivy24 contract tests run only in a protected environment**, never on
pull requests from forks, and are the only tests permitted to touch a real tenant.

### Portability constraint

CDW taxonomy validation and vault paths sit behind an **injectable adapter**. Hard-coding
`~/Documents/Obsidian Vault` or the `SCHEMA.md` customer list into Core would make GraphKit
unable to run on CI or on any other workstation. The default implementation reads the real vault;
tests and CI inject a stub.

## Out of scope for v1

- Interactive and device-code authentication. If added later, use **MSAL.NET directly** as the
  auth component while keeping requests raw REST — do not hand-build delegated caches, rotating
  refresh tokens, CAE capability declaration, or claims-challenge machinery, and do not adopt the
  Graph workload SDK to get them.
- Delegated refresh-token persistence and CAE claims-challenge implementation.
- Universal generic create/update/delete.
- A global beta mode. Version is per-operation; see "API version is a fact, not a mode."
- Blind POST/PATCH replay on 5xx or network errors.
- **Persistent app access-token cache.** The source credential is already in SecretManagement,
  access tokens are short-lived, and persistence adds theft and stale-cache risk for no gain.
  In-memory only.
- Cross-process throttle coordination.
- High-level cross-tenant comparison and orchestration commands. Simultaneous low-level contexts
  for different tenants are supported in v1 and are covered by token-isolation and throttle tests;
  they are not a v1 exclusion.
- **`GraphKit.Auth`**, the compiled MSAL adapter with an isolated `AssemblyLoadContext`. It is the
  recorded end-state authentication boundary, deliberately deferred: v1 consumes MSAL transitively
  through `Microsoft.Graph.Authentication` as an accepted compatibility constraint, guarded by the
  import-order matrix. `IGraphTokenSource` exists so the eventual swap is an implementation
  change rather than an interface change.
- Porting all ~175 scripts. Phase 1 validates the module against Ivy24; it does not migrate a
  backlog. Existing scripts are catalogued as `type: script` vault pages and ported when next
  touched.
- The vendored IntuneManagement trees; only the type table is lifted.
- Extracting IHA's caching layer.
- PowerShell Gallery publication.
