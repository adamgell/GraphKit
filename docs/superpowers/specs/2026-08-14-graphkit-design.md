# GraphKit — Design

- **Date:** 2026-08-14
- **Status:** Approved for planning
- **Author:** Adam Gell

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

Given the decision below to delegate authentication to the Graph SDK, the 61 `Connect-MgGraph`
files are already aligned with the target and need the least porting. The 44 raw
`client_credentials` scripts are the ones that change.

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

Already implements roughly 70% of the intended core. It is a PowerShell module
(`src/healthcheck.psd1` v0.2.0) with:

- Multi-tenant configuration, per-tenant output directories, tenant management menu
- Certificate-based authentication (`Get-CBAToken`), bearer token, and MgGraph SDK paths
- `Invoke-IntuneGraphRequest` (594 lines): `@odata.nextLink` paging, `$batch`, proactive
  token-expiry detection; plus `Invoke-ParallelGraphRequest` (318 lines)
- 17 JSON report definitions governed by a JSON schema, with VS Code templates
- API response caching, endpoint caching, and checkpoint/resume for large collections

**Gaps identified:**

1. **No throttling handling.** `Invoke-IntuneGraphRequest` contains zero references to
   `429`, `503`, `Retry-After`, `TooManyRequests`, or backoff. The parallel request path
   makes throttling more likely, not less.
2. **No tests.** `.github/workflows/pester-tests.yml` runs on every push, but zero
   `*.Tests.ps1` files are tracked. CI passes because it tests nothing.
3. **No `ConsistencyLevel` handling** for `$count` / `$search` / advanced `$filter`.
4. **Declares PowerShell 7.2**, which is past end of support.

It is also an *application*, not a *library*: ~25 module-scope `$script:` variables, coupled
to `ImportExcel` and the reporting pipeline. It is not something to import for a one-liner.

### IntuneManagement (Micke-K, MIT)

`Extensions/EndpointManager.psm1` registers **108 object types** mapping Intune/Entra object
names to Graph endpoints. The table is worth lifting; the 9,186 lines of WPF UI around it is
not. The local copy carries no LICENSE file, so vendoring requires pulling the upstream MIT
text into `THIRD-PARTY-NOTICES.md`.

### External prior art

Surveyed 2026-08-14. None of these removes the need for GraphKit's plumbing layer, but several
constrain or inform it.

| Project | Relevance |
| --- | --- |
| **Microsoft.Graph SDK** | **Adopted for authentication.** Ships MSAL token caching, refresh, CA claims challenges, sovereign clouds, managed identity, and an outer-response retry handler tunable via `Set-MgRequestContext -MaxRetry -RetryDelay -RetriesTimeLimit`. The widely-cited failure at ~60–70 Autopilot devices ("more than 3 retries encountered") is `-MaxRetry` at its default of 3 — a configuration miss, not an architectural limit. |
| **Maester** (`maester365/maester`) | Pester-based M365/Entra security test framework: 40+ EIDSCA tests, CIS and CISA/SCuBA baselines, multi-tenant assessment, HTML reports, CI/CD integration. Overlaps IntuneHealthAutomation's *reporting* purpose, not GraphKit's plumbing. Worth evaluating before building further health-check reports by hand. |

#### What Maester's auth confirms

`Connect-Maester.ps1` (495 lines) is broad — 9 services, the full sovereign-cloud matrix with a
separate enum per service, explicit module import ordering to dodge bundled-DLL conflicts, and
scope-on-demand switches (`-SendMail`, `-Privileged`) that keep the default least-privilege.

It is also **shallow exactly where the hard problems are**: Graph auth is a pass-through to
`Connect-MgGraph` with no token acquisition, cache, or refresh of its own; zero
`client_credentials`; certificate auth only for SharePoint; and zero references to `429`,
`Retry-After`, or backoff anywhere in the connect path. Its `Invoke-MtGraphRequestCache` is a
hashtable keyed on absolute URI with no TTL, invalidation, or size bound.

Two conclusions, both of which shaped this design. First, a mature and well-staffed project
reached the same verdict — delegate token lifecycle to the SDK — which is corroboration, not
coincidence. Second, throttling remains unsolved even there, confirming it as GraphKit's
actual contribution. Lifted directly: sovereign-cloud enums, existing-session reuse before
reconnecting, and scope-on-demand as a least-privilege default. Explicitly **not** lifted: the
unbounded cache.
| **IntuneAssignmentChecker** (Ugur Koc) | v3 was a single script; v4 is a module with assignment simulation, reverse lookup, and a read-only MCP server. Overlaps IHA's assignment analysis, and its script→module evolution is the same path taken here. |
| **Microsoft365DSC** | Configuration-as-code across the full M365 surface with drift detection. Broader and heavier than this work; known gaps in Intune configuration-profile export. |
| **EntraExporter** | Entra configuration to versioned JSON. Supersedes the deprecated AzureADExporter. Excludes several object classes unless `-All` is passed. |
| **IntuneBackupAndRestore**, **IntuneManagement** | Policy backup/copy/migrate between tenants. |
| **Sampler** (gaelcolas) | The community-standard module scaffolder — InvokeBuild tasks for build/test/pack/publish, cross-platform, no admin rights required, ModuleFast dependency resolution. An open question against the hand-rolled layout below. |

Two Microsoft guidance points materially changed this design: batch envelopes returning 200 OK
while inner requests are throttled, and the `x-ms-retry-after-ms` header variant. Both are
captured in the request-core section.

Name check: `GraphKit` is available on the PowerShell Gallery. `GraphTools` (Kevin Blumenfeld)
and `PSGraphKit` (Martin Welen) are taken.

### pliving/Graph.ps1

293 lines with the right bones — config validation, `Join-GraphUri`,
`Invoke-GraphRequest -AllPages`, structured error unwrapping, JWT claim inspection,
`$count`-with-fallback. Superseded by IntuneHealthAutomation's more developed core, but
confirms the shape.

## Decision

Extract the plumbing from IntuneHealthAutomation into a standalone `GraphKit` module, in
stages. Build and prove GraphKit first; cut IntuneHealthAutomation over to it as separate,
later work.

Rejected alternatives:

- **Big-bang refactor** — invasive change to an actively-developed app with no test suite
  to catch regressions.
- **Extend IntuneHealthAutomation in place** — a quick-action import would drag `ImportExcel`,
  caching, and reporting along, and the surface would stay Intune-shaped rather than
  Graph-shaped.
- **Greenfield with copy-harvest** — two Graph layers that drift apart permanently.

### Dependency shape

```
GraphKit            plumbing: auth, tenants, request core, permissions
   ^
   |
healthcheck (IHA)   domain: reports, Excel, caching, checkpointing
```

IntuneHealthAutomation gains `RequiredModules = @{ModuleName='GraphKit'; ModuleVersion='1.0.0'}`
and deletes its duplicated layer.

The payoff runs both directions. GraphKit alone stays light — one dependency, no reporting
stack. Importing both yields a shared tenant context that does not exist today:

```powershell
Use-GraphTenant ivy24              # authenticate once
Get-GraphObject CompliancePolicy   # ad-hoc, instant
Invoke-IntuneHealthCheck           # full IHA run, same tenant, no re-auth
```

And IntuneHealthAutomation inherits the throttling handling and test suite it currently lacks.

### Authentication is delegated to the Graph SDK

GraphKit takes a dependency on **`Microsoft.Graph.Authentication`** and acquires tokens through
`Connect-MgGraph`. It does not implement token acquisition, caching, or refresh.

This reverses an earlier decision to hand-roll raw REST authentication. Measurement is what
changed it — `Microsoft.Graph.Authentication` v2.38.1 imports in **96 ms** (38.8 MB on disk),
so the "heavy dependency" objection does not survive contact with a stopwatch. `Connect-MgGraph`
natively covers every auth mode in use here: `-ClientSecretCredential`, `-CertificateThumbprint`,
`-Certificate`, `-CertificateSubjectName`, `-AccessToken`, `-Identity` (managed identity), and
`-UseDeviceCode`.

What delegation buys, all of it genuinely hard to rebuild correctly:

- MSAL token cache, refresh, and clock-skew handling
- **Conditional Access claims challenges.** Graph can answer 401 with a `WWW-Authenticate`
  claims challenge requiring re-request with a claims parameter. Hand-rolled
  `client_credentials` implementations typically ignore this. Given the customer tenants this
  module targets are CA-heavy, that is a correctness issue, not a nicety.
- All five sovereign clouds via `-Environment`
- Managed identity, for later unattended use

The earlier argument that the SDK's retry handler is inadequate — citing bulk Autopilot
registration failing at ~60–70 devices with "more than 3 retries encountered" — was a
misreading. That is `-MaxRetry` sitting at its default of 3, addressable with
`Set-MgRequestContext -MaxRetry 10`. It is a configuration miss, not an architectural limit.

**Accepted cost: one global tenant context.** `Get-MgContext` takes no parameters; the SDK holds
exactly one connection, so two tenants cannot be live simultaneously. `Use-GraphTenant`
reconnects, which MSAL's cache makes silent for repeat switches. Cross-tenant comparison in a
single pipeline is therefore **out of scope** — it was never a stated requirement, and
sequential switching covers the actual workflow.

The request layer stays GraphKit's, because the gaps below are application-level and the SDK
does not close them regardless of which transport acquires the token.

## Scope

### Moves into GraphKit

| Area | From |
| --- | --- |
| Tenants | `Save-/Remove-TenantConfiguration`, `New-TenantConfigurationPrompt`, `Show-TenantManagementMenu`, `Get-SecretsConfiguration` |
| Request core | `Invoke-IntuneGraphRequest`, `Invoke-ParallelGraphRequest`, `Get-GraphUrl` |
| Permissions | `Test-GraphPermissions`, `Get-TokenPermissionAnalysis`, `Get-AppRegistrationPermissions`, `Grant-IntuneAppPermissions` (~1,400 lines, generalized off the health check's fixed permission set) |

### Retired, not moved

The decision to delegate authentication (below) means several IntuneHealthAutomation functions
are deleted rather than extracted:

- `Get-CBAToken` (253 lines) → `Connect-MgGraph -CertificateThumbprint`
- `Update-AccessToken` (150 lines) → MSAL token cache inside the SDK
- `Set-GraphEnvironment` (65 lines) → `Connect-MgGraph -Environment`

Bearer-token mode survives natively via `Connect-MgGraph -AccessToken`. Roughly 470 lines of
token-lifecycle code stop being maintained here.

### Stays in IntuneHealthAutomation

- 17 report definitions and the reporting/Excel pipeline
- `src/private/Processing` (28 files of Intune-specific shaping)
- `Checkpoint-DeviceCollection`, console UI, `Invoke-IntuneHealthCheck`
- **The entire caching layer** (~1,300 lines). It is entangled with checkpointing and the
  collection flow; extracting it is the highest-risk piece and is deferred until GraphKit's
  request core is proven.

### New in GraphKit

- Retry and `Retry-After` handling
- A committed Pester test suite
- SecretManagement-backed credential storage
- `Get-GraphObject` with tab completion over the 108-type table
- `Export-GraphResult`, including vault-aware evidence output

## Components

### Repository

New private repo at `~/repo/GraphKit` → `github.com/adamgell/GraphKit`, scaffolded with
**Sampler** (`New-SampleModule -ModuleType SimpleModule`).

Sampler supplies InvokeBuild tasks for build/test/pack/publish, ModuleBuilder compilation,
GitVersion, PSScriptAnalyzer, JaCoCo coverage, and CI templates — replacing the hand-maintained
`New-IntuneModuleRelease` equivalent. It runs on Windows, Linux, and macOS without admin rights.

Verified against Sampler 0.120.1 on 2026-08-14:

- **Pester 6 is compatible.** Sampler's version gates are lower-bound only (`>= 5.0.0`), and it
  references none of the options v6 removed — no `CoverageGutters`, no `UseBreakpoints`, no
  `FailOnNullOrEmptyForEach`. Coverage is JaCoCo, which v6 retains. Its changelog entry about
  updating sample tests to Pester 5 concerns Sampler's own samples, not a constraint on ours.
- **`New-SampleModule` cannot run non-interactively.** Its Plaster template prompts
  "Will you use Git for source control?" unconditionally; no parameter suppresses it, and it
  fails outright in a non-interactive host. Scaffolding is therefore a one-time manual step and
  cannot be automated in CI. Acceptable, but it must not be scripted.
- Sampler pins **ModuleBuilder 3.1.8**, because newer versions break its task alias
  registration. Do not upgrade ModuleBuilder independently.

```
GraphKit/
  source/
    GraphKit.psd1                    # RequiredModules: Microsoft.Graph.Authentication
    Public/
      Register-GraphTenant, Get-GraphTenant, Use-GraphTenant,
      Remove-GraphTenant, Test-GraphTenant
      Invoke-GraphRequest, Invoke-GraphBatch
      Get-GraphObject, Get-GraphObjectType
      Test-GraphPermission, Get-GraphTokenPermission,
      Get-GraphAppRegistrationPermission, Grant-GraphAppPermission
      Export-GraphResult
    Private/
      Invoke-GraphRetry, Resolve-GraphUri,
      ConvertFrom-JwtPayload, Write-VaultEvidence
    Data/ObjectTypes.psd1
    Formats/GraphKit.Format.ps1xml
  tests/Unit, tests/QA
  build.yaml, build.ps1, RequiredModules.psd1
  THIRD-PARTY-NOTICES.md
```

**Build note:** ModuleBuilder compiles `Public/` and `Private/` into a single `.psm1` under
`output/`. Non-code assets — `Data/ObjectTypes.psd1` and `Formats/GraphKit.Format.ps1xml` — are
not compiled and must be listed in `build.yaml` under `CopyPaths`, or they will be missing from
the built module while still present in source. This is a common first-build failure.

`Get-GraphToken` is absent by design: token acquisition belongs to `Connect-MgGraph`.

### Tenant profiles

Metadata in `~/.graphkit/profiles.json` (no secrets; safe to commit). Secrets and bearer
tokens in `Microsoft.PowerShell.SecretManagement` under `GraphKit:<name>`. The backend is
swappable — SecretStore now, Keychain, 1Password, or Key Vault later — without module changes.

Each profile carries:

| Field | Notes |
| --- | --- |
| `Name` | Profile identifier; also the vault customer tag when `Kind = customer` |
| `Kind` | `customer` \| `lab` \| `internal` |
| `TenantId`, `ClientId` | |
| `AuthMethod` | `Certificate` \| `ClientSecret` \| `BearerToken` \| `ManagedIdentity` \| `DeviceCode` — maps directly onto a `Connect-MgGraph` parameter |
| `Environment` | `Global` \| `China` \| `Germany` \| `USGov` \| `USGovDoD` — passed through to `-Environment` |

`Use-GraphTenant` resolves the profile, pulls its secret from SecretManagement, and calls
`Connect-MgGraph` with the corresponding parameter. Following Maester's pattern, it **checks
`Get-MgContext` first and skips reconnection when the existing context already matches the
requested tenant** — which keeps repeat switches instant and preserves sessions established by
federated credentials or managed identity.

**`Kind` governs taxonomy validation.** Only `Kind = customer` validates `Name` against the
CDW KB `SCHEMA.md` customer tag list. Lab and internal profiles are exempt — `ivy24` is a lab
tenant and is not, and should not be, a customer tag.

**Migration is a first-class command.** `Register-GraphTenant -FromLegacyConfig` imports both
IntuneHealthAutomation's `config/secrets.json` tenant array and the `Start-WithConsole *.cmd`
launchers, moving secrets into the vault so nothing is retyped and the plaintext copies can be
deleted.

### Request core

`Invoke-GraphRequest` wraps **`Invoke-MgGraphRequest`**, inheriting the SDK's transport, auth
plumbing, and its outer-response retry handler (tuned once at import via
`Set-MgRequestContext -MaxRetry`). On top of that it adds paging, URI resolution,
`ConsistencyLevel: eventual` when `$count`, `$search`, or advanced `$filter` appear, a `-Beta`
switch, and the throttling gaps below.

This is one request path, not two. The SDK is the transport; GraphKit owns the semantics it
does not implement.

`Invoke-GraphBatch` wraps `/$batch` at the 20-request limit.

**Batch throttling is not the same as request throttling.** Per Microsoft's throttling guidance,
each request inside a JSON batch is evaluated individually against limits — an inner request can
fail with 429 while **the batch envelope itself still returns 200 OK**. Treating the envelope
status as success silently drops data. `Invoke-GraphBatch` must therefore:

1. Inspect every inner response status, not just the envelope.
2. Retry failed inner requests using the `Retry-After` value from the **inner** JSON body.
3. Re-issue all failed inner requests as a new batch after the longest inner retry-after.

This is a correctness requirement, not an optimization.

### Throttling

The headline gap fix. The SDK's Kiota retry handler covers the **outer** response only, keyed on
the standard `Retry-After`. Everything below is application-level and remains GraphKit's
responsibility regardless of transport.

- Honor `Retry-After` in **all three** forms — delay-seconds, HTTP-date, and the
  `x-ms-retry-after-ms` variant that some Intune and Entra endpoints return instead of, or
  alongside, the standard header. Reading only `Retry-After` misses throttling signals on
  exactly the endpoints this module targets most.
- Exponential backoff with jitter when no header is present. Microsoft's guidance notes some
  resources return **no** `Retry-After` at all on 429, so backoff is a required fallback path,
  not a rare one.
- Retry on 429, 503, 504, and transient socket errors. Default 5 attempts, configurable.
- Throttling limits **cannot be raised** by request — Microsoft has confirmed this publicly.
  Backoff and batching are the only mitigations; for genuinely bulk extraction the documented
  answer is Graph Data Connect, which is out of scope here.
- **Cross-runspace backoff.** `Invoke-ParallelGraphRequest` uses separate runspaces, so a 429
  in one thread must back off the others. This requires a synchronized throttle-state object
  passed via `$using:`, holding a `NotBefore` timestamp each runspace checks before issuing
  and updates on 429. Per-thread retry alone would worsen throttling under parallelism — this
  is the single most important detail in the retry design.

### Object accessor

`Data/ObjectTypes.psd1` holds the 108 endpoint mappings lifted from IntuneManagement (MIT;
upstream license text in `THIRD-PARTY-NOTICES.md`). Each entry records name, API path, beta
flag, default `$select` / `$expand`, and whether the type supports assignments.

`Get-GraphObject -Type CompliancePolicy -Expand assignments` with an `ArgumentCompleter` on
`-Type`. **Tab completion is the discovery mechanism** — no catalogue to maintain, which
resolves problem 3 without new upkeep.

### Output and evidence export

Results are `PSCustomObject` with a `PSTypeName` of `GraphKit.<Type>` plus `_Tenant`,
`_RetrievedUtc`, and `_GraphPath`. `Formats/GraphKit.Format.ps1xml` supplies default table
views.

`Export-GraphResult -As Csv | Json | Markdown | VaultEvidence`.

`VaultEvidence` must obey `SCHEMA.md`, which states that evidence pages are summaries with
pointers to source paths and must never contain raw exports, credentials, or PII. Therefore:

1. Raw rows are written to `~/repo/report-exports/<name>/` — **outside the vault**.
2. A summary page is written to `cdw-kb/evidence/<name>/` containing rollups and counts only,
   with `sources:` pointing at (1), at least two wikilinks, and correct frontmatter
   (`type: evidence`, `tags: [evidence, graph-api, …]`, `confidence`, `created`, `updated`).
3. `customers:` is `[<name>]` for `Kind = customer`, and `[]` for lab and internal profiles.
4. `log.md` is appended and `index.md` updated, per the schema's log and index rules.
5. A **redaction assertion** runs before any write: no tenantId, clientId, secret, or bearer
   token may appear in vault output. This is enforced in code and covered by a test.

## Versions

**Pester 6.1.0**, **PowerShell 7.4** as the manifest floor, **Sampler 0.120.1** for build, and
**`Microsoft.Graph.Authentication`** as the sole runtime dependency (ModuleBuilder held at 3.1.8
per Sampler's pin).

The floor is a constraint, not a preference: Pester 6 targets Windows PowerShell 5.1 and
PowerShell 7.4+, having dropped PowerShell 6 and early 7 builds. 7.4 is chosen over 7.5
because Pester is a test-time dependency only, and customer jump boxes and CI images run LTS;
requiring 7.5 would risk an import failure elsewhere for no gain. Local development runs 7.5.4.

This also forces a correction during cutover: IntuneHealthAutomation declares 7.2, which is
past end of support.

## Testing

Pester 6.1.0, **`Invoke-MgGraphRequest` mocked**, no live Graph calls in CI. Tests are
**committed** — the current state of zero tracked test files behind a green CI badge is itself a
defect.

Use the v6 dash-style assertions exclusively, with `Should.DisableV5 = $true`. Both syntaxes
work by default in v6; pinning prevents drift back to v5 style in a greenfield suite. Mock
verification uses `Should-Invoke` / `Should-NotInvoke`.

Three v6 behaviors are load-bearing here:

- `Assert-MockCalled` and `Assert-VerifiableMock` are removed, and **mock fall-through to the
  real command is gone**. In v5 a mis-scoped `Invoke-MgGraphRequest` mock could silently fall
  through and hit real Graph; in v6 it cannot. Mocking a command from a dependency module
  requires `-ModuleName GraphKit` scoping.
- `Run.FailOnNullOrEmptyForEach` now defaults on. The 108-type table is driven through
  `-ForEach`; if it failed to load, v5 would silently pass zero tests and v6 throws.
- Discovery is per-file. Each test file imports GraphKit in its own `BeforeAll` rather than
  relying on another file having done so.

Also relevant: `-Focus` is removed, `Set-ItResult -Pending` is removed, duplicate `BeforeAll`
within a block now throws, and coverage is profiler-based by default.

### Coverage targets

- `@odata.nextLink` paging, including multi-page and empty-collection cases
- 429 and `Retry-After` in both delay-seconds and HTTP-date forms
- Cross-runspace backoff: a 429 in one runspace defers the others
- Token refresh at expiry, and the expiry-skew boundary
- Graph error unwrapping into actionable messages
- Legacy-config migration from both `secrets.json` and the `.cmd` launchers
- Profile `Kind` validation: `customer` enforces the taxonomy, `lab` and `internal` bypass it
- Vault redaction: no credential can reach vault output

### CI

Windows, Ubuntu, and macOS — development happens on macOS and the module claims
cross-platform support, so all three are proven. Matrix pinned to PowerShell 7.4 (the declared
floor) and latest, so a 7.5-only API cannot slip in below the stated minimum.

## Phases

1. **Core.** Module skeleton, auth, tenant profiles, request core, retry/throttling, test
   suite, CI. Proven against the **Ivy24 lab tenant** — a lab target means the retry paths and
   mutating verbs can be exercised without customer exposure. Tenant and client IDs are
   registered via `Register-GraphTenant`, never written into the repo, consistent with existing
   Theseus practice of omitting numeric identifiers from documentation.
2. **Permissions.** Move the permission tooling down and generalize it off the health check's
   fixed permission set.
3. **Objects.** `Get-GraphObject`, the 108-type table, and tab completion.
4. **Export.** `Export-GraphResult` and vault evidence output.
5. **Cutover.** Repoint IntuneHealthAutomation at GraphKit and delete its duplicated layer.
   Separate work, only after 1–4 are proven.

Caching remains in IntuneHealthAutomation throughout.

## Out of scope

- Porting all ~175 scripts. Phase 1 validates the module against the Ivy24 tenant; it does not
  migrate a script backlog. Existing scripts are catalogued as `type: script` vault pages and
  ported opportunistically when next touched.
- The vendored IntuneManagement trees. Never ported; only the object-type table is lifted.
- Extracting IntuneHealthAutomation's caching layer.
- Publishing to the PowerShell Gallery.
