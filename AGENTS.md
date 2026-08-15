# Repository Guidelines

## Project Overview

GraphKit is planned as an app-only, multi-tenant Microsoft Graph execution and analysis layer with explicit Intune and Entra operation semantics. It is not a generic Graph SDK or an OAuth implementation. Its core value is reliable request execution: immutable tenant contexts, operation metadata, semantics-aware retry/throttling, permission analysis, and evidence export.

**Repository status:** design-approved, scaffolded, and implemented through phase 4 of the v1 plan, with phase 1 verified against a live tenant on 2026-08-15.

Phase 1 (Core): descriptor catalog and strategy registry, immutable contexts and locked atomic profile store, four token sources with single-flight, owned transport with tenant-proof binding, semantics-aware retry, scoped throttle with AIMD admission (starting conservatively and ramping to the cap), URI security, paging, batch, vault credential resolution, and the MSAL import guard. Phases 2-4 ship `Get-GraphObject` with tab completion, four-state permission analysis, and `Export-GraphResult` with an evidence DTO allowlist.

**Gate 1.8 passed live against the Ivy24 lab tenant on 2026-08-15**: package digest verified, profile resolved SecretStore -> PFX -> MSAL, token acquired, 13 managed devices / 75 mobile apps / 15 device configurations read, and an app assignment applied to a test group and reverted (revert confirmed independently, not from the script's own report).

**A correction worth carrying forward.** This file previously recorded phases 1-4 as complete while `New-GraphTokenSource` defaulted every auth method to a scriptblock that threw "MSAL confidential-client resolution is not wired". GraphKit could not acquire a token by any means, and the entire suite passed because every test injects a factory. Setting up a vault and running the smoke test for real is what exposed it. **Treat "implemented" and "verified against a live tenant" as different claims in this file, and say which one you mean.**

Live-verification status by auth mode:

- `Certificate` - PROVEN end to end against Ivy24 (vault -> PFX -> MSAL -> token -> paged reads -> mutation and revert).
- `ClientSecret` - PROVEN end to end against Ivy24 on 2026-08-15. A one-hour secret was added to the app registration, stored in the vault, registered as a second profile, used to acquire a token and read 13 managed devices, and then removed from the app registration, the vault and the profile store. Verified afterwards that zero client secrets remain on the registration.
- `BearerToken` (vault-resolved) - PROVEN end to end against Ivy24 on 2026-08-15. A real token was stored in the vault, registered as a profile holding only a vault reference, resolved back through `Get-GraphVaultCredential`, and used to read 13 managed devices. The source correctly reports `CanRefresh = False`, and a forced refresh fails loudly rather than silently returning a token the service may already have rejected. Secret and profile removed afterwards; verified nothing remained.
- `ManagedIdentity` - PROVEN end to end against Ivy24 on 2026-08-15, in the only place it can be: a throwaway Azure Container Instance with a user-assigned identity granted `DeviceManagementManagedDevices.Read.All`. GraphKit was installed from a package, a profile registered, a token acquired through `ManagedIdentityApplicationBuilder` against the real IMDS endpoint, and 13 managed devices read - the same count the certificate path returns. No secret existed anywhere in that container. All Azure resources were deleted afterwards, so **re-proving this costs a fresh container**; it cannot be re-run from a workstation.

Proving `ClientSecret` also demonstrated context independence directly against the tenant: a `Certificate` context and a `ClientSecret` context for the same tenant reported their own `AuthMode` and held distinct tokens, which is the isolation claim the design rests on.

The container run was worth more than the one auth mode it was built for, because it was the first time GraphKit ran on a **clean machine**. It immediately hit a bug no workstation could surface: `Enter-GraphProfileStoreLock` could not create its `.lock` sidecar because `~/.graphkit` did not exist yet, and the retry loop caught that `DirectoryNotFoundException` and reported it as "another GraphKit process may be writing" - a confident diagnosis of the wrong problem, on the very first `Register-GraphTenant` any new user would ever run. Every developer machine had passed through that state months earlier. **When adding a gate, prefer one that starts from nothing.**

Two things about the container are worth knowing before repeating it. `Microsoft.PowerShell.SecretManagement` is a hard `RequiredModules` entry, so it must be installed even for managed identity, which has no stored secret and never opens a vault; installing the module is not the same as registering a vault, and no vault extension was present, so lazy vault validation was still genuinely tested. Whether that dependency should be hard is an open question - the spec asks that managed identity, injected credentials, help, catalog inspection and CI all stay usable without a vault, and the module dependency is the one part of that which is not yet lazy.

Deterministic CI (`.github/workflows/ci.yml`) gates on the whole Pester result across PowerShell 7.4/7.6 on Windows/Ubuntu/macOS. 559 deterministic tests are green under `./build.ps1 -Tasks test`; `tests/QA/Assert-GateResult.ps1` enforces the expected-minimum-count gate. Test suites now include `tests/Adapter/LoopbackSender.Tests.ps1` (the real HttpClient against an in-process HttpListener) and `tests/Concurrency/TokenIsolation.Tests.ps1`.

Remaining per spec: the phase-5 cutover, deliberately not started until a private package channel is decided.

Two exceptions are real and runnable today, copied from IntuneHealthAutomation:

- `scripts/New-ClientServicePrincipalCBA.ps1` — creates the certificate-based app registrations that GraphKit tenant profiles consume.
- `scripts/New-Ivy24LabApp.ps1` — unattended runner that recreates the Ivy24 lab registration end to end and proves it: delete, create, verify every role was actually granted, authenticate app-only with the generated certificate, read a real Intune endpoint.
- `tests/New-ClientServicePrincipalCBA.Tests.ps1` — 57 passing Pester tests covering that script.

These are standalone scripts, deliberately not module functions: converting the CBA script into `New-GraphAppRegistration` is phase 2 work. IntuneHealthAutomation keeps its own copy of the script — it is referenced by seven docs, `New-Release.ps1` packaging, and at runtime by `src/private/Authentication/Invoke-CertificateSetupPrompt.ps1` — so the two copies diverge intentionally until the phase 6 cutover.

## Architecture & Data Flow

Planned flow:

1. `Register-GraphTenant` persists non-secret profile metadata; credentials stay in `Microsoft.PowerShell.SecretManagement`.
2. `Get-GraphContext` resolves a profile into an immutable runtime context before parallel work begins.
3. Public commands resolve an operation descriptor from `source/Data/Operations/*.psd1`.
4. `Invoke-GraphOperation` validates URI/query/version/cloud/permission rules, then issues the request through a **GraphKit-owned `HttpClient`** using a token from the context's own MSAL confidential client.
5. The request pipeline handles paging, deadlines, cancellation, scoped admission control, and semantics-aware retry. GraphKit is the **sole retry owner**; there is no underlying handler that can retry behind its back.
6. Results return as `PSCustomObject` values with `PSTypeName` `GraphKit.<Type>` and provenance such as `_Tenant`, `_RetrievedUtc`, `_GraphPath`, and `_ApiVersion` where applicable.
7. `Export-GraphResult` writes CSV, JSON, Markdown, or redacted vault evidence.

Preserve these boundaries:

- **Do not use `Connect-MgGraph` / `Invoke-MgGraphRequest` as the transport.** Measured 2026-08-14: `Set-MgRequestContext` executed inside a `ForEach-Object -Parallel` child runspace **mutated the parent's configuration**. SDK state lives in process-global .NET statics shared across runspaces, and `Get-MgContext` takes no parameters because there is exactly one connection. A tenant switch in one runspace therefore retargets every other: a loop paging Tenant A would issue its next page with Tenant B's token while still labelling results Tenant A. Silent cross-tenant contamination is the worst failure this module could have. This also voids the no-replay guarantee (the SDK handler can retry a 503 before GraphKit sees it) and makes the promised split timeouts undeliverable (`Invoke-MgGraphRequest` exposes no timeout or cancellation parameters).
- Acquire tokens with **MSAL.NET** per context, which has no global state and still performs certificate assertion signing. Contexts own an `IGraphTokenSource`, not an MSAL client directly: managed identity uses `ManagedIdentityApplicationBuilder`/`AcquireTokenForManagedIdentity` rather than `ConfidentialClientApplicationBuilder`/`AcquireTokenForClient`, and fixed bearer tokens cannot refresh at all.
- **v1 consumes MSAL transitively** via `Microsoft.Graph.Authentication`, depended on **solely to deliver `Microsoft.Identity.Client.dll`**; never call `Connect-MgGraph`. Bind late, stay on long-stable surface, and **never ship a competing `Microsoft.Identity.Client.dll`** — four MSAL versions already coexist in a typical environment (Az.Accounts, Graph.Authentication, PSResourceGet) and first load wins in the default ALC. This is an accepted compatibility constraint, not a sound boundary: that DLL is a private implementation detail with no contract for location, load timing, or version. CI must run an import-order matrix in fresh processes.
- The recorded end state is **`GraphKit.Auth`** — a compiled adapter referencing an explicit `Microsoft.Identity.Client` version, loaded into an isolated `AssemblyLoadContext`, exposing only GraphKit-owned request/result types so no MSAL type crosses the boundary. Much later, not v1. Because contexts own `IGraphTokenSource`, that swap is an implementation change, not an interface change.
- Do not build another OAuth client and do not persist access tokens. Client-credentials flows return no refresh token: an expired token is replaced by reacquiring from the source credential, which already lives in SecretManagement.
- API version is per-operation metadata, never a global beta mode.
- Generic reads may use `Get-GraphObject`; do not introduce a universal generic mutation API.
- IntuneHealthAutomation retains reports, Excel processing, checkpointing, console UI, and caching until the later cutover.
- A current context is interactive convenience only. Low-level work must accept `-Context` or `-ProfileId` and resolve it before entering runspaces.

Example planned usage:

```powershell
$context = Get-GraphContext -ProfileId ivy24
Get-GraphObject -Context $context -Type ManagedDevice
```

## Key Directories

Current:

- `docs/superpowers/specs/` — approved design decisions and the present source of truth.
- `scripts/` — standalone operational scripts copied from IntuneHealthAutomation. Not module functions, and not the future `source/Public/`.
- `tests/` — Pester tests for those scripts. Resolves the script under test via `Split-Path $PSScriptRoot -Parent`, so `tests/` and `scripts/` must remain siblings.
Scaffolded (2026-08-15):

- `source/Public/` — exported PowerShell functions; one command per file (scaffold placeholders only for now).
- `source/Private/` — request, retry, URI, throttle, and evidence helpers (scaffold placeholder only for now).
- `source/Data/Operations/` — `.psd1` operation descriptors governing behavior.
- `source/Formats/` — PowerShell formatting definitions.
- `tests/Unit/` — deterministic retry and policy tests using injected dependencies and virtual time.
- `tests/QA/` — repository/module quality checks; currently `BuiltModule.tests.ps1` (phase 1.1 gate) plus Sampler-generated module checks.
- `output/` — generated package output; do not edit it directly.

Planned for later increments:

- `tests/Adapter/` — HTTP-result normalization and loopback-server tests.
- `tests/Concurrency/` — real-runspace throttle and isolation tests.

## Development Commands

```powershell
./build.ps1 -ResolveDependency -Tasks noop   # restore Sampler/Pester/ModuleBuilder and runtime deps
./build.ps1 -Tasks build                     # Clean + Build_Module_ModuleBuilder + changelog
./build.ps1 -Tasks test                      # Pester_Tests_Stop_On_Fail + coverage threshold
./build.ps1 -Tasks pack                      # build + package_module_nupkg
Invoke-Pester ./tests/New-ClientServicePrincipalCBA.Tests.ps1 -Output Detailed
Invoke-Pester ./tests/QA/BuiltModule.tests.ps1   # phase 1.1 gate: built package in clean pwsh
```

Treat `build.ps1`, `build.yaml`, and `RequiredModules.psd1` as authoritative for exact task names.

## Code Conventions & Common Patterns

- Use standard PowerShell `Verb-Noun` names with the `Graph` noun prefix, for example `Get-GraphContext`, `Invoke-GraphOperation`, and `Test-GraphPermission`.
- Keep exported commands in `source/Public/` and implementation helpers in `source/Private/`; do not add a second module layout.
- Make operation behavior descriptor-driven. Descriptors own method, path, API version, response kind, paging, retry safety, concurrency, permissions, licensing, clouds, and stability.
- Prefer explicit operation-specific handling over abstractions that hide Graph differences.
- Normalize transport outcomes before policy logic. Retry code should consume a stable result record rather than PowerShell exception internals.
- Inject `Send`, `UtcNow`, `Delay`, and `Jitter` into retry logic. Tests must use virtual time and deterministic jitter.
- Prefer `PSCustomObject` records or a small compiled type over many public PowerShell classes; class definitions persist awkwardly across test runs.
- Resolve immutable contexts before asynchronous/runspace work. Shared throttle state must be thread-safe and scoped by cloud, tenant, client, resource family, and read/write class.
- Error handling must preserve certainty: distinguish known failure from indeterminate commit. Never blanket-replay POST/PATCH after timeouts, resets, or ambiguous 5xx responses.
- A successful 2xx response with `Retry-After` remains success: update future pacing, never replay it.
- Treat `@odata.nextLink` as opaque, validate its Graph authority before forwarding authorization, and continue through empty pages carrying a next link.
- Never log, commit, export, or place in vault evidence tenant IDs, client IDs, credentials, secrets, bearer tokens, or PII.

## Important Files

Current:

- `docs/superpowers/specs/2026-08-14-graphkit-design.md` — approved scope, architecture, reliability rules, planned layout, versions, and testing contracts.
- `AGENTS.md` — repository guidance for assistants and contributors.

- `source/GraphKit.psd1` — module manifest and runtime dependency declaration.
- `build.yaml` — Sampler/ModuleBuilder configuration and required asset copying.
- `build.ps1` — build entry point.
- `RequiredModules.psd1` — development/build dependencies.
- `source/Data/Operations/*.psd1` — operation catalog.
- `source/Formats/GraphKit.Format.ps1xml` — default display views.
- `THIRD-PARTY-NOTICES.md` — required before lifting the MIT-licensed IntuneManagement type table.

`source/Data/Operations/` and `source/Formats/GraphKit.Format.ps1xml` are not compiled into the generated `.psm1`. They must appear in `build.yaml` `CopyPaths`, or packaged builds will silently omit them.

## Runtime/Tooling Preferences

- Runtime compatibility floor: PowerShell 7.4.
- Primary development and release target: PowerShell 7.6.
- Build system: Sampler 0.120.1.
- Module compilation: ModuleBuilder 3.1.8, pinned through Sampler; do not upgrade it independently.
- Test framework: Pester 6.1.0.
- Runtime dependencies: `Microsoft.Graph.Authentication` (pinned minimum; MSAL delivery vehicle only, `Connect-MgGraph` never called) and `Microsoft.PowerShell.SecretManagement` (required for every persisted credential).
- Operational prerequisite, not a module dependency: a registered SecretManagement vault extension. Its absence must fail at import with an actionable message, not at first token acquisition.
- Module format: authored public/private scripts compiled into one `.psm1` under `output/`, with non-code assets copied separately.
- No Node, Bun, npm, or other package-manager workflow is defined.
- No PSScriptAnalyzer, formatter, lockfile, version file, or CI configuration exists yet.

## Testing & QA

`tests/New-ClientServicePrincipalCBA.Tests.ps1` exists and passes (57 tests, 12 contexts). Every test corresponds to a defect that actually occurred while creating the Ivy24 registration, and they share one failure mode: **the script reported success while not having done the thing.** Two are AST-based and worth reusing as patterns — one asserts no code sits inside a block comment (113 lines containing the entire permission-granting pipeline once did, so registrations had permissions configured and zero granted), the other asserts no variable is read that is never assigned (`$GraphAppId` and `$context` both silently expanded to empty strings without `Set-StrictMode`). Both were mutation-tested: each detector was confirmed to fail when its bug is reintroduced.

When module implementation begins, commit real `*.Tests.ps1` files and preserve these approved contracts:

- Unit-test retry policy against normalized transport results, not mocked HTTP exception shapes.
- Cover attempt counts, delay precedence, deadlines, cancellation, scoped throttle state, one refresh after `401`, no replay after `202`, no ambiguous-write replay, and batch retry selection.
- Use loopback HTTP integration tests for duplicate/malformed headers, empty or binary bodies, content encoding, and connection closure.
- Use real runspaces for concurrency tests; run those containers serially at Pester level.
- Import GraphKit in each test file's `BeforeAll` because Pester discovery is per-file.
- Register a default mock that throws before filtered mocks. Use `Should-Invoke`/`Should-NotInvoke`, dash-style assertions, and `-ModuleName GraphKit` for dependency-module commands.
- Do not use Pester parallelism or experimental global mocks for stateful retry/cache tests.
- Add response-shape contract tests for every `BetaPreferred` and `BetaOnly` operation.
- Test next-link authority validation and assert redaction before any vault evidence write.
- CI must gate on the whole Pester result: overall status, failed containers, discovery errors, failed tests, total count, and an expected minimum count. `FailedCount -eq 0` alone is insufficient.
- Test on PowerShell 7.4 and 7.6 across Windows, Ubuntu, and macOS.
- Publish only the already-tested package artifact; do not rebuild in the publish job.

Coverage runs through Sampler/Pester (JaCoCo output); `CoveragePercentTarget` is 0 until thresholds are defined.
