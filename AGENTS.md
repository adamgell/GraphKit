# Repository Guidelines

## Project Overview

GraphKit is an app-only, multi-tenant Microsoft Graph execution and analysis layer with explicit Intune and Entra operation semantics. It is not a generic Graph SDK or an OAuth implementation. Its core value is reliable request execution: immutable tenant contexts, operation metadata, semantics-aware retry/throttling, permission analysis, and evidence export.

**Current release status:** GraphKit `0.3.0` is the current immutable release on PSGallery, published at `2026-08-30T04:38:20.12Z`. The 207381-byte public archive SHA-256 is `45319d7cf4f8333697343ccf9c1089c7e04da87a8df62553cbc140089337536d`; reviewed PR head `a0f0e92a054fe2976ca74a844f5de6161e1b8c67` merged to main as `a1b0b8d54c17671761ef5aee017a453b072d1fe9`. PR-head CI run `33292245900` and exact-main CI run `33292580847` each passed 772 tests across all six Windows/macOS/Ubuntu PowerShell 7.4/7.6 jobs. This deterministic and CI evidence is not live service proof. GraphKit `0.2.2` remains an immutable predecessor; its hard SecretManagement contract matters only to hosts pinned to that version. Phases 1-5 are implemented; live verification remains recorded separately per auth mode, descriptor, and operation because implementation is not evidence of service behavior.

GraphKit `0.3.1` is an unpublished maintenance bridge candidate for TenantPulse's IntuneHealthAutomation successor path. It adds only `AppleEnrollmentProfile.ListByToken` and `ManagedDevice.GetBeta` above the stable `0.3.0` package inputs. Their catalog, route, and result-shape behavior is deterministic-test evidence only; no live-service verification or PSGallery publication is claimed. Keep this stable-line bridge separate from the broader R8 development line.

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

Two things about the container are worth knowing before repeating it. The immutable PSGallery `0.2.2` package was built while `Microsoft.PowerShell.SecretManagement` was a hard `RequiredModules` entry, so it had to be installed even for managed identity, which has no stored secret and never opens a vault. The `0.3.0` release removes that hard dependency: managed identity, injected credentials, help, catalog inspection and CI stay usable without SecretManagement, while first vault use explicitly validates and imports version 1.1.2 or newer and requires a registered extension. `Install-GraphKitPinned.ps1` preserves automatic SecretManagement installation for a `0.2.2` pin and makes it opt-in for `0.3.0`. None of this alters or republishes the stable `0.2.2` artifact.

Run the suite through `./build.ps1 -Tasks test`, never `Invoke-Pester ./tests` directly: the changelog checks are Sampler-generated and depend on build-injected variables, so a bare Pester run reports two false failures.

**Remote CI contract.** `.github/workflows/ci.yml` runs PowerShell 7.4 and 7.6 across Windows, Ubuntu, and macOS. A source revision is CI-verified only when all six matrix jobs pass for that exact SHA; workflow existence or an older successful run is not evidence. The published `0.3.0` evidence is 772 deterministic tests. The `0.3.1` maintenance tree requires 790 deterministic tests under `./build.ps1 -Tasks test`, with zero failures, errors, or skips, and its all-file tested-release proof enforces the same minimum-count floor used by CI and package verification.

**Phase 5 (cutover) implementation and Ivy24 verification are complete.** All eight steps ran and were verified against the Ivy24 lab tenant: legacy-caller inventory, `Import-GraphLegacyProfile`, a private versioned package channel with publish/pin/install, a live read through the *installed* package, a GraphKit-backed data plane in IHA behind a default-off flag, reads and a reverted mutating write through it, and a full credential-generation rollover ending in the old generation's revocation. Catalog coverage of IHA's declared surface is 27 of 27 at the API version it actually calls. The 2026-08-15 cutover record preserved two operator actions because active customer repointing would have required the legacy fallback to remain. Current operator status on 2026-08-29 is that no legacy or customer-tenant consumer uses these paths, so that historical contingency is not a `0.3.0` release blocker; the repository does not independently inventory external consumers. Purging deleted directory data remains policy-controlled housekeeping rather than package work. Read `docs/cutover/2026-08-15-phase5-cutover.md` before revisiting the historical cutover.

Three things from that work belong here because they change how you run the build:

- **Pack before test, not after.** The `pack` task begins with `Clean`, so `build,test,pack` rebuilds the module *after* the suite ran and packages bytes nothing tested. `Publish-GraphKitPackage.ps1` now enforces this by comparing the packaged `GraphKit.psm1` against the built module the tests imported, and refuses on mismatch.
- **IntuneHealthAutomation is a beta-first consumer.** It declares its Graph surface in `src/data/GraphEndpoints.json` and reads beta for almost all of it. A v1.0 descriptor does not serve a beta caller, because API version is per-operation metadata. Measure coverage with `./scripts/Get-GraphKitCutoverCoverage.ps1`.
- **A descriptor's `RequiredPermissions` is a claim about the service, and only the service can confirm it.** Three of the twenty-six descriptors added declared permissions that returned 403 despite the token demonstrably carrying them. Live-verify every new descriptor.

Current disposition of that descriptor debt: `ConditionalAccessPolicy.List` and `AuthenticationMethodsPolicy.Get` were positively proven on 2026-08-16, and `NamedLocation.List` was positively proven with `Policy.Read.All` on 2026-08-29. The obsolete `DeviceCleanupRule.Get` singleton was removed; `ManagedDeviceCleanupRule.ListBeta` is the documented replacement and was positively proven on 2026-08-29 with `DeviceManagementManagedDevices.Read.All`. `DeviceManagementScript.List` alone remains correct-but-not-live-verified: its 403 named `DeviceManagementScripts.Read.All`, but the lab token does not carry that scope, so no successful response-shape claim is made.

Two exceptions are real and runnable today, copied from IntuneHealthAutomation:

- `scripts/New-ClientServicePrincipalCBA.ps1` — creates the certificate-based app registrations that GraphKit tenant profiles consume.
- `scripts/New-Ivy24LabApp.ps1` — unattended runner that recreates the Ivy24 lab registration end to end and proves it: delete, create, verify every role was actually granted, authenticate app-only with the generated certificate, read a real Intune endpoint.
- `tests/New-ClientServicePrincipalCBA.Tests.ps1` — 57 passing Pester tests covering that script.

These are standalone scripts, deliberately not module functions: converting the CBA script into `New-GraphAppRegistration` is phase 2 work. IntuneHealthAutomation keeps its own historical copy of the script — it is referenced by seven docs, `New-Release.ps1` packaging, and `src/private/Authentication/Invoke-CertificateSetupPrompt.ps1`. No adopted runtime currently depends on reconciling those copies, so any future consolidation is separate work rather than a `0.3.0` blocker.

## Architecture & Data Flow

Runtime flow:

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
- IntuneHealthAutomation retains its reports, Excel processing, checkpointing, console UI, and caching in its own repository; no adopted runtime currently makes their consolidation a GraphKit release condition.
- A current context is interactive convenience only. Low-level work must accept `-Context` or `-ProfileId` and resolve it before entering runspaces.

Example planned usage:

```powershell
$context = Get-GraphContext -ProfileId ivy24
Get-GraphObject -Context $context -Type ManagedDevice
```

## Key Directories

- `docs/superpowers/specs/` — approved design decisions and product contracts.
- `source/Public/` — exported PowerShell commands, one command per file.
- `source/Private/` — transport, auth, retry, URI, throttle, paging, batching, and evidence helpers.
- `source/Data/Operations/` — versioned `.psd1` operation descriptors.
- `source/Formats/` — PowerShell formatting definitions.
- `tests/Unit/` — deterministic policy and pipeline tests.
- `tests/Adapter/` — real-HTTP loopback adapter tests.
- `tests/Concurrency/` — real-runspace isolation and throttle tests.
- `tests/QA/` — repository, package, import, and whole-result gates.
- `scripts/` — standalone operational, cutover, and publication scripts.
- `output/` — generated build/package output; never edit it directly.

## Development Commands

```powershell
./build.ps1 -ResolveDependency -Tasks noop   # restore exact build/runtime dependencies
./build.ps1 -Tasks pack                      # Clean + build + package candidate
./build.ps1 -Tasks test                      # test the package-producing build
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

## Write Operations

The catalog was read-only except for one assignment until 2026-08-16. It now carries eight writes,
and the rules that keep them safe are enforced in code and tests rather than left to reviewers.

**Mutation is declared, never inferred from the HTTP verb.** `ReplayPolicy = 'Safe'` means the
operation changes nothing, and that is what `Invoke-GraphOperation` gates on. Two descriptors are
POSTs that mutate nothing - `AppInstallSummaryReport.Get` and `DeviceReport.Export` post a body to
obtain a report - so a verb-based gate would prompt on reads and teach callers that the prompt is
noise.

**Every write declares an `Impact`** (`Low`/`Medium`/`High`), enforced by a descriptor invariant
because the default is the permissive direction: an undeclared Impact reads as not-High, so a
destructive operation added without one silently skips the confirmation. `High` means irreversible
data loss and requires an explicit `-Force`.

**`-Force` does not prompt, by design.** The first version called `ShouldContinue`, which does not
reliably throw in a non-interactive host - it *blocks on stdin*. A test run hung past ten minutes
with six stuck processes. A wedged CI job is worse than a failed one. Requiring a named switch also
records the intent to destroy in the command itself, where shell history and a code review can see
it. Do not "improve" this back into a prompt.

**`ConfirmImpact` cannot do this job.** It is a property of the *cmdlet*, and `Invoke-GraphOperation`
is one cmdlet serving every descriptor, so it cannot vary per operation. Its default `Medium`
against the default `$ConfirmPreference` of `High` means `ShouldProcess` returns true *without
prompting*.

**Graph's `/assign` is a REPLACE.** Whatever is omitted is unassigned, so a caller who posts one
assignment intending to add it silently removes every other. Every assignment write must ship
alongside the read that lets a caller fetch the current set first - enforced by a paired-descriptor
invariant.

**A write's declared permission is a claim only the service can settle.** `ManagedDevice.SyncDevice`
returns 403 with a `DeviceManagementManagedDevices.ReadWrite.All` token, which is what proves
`PrivilegedOperations.All` is genuinely required rather than over-declared. The three device actions
are permission-verified but operation-unverified; the lab app lacks that scope.

**`ManagedDevice.Wipe` will not be live-verified.** There is no safe way to prove a factory reset
works except by factory-resetting something. Its *gate* is verified against a real device id: `-WhatIf`
sends nothing and the un-forced call is refused. Verify the protection, not the destruction.

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
- Hard runtime dependency: `Microsoft.Graph.Authentication` (pinned minimum; MSAL delivery vehicle only, `Connect-MgGraph` never called).
- Lazy vault dependency: `Microsoft.PowerShell.SecretManagement` (tested at 1.1.2) and a registered vault extension are required only when resolving or mutating a vault-backed credential. Their absence must fail at that boundary with an actionable message; non-vault import and catalog inspection must remain usable.
- Module format: authored public/private scripts compiled into one `.psm1` under `output/`, with non-code assets copied separately.
- No Node, Bun, npm, or other package-manager workflow is defined.
- PSScriptAnalyzer is restored as a build dependency but is not a separate repository gate; no formatter, lockfile, or version file is defined. `.github/workflows/ci.yml` defines the six-job CI matrix.

## Testing & QA

`tests/New-ClientServicePrincipalCBA.Tests.ps1` exists and passes (57 tests, 12 contexts). Every test corresponds to a defect that actually occurred while creating the Ivy24 registration, and they share one failure mode: **the script reported success while not having done the thing.** Two are AST-based and worth reusing as patterns — one asserts no code sits inside a block comment (113 lines containing the entire permission-granting pipeline once did, so registrations had permissions configured and zero granted), the other asserts no variable is read that is never assigned (`$GraphAppId` and `$context` both silently expanded to empty strings without `Set-StrictMode`). Both were mutation-tested: each detector was confirmed to fail when its bug is reintroduced.

Implementation and deterministic tests are present; preserve these approved contracts as subsequent phases add or revise coverage:

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
