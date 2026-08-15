# Repository Guidelines

## Project Overview

GraphKit is planned as an app-only, multi-tenant Microsoft Graph execution and analysis layer with explicit Intune and Entra operation semantics. It is not a generic Graph SDK or an OAuth implementation. Its core value is reliable request execution: immutable tenant contexts, operation metadata, semantics-aware retry/throttling, permission analysis, and evidence export.

**Repository status:** design-only. The only implemented project artifact is `docs/superpowers/specs/2026-08-14-graphkit-design.md`; no module scaffold, source, tests, build files, or CI workflows exist yet. Treat the design as approved intent, not runnable behavior.

## Architecture & Data Flow

Planned flow:

1. `Register-GraphTenant` persists non-secret profile metadata; credentials stay in `Microsoft.PowerShell.SecretManagement`.
2. `Get-GraphContext` resolves a profile into an immutable runtime context before parallel work begins.
3. Public commands resolve an operation descriptor from `source/Data/Operations/*.psd1`.
4. `Invoke-GraphRequest` validates URI/query/version/cloud/permission rules, then calls `Invoke-MgGraphRequest` from `Microsoft.Graph.Authentication`.
5. The request pipeline handles paging, deadlines, cancellation, scoped admission control, and semantics-aware retry.
6. Results return as `PSCustomObject` values with `PSTypeName` `GraphKit.<Type>` and provenance such as `_Tenant`, `_RetrievedUtc`, `_GraphPath`, and `_ApiVersion` where applicable.
7. `Export-GraphResult` writes CSV, JSON, Markdown, or redacted vault evidence.

Preserve these boundaries:

- Authentication and token acquisition belong to `Microsoft.Graph.Authentication`; do not build another OAuth client or persistent access-token cache.
- API version is per-operation metadata, never a global beta mode.
- Generic reads may use `Get-GraphObject`; do not introduce a universal generic mutation API.
- IntuneHealthAutomation retains reports, Excel processing, checkpointing, console UI, and caching until the later cutover.
- A current context is interactive convenience only. Low-level work must accept `-Context` or `-ProfileName` and resolve it before entering runspaces.

Example planned usage:

```powershell
$context = Get-GraphContext -Profile ivy24
Get-GraphObject -Context $context -Type ManagedDevice
```

## Key Directories

Current:

- `docs/superpowers/specs/` — approved design decisions and the present source of truth.

Planned after Sampler scaffolding:

- `source/Public/` — exported PowerShell functions; one command per file.
- `source/Private/` — request, retry, URI, throttle, and evidence helpers.
- `source/Data/Operations/` — `.psd1` operation descriptors governing behavior.
- `source/Formats/` — PowerShell formatting definitions.
- `tests/Unit/` — deterministic retry and policy tests using injected dependencies and virtual time.
- `tests/Adapter/` — HTTP-result normalization and loopback-server tests.
- `tests/Concurrency/` — real-runspace throttle and isolation tests.
- `tests/QA/` — repository/module quality checks; exact scope is not yet defined.
- `output/` — generated package output; do not edit it directly.

## Development Commands

No repository-defined build, test, lint, format, run, or publish command exists yet. Do not invent commands or report checks as runnable until the scaffold adds them.

The approved one-time scaffold command is:

```powershell
New-SampleModule -ModuleType SimpleModule
```

Run it manually: Sampler's Plaster template prompts for Git usage and cannot be scripted non-interactively. Once present, treat `build.ps1`, `build.yaml`, and `RequiredModules.psd1` as authoritative for exact commands.

## Code Conventions & Common Patterns

- Use standard PowerShell `Verb-Noun` names with the `Graph` noun prefix, for example `Get-GraphContext`, `Invoke-GraphRequest`, and `Test-GraphPermission`.
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

Planned:

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
- Sole planned runtime dependency: `Microsoft.Graph.Authentication`.
- Module format: authored public/private scripts compiled into one `.psm1` under `output/`, with non-code assets copied separately.
- No Node, Bun, npm, or other package-manager workflow is defined.
- No PSScriptAnalyzer, formatter, lockfile, version file, or CI configuration exists yet.

## Testing & QA

No tests currently exist. When implementation begins, commit real `*.Tests.ps1` files and preserve these approved contracts:

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

Coverage is intended to use JaCoCo output through Sampler/Pester, but no threshold or command is defined yet.
