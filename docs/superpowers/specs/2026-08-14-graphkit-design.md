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

The payoff runs both directions. GraphKit alone stays fast and dependency-free. Importing
both yields a shared tenant context that does not exist today:

```powershell
Use-GraphTenant ivy24              # authenticate once
Get-GraphObject CompliancePolicy   # ad-hoc, instant
Invoke-IntuneHealthCheck           # full IHA run, same tenant, no re-auth
```

And IntuneHealthAutomation inherits the throttling handling and test suite it currently lacks.

## Scope

### Moves into GraphKit

| Area | From |
| --- | --- |
| Auth | `Get-CBAToken`, `Update-AccessToken`, `Set-GraphEnvironment`, `Get-SecretsConfiguration` |
| Tenants | `Save-/Remove-TenantConfiguration`, `New-TenantConfigurationPrompt`, `Show-TenantManagementMenu` |
| Request core | `Invoke-IntuneGraphRequest`, `Invoke-ParallelGraphRequest`, `Get-GraphUrl` |
| Permissions | `Test-GraphPermissions`, `Get-TokenPermissionAnalysis`, `Get-AppRegistrationPermissions`, `Grant-IntuneAppPermissions` (~1,400 lines, generalized off the health check's fixed permission set) |

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

New private repo at `~/repo/GraphKit` → `github.com/adamgell/GraphKit`.

```
GraphKit/
  GraphKit.psd1 / GraphKit.psm1
  Public/
    Register-GraphTenant, Get-GraphTenant, Use-GraphTenant,
    Remove-GraphTenant, Test-GraphTenant
    Invoke-GraphRequest, Invoke-GraphBatch
    Get-GraphObject, Get-GraphObjectType
    Test-GraphPermission, Get-GraphTokenPermission,
    Get-GraphAppRegistrationPermission, Grant-GraphAppPermission
    Export-GraphResult
  Private/
    Get-GraphToken, Invoke-GraphRetry, Resolve-GraphUri,
    ConvertFrom-JwtPayload, Write-VaultEvidence
  Data/ObjectTypes.psd1
  Formats/GraphKit.Format.ps1xml
  Tests/
  THIRD-PARTY-NOTICES.md
```

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
| `AuthMethod` | `Certificate` \| `ClientSecret` \| `BearerToken` |
| `Environment` | `Global` \| `USGov` \| … (IHA already supports this) |

**`Kind` governs taxonomy validation.** Only `Kind = customer` validates `Name` against the
CDW KB `SCHEMA.md` customer tag list. Lab and internal profiles are exempt — `ivy24` is a lab
tenant and is not, and should not be, a customer tag.

**Migration is a first-class command.** `Register-GraphTenant -FromLegacyConfig` imports both
IntuneHealthAutomation's `config/secrets.json` tenant array and the `Start-WithConsole *.cmd`
launchers, moving secrets into the vault so nothing is retyped and the plaintext copies can be
deleted.

### Request core

`Invoke-GraphRequest` — promoted from `Invoke-IntuneGraphRequest`, preserving paging, URI
resolution, and token-expiry detection. Adds `ConsistencyLevel: eventual` automatically when
`$count`, `$search`, or advanced `$filter` appear, and a `-Beta` switch.

`Invoke-GraphBatch` wraps `/$batch` at the 20-request limit.

### Throttling

The headline gap fix.

- Honor `Retry-After` in **both** forms — delay-seconds and HTTP-date.
- Exponential backoff with jitter when the header is absent.
- Retry on 429, 503, 504, and transient socket errors. Default 5 attempts, configurable.
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

**Pester 6.1.0** and **PowerShell 7.4** as the manifest floor.

The floor is a constraint, not a preference: Pester 6 targets Windows PowerShell 5.1 and
PowerShell 7.4+, having dropped PowerShell 6 and early 7 builds. 7.4 is chosen over 7.5
because Pester is a test-time dependency only, and customer jump boxes and CI images run LTS;
requiring 7.5 would risk an import failure elsewhere for no gain. Local development runs 7.5.4.

This also forces a correction during cutover: IntuneHealthAutomation declares 7.2, which is
past end of support.

## Testing

Pester 6.1.0, `Invoke-RestMethod` mocked, no live Graph calls in CI. Tests are **committed** —
the current state of zero tracked test files behind a green CI badge is itself a defect.

Use the v6 dash-style assertions exclusively, with `Should.DisableV5 = $true`. Both syntaxes
work by default in v6; pinning prevents drift back to v5 style in a greenfield suite. Mock
verification uses `Should-Invoke` / `Should-NotInvoke`.

Three v6 behaviors are load-bearing here:

- `Assert-MockCalled` and `Assert-VerifiableMock` are removed, and **mock fall-through to the
  real command is gone**. In v5 a mis-scoped `Invoke-RestMethod` mock could silently fall
  through and hit real Graph; in v6 it cannot.
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
