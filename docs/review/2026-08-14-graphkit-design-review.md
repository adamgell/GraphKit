# GraphKit Design Re-review

- **Date:** 2026-08-14
- **Reviewed:** `docs/superpowers/specs/2026-08-14-graphkit-design.md`
- **Scope:** Architecture, authentication, transport security, reliability, testing, packaging, migration, and cutover
- **Verdict:** Materially improved, but not implementation-ready

## Resolved Since the Previous Review

- GraphKit owns `HttpClient` transport and retry decisions; the SDK no longer hides physical retries.
- Credential forwarding remains enforced under `-Raw`, with explicit Graph and external-download policies.
- `GraphKit.OperationResult` separates data from outcome, certainty, telemetry, and provenance.
- `Microsoft.PowerShell.SecretManagement` is recognized as a runtime dependency.
- Descriptors now precede Permissions at the phase level.
- Deterministic and live CI lanes are separated.
- Secret retirement is an explicit completion gate.

## Blocking Findings

### P0 — `Use-GraphTenant` Still Uses Rejected SDK State

The revised architecture says `Connect-MgGraph` is never called and the SDK context is unusable (`:116-164`, `:200-201`), but:

- `Update-AccessToken` still maps to an “SDK token cache” (`:262`).
- `Use-GraphTenant` still reads `Get-MgContext` and skips reconnection (`:387-388`).

This path either consults irrelevant state or reintroduces the process-global identity source removed by the redesign.

**Correction:** make `Use-GraphTenant` select only an immutable GraphKit context. Delete all `Get-MgContext` and reconnection behavior. Change the retired-token mapping to the per-context GraphKit token-source cache.

### P0 — MSAL Is Consumed Through a Transitive Implementation Detail

The plan requires `Microsoft.Graph.Authentication` solely because it currently contains `Microsoft.Identity.Client.dll` (`:188-208`, `:792`). The parent module does not provide a stable public contract for the private assembly’s location, load timing, or exact version. The first MSAL loaded by Az or PSResourceGet may win instead.

A minimum version on `Microsoft.Graph.Authentication` does not prove which MSAL binary GraphKit is using. The plan itself notes that PSResourceGet’s older MSAL is present in effectively every session (`:190-196`).

**Correction:** own a supported MSAL boundary:

- Build a small compiled `GraphKit.Auth` adapter.
- Reference an explicit `Microsoft.Identity.Client` package version.
- Load it in an isolated `AssemblyLoadContext`.
- Expose only GraphKit-owned token request/result contracts.
- Remove `Microsoft.Graph.Authentication` as a runtime dependency.

If the transitive approach remains, document it as an accepted compatibility constraint and test all supported module import orders in fresh processes.

### P0 — Secret Retirement Precedes Caller Cutover

Phase 5 rotates secrets and deletes plaintext sources (`:908-913`). Phase 6 then repoints IntuneHealthAutomation (`:915-917`). Completing phase 5 first invalidates credentials still used by current launchers and the duplicated IHA authentication layer.

**Correction:** make deployment and retirement one ordered cutover gate:

1. Inventory legacy callers.
2. Import and verify GraphKit profiles.
3. Publish and pin GraphKit.
4. Repoint every caller.
5. Verify reads and controlled writes.
6. Rotate credentials.
7. Remove plaintext sources.
8. Reverify with rotated credentials.

Alternatively, move legacy callers to SecretManagement before rotation.

### P0 — External Bearer Tokens Are Not Tenant-Bound

Bearer profiles accept an opaque provider or vault token (`:243-247`). The transport validates only the Graph host (`:503-505`), while telemetry, provenance, and permission commands trust the configured context tenant (`:673-694`, `:709-716`). Commercial Graph uses the same host across tenants.

A Tenant B token attached to a Tenant A profile can succeed against B while results are stamped as A.

**Correction:**

- Add `VerifiedTenantId` and verification state to token-source results.
- Require `Context.VerifiedTenantId == TargetTenantId` immediately before every write.
- Reject unverified bearer contexts for permission mutation and tenant-stamped evidence.
- Restrict unverifiable fixed bearer tokens to explicitly unverified/read-only operations.
- Do not treat JWT claims as authoritative identity.

## High-Priority Design Findings

### P1 — Core Increments Remain Dependency-Inverted

The design says contracts must precede consumers (`:874-888`), but:

- Retry is implemented in 1.2 before descriptors in 1.3.
- URI/cloud policy is implemented in 1.4 before contexts in 1.5.
- Gate 1.1 says operation data loads before the loader exists.

**Correction:** reorder Core:

1. Scaffold/package and verify asset presence.
2. Descriptor schema, validator, strategy registry, and minimal descriptors.
3. Immutable context and token-source interfaces.
4. Normalized transport, deadlines, and retry engine.
5. Paging and URI security.
6. Authentication and vault providers.
7. Throttling and runspace coordination.
8. Protected Ivy24 smoke.

### P1 — Contexts Need a Token-Source Abstraction

The plan describes contexts as owning a confidential MSAL client (`:169-170`, `:202-204`, `:488-489`) while supporting managed identity, fixed bearer tokens, and caller providers (`:243-247`, `:358-375`). These modes do not share one acquisition or refresh API.

Managed identity uses `ManagedIdentityApplicationBuilder` and `AcquireTokenForManagedIdentity`, not `ConfidentialClientApplicationBuilder` and `AcquireTokenForClient`. See [Managed identity with MSAL.NET](https://learn.microsoft.com/entra/msal/dotnet/advanced/managed-identity).

**Correction:** contexts should own `IGraphTokenSource`:

```text
Acquire(forceRefresh, cancellation)
CanRefresh
AuthMode
Audience
VerifiedTenantId
ClientId
ExpiresOn
```

Implement confidential-client, managed-identity, provider, and fixed-bearer sources separately. Retry once after `401` only when `CanRefresh`; fixed bearer tokens fail immediately.

### P1 — Descriptor Schema Cannot Drive the Promised Pipeline

The sample descriptor (`:402-419`) omits fields required elsewhere:

- `OperationKind`
- `HandlerStrategyId`
- typed permission requirements
- supported auth modes
- `CredentialPolicy`
- external host allowlist
- `ResourceFamily`
- read/write throttle class

It also stores one static `RetrySafety`, although the same POST may be rejected before execution on `429` and ambiguous after timeout or `503` (`:549-570`).

**Correction:**

- Keep intrinsic replay policy in descriptors: `Safe`, `Conditional`, `Reconciliable`, `NeverReplay`.
- Model attempt certainty separately: `Rejected`, `Ambiguous`, `MayHaveCommitted`, `Succeeded`.
- Publish one normative versioned descriptor schema containing handler, credential, permission, and throttle fields.
- Add cross-field validation; for example, `CredentialPolicy=None` requires explicit allowed hosts.

### P1 — Tests Do Not Exercise the Real Sender or Token Isolation

Unit tests inject `Send`, and adapter tests still refer to an “HTTP cmdlet” while concentrating on result normalization (`:807-837`). These tests can pass even when the actual `HttpClient` follows redirects, forwards credentials incorrectly, ignores split cancellation, or contains a retrying handler.

The authentication gate proves one Ivy24 acquisition but not context isolation or token single-flight (`:895-900`).

**Correction:** run loopback tests through the built sender and assert:

- redirects are disabled or validated per hop
- `GraphBearer` attaches only to exact Graph authorities
- `None` never carries authorization
- connection, header, and body cancellation boundaries work
- one GraphKit attempt equals one handler send
- concurrent contexts receive only their own tokens
- acquisitions collapse to one call per cache key
- `401` force-refresh remains context-local

### P1 — Build and Delivery Gates Lack Executable Commands

The plan says every increment needs an exact command (`:887-888`), but the phase table supplies only prose conditions. Gate 1.1 imports loose `output/` files instead of installing the distributable package (`:894`).

The private channel remains unspecified (`:915-917`): no repository, version source, publish/install commands, integrity check, retention policy, or exact IHA pin.

**Correction:** define canonical commands for dependency restore, build, deterministic tests, package creation, temporary-repository registration, exact package installation, installed-package smoke, private publication, and the IHA version update. Promote the exact tested package bytes without rebuilding.

## Additional Corrections

- **Vault validation:** do not fail module import merely because no vault extension is registered (`:793`). Validate only when resolving or mutating a persisted vault-backed credential. Managed identity, injected credentials, help, catalog inspection, and CI must remain usable without a vault.
- **Permission contexts:** home-tenant application configuration and customer-tenant grants require separate authenticated contexts (`:709-760`). Missing home access should produce `Configured = Unknown`, not false.
- **Batch results:** one envelope cannot represent mixed successful, failed, and indeterminate subrequests (`:655-663`, `:686-700`). Return one ordered `OperationResult` per original subrequest.
- **Profile paths:** profile `Name` becomes an export path segment (`:354-360`, `:775-776`). Introduce a strict path-safe `ProfileId`; canonicalize output paths and verify they remain beneath configured roots.
- **PII:** the evidence assertion checks tenant ID, client ID, secret, and token but not general PII (`:772-781`). Construct vault evidence from an allowlisted summary DTO and reject unknown fields.
- **Profile persistence:** add `SchemaVersion`, explicit migrations, atomic replacement, backup recovery, and an interprocess lock for `~/.graphkit/profiles.json`.
- **Result semantics:** add `Cancelled`; define `-PassThruResult` as an alternate envelope-only output mode; preserve full envelopes in JSON when requested.
- **Public naming:** standardize on `-ProfileName`; the example still uses `-Profile` (`:342-347`).
- **CI runtime selection:** install and assert the exact PowerShell version in each matrix row.
- **Live tests:** make Ivy24 tests scheduled and release-gating, bind results to the package digest, and guarantee mutation cleanup even after assertion failure.

## Recommended Revision Order

1. Remove the remaining SDK context path.
2. Select a supported, isolated MSAL packaging model.
3. Correct cutover and credential-rotation order.
4. Define tenant-verified token-source contracts.
5. Publish the normative descriptor schema and retry-state model.
6. Reorder Core around descriptor and context contracts.
7. Add real-sender and multi-context authentication tests.
8. Define canonical package commands, private channel, and exact IHA pinning.
