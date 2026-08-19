# GraphKit and TenantPulse product program design

**Date:** 2026-08-19  
**Status:** Design approved; written specification pending user review  
**Scope:** GraphKit and TenantPulse, including the recorded deferred end state  
**Delivery model:** Vertical release trains

## Summary

GraphKit and TenantPulse form one product system with two deliberately separate responsibilities.
GraphKit executes declared Microsoft Graph operations reliably. TenantPulse plans datasets, stores
snapshots, expands policy data, evaluates tenant-health checks, and renders findings.

The program completes three scopes back to back:

1. Complete the TenantPulse catalog and its consumer-facing coverage.
2. Complete the current GraphKit and TenantPulse product contracts, including privacy, scale,
   reliability, and verification debt.
3. Deliver the recorded deferred end state, including `GraphKit.Auth`, app-registration
   provisioning, the IntuneHealthAutomation phase-6 cutover, and a separate Azure Resource
   Manager provider for `TP.INT.0010`.

Work ships as vertical release trains. A train adds producer support in GraphKit when needed,
proves that support, consumes it in TenantPulse, proves the resulting behavior, and leaves both
repositories at independently releasable commits. Public publication is conditional rather than a
per-train requirement.

## Approved decisions

- Execute catalog completion, current-contract completion, and the recorded end state in that
  order.
- Use vertical release trains rather than a platform-first batch or a coordinated big bang.
- Keep GraphKit as the execution producer and TenantPulse as the analysis consumer.
- Do not represent a multi-request analysis walk as a Microsoft Graph endpoint descriptor.
- Keep Azure Resource Manager outside the Microsoft Graph operation pipeline.
- Replace transitive MSAL delivery behind the existing `IGraphTokenSource` boundary when
  `GraphKit.Auth` ships.
- Use safe autonomy. Source changes, tests, commits, pushes, CI, dry runs, and reversible Ivy24
  gates can proceed without another approval. Public publication, customer-tenant access or
  mutation, permission grants, credential changes, resource purges, and irreversible actions
  require explicit approval.
- Publish only when another machine must resolve a module through PSGallery for validation, or
  when the owner requests a public release. Use exact local packages or the existing versioned
  file channel otherwise.
- Never read, stage, commit, quote, inventory, or hand off `.env` contents. GraphKit's current
  `.env` ignore gap is an R0 source-hygiene defect.

## Current baseline

### GraphKit

- The published module version is `0.2.2`.
- Phases 1 through 4 are implemented. Certificate, client-secret, managed-identity, and
  vault-resolved bearer-token modes have separate live evidence.
- Phase 5 is implemented. Customer repoint verification, legacy-layer retirement, and deleted-app
  purge remain operator-gated actions.
- Before this specification commit, local `main` contained the `0.2.2`
  TenantPulse-unblocking descriptor commit and was one commit ahead of `origin/main`.
- GitHub CI has succeeded on earlier release SHAs, but the exact local `0.2.2` source SHA has not
  run remotely because it has not been pushed.
- Five older descriptors retain explicit live-verification debt: `NamedLocation`,
  `ConditionalAccessPolicy`, `AuthenticationMethodsPolicy`, `DeviceManagementScript`, and
  `DeviceCleanupRule`.
- `Microsoft.PowerShell.SecretManagement` remains a hard module dependency even for flows that do
  not use a vault. The intended lazy boundary is not complete.
- `GraphKit.Auth`, `New-GraphAppRegistration`, and the IntuneHealthAutomation phase-6
  authentication cutover are recorded but deferred.

### TenantPulse

- The published module version is `0.1.1`. Its runtime manifest declares GraphKit
  `ModuleVersion = '0.2.2'`, which is a minimum version rather than an exact pin.
- The local `main` branch contains the AP08 status correction and `TP.INT.0017`/`0018`, and is two
  commits ahead of `origin/main` as of this design.
- The catalog contains 53 checks. Forty-eight resolve against released GraphKit operations. Five
  remain honestly Pending:
  - `TP.INT.0009`: Windows diagnostic data processor configuration.
  - `TP.INT.0013`: Intune RBAC group protection.
  - `TP.INT.0014`: Endpoint Security BitLocker full-disk encryption.
  - `TP.INT.0015`: Endpoint Security LAPS configuration.
  - `TP.INT.0029`: Assigned and current security baselines.
- Phase 2 settings expansion is implemented and live-gated, but Settings Catalog assignments,
  Administrative Templates, assignment `intent`, expansion summary, default-on behavior, and
  scale work remain.
- Documented analysis gaps remain for Conditional Access group membership, transitive or
  group-based privileged-role assignments, application-registration credentials, Intune policy
  assignment verification, and non-JSON findings output.
- Dataset read and write paths materialize full object graphs. Manifest updates impose O(n) work
  per dataset write. Expansion drivers accumulate whole families in memory.
- Evidence redaction protects declared identities but leaves unmarked person-identifying Detail
  values unchanged.

## Version and unpublished package identity

Published versions are immutable. Neither repository rebuilds changed bytes under a version that
already exists on PSGallery or in a versioned file channel.

When a train changes GraphKit without requiring public publication, it produces a unique
prerelease package from the next semantic version. The package identity includes the train and
source revision, and the local pin records its digest. TenantPulse integration work resolves that
exact prerelease package from the local channel or an explicit bundle. It does not accept the
same-numbered stable gallery package as a substitute.

The stable TenantPulse manifest never claims a GraphKit version that is unavailable from its
selected distribution source. If cross-machine validation requires PSGallery, GraphKit first
publishes an approval-gated stable package from the already-tested bytes. TenantPulse then updates
its dependency, repacks, and reruns its gates against the gallery-resolved package.

No feed entry is overwritten. Multiple trains can accumulate under `Unreleased`, but every package
used across a repository or machine boundary has a unique version and digest.

TenantPulse's runtime manifest uses `RequiredVersion` for GraphKit. The build dependency file keeps
its separate restore-time pin. A host must not satisfy TenantPulse with newer GraphKit bytes that
the TenantPulse release never verified.

For a producer-consumer train, GraphKit completes package verification, source push, CI, and any
required live gate before handing an exact package to TenantPulse. Local TenantPulse work can use
the digest-pinned prerelease package. Before TenantPulse source is pushed, its CI environment must
be able to resolve that exact GraphKit version. TenantPulse CI currently resolves GraphKit from
PSGallery. Unless an alternate immutable CI-accessible source is implemented, that cross-machine
gate requires approval to publish the already-tested GraphKit package first. A consumer commit
must not depend on a package its CI environment cannot obtain.

## Product boundaries

### GraphKit owns execution

GraphKit owns:

- immutable tenant contexts and profile resolution;
- credential-reference resolution and token acquisition;
- Graph authority, cloud, tenant, and credential binding;
- descriptor loading and validation;
- request construction, paging, batching, deadlines, cancellation, retry, and throttling;
- operation permission metadata and permission analysis;
- normalized outcome certainty and evidence-safe result envelopes; and
- official, reusable Microsoft Graph operation primitives.

GraphKit does not own tenant-health checks, scoring, report semantics, or TenantPulse-specific
composite datasets. It does not become a universal CRUD API or a generic Microsoft API switchboard.

### TenantPulse owns analysis

TenantPulse owns:

- the check catalog and dataset requirements;
- deterministic collection planning and dependency ordering;
- snapshot persistence and schema migration;
- composite dataset plans over official GraphKit primitives;
- Settings Catalog, typed-policy, and Administrative Template expansion;
- conflict analysis, scoring, and findings;
- pseudonymization, evidence classification, and rendering; and
- provider-neutral collection failure mapping.

TenantPulse does not issue undeclared raw Microsoft Graph requests. Every Graph call must resolve
through a released GraphKit operation and pass the `Read` and `Safe` contract.

### Composite operations

The four remaining `*.Walk` names describe consumer workflows, not Microsoft Graph operations.
TenantPulse replaces them with explicit composite plans. Each plan declares its GraphKit primitive
operations, dependency order, identity joins, partial-failure behavior, and provenance.

If a composite requires a reusable Microsoft Graph primitive that GraphKit lacks, GraphKit adds the
official primitive first. GraphKit does not add a fake endpoint descriptor to satisfy a DatasetMap
name.

### Azure Resource Manager

`TP.INT.0010` reads Azure Resource Manager diagnostic settings. It does not enter GraphKit's
Microsoft Graph descriptor catalog.

A separate provider contract owns:

- the Resource Manager authority and token audience;
- Azure RBAC requirements;
- API-version selection;
- request, retry, throttle, and error semantics;
- resource ID validation; and
- provider provenance in the snapshot.

The provider can share GraphKit-owned identity request and result types after `GraphKit.Auth`
exists. No Graph operation or Graph permission metadata can stand in for an ARM call.

### GraphKit.Auth

`GraphKit.Auth` is a compiled adapter loaded in an isolated `AssemblyLoadContext`. It implements the
existing token-source contract and exposes only GraphKit-owned request and result types. No MSAL
type crosses the boundary.

The migration runs the transitive and isolated implementations against the same deterministic and
protected-live contracts. GraphKit removes `Microsoft.Graph.Authentication` only after all four
auth modes meet their applicable parity gates. Managed identity requires a newly created Azure
host for any new live proof.

## Data flow

```text
Check catalog
  -> deterministic collection manifest
  -> provider execution
       Graph: verified descriptor from the exact GraphKit package
       Composite: TenantPulse plan over verified GraphKit primitives
       ARM: separate Resource Manager provider
  -> immutable content-addressed snapshot
  -> optional expansion artifacts
  -> deterministic check evaluation
  -> pseudonymized finding envelope
  -> JSON and approved additional renderers
```

A Graph-backed dataset resolves a `{Type, Operation, ApiVersion}` tuple from the exact verified
GraphKit package. The operation
must declare `ThrottleClass = Read` and `ReplayPolicy = Safe`. API-version mismatch is a contract
failure, not a reason to send the request optimistically.

A composite dataset records every child operation, API version, status, and provenance. If one
child fails, the parent outcome records the missing scope. A partial response cannot become a
successful-looking empty dataset.

The ARM provider uses the same provider-neutral collection outcome shape but retains its own
authority, permission, request, and provenance fields.

## Collection outcomes

Each dataset record carries `Status` plus structured failure metadata:

- `Collected` carries neither a failure class nor gaps.
- `Partial` carries one or more `Gaps`; each gap identifies its scope and `FailureClass`.
- `Failed` and `Skipped` carry a top-level `FailureClass`.

Reason text provides bounded operator detail. It does not carry the only copy of status, failure
class, or gap scope.

| Status | Meaning |
| --- | --- |
| `Collected` | The provider returned the complete authoritative dataset required by the contract. |
| `Partial` | Authoritative rows exist, and every known missing child, page, or expansion is recorded. |
| `Failed` | No usable authoritative dataset exists because provider execution failed. |
| `Skipped` | No request was sent because a declared capability, gate, permission, license, or dependency prevented collection. |

Supported failure classes are `DescriptorPending`, `PlatformUnavailable`, `PermissionDenied`,
`LicenseRequired`, `GateUnknown`, `DependencyUnavailable`, `AuthenticationFailed`,
`DeadlineExpired`, `Cancelled`, `InvalidProviderData`, `ProviderFailed`, and `Indeterminate`.

Provider adapters map every native outcome explicitly:

- GraphKit `Succeeded` maps to `Collected`, unless a composite plan has recorded gaps and maps the
  parent to `Partial`.
- GraphKit `Failed` maps to `Failed` and the most specific supported failure class. A definite
  provider failure with no narrower classification uses `ProviderFailed`.
- GraphKit `DeadlineExpired` maps to `Failed` and `DeadlineExpired`.
- GraphKit `Cancelled` maps to `Failed` and `Cancelled`.
- An outcome whose certainty is indeterminate maps to `Failed` and `Indeterminate`.
- Missing descriptors, unsupported platforms, proven license gates, unknown gates, unavailable
  dependencies, and pre-request permission failures map to `Skipped` with their specific class.

The snapshot schema, writer, reader, manifest, evaluator, and renderers migrate together before a
composite dataset ships. The evaluator passes `Partial` rows and structured gap metadata to a rule
that explicitly accepts partial input. A rule that does not accept partial input returns
`NotApplicable` with the recorded gaps. No partial dataset becomes complete merely because it
contains one row.

Checks map status and failure class explicitly to `NotApplicable`, `Error`, or a bounded finding.
No collection failure, unsupported platform path, unknown license gate, or missing dependency
becomes `Pass`.

When Microsoft exposes no supportable API, `Skipped` plus `PlatformUnavailable` is a valid
product-complete outcome. It replaces misleading `descriptor-pending: awaiting GraphKit release`
text and remains visible in findings and status artifacts.

## Snapshot and scale invariants

- Snapshot files remain immutable and content-addressed.
- Streaming writers write to a same-directory temporary file, hash bytes while writing, fsync, and
  atomically rename the completed file.
- Manifest changes batch multiple entries and atomically replace the previous manifest.
- A manifest never points to an incomplete or unverified file.
- An interrupted run leaves either the previous valid manifest or identifiable resumable
  fragments.
- Readers reject schema versions they do not understand.
- Migration is explicit. Older readers never silently ignore new provider, provenance, or privacy
  fields.
- Evaluation order and serialized output remain deterministic across retries, streaming chunk
  boundaries, and worker counts.
- The settings-definition corpus path uses bounded-memory serialization and hashing. It does not
  require a second full in-memory copy.
- Live parallel fan-out remains disabled until the shared-context and throttle behavior is
  root-caused and proven against the real sender. Captured-payload speed does not prove live
  safety.

## Evidence and privacy contract

Every tenant-derived finding field declares one of these classes:

- identity requiring pseudonymization;
- secret or sensitive value requiring removal or irreversible redaction;
- safe technical value;
- safe operator label retained intentionally; or
- bounded operator text requiring explicit review.

This requirement covers the whole canonical finding, not only `evidence[]`. It includes `reason`,
error text, evidence identity and sort keys, evidence Detail, rule-supplied metadata, top-level
labels, and renderer-only fields.

Rules cannot rely on an optional `RedactDetailKeys` list or a length cap as the only protection.
The finding schema and rule loader enforce complete classification. Tenant-derived reason and
error values use a stable reason code plus classified arguments, or an equally enforceable
sanitization contract. Free text cannot carry an unclassified tenant identifier into a redacted
artifact.

Mutation tests insert identity-shaped, secret-shaped, policy-label, and safe technical values into
every class and every tenant-derived finding field. They prove both protection and retained
remediation value.

Redaction must not destroy safe labels, dates, IDs that are already pseudonyms, or configuration
metadata required to remediate a finding. `-Redact` protects identities and sensitive values; it
does not turn all Detail or reason fields into empty strings.

## Release trains

### R0: Source and release truth

- Add `.env` to GraphKit's ignore rules without reading the file.
- Reconcile stale GraphKit status claims about remotes, CI, publication, versions, and current
  distribution.
- Pack first, test the exact GraphKit `0.2.2` bytes, push the source, and require CI on that SHA.
- Change TenantPulse's GraphKit runtime dependency from minimum `ModuleVersion` semantics to exact
  `RequiredVersion` semantics.
- Verify TenantPulse's two local commits with the exact GraphKit package, push them, and require CI
  on that SHA.
- Prove the producer-consumer handoff rule with the current gallery-resolved `0.2.2` package.
- Keep both repositories source-clean except for protected ignored local secret files.
- Do not republish an existing immutable gallery version.

### R1: Outcome foundation and settings expansion

**R1a: Provider outcome and gate foundation**

- Version and migrate the snapshot, manifest, writer, reader, evaluator, and renderer contract to
  the two-dimensional `Status` and `FailureClass` model.
- Map GraphKit `Succeeded`, `Failed`, `DeadlineExpired`, `Cancelled`, and indeterminate outcomes
  completely.
- Pass `Partial` rows and structured gaps to explicitly partial-aware checks.
- Replace the stub license and feature-gate registry with deterministic gate resolution,
  persistence, and check mapping. `LicenseRequired` requires proven license evidence;
  unresolved gates use `GateUnknown`.
- Preserve compatibility with existing snapshots through an explicit migration rather than
  interpreting old reason strings.

**R1b: Settings expansion**

- Consume the released `ConfigurationPolicyAssignment.ListBeta` operation.
- Populate Settings Catalog assignment targets and typed assignment `intent`.
- Add Administrative Template expansion from released group-policy primitives.
- Emit the deferred expansion-summary dataset.
- Recompute conflict overlap from real assignments and eliminate assignment-derived `unknown`
  outcomes where data is authoritative.
- Replace stale documentation that says the assignment descriptor is unavailable.
- Keep expansion opt-in until R6 changes the public default contract.

### R2: Four composite Pending checks

- Replace `IntuneRbacGroupProtectionWalk.Walk` with an explicit composite plan over role
  assignments, groups, and restricted-management administrative-unit primitives.
- Replace the BitLocker and LAPS Walks with explicit policy-family and setting composition.
- Replace the security-baseline Walk with template, policy, version, and assignment composition.
- Add only official reusable GraphKit primitives that these plans require.
- Prove the BitLocker value mapping and LAPS template identity against live tenant data before
  clearing their Pending states.
- Preserve partial gaps and unsupported policy families explicitly.

### R3: Data-processor check disposition

- Research current official Microsoft documentation and service metadata.
- Probe the beta resource only through a controlled Ivy24 read.
- Ship `TP.INT.0009` only if the method, path, response shape, permission, and tenant behavior are
  proven.
- If Microsoft still exposes no supportable method, replace `DescriptorPending` with
  `PlatformUnavailable` and document the exact evidence and re-evaluation trigger.

### R4: Coverage completion

- Expand Conditional Access group references to membership data with bounded cycle and size rules.
- Include transitive and group-based privileged-role assignments where Microsoft exposes an
  authoritative read.
- Add the official Graph application-registration primitive and extend credential hygiene beyond
  service principals.
- Make applicable Intune checks assignment-aware instead of existence-only.
- Add at least one supported findings renderer beyond JSON without weakening the canonical JSON
  contract.
- Keep evidence caps explicit and report when a view is sampled or truncated.

### R5: Privacy contract complete

- Introduce enforced classification for every tenant-derived finding field.
- Migrate every shipped check, engine-generated reason and error, snapshot projection, and
  renderer.
- Replace free-text tenant-derived reasons with stable reason codes and classified arguments, or
  an equally enforceable sanitization contract.
- Remove obsolete ad hoc redaction paths only after all callers migrate.
- Prove redaction with mutation, snapshot, renderer, and path-containment tests.
- Re-run a redacted Ivy24 findings sweep and inspect the actual artifact.

### R6: Scale and default behavior

- Stream dataset collection, persistence, and reads.
- Remove whole-dataset deep clones from evaluation through immutable projections, bounded
  per-check materialization, or an equivalent isolation mechanism.
- Stream or bound renderer input so rendering does not restore the persistence memory peak.
- Batch manifest updates.
- Publish expansion families through fragment-and-merge rather than whole-family accumulation.
- Bound settings-definition corpus memory.
- Add end-to-end peak-memory gates that span collection, read, evaluation, and rendering for the
  50,000-row dataset and 5,000-policy expansion scenarios. The R6 plan records measured baselines
  and numeric pass limits before implementation.
- Root-cause the live RunspacePool slowdown and prove shared identity and throttle coordination.
- After performance, crash-recovery, compatibility, and live gates pass, replace the opt-in switch
  with a public API contract that makes settings expansion the default without violating
  `PSAvoidDefaultValueSwitchParameter`.

### R7: GraphKit platform debt

- Make non-vault flows usable without a hard SecretManagement import dependency while preserving
  actionable validation for persisted credentials.
- Close the five descriptor live-verification debts with the exact service permissions.
- Keep clean-machine, installed-package, import-order, sender, concurrency, and full matrix gates
  green.
- Reconcile design, status, README, changelog, and release claims with observed evidence.

### R8: GraphKit.Auth

- Define GraphKit-owned auth request and result types.
- Build and package the isolated adapter reproducibly.
- Implement certificate, client-secret, managed-identity, and fixed-bearer token sources behind
  the existing interface.
- Run deterministic dual-provider parity and import-order tests.
- Run applicable protected live gates.
- Remove the transitive Graph authentication dependency only after the migration gate succeeds.

### R9: Provisioning and IntuneHealthAutomation phase 6

- Convert the proven standalone certificate app-registration flow into
  `New-GraphAppRegistration` without removing the script before all callers migrate.
- Preserve role-grant verification that checks what the service actually granted.
- Package and install exact GraphKit dependencies on target hosts.
- Run same-session read-only customer repoint verification only after explicit approval.
- Keep a rollback window and previous pin until the new path is proven.
- Retire the legacy authentication layer only after approved customer verification.
- Purge deleted directory objects and rotate or revoke credentials only as explicit operator
  actions.

### R10: ARM provider and TP.INT.0010

- Implement the separate Resource Manager provider contract.
- Add deterministic authority, resource-ID, API-version, retry, and permission tests.
- Run a protected live diagnostic-settings read.
- Add the dataset and check only after the provider result and permission model are proven.
- Keep Graph and ARM provenance distinguishable through snapshot, finding, and renderer layers.

### R11: Closeout

- Remove obsolete Pending paths and stale fallback tests after each caller migrates.
- Reconcile every open roadmap, status, changelog, and README claim.
- Run clean-machine installs and end-to-end assessments from empty local state.
- Publish only if cross-machine validation requires gallery resolution or the owner requests a
  public release.
- If an operator approval is withheld, record exact commands, prerequisites, rollback, and
  evidence requirements, and keep the program status `Blocked` rather than claiming closeout.

## Train workflow

Each repository follows this development loop:

1. Write and approve the train-specific design and implementation plan.
2. Reproduce the defect or establish the missing observable contract.
3. Add a failing behavioral test when the train changes a permanent contract.
4. Implement the smallest complete vertical slice.
5. Run focused development verification.
6. Pack. The pack task performs `Clean` and creates the candidate build.
7. Run the full repository suite against the build produced by that pack.
8. Update every minimum-test ratchet location from the full result, then repeat pack and full test
   if the ratchet change modifies source.
9. Verify package identity and record the tested-file digest.
10. Run independent code review, silent-failure review where applicable, type-design review for
    new public types, and simplification.
11. If review or simplification changes source, repeat steps 6 through 10.
12. Commit and push the source.
13. Require the supported CI matrix on the exact train SHA.
14. Run protected Ivy24 validation when service behavior is part of the claim.
15. Run approval-gated customer or operator validation when Ivy24 cannot prove the real boundary.

A producer-consumer train completes GraphKit through its applicable step 14 before the consumer
handoff. It then creates an immutable exact-version package and digest pin for TenantPulse
development. Before TenantPulse is pushed, that exact GraphKit version must be available from the
source TenantPulse CI uses. Because the current workflow resolves from PSGallery, a new GraphKit
dependency triggers the explicit publication approval gate unless an alternate immutable
CI-accessible source has been implemented. After the handoff, TenantPulse updates
`RequiredVersion`, repeats the repository loop, and runs its own live gate.

Public publication remains conditional. When publication is required, publish the already-tested
artifact, verify the remotely installed bytes, and update the evidence ledger. Never push a
consumer commit whose CI dependency cannot resolve.

## Evidence ledger

Each deliverable records these states independently:

| State | Required evidence |
| --- | --- |
| Implemented | Source and migrated callers exist; obsolete paths are removed. |
| Deterministically verified | Focused and full local gates pass against the changed contract. |
| CI verified | The supported matrix passes on the exact source SHA. |
| Live verified | The protected tenant or approved customer run proves the service behavior claimed. |
| Published | The exact tested package is available from the selected channel and its installed bytes verify. |

A deliverable can reach product-complete status without `Published` when no cross-machine gallery
resolution is required. A service-dependent capability cannot reach live-verified status from a
mock, captured payload, metadata document, or successful import.

## Safety and rollback

- Use `-WhatIf` and descriptor impact gates for writes.
- Never live-verify a destructive device action by performing the destruction.
- Every reversible Ivy24 mutation records pre-state, applies one controlled change, reads it back,
  restores pre-state in `finally`, and confirms restoration independently.
- Stop before customer-tenant access, permission grants, credential operations, resource purges,
  public publication, or irreversible actions and obtain explicit approval.
- Keep old pins, credentials, and caller paths until the new path passes its own same-session gate.
- If verification fails, restore the previous pin or provider reference before doing more work.
- Do not catch an infrastructure failure and report a more confident business diagnosis.

## Program completion criteria

The program is complete when all of these statements are true:

- Both repositories are pushed, CI-green on their exact final SHAs, and source-clean except for
  ignored local secrets.
- Every Graph-backed dataset resolves against an exact verified GraphKit package through an
  official primitive or an explicit composite plan.
- No DatasetMap row uses `Pending` after its capability exists.
- Unsupported service capabilities use `PlatformUnavailable` with an evidence-backed recheck
  trigger rather than an indefinite release promise.
- When executed against a tenant, all 53 current checks and every subsequently approved check
  produce an honest collected, license-gated, permission-gated, platform-unavailable, partial,
  dependency-unavailable, failed, or skipped outcome. None silently pass on missing data.
- Settings assignments, Administrative Templates, intent, expansion summary, and conflict overlap
  are complete.
- Snapshot persistence, evaluation, expansion, and rendering meet the approved end-to-end memory,
  streaming, atomicity, and determinism gates.
- Every tenant-derived finding field, including reason and error text, has enforced privacy
  classification, and all renderers preserve it.
- The documented Conditional Access, privileged-role, credential, assignment, and rendering gaps
  are resolved or carry an evidence-backed platform limitation.
- GraphKit's non-vault flows are genuinely lazy, and its older descriptor verification debt is
  closed.
- `GraphKit.Auth` replaces transitive MSAL delivery without changing TenantPulse's public contract.
- The separate ARM provider supports `TP.INT.0010` without entering the Graph operation catalog.
- IntuneHealthAutomation's approved customer cutover and legacy authentication retirement are
  complete.
- Approved destructive operator cleanup is complete. If required approval is withheld, the
  program remains `Blocked`; an executable runbook does not make it `Complete`.
- Deterministic, CI, live, customer, and publication claims remain separately evidenced.

## Explicit non-goals

- A universal generic mutation API.
- A global beta mode.
- Blind POST or PATCH replay after ambiguous failures.
- Persistent access-token storage.
- Process-global Graph identity state.
- Fake Graph descriptors for composite or ARM operations.
- Automatic destructive-device live tests.
- Big-bang migration of unrelated scripts or the whole IntuneHealthAutomation cache layer.
- Public publication as a substitute for verification.

## Planning decomposition

This document governs the program. It is not one implementation plan. Each release train receives
a focused spec and plan because the trains have different schemas, permissions, live gates, and
rollback boundaries.

Implementation planning starts with R0. R0 establishes source truth, secret-ignore safety, exact
package verification, push parity, and CI evidence before any new feature work begins.
