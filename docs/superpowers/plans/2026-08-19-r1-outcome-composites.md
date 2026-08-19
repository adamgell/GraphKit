# R1 Outcome Foundation and Composite Checks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace TenantPulse's five honest `Pending` collection paths with explicit provider outcomes and tested composite plans, while adding only official reusable GraphKit primitives and preserving the GraphKit/TenantPulse product boundary.

**Architecture:** GraphKit remains the single-operation Microsoft Graph execution layer. TenantPulse owns collection plans, joins, compact evidence rows, check semantics, and partial-gap handling. The five pending entries are not implemented as a generic GraphKit `Walk` strategy: four become explicit TenantPulse plans over released primitives, and the Windows data-processor entry receives a controlled disposition based on live service evidence.

**Tech Stack:** PowerShell 7.4+, Pester 6.1.0, Sampler 0.120.1, ModuleBuilder 3.1.8, GraphKit 0.2.2 as the current producer baseline, TenantPulse snapshot and assessment pipelines, and protected Ivy24 read-only verification.

---

## Global constraints

1. Work only in the isolated branches `product/r1-outcome-composites` at:
   - `/Users/Adam.Gell/repo/GraphKit/.worktrees/r1-outcome-composites`
   - `/Users/Adam.Gell/repo/TenantPulse/.worktrees/r1-outcome-composites`
2. Do not modify either repository's `r0-source-truth` worktree. R0 invariant 10 forbids operation descriptors, settings assignments, outcome-model migration, and other R1 work there.
3. Do not inspect, print, stage, copy, or commit any `.env` file.
4. Do not invent Graph operation names or a generic GraphKit `Walk` strategy.
5. GraphKit descriptors may be added only for official, reusable single-operation Microsoft Graph endpoints whose method, path, response shape, API version, permission, and tenant behavior are proven.
6. Every Graph-backed dataset must resolve an exact `{Type, Operation, ApiVersion}` tuple from the exact GraphKit package used by TenantPulse.
7. A partial child collection must never become an empty successful dataset or a successful-looking `Pass`.
8. Keep all composite fan-out sequential until live shared-context and throttle behavior is root-caused and proven. Captured-payload speed does not prove live parallel safety.
9. All work in this plan is read-only. No live mutation, credential operation, tenant switching, customer access, destructive test, or publication occurs without a separate explicit operator approval.
10. Pack before test. A `pack` task cleans and creates the candidate build; the full suite must run after that pack and against its generated module.
11. Separate evidence claims: implemented, deterministically verified, CI verified, live verified, and published.
12. Existing released descriptor-backed areas remain unchanged unless a focused test proves a contract defect. This plan does not redo authorization policy, directory settings, PIM, cross-tenant, connectors, branding, feature updates, or Autopilot descriptor work already present in GraphKit 0.2.2.

## Current pending contract

TenantPulse's authoritative `source/Data/DatasetMap.psd1` contains exactly five pending entries:

- `dataProcessorServiceForWindowsFeaturesOnboarding`
- `intuneRbacGroupProtection`
- `endpointSecurityDiskEncryptionPolicies`
- `endpointSecurityLapsPolicies`
- `securityBaselinesAssignedAndCurrent`

The existing check functions already define the compact row contracts:

- RBAC: `roleDefinitionName`, `groupId`, `groupDisplayName`, `isManagementRestricted`, `isAssignableToRole`.
- BitLocker: `policyId`, `policyName`, `isFullDiskEncryption`.
- LAPS: `policyId`, `policyName`, `backsUpToEntra`, `hasSufficientComplexity`, `hasSufficientLength`, `hasPostAuthAction`.
- Security baseline: `id`, `name`, `templateFamily`, `hasAssignment`, `isDeprecated`, with native Boolean values.
- Data processor: one singleton row with `hasValidWindowsLicense` and `areDataProcessorServiceForWindowsFeaturesEnabled`.

The first four composite plans must also carry provider provenance and structured gaps outside the compact rule rows. They must distinguish an authoritative empty result from a partial result with zero rows.

---

### Task 1: Define the provider outcome and gap contract

**Repository:** TenantPulse

**Files:**
- Create `source/Private/Collect/New-PulseCollectionOutcome.ps1`.
- Create `source/Private/Collect/New-PulseCollectionGap.ps1`.
- Modify `source/Private/Snapshot/Write-PulseDataset.ps1`.
- Modify `source/Private/Snapshot/Read-PulseDataset.ps1`.
- Modify `source/Private/Snapshot/Get-PulseSnapshotManifest.ps1`.
- Modify `source/Private/Snapshot/Get-PulseSnapshotStore.ps1`.
- Modify `source/Private/Snapshot/Set-PulseManifestEntry.ps1`.
- Add focused tests under `tests/Unit/Collect/`, `tests/Unit/Snapshot/`, and `tests/Unit/Evaluate/`.

**Contract:** Every dataset result is a record with these fields:

```powershell
[pscustomobject]@{
    Dataset       = [string]
    Status        = 'Collected' # Collected|Partial|Failed|Skipped
    Rows          = [object[]]
    Gaps          = [object[]]
    FailureClass  = [string] $null
    ReasonCode    = [string]
    Detail        = [hashtable]
    Provider      = [string]
    ApiVersion    = [string]
    Operations    = [object[]]
}
```

Each gap is:

```powershell
[pscustomobject]@{
    Scope         = [string]
    FailureClass  = [string]
    ReasonCode    = [string]
    Detail        = [hashtable]
    Operation     = [string]
    ApiVersion    = [string]
}
```

Supported failure classes are exactly `DescriptorPending`, `PlatformUnavailable`, `PermissionDenied`, `LicenseRequired`, `GateUnknown`, `DependencyUnavailable`, `AuthenticationFailed`, `DeadlineExpired`, `Cancelled`, `InvalidProviderData`, `ProviderFailed`, and `Indeterminate`.

- [ ] Write failing tests for `Collected`, `Partial`, `Failed`, and `Skipped` records.
- [ ] Write failing tests that reject missing `Status`, invalid status values, invalid failure classes, and a `Partial` record without at least one gap.
- [ ] Write failing tests that prove a `Collected` record has no failure class or gaps.
- [ ] Implement constructors and validation using existing PowerShell record conventions, not public PowerShell classes.
- [ ] Add explicit schema-version migration for existing snapshots. Older readers must reject unknown versions; they must not infer status from historical reason text.
- [ ] Run the focused TenantPulse outcome and snapshot tests.
- [ ] Commit the task without running formatters, linters, or the full repository suite.

**Acceptance:** Focused tests prove the two-dimensional status/failure-class contract and deterministic serialized field order. Existing released snapshot fixtures continue to load through the explicit migration path.

---

### Task 2: Make gates deterministic and map them to provider outcomes
**Files:**
- Modify `source/Private/Evaluate/Get-PulseGateStatus.ps1`.
- Modify `source/Private/Evaluate/Invoke-PulseEvaluation.ps1` only where gate outcomes must map to collection failure classes.
- Modify `source/Private/Checks/Test-PulsePimPermanentAssignments.ps1` only where it consumes the gate result.
- Add `tests/Unit/Evaluate/Get-PulseGateStatus.Tests.ps1`.
- Add `tests/Unit/Evaluate/PulseGateOutcomeMapping.Tests.ps1`.

**Required behavior:**

```powershell
Get-PulseGateStatus -Gate 'EntraP2'
# returns a deterministic record with Status = Available, Unavailable, or Unknown
```

- `Available` allows collection.
- `Unavailable` produces `Skipped` with `FailureClass = LicenseRequired`.
- `Unknown` produces `Skipped` with `FailureClass = GateUnknown`.
- Gate resolution must use collected license evidence or an explicitly injected provider; it must not guess from a missing dataset.
- A permission denial from a Graph operation remains `PermissionDenied`, not `LicenseRequired`.
- No unknown gate may evaluate as `Pass`.

- [ ] Write failing tests for available, unavailable, and unknown `EntraP2` states.
- [ ] Write failing tests that distinguish permission denial from a proven license failure.
- [ ] Implement deterministic gate resolution and provider-outcome mapping.
- [ ] Update PIM evaluation to consume the new gate result without changing its permanent-active assignment rule.
- [ ] Run focused gate and PIM tests.
- [ ] Commit the task without running formatters, linters, or the full repository suite.

**Acceptance:** `TP.ENT.0022` can report a proven license skip or unknown gate without pretending the PIM dataset was collected, and existing PIM rows still evaluate identically when the gate is available.

---

### Task 3: Make collection manifest and provider adapters partial-aware

**Repository:** TenantPulse

**Files:**
- Modify `source/Private/Collect/Get-PulseCollectionManifest.ps1`.
- Modify `source/Private/Collect/Invoke-PulseCollection.ps1`.
- Modify `source/Private/Collect/Assert-PulseReadOnlyDescriptor.ps1`.
- Modify `source/Private/Snapshot/Write-PulseDataset.ps1` and its reader counterpart.
- Add tests under `tests/Unit/Collect/` and `tests/Unit/Snapshot/`.

**Required behavior:**

- Released single-operation datasets continue to use the existing exact descriptor assertion.
- `Pending` is no longer a runtime implementation path for a capability that has a plan. A pending row may remain only until its plan's package and live gate complete.
- Composite plans return `Operations`, `Rows`, and `Gaps` together.
- A child failure records its scope and operation. It does not silently remove the parent row.
- A composite with no rows is `Collected` only when every child proves the authoritative empty state.
- A composite with any unresolved child is `Partial` when usable authoritative rows exist, otherwise `Failed` or `Skipped` according to the provider outcome.
- Manifest order remains dependency-first and deterministic.

- [ ] Add failing tests for one successful composite child and one failed child with retained rows and a structured gap.
- [ ] Add failing tests for an authoritative empty composite versus a zero-row partial composite.
- [ ] Add failing tests for dependency failure propagation and cycle rejection.
- [ ] Implement plan dispatch through a narrow provider-plan registry keyed by dataset name. Do not add a generic GraphKit strategy.
- [ ] Keep all plan calls sequential and pass the resolved immutable Graph context through each call.
- [ ] Run focused collection and snapshot tests.
- [ ] Commit the task without running formatters, linters, or the full repository suite.

**Acceptance:** The collector and snapshot layer preserve rows, gaps, operation provenance, and deterministic ordering across partial and failed composite collection.

---

### Task 4: Implement the Intune RBAC group-protection plan

**Repository:** TenantPulse, with GraphKit changes only if an official primitive is missing.

**Files:**
- Create `source/Private/Collect/Invoke-PulseIntuneRbacGroupProtectionPlan.ps1`.
- Modify `source/Data/DatasetMap.psd1` only at the cutover step after package and live gates.
- Modify `source/Data/Checks/TP.INT.0013.psd1` only to accept structured partial outcomes if required by the outcome contract.
- Modify `source/Private/Checks/Test-PulseRbacGroupsProtected.ps1` only to consume the new gap-aware envelope; preserve its rule semantics.
- Add `tests/Unit/Collect/IntuneRbacGroupProtectionPlan.Tests.ps1`.
- Add GraphKit primitive descriptors and tests only when the controlled service probe proves a missing official endpoint.

**Plan contract:**

1. Resolve and validate the released `DeviceManagementRoleDefinition.List` and `DeviceManagementRoleAssignment.List` descriptors.
2. Identify group-backed role assignments.
3. Resolve each required group through the released `Group.Get` select path.
4. Emit one compact row per distinct group and preserve role names.
5. Preserve every failed child lookup as a gap.
6. Treat no group-backed assignments as an authoritative collected empty result only after the assignment collection completed successfully.

- [ ] Write fixtures for protected groups, unprotected groups, duplicate group references, no group-backed assignments, missing group flags, and a failed child lookup.
- [ ] Write failing tests for deterministic row ordering and gap scope.
- [ ] Implement the plan with sequential `Get-GraphObject` calls and existing read-only descriptor validation.
- [ ] Run focused plan and check tests.
- [ ] Perform a controlled Ivy24 read to verify the actual role-assignment and group response shapes and required permissions.
- [ ] Only after package and live evidence, remove `Pending` from `intuneRbacGroupProtection` and update the check's status documentation.
- [ ] Commit the task without running formatters, linters, or the full repository suite.

**Acceptance:** TP.INT.0013 cannot turn a failed group lookup into a zero-row `Pass`, and its compact rule behavior remains unchanged for complete inputs.

---

### Task 5: Implement shared Endpoint Security policy expansion for BitLocker and LAPS

**Repository:** TenantPulse, with GraphKit changes only if an official primitive is missing.

**Files:**
- Create `source/Private/Collect/Invoke-PulseEndpointSecurityPolicyPlan.ps1`.
- Create focused value resolvers under `source/Private/Collect/` for BitLocker and LAPS.
- Modify `source/Data/DatasetMap.psd1` only at the cutover step after package and live gates.
- Modify `source/Private/Checks/Test-PulseBitLockerFullDiskEncryption.ps1` and `Test-PulseLapsConfigurationMeetsBar.ps1` only for structured partial input.
- Add `tests/Unit/Collect/EndpointSecurityPolicyPlan.Tests.ps1`.

**Plan contract:**

- Use released `ConfigurationPolicy.ListBeta`.
- Filter BitLocker to `templateFamily = endpointSecurityDiskEncryption`.
- Filter LAPS to `templateFamily = endpointSecurityAccountProtection`, then the live-verified LAPS template identity.
- Use released `ConfigurationPolicySetting.ListBeta` once per selected policy.
- Keep all four LAPS criteria on the same policy.
- Resolve BitLocker from the child setting `device_vendor_msft_bitlocker_systemdrivesencryptiontype_osencryptiontypedropdown_name_1`; do not treat the parent enablement option as the full-encryption value.
- Preserve every policy's compact row, including false values.
- Preserve failed policy-setting reads as scoped gaps.

- [ ] Write fixtures for full encryption, used-space-only encryption, missing child setting, mixed LAPS policy compliance, wrong template identity, and partial per-policy reads.
- [ ] Write failing tests for strict Boolean/field-presence behavior.
- [ ] Implement the shared sequential policy plan and the two value resolvers.
- [ ] Run focused plan and check tests.
- [ ] Reverify the BitLocker child setting mapping and LAPS template identity against Ivy24.
- [ ] Only after package and live evidence, remove `Pending` from both map entries and update their documentation.
- [ ] Commit the task without running formatters, linters, or the full repository suite.

**Acceptance:** BitLocker and LAPS findings reflect only values resolved from the same policy they describe, and a partial settings walk cannot become a false `Fail` or `Pass`.

---

### Task 6: Implement the security-baseline assignment and version plan

**Repository:** TenantPulse, with GraphKit changes only if an official primitive is missing.

**Files:**
- Create `source/Private/Collect/Invoke-PulseSecurityBaselinePlan.ps1`.
- Modify `source/Data/DatasetMap.psd1` only at the cutover step after package and live gates.
- Modify `source/Private/Checks/Test-PulseSecurityBaselinesAssignedAndCurrent.ps1` only for structured partial input.
- Add `tests/Unit/Collect/SecurityBaselinePlan.Tests.ps1`.
- Add official GraphKit primitive descriptors and tests only after service metadata and live response proof.

**Plan contract:**

- Discover security-baseline policy families using released configuration-policy primitives.
- Resolve assignment state using the released `ConfigurationPolicyAssignment.ListBeta` operation where its response is authoritative.
- Resolve template/version/deprecation state through an official reusable primitive. If Microsoft exposes no supportable method, return `Skipped` with `PlatformUnavailable` and record the recheck trigger instead of creating a fake descriptor.
- Emit native Booleans for `hasAssignment` and `isDeprecated`.
- Treat zero baselines as the existing `NotApplicable` check result, not as a hidden pass.
- Preserve scoped gaps for any missing assignment or version child.

- [ ] Write fixtures for assigned/current, unassigned/current, assigned/deprecated, mixed rows, zero rows, non-Boolean values, and partial child reads.
- [ ] Write failing tests that reject string `'false'` and missing Boolean fields.
- [ ] Implement the plan over proven primitives.
- [ ] Run focused plan and check tests.
- [ ] Perform the controlled Ivy24 read and permission verification.
- [ ] Remove `Pending` only if the complete policy, assignment, and version contract is proven; otherwise record `PlatformUnavailable`.
- [ ] Commit the task without running formatters, linters, or the full repository suite.

**Acceptance:** TP.INT.0029 reports only authoritative assignment/version state and never coerces an invalid provider value into a security result.

---

### Task 7: Resolve the Windows data-processor disposition

**Repositories:** GraphKit and TenantPulse.

**Files:**
- GraphKit: create `source/Data/Operations/DataProcessorServiceForWindowsFeaturesOnboarding.Get.psd1` only if the service probe proves the endpoint.
- GraphKit: add descriptor validation and response-shape tests under `tests/Unit/Operations/`.
- TenantPulse: modify `source/Data/DatasetMap.psd1` and the Windows data-processor provider adapter.
- TenantPulse: add `tests/Unit/Collect/WindowsDataProcessor.Tests.ps1` and QA catalog coverage.
- TenantPulse: update `docs/STATUS.md` and the relevant check documentation with evidence.

**Required decision:**

- Probe beta against Ivy24 with a read-only request.
- Prove method, path, response shape, API version, application permission, and tenant behavior.
- If all are proven, add a `Singleton.Default` GraphKit descriptor, pin the exact package, remove `Pending`, and map the result to `Collected` or `Failed` with the specific provider class.
- If any required contract is unsupported, remove `DescriptorPending` and map the dataset to `Skipped` with `FailureClass = PlatformUnavailable`, including the exact evidence and re-evaluation trigger.

- [ ] Write the provider and catalog tests before changing the map.
- [ ] Run the controlled Ivy24 probe.
- [ ] Implement exactly one of the two evidence-backed dispositions.
- [ ] Run focused GraphKit and TenantPulse tests.
- [ ] Commit the task without running formatters, linters, or the full repository suite.

**Acceptance:** TP.INT.0009 no longer claims that an unavailable GraphKit release is the reason for the outcome. It is either live-proven through an exact descriptor or explicitly platform-unavailable.

---

### Task 8: Producer-consumer package handoff and documentation

**Repositories:** GraphKit and TenantPulse.

**Files:**
- GraphKit `CHANGELOG.md`, `README.md`, `AGENTS.md`, and operation descriptor documentation where claims changed.
- TenantPulse `CHANGELOG.md`, `README.md`, `docs/STATUS.md`, and check/dataset documentation.
- GraphKit and TenantPulse QA/package verification tests.

- [x] Pack GraphKit and run the full GraphKit suite against the packed build.
- [x] Verify the tested GraphKit package identity and record its digest.
- [x] Update TenantPulse's exact GraphKit runtime dependency only if the producer version changed.
- [x] Pack TenantPulse and run the full TenantPulse suite against the packed build.
- [x] Verify package/build/source preservation and the whole-result test gates.
- [x] Update every minimum-test ratchet from measured results.
- [x] State implemented, deterministic, CI, live, and published evidence separately.
- [x] Do not publish either package in this plan without a separate explicit publication approval; both candidates remain unpublished.
- [x] Commit the documentation and release-truth updates without running formatters, linters, or unrelated project-wide commands.

**Acceptance:** The two repositories document the same exact producer-consumer package contract, every remaining pending or platform-unavailable path has evidence, and no documentation claims a live or published result that was not exercised.

---

## Execution order and review gates

Tasks 1 through 3 are sequential because the composite plans depend on their outcome and collector contracts. Tasks 4, 5, and 6 can be developed as separate slices after Task 3, but their cutover edits to `DatasetMap.psd1` remain gated on exact package and live evidence. Task 7 is independently gated by the controlled service probe. Task 8 runs last.

Each implementation task requires a focused test run and a task-scoped code review. After all tasks, run the complete GraphKit and TenantPulse pack-then-test gates, then run a whole-branch review against the exact branch base. Do not merge or publish until all Critical and Important findings are resolved or explicitly escalated.

## Explicit non-goals

- A generic GraphKit `Walk` or composite strategy.
- A universal mutation API.
- Global beta mode.
- Blind replay of ambiguous writes.
- Parallel live fan-out before shared-state proof.
- ARM support for `TP.INT.0010`.
- Application-registration credential coverage that lacks an official GraphKit application descriptor.
- Conditional Access group expansion, transitive privileged-role expansion, additional renderers, or R6 scale work.
- Destructive live verification.
