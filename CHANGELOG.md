# Changelog for GraphKit

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-08-29

GraphKit `0.3.0` was published to PSGallery at `2026-08-30T04:38:20.12Z`. The 207381-byte public
archive SHA-256 is `45319d7cf4f8333697343ccf9c1089c7e04da87a8df62553cbc140089337536d`. Reviewed
PR head `a0f0e92a054fe2976ca74a844f5de6161e1b8c67` merged to main as
`a1b0b8d54c17671761ef5aee017a453b072d1fe9`; PR-head CI run `33292245900` and exact-main CI run
`33292580847` passed 772 tests across all six Windows/macOS/Ubuntu PowerShell 7.4/7.6 jobs. The
retained release-worktree archive is byte-identical to the public archive; rebuilt ZIP container
hashes are not a replacement identity for the published bytes. PSGallery `0.2.2` remains an
immutable predecessor.

### Added

- Five official beta collection descriptors, all positively verified app-only against Ivy24
  on 2026-08-29:
  - `DeviceManagementUnifiedRoleAssignment.ListBeta`, with fixed
    `$expand=roleDefinition,principals` and `DeviceManagementRBAC.Read.All`.
  - `DeviceManagementTemplate.ListBeta`, providing template version and deprecation metadata.
  - `DeviceManagementConfigurationPolicyTemplate.ListBeta`, providing the distinct current
    Settings Catalog template lifecycle, family, and native-version metadata.
  - `DeviceManagementIntent.ListBeta`, providing the native assignment and template relation.
  - `ManagedDeviceCleanupRule.ListBeta`, the documented per-platform cleanup-rules collection.

### Changed

- `Microsoft.PowerShell.SecretManagement` 1.1.2+ is now a lazy vault dependency rather than a
  hard module dependency. Non-vault import, managed identity, help, and catalog inspection remain
  usable without it. First vault use validates and imports an eligible version, and calls
  `Get-SecretVault` and `Get-Secret` module-qualified so unrelated same-named functions cannot
  satisfy the boundary.
- `Install-GraphKitPinned.ps1` installs only hard `Microsoft.Graph.Authentication` by default for
  `0.3.0`; `-InstallSecretManagement` pre-provisions vault support. A `0.2.2` pin still installs
  SecretManagement automatically because that immutable published manifest requires it.
- `NamedLocation.List` is now positively verified app-only with `Policy.Read.All`. The earlier
  `Policy.Read.ConditionalAccess` 403 remains evidence that the narrower scope is insufficient.
- The undocumented `DeviceCleanupRule.Get` singleton was removed and replaced by
  `ManagedDeviceCleanupRule.ListBeta`. `DeviceManagementScript.List` remains declared from the
  service's scope-specific 403 and documented response schema, but a successful live response
  is still pending a token carrying `DeviceManagementScripts.Read.All`.

## [0.2.2] - 2026-08-18

### Added

- Thirteen read-only descriptors that unblock TenantPulse checks waiting on
  `descriptor-pending`. All are official Graph GETs; none invent a Walk composite.
  - `RoleAssignmentScheduleInstance.List` and `RoleEligibilityScheduleInstance.List`
    (`/roleManagement/directory/...`, v1.0) for TP.ENT.0022.
  - `CrossTenantAccessPolicy.GetDefault` (`/policies/crossTenantAccessPolicy/default`,
    v1.0) for TP.ENT.0023. That is the default singleton, not the parent policy object.
  - `ApplePushNotificationCertificate.Get` (v1.0, `certificate` declared sensitive),
    `AndroidManagedStoreAccountEnterpriseSettings.Get` (beta), and
    `MobileThreatDefenseConnector.List` (v1.0) for TP.INT.0019/0022/0024.
  - `OperationApprovalPolicy.List`, `IntuneBrandingProfile.List`, and
    `WindowsFeatureUpdateProfile.List` (all beta) for TP.INT.0008/0011/0012.
  - `WindowsAutopilotDeploymentProfile.List` (beta, `$expand=assignments` is the
    operation identity) for TP.INT.0026.
  - `DeviceManagementRoleDefinition.List`, `DeviceManagementRoleAssignment.List`
    (`/deviceManagement/roleAssignments`, v1.0), and `Group.Get` (v1.0, `$select`
    of `isAssignableToRole`/`isManagementRestricted`) as primitives for TP.INT.0013.
- `AuthorizationPolicy.Get` and `DirectorySetting.List` already existed; they cover
  TP.ENT.0012/0013/0015/0016. `ConfigurationPolicy.ListBeta` plus settings/assignment
  siblings already cover BitLocker/LAPS/baseline enumeration (TP.INT.0014/0015/0029).
- `DataProcessorServiceForWindowsFeaturesOnboarding.Get` is not shipped: the resource
  page exists on beta, the official GET method page does not.

## [0.2.1] - 2026-08-17

### Fixed

- **The descriptor declaration is now authoritative over row data.** `Export-GraphResult`'s
  envelope sanitiser name-matched the whole envelope including `.Data`, so `passwordCredentials`
  matched its `credential` pattern and was redacted wholesale - taking `endDateTime` and `keyId`
  with it. Neither a dotted declaration nor `-NoRedact` escaped it, because neither was what
  redacted. Telemetry and Provenance are still sanitised; `.Data` is governed by
  `SensitiveProperties`. Raw rows keep the name-based pass, since there is no descriptor to defer
  to.
- An envelope whose rows carry secret-looking property names while declaring none now **warns**,
  naming them and pointing at the descriptor, rather than being silently redacted or silently
  exported.

### Changed

- `ServicePrincipal.List` declares credential **value** fields rather than the arrays, so
  credential metadata survives an export while the secret does not.

## [0.2.0] - 2026-08-16

### Added

- Descriptors may declare `SensitiveProperties`: the response properties an operation is known
  to return secrets in. Declarations may be dotted paths, so a nested branch can be redacted
  without losing its siblings. Validated at load, because a typo would redact nothing and look
  correct.
- `Export-GraphResult -NoRedact` writes rows exactly as the service returned them.
- **Write operations.** `Invoke-GraphOperation` now declares `SupportsShouldProcess`, so `-WhatIf`
  gives a real dry run on any mutating operation. What counts as mutating is declared by the
  descriptor's `ReplayPolicy`, not inferred from the HTTP verb - two descriptors are POSTs that
  change nothing, and a verb-based gate would prompt on reads. ConfirmImpact is deliberately not
  raised, so unattended writes still run without a console.
- Actions may declare `RequestBodyKind = $null` and are then executed without a body. The action
  strategy previously demanded a body from every action, which excluded most of the write surface:
  Intune device actions are bodyless POSTs and deletes carry no body at all.
- **Descriptors may declare `Impact` (`Low`/`Medium`/`High`).** `High` means the operation can
  cause irreversible data loss, and `Invoke-GraphOperation` then requires an explicit `-Force`.
  It does not prompt: `ShouldContinue` blocks rather than throws in a non-interactive host, which
  would wedge a CI job instead of failing it. Requiring a named switch also records the intent to
  destroy in the command itself, where a code review can see it. A non-mutating operation
  declaring an impact is rejected at load.
- Assignment writes for the remaining policy types, closing a read/write asymmetry:
  `DeviceConfiguration.Assign` and `ConfigurationPolicy.AssignBeta`. Assignment *reads* already
  existed for both, so a caller could see assignments it had no way to change. All assignment
  writes are live-verified end to end - create, assign, read back, delete - against a lab tenant.
- Every write now declares `Impact`, enforced by a descriptor invariant, and every assignment write
  is required to ship with the read that makes it safe to use, because Graph's `/assign` is a
  replace and omitted assignments are removed.
- Three device write descriptors (64 operations): `ManagedDevice.Retire` and `ManagedDevice.Delete`
  (`Medium` - disruptive but recoverable) and `ManagedDevice.Wipe` (`High`). Wipe requires a
  request body even though Graph accepts an empty one, because `keepUserData` defaults to false
  server-side and the empty body is therefore the most destructive possible call.
- Two write descriptors (61 operations): `ManagedDevice.SyncDevice` and
  `DeviceCompliancePolicy.Assign`. Destructive device actions - retire, wipe, delete - are
  deliberately NOT included; see the note in `AGENTS.md`.
- Four read-only beta descriptors requested by a consumer, taking the catalog from 55 to 59:
  `GroupPolicyConfiguration.ListBeta`, `GroupPolicyDefinitionValue.ListBeta`,
  `GroupPolicyPresentationValue.ListBeta` (the Administrative Template walk) and
  `ConfigurationPolicyAssignment.ListBeta`. The last closes a silent gap - assignment
  descriptors existed for compliance policies, device configurations and mobile apps, so a
  reconciliation across policy types contributed nothing for Settings Catalog and still
  reported success.

### Changed

- **Every export format now redacts declared secret-bearing properties.** Previously only
  `-As Json` redacted; `-As Csv`, `-As Markdown` and the VaultEvidence `rows.json` wrote rows
  raw. What is redacted is declared by the operation rather than guessed from property names:
  guessing was measured against live responses and would have redacted nine
  DeviceCompliancePolicy password-policy settings while still missing `scriptContent`.
- **CSV cells beginning `=`, `+`, `-` or `@` are prefixed with an apostrophe** so they are not
  executed as formulas when opened in a spreadsheet. Strings only - negative numbers are
  untouched.
- Exporting rows without an envelope now warns that no declaration is available and nothing was
  redacted, rather than passing silently.
- **A `PathTemplate` that fixes a query option now extends it with `&`.** `Resolve-GraphUri`
  always joined with `?`, so a descriptor with a fixed option plus a caller-supplied one
  produced `...?$expand=definition?$filter=x` - not two options, since the second `?` becomes
  part of the first option's value. Graph returns 200 and silently ignores the filter, so the
  caller gets a complete unfiltered collection that looks like a filtered one. Only
  `Organization/GetMdmAuthority` fixed an option before now, and it was safe purely because it
  declares no caller options at all.
- A caller-supplied query option that the descriptor already fixes is now rejected by name,
  rather than emitted twice for Graph to reject with an error naming the option instead of the
  descriptor responsible.

### Deprecated

- For soon-to-be removed features.

### Removed

- For now removed features.

### Fixed

- For any bug fix.

### Security

- In case of vulnerabilities.
