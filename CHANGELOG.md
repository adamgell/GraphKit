# Changelog for GraphKit

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

