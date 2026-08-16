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

### Deprecated

- For soon-to-be removed features.

### Removed

- For now removed features.

### Fixed

- For any bug fix.

### Security

- In case of vulnerabilities.

