# GraphKit

[![PSGallery Version](https://img.shields.io/powershellgallery/v/GraphKit)](https://www.powershellgallery.com/packages/GraphKit)
[![PSGallery Downloads](https://img.shields.io/powershellgallery/dt/GraphKit)](https://www.powershellgallery.com/packages/GraphKit)
[![PowerShell 7.4+](https://img.shields.io/badge/PowerShell-7.4%2B-blue)](https://github.com/PowerShell/PowerShell)

> Query Microsoft Graph across multiple tenants from PowerShell — auth, retries, throttling, and paging handled for you.

GraphKit is an app-only, multi-tenant Microsoft Graph execution and analysis layer for PowerShell, with explicit Microsoft Intune and Entra operation semantics.

It centralizes tenant profiles, credential resolution, token acquisition, Graph request execution, paging, batching, throttling, retry policy, permission analysis, and evidence export without becoming a generic Graph SDK or OAuth client.

## Release status

GraphKit `0.3.0` is the current immutable release on PSGallery, published 2026-08-30 at
`2026-08-30T04:38:20.12Z`. Its 207381-byte public archive has SHA-256
`45319d7cf4f8333697343ccf9c1089c7e04da87a8df62553cbc140089337536d`. Reviewed PR head
`a0f0e92a054fe2976ca74a844f5de6161e1b8c67` was merged to main as
`a1b0b8d54c17671761ef5aee017a453b072d1fe9`; PR-head CI run `33292245900` and exact-main CI run
`33292580847` passed 772 tests across all six Windows/macOS/Ubuntu PowerShell 7.4/7.6 jobs. This
deterministic and CI evidence is distinct from live service verification. `0.3.0` makes
SecretManagement lazy for non-vault flows and adds the live-proven TenantPulse collection
descriptors described in `CHANGELOG.md`.

GraphKit `0.2.2` is an immutable predecessor. Its hard SecretManagement contract remains relevant
only for hosts pinned to that version.

## What it provides

- Immutable, tenant-specific execution contexts
- Certificate, client-secret, managed-identity, and vault-resolved bearer-token authentication
- MSAL.NET for token acquisition
- A GraphKit-owned `HttpClient` transport
- Descriptor-driven operations with per-operation API versions
- Semantics-aware retry and throttling, including protection against ambiguous mutation replay
- Opaque next-link validation and tenant/cloud authority checks
- Permission discovery, comparison, and app-role management
- Sanitized CSV, JSON, Markdown, and vault evidence export

GraphKit does not use `Connect-MgGraph` or `Invoke-MgGraphRequest` as its transport. The Microsoft Graph PowerShell SDK maintains process-global state that can interfere with concurrent work across tenants. GraphKit instead owns the request pipeline while using MSAL only for authentication.

## Requirements

- PowerShell 7.4 or later
- `Microsoft.Graph.Authentication` 2.38.1 or later, used as the MSAL delivery dependency
- `Microsoft.PowerShell.SecretManagement` 1.1.2 or later only when using vault-backed credentials;
  `0.3.0` validates and imports it at first vault use
- A registered SecretManagement vault extension when using stored credentials

Published `0.2.2` still declares SecretManagement as a hard dependency. The pinned installer
preserves that immutable package contract while treating SecretManagement as opt-in for `0.3.0`.
Import, help, catalog inspection, managed identity, injected credentials, and Windows certificate-
store credentials do not require SecretManagement in `0.3.0`. The certificate example below uses
a vault reference and therefore exercises the optional vault path.

## Typical usage

Register a tenant profile, resolve an execution context, and perform a typed Graph read:

```powershell
Register-GraphTenant -ProfileId ivy24 -TenantId $tenantId -ClientId $clientId -AuthMode Certificate -CertificateVaultName 'GraphKit'

$context = Get-GraphContext -ProfileId ivy24
Get-GraphObject -Context $context -Type ManagedDevice
```

Other primary commands include:

```powershell
Get-GraphTenant
Get-GraphOperation
Invoke-GraphOperation
Invoke-GraphBatch
Test-GraphPermission
Compare-GraphPermission
Export-GraphResult
```

Low-level operations accept an explicit `-Context` or `-ProfileId`; callers should resolve the tenant before entering parallel or asynchronous work.

## Development

Dependencies and build tools are restored through the repository scripts. Run the test suite through the build entry point rather than invoking Pester directly:

```powershell
./build.ps1 -ResolveDependency -Tasks noop
./build.ps1 -Tasks pack
./build.ps1 -Tasks test
```

The `pack` task begins with `Clean`, so package before testing. The `test` task then proves the exact package-producing build and writes the NUnit result consumed by the release gate. Generated artifacts are written under `output/` and must not be edited directly.

## Project layout

- `source/Public/` — exported GraphKit commands
- `source/Private/` — transport, retry, paging, throttle, URI, and evidence helpers
- `source/Data/Operations/` — operation descriptors
- `tests/Unit/` — deterministic policy and pipeline tests
- `tests/Adapter/` — transport and loopback integration tests
- `tests/Concurrency/` — runspace isolation and throttling tests
- `docs/superpowers/specs/` — approved architecture and design decisions
- `scripts/` — standalone operational and cutover scripts

GraphKit is intended to provide the reliable Graph plumbing for applications such as IntuneHealthAutomation. Reporting, Excel processing, checkpointing, and application-specific workflows remain outside this module.
