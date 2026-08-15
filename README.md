# GraphKit

GraphKit is an app-only, multi-tenant Microsoft Graph execution and analysis layer for PowerShell, with explicit Microsoft Intune and Entra operation semantics.

It centralizes tenant profiles, credential resolution, token acquisition, Graph request execution, paging, batching, throttling, retry policy, permission analysis, and evidence export without becoming a generic Graph SDK or OAuth client.

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
- `Microsoft.PowerShell.SecretManagement` 1.1.2 or later
- A registered SecretManagement vault when using stored credentials

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
./build.ps1 -Tasks build
./build.ps1 -Tasks test
./build.ps1 -Tasks pack
```

The `pack` task produces the package from the tested build output. Generated artifacts are written under `output/` and should not be edited directly.

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
