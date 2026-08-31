# GraphKit R8 compiled authentication boundary

**Date:** 2026-08-30

**Status:** Approved by the active end-to-end product-program goal

**Scope:** GraphKit R8 only

**Successor train:** `0.4.0-r8.g<source-revision>`

## Problem

The immutable public `0.3.0` package acquires tokens through PowerShell classes that bind late to
the `Microsoft.Identity.Client.dll` delivered as a private implementation detail of
`Microsoft.Graph.Authentication`. The post-release hardening branch rejects a parent-created
PowerShell token source when it reaches another runspace because invoking the nested PowerShell
class path there can hang. That is safe containment, but it does not satisfy the approved
immutable-context contract.

R8 replaces the built-in certificate, client-secret, managed-identity, and fixed-bearer paths with
a compiled, runspace-neutral adapter. It does not change public command signatures or TenantPulse's
public contract.

## Release identity

Published `0.3.0` remains immutable. R8 uses base version `0.4.0` and a prerelease identity derived
from the exact source used to build it:

```text
0.4.0-r8.g<12-lowercase-hex-commit>
```

A development build from a dirty tree adds a deterministic dirty-tree suffix:

```text
0.4.0-r8.g<12-lowercase-hex-commit>.d<12-lowercase-hex-diff-hash>
```

Only a clean-tree package may become release authority or cross a repository/machine boundary.
The tested-release proof records the full semantic version, source revision, clean/dirty state,
and package digest. No R8 build may create or publish changed bytes as `0.3.0`.

## Assembly boundary

R8 ships two GraphKit-owned assemblies under `Assemblies/GraphKit.Auth/`:

```text
GraphKit.Auth.Contracts.dll       default AssemblyLoadContext
GraphKit.Auth.dll                 isolated collectible AssemblyLoadContext
GraphKit.Auth.deps.json           isolated dependency resolver input
Microsoft.Identity.Client.dll     exact 4.82.1, isolated only
Microsoft.IdentityModel.Abstractions.dll and the locked runtime closure
```

`GraphKit.Auth.Contracts.dll` has no NuGet dependency. PowerShell loads it through the built module
manifest before parsing the root module. It owns all DTOs, interfaces, the strict loader, default-
context source proxies, and host lifetime. The source manifest leaves `RequiredAssemblies` empty
because generated binaries are intentionally absent from `source/`; the post-build copy task adds
the contracts path to the built manifest only after the allowlisted DLL exists, then validates that
manifest with `Test-ModuleManifest`.

`GraphKit.Auth.dll` references `Microsoft.Identity.Client` 4.82.1 and
`GraphKit.Auth.Contracts`. A named collectible `AssemblyLoadContext` loads the provider and its
locked dependency closure. When the provider requests `GraphKit.Auth.Contracts`, the load context
returns the already-loaded default-context contract assembly. This preserves CLR type identity
while keeping every MSAL assembly outside the default load context.

No public member in `GraphKit.Auth.Contracts` or any cross-boundary interface may name an MSAL
type. Reflection QA enforces that constraint.

## ABI version 1

The contract marker is the ordinal string `GraphKit.Auth.Abi/1`.

```csharp
public enum GraphAuthMode
{
    Certificate,
    ClientSecret,
    ManagedIdentity,
    BearerToken
}

public abstract class GraphCredential { }

public sealed class CertificateCredential : GraphCredential
{
    public X509Certificate2 Certificate { get; }
    public bool OwnsMaterial { get; }
}

public sealed class ClientSecretCredential : GraphCredential
{
    public SecureString Secret { get; }
    public bool OwnsMaterial { get; }
}

public sealed class ManagedIdentityCredential : GraphCredential
{
    public string? UserAssignedClientId { get; }
}

public sealed class FixedBearerCredential : GraphCredential
{
    public string AccessToken { get; }
}
```

`GraphTokenRequest` is immutable after construction and contains the source-constant request
fields:

- `Environment`
- `TenantId` (`Guid`)
- `Authority` (`Uri`)
- `Resource` (`Uri`)
- `ClientId` (`Guid?`)
- `AuthMode`
- `Credential`
- `CredentialGeneration`

The existing `IGraphTokenSource.Acquire(bool forceRefresh, CancellationToken cancellation)` method
continues to carry the two per-call fields. This deliberately refines the earlier conceptual field
list: certificate/secret objects are transferred once when the source is created, not copied into a
second request object on every acquisition. There is no duplicate descriptor DTO.

`GraphTokenResult` contains:

- `AccessToken`
- `ExpiresOnUtc`
- `ReceivedOnUtc`
- `TokenType`
- `Scopes`
- `VerifiedTenantId`
- `TokenFingerprint`
- `CredentialGeneration`

`ReceivedOnUtc` remains explicit because cache replacement needs acquisition order without parsing
the resource-owned JWT. `VerifiedTenantId` remains settable because the tenant-binding pipeline
records proof on the exact result that supplied the bearer.

`GraphAuthException` is the only provider-failure exception permitted across the ALC. The isolated
provider catches every MSAL-derived exception before returning and creates a GraphKit-owned failure
with sanitized `Code`, `Category`, `Message`, `RetryAfter`, and `CorrelationId` fields. It never
assigns an MSAL exception as `InnerException`, stores an MSAL object in `Data`, or exposes an MSAL
stack/type name through another contract member. Cancellation remains `OperationCanceledException`,
a framework type shared by both contexts.

`IGraphTokenSource : IDisposable` preserves the existing duck surface:

```csharp
bool CanRefresh { get; }
string AuthMode { get; }
string Audience { get; }
string? ClientId { get; }
DateTimeOffset ExpiresOn { get; }
string? VerifiedTenantId { get; }
string CredentialGeneration { get; }
GraphTokenResult Acquire(bool forceRefresh, CancellationToken cancellation);
void AdoptSharedResult(GraphTokenResult result, bool forceRefresh);
```

`IGraphTokenSourceFactory.Create(GraphTokenRequest)` is the only provider factory member
used across the ALC. The factory and every returned source implement contract-assembly interfaces.

## Source and host lifetime

`GraphAuthHost` owns one isolated load context per module import. It validates the contract marker,
factory type, provider assembly identity, exact MSAL version, load-context identity, and public
surface before accepting the provider.

The contracts assembly itself is loaded in the default context and therefore follows normal CLR
first-load-wins identity. Module import validates `GraphKit.Auth.Abi/1` and the exact expected
contract assembly identity before using an already-loaded copy. An incompatible in-process
GraphKit.Auth ABI upgrade requires a fresh PowerShell process; GraphKit fails clearly rather than
casting across mismatched contract identities.

The host returns default-context proxies around isolated sources. A proxy:

- is runspace-neutral;
- forwards only ABI-v1 members;
- rejects use after disposal;
- participates in the existing GraphKit single-flight and tenant-proof pipeline;
- clears its inner-source reference during disposal; and
- unregisters itself from the host exactly once.

The module lifecycle registers the host before registering sources. Existing LIFO cleanup therefore
disposes every source before the host. Host shutdown refuses new sources, cancels/drains active
acquisitions within the module cleanup deadline, disposes remaining sources, clears strong
`Assembly`, `Type`, factory, and load-context references, calls `Unload()`, and exposes a weak
reference for bounded unload verification.

Certificates and secure strings carry explicit ownership. Persisted material is transferred to a
GraphKit-owned source and disposed exactly once. Caller-injected certificates remain caller-owned.
Fixed bearer strings cannot be zeroed in managed memory, so the source clears all references on
disposal and never logs or exports them.

## Context construction and credential resolution

The four built-in modes create compiled sources. Certificate and client-secret profiles resolve
vault material in the runspace that creates `GraphKit.Context`, validate the exact credential
generation there, and transfer only framework/GraphKit-owned types to the adapter. No PowerShell
credential-resolver scriptblock crosses a runspace or ALC boundary.

Context construction still performs no token acquisition and no service call. For persisted
certificate or secret profiles it now performs the local vault read needed to make the resulting
context immutable and runspace-neutral. Managed identity and inline fixed bearer remain vault-free;
a vault-backed fixed bearer necessarily resolves its named vault value during context construction.

PFX resolution remains one-read: the exact byte snapshot used to calculate the generation is the
snapshot imported into the owned `X509Certificate2`. Unversioned mutable selectors retain a
per-context nonce; versioned immutable selectors may share a process flight only when the version
API can actually resolve them.

## Compatibility paths

`Get-GraphContext -TokenProvider` remains public and behaves as the existing caller-owned,
same-runspace PowerShell compatibility path. It is not one of the four R8 parity modes and must not
be described as runspace-neutral.

`Get-GraphContext -MsalFactory` remains an internal-test/public compatibility seam. Supplying it
selects the legacy same-runspace source so deterministic legacy-versus-compiled parity can be
measured without allowing an MSAL object to cross the isolated adapter. Its help text identifies
the scope. Removing or replacing either parameter requires a separate public-contract decision.

The supported claim after R8 is precise: contexts created through the four built-in modes are
runspace-neutral; arbitrary PowerShell provider/factory scriptblocks are not.

## Build and package

The repository pins .NET SDK `10.0.400` in `global.json`, targets `net8.0`, commits NuGet lock files,
and restores with locked mode. The package is framework-dependent, RID-neutral, non-self-contained,
and does not contain PDBs, reference assemblies, native broker assets, or runtime-specific output.

The build workflow is:

```text
Clean
  -> Build_GraphKitAuth
  -> Build_Module_ModuleBuilder
  -> Copy_GraphKitAuth_Into_BuiltModule
  -> Build_NestedModules_ModuleBuilder
  -> Create_changelog_release_output
  -> package_module_nupkg
```

Generated binaries stay under `output/`; source directories never contain generated assemblies.
The copy task uses an explicit allowlist and fails on a missing or unexpected runtime file. It then
updates only the built `GraphKit.psd1` with
`RequiredAssemblies = @('Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll')` and runs
`Test-ModuleManifest`. The canonical release proof already hashes every built-module and package
entry; it is extended for the full prerelease version and source-revision identity.

## Verification gates

Deterministic gates must prove:

- ABI marker and exact member shapes;
- no MSAL type crosses the contract surface;
- MSAL failures become GraphKit-owned exceptions with no MSAL inner exception, `Data` value, or
  public member type;
- exact MSAL 4.82.1 loads only in the named isolated context;
- preloaded Az/Graph/PSResourceGet MSAL remains unchanged;
- fixed bearer cannot refresh;
- certificate, secret, managed identity, and bearer match the legacy deterministic contracts;
- force-refresh, cache adoption, cancellation, fingerprint, generation, and disposal semantics;
- one exact parent-created built-in context works in real child runspaces;
- two tenant contexts do not exchange tokens or tenant proof;
- same-key work shares one flight and a `401` refresh does not poison another context;
- source disposal precedes host disposal and the isolated context becomes collectible;
- a clean installed package imports with no `Microsoft.Graph.Authentication` dependency; and
- all Windows/macOS/Linux PowerShell 7.4/7.6 jobs pass on the exact SHA.

Protected live parity is separate. Certificate, client secret, and fixed bearer require Ivy24
proof using the exact tested prerelease. Managed identity requires a fresh Azure host because the
earlier container was deleted. The transitive dependency and legacy built-in implementation are
removed only after all applicable parity gates pass. Public publication remains approval-gated and
can use only already-tested bytes.

## Rollback

Before stable publication, rollback means returning consumers to immutable GraphKit `0.3.0` and
discarding the unpublished R8 prerelease. No profile schema migration is required. The legacy
PowerShell implementation remains in source until protected parity passes, so an R8 prerelease can
be rebuilt with the compiled cutover disabled during development without changing persisted data.
