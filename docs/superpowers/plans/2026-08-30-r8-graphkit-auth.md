# GraphKit R8 Authentication Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a digest-bound GraphKit `0.4.0-r8` prerelease whose four built-in authentication modes use a runspace-neutral compiled adapter with exact MSAL 4.82.1 isolated from the process default load context.

**Architecture:** A dependency-free `GraphKit.Auth.Contracts.dll` loads in the default `AssemblyLoadContext` and owns the GraphKit ABI, strict loader, proxies, and lifetime. `GraphKit.Auth.dll` and its locked MSAL runtime closure load in one named collectible context per module import; only contract types cross. PowerShell resolves persisted credential material before a context leaves its creation runspace, then transfers owned framework types into the compiled source.

**Tech Stack:** PowerShell 7.4/7.6, Sampler 0.120.1, ModuleBuilder 3.1.8, Pester 6.1.0, .NET SDK 10.0.400 targeting `net8.0`, Microsoft.Identity.Client 4.82.1, collectible `AssemblyLoadContext`, locked NuGet restore.

---

## Status (2026-09-01)

Deterministic implementation is complete and green: Tasks 1-7 (prerelease identity, ABI and
package boundary, dependency-free contract assembly, isolated provider, build/package/CI
wiring, built-in cutover, and deterministic parity/runspace proof) plus Task 8 Steps 0-3
(deterministic prerequisites and the digest-bound protected runner; the exact verified revision is
recorded by the current release proof rather than pinned in this plan). The remaining checkboxes are
approval-gated and out of scope for deterministic
completion: Task 8 Steps 4-6 (protected live parity evidence), Task 9 (transitive MSAL removal,
sequenced after live parity), and Task 10 (exact-SHA CI and publication).


## File map

New compiled source:

- `global.json` — exact .NET SDK selection.
- `src/GraphKit.Auth/Directory.Build.props` — deterministic, warning-clean, `net8.0` defaults.
- `src/GraphKit.Auth/GraphKit.Auth.sln` — the two production projects and unit-test project.
- `src/GraphKit.Auth/GraphKit.Auth.Contracts/GraphKit.Auth.Contracts.csproj` — dependency-free shared ABI.
- `src/GraphKit.Auth/GraphKit.Auth.Contracts/Contracts.cs` — credentials, descriptors, requests, results, and interfaces.
- `src/GraphKit.Auth/GraphKit.Auth.Contracts/GraphAuthLoadContext.cs` — strict shared-contract resolver.
- `src/GraphKit.Auth/GraphKit.Auth.Contracts/GraphAuthHost.cs` — provider load, validation, proxy ownership, unload.
- `src/GraphKit.Auth/GraphKit.Auth.Contracts/GraphTokenSourceProxy.cs` — default-context proxy and disposal state.
- `src/GraphKit.Auth/GraphKit.Auth/GraphKit.Auth.csproj` — isolated provider with MSAL 4.82.1.
- `src/GraphKit.Auth/GraphKit.Auth/GraphTokenSourceFactory.cs` — descriptor validation and source construction.
- `src/GraphKit.Auth/GraphKit.Auth/GraphTokenSource.cs` — cache, refresh, adoption, cancellation, disposal.
- `src/GraphKit.Auth/GraphKit.Auth/MsalTokenClient.cs` — confidential-client and managed-identity acquisition.
- `src/GraphKit.Auth/GraphKit.Auth.Tests/GraphKit.Auth.Tests.csproj` — deterministic provider tests.
- `src/GraphKit.Auth/GraphKit.Auth.Tests/*.cs` — factory, cache, force-refresh, cancellation, and ownership tests.
- `src/GraphKit.Auth/**/packages.lock.json` — exact restored dependency graphs.

New build and PowerShell integration:

- `.build/GraphKitAuth.tasks.ps1` — locked build and allowlisted package staging.
- `scripts/Get-GraphKitTrainVersion.ps1` — deterministic full prerelease identity.
- `source/Private/TokenSources/New-GraphAuthTokenSource.ps1` — CLR descriptor bridge and ownership transfer.
- `tests/QA/GraphKitAuthPackage.tests.ps1` — binary/runtime-closure/ALC/no-leak package gates.
- `tests/Unit/Auth/GraphKitAuth.Tests.ps1` — public ABI and fixed-bearer behavior.
- `tests/Concurrency/GraphKitAuthRunspace.Tests.ps1` — exact source/context cross-runspace proof.
- `tests/Unit/Auth/GraphKitAuthParity.Tests.ps1` — legacy and compiled deterministic contract parity.

Existing files to modify:

- `build.ps1`, `build.yaml`, `.github/workflows/ci.yml` — generated version, compiled build task, SDK setup, and .NET tests.
- `source/GraphKit.psd1` — `0.4.0-r8` and eventual dependency removal; generated assemblies are
  referenced only in the built manifest.
- `source/Private/Initialize-GraphModuleLifecycle.ps1` — host-first/source-later LIFO registration.
- `source/Private/TokenSources/GraphTokenSource.ps1` — compiled production selection; retained compatibility classes.
- `source/Private/TokenSources/New-GraphMsalApplication.ps1` — legacy parity/test-only scope.
- `source/Private/Transport/Send-GraphHttpRequest.ps1` — CLR-source cache adoption and scoped legacy guard.
- `source/Public/Get-GraphContext.ps1` — compiled built-ins, same-runspace provider/factory compatibility.
- `source/Private/Assert-GraphMsalEnvironment.ps1` — remove default-ALC guard after cutover.
- `scripts/New-GraphKitTestedReleaseProof.ps1`, `scripts/Test-GraphKitReleaseProof.ps1` — full prerelease/source-revision proof.
- `scripts/Install-GraphKitPinned.ps1`, `scripts/Publish-GraphKitPackage.ps1`, `scripts/Publish-GraphKitToGallery.ps1` — prerelease-aware exact artifact handling.
- `tests/QA/PackageIdentity.tests.ps1`, `tests/QA/PackageDependencies.tests.ps1`, `tests/QA/ImportOrderMatrix.tests.ps1`, `tests/QA/ReleaseProof.tests.ps1`, `tests/QA/ReleaseTruth.tests.ps1` — successor identity and isolated dependency assertions.
- `README.md`, `AGENTS.md`, `CHANGELOG.md`, both governing specs — exact completed/evidence status.

### Task 1: Freeze and test successor package identity

**Files:**

- Create: `scripts/Get-GraphKitTrainVersion.ps1`
- Modify: `build.ps1`
- Modify: `source/GraphKit.psd1`
- Modify: `scripts/New-GraphKitTestedReleaseProof.ps1`
- Modify: `scripts/Test-GraphKitReleaseProof.ps1`
- Test: `tests/QA/PackageIdentity.tests.ps1`
- Test: `tests/QA/ReleaseProof.tests.ps1`

- [x] **Step 1: Write failing successor-version tests**

Add assertions that source declares base `0.4.0`, the train is `r8`, the built/package version is
`0.4.0-r8.g<12 hex>` for a clean tree, and the proof records the exact full version and 40-hex
source revision. Add a fixture proving that a prerelease package is found under a base-version
module directory.

```powershell
$metadata.version | Should -Match '^0\.4\.0-r8\.g[0-9a-f]{12}$'
$proof.source.revision | Should -Match '^[0-9a-f]{40}$'
$proof.module.version | Should -Be ([string] $metadata.version)
```

- [x] **Step 2: Run the focused tests and verify red**

Run:

```powershell
./build.ps1 -Tasks pack
./build.ps1 -Tasks test
```

Expected: failures naming stable `0.3.0`, missing source revision, and prerelease package discovery.

- [x] **Step 3: Implement deterministic version generation**

`Get-GraphKitTrainVersion.ps1` returns one string and nothing else:

```powershell
$base = '0.4.0'
$train = 'r8'
$revision = (& git -C $RepositoryRoot rev-parse HEAD).Trim().ToLowerInvariant()
$diff = (& git -C $RepositoryRoot diff --binary HEAD)
$suffix = if ([string]::IsNullOrEmpty($diff)) {
    ''
} else {
    $bytes = [Text.Encoding]::UTF8.GetBytes($diff)
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    ".d$($hash.Substring(0, 12))"
}
"$base-$train.g$($revision.Substring(0, 12))$suffix"
```

Set `$env:ModuleVersion` in `build.ps1` before Sampler resolves build metadata. Record the complete
semantic version and source state in proof schema v2. Resolve the built directory from base
`ModuleVersion` while resolving the package from full PSData prerelease/version metadata.

- [x] **Step 4: Run identity/proof tests and verify green**

Expected: every new identity fixture passes; no package named `GraphKit.0.3.0.nupkg` is produced.

- [x] **Step 5: Commit**

```bash
git add build.ps1 source/GraphKit.psd1 scripts/Get-GraphKitTrainVersion.ps1 scripts/New-GraphKitTestedReleaseProof.ps1 scripts/Test-GraphKitReleaseProof.ps1 tests/QA/PackageIdentity.tests.ps1 tests/QA/ReleaseProof.tests.ps1
git commit -m "build: establish the GraphKit R8 prerelease identity"
```

### Task 2: Add red ABI and package-boundary tests

**Files:**

- Create: `tests/Unit/Auth/GraphKitAuth.Tests.ps1`
- Create: `tests/QA/GraphKitAuthPackage.tests.ps1`
- Modify: `tests/QA/PackageDependencies.tests.ps1`

- [x] **Step 1: Write the missing-artifact and ABI tests**

The tests require these exact package paths:

```text
Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll
Assemblies/GraphKit.Auth/GraphKit.Auth.dll
Assemblies/GraphKit.Auth/GraphKit.Auth.deps.json
Assemblies/GraphKit.Auth/Microsoft.Identity.Client.dll
Assemblies/GraphKit.Auth/Microsoft.IdentityModel.Abstractions.dll
```

Load the contracts assembly and assert:

```powershell
[GraphKit.Auth.GraphAuthHost]::ContractMarker | Should -Be 'GraphKit.Auth.Abi/1'
[GraphKit.Auth.IGraphTokenSource].GetMethod('Acquire').ReturnType.FullName |
    Should -Be 'GraphKit.Auth.GraphTokenResult'
```

Reflect over every public type/member signature and fail when the declaring assembly or full type
name contains `Microsoft.Identity.Client`.

- [x] **Step 2: Run the two files and verify red**

Expected: missing assembly/package path failures only.

- [x] **Step 3: Commit tests only**

```bash
git add tests/Unit/Auth/GraphKitAuth.Tests.ps1 tests/QA/GraphKitAuthPackage.tests.ps1 tests/QA/PackageDependencies.tests.ps1
git commit -m "test: define the GraphKit Auth package boundary"
```

### Task 3: Implement the dependency-free contract assembly

**Files:**

- Create: `global.json`
- Create: `src/GraphKit.Auth/Directory.Build.props`
- Create: `src/GraphKit.Auth/GraphKit.Auth.Contracts/GraphKit.Auth.Contracts.csproj`
- Create: `src/GraphKit.Auth/GraphKit.Auth.Contracts/Contracts.cs`
- Create: `src/GraphKit.Auth/GraphKit.Auth.Contracts/GraphTokenSourceProxy.cs`
- Create: `src/GraphKit.Auth/GraphKit.Auth.Contracts/GraphAuthLoadContext.cs`
- Create: `src/GraphKit.Auth/GraphKit.Auth.Contracts/GraphAuthHost.cs`

- [x] **Step 1: Pin the SDK and deterministic defaults**

`global.json`:

```json
{
  "sdk": {
    "version": "10.0.400",
    "rollForward": "disable",
    "allowPrerelease": false
  }
}
```

`Directory.Build.props` sets `TargetFramework=net8.0`, `Nullable=enable`,
`ImplicitUsings=enable`, `TreatWarningsAsErrors=true`, `Deterministic=true`,
`ContinuousIntegrationBuild=true`, `DebugType=None`, and
`RestorePackagesWithLockFile=true`.

- [x] **Step 2: Implement ABI-v1 DTOs and interfaces**

Use sealed mutable-result/plain-constructor types, not records and not PowerShell types. Validate
null/empty strings, absolute HTTPS authorities/resources, GUID presence by auth mode, credential
discriminator agreement, private-key presence, and non-empty generation before a provider loads.

The result must retain a settable `VerifiedTenantId`:

```csharp
public sealed class GraphTokenResult
{
    public required string AccessToken { get; init; }
    public DateTimeOffset ExpiresOnUtc { get; init; }
    public DateTimeOffset ReceivedOnUtc { get; init; }
    public required string TokenType { get; init; }
    public required string[] Scopes { get; init; }
    public string? VerifiedTenantId { get; set; }
    public required string TokenFingerprint { get; init; }
    public required string CredentialGeneration { get; init; }
}
```

- [x] **Step 3: Implement strict loader and proxy lifetime**

`GraphAuthLoadContext.Load` returns the default contracts assembly for the exact matching contract
name and uses `AssemblyDependencyResolver` for every isolated dependency. It rejects a second
contracts copy, an unexpected provider name/version, and a provider path outside the declared
payload root. Host import validates `GraphKit.Auth.Abi/1`; an incompatible contracts assembly
already loaded in the default context fails with an instruction to start a fresh PowerShell
process.

`GraphTokenSourceProxy` uses `Interlocked` state, forwards contract members, clears the inner source
on dispose, and tells the host exactly once. It never catches and relabels provider exceptions.

- [x] **Step 4: Build the contracts project**

Run:

```bash
dotnet build src/GraphKit.Auth/GraphKit.Auth.Contracts/GraphKit.Auth.Contracts.csproj -c Release
```

Expected: zero warnings and errors; no `Microsoft.Identity.Client` in `project.assets.json`.

- [x] **Step 5: Commit**

```bash
git add global.json src/GraphKit.Auth
git commit -m "feat: define the GraphKit Auth ABI"
```

### Task 4: Implement the isolated provider and deterministic .NET tests

**Files:**

- Create: `src/GraphKit.Auth/GraphKit.Auth/GraphKit.Auth.csproj`
- Create: `src/GraphKit.Auth/GraphKit.Auth/GraphTokenSourceFactory.cs`
- Create: `src/GraphKit.Auth/GraphKit.Auth/GraphTokenSource.cs`
- Create: `src/GraphKit.Auth/GraphKit.Auth/MsalTokenClient.cs`
- Create: `src/GraphKit.Auth/GraphKit.Auth.Tests/GraphKit.Auth.Tests.csproj`
- Create: `src/GraphKit.Auth/GraphKit.Auth.Tests/GraphTokenSourceTests.cs`
- Create: `src/GraphKit.Auth/GraphKit.Auth.Tests/OwnershipTests.cs`
- Create: `src/GraphKit.Auth/GraphKit.Auth.sln`

- [x] **Step 1: Write failing .NET source-contract tests**

Use an internal fake acquisition client to prove cache reuse, adaptive refresh, forced-refresh
replacement, cancellation, failed-acquisition fanout, generation rejection, fixed-bearer refusal,
and exactly-once material disposal. A representative test is:

```csharp
[Fact]
public void ForcedRefreshReplacesAnOlderCachedResult()
{
    using var source = SourceFixture.Refreshable("first", "second");
    Assert.Equal("first", source.Acquire(false, CancellationToken.None).AccessToken);
    Assert.Equal("second", source.Acquire(true, CancellationToken.None).AccessToken);
    Assert.Equal("second", source.Acquire(false, CancellationToken.None).AccessToken);
}
```

- [x] **Step 2: Run .NET tests and verify red**

Run:

```bash
dotnet test src/GraphKit.Auth/GraphKit.Auth.Tests/GraphKit.Auth.Tests.csproj -c Release
```

Expected: missing provider/source types.

- [x] **Step 3: Implement the minimal complete provider**

`GraphKit.Auth.csproj` pins:

```xml
<PackageReference Include="Microsoft.Identity.Client" Version="4.82.1" />
<ProjectReference Include="../GraphKit.Auth.Contracts/GraphKit.Auth.Contracts.csproj">
  <Private>false</Private>
  <ExcludeAssets>runtime</ExcludeAssets>
</ProjectReference>
```

The factory accepts one immutable `GraphTokenRequest` containing the source-constant identity and
credential fields and creates one confidential-client or managed-identity MSAL application per
source. Per-call force refresh and cancellation remain arguments to `IGraphTokenSource.Acquire`;
there is no duplicate descriptor DTO. The source computes SHA-256 token fingerprints, uses
`AuthenticationResult.ExpiresOn`, records `ReceivedOnUtc` at successful acquisition, validates
generation on every result/adoption, and never parses a JWT. Fixed bearer returns
`DateTimeOffset.MinValue` expiry and throws on force. Every MSAL exception is caught inside the
isolated provider and converted to a GraphKit-owned `GraphAuthException` without preserving an
MSAL `InnerException` or `Data` value.

- [x] **Step 4: Lock restore and run tests green**

Run:

```bash
dotnet restore src/GraphKit.Auth/GraphKit.Auth.sln --use-lock-file
dotnet restore src/GraphKit.Auth/GraphKit.Auth.sln --locked-mode
dotnet test src/GraphKit.Auth/GraphKit.Auth.Tests/GraphKit.Auth.Tests.csproj -c Release --no-restore
```

Expected: all tests pass, zero warnings, committed lock files name exact MSAL 4.82.1.

- [x] **Step 5: Commit**

```bash
git add src/GraphKit.Auth
git commit -m "feat: add the isolated GraphKit Auth provider"
```

### Task 5: Integrate compiled build, package, and CI

**Approved base:** `a8b74d8df692e70bb89d1645796c6cecae31aafc`, independently approved with
no Critical, Important, or Minor findings. Verify this literal HEAD and a clean tracked worktree
before writing tests; stop if either differs.

**Files:**

- Create: `.build/GraphKitAuth.tasks.ps1`
- Create: `scripts/private/GraphKit.AuthStageCapture.cs`
- Modify: `build.yaml`
- Modify: `.github/workflows/ci.yml`
- Modify: this complete Task 5 section
- Modify: `scripts/Test-GraphKitReleaseProof.ps1`
- Modify: `source/GraphKit.psd1` only if needed to make its empty source-manifest
  `RequiredAssemblies` intent explicit
- Test: `tests/QA/GraphKitAuthPackage.tests.ps1`
- Test: `tests/QA/BuiltModule.tests.ps1`
- Test: `tests/QA/ReleaseProof.tests.ps1`

Do not modify the PowerShell authentication bridge, remove `Microsoft.Graph.Authentication`, alter
public commands, perform live authentication, touch a vault or tenant, create Azure resources, or
implement Tasks 6-10. Preserve the immutable public `0.3.0` artifact.

#### Controller rulings

The sealed stage protects against accidental mutation and unprivileged or different-identity
writers. Require fresh create-new topology, physical containment, no links or aliases, stable native
identities, regular-file link count one, exact closure and digest revalidation, and owner-only sealed
permissions. Directory link counts are platform-defined and are not required to be one. Do not
claim resistance to the filesystem owner, administrator/root, writable ancestors, or an actor able
to re-grant permissions. The path-based loader is not an adversarial atomic byte-binding mechanism.

Keep mutable compiler output and authorized stage bytes separate:

```text
output/GraphKit.Auth/capture/.build-<unique-secure-run-id>/publish/{provider/,payload/}
output/GraphKit.Auth/capture/.build-<unique-secure-run-id>/dotnet-test/
output/GraphKit.Auth/capture/<unique-secure-run-id>/{manifest.json,payload/}
output/GraphKit.Auth/stage/<full-module-version>/<manifest-sha256>/{manifest.json,payload/}
```

`stage` is never the direct `dotnet publish` destination. A version path is create-new and fails
closed if it exists; it is never reused, merged, or overwritten. Bind Task 5 to one Release lineage:
locked restore, build without restore, machine-readable xUnit with no build or restore and no
skipped/unexecuted outcome, then provider publish without build or restore. Contracts, tested
provider, and published provider must come from that one build. The build workspace is one exact
owner-only child created before either mutable output root; no top-level `publish` or `dotnet-test`
child is permitted beneath the GraphKit.Auth authority root.

The focused private C# helper is authorized only for relative no-follow opens, physical
containment, native identity and link count, stable-handle hashing, and platform permission
evidence. Do not modify `GraphKit.SourceCapture.cs` or embed a large native implementation in the
Invoke-Build task. The helper is build-time/private and changes no public or runtime ABI.

- [x] **Step 1: Record the approved baseline and write genuine failing tests**

Record the approved boundary before implementation: 48 .NET tests; 23 focused
`GraphKitAuth.Tests.ps1` cases; 8 package cases; and 31 combined cases with 26 passed and exactly
five missing direct package paths. Reds must be attributable to absent Task 5 behavior, with no
discovery error, skip, or NotRun.

Test all five package paths, exact five-file closure, existing-version refusal without mutation,
and missing, extra, renamed, writable, byte-mutated, byte-identical-replaced, hard-linked,
escaped-linked, case-aliased, separator-aliased, Unicode-normalization-aliased, symlink, and
junction/reparse mutations. Require native identity stability and link count one for regular files
and the manifest, but never require directory link count one. Keep the source `RequiredAssemblies`
empty and the built value exact. Match stage, built-module, and archive digests. Use a fresh process
to load contracts in Default ALC and the provider/MSAL/IdentityModel in one named collectible ALC,
construct without acquisition from the reverified sealed payload, preserve any Default-ALC MSAL,
and prove unload.

Extend release-proof mutations for exact duplicates, portable case, NFC, separators, traversal,
and ZIP external attributes encoding symlinks, reparse points, or non-regular files. Negative
fixtures must not contact Graph, read a vault, acquire a token, or require external state.

- [x] **Step 2: Implement one locked build lineage and fresh sealed staging**

`Build_GraphKitAuth` asserts `dotnet --version` is exactly `10.0.400`, restores the solution once
with `--locked-mode`, builds the complete Release solution with `--no-restore`, runs the Release test
project with `--no-build --no-restore`, and publishes only the already-built provider with
`--no-build --no-restore --no-self-contained` and no RID. Parse TRX and require at least the approved
48 tests with `total = executed = passed` and zero failed, skipped, not-executed, aborted, timeout,
or error outcomes. Preserve `TreatWarningsAsErrors` and compare provider and dependency identities
and digests across the build/test/publish lineage.

Raw provider publish is untrusted and contains exactly:

```text
GraphKit.Auth.dll
GraphKit.Auth.deps.json
Microsoft.Identity.Client.dll
Microsoft.IdentityModel.Abstractions.dll
```

Obtain `GraphKit.Auth.Contracts.dll` separately from the same build, verify its dependency-free
identity and lineage, and form the exact fixed five-file payload. Verify managed identities,
including MSAL `4.82.1.0` and IdentityModel `8.14.0.0`; do not permit another runtime dependency.

Create an owner-only capture on the same filesystem. Copy each file individually with create-new
semantics, flush it, reopen without following links, and verify digest, native identity, link count,
closure, containment, and aliases. Write a fixed-property-order canonical UTF-8-without-BOM manifest
containing no absolute path, run ID, timestamp, or volatile data. It records full module version,
ordinal payload paths, lengths, SHA-256 values, native file identities, link counts, directory
identities, and final permission policy; it does not recursively contain its own hash or identity.
The manifest itself is a no-follow regular link-count-one file.

Seal all files and directories against owner writes, using exact Unix modes or protected Windows
ACLs rather than the read-only attribute alone. Hash canonical manifest bytes, same-filesystem
atomically rename the capture into `stage/<full-version>/<manifest-sha256>`, then reopen and
revalidate the manifest-name/hash binding, closures, identities, permissions, aliases, and physical
containment. `manifest.json` is metadata; only `payload/` supplies runtime bytes.

`Prepare_GraphKitAuth_Clean` runs before Sampler `Clean`. It first verifies every prior stage and
may unseal only exact physically contained envelopes whose canonical manifest, digest path,
identities, permissions, and closure pass. Missing or forged manifests, partial sealing, links,
aliases, and containment ambiguity fail closed before `Clean`.

Machine-readable .NET results and provider-publish scratch live only below one unique owner-only
`output/GraphKit.Auth/capture/.build-<run-id>/` workspace. Once the sealed stage no longer depends
on its payload source, an outer `finally` atomically moves that exact captured workspace, with
no-replace semantics, into a task-specific `output/GraphKit.Auth.quarantine-<id>/` sibling. This
workspace move is independent of the source-build quarantine and runs on both success and failure,
so a completed build restores an empty `capture` root before returning. A hard process death can
leave the workspace in `capture`; the next Prepare must fail closed rather than delete it.

Separately, after capture and before module version is recalculated, move only these literal source
generated roots intact into the same recoverable task-specific quarantine, including on failure:

```text
src/GraphKit.Auth/GraphKit.Auth.Contracts/bin
src/GraphKit.Auth/GraphKit.Auth.Contracts/obj
src/GraphKit.Auth/GraphKit.Auth/bin
src/GraphKit.Auth/GraphKit.Auth/obj
src/GraphKit.Auth/GraphKit.Auth.Tests/bin
src/GraphKit.Auth/GraphKit.Auth.Tests/obj
src/GraphKit.Auth/GraphKit.Auth.Tests/TestResults
```

Do not resolve these through recursion, wildcard expansion, or discovery. Quarantine must finish
before module version or proof state is recaptured.

The approved Task 3/4 ABI Pester boundary resolves its actual-provider candidate from three of
those historical source-build paths. After release-proof capture, materialize only the sealed,
immediately reverified five payload files at those exact paths for that test boundary; refuse any
pre-existing destination and require every copied digest and link count to match the manifest.
Use a temporary process-scoped `core.excludesFile` containing exactly five root-anchored literal
file patterns, saving and restoring every inherited `GIT_CONFIG_*` value without changing any Git
configuration file. Prove an unrelated untracked sentinel still changes source identity. One
outer `try/finally` runs Pester, removes exactly the five files and only empty literal parents,
restores Git environment, and proves fingerprint/status restoration before release-proof
finalization runs with no exclusion active. This is test-fixture projection from the authorized
stage, not another build or another package source.

- [x] **Step 3: Copy only a freshly reverified stage into the built module**

Immediately before copy, repeat the full sealed-stage verification. Create
`Assemblies/GraphKit.Auth` fresh and copy the five literal names individually with create-new
semantics; never use `Copy-Item *`. Rehash destinations and reject extras, links, aliases, or
replacement. Only after contracts exists, update only the built manifest so `RequiredAssemblies`
is exactly `@('Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll')`, then run
`Test-ModuleManifest`. Keep the source value empty and retain both current runtime modules.

The build order is exact:

```text
Prepare_GraphKitAuth_Clean
  -> Clean
  -> Build_GraphKitAuth
  -> Build_Module_ModuleBuilder
  -> Copy_GraphKitAuth_Into_BuiltModule
  -> Build_NestedModules_ModuleBuilder
  -> Create_changelog_release_output
  -> package_graphkit_r8_nupkg
```

- [x] **Step 4: Reverify before import and harden canonical proof**

The release-proof verifier must match packed runtime bytes to the sealed manifest and reject
duplicates, portable-case and NFC-equivalent collisions, backslashes, absolute/drive paths,
empty/dot/dot-dot segments, and ZIP link/reparse/non-regular encodings. The package test
independently proves the exact five-file auth subtree. Reverify the stage immediately before the
fresh-process `GraphAuthHost` probe; never load that probe from raw publish or the mutable built
copy. Built and archive bytes independently match all five stage digests.

PowerShell 7.4 CI is the future .NET 8 runtime/import evidence; local xUnit on this host rolls the
net8 project to installed .NET 10. Record the distinction and do not claim observed .NET 8 evidence
until the exact-SHA PowerShell 7.4 row passes.

- [x] **Step 5: Enforce exact-event-source CI and run all gates**

CI retains all six Windows/Ubuntu/macOS by PowerShell `7.4.19`/`7.6.5` rows and triggers on pushes
to `main` and `codex/**`, pull requests, and manual dispatch. Checkout selects PR head repository
and full head SHA for PRs, otherwise current repository and `github.sha`, with `fetch-depth: 0`.
Immediately assert `git rev-parse HEAD` ordinally against that event SHA before SDK setup or restore.
Use one `actions/setup-dotnet@v4` for `10.0.400`, assert the complete three-part PowerShell version,
and reach `Build_GraphKitAuth` through pack in every row. A same-SHA push run is later release
authority; the PR merge-ref run is supplementary.

Run locked dependency restore, pack, focused Auth ABI/package/built/release-proof Pester, then the
full `./build.ps1 -Tasks test`. Require zero failures, discovery errors, skips, and NotRun. After
the dirty candidate is green, commit once, then repeat pack/test on the exact clean commit because
its prerelease identity changes. Run the standalone whole-result gate and canonical verifier
against the already-tested package. Require clean status, `git diff --check`, unchanged lock graphs,
exact five-file closure, no generated files tracked, all seven literal generated roots absent, and
no blanket ignore rule. Retain ignored package, proof, and stage evidence.

- [x] **Step 6: Commit and report**

```bash
git add .build/GraphKitAuth.tasks.ps1 scripts/private/GraphKit.AuthStageCapture.cs build.yaml source/GraphKit.psd1 .github/workflows/ci.yml docs/superpowers/plans/2026-08-30-r8-graphkit-auth.md scripts/Test-GraphKitReleaseProof.ps1 tests/QA/GraphKitAuthPackage.tests.ps1 tests/QA/BuiltModule.tests.ps1 tests/QA/ReleaseProof.tests.ps1
git commit -m "build: package the isolated GraphKit Auth runtime"
```

Write ignored `.superpowers/sdd/2026-08-30-r8-graphkit-auth/task-5-report.md` after the commit with
the exact SHA, red/green counts, SDK/runtime distinction, threat boundary, platform fixtures,
dependency closure, stage/build/archive digests, remaining external CI evidence, and concerns. No
push, PR, publication, tenant, vault, token acquisition, Azure, merge, or gallery action occurs.

### Task 6: Cut built-in context construction over to compiled sources

**Files:**

- Create: `source/Private/TokenSources/New-GraphAuthTokenSource.ps1`
- Modify: `source/Private/Initialize-GraphModuleLifecycle.ps1`
- Modify: `source/Private/TokenSources/GraphTokenSource.ps1`
- Modify: `source/Private/Transport/Send-GraphHttpRequest.ps1`
- Modify: `source/Public/Get-GraphContext.ps1`
- Test: `tests/Unit/Auth/GraphKitAuth.Tests.ps1`
- Test: `tests/Unit/Profiles/Get-GraphContext.Tests.ps1`
- Test: `tests/Adapter/Send-GraphHttpRequest.Tests.ps1`

- [x] **Step 1: Write failing bridge/ownership tests**

Assert that production certificate, client-secret, managed-identity, and bearer contexts return an
object implementing `GraphKit.Auth.IGraphTokenSource`; `-TokenProvider` and `-MsalFactory` return the
legacy same-runspace source. Assert that persisted PFX bytes are read once, unsupported vault
version metadata fails before vault access, and failed host creation disposes owned material.

- [x] **Step 2: Verify red**

Run the three focused Pester files. Expected: built-in contexts still return PowerShell classes.

- [x] **Step 3: Implement the bridge**

`New-GraphAuthTokenSource` constructs a `GraphTokenRequest` and transfers material only
after generation verification. Production `New-GraphTokenSource` selects it when `-MsalFactory` is
absent. Register the host before any source and register each compiled source as GraphKit-owned.

In the sender, adopt shared results for either legacy `GraphTokenSourceBase` or compiled
`IGraphTokenSource`. Apply the creation-runspace preflight only to the legacy base class.

- [x] **Step 4: Run focused tests green and commit**

```bash
git add source/Private/TokenSources/New-GraphAuthTokenSource.ps1 source/Private/Initialize-GraphModuleLifecycle.ps1 source/Private/TokenSources/GraphTokenSource.ps1 source/Private/Transport/Send-GraphHttpRequest.ps1 source/Public/Get-GraphContext.ps1 tests/Unit/Auth/GraphKitAuth.Tests.ps1 tests/Unit/Profiles/Get-GraphContext.Tests.ps1 tests/Adapter/Send-GraphHttpRequest.Tests.ps1
git commit -m "feat: use compiled token sources for built-in auth"
```


### Task 7: Prove deterministic parity and genuine cross-runspace use

**Approved base:** exact independently approved clean Task 6 commit
`d16ca572f3746a596456dc8421d4b821f8bcc583`. At dispatch, require
`git rev-parse HEAD` to equal that SHA and `git status --short` to be empty. The stale tracked
Task 7 plan section is a known exception on this sealed base; replacing it is the first tracked
Task 7 edit and remains part of the one Task 7 implementation commit.

**Files:**

- Modify: `docs/superpowers/plans/2026-08-30-r8-graphkit-auth.md`
- Create: `tests/Fixtures/GraphKitAuthParityCases.json`
- Create: `src/GraphKit.Auth/GraphKit.Auth.Tests/GraphTokenSourceParityTests.cs`
- Create: `tests/Unit/Auth/GraphKitAuthParity.Tests.ps1`
- Create: `tests/Concurrency/GraphKitAuthRunspace.Tests.ps1`
- Modify: `src/GraphKit.Auth/GraphKit.Auth.Tests/GraphKit.Auth.Tests.csproj`
- Modify: `src/GraphKit.Auth/GraphKit.Auth.Tests/OwnershipTests.cs`
- Modify: `src/GraphKit.Auth/GraphKit.Auth.Contracts/GraphAuthHost.cs`
- Modify: `source/Private/TokenSources/GraphTokenSource.ps1`
- Modify: `tests/Unit/TokenSources/GraphTokenSource.Tests.ps1`
- Modify: `tests/Concurrency/TokenIsolation.Tests.ps1`
- Modify: `tests/Adapter/GraphModuleLifecycleSender.Tests.ps1`
- Modify: `tests/Unit/Transport/GraphModuleLifecycle.Tests.ps1`
- Modify: `tests/Unit/Auth/GraphKitAuth.Tests.ps1`

Do not change public command signatures, the frozen CLR ABI, runtime package closure,
dependency/import guard, package identity policy, or Task 8+ implementation files. Do not contact
Graph, a real vault/credential, tenant, IMDS, or Azure; do not push, publish, or use Pester
parallelism. A locked-cache miss that would require network access stops for controller authority.

#### Controller rulings

Parity covers normalized behavior common to legacy and compiled sources using one strict checked-in
matrix with independently authored literal expectations for each runner. Disposal, reference
clearing, owned-material drain, host shutdown, and ALC unload are compiled-only successor guarantees
because legacy PowerShell sources are not `IDisposable`; never retrofit legacy disposal for symmetry.

Parent-created contexts and sources enter child thread runspaces only through a unique AppDomain
holder. Child `ArgumentList` carries primitive manifest paths, holder keys, and flags. A required
child module import may automatically create that module instance's ordinary module-scoped host,
but Step 5 children never construct a host, context, source, profile, or vault and use only the exact
parent context/source recovered from the holder; their automatic import host is unused and cleaned.
Step 6's separate owning lifecycle job may create the synthetic public fixed-bearer context solely
to prove module removal, later-use refusal, and ALC collection. Every child module is removed and its
cleanup observed before the parent ALC collection assertion.

The real fixed-bearer runspace gate uses public `Get-GraphContext` against a temporary raw schema-1
profile containing a clearly synthetic inline `Credential.Token`. It does not use
`Register-GraphTenant`, SecretManagement, a vault, `-MsalFactory`, or private source construction;
this test fixture is not a supported operator workflow for real bearer tokens.

Add private bounded waiter-count instrumentation to `GraphTokenFlight` as the outer-flight
happens-before gate. Do not alter keys, results, removal races, cancellation replacement, public
commands, or the frozen CLR ABI.

Prove lifecycle by composition without production marker hooks: provider xUnit owns source/material
drain; retained Task 3 gates own host/proxy shutdown and unload; module tests own actual registration
plus generic test-probe LIFO; packaged fixed bearer owns exact runspace crossing, use-after-removal,
and ALC collection.

Tests for behavior already delivered by Tasks 3-6, including compiled runspace neutrality, may
characterize green on the clean base only when a reversible semantic mutation makes the intended
named case fail and the source is restored byte-for-byte. New Task 7 waiter instrumentation and
dead-host-field removal require genuine base failures; any lifecycle behavior absent on the base
does too. The new runspace harness itself is not a production red: mutation-prove that it rejects
source reconstruction, legacy cross-runspace use, lost `ReferenceEquals`, and leaked child module
hosts. Discovery/setup errors, stale output, skips, NotRun, timing, and external state are invalid
reds.

Five count authorities remain separate. Task 7 records and asserts exact post-discovery equality for
.NET, focused Pester, Task 6 owning, expanded regression, and whole Pester. The existing build check
accepting at least 48 .NET tests is not Task 7 count authority; durable global ratchet
synchronization remains Task 9 scope.

- [x] **Step 1: Replace the tracked plan section and record exact clean baselines**

Verify exact HEAD and clean status, then replace the complete tracked Task 7 section with this final
controller contract before authoring tests. Do not create an intervening documentation commit.

Record these exact clean Task 6 baselines:

```text
.NET GraphKit.Auth:             48
Task 7 focused Pester:          95
Task 6 owning Pester:          246
Task 6 expanded regression:    440
Whole repository Pester:     1,180
```

The focused baseline is the sum of the five existing Task 7 files on clean Task 6:
`TokenIsolation` 8, `GraphTokenSource` 48, `GraphModuleLifecycleSender` 2,
`GraphModuleLifecycle` 13, and `GraphKitAuth` 24. The two new files contribute zero at base.

- [x] **Step 2: Add the strict shared 16-row matrix and test-only discovery**

Create `GraphKitAuthParityCases.json` with exact top-level fields `schemaVersion`, `rowCount`, and
`rows`; require schema `1` and `rowCount` `16`. Every row has exactly `id`, `runners`, `scenario`,
`authMode`, `callLayerByRunner`, `input`, and `expectedByRunner`. Every row runs once in both
`xunit-compiled` and `pester-legacy`.

| Row ID | Auth mode | xUnit layer | Pester layer |
| --- | --- | --- | --- |
| `construction-certificate` | Certificate | construction only | construction only |
| `construction-client-secret` | ClientSecret | construction only | construction only |
| `construction-managed-identity` | user-assigned ManagedIdentity | construction only | construction only |
| `construction-bearer-token` | BearerToken | construction only | construction only |
| `ordinary-cache-hit` | Certificate | direct source | direct source |
| `expired-result-refresh` | ClientSecret | direct source | direct source |
| `ordinary-forced-ordinary` | ManagedIdentity | direct source | direct source |
| `acquisition-failure-fanout-retry` | Certificate | compiled internal source flight | legacy production outer keyed flight |
| `caller-cancellation-no-cache` | ClientSecret | direct source | direct source |
| `fixed-bearer-cache-force-refusal` | BearerToken | direct source | direct source |
| `fingerprint-certificate` | Certificate | direct source | direct source |
| `fingerprint-client-secret` | ClientSecret | direct source | direct source |
| `fingerprint-managed-identity` | ManagedIdentity | direct source | direct source |
| `fingerprint-bearer-token` | BearerToken | direct source | direct source |
| `adoption-generation-mismatch` | Certificate | direct source | direct source |
| `adoption-valid` | ManagedIdentity | direct source | direct source |

Each `expectedByRunner` record is independently and literally authored for its runner with one
closed field set: source contract/metadata, token sequence, expiries, token types, ordered scopes,
tenant proof, fingerprint, generation, received-time rule, application/provider acquisition counts,
force flags, reference identity, normalized failure kind, cache state, and final flight-registry
count. Null and empty values remain explicit. Neither runner derives expectations from production
code, matrix input, or the other runner.

Compare token, expiry, type, ordered scopes, tenant proof, fingerprint, generation, and source
metadata ordinally. Check reference identity separately. Normalize only `AcquisitionFailure`,
`Canceled`, `RefreshRefused`, `GenerationMismatch`, and `Disposed`. Legacy `ReceivedOnUtc` is
wall-clock: require non-default, monotonic, and no later than valid expiry. Compiled acquisition time
uses the injected clock; adopted literal results retain their supplied time in both runners.

Construction expects zero token acquisitions. Compiled Certificate, ClientSecret, and
ManagedIdentity create exactly one application/client during factory construction; legacy
`-MsalFactory` remains uninvoked until acquisition. BearerToken creates none.

Use these exact fingerprint inputs and literal lowercase SHA-256 values:

```text
task7-fingerprint-certificate
245d574cc6b41262c018a65535f9937601045f29abff3df9d112e491048948b6
task7-fingerprint-client-secret
b4ec6c20d74417b5be0b54ce83bc39a9f0b2e990ec173e6ee9373491a65de55e
task7-fingerprint-managed-identity
6973fa751d466a0429077804c84708dc98188047d415ca992a583a6bf7744866
task7-fingerprint-bearer-token
04fa2face75f1b6e4df7e9270266abec23741a9e91c7fad9b12b1c8585c30bca
```

Both loaders independently reject these nine permanent malformed cases:

```text
unsupported-schema-version
incorrect-row-count
duplicate-row-id
missing-required-row-id
unknown-property
missing-required-property
duplicate-json-property
invalid-runner-call-layer
missing-runner-expectation
```

They also reject unknown or wrong-typed fields, invalid ID/runner sets, and duplicate JSON
properties before executing any semantic row. Mutation cases must be individually discoverable in
both runners rather than hidden in a setup failure.

Link the exact repository fixture into the .NET test output:

```xml
<None Include="../../../tests/Fixtures/GraphKitAuthParityCases.json"
      Link="Fixtures/GraphKitAuthParityCases.json"
      CopyToOutputDirectory="PreserveNewest"
      CopyToPublishDirectory="Never" />
```

xUnit loads only `AppContext.BaseDirectory/Fixtures/GraphKitAuthParityCases.json`; Pester loads only
`<repo>/tests/Fixtures/GraphKitAuthParityCases.json`. No current-directory or alternate fallback is
allowed. Each reports the same matrix SHA-256 and proves no row was filtered.

After all test-only files/changes discover successfully and before any production edit, record a
literal per-file and per-theory inventory. Let `D`, `F`, `O`, `E`, and `W` be net new .NET,
Task 7 focused, Task 6 owning, expanded-regression, and whole-repository discoveries. Assert exact
equality, never a minimum:

```text
.NET exact total              = 48 + D
Task 7 focused exact total    = 95 + F
Task 6 owning exact total     = 246 + O
Expanded exact total          = 440 + E
Whole Pester exact total      = 1,180 + W
```

The planned .NET ledger is `+16` semantic rows, `+9` loader-mutation cases, `+2`
Certificate/ClientSecret drain-theory cases, and `-1` superseded single-mode fact: planned net
`D = 26`, exact .NET total `74`. Any discovery difference stops the task for inventory
reconciliation before production work. Additional reviewed cases must be itemized into `D`.

Run the test-only base phase. Characterization-green Task 3-6 families, including the new harness
over already runspace-neutral compiled sources, require reversible mutation proof; genuinely absent
Task 7 waiter/dead-field/lifecycle behavior must fail for the intended reason. Restore every
mutation byte-for-byte and repack before proceeding.

- [x] **Step 3: Make compiled-source drain deterministic for both owned modes**

Replace the existing single-mode, delay-based active-acquisition disposal fact with a
Certificate/ClientSecret theory. The fake client signals entry, waits on the supplied cancellation
token, records cancellation, exits, and only then may material cleanup record disposal. Require:

```text
acquire-entered -> cancellation-observed -> acquire-exited -> material-disposed
```

Require one client and one material disposal, bounded event/task completion, and no sleep, finite
`Task.Delay`, or `CancelAfter` as ordering evidence.

- [x] **Step 4: Add exact outer-flight waiter instrumentation**

Add private thread-safe follower entry/departure counts to `GraphTokenFlight`. Increment only after
a follower obtains the exact registry flight and before it awaits; decrement in `finally`. Expose
only minimal in-module observation to tests.

Remove duration-based scheduling assumptions from the Task 7 file set. Leaders/providers wait on
explicit gates. Tests require exact bounded waiter counts before release, failure, cancellation,
disposal, or replacement. Cancellation-aware infinite waits used only to model work until
cancellation are allowed; elapsed duration is never evidence.

Cover ordinary collapse, provider-failure fanout, leader-cancellation replacement,
production-sender collapse, ordinary/forced partitioning, concurrent credential reuse,
active-source disposal, and exact empty-registry cleanup.

- [x] **Step 5: Prove exact parent-source use across thread runspaces**

Use `Start-ThreadJob` with a GUID AppDomain holder containing the parent context/source,
ready/go/release gates, a `ConcurrentQueue<object>` of child-observed sources, counters, and results.
Children retrieve and enqueue the actual parent source; the parent requires `ReferenceEquals` for
every child.

Every case is bounded: child ready uses `Wait(5000)`; provider work waits on a
cancellation-aware gate; the parent uses `Wait-Job -Timeout 10` and `Receive-Job` without `-Wait`.
`finally` releases/cancels gates, removes modules/jobs, clears AppDomain data and references, and
disposes synchronization objects. No unbounded wait, sleep, delay, `Receive-Job -Wait`, child
`Get-GraphContext`, request reconstruction, profile/vault access, or explicit host/source creation.

Each child retains its exact imported `ModuleInfo`, removes it in `finally`, requires that module's
lifecycle `CleanupDone.Wait(5000)`, clears child module/host references, and reports cleanup before
the parent removes the job. The import-created child host is allowed but never used as the parent
source under test.

Required cases:

1. A real compiled fixed-bearer context created through public `Get-GraphContext` against a temporary
   raw schema-1 store whose only material is
   `Credential.Token = 'task7-synthetic-fixed-bearer-token'`. Use a fixed synthetic TenantId,
   `ClientId = $null`, no selector, no `-MsalFactory`, vault, or private constructor. Two children
   prove exact source identity, stable same result reference/token, and force refusal. Delete the
   store in `finally`.
2. Distinct controlled tenant/source/key fixtures released together show no token, fingerprint,
   proof, generation, or adoption crossover and perform no network call.
3. Two sources with one key show exact follower count, one acquisition, one adoption, identical
   result reference/properties, and empty registry.
4. One ordinary and one forced flight for one tuple are simultaneously resident, receive exact
   force flags, make two calls, never join, and do not contaminate unrelated cache state.
5. A legacy `GraphTokenSourceBase` rejects cross-runspace before entering or waiting on a flight;
   label this compatibility containment.

A controlled C# sender fixture may implement the default-context interface for observations, but
cannot replace the real public fixed-bearer case or production-source xUnit matrix.

- [x] **Step 6: Prove lifecycle by composition and collect the packaged ALC**

Remove unused private `_drained`, `_shutdownCompleted`, and their dead Reset/Set calls from
`GraphAuthHost`. Assert those fields absent while the literal public ABI and retained Task 3
shutdown, reentrant cancellation, sanitized failure, clearing, and weak-reference gates stay green.

Do not add production marker hooks. Prove:

- provider xUnit: Certificate and ClientSecret cancellation/drain/material order;
- retained Task 3: host/proxy shutdown and unload;
- actual module registration by reference as `[real host, real source1, real source2]`;
- generic module cleanup with test-only marker disposables registered as `[host, source1, source2]`
  and disposed exactly once as `[source2, source1, host]`; and
- sender/module integration: cancellation and source drain precede host cleanup,
  `CleanupDone.Wait(5000)` succeeds, active operations are zero, owned resources are empty, and no
  duplicate disposal occurs.

In an isolated bounded thread job, import the package and create the real synthetic fixed-bearer
context. Capture the source, lifecycle state, and host `LoadContextWeakReference`. Finish/clean all
child modules/jobs, remove the owning module, require cleanup complete, zero active operations, and
an empty owned-resource collection.

While retaining the exact source, call `Acquire` and require `ObjectDisposedException`. Only then
clear source, context, module, host, state, holder, queues, closures, AppDomain data, and every other
strong reference. Run a finite GC/finalizer loop and require the provider ALC weak reference dead.

- [x] **Step 7: Run exact focused and complete gates**

Pack before any Pester import. Run locked .NET restore/build/test and parse TRX to require exactly
`48 + D` passed cases and every other outcome zero. The build's existing `>=48` check is not this
authority.

Run repository-pinned Pester 6.1.0 serially over:

```text
tests/Unit/Auth/GraphKitAuthParity.Tests.ps1
tests/Concurrency/GraphKitAuthRunspace.Tests.ps1
tests/Concurrency/TokenIsolation.Tests.ps1
tests/Unit/TokenSources/GraphTokenSource.Tests.ps1
tests/Adapter/GraphModuleLifecycleSender.Tests.ps1
tests/Unit/Transport/GraphModuleLifecycle.Tests.ps1
tests/Unit/Auth/GraphKitAuth.Tests.ps1
```

Require exact `95 + F` with zero failure, skip, NotRun, inconclusive, failed blocks, or failed
containers. Repeat the frozen Task 6 owning and expanded projections at exact `246 + O` and
`440 + E`.

The exact Task 6 owning projection is these seven files, with no implicit glob or helper-owned
addition:

```text
tests/Unit/Auth/GraphKitAuth.Tests.ps1
tests/Unit/Auth/Get-GraphVaultCredential.Tests.ps1
tests/Unit/Profiles/Get-GraphContext.Tests.ps1
tests/Unit/Profiles/Register-GraphTenant.Tests.ps1
tests/Unit/Profiles/Test-GraphTenant.Tests.ps1
tests/Unit/TokenSources/GraphTokenSource.Tests.ps1
tests/Adapter/Send-GraphHttpRequest.Tests.ps1
```

The exact expanded projection is those seven plus these eight files, for 15 total:

```text
tests/Unit/Auth/SecretManagementBoundary.Tests.ps1
tests/Adapter/GraphModuleLifecycleSender.Tests.ps1
tests/Unit/Transport/GraphModuleLifecycle.Tests.ps1
tests/QA/GraphKitAuthPackage.tests.ps1
tests/QA/BuiltModule.tests.ps1
tests/QA/ReleaseProof.tests.ps1
tests/Unit/Profiles/Import-GraphLegacyProfile.Tests.ps1
tests/Unit/Profiles/Use-GraphTenant.Tests.ps1
```

Record per-file counts for both projections before and after Task 7 so `O` and `E` are reproducible.

Run `./build.ps1 -Tasks test`. Before commit, the inner Pester result must equal `1,180 + W`; the
outer tested-release recorder may refuse dirty authority and must be the only outer failure. After
commit, repeat clean and require the whole workflow, proof record, standalone no-rebuild verifier,
generated-output cleanup, and clean status green.

Reject the task if scheduler duration is used as ordering evidence, a child reconstructs a source,
an automatic child host remains alive, generated output is tracked, public ABI changes, or external
access occurs.

- [x] **Step 8: Commit, repeat on exact clean SHA, and report**

Commit only the reviewed file set:

```bash
git add docs/superpowers/plans/2026-08-30-r8-graphkit-auth.md \
  tests/Fixtures/GraphKitAuthParityCases.json \
  src/GraphKit.Auth/GraphKit.Auth.Tests/GraphTokenSourceParityTests.cs \
  src/GraphKit.Auth/GraphKit.Auth.Tests/GraphKit.Auth.Tests.csproj \
  src/GraphKit.Auth/GraphKit.Auth.Tests/OwnershipTests.cs \
  src/GraphKit.Auth/GraphKit.Auth.Contracts/GraphAuthHost.cs \
  source/Private/TokenSources/GraphTokenSource.ps1 \
  tests/Unit/Auth/GraphKitAuthParity.Tests.ps1 \
  tests/Concurrency/GraphKitAuthRunspace.Tests.ps1 \
  tests/Unit/TokenSources/GraphTokenSource.Tests.ps1 \
  tests/Concurrency/TokenIsolation.Tests.ps1 \
  tests/Adapter/GraphModuleLifecycleSender.Tests.ps1 \
  tests/Unit/Transport/GraphModuleLifecycle.Tests.ps1 \
  tests/Unit/Auth/GraphKitAuth.Tests.ps1
git commit -m "test: prove GraphKit Auth parity and runspace isolation"
```

Repeat pack, exact TRX total, focused/owning/expanded Pester equality, complete test, release-proof
verification, generated-output checks, and clean status on the exact clean commit because the
prerelease identity changes with SHA.

Write `.superpowers/sdd/2026-08-30-r8-graphkit-auth/task-7-report.md` outside the commit. Report the
matrix schema and 16 IDs, independent compiled/legacy results, D/F/O/E/W inventories and totals,
object-identity queue evidence, acquisition/adoption/waiter counts, ordinary/forced partitioning,
tenant isolation, certificate/secret phase order, actual registration order, probe LIFO order,
cleanup state, use-after-removal result, ALC result, ABI result, package/source identities, and
evidence limits.

Task 7 makes no live MSAL, Graph, vault, tenant, IMDS, Azure, remote CI, merge, publication, or
service-behavior claim.


### Task 8: Prove protected live parity before transitive cutover

**Files:**

- Create: `scripts/Invoke-GraphKitAuthParity.ps1`
- Create: `scripts/private/Invoke-GraphKitAuthParityWorker.ps1`
- Create: `tests/QA/GraphKitAuthLiveParity.tests.ps1`
- Create: `source/Private/Operations/Assert-GraphOperationAuthMode.ps1`
- Modify: `source/Data/Operations/*.psd1`
- Modify: `source/Private/Operations/Import-GraphOperationDescriptor.ps1`
- Modify: `source/Public/Get-GraphObject.ps1`
- Modify: `source/Public/Invoke-GraphOperation.ps1`
- Modify: `source/Public/Invoke-GraphBatch.ps1`
- Modify: `source/Private/Confirm-GraphTenantBinding.ps1`
- Modify: `source/Private/Invoke-GraphPaging.ps1`
- Modify: `source/Private/Invoke-GraphRetry.ps1`
- Modify: `source/Private/Transport/Send-GraphHttpRequest.ps1`
- Modify: `source/Private/Wait-GraphThrottleGate.ps1`
- Modify: `tests/Adapter/TokenIdentityPipeline.Tests.ps1`
- Modify: `tests/Unit/Auth/Confirm-GraphTenantBinding.Tests.ps1`
- Modify: `tests/Unit/Operations/DescriptorInvariants.Tests.ps1`
- Modify: `tests/Unit/Operations/Get-GraphObject.Tests.ps1`
- Modify: `tests/Unit/Operations/Import-GraphOperationDescriptor.Tests.ps1`
- Modify: `tests/Unit/Pipeline/Invoke-GraphBatch.Tests.ps1`
- Modify: `tests/Unit/Pipeline/Invoke-GraphOperation.Tests.ps1`
- Modify: `tests/Unit/Pipeline/Invoke-GraphPaging.Tests.ps1`
- Modify: `tests/Unit/Throttle/ThrottleGate.Tests.ps1`
- Modify: `tests/Unit/Transport/Invoke-GraphRetry.Tests.ps1`
- Modify: `docs/superpowers/plans/2026-08-30-r8-graphkit-auth.md`
- Modify after separately authorized observed results:
  `docs/superpowers/specs/2026-08-30-r8-graphkit-auth-design.md`

Current Task 8 authority is deterministic only. Do not run live mode, access or change a
credential/profile/vault, contact Graph or a tenant, change a permission, create/delete Azure
resources, use external network access, or push, open/merge a PR, merge, or publish without
separate explicit authority. The ignored controller record
`.superpowers/sdd/2026-08-30-r8-graphkit-auth/progress.md` remains outside every commit.

- [x] **Step 0: Close deterministic prerequisites exposed by the parity red phase**

The protected BearerToken read is not a valid parity proof unless the descriptor catalog and every
descriptor-backed public entry point actually allow that mode. Normalize `SupportedAuthModes` to
the four implemented public modes, reject empty, unknown, non-string, or case-insensitive duplicate
values at descriptor import, and fail closed before URI construction or transport in
`Get-GraphObject`, descriptor-mode `Invoke-GraphOperation`, and descriptor-backed
`Invoke-GraphBatch`. Preserve the explicit `Provider`-context exemption and raw-mode compatibility.

A successful safe read is not protected-live evidence unless its tenant proof is the proof returned
by the transport for that same token. Require tenant proof for descriptors whose
`IdentityRequirement` is `Verified`; reject blank or ambiguous token identity before caching;
preserve cloud, client, fingerprint, generation, actual tenant, and proof provenance through every
page; and enforce the caller's one inherited deadline across admission, acquisition, nested proof,
retry delay, paging, and the final target send. Cancellation wins when caller cancellation and
deadline expiry coincide. No row may be retained and no target request may be sent after proof,
identity, cancellation, or deadline certainty is lost.

Write focused red tests for the catalog and every public execution path, Provider/raw exemptions,
cache-key collisions, proof scope, verified paged provenance, cached-proof deadline expiry,
acquisition/proof boundary expiry, admission and retry-delay clamping, and cancellation forwarding.
Require independent static review of both prerequisite tranches before the first coherent pack.
Land the reviewed prerequisite repair as its own commit before the runner commit so the artifact
lineage records why previously inert descriptor metadata and unpropagated read proof changed.

Stage that prerequisite commit only from this reviewed literal set:

```text
docs/superpowers/plans/2026-08-30-r8-graphkit-auth.md
source/Data/Operations/AndroidEnrollmentProfile.List.psd1
source/Data/Operations/AndroidManagedStoreAccountEnterpriseSettings.Get.psd1
source/Data/Operations/AppConfigurationPolicy.List.psd1
source/Data/Operations/AppInstallSummaryReport.Get.psd1
source/Data/Operations/AppProtectionPolicy.List.psd1
source/Data/Operations/AppleEnrollmentProgramToken.List.psd1
source/Data/Operations/ApplePushNotificationCertificate.Get.psd1
source/Data/Operations/AppleVppToken.List.psd1
source/Data/Operations/AuthenticationMethodsPolicy.Get.psd1
source/Data/Operations/AuthorizationPolicy.Get.psd1
source/Data/Operations/AutopilotDevice.List.psd1
source/Data/Operations/CertificateConnector.List.psd1
source/Data/Operations/ConditionalAccessPolicy.List.psd1
source/Data/Operations/ConfigurationConflict.List.psd1
source/Data/Operations/ConfigurationPolicy.AssignBeta.psd1
source/Data/Operations/ConfigurationPolicy.ListBeta.psd1
source/Data/Operations/ConfigurationPolicyAssignment.ListBeta.psd1
source/Data/Operations/ConfigurationPolicySetting.ListBeta.psd1
source/Data/Operations/ConfigurationSettingDefinition.ListBeta.psd1
source/Data/Operations/CrossTenantAccessPolicy.GetDefault.psd1
source/Data/Operations/DeviceCategory.List.psd1
source/Data/Operations/DeviceCategory.ListBeta.psd1
source/Data/Operations/DeviceCompliancePolicy.Assign.psd1
source/Data/Operations/DeviceCompliancePolicy.List.psd1
source/Data/Operations/DeviceCompliancePolicy.ListBeta.psd1
source/Data/Operations/DeviceCompliancePolicyAssignment.List.psd1
source/Data/Operations/DeviceConfiguration.Assign.psd1
source/Data/Operations/DeviceConfiguration.List.psd1
source/Data/Operations/DeviceConfiguration.ListBeta.psd1
source/Data/Operations/DeviceConfigurationAssignment.List.psd1
source/Data/Operations/DeviceEnrollmentConfiguration.List.psd1
source/Data/Operations/DeviceEnrollmentConfiguration.ListBeta.psd1
source/Data/Operations/DeviceManagementConfigurationPolicyTemplate.ListBeta.psd1
source/Data/Operations/DeviceManagementIntent.ListBeta.psd1
source/Data/Operations/DeviceManagementRoleAssignment.List.psd1
source/Data/Operations/DeviceManagementRoleDefinition.List.psd1
source/Data/Operations/DeviceManagementScript.List.psd1
source/Data/Operations/DeviceManagementTemplate.ListBeta.psd1
source/Data/Operations/DeviceManagementUnifiedRoleAssignment.ListBeta.psd1
source/Data/Operations/DeviceReport.Export.psd1
source/Data/Operations/DirectoryRoleAssignment.List.psd1
source/Data/Operations/DirectoryRoleDefinition.List.psd1
source/Data/Operations/DirectoryRoleDefinition.ListBeta.psd1
source/Data/Operations/DirectorySetting.List.psd1
source/Data/Operations/DirectorySettingTemplate.List.psd1
source/Data/Operations/Domain.List.psd1
source/Data/Operations/DomainConnector.List.psd1
source/Data/Operations/EntraDevice.List.psd1
source/Data/Operations/EntraDevice.ListBeta.psd1
source/Data/Operations/Group.Get.psd1
source/Data/Operations/Group.List.psd1
source/Data/Operations/Group.ListBeta.psd1
source/Data/Operations/GroupMember.List.psd1
source/Data/Operations/GroupPolicyConfiguration.ListBeta.psd1
source/Data/Operations/GroupPolicyDefinitionValue.ListBeta.psd1
source/Data/Operations/GroupPolicyPresentationValue.ListBeta.psd1
source/Data/Operations/IntuneBrandingProfile.List.psd1
source/Data/Operations/ManagedDevice.Delete.psd1
source/Data/Operations/ManagedDevice.Get.psd1
source/Data/Operations/ManagedDevice.List.psd1
source/Data/Operations/ManagedDevice.ListBeta.psd1
source/Data/Operations/ManagedDevice.Retire.psd1
source/Data/Operations/ManagedDevice.SyncDevice.psd1
source/Data/Operations/ManagedDevice.Wipe.psd1
source/Data/Operations/ManagedDeviceCleanupRule.ListBeta.psd1
source/Data/Operations/ManagedDeviceSetting.Get.psd1
source/Data/Operations/MobileApp.Assign.psd1
source/Data/Operations/MobileApp.List.psd1
source/Data/Operations/MobileApp.ListBeta.psd1
source/Data/Operations/MobileAppAssignment.List.psd1
source/Data/Operations/MobileAppCategory.List.psd1
source/Data/Operations/MobileThreatDefenseConnector.List.psd1
source/Data/Operations/NamedLocation.List.psd1
source/Data/Operations/OperationApprovalPolicy.List.psd1
source/Data/Operations/Organization.GetMdmAuthority.psd1
source/Data/Operations/Organization.List.psd1
source/Data/Operations/Organization.ListBeta.psd1
source/Data/Operations/RoleAssignmentScheduleInstance.List.psd1
source/Data/Operations/RoleEligibilityScheduleInstance.List.psd1
source/Data/Operations/SecurityDefaultsPolicy.Get.psd1
source/Data/Operations/ServicePrincipal.List.psd1
source/Data/Operations/SubscribedSku.List.psd1
source/Data/Operations/User.List.psd1
source/Data/Operations/WindowsAutopilotDeploymentProfile.List.psd1
source/Data/Operations/WindowsFeatureUpdateProfile.List.psd1
source/Data/Operations/WindowsUpdateCatalogItem.List.psd1
source/Private/Confirm-GraphTenantBinding.ps1
source/Private/Invoke-GraphPaging.ps1
source/Private/Invoke-GraphRetry.ps1
source/Private/Operations/Assert-GraphOperationAuthMode.ps1
source/Private/Operations/Import-GraphOperationDescriptor.ps1
source/Private/Transport/Send-GraphHttpRequest.ps1
source/Private/Wait-GraphThrottleGate.ps1
source/Public/Get-GraphObject.ps1
source/Public/Invoke-GraphBatch.ps1
source/Public/Invoke-GraphOperation.ps1
tests/Adapter/TokenIdentityPipeline.Tests.ps1
tests/Unit/Auth/Confirm-GraphTenantBinding.Tests.ps1
tests/Unit/Operations/DescriptorInvariants.Tests.ps1
tests/Unit/Operations/Get-GraphObject.Tests.ps1
tests/Unit/Operations/Import-GraphOperationDescriptor.Tests.ps1
tests/Unit/Pipeline/Invoke-GraphBatch.Tests.ps1
tests/Unit/Pipeline/Invoke-GraphOperation.Tests.ps1
tests/Unit/Pipeline/Invoke-GraphPaging.Tests.ps1
tests/Unit/Throttle/ThrottleGate.Tests.ps1
tests/Unit/Transport/Invoke-GraphRetry.Tests.ps1
```

- [x] **Step 1: Write and test a digest-bound protected runner**

The public runner keeps its literal six-parameter contract, requires the exact package path and
SHA-256, and accepts one auth mode per invocation. The runner and its private worker are trusted
verifier code. The parent alone snapshots, extracts, seals, retains native identity/closure evidence,
starts the worker, validates its strict nonce- and request-hash-bound primitive JSON response, and
performs exact cleanup. The parent never imports the candidate manifest or loads
`GraphKit.Auth.Contracts`; the worker alone revalidates the sealed state, imports and diagnoses the
candidate, removes it, emits one bounded redacted frame, and exits. No environment-selected role,
scriptblock serialization, raw-stream test hook, or production worker override is accepted.

The parent creates lifecycle ownership before start, withholds stdin until ownership is established,
drains bounded stdout/stderr concurrently under one operation clock plus a bounded teardown phase,
and authorizes cleanup only after root exit, OS-owner emptiness, and EOF on both pipes. Windows uses
an unnamed kill-on-close Job Object and proves its active-process count is zero. Unix starts the
trusted worker in a new session/process group and proves that group empty; this covers the worker and
descendants that remain in that group, while inherited stdout/stderr EOF is an additional escape
detector. This is lifecycle containment within the same-identity, non-adversarial verifier boundary,
not a hostile-process sandbox: a descendant that deliberately creates a new session/group and closes
both IPC streams is outside the claim. An escaped descendant that retains IPC makes exit
unconfirmed, preserves the sealed stage, and produces `CleanupFailed`. Tests pin normal and forced
exit, a grandchild retaining a staged DLL and stdout, a Unix `setsid` escape, permanently failing
lifecycle polls, malformed protocol frames, path rederivation, and two sequential imports in one
long-lived parent with no GraphKit assemblies retained there.

Dry-run tests prove certificate, client-secret, managed-identity, and fixed-bearer routing without
reading a credential, calling Graph, granting a permission, or creating Azure resources. Real mode
emits only redacted counts, auth mode, adapter diagnostics, package digest, and success/failure state.

- [x] **Step 2: Commit deterministic prerequisites and runner in sequence**

First commit the reviewed prerequisite set above and repeat its focused and complete local gates on
that exact clean SHA. Then commit only
`docs/superpowers/plans/2026-08-30-r8-graphkit-auth.md`,
`scripts/Invoke-GraphKitAuthParity.ps1`,
`scripts/private/Invoke-GraphKitAuthParityWorker.ps1`, and
`tests/QA/GraphKitAuthLiveParity.tests.ps1`. No observed-evidence file belongs in either commit.

- [x] **Step 3: Pack/test and freeze the exact clean runner commit**

Run the complete local gates with the transitive dependency still present but production contexts
already using the isolated provider. Pack, test, run canonical proof and the standalone no-rebuild
verifier on the exact clean runner commit; freeze that verified package outside every Clean/pack
root; record its source revision, full prerelease, package digest, and proof digest. All four DryRun
modes must pass against that one frozen copy. Do not rebuild after the freeze or between live modes.

- [ ] **Step 4: Run Ivy24 parity only after separate explicit authority**

Using the exact tested package, prove certificate, client-secret, and fixed-bearer acquisition plus
a safe read. Do not persist tokens, secret values, tenant IDs, client IDs, or response content in
repository evidence.

- [ ] **Step 5: Provision a fresh managed-identity host only after separate explicit authority**

Create the minimum throwaway Azure host and permission grant, install the same package digest,
perform the managed-identity read, record redacted evidence, and delete the host/resources. The
earlier legacy container run is not compiled-provider parity.

- [ ] **Step 6: Commit only redacted observed evidence without rebuilding**

After all four modes pass against one frozen artifact under separately authorized live execution,
commit only `docs/superpowers/specs/2026-08-30-r8-graphkit-auth-design.md`. That docs-only evidence
commit is not the packaged source revision and must not trigger a rebuild or change the frozen
artifact. Do not proceed to dependency removal until all four applicable protected-live parity
modes pass.

### Task 9: Remove transitive MSAL and run the final local gate

**Files:**

- Modify: `source/GraphKit.psd1`
- Delete: `source/Private/Assert-GraphMsalEnvironment.ps1`
- Modify: `source/Private/TokenSources/New-GraphMsalApplication.ps1`
- Modify: `tests/QA/ImportOrderMatrix.tests.ps1`
- Modify: `tests/QA/PackageDependencies.tests.ps1`
- Modify: `tests/Unit/Auth/MsalGuard.Tests.ps1`
- Modify: `scripts/Install-GraphKitPinned.ps1`
- Modify: every minimum-test ratchet location reported by `tests/QA/MinimumTestsRatchetSync.tests.ps1`
- Modify: `README.md`
- Modify: `AGENTS.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/superpowers/specs/2026-08-14-graphkit-design.md`
- Modify: `docs/superpowers/specs/2026-08-19-graphkit-tenantpulse-product-program-design.md`
- Modify: `docs/superpowers/specs/2026-08-30-r8-graphkit-auth-design.md`

- [ ] **Step 1: Write red final dependency/import-order tests**

Preload each available competing module in a fresh process, record the default-context MSAL
assembly/version/location before GraphKit import, create a compiled source, and assert:

```powershell
$afterDefault.FullName | Should -Be $beforeDefault.FullName
$diagnostics.MsalVersion | Should -Be '4.82.1.0'
$diagnostics.MsalLoadContext | Should -Not -Be 'Default'
```

Clean package metadata must contain no `Microsoft.Graph.Authentication` dependency.

- [ ] **Step 2: Remove the transitive runtime path**

Remove the manifest dependency and import-time default-ALC guard. Retain legacy factory code only as
the documented `-MsalFactory` compatibility/test path; it may require a caller-supplied factory and
must not make production GraphKit depend on Graph Authentication.

- [ ] **Step 3: Pack before the full test run**

```powershell
./build.ps1 -Tasks pack
./build.ps1 -Tasks test
```

Expected: zero failed, errors, skips, and NotRun across Pester; zero .NET test failures.

- [ ] **Step 4: Synchronize the measured ratchet and repeat**

Update all six ratchet authorities to the actual full Pester total, then pack and run the full suite
again because ratchet files are source changes.

- [ ] **Step 5: Verify exact artifact identity**

Run the standalone whole-result gate and canonical proof verifier. Independently compare built
module, package entries, and proof records byte-for-byte. Require a clean-tree full prerelease,
source revision match, exactly one private MSAL 4.82.1, and no default-context copy.

- [ ] **Step 6: Run clean-install smoke from empty module state**

Install the exact local prerelease into an isolated `PSModulePath`, import in fresh PowerShell 7.4
and 7.6 processes, create fixed-bearer and managed-identity contexts without a vault or Graph SDK,
and assert operation data/default views.

- [ ] **Step 7: Reconcile claims**

Document deterministic completion separately from protected live parity. State the compatibility
scope of `TokenProvider`/`MsalFactory`, the eager local vault read at context creation, exact SDK/MSAL
pins, and the immutable public `0.3.0` boundary.

- [ ] **Step 8: Independent reviews and final local commit**

Require code, silent-failure, type-design, package, and simplification reviews. If any edit results,
repeat pack/test/proof. Commit only the reviewed clean state.

### Task 10: Exact-SHA CI and promotion boundary

**Files:**

- Modify only evidence ledgers/docs after observed results.

- [ ] **Step 1: Push and require six exact-SHA jobs**

Push the R8 branch, open/update one PR, and require Windows, Ubuntu, and macOS on PowerShell 7.4 and
7.6 for the exact final SHA. Do not treat an older green run as evidence.

- [ ] **Step 2: Decide stable publication at the explicit approval gate**

If TenantPulse/CI requires a stable GraphKit dependency, request publication authority for the
already-tested bytes. Publish no rebuilt artifact. Verify gallery hash and clean remote install
before changing TenantPulse's `RequiredVersion`.

- [ ] **Step 3: Mark R8 complete only after every applicable gate**

Until protected live parity and exact-SHA CI are observed, record R8 as implemented/deterministic
but not service-verified. If authority is withheld, retain the exact executable runbook and active
program status; do not convert readiness into completion.

## Self-review record

- Spec coverage: ABI, ALC isolation, four modes, compatibility seams, package identity, deterministic
  parity, runspaces, lifecycle, dependency removal, clean install, CI, live proof, and publication
  boundaries each map to an explicit task.
- Placeholder scan: no implementation step is deferred without an evidence gate; protected actions
  name their authority boundary rather than claiming completion.
- Type consistency: every task uses `GraphKit.Auth.Contracts`, `GraphKit.Auth`,
  `GraphTokenRequest`, `GraphTokenResult`, `GraphAuthException`,
  `IGraphTokenSource`, `IGraphTokenSourceFactory`, and `GraphAuthHost` with the ABI-v1 shapes frozen
  in the R8 design.
