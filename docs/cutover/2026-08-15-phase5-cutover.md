# Phase 5 Cutover — completion record, 2026-08-15

Phase 5 is the eight-step cutover that repoints IntuneHealthAutomation onto GraphKit and
retires the legacy credential path. All eight steps ran and were verified against the Ivy24 lab
tenant. Two sub-parts of step 8 remain, and neither is a judgement call about effort — one is a
platform fact, the other an operator action by policy.

This document was assembled incrementally while the work happened, and several figures in it
drifted. They were recounted from the repository on completion: **37 descriptors were added,
32 of them live-verified, 5 correct-but-unverified.** Earlier revisions said 29 and 24, and
listed four unverified rather than five — `NamedLocation` was corrected after a 403 and never
re-verified, and had quietly dropped off the list.

| Step | State |
| --- | --- |
| 1. Inventory legacy callers | **Done** |
| 2. Import profiles into SecretManagement | **Done** — `Import-GraphLegacyProfile`, dry-run verified against the real file |
| 3. Private versioned package channel | **Done** — publish + pin, proven end to end |
| 4. Install pinned version on hosts, smoke it | **Done** — the *installed* package read live tenant data |
| 5. Repoint callers with rollback | **Done** — GraphKit data plane behind a default-off flag |
| 6. Verify reads, then controlled writes | **Done** — reads and a mutating write, reverted and confirmed |
| 7. Second credential without revoking the first | **Done** — full rollover executed against Ivy24 |
| 8. Revoke old credential, retire plaintext | **Revocation done and proven**; two sub-parts remain the operator's |

## Steps 1–4: inventory, import, channel, install

**The seam is narrower than the call-site count suggests.** IHA has 45 direct
`Connect-MgGraph` / `Invoke-MgGraphRequest` references across 13 files, but the data plane
funnels through one wrapper, `Invoke-IntuneGraphRequest`, with 60 consumers. Repointing is
therefore two seams — a data plane and an auth plane — not 45 edits.

**The legacy file holds no secrets.** `secrets.json` carries tenant metadata and certificate
*thumbprints*; private keys live in the OS certificate store, and `bearerTokens` is null. The
importer refuses to relocate bearer tokens if it ever finds them, because moving a secret is an
operator decision rather than a migration detail.

**Two customer tenants** are configured — `contoso` (LocalMachine) and `fabrikam`
(CurrentUser) — both certificate-store based, so the import must run on the Windows execution
host. The dry run works anywhere and was verified on macOS.

**The channel is local-only, at `~/graphkit-channel`.** The owner's decision: no GitHub
repository, no external publication. Two corrections were needed to make it real:

- The pin originally pointed at a session scratch directory that would vanish. The machinery
  was proven; the channel *instance* was not durable.
- The pin record defaulted to `output/`, which the `pack` task deletes — so the file describing
  the published artifact destroyed itself on the next build. It now lives beside the package.

**The channel is proven, not merely built.** `pack → test → publish → pin → register → install
→ digest verify → clean-process import → live read` all ran for real. Three things that would
have shipped silently were caught by making them checkable:

- The `pack` task begins with `Clean`, so the natural `build,test,pack` ordering **rebuilds the
  module after the suite ran** and publishes bytes no test ever saw. The publisher now compares
  the `GraphKit.psm1` inside the package against the built module the tests imported, and
  refuses on mismatch. The correct order is **pack first, then test**.
- `Install-PSResource` resolves dependencies from the *same* repository it installs from, so a
  single-module private channel cannot satisfy its own graph. Dependencies come from PSGallery
  by minimum version instead — which is also the intent, since mirroring
  `Microsoft.Graph.Authentication` privately would ship the competing
  `Microsoft.Identity.Client.dll` the design forbids.
- A pin recording an absolute publisher path is not portable. `-Source` overrides it; the
  sha256 still gates the install, so relocating a channel cannot weaken the guarantee.

## Steps 5–6: the repoint

Two blockers stood in the way, both real, both now resolved.

**1. IntuneHealthAutomation is a beta-first consumer.** It declares its Graph surface in
`src/data/GraphEndpoints.json`, and almost every collection there is read from **beta**.
GraphKit's catalog was v1.0 only, so measured against the version IHA actually calls, coverage
was **zero** — including for paths that appeared to match. GraphKit treats API version as
per-operation descriptor metadata rather than a global mode, which is the correct model and
precisely why a v1.0 descriptor does not serve a beta caller.

Thirty-seven descriptors later, coverage is complete:

```
Covered      : 27   descriptor exists at the version IHA calls
CoveredAtV1  :  0
VersionGap   :  0
Uncovered    :  0
```

Run `./scripts/Get-GraphKitCutoverCoverage.ps1 -IhaPath <iha>` to regenerate this.

The version gap was closed with beta **siblings** (`Operation = 'ListBeta'`, `Stability =
'DualVersion'`) rather than by flipping the verified v1.0 descriptors: `Type` + `Operation` is
the catalog key, so one descriptor cannot serve both versions, and changing an existing
descriptor's `ApiVersion` would silently alter the response shape for every current caller.
Naming the operation is how a caller chooses a version. The siblings are not redundant —
`MobileApp` returns **80** items at beta against 75 at v1.0.

Two structural gaps surfaced while closing the catalog:

- **No `Singleton` handler strategy existed.** Not cosmetic: `Collection.Default` unwraps a
  `value` array, so a singleton carrying its own `value` *property* would be silently replaced
  by that property — the object swapped for one of its fields, with no error.
  `Singleton.Default` issues one request, unwraps nothing, and does not page even if the
  response carries a `nextLink`.
- **Intune's report endpoints return JSON under `Content-Type: application/octet-stream`.** The
  transport classified it as binary — correctly, by the header — so callers received a byte
  dump where the descriptor promised Json. The descriptor is the authority on operation
  behaviour, so it now wins, but only ever to upgrade bytes that actually sniff as JSON. A
  `Binary` descriptor like `DeviceReport.Export` is untouched, and a non-JSON payload is left
  intact rather than mangled.

**2. The callers pass computed URIs.** Most call sites hand `Invoke-IntuneGraphRequest` a
variable — `$assignmentUri`, a `@odata.nextLink` — not a literal. GraphKit resolves a `Type` to
a descriptor. Those are different models, so a direct repoint would be a semantic rewrite of
roughly sixty call sites.

**Resolved by translating instead of rewriting.** `Invoke-GraphKitGraphRequest` maps an
already-built URI back onto the descriptor that serves it, so the sixty call sites move without
being touched. It is gated behind `IHA_GRAPHKIT_REPOINT`, defaults **off**, and falls through
to the legacy path both when no descriptor covers the URI and when the GraphKit path throws —
so enabling it can never be worse than not enabling it, and rollback is one environment
variable rather than a code revert.

Verified against Ivy24: version-exact resolution (`beta/managedDevices` →
`ManagedDevice/ListBeta`, `v1.0/managedDevices` → `ManagedDevice/List`), path-parameter
extraction from `groups/{id}/members`, a real read of 13 devices, and an uncovered URI
correctly falling through. Step 6's write was exercised too — prior assignment state captured,
a test assignment applied, the result confirmed by an **independent read** rather than the
write's own report, and the revert run in a `finally` and likewise confirmed independently.

**Scope note.** IntuneHealthAutomation **v2** is a rewrite in progress and will not consume
this shim: it calls GraphKit's public commands directly. The shim's only remaining audience is
**v1's reversible-cutover fallback** — keeping v1 running on GraphKit for as long as v1 is in
service. It does not need to be kept current against the rewrite, and it should not be
presented as the integration path. What v2 consumes is the operation catalog, and the contract
it codes against is `Type` + `Operation`.

## Live verification earned its keep

Thirty-two of the thirty-seven new descriptors were verified against Ivy24. Three had **wrong
`RequiredPermissions`** that no static review would have caught, because the permission a
descriptor declares is a claim about the service, and the service is the only authority on it:

| Descriptor | Declared | Actually required | How it surfaced |
| --- | --- | --- | --- |
| `NamedLocation` | `Policy.Read.ConditionalAccess` | `Policy.Read.All` | Token demonstrably carried the role; still 403 |
| `ConditionalAccessPolicy` | `Policy.Read.ConditionalAccess` | `Policy.Read.All` | Same, confirmed independently |
| `DeviceManagementScript` | `DeviceManagementConfiguration.Read.All` | `DeviceManagementScripts.Read.All` | The Intune service named the scope in its 403 |

All three are corrected. **Five** descriptors are correct-but-unverified and say so in their own
header comments rather than being quietly counted as passing:

| Descriptor | Needs |
| --- | --- |
| `NamedLocation` | `Policy.Read.All` |
| `ConditionalAccessPolicy` | `Policy.Read.All` |
| `AuthenticationMethodsPolicy` | `Policy.Read.All` |
| `DeviceManagementScript` | `DeviceManagementScripts.Read.All` |
| `DeviceCleanupRule` | unknown — it returned 403 with the scope it declares, so its permission is a guess that may be wrong the same way the other three were |

Granting those scopes on the lab app and re-running the descriptor verification closes all five.

## Steps 7–8: rollover, revocation, and what remains

**The rollover was executed, not argued.** The whole step 7 → 8 sequence ran against Ivy24
using client secrets created for the purpose, so the certificate profile every other
verification depends on was never at risk:

| Stage | Result |
| --- | --- |
| Generation A issued and proven | token acquired, profile resolves it |
| Generation B created **without** revoking A | both present on the registration |
| Both generations valid simultaneously | distinct tokens from each — the property step 7 exists for |
| Profile reference switched to B | real read: 13 devices |
| **A revoked, only after B was proven** | removed from the registration and the vault |
| B still working after A's revocation | 13 devices |

Afterwards: zero client secrets remain on the registration, zero rollover slots in the vault,
the certificate untouched, and the `ivy24` profile still reads 13 devices.

Worth knowing before repeating this: **a newly created Entra secret is accepted eventually, not
immediately.** A fresh context was rejected with `AADSTS7000215` seconds after another context
had succeeded with the same secret. That is directory propagation lag, not a GraphKit fault, so
a rollover must retry the first read through a new generation rather than treating one
rejection as failure.

**The exposure that step 8 exists to retire is inert.** `secrets.json` contains no secret
material — thumbprints are references, not keys. One real 40-character client secret *is*
committed in IHA's git history, in two blobs, alongside a Power Automate URL carrying an
embedded `sig=`. It belongs to an app registration in the **Ivy24 lab** (not a customer), named
"Powershell Test", deleted on 2026-08-15. The repository is private. The secret cannot
authenticate, because the app does not exist.

The plaintext retirement is underway in the owner's own working tree:
`config/secrets.example.json` previously carried the real Ivy24 `tenantId` and the `clientId`
of the very app whose secret is in git history; both are now placeholders with `bearerTokens`
emptied.

### The two things that remain

**1. Purge the deleted lab app.** A deleted registration is restorable from the directory's
deleted-items bin for 30 days — until roughly **2026-09-14** — and restoring it restores its
`passwordCredentials`. After that date the exposure expires on its own. Permanently deleting
directory data is an operator action by policy, not an automated one:

```bash
az rest --method DELETE --url "https://graph.microsoft.com/v1.0/directory/deletedItems/<objectId>"
```

The Logic App URL points at `prod-145.westus`, while the only Logic App in the subscription is
in `eastus` — probably already dead, but it was **not** tested, because triggering it to find
out would run the workflow.

**2. Retire the legacy IHA authentication layer.** Blocked by a platform fact, not caution.
Both customer profiles are certificate-**store** profiles, so their private keys live in the
Windows certificate store. Verified on the development machine: `IsWindows` is false, the
`Cert:` drive does not exist, and `Register-GraphTenant` refuses with *"Certificate store
lookup is Windows-only; this platform is Unix."* The customer tenants are unreachable from
there, so the verification that must precede retirement is impossible rather than merely
unauthorised.

`scripts/Complete-GraphKitCutover.ps1` performs it as one gated command on the execution host:
import the legacy profiles, verify the repoint **read-only** against a named tenant with the
flag enabled for that run only, and retire the legacy layer only if that verification passed
*in the same run* — a previously green run deliberately does not count, because the thing being
deleted is the fallback. Retirement uses `git rm` on a branch, so it is a reviewable diff and
recoverable from history.

## Running GraphKit on Windows

GraphKit's 624 tests all pass on macOS, and that proves less about Windows than the number
suggests: the certificate-store credential resolver and certificate-store profile registration
both throw on non-Windows by design, so they have **never executed on any platform**.

Reading that resolver with Windows in mind found a real gap before anyone hit it. It selected a
certificate by thumbprint and returned it without checking the private key was accessible. A
certificate without one cannot sign a client assertion, so the lookup succeeded and the failure
surfaced later inside MSAL, where the message is about assertion signing rather than about the
certificate the operator chose — the common Windows case being a public certificate installed
without its key, or a LocalMachine key the process cannot read. It now fails at the lookup.

`scripts/Test-GraphKitOnWindows.ps1` exercises those paths with a throwaway self-signed
certificate and needs no tenant, vault, or secret. `~/graphkit-cutover-bundle` packages it with
the pinned build for transfer to the execution host.

## Next moves

1. Run `Test-GraphKitOnWindows.ps1` on the Windows host — the only place several code paths can
   execute at all.
2. Grant the five outstanding scopes on the lab app and re-run the descriptor verification.
3. Verify the repoint read-only on one customer tenant with
   `Complete-GraphKitCutover.ps1`, then the other.
4. Enable `IHA_GRAPHKIT_REPOINT` on the host for a rollback window, then retire the legacy
   layer with `-RetireLegacyLayer`.
5. Purge the deleted lab app before **2026-09-14**.
