# Phase 5 Cutover — status as of 2026-08-15

Phase 5 is the eight-step cutover that repoints IntuneHealthAutomation onto GraphKit and
retires the legacy credential path. This records what is done, what is blocked, and — more
usefully — *why* the blocks are real rather than remaining effort.

| Step | State |
| --- | --- |
| 1. Inventory legacy callers | **Done** |
| 2. Import profiles into SecretManagement | **Done** — `Import-GraphLegacyProfile`, dry-run verified against the real file |
| 3. Private versioned package channel | **Done** — publish + pin, proven end to end |
| 4. Install pinned version on hosts, smoke it | **Done** — installed package read live tenant data |
| 5. Repoint callers with rollback | **Done** — GraphKit data plane behind a default-off flag, verified on Ivy24 |
| 6. Verify reads, then controlled writes | **Reads done**; a mutating write through the shim is not yet exercised |
| 7. Second credential without revoking the first | **Property proven; the rotation itself is unnecessary** (see below) |
| 8. Revoke old credential, retire plaintext | **Partly done by the owner; the rest must not happen yet** |

## What steps 1–4 established

**The seam is narrower than the call-site count suggests.** IHA has 45 direct
`Connect-MgGraph` / `Invoke-MgGraphRequest` references across 13 files, but the data plane
funnels through one wrapper, `Invoke-IntuneGraphRequest`, with 60 consumers. Repointing is
therefore two seams — a data plane and an auth plane — not 45 edits.

**The legacy file holds no secrets.** `secrets.json` carries tenant metadata and certificate
*thumbprints*; private keys live in the OS certificate store, and `bearerTokens` is null. The
importer refuses to relocate bearer tokens if it ever finds them, because moving a secret is
an operator decision.

**Two customer tenants** are configured: `contoso` and `fabrikam`, both
certificate-store based. Certificate-store profiles are Windows-only by design, so the import
must run on the IHA execution host; the dry run works anywhere and was verified on macOS.

**The channel is proven, not merely built.** `pack → test → publish → pin → register →
install → digest verify → clean-process import → live read` all ran for real. Two things that
would have shipped silently were caught by making them checkable:

- The `pack` task begins with `Clean`, so the natural `build,test,pack` ordering **rebuilds
  the module after the suite ran**. Publishing then ships bytes no test ever saw. The
  publisher now compares the `GraphKit.psm1` inside the package against the built module the
  tests imported, and refuses on mismatch. The correct order is **pack first, then test**.
- `Install-PSResource` resolves dependencies from the *same* repository it installs from, so a
  single-module private channel cannot satisfy its own graph. Dependencies come from PSGallery
  by minimum version instead — which is also the intent, since mirroring
  `Microsoft.Graph.Authentication` privately would be shipping the competing
  `Microsoft.Identity.Client.dll` the design forbids.

## Why step 5 is blocked, and what changed

Two independent blockers, both real.

**1. IntuneHealthAutomation is a beta-first consumer.** It declares its Graph surface in
`src/data/GraphEndpoints.json`, and almost every collection there is read from **beta**.
GraphKit's catalog was v1.0 only, so measured against the version IHA actually calls,
coverage was **zero** — including for paths that appeared to match. GraphKit treats API
version as per-operation descriptor metadata rather than a global mode, which is the correct
model and precisely why a v1.0 descriptor does not serve a beta caller.

Twenty-nine descriptors were added, and coverage is now:

```
Covered      : 27   descriptor exists at the version IHA calls
CoveredAtV1  :  0
VersionGap   :  0
Uncovered    :  0
```

**Catalog coverage is complete.** The version gap was closed by adding beta *siblings*
(`Operation = 'ListBeta'`, `Stability = 'DualVersion'`) rather than flipping the verified v1.0
descriptors, because `Type` + `Operation` is the catalog key and changing an existing
descriptor's `ApiVersion` would silently alter the response shape for every current caller.
Naming the operation is how the caller chooses a version, which keeps API version a
per-operation fact rather than a global mode. The siblings are not redundant: `MobileApp`
returns **80** items at beta against 75 at v1.0.

Run `./scripts/Get-GraphKitCutoverCoverage.ps1 -IhaPath <iha>` for the current list.

The missing `Singleton` handler strategy has since been added. It is not a cosmetic
distinction: `Collection.Default` unwraps a `value` array, so a singleton carrying its own
`value` **property** would be silently replaced by that property — the object swapped for one
of its fields, with no error. `Singleton.Default` issues one request, unwraps nothing, and
does not page even if the response carries a `nextLink`. Three singleton descriptors now use
it, closing `ManagedDeviceSettings`, `DeviceCleanupRules` and `MFA`.

`AppInstallErrors` was the last gap and is a **report action** (`POST
.../reports/getAppsInstallSummaryReport`) rather than a read. Covering it exposed a transport
defect worth more than the descriptor: Intune's report endpoints return a **JSON document
under `Content-Type: application/octet-stream`**, so the transport correctly classified it as
binary and callers received a byte dump where the descriptor promised Json. The descriptor is
the authority on operation behaviour, so it now wins — but only ever to upgrade bytes that
actually sniff as JSON, so a `Binary` descriptor like `DeviceReport.Export` is never touched
and a non-JSON payload is left intact rather than mangled.

**2. The callers pass computed URIs.** Most call sites hand `Invoke-IntuneGraphRequest` a
variable — `$assignmentUri`, `$currentUri`, a `@odata.nextLink` — not a literal. GraphKit
resolves a `Type` to a descriptor. Those are different models, so a direct repoint would be a
semantic rewrite of roughly sixty call sites.

**Resolved by translating instead of rewriting.** `Invoke-GraphKitGraphRequest` maps an
already-built URI back onto the descriptor that serves it, so the sixty call sites move
without being touched. It is gated behind `IHA_GRAPHKIT_REPOINT`, defaults **off**, and falls
through to the legacy path both when no descriptor covers the URI and when the GraphKit path
throws — so enabling it can never be worse than not enabling it, and rollback is one
environment variable rather than a code revert.

Verified against Ivy24: version-exact resolution (`beta/managedDevices` → `ManagedDevice/ListBeta`,
`v1.0/managedDevices` → `ManagedDevice/List`), path-parameter extraction from
`groups/{id}/members`, a real read of 13 devices through the repointed plane, `mobileApps`
returning **80 at beta against 75 at v1.0**, and an uncovered URI correctly falling through.

Rewriting the call sites to call `Get-GraphObject` directly is still the better end state.
This makes that migration incremental and reversible rather than one large irreversible change,
and it is what lets a customer tenant be moved one flag at a time.

## Live verification earned its keep

Twenty-four of twenty-nine new descriptors were verified against Ivy24. Three had **wrong
`RequiredPermissions`** that no static review would have caught, because the permission a
descriptor declares is a claim about the service and the service is the only authority on it:

| Descriptor | Declared | Actually required | How it surfaced |
| --- | --- | --- | --- |
| `NamedLocation` | `Policy.Read.ConditionalAccess` | `Policy.Read.All` | Token demonstrably carried the role; still 403 |
| `ConditionalAccessPolicy` | `Policy.Read.ConditionalAccess` | `Policy.Read.All` | Same, confirmed independently |
| `DeviceManagementScript` | `DeviceManagementConfiguration.Read.All` | `DeviceManagementScripts.Read.All` | Intune service named the scope in its 403 |

All three are corrected. Four descriptors are **correct-but-unverified** and say so in their
own header comments rather than being quietly counted as passing: `ConditionalAccessPolicy`
and `AuthenticationMethodsPolicy` need `Policy.Read.All`, `DeviceManagementScript` needs
`DeviceManagementScripts.Read.All`, and `DeviceCleanupRule` returned 403 with the scope it
declares — so its permission is a guess that may be wrong the same way the other three were.
Twenty-four of twenty-nine new descriptors are live-verified.

## Steps 7–8: the premise is largely moot

The spec's rotation sequence assumes exposed secrets needing rotation. Investigation found:

- `secrets.json` contains **no secret material** — thumbprints are references, not keys.
- One real 40-character client secret **is** committed in IntuneHealthAutomation's git
  history, in two blobs, together with a Power Automate URL carrying an embedded `sig=`.
- That credential belongs to an app registration in the **Ivy24 lab** (not a customer), named
  "Powershell Test", which was **deleted on 2026-08-15**. The exposed secret is therefore
  inert: it cannot authenticate, because the app does not exist.
- The repository is **private**, which bounds the exposure to its collaborators.

**One residual risk, and it has a deadline.** A deleted app registration is restorable from
the directory's deleted-items bin for 30 days — until roughly **2026-09-14** — and restoring
it restores its `passwordCredentials`. Purging it permanently makes the committed secret
unconditionally dead:

```bash
az rest --method DELETE --url "https://graph.microsoft.com/v1.0/directory/deletedItems/<objectId>"
```

That is irreversible, so it is left as the operator's call rather than done automatically. The
Logic App URL points at `prod-145.westus`, while the only Logic App in the subscription is in
`eastus` — probably already dead, but it was **not** tested, because triggering it to find out
would run the workflow.

**Step 7's property is already proven; its rotation is not needed.** The property step 7 exists
to establish is that two credential generations can be valid at once and every caller can tell
which it is using. That was demonstrated directly against Ivy24 earlier: a `Certificate` context
and a `ClientSecret` context for the same tenant each reported their own `AuthMode` and held
distinct tokens. What step 7 does *not* have is a reason to run — it exists to stage the
retirement of an exposed credential, and there is no live exposed credential to retire.
Performing a rotation on the lab certificate purely to tick the box would risk the profile every
other verification in this cutover depends on, for no security benefit.

**Step 8 is partly done and must not be finished yet.** The plaintext retirement is underway in
the owner's own working tree: `config/secrets.example.json` previously carried the real Ivy24
`tenantId` and the `clientId` of the very app whose secret is in git history, and both are now
placeholders with `bearerTokens` emptied.

Three things in step 8 are deliberately **not** done:

- **Revoking the old credential** — there is nothing exposed and live to revoke.
- **Deleting the old IHA authentication layer** — the repoint is default-off and has been
  verified on the lab tenant only. Deleting the legacy path now would remove the fallback that
  makes the repoint reversible, which is precisely the ordering the spec forbids breaking.
- **Purging the deleted lab app** — permanent deletion of directory data is the operator's
  action, not an automated one, and it has the 30-day deadline noted above.

## The recommended next moves

1. Decide `DualVersion` for the eight version-gap rows, or add beta siblings under distinct
   types.
2. Grant the four outstanding scopes on the lab app to close the last unverified descriptors.
3. Do the data-plane rewrite behind a flag that defaults to the legacy path, so both run
   side by side and rollback stays one switch.
4. Verify reads on Ivy24 first, then one customer tenant read-only, before any write.
5. Purge the deleted lab app before the 30-day window closes.
