# GraphKit Code Review — 2026-08-15

- **Scope:** all 7,907 lines of `source/`, after phases 1–4
- **Baseline:** 510 deterministic tests green
- **Result:** 17 defects found and fixed; 559 tests green
- **Commits:** `81cfe0a`, `7bad06a`, `795c427`, `6c682df`, `f92cf54`, `50f829e`

Every finding was reproduced before being fixed. **None of the 17 was caught by the existing
510-test suite**, which is the most useful signal in this review: the suite tested the paths the
code takes, not the paths it refuses to take - and, in two cases, the paths it had never
implemented at all.

## The dominant failure mode

Nine of the seventeen are one shape: **bounded or partial work reported as complete.**

| Where | Reported | Actually |
| --- | --- | --- |
| Paging hit the page cap | `Succeeded` / `Known` | pages missing |
| Directory reads (`appRoleAssignments`, `oauth2PermissionGrants`) | complete grant list | first page only |
| Long-running job poll budget exhausted | `Succeeded` | job never finished |
| Batch inner `Retry-After` non-integer | 0s delay | server asked for a wait |
| `Retry-After: 0` or a past HTTP-date | 0s delay | backoff suppressed |
| Token expiring in milliseconds | valid | guaranteed 401 |
| Admission slots exhausted | exception | should have waited |
| `NeverReplay` GET, ambiguous commit | replayed | must not replay |
| Evidence `Notes` / `Counts` | allowlisted | unconstrained |

The module is unusually rigorous about this in its *documented* design — `Certainty`,
`Indeterminate`, "no silent caps" — which is exactly why the gaps matter: the contract promises a
distinction the implementation did not always draw.

## Findings

### Fixed — correctness

1. **`ReplayPolicy` overridden by the HTTP verb** (`Get-GraphRetryDecision`). `$safe = $isRead -or …`
   honoured `NeverReplay` on the rejected path and ignored it on the ambiguous path — the one where
   commit state is unknown. A one-shot export download is a GET that must not be replayed.
2. **Admission control threw instead of waiting** (`Wait-GraphThrottleGate`). It waited out the
   cooldown then called `AcquireAdmission` unconditionally, which throws when slots are busy —
   firing precisely when a qualified 429 had cut concurrency to the floor, and telling the caller
   to use the gate they had just used.
3. **No refresh skew on cached tokens** (`GraphTokenSource`). `ExpiresOnUtc -gt UtcNow` served a
   token expiring in milliseconds, spending the single permitted force-refresh on a predictable
   401. Now `min(5m, max(60s, 10% lifetime))`, which required recording `ReceivedOnUtc` since
   lifetime cannot be derived from the JWT. Spread is derived from the token fingerprint —
   deterministic per token, staggered across tokens.
4. **Directory reads returned the first page only** (`Invoke-GraphDirectoryRead`). The permission
   analyzer reported `MissingGrant` for permissions that *are* granted — under-reporting, the
   direction that invites re-granting or a false "broken registration" conclusion.
5. **Truncated paging reported as complete** (`Invoke-GraphPaging`). A `Write-Warning` is not part
   of the result contract and vanishes under `SilentlyContinue`.
6. **Exhausted job poll budget reported as completion** (`Invoke-GraphHandlerStrategy`). Returned
   an in-progress status object in place of a report. Now `DeadlineExpired` / `Indeterminate` —
   the job may still be running, so the honest answer is unknown, not failed.
7. **Batch `Retry-After` bypassed the hostile parser.** A bare `[int]::TryParse`, so an HTTP-date,
   the `30,120` form, or `x-ms-retry-after-ms` yielded zero delay — in the one place Graph's own
   guidance says to read the inner response.
8. **A zero delay suppressed backoff**, retrying instantly against an endpoint that had just
   refused.
9. **Per-call connect timeout silently ignored** after the first send; clients are now pooled by
   timeout.

### Fixed — hardening

10. **Evidence allowlist stopped at depth 1.** `Counts` and `Notes` were unconstrained and the
    credential regex read names, never values, so a bearer token in a note passed every check.
11. **`-Name` could escape `-Path`** on file export, while the raw-export path was already
    containment-checked.
12. **`PathTemplate` unvalidated** — a missing leading `/` yields a *different host*.
13. **`.AbsoluteUri` in two error paths** throws on the relative URI it just rejected, masking the
    real message.
14. **Dead `if`/`else`** with identical arms in the `Retry-After` parser.

### Deliberately not changed

**RESOLVED 2026-08-15.** The throttle coordinator previously started at the concurrency cap, so
the first burst against a cold scope ran at full concurrency - the throttle wave AIMD exists to
avoid, and a scope is coldest exactly when a run starts. It was left alone during the review
because it is a tuning decision rather than a demonstrated defect, and changing it moves a
baseline several tests rely on. The owner subsequently took the decision: it now starts at
`InitialConcurrency` (2) and ramps to the cap, with four baseline assertions updated.

**Negative service-principal caching.** `Get-GraphServicePrincipalObject` caches `$null` when the
SP does not exist, so an SP created later in the same session still reads as missing. Cleared by a
new session; noted rather than fixed.

## Test changes, and why

Two existing tests were modified. Editing a test to make it pass is normally a smell, so both are
recorded explicitly:

- **`ThrottleConcurrency`** asserted deny-on-contention. The semantics deliberately changed to
  wait-then-timeout; the property under test — only `MaxConcurrent` admitted concurrently — is
  unchanged, and it now proves it in 2s instead of 123s.
- **`Get-GraphRetryDelay`** asserted `Retry-After: -5` → `0`, i.e. retry immediately. Clamping
  exists to prevent a *negative* sleep, not to mandate an instant retry.

## What was verified, not assumed

Three suspicions were investigated and proved wrong, and are listed because a review that only
reports hits is not trustworthy: `RecordSuccess` double-counting the AIMD streak (never called
externally), the profile-store lock being advisory (`Register-GraphTenant` and
`Remove-GraphTenant` both take it), and `Cancelled`/`DeadlineExpired` being unimplemented
(produced in `Invoke-GraphRetry`).

## What is genuinely strong

The transport does what the spec promises: no redirects, no cookies, no chained handler,
`Authorization` per-message, `HttpClient.Timeout` infinite so it cannot preempt phase timeouts,
and it never throws for HTTP outcomes. `Resolve-GraphUri` escapes path tokens so an id of `../../x`
is inert. `Test-GraphPathContainment` uses lexical `GetFullPath` plus an ordinal
prefix-with-separator — the correct algorithm. The `Retry-After` parser gets the hard ordering
right: delta-seconds, then HTTP-date, and only then a comma split, never splitting first. Tenant
binding is cached by fingerprint + generation and never trusts a provider's claim. Batch is
read-only by default behind a `Safe`-descriptor gate. `Grant-GraphAppPermission` is diff-based and
idempotent under `ShouldProcess`. Permission `Configured` is genuinely tri-state.

## Found later, by running for real

Three further defects surfaced only when the module was run for real - two against a live
tenant, and one on a machine that had never run it before - all after the static review was
complete. Both are recorded here because they say something the review
itself could not: **a passing suite proved less than it appeared to.**

15. **Every auth method was a stub.** `New-GraphTokenSource` defaulted Certificate,
    ClientSecret, ManagedIdentity and BearerToken to scriptblocks that threw "MSAL
    confidential-client resolution is not wired ... pass -MsalFactory". GraphKit could not
    acquire a token by any means. All 557 tests passed because **every one injects a
    factory**, and `AGENTS.md` recorded phase 1 as complete. Fixed by
    `source/Private/TokenSources/New-GraphMsalApplication.ps1`.

16. **Every paged read failed.** `Invoke-GraphPaging` invoked its transport delegate without
    `-CancellationToken`, binding `$null` to a parameter typed
    `[System.Threading.CancellationToken]`, which cannot accept null. Injected test
    transports do not type that parameter strictly, so only a real paged read against a live
    tenant could expose it.

17. **The first `Register-GraphTenant` on a clean machine failed, and blamed the wrong thing.**
    `Enter-GraphProfileStoreLock` opens a `.lock` sidecar next to `profiles.json`, but nothing
    creates `~/.graphkit` first — `Save-GraphProfileStore` does, and it runs *after* the lock is
    taken. The resulting `DirectoryNotFoundException` was swallowed by the retry loop and
    reported as *"Another GraphKit process may be writing"*: ten retries, one second, and a
    confident diagnosis of a concurrent writer that did not exist. Every machine is in this
    state until the first profile is registered. The lock now creates its directory, retries
    only on `IOException` (genuine contention), and surfaces anything else immediately with its
    real cause.

The generalisable lesson, and the reason the loopback and live gates matter more than their
test count suggests: **the suite tested the seams it was built around.** Wherever a test
injects a dependency, the real implementation of that dependency is unverified by
construction - and in two cases here it did not exist at all.

Finding 17 adds a second axis to that lesson. It was not a seam problem — no dependency was
injected — it was a **state** problem: every developer machine, every CI runner with a warm
home directory, and every test using `TestDrive` had already passed through the one state
where the bug lives. It took a container that had never run GraphKit before to find it, which
is an argument for gates that **start from nothing**, not merely gates that use real
components.

## Residual risk

The tests still mostly exercise happy paths and injected transports. The spec already calls for
loopback tests through the **built sender** — asserting redirects, authority binding, that
`CredentialPolicy = None` never carries authorization, split-timeout boundaries, real cancellation,
and one-attempt-equals-one-send — and for **cross-context token isolation** tests. Neither exists
yet, and they are the tests most likely to catch the next defect of this kind.
