# GraphKit Code Review — 2026-08-15

- **Scope:** all 7,907 lines of `source/`, after phases 1–4
- **Baseline:** 510 deterministic tests green
- **Result:** 14 defects found and fixed; 541 tests green
- **Commits:** `81cfe0a`, `7bad06a`, `795c427`, `6c682df`, `f92cf54`, `50f829e`

Every finding was reproduced before being fixed. **None of the 14 was caught by the existing
510-test suite**, which is the most useful signal in this review: the suite tested the paths the
code takes, not the paths it refuses to take.

## The dominant failure mode

Nine of the fourteen are one shape: **bounded or partial work reported as complete.**

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

**The throttle coordinator starts at the concurrency cap**, so the first burst runs at full
concurrency — the throttle wave AIMD exists to avoid. The spec argues for starting conservatively,
but this is a tuning decision rather than a demonstrated defect, and it moves a baseline several
existing tests rely on. Recorded in `GraphThrottleCoordinator.ps1`. **Open question for the
owner.**

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

## Residual risk

The tests still mostly exercise happy paths and injected transports. The spec already calls for
loopback tests through the **built sender** — asserting redirects, authority binding, that
`CredentialPolicy = None` never carries authorization, split-timeout boundaries, real cancellation,
and one-attempt-equals-one-send — and for **cross-context token isolation** tests. Neither exists
yet, and they are the tests most likely to catch the next defect of this kind.
