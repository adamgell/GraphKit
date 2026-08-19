# External security review (omp) — 2026-08-16

Independent review of GraphKit at commit `5cc3126`, scoped to the per-operation transport
timeout added that day and to the module's security invariants. Run against the repository, so
the reviewer read the code, ran the suite, and probed empirically rather than reasoning from a
diff.

**Verdict: no Critical or Important findings. Five Minor. Every stated invariant verified.**

## The timeout change: approved

No request-smuggling vector (timeouts touch only client-side `CancellationTokenSource` phases;
nothing descriptor-controlled reaches the wire format), no material DoS amplification, and the
validation was judged sufficient. Three independent bounds were confirmed present: the loader's
closed key set + positive-int + 600s ceiling, the retry engine's clamp to the remaining
deadline, and `[ValidateRange(1, 3600)]` on the sender parameters.

## Findings and disposition

| # | Finding | Status |
| --- | --- | --- |
| 1 | Admission slot leak on a throwing send → session-scoped throttle deadlock | **Fixed** |
| 2 | One attempt could overrun the deadline ~3× | **Fixed** |
| 3 | CSV formula injection in exports | **Fixed** |
| 4 | Redaction is format-inconsistent | **Fixed** |
| 5 | `Get-GraphOperation` returns live catalog objects by reference | **Fixed** |

**All five findings are closed as of 2026-08-16.** The three that were open pending a decision
were decided and implemented; what follows records the decisions and, for finding 4, why the
obvious fix was rejected.

### 1. Admission slot leak — fixed, and it was real

`Wait-GraphThrottleGate` takes a slot, and the only releases were the normal-completion path
and the mid-throttle deadline path. `TokenSource.Acquire` and the send sat between them
**unguarded**, so any throw kept the slot forever. That is not hypothetical: a wrong vault
secret name, a certificate without a private key, or an MSAL service exception all reach there.

The consequence is disproportionate to the cause. The coordinator starts at
`InitialConcurrency = 2`, so **two** failures on one scope exhaust it for the rest of the
session, and every later operation on that `tenant|client|class|family` then blocks and reports
*"back-pressure, not a transport error"* — blaming Graph for a slot the module never returned.
Same shape as the `.lock` sidecar incident: a confident diagnosis of the wrong problem.

Verified before fixing, and the verification is worth recording because the first two attempts
were wrong:

- Probe 1 measured slots by *acquiring* them, which consumes what it measures. Useless.
- Probe 2 read `GetInFlight($scope.Leaf)`. The real key is `$scope.LeafKey`, so it read a
  never-populated state and reported 0. It would have reported "no leak" forever.
- Probe 3 added a **control** — assert in-flight is ≥ 1 *during* a send. The control failed,
  which is what exposed probes 1 and 2 as blind. With the key corrected the control read 1, and
  the throwing send left **1 slot leaked**.

The lesson is the control, not the leak: a probe that cannot detect the thing it is looking for
returns the same answer as a healthy system.

Fixed with try/catch releasing and rethrowing. Regression test asserts in-flight returns to zero
after three throwing sends.

### 2. Deadline overrun — fixed

`$remainingSeconds` was computed once and applied to each phase, but the phases run
**sequentially**, so a descriptor declaring all three could hold one attempt for roughly
`phases × remaining` — about 900s under the default 300s deadline, with the deadline only
checked between attempts. The budget is now divided across the declared phases. This was a
defect in the timeout change itself, found by the reviewer within an hour of it being written.

### 3. CSV formula injection — FIXED

`Export-Csv` writes values verbatim, so a cell beginning `=`, `+`, `-`, or `@` executes when the
report is opened in Excel. Graph data is partly attacker-influenceable at the customer: users
can rename their own devices in many Intune configurations, and these reports are shared *with*
customers.

**Decided: neutralise.** Cells beginning `=`, `+`, `-`, `@` are prefixed with an apostrophe in
the Csv branch. Strings only — a numeric `-5` is not a formula risk and prefixing it would
corrupt every negative value in a report — and Csv only, since JSON and Markdown do not execute
formulas.

### 4. Redaction is format-inconsistent — FIXED, but not the way it looked

`-As Json` replaces properties named `token|secret|bearer|…` with `[REDACTED]`. The same result
exported `-As Csv`, `-As Markdown`, or `-As VaultEvidence` writes those rows **raw**.

This matters more after 2026-08-15 than before it, because descriptors added that day return
exactly this material: `DeviceManagementScript.List` returns `scriptContent`, and deployment
scripts routinely embed credentials; `ConfigurationPolicy` and `DeviceConfiguration` settings
carry Wi-Fi PSKs and VPN pre-shared keys.

**Decided: redact in every format, with `-NoRedact` to opt out.** But extending the EXISTING
redaction would have been worse than leaving the finding open, and measuring is what showed it.

That redaction matches property names against a pattern written for the envelope. Against real
lab-tenant responses it matches `passwordRequired`, `passwordMinimumLength` and seven more
DeviceCompliancePolicy **settings** — configuration, not credentials — while `scriptContent` and
the Settings Catalog value fields match nothing. Applying it verbatim would have redacted nine
innocuous compliance fields on every compliance export and still leaked the two secrets that
motivated this finding: an export carrying `[REDACTED]` markers, reading as sanitised, and
holding the secrets anyway.

So redaction is **declared, not guessed**. Descriptors name the properties their responses carry
secrets in (`SensitiveProperties`, dotted paths supported), the declaration travels on the
envelope's provenance because `Export-GraphResult` never sees a descriptor, and all four write
paths honour it — Csv, Markdown, Json including the envelope's own `Data`, and the VaultEvidence
`rows.json`. Raw rows carry no declaration and now warn rather than passing silently.

### 5. Mutable catalog by reference — FIXED

`Get-GraphOperation` returns the cached descriptor hashtables themselves, so a caller mutating
one mutates the session catalog. Bounded by the non-bypassable sender boundary and per-hop
credential-policy checks, and module state is per-runspace, so the realistic worst case is a
self-inflicted downgrade in the caller's own runspace.

**Fixed** with a deep copy at the public boundary; internal resolution keeps the cached
instance, since that path already owns the original and runs per request.

Confirmed before fixing — setting `CredentialPolicy = 'None'` on a returned descriptor made the
next lookup report `None`, meaning a later request would have run with no bearer token. The fix
then had a defect of its own that the isolation tests could not see: a recursive scriptblock
invoked with `&` unrolls a single-element array, so `RequiredPermissions` came back as a bare
hashtable and `.RequiredPermissions[0].Value` was `$null`. A copy has to be **faithful** as well
as isolated, and only an assertion on the descriptor's own values caught it.

## Invariants the reviewer verified

Cross-tenant isolation (per-context token sources, single-flight keyed by
environment|tenant|authority|scopes|client|mode|identity|generation, throttle state scoped per
tenant, tenant binding proved by a real `/organization` read rather than a provider claim);
authorization handling (bearer attached only after scheme+authority equality, `@odata.nextLink`
re-validated every page as attacker-influenced data, telemetry carries sanitized URIs only);
path/URI safety (`EscapeDataString` on path tokens, templates rooted and `..`-free at load);
secret hygiene (profiles hold vault references only, injected material refused for persistence,
legacy import refuses plaintext bearer tokens); and file-system containment before every write.

## What the reviewer assumed rather than verified

`Import-PowerShellDataFile` non-execution semantics, and that MSAL exceptions can escape
`Acquire` under STS throttling — the leak path exists for *any* throw, but MSAL specifically was
not live-reproduced.
