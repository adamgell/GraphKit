# GraphKit 0.3.0 Release-Truth Closeout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reconcile GraphKit's current repository narrative and release-identity QA with the verified immutable GraphKit 0.3.0 PSGallery release without changing the packaged manifest or rebuilding/publishing replacement 0.3.0 bytes.

**Architecture:** Current release truth lives in repository-only documentation and QA wording. The immutable `source/GraphKit.psd1` and retained/public `.nupkg` remain untouched; dated historical plans receive a superseding execution banner rather than rewritten history.

**Tech Stack:** PowerShell 7.4/7.6, Pester 6.1.0, Sampler 0.120.1, Markdown, GitHub Actions, PSGallery.

**Spec:** `docs/superpowers/specs/2026-08-19-graphkit-tenantpulse-product-program-design.md`

## Global Constraints

- Preserve the published GraphKit `0.3.0` archive at SHA-256 `45319d7cf4f8333697343ccf9c1089c7e04da87a8df62553cbc140089337536d`; never republish or describe a fresh ZIP as those bytes.
- Preserve `source/GraphKit.psd1` exactly in this train; publication evidence belongs in repository documentation because editing the released manifest under version `0.3.0` would create changed same-version source bytes.
- Use exact merged `main` SHA `a1b0b8d54c17671761ef5aee017a453b072d1fe9` and exact-main CI run `33292580847`; distinguish these from reviewed PR head `a0f0e92a054fe2976ca74a844f5de6161e1b8c67` and PR-head CI run `33292245900`.
- Record publication time `2026-08-30T04:38:20.12Z`, public archive size `207381` bytes, 772 passing tests, and six green Windows/macOS/Ubuntu PowerShell 7.4/7.6 jobs.
- Keep dated pre-publication evidence as history; add a dated superseding banner instead of rewriting what was true when a plan was authored.
- Run `./build.ps1 -Tasks pack` before `./build.ps1 -Tasks test`; do not invoke bare Pester for the authoritative full gate.
- Do not touch the user's primary checkout; work only in `.worktrees/program-completion` on `codex/program-completion`.

---

### Task 1: Reconcile and permanently gate GraphKit 0.3.0 release truth

**Files:**
- Create: `tests/QA/ReleaseTruth.tests.ps1`
- Modify: `tests/QA/PackageIdentity.tests.ps1`
- Modify: `README.md`
- Modify: `AGENTS.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/superpowers/plans/2026-08-29-graphkit-0.3.0-integration.md`
- Modify: `.github/workflows/ci.yml`
- Modify: `scripts/Publish-GraphKitPackage.ps1`
- Modify: `tests/QA/PublishChannel.tests.ps1`
- Test: `tests/QA/MinimumTestsRatchetSync.tests.ps1`

**Interfaces:**
- Consumes: repository files `README.md`, `AGENTS.md`, `CHANGELOG.md`, `source/GraphKit.psd1`, `docs/superpowers/plans/2026-08-29-graphkit-0.3.0-integration.md`, and the exact release constants in Global Constraints.
- Produces: truthful current source/operator/release narrative plus a QA contract that rejects stale unpublished-candidate claims while preserving the released module version and historical plan.

- [ ] **Step 1: Write the failing release-truth test**

Create `tests/QA/ReleaseTruth.tests.ps1` with five tests that load the five files above as raw
text. Extract the current GraphKit `0.3.0` release text from the README release-status paragraph,
the `AGENTS.md` current-release paragraph, and the `CHANGELOG.md` `0.3.0` release paragraph; do
not satisfy a current-release assertion from another document section. Each extracted scope must
contain the publication timestamp, 207381-byte archive identity, archive SHA-256, reviewed PR
head, merged-main SHA, PR-head CI run, exact-main CI run, 772-test result, and six-job
Windows/macOS/Ubuntu PowerShell 7.4/7.6 claim, and must not use `candidate` or `unpublished`.
Keep the Pester total at 777 by strengthening the existing tests rather than adding cases:

```powershell
Describe 'GraphKit current release truth' -Tag 'QA' {
    It 'records every verified field in the scoped README current-release text' {
        Assert-CurrentReleaseEvidence -Text $readmeCurrentRelease -Location 'README release status'
    }

    It 'records every verified field in the scoped operator current-release text' {
        Assert-CurrentReleaseEvidence -Text $agentsCurrentRelease -Location 'AGENTS current release status'
    }

    It 'records every verified field in the scoped changelog current-release text' {
        $changelogCurrentRelease | Should -Match '^## \[0\.3\.0\] - 2026-08-30'
        Assert-CurrentReleaseEvidence -Text $changelogCurrentRelease -Location 'CHANGELOG 0.3.0 release section'
    }

    It 'preserves the immutable released manifest identity' {
        $manifest = Import-PowerShellDataFile $manifestPath
        [string] $manifest.ModuleVersion | Should -Be '0.3.0'
        [string] $manifest.PrivateData.PSData.ReleaseNotes | Should -Match '^0\.3\.0(?:\r?\n)'
    }

    It 'marks the dated integration plan as executed and superseded by publication evidence' {
        $integrationPlan | Should -Match 'Status:\s*Completed and published'
        $integrationPlan | Should -Match '33292245900'
        $integrationPlan | Should -Match '33292580847'
    }
}
```

Use `BeforeAll` to resolve the repository root from `$PSScriptRoot`, load each text once, and set `$manifestPath`.

- [ ] **Step 2: Rename candidate-only QA descriptions**

In `tests/QA/PackageIdentity.tests.ps1`, rename only human-readable `Describe`/`It` labels and the extraction directory from `candidate` to `release`; do not change version assertions, manifest parsing, dependency checks, or package paths.

- [ ] **Step 3: Run the focused tests and verify the new truth gate fails**

Run:

```powershell
./build.ps1 -Tasks build
Import-Module ./output/RequiredModules/Pester/6.1.0/Pester.psd1 -Force
Invoke-Pester -Path @('./tests/QA/ReleaseTruth.tests.ps1','./tests/QA/PackageIdentity.tests.ps1') -Output Detailed
```

Expected: package-identity tests remain green; release-truth tests fail on the stale candidate/unpublished documentation and absent completion banner.

- [ ] **Step 4: Replace the README release-status block**

State exactly that GraphKit `0.3.0` is the current immutable PSGallery release, published 2026-08-30; include the public archive SHA-256, merged-main SHA, exact-main CI run, and 772-test/six-job result. Keep `0.2.2` as an immutable predecessor whose hard SecretManagement contract remains relevant only to hosts pinned to that version. Preserve the 0.3.0 lazy-vault explanation.

- [ ] **Step 5: Reconcile operator guidance**

Make the same release correction in `AGENTS.md:7` and change the `0.3.0 candidate` wording near the clean-machine dependency history to `0.3.0 release`. Retain the live-evidence distinctions and the one remaining `DeviceManagementScript.List` debt; do not call deterministic or CI evidence live proof.

- [ ] **Step 6: Close the changelog release paragraph**

Keep `## [0.3.0] - 2026-08-29` as the source-release section date, but replace the candidate/non-publication paragraph with a publication note containing the 2026-08-30 PSGallery timestamp, exact archive hash, merged-main SHA, both CI run IDs, and the 772-test result. Explain that the retained release-worktree archive is byte-identical to the public archive and that rebuilt ZIP container hashes are not a replacement identity.

- [ ] **Step 7: Add a superseding execution banner to the dated integration plan**

Immediately below the plan title, add:

```markdown
> **Status: Completed and published.** The candidate steps below were executed from reviewed
> head `a0f0e92a054fe2976ca74a844f5de6161e1b8c67`, merged as
> `a1b0b8d54c17671761ef5aee017a453b072d1fe9`, and passed PR-head CI run
> `33292245900` plus exact-main CI run `33292580847` (772 tests; all six matrix jobs).
> The already-tested archive was published to PSGallery on 2026-08-30 with SHA-256
> `45319d7cf4f8333697343ccf9c1089c7e04da87a8df62553cbc140089337536d`.
> The body is retained as the historical pre-publication execution plan.
```

Mark all eleven existing execution checkboxes complete because their outputs and gates are now proven. Do not rewrite command examples or historical candidate wording inside the retained body.

- [ ] **Step 8: Run focused QA green**

Run the same focused command from Task 1 Step 3.

Expected: every `ReleaseTruth` and `PackageIdentity` test passes.

- [ ] **Step 9: Prove the manifest was not changed**

Run:

```bash
git diff --exit-code origin/main -- source/GraphKit.psd1
git status --short
```

Expected: no manifest diff; only this plan and the planned documentation, CI, publisher, and QA files are modified.

- [ ] **Step 10: Pack and run the authoritative full gate**

Run:

```powershell
./build.ps1 -Tasks pack
./build.ps1 -Tasks test
```

Expected first run: the suite executes 777 tests with zero failures, errors, or skips, then the whole-result gate rejects the stale 772 floor synchronization only if the release-floor locations were changed inconsistently.

- [ ] **Step 11: Ratchet the current-development test floor to 777**

After confirming the exact 777 total, change every synchronized floor from 772 to 777:

```text
.github/workflows/ci.yml
scripts/Publish-GraphKitPackage.ps1 (gate call and operator hint)
tests/QA/PublishChannel.tests.ps1 (New-PassingResult default)
```

Also change the static failing-result fixture total in `PublishChannel.tests.ps1` to 777 for truthful fixture metadata. Update `AGENTS.md` so the published 0.3.0 evidence remains 772 tests while the post-release development tree requires 777. Run:

```powershell
./build.ps1 -Tasks pack
./build.ps1 -Tasks test
```

Expected: 777 tests, zero failures/errors/skips, whole-result gate green, and `MinimumTestsRatchetSync.tests.ps1` green.

- [ ] **Step 12: Commit the reviewed closeout**

```bash
git add README.md AGENTS.md CHANGELOG.md .github/workflows/ci.yml scripts/Publish-GraphKitPackage.ps1 docs/superpowers/plans/2026-08-29-graphkit-0.3.0-integration.md docs/superpowers/plans/2026-08-30-r11-release-truth-closeout.md tests/QA/ReleaseTruth.tests.ps1 tests/QA/PackageIdentity.tests.ps1 tests/QA/PublishChannel.tests.ps1
git commit -m "docs: reconcile GraphKit 0.3.0 release truth"
```

Do not push or merge as part of this task; those are cross-repository final-gate actions after review.
