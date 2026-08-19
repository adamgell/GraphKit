# R0 Source and Release Truth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish one auditable source, package, dependency, and CI truth for GraphKit and TenantPulse before any R1 feature work begins.

**Architecture:** R0 changes no GraphKit runtime behavior. It first fixes repository hygiene and proves that the unchanged GraphKit `0.2.2` module payload built from current source matches the immutable PSGallery payload, then pushes that exact source and requires its full CI matrix. TenantPulse then moves its runtime dependency from minimum-version semantics to exact `RequiredVersion = '0.2.2'`, bumps its changed package identity to an unpublished `0.1.2` candidate, proves source-to-package preservation, and pushes only after the GraphKit producer gate is green.

**Tech Stack:** PowerShell 7.4/7.6, Pester 6.1.0, Sampler 0.120.1, ModuleBuilder 3.1.8, PSResourceGet 1.2.0, Git, GitHub Actions, GitHub CLI.

---

## Scope, worktrees, and non-negotiable invariants

Use these existing isolated worktrees:

- GraphKit: `/Users/Adam.Gell/repo/GraphKit/.worktrees/r0-source-truth`, branch `product/r0-source-truth`
- TenantPulse: `/Users/Adam.Gell/repo/TenantPulse/.worktrees/r0-source-truth`, branch `product/r0-source-truth`

The 2026-08-19 pre-plan baseline is already established:

- GraphKit: `./build.ps1 -Tasks pack` then `./build.ps1 -Tasks test` passed; 748 tests, 0 failed, 0 errors, 0 skipped on macOS / PowerShell 7.6.5.
- TenantPulse: `./build.ps1 -Tasks pack` then `./build.ps1 -Tasks test` passed; 2009 tests, 0 failed, 0 errors, 0 skipped, 0 NotRun on macOS / PowerShell 7.6.5.

These invariants govern every task:

1. Never read, print, stage, diff, or copy either repository's `.env` file.
2. GraphKit `0.2.2` is immutable on PSGallery. Do not bump it and do not publish or republish it during R0.
3. Repository-only GraphKit changes must leave the built module payload byte-identical to gallery-installed `0.2.2` files.
4. Published TenantPulse `0.1.1` is immutable. Changing its manifest changes package bytes, so source becomes an unpublished `0.1.2` candidate; never build changed bytes under `0.1.1`.
5. `source/TenantPulse.psd1` uses exact runtime semantics: `RequiredVersion = '0.2.2'`.
6. `RequiredModules.psd1` remains the separate restore-time pin: `GraphKit = '0.2.2'`.
7. Pack first, test second. `pack` begins with `Clean`; `test` must prove the package-producing build.
8. No TenantPulse publication occurs in R0. The publisher runs with `-WhatIf` only.
9. Do not push TenantPulse until GraphKit source, gallery-payload parity, and exact-SHA CI are green.
10. No R1 work: no operation descriptors, settings assignments, outcome model, schema migration, ARM provider, or live-tenant mutation.

Official PowerShell manifest semantics are the basis for the dependency change: `ModuleVersion` is a minimum, while `RequiredVersion` is exact and cannot be combined with `ModuleVersion` or `MaximumVersion`. Reference: <https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_module_manifests?view=powershell-7.6#requiredmodules>.

## File responsibility map

### GraphKit

- Create `tests/QA/RepositoryHygiene.Tests.ps1`: executable `.env`, worktree, `docs/`, and exact build-dependency policy proof.
- Create `tests/QA/MinimumTestsRatchetSync.tests.ps1`: one standing gate that keeps CI, package verification, operator guidance, and the passing publish fixture on one minimum-test value.
- Modify `.gitignore`: ignore `.env`, retain generated/worktree ignores, and stop ignoring all of `docs/`.
- Modify `RequiredModules.psd1`: replace floating build-tool versions with the exact versions used by the verified baseline.
- Modify `.github/workflows/ci.yml`: pack before test and raise the whole-result floor to 753.
- Modify `scripts/Publish-GraphKitPackage.ps1`: use the same 753-test release floor and operator hint.
- Modify `tests/QA/PublishChannel.tests.ps1`: keep passing/failing NUnit fixtures aligned with the 753-test floor.
- Modify `AGENTS.md`: replace planned/scaffolded/local-only claims with current implementation, current pinned tooling, and evidence rules.
- Modify `README.md`: document the pack-then-test order.
- Do not modify `source/`, `source/GraphKit.psd1`, released changelog entries, historical reviews, or historical cutover records.

### TenantPulse

- Create `tests/QA/ModuleManifest.tests.ps1`: prove version identity and exact GraphKit dependency in source, built output, and `.nupkg`, while separately proving the restore pin.
- Modify `source/TenantPulse.psd1`: bump candidate version to `0.1.2` and replace minimum GraphKit semantics with exact `RequiredVersion` semantics.
- Modify `tests/QA/ReadOnly.tests.ps1`: import the real GraphKit catalog by exact module specification and correct current comments.
- Modify `tests/Unit/Get-PulseTenantSnapshot.Tests.ps1`: correct the current real-dependency comment to `0.2.2`; do not alter test behavior.
- Modify `.github/workflows/ci.yml`: pack before test and raise the whole-result floor to 2014.
- Modify `.build/AssertGateResult.tasks.ps1`: raise the local build floor to 2014 with measured-count accounting.
- Modify `scripts/Publish-TenantPulsePackage.ps1`: use the same 2014-test floor and operator hint.
- Modify `tests/QA/PublishTenantPulsePackage.tests.ps1`: align its fabricated passing result with 2014.
- Modify `CHANGELOG.md`: close the published `0.1.1` history and add the exact-dependency `0.1.2` candidate change under `Unreleased`.
- Modify `README.md`, `THIRD-PARTY-NOTICES.md`, and `docs/STATUS.md`: distinguish published `0.1.1`, current unpublished `0.1.2`, exact runtime dependency, and restore pin.
- Leave `RequiredModules.psd1` code unchanged at `GraphKit = '0.2.2'`.

---

### Task 1: Make GraphKit repository hygiene executable

**Files:**
- Create: `tests/QA/RepositoryHygiene.Tests.ps1`
- Modify: `.gitignore:1-15`
- Modify: `RequiredModules.psd1:15-20`
- Add after the ignore fix makes it visible: `docs/superpowers/plans/2026-08-19-r0-source-release-truth.md`
- [ ] **Step 1: Confirm the dependency toolchain without touching `.env`**

Run from the GraphKit R0 worktree:

```powershell
./build.ps1 -ResolveDependency -Tasks noop
```

Expected: `Build succeeded. 1 tasks, 0 errors, 0 warnings`.

- [ ] **Step 2: Write the failing repository-hygiene tests**

Create `tests/QA/RepositoryHygiene.Tests.ps1` with this complete content:

```powershell
BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath

    if (-not (Get-Command -Name git -ErrorAction SilentlyContinue)) {
        throw 'Repository hygiene tests require git because .gitignore behavior, not file text, is the contract.'
    }

    function Get-GitIgnoreExitCode {
        param([Parameter(Mandatory)] [string] $Path)

        & git -C $script:repoRoot check-ignore --quiet --no-index -- $Path
        return $LASTEXITCODE
    }
}

Describe 'Repository hygiene' -Tag 'QA' {
    It 'ignores local .env without reading it' {
        Get-GitIgnoreExitCode -Path '.env' | Should -Be 0
    }

    It 'ignores isolated worktrees' {
        Get-GitIgnoreExitCode -Path '.worktrees/r0-marker' | Should -Be 0
    }

    It 'does not ignore tracked-source docs' {
        Get-GitIgnoreExitCode -Path 'docs/r0-marker.md' | Should -Be 1
    }

    It 'pins every declared dependency to an exact version' {
        $dependencies = Import-PowerShellDataFile -Path (Join-Path $script:repoRoot 'RequiredModules.psd1')
        $unversioned = @(
            $dependencies.GetEnumerator() |
                Where-Object { [string] $_.Value -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$' } |
                ForEach-Object Key
        )

        $unversioned | Should -BeNullOrEmpty
    }
}
```

The tests pass path names only to Git. They never open `.env` and do not create the marker files.

- [ ] **Step 3: Run the focused tests and prove all three defects are real**

Run:

```powershell
pwsh -NoProfile -Command "Import-Module ./output/RequiredModules/Pester/6.1.0/Pester.psd1 -Force; Invoke-Pester -Path ./tests/QA/RepositoryHygiene.Tests.ps1 -Output Detailed"
```

Expected before the fix:

- `ignores local .env without reading it` fails because Git returns 1.
- `ignores isolated worktrees` passes because Git returns 0.
- `does not ignore tracked-source docs` fails because the blanket `docs/` rule returns 0.
- `pins every declared dependency to an exact version` fails and names the six values currently set to `latest`.

- [ ] **Step 4: Replace the contradictory ignore rules and floating build tools**

Replace `.gitignore` with exactly:

```gitignore
# Sampler build output - generated, never committed
output/

# Local Pester/coverage artifacts
*.coverage.xml
testResults/

# Local secrets - never read or commit
.env

# Isolated feature worktrees
.worktrees/

# docs/ is repository source of truth. Ignore a specific generated docs path only if one
# is introduced; never restore a blanket docs/ rule.
```

This removes the active `docs/` rule and adds the explicit `.env` rule. Do not inspect the existing `.env` file.

In `RequiredModules.psd1`, replace only the six floating build-tool declarations with:

```powershell
InvokeBuild                 = '5.14.23'
PSScriptAnalyzer            = '1.25.0'
Pester                      = '6.1.0'
ModuleBuilder               = '3.1.8'
ChangelogManagement         = '3.1.0'
Sampler                     = '0.120.1'
```

The five non-ModuleBuilder versions match the green baseline. `ModuleBuilder` remains at the repository-mandated `3.1.8`; do not upgrade it independently. Leave the two runtime dependencies unchanged.

- [ ] **Step 5: Run the focused tests and direct Git probes**

Run:

```powershell
pwsh -NoProfile -Command "Import-Module ./output/RequiredModules/Pester/6.1.0/Pester.psd1 -Force; Invoke-Pester -Path ./tests/QA/RepositoryHygiene.Tests.ps1 -Output Detailed"

git check-ignore --quiet --no-index -- .env
if ($LASTEXITCODE -ne 0) { throw '.env is not ignored.' }

git check-ignore --quiet --no-index -- .worktrees/r0-marker
if ($LASTEXITCODE -ne 0) { throw '.worktrees is not ignored.' }

git check-ignore --quiet --no-index -- docs/r0-marker.md
if ($LASTEXITCODE -ne 1) { throw 'docs is still ignored.' }
```

Expected: 4 Pester tests pass; the command block returns without throwing. Normal `git status --short` now shows the plan under `docs/`; do not use `git add -f`.

- [ ] **Step 6: Commit the hygiene and reproducibility contract**

```bash
git add .gitignore RequiredModules.psd1 tests/QA/RepositoryHygiene.Tests.ps1 docs/superpowers/plans/2026-08-19-r0-source-release-truth.md
git commit -m "test(qa): enforce GraphKit repository hygiene"
```

Expected: one commit containing the ignore policy, exact build-tool pins, four behavioral tests, and this implementation plan. No ignored-file override is used.

---

### Task 2: Make GraphKit package-first CI and test floors agree

**Files:**
- Create: `tests/QA/MinimumTestsRatchetSync.tests.ps1`
- Modify: `.github/workflows/ci.yml:74-96`
- Modify: `scripts/Publish-GraphKitPackage.ps1:111-114`
- Modify: `tests/QA/PublishChannel.tests.ps1:35-43,110-121`

- [ ] **Step 1: Add the standing ratchet-synchronization gate**

Create `tests/QA/MinimumTestsRatchetSync.tests.ps1` with this complete content:

```powershell
BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath

    function Get-SingleRatchetValue {
        param(
            [Parameter(Mandatory)] [string] $Text,
            [Parameter(Mandatory)] [string] $Pattern,
            [Parameter(Mandatory)] [string] $Location
        )

        $matches = @([regex]::Matches($Text, $Pattern))
        if ($matches.Count -eq 0) {
            throw "MinimumTests pattern matched nothing in $Location."
        }

        $values = @($matches | ForEach-Object { [int] $_.Groups[1].Value } | Select-Object -Unique)
        if ($values.Count -ne 1) {
            throw "MinimumTests pattern found distinct values in $Location: $($values -join ', ')."
        }

        return $values[0]
    }
}

Describe 'MinimumTests ratchet synchronization' -Tag 'QA' {
    It 'keeps CI, package verification, operator guidance, and the passing fixture equal' {
        $ci = Get-Content -LiteralPath (Join-Path $script:repoRoot '.github/workflows/ci.yml') -Raw
        $publisher = Get-Content -LiteralPath (Join-Path $script:repoRoot 'scripts/Publish-GraphKitPackage.ps1') -Raw
        $publishTests = Get-Content -LiteralPath (Join-Path $script:repoRoot 'tests/QA/PublishChannel.tests.ps1') -Raw

        $values = [ordered] @{
            CI = Get-SingleRatchetValue -Text $ci -Pattern '-MinimumTests\s+(\d+)\s+-AllowedSkips' -Location '.github/workflows/ci.yml'
            PublishCall = Get-SingleRatchetValue -Text $publisher -Pattern '-MinimumTests\s+(\d+)\s+-AllowedSkips' -Location 'scripts/Publish-GraphKitPackage.ps1 gate call'
            PublishHint = Get-SingleRatchetValue -Text $publisher -Pattern '-MinimumTests\s+(\d+)[\x27\x22]' -Location 'scripts/Publish-GraphKitPackage.ps1 error hint'
            PassingFixture = Get-SingleRatchetValue -Text $publishTests -Pattern '(?s)function New-PassingResult.*?\[int\]\s+\$Total\s*=\s*(\d+)' -Location 'tests/QA/PublishChannel.tests.ps1'
        }

        @($values.Values | Select-Object -Unique).Count | Should -Be 1 -Because (
            'every release gate must use one floor; found ' +
            (($values.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ')
        )
    }
}
```

- [ ] **Step 2: Run the new synchronization test against the existing 600 floor**

Run:

```powershell
pwsh -NoProfile -Command "Import-Module ./output/RequiredModules/Pester/6.1.0/Pester.psd1 -Force; Invoke-Pester -Path ./tests/QA/MinimumTestsRatchetSync.tests.ps1 -Output Detailed"
```

Expected: 1 test passes. This establishes that later edits cannot update only one release gate.

- [ ] **Step 3: Make CI build the package before testing it**

In `.github/workflows/ci.yml`, replace the current `Build` step with:

```yaml
      - name: Pack candidate
        shell: pwsh
        run: pwsh -File ./build.ps1 -Tasks pack
```

Keep the following `Test` step unchanged. The order must be resolve, pack, test, whole-result gate.

- [ ] **Step 4: Raise all GraphKit release floors to the measured post-change total**

The baseline 748 tests plus four repository-hygiene tests plus one ratchet-sync test equals 753. Make these exact edits in one commit:

```powershell
# scripts/Publish-GraphKitPackage.ps1
& pwsh -NoProfile -File $gate -ResultPath $TestResultPath -MinimumTests 753 -AllowedSkips 0 | Write-Verbose
```

The adjacent thrown operator command must also say `-MinimumTests 753`.

```yaml
# .github/workflows/ci.yml
pwsh -File ./tests/QA/Assert-GateResult.ps1 -ResultPath $resultFiles[0].FullName -MinimumTests 753 -AllowedSkips 0
```

```powershell
# tests/QA/PublishChannel.tests.ps1
function New-PassingResult {
    param([string] $Root, [string] $Version = '9.9.9', [int] $Total = 753)
```

Also change the deliberately failing NUnit fixture's `total="600"` to `total="753"`; it must fail because `failures="4"`, not because it is below the floor.

Do not change the generic `500` defaults in `tests/QA/Assert-GateResult.ps1` or `GateResult.tests.ps1`; those are unit-fixture defaults, not release policy. Do not change unrelated 600-second timeout tests.

- [ ] **Step 5: Run the focused release-gate tests**

Run:

```powershell
pwsh -NoProfile -Command "Import-Module ./output/RequiredModules/Pester/6.1.0/Pester.psd1 -Force; Invoke-Pester -Path @('./tests/QA/MinimumTestsRatchetSync.tests.ps1','./tests/QA/PublishChannel.tests.ps1','./tests/QA/GateResult.tests.ps1') -Output Detailed"
```

Expected: all focused tests pass; no package is published because the publish tests use throwaway file-system fixtures.

- [ ] **Step 6: Commit package-first CI and synchronized gates**

```bash
git add .github/workflows/ci.yml scripts/Publish-GraphKitPackage.ps1 tests/QA/PublishChannel.tests.ps1 tests/QA/MinimumTestsRatchetSync.tests.ps1
git commit -m "ci: verify packaged GraphKit before tests"
```

---

### Task 3: Reconcile GraphKit status and prove immutable 0.2.2 payload parity

**Files:**
- Modify: `AGENTS.md:3-9,28-36,48-58,79-112`
- Modify: `README.md:59-70`
- Verify only: `source/GraphKit.psd1`
- Verify only: `output/GraphKit.0.2.2.nupkg`

- [ ] **Step 1: Replace stale planned/scaffolded wording in `AGENTS.md`**

Make these content changes without altering the live-verification history:

1. Replace “GraphKit is planned as” with “GraphKit is”.
2. Replace the repository-status sentence with:

```markdown
**Current release status:** GraphKit `0.2.2` is the immutable stable package on PSGallery. Phases 1-5 are implemented; live verification remains recorded separately per auth mode, descriptor, and operation because implementation is not evidence of service behavior.
```

3. Replace the obsolete “CI has never run / no remote” paragraph with:

```markdown
**Remote CI contract.** `.github/workflows/ci.yml` runs PowerShell 7.4 and 7.6 across Windows, Ubuntu, and macOS. A source revision is CI-verified only when all six matrix jobs pass for that exact SHA; workflow existence or an older successful run is not evidence. Locally, 753 deterministic tests must pass under `./build.ps1 -Tasks test`, with zero failures, errors, or skips, and `tests/QA/Assert-GateResult.ps1` enforces the same minimum-count floor used by CI and package verification.
```

4. Change the `## Architecture & Data Flow` introduction from `Planned flow:` to `Runtime flow:`.
5. Replace the `Current` / `Scaffolded` / `Planned for later increments` directory subsections with one current list:

```markdown
- `docs/superpowers/specs/` — approved design decisions and product contracts.
- `source/Public/` — exported PowerShell commands, one command per file.
- `source/Private/` — transport, auth, retry, URI, throttle, paging, batching, and evidence helpers.
- `source/Data/Operations/` — versioned `.psd1` operation descriptors.
- `source/Formats/` — PowerShell formatting definitions.
- `tests/Unit/` — deterministic policy and pipeline tests.
- `tests/Adapter/` — real-HTTP loopback adapter tests.
- `tests/Concurrency/` — real-runspace isolation and throttle tests.
- `tests/QA/` — repository, package, import, and whole-result gates.
- `scripts/` — standalone operational, cutover, and publication scripts.
- `output/` — generated build/package output; never edit it directly.
```

6. Replace the development command block with:

```powershell
./build.ps1 -ResolveDependency -Tasks noop   # restore exact build/runtime dependencies
./build.ps1 -Tasks pack                      # Clean + build + package candidate
./build.ps1 -Tasks test                      # test the package-producing build
```

Retain the existing warning not to use a bare full-suite `Invoke-Pester ./tests` call.

- [ ] **Step 2: Correct the public development order in `README.md`**

Replace the development command block and the sentence below it with:

```powershell
./build.ps1 -ResolveDependency -Tasks noop
./build.ps1 -Tasks pack
./build.ps1 -Tasks test
```

```markdown
The `pack` task begins with `Clean`, so package before testing. The `test` task then proves the exact package-producing build and writes the NUnit result consumed by the release gate. Generated artifacts are written under `output/` and must not be edited directly.
```

- [ ] **Step 3: Confirm no GraphKit module source or version changed**

Run:

```powershell
$manifest = Import-PowerShellDataFile ./source/GraphKit.psd1
if ([string] $manifest.ModuleVersion -ne '0.2.2') { throw 'R0 must keep GraphKit at 0.2.2.' }

git diff --name-only HEAD~2..HEAD -- source
if ($LASTEXITCODE -ne 0) { throw 'Unable to inspect source change names.' }
```

Expected: module version `0.2.2`; the source-name command prints nothing.

- [ ] **Step 4: Pack first, test second, and gate the exact local candidate**

Run:

```powershell
./build.ps1 -ResolveDependency -Tasks noop
./build.ps1 -Tasks pack
./build.ps1 -Tasks test

$resultFiles = @(Get-ChildItem ./output/testResults/NUnitXml_GraphKit_v0.2.2.*.xml)
if ($resultFiles.Count -ne 1) { throw "Expected one GraphKit result, found $($resultFiles.Count)." }
pwsh -NoProfile -File ./tests/QA/Assert-GateResult.ps1 -ResultPath $resultFiles[0].FullName -MinimumTests 753 -AllowedSkips 0
if ($LASTEXITCODE -ne 0) { throw 'GraphKit whole-result gate failed.' }
```

Expected: `Tests Passed: 753, Failed: 0, Skipped: 0`; gate prints `total >= 753`.

- [ ] **Step 5: Exercise package-to-tested-build proof without external publication**

Run:

```powershell
$proofRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('graphkit-r0-proof-' + [guid]::NewGuid())
try {
    $channel = Join-Path $proofRoot 'channel'
    $pin = Join-Path $proofRoot 'graphkit.pin.json'
    ./scripts/Publish-GraphKitPackage.ps1 `
        -PackagePath ./output/GraphKit.0.2.2.nupkg `
        -Channel FileSystem `
        -Destination $channel `
        -TestResultPath $resultFiles[0].FullName `
        -PinPath $pin

    $record = Get-Content -LiteralPath $pin -Raw | ConvertFrom-Json
    if ($record.version -ne '0.2.2') { throw 'Pin did not record GraphKit 0.2.2.' }
    if ($record.sha256 -ne (Get-FileHash ./output/GraphKit.0.2.2.nupkg -Algorithm SHA256).Hash) {
        throw 'Pin hash does not identify the candidate package.'
    }
}
finally {
    if (Test-Path -LiteralPath $proofRoot) { Remove-Item -LiteralPath $proofRoot -Recurse -Force }
}
```

Expected: temporary file-system publication succeeds, pin version/hash match, and no GitHub or gallery API is called.

- [ ] **Step 6: Compare every locally built module file with gallery-installed 0.2.2**

Run:

```powershell
Import-Module Microsoft.PowerShell.PSResourceGet -RequiredVersion 1.2.0 -Force
$galleryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('graphkit-gallery-r0-' + [guid]::NewGuid())
try {
    Save-PSResource -Name GraphKit -Version 0.2.2 -Repository PSGallery -Path $galleryRoot -TrustRepository

    $localRoot = (Resolve-Path ./output/module/GraphKit/0.2.2).ProviderPath
    $savedRoot = (Resolve-Path (Join-Path $galleryRoot 'GraphKit/0.2.2')).ProviderPath

    $localFiles = @(
        Get-ChildItem -LiteralPath $localRoot -Recurse -File |
            ForEach-Object { [System.IO.Path]::GetRelativePath($localRoot, $_.FullName) } |
            Sort-Object
    )
    if ($localFiles.Count -eq 0) { throw 'The local GraphKit payload is empty.' }

    $savedFiles = @(
        Get-ChildItem -LiteralPath $savedRoot -Recurse -File |
            ForEach-Object { [System.IO.Path]::GetRelativePath($savedRoot, $_.FullName) } |
            Sort-Object
    )

    $fileSetDifferences = @(Compare-Object -ReferenceObject $localFiles -DifferenceObject $savedFiles)
    if ($fileSetDifferences.Count -ne 0) {
        throw "GraphKit payload file sets differ:$([Environment]::NewLine)$($fileSetDifferences | Out-String)"
    }

    $hashMismatches = @(
        foreach ($relative in $localFiles) {
            $localHash = (Get-FileHash -LiteralPath (Join-Path $localRoot $relative) -Algorithm SHA256).Hash
            $savedHash = (Get-FileHash -LiteralPath (Join-Path $savedRoot $relative) -Algorithm SHA256).Hash
            if ($localHash -ne $savedHash) { $relative }
        }
    )
    if ($hashMismatches.Count -ne 0) {
        throw "GraphKit payload hash mismatches:$([Environment]::NewLine)$($hashMismatches -join [Environment]::NewLine)"
    }
}
finally {
    if (Test-Path -LiteralPath $galleryRoot) { Remove-Item -LiteralPath $galleryRoot -Recurse -Force }
}
```

Expected: the local payload is nonempty, the local and PSGallery relative-file sets are identical in both directions, and every common relative path has the same SHA-256 hash. If any mismatch occurs, stop R0. Never overwrite PSGallery `0.2.2`; a new GraphKit version and explicit publication decision would be required.

- [ ] **Step 7: Commit GraphKit status truth**

```bash
git add AGENTS.md README.md
git commit -m "docs: reconcile GraphKit source and release truth"
```

- [ ] **Step 8: Re-run the final GraphKit local proof after the documentation commit**

Run the Step 4 commands again.

Expected: 753 tests pass and the whole-result gate passes. Documentation is not shipped in the module payload, so Step 6 parity remains valid.

- [ ] **Step 9: Fast-forward GraphKit main, push once, and require exact-SHA CI**

Run from the GraphKit R0 worktree first:

```bash
git status --short
git fetch origin
git merge-base --is-ancestor origin/main HEAD
git rev-parse HEAD
```

Expected: clean status; the ancestry command exits 0. Record the printed SHA in the execution report.

Then run from `/Users/Adam.Gell/repo/GraphKit`:

```bash
git merge --ff-only product/r0-source-truth
git push origin main
```

Then verify the exact pushed SHA from PowerShell:

```powershell
$sha = (git rev-parse HEAD).Trim()
$runs = @(gh run list --workflow CI --commit $sha --limit 1 --json databaseId,headSha,status,conclusion,url | ConvertFrom-Json)
if ($runs.Count -ne 1 -or $runs[0].headSha -ne $sha) { throw 'No CI run found for the exact GraphKit SHA.' }
gh run watch $runs[0].databaseId --exit-status
if ($LASTEXITCODE -ne 0) { throw 'GraphKit CI failed.' }
$detail = gh run view $runs[0].databaseId --json headSha,conclusion,jobs,url | ConvertFrom-Json
if ($detail.headSha -ne $sha -or $detail.conclusion -ne 'success') { throw 'GraphKit CI did not succeed for the exact SHA.' }
if (@($detail.jobs).Count -ne 6 -or @($detail.jobs | Where-Object conclusion -ne 'success').Count -ne 0) {
    throw 'GraphKit did not pass all six OS/PowerShell matrix jobs.'
}
$detail | Select-Object headSha, conclusion, url
```

Expected: the exact SHA succeeds in all six jobs. Do not begin Task 4 until this passes.

---

### Task 4: Make TenantPulse package identity and exact GraphKit dependency testable

**Files:**
- Create: `tests/QA/ModuleManifest.tests.ps1`
- Modify: `source/TenantPulse.psd1:14-15,53-60`
- Modify: `tests/QA/ReadOnly.tests.ps1:18-24,85-93,184-190`
- Modify: `tests/Unit/Get-PulseTenantSnapshot.Tests.ps1:14-18`

- [ ] **Step 1: Confirm GraphKit producer handoff before touching TenantPulse**

From `/Users/Adam.Gell/repo/GraphKit/.worktrees/r0-source-truth`, assert that the worktree still identifies the exact GraphKit `main` revision pushed in Task 3 Step 9:

```powershell
Set-Location /Users/Adam.Gell/repo/GraphKit/.worktrees/r0-source-truth
git fetch origin
if ($LASTEXITCODE -ne 0) { throw 'Could not refresh GraphKit origin/main.' }

$worktreeSha = (git rev-parse HEAD).Trim()
$pushedMainSha = (git rev-parse origin/main).Trim()
if ($worktreeSha -ne $pushedMainSha) {
    throw "GraphKit R0 worktree HEAD $worktreeSha does not equal pushed main $pushedMainSha."
}
```

With `$sha = $worktreeSha`, rerun the exact-SHA `gh run view` assertions from Task 3 Step 9. Then, without leaving `/Users/Adam.Gell/repo/GraphKit/.worktrees/r0-source-truth`, rerun the gallery payload comparison from Task 3 Step 6 against the build under that worktree's ignored `output/` directory. Do not depend on `output/` existing in `/Users/Adam.Gell/repo/GraphKit`.

Expected: the R0 worktree HEAD equals the pushed GraphKit `main` SHA, exact-SHA CI is green, and the worktree's source-built GraphKit files match PSGallery `0.2.2`. If not, stop; the consumer cannot move ahead of the producer.

- [ ] **Step 2: Write the failing TenantPulse package-identity tests**

Create `tests/QA/ModuleManifest.tests.ps1` with this complete content:

```powershell
BeforeAll {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:sourceManifestPath = Join-Path $script:repoRoot 'source/TenantPulse.psd1'
    $script:sourceManifest = Import-PowerShellDataFile -Path $script:sourceManifestPath
    $script:candidateVersion = [string] $script:sourceManifest.ModuleVersion
    $script:builtManifestPath = Join-Path $script:repoRoot "output/module/TenantPulse/$script:candidateVersion/TenantPulse.psd1"
    $script:packagePath = Join-Path $script:repoRoot "output/TenantPulse.$script:candidateVersion.nupkg"

    function Assert-ExactGraphKitRequirement {
        param([Parameter(Mandatory)] [hashtable] $Manifest)

        $requirements = @($Manifest.RequiredModules | Where-Object { $_.ModuleName -eq 'GraphKit' })
        $requirements.Count | Should -Be 1
        [string] $requirements[0].RequiredVersion | Should -Be '0.2.2'
        $requirements[0].ContainsKey('ModuleVersion') | Should -BeFalse
        $requirements[0].ContainsKey('MaximumVersion') | Should -BeFalse
    }
}

Describe 'TenantPulse package identity and GraphKit dependency' -Tag 'QA' {
    It 'uses a new 0.1.2 identity for changed package bytes' {
        $script:candidateVersion | Should -Be '0.1.2'
    }

    It 'requires exact GraphKit 0.2.2 in the source manifest' {
        Assert-ExactGraphKitRequirement -Manifest $script:sourceManifest
    }

    It 'keeps the independent restore-time GraphKit pin at 0.2.2' {
        $restoreDependencies = Import-PowerShellDataFile -Path (Join-Path $script:repoRoot 'RequiredModules.psd1')
        [string] $restoreDependencies.GraphKit | Should -Be '0.2.2'
    }

    It 'preserves exact GraphKit 0.2.2 in the built manifest' {
        Test-Path -LiteralPath $script:builtManifestPath -PathType Leaf | Should -BeTrue
        $builtManifest = Import-PowerShellDataFile -Path $script:builtManifestPath
        Assert-ExactGraphKitRequirement -Manifest $builtManifest
    }

    It 'preserves exact GraphKit 0.2.2 in the candidate nupkg manifest' {
        Test-Path -LiteralPath $script:packagePath -PathType Leaf | Should -BeTrue
        $extractRoot = Join-Path $TestDrive 'package'
        if (Test-Path -LiteralPath $extractRoot) {
            Remove-Item -LiteralPath $extractRoot -Recurse -Force
        }
        [System.IO.Compression.ZipFile]::ExtractToDirectory($script:packagePath, $extractRoot)
        $packagedManifest = Import-PowerShellDataFile -Path (Join-Path $extractRoot 'TenantPulse.psd1')
        Assert-ExactGraphKitRequirement -Manifest $packagedManifest
    }
}
```

- [ ] **Step 3: Run the focused tests and prove the old artifact is wrong**

Run from the TenantPulse R0 worktree:

```powershell
pwsh -NoProfile -Command "Import-Module ./output/RequiredModules/Pester/6.1.0/Pester.psd1 -Force; Invoke-Pester -Path ./tests/QA/ModuleManifest.tests.ps1 -Output Detailed"
```

Expected before the source change:

- `uses a new 0.1.2 identity` fails because source is `0.1.1`.
- source, built, and package exact-dependency tests fail because they contain `ModuleVersion = '0.2.2'` and no `RequiredVersion`.
- the separate restore-time pin test passes.

- [ ] **Step 4: Change TenantPulse to a new exact-dependency candidate**

In `source/TenantPulse.psd1`, make these exact changes:

```powershell
ModuleVersion = '0.1.2'
```

```powershell
RequiredModules = @(
    # TenantPulse reads the tenant exclusively through GraphKit's read-class descriptors.
    # RequiredVersion is deliberate: a newer GraphKit catalog is a different producer
    # contract and must be re-verified before TenantPulse consumes it.
    @{ ModuleName = 'GraphKit'; RequiredVersion = '0.2.2' }
)
```

Do not change `RequiredModules.psd1`; its `GraphKit = '0.2.2'` value is the independent restore-time pin.

- [ ] **Step 5: Make the real-catalog QA import exact GraphKit**

In `tests/QA/ReadOnly.tests.ps1`, change current, nonhistorical references from GraphKit `0.1.0` to exact GraphKit `0.2.2`, then replace the real import with:

```powershell
Import-Module -FullyQualifiedName @{
    ModuleName = 'GraphKit'
    RequiredVersion = '0.2.2'
} -Force -ErrorAction Stop
```

In the Pending-dataset assertion text, replace the stale `0.1.1-release TODO` wording with `released-catalog follow-up`. Preserve dated historical comments that explain which descriptors originally shipped in `0.1.1`.

In `tests/Unit/Get-PulseTenantSnapshot.Tests.ps1`, change only the current introductory comment from “GraphKit 0.1.0” to “GraphKit 0.2.2”; keep all mocks and behavior unchanged.

- [ ] **Step 6: Pack the new candidate and turn the focused test green**

Run:

```powershell
./build.ps1 -ResolveDependency -Tasks noop
./build.ps1 -Tasks pack
pwsh -NoProfile -Command "Import-Module ./output/RequiredModules/Pester/6.1.0/Pester.psd1 -Force; Invoke-Pester -Path @('./tests/QA/ModuleManifest.tests.ps1','./tests/QA/ReadOnly.tests.ps1') -Output Detailed"
```

Expected: `output/TenantPulse.0.1.2.nupkg` exists; all five manifest tests and every real-catalog read-only test pass against GraphKit `0.2.2`.

- [ ] **Step 7: Commit the exact dependency and package identity**

```bash
git add source/TenantPulse.psd1 tests/QA/ModuleManifest.tests.ps1 tests/QA/ReadOnly.tests.ps1 tests/Unit/Get-PulseTenantSnapshot.Tests.ps1
git commit -m "fix(manifest): require exact GraphKit 0.2.2"
```

---

### Task 5: Align TenantPulse package-first CI, release floors, and documentation

**Files:**
- Modify: `.github/workflows/ci.yml:76-98,718-720`
- Modify: `.build/AssertGateResult.tasks.ps1:495-500`
- Modify: `scripts/Publish-TenantPulsePackage.ps1:166-180`
- Modify: `tests/QA/PublishTenantPulsePackage.tests.ps1:92-99`
- Modify: `CHANGELOG.md:6-10`
- Modify: `README.md:155-176,353-383`
- Modify: `THIRD-PARTY-NOTICES.md:140-145`
- Modify: `docs/STATUS.md:105-124`

- [ ] **Step 1: Make TenantPulse CI package before testing**

In `.github/workflows/ci.yml`, replace the current `Build` step with:

```yaml
      - name: Pack candidate
        shell: pwsh
        run: pwsh -File ./build.ps1 -Tasks pack
```

Keep the following `Test` and whole-result gate steps. The workflow order becomes resolve, pack, test, gate.

- [ ] **Step 2: Raise all TenantPulse release floors to 2014 in one change**

The measured baseline 2009 plus five `ModuleManifest.tests.ps1` tests equals 2014. Update all locations guarded by `tests/QA/MinimumTestsRatchetSync.tests.ps1`:

```powershell
# .build/AssertGateResult.tasks.ps1
$script:tenantPulseGateMinimumTests = 2014
```

Add this accounting line immediately above it:

```powershell
# 2009 -> 2014 (R0 source/release truth): +5 package-identity and exact GraphKit
# dependency assertions across source, restore pin, built manifest, and nupkg.
```

```yaml
# .github/workflows/ci.yml
pwsh -File ./tests/QA/Assert-GateResult.ps1 -ResultPath $resultFiles[0].FullName -MinimumTests 2014 -AllowedSkips $allowedSkips -AllowNotRun 1
```

```powershell
# scripts/Publish-TenantPulsePackage.ps1
& pwsh -NoProfile -File $gate -ResultPath $TestResultPath -MinimumTests 2014 -AllowedSkips 0 -AllowNotRun 1 | Write-Verbose
```

The adjacent operator error hint and current accounting comments must also say `2014` and `2009 -> 2014`.

```xml
<!-- tests/QA/PublishTenantPulsePackage.tests.ps1 fabricated passing result -->
<test-results name="TenantPulse $Version" total="2014" failures="0" errors="0" skipped="0">
```

Update that test file's adjacent tracking comment from `2009` to `2014`.

- [ ] **Step 3: Close published 0.1.1 history and describe the 0.1.2 candidate**

At the top of `CHANGELOG.md`, use this structure:

```markdown
## [Unreleased]

### Changed

- **Exact GraphKit runtime contract (TenantPulse 0.1.2 candidate).** The module manifest now requires exactly GraphKit `0.2.2`; `RequiredModules.psd1` remains the separate restore-time `0.2.2` pin. Source, built manifest, and candidate package are checked independently. Published TenantPulse `0.1.1` remains immutable and is not republished.

## [0.1.1] - 2026-08-19

### Added
```

Keep all existing `Added` and `Changed` content below the new `0.1.1` heading. Do not rewrite dated GraphKit `0.1.1` migration history.

- [ ] **Step 4: Correct current dependency and build claims in `README.md`**

Make these exact current-state changes:

1. Change the GraphKit prerequisite to:

```markdown
- [GraphKit](https://github.com/AdamGell/GraphKit) exactly `0.2.2`, installed from PSGallery. TenantPulse `0.1.2` declares this with `RequiredVersion`, so a newer unverified GraphKit does not satisfy the runtime contract.
```

2. Replace the release paragraph with:

```markdown
GraphKit `0.2.2` and TenantPulse `0.1.1` are published on PSGallery. Published TenantPulse `0.1.1` used minimum-version dependency semantics; current source is the unpublished `0.1.2` candidate, which requires exact GraphKit `0.2.2`. The twelve GET/List datasets that were Pending on GraphKit `0.1.1` remain live. See `docs/STATUS.md` for live-gate evidence and current candidate status.
```

3. Replace the development commands with:

```powershell
./build.ps1 -ResolveDependency -Tasks noop
./build.ps1 -Tasks pack
./build.ps1 -Tasks test
```

4. Replace the next sentence with:

```markdown
The `pack` task begins with `Clean`, so package before testing. The `test` task proves that package-producing build, enforces the whole-result gate, and records the per-shipped-file SHA-256 manifest that `scripts/Publish-TenantPulsePackage.ps1` compares with the `.nupkg`.
```

5. Replace the dependency explanation with:

```markdown
`source/TenantPulse.psd1` declares GraphKit `0.2.2` with `RequiredVersion`, the exact runtime contract. `RequiredModules.psd1` separately pins `GraphKit = '0.2.2'` for build-time restore through PSGallery. These two files intentionally use different schemas but must resolve the same version.
```

- [ ] **Step 5: Correct notices and internal status**

In `THIRD-PARTY-NOTICES.md`, replace the GraphKit note with:

```markdown
The sole Graph-access layer TenantPulse calls through. `source/TenantPulse.psd1` requires exact GraphKit `0.2.2`; `RequiredModules.psd1` separately pins `0.2.2` for build restore. GraphKit is not vendored and resolves from PSGallery.
```

In `docs/STATUS.md`, keep the existing `GraphKit 0.2.2 consume (TenantPulse 0.1.1)` history, then add this paragraph after its current closing paragraph:

```markdown
**R0 package-identity correction (2026-08-19):** published TenantPulse `0.1.1` remains the historical consumer artifact and is not overwritten. Current source is the unpublished `0.1.2` candidate because changing `RequiredModules` changes shipped bytes. Its runtime manifest requires exact GraphKit `0.2.2`; the build dependency file retains its separate `0.2.2` restore pin. Source, built manifest, `.nupkg`, full suite, and dry-run digest verification must all agree before this candidate can be called releasable.
```

Do not alter historical live-gate tables, redacted evidence, or old GraphKit `0.1.1` spike records.

- [ ] **Step 6: Run focused gates for every changed contract**

Run:

```powershell
pwsh -NoProfile -Command "Import-Module ./output/RequiredModules/Pester/6.1.0/Pester.psd1 -Force; Invoke-Pester -Path @('./tests/QA/ModuleManifest.tests.ps1','./tests/QA/MinimumTestsRatchetSync.tests.ps1','./tests/QA/PublishTenantPulsePackage.tests.ps1','./tests/QA/ReadOnly.tests.ps1') -Output Detailed"
```

Expected: all focused tests pass. The publisher tests remain dry-run fixtures and perform no external publication.

- [ ] **Step 7: Commit TenantPulse CI, ratchet, and source truth**

```bash
git add .github/workflows/ci.yml .build/AssertGateResult.tasks.ps1 scripts/Publish-TenantPulsePackage.ps1 tests/QA/PublishTenantPulsePackage.tests.ps1 CHANGELOG.md README.md THIRD-PARTY-NOTICES.md docs/STATUS.md
git commit -m "ci: verify the TenantPulse 0.1.2 candidate"
```

---

### Task 6: Prove and push the TenantPulse consumer handoff

**Files:**
- Verify only: `output/TenantPulse.0.1.2.nupkg`
- Verify only: `output/module/TenantPulse/0.1.2/TenantPulse.psd1`
- Verify only: `output/RequiredModules/GraphKit/0.2.2/GraphKit.psd1`

- [ ] **Step 1: Resolve, pack, test, and gate in the only valid order**

Run from the TenantPulse R0 worktree:

```powershell
./build.ps1 -ResolveDependency -Tasks noop
./build.ps1 -Tasks pack
./build.ps1 -Tasks test

$resultFiles = @(Get-ChildItem ./output/testResults/NUnitXml_TenantPulse_v0.1.2.*.xml)
if ($resultFiles.Count -ne 1) { throw "Expected one TenantPulse result, found $($resultFiles.Count)." }
pwsh -NoProfile -File ./tests/QA/Assert-GateResult.ps1 -ResultPath $resultFiles[0].FullName -MinimumTests 2014 -AllowedSkips 0 -AllowNotRun 1
if ($LASTEXITCODE -ne 0) { throw 'TenantPulse whole-result gate failed.' }
```

Expected: `Tests Passed: 2014, Failed: 0, Skipped: 0, NotRun: 0`; gate prints `total >= 2014`.

- [ ] **Step 2: Import the built candidate and prove the exact dependency loaded**

Run in a fresh PowerShell process:

```powershell
pwsh -NoProfile -Command '
$separator = [System.IO.Path]::PathSeparator
$env:PSModulePath = @(
    (Resolve-Path ./output/module).ProviderPath
    (Resolve-Path ./output/RequiredModules).ProviderPath
    $env:PSModulePath
) -join $separator
Remove-Module TenantPulse, GraphKit -Force -ErrorAction SilentlyContinue
$tenantPulse = Import-Module TenantPulse -RequiredVersion 0.1.2 -Force -PassThru -ErrorAction Stop
$graphKit = Get-Module GraphKit
if ($tenantPulse.Version.ToString() -ne "0.1.2") { throw "Wrong TenantPulse version: $($tenantPulse.Version)" }
if ($null -eq $graphKit -or $graphKit.Version.ToString() -ne "0.2.2") { throw "Wrong GraphKit version: $($graphKit.Version)" }
"TenantPulse=$($tenantPulse.Version); GraphKit=$($graphKit.Version)"
'
```

Expected: `TenantPulse=0.1.2; GraphKit=0.2.2`.

- [ ] **Step 3: Run the real publish-preparation proof with publication disabled**

Run:

```powershell
./scripts/Publish-TenantPulsePackage.ps1 `
    -PackagePath ./output/TenantPulse.0.1.2.nupkg `
    -TestResultPath $resultFiles[0].FullName `
    -WhatIf
```

Expected:

- whole-result gate passes at 2014;
- every file in the tested-module digest matches both built output and `.nupkg`;
- output says what would publish;
- `Publish-PSResource` performs no publication.

- [ ] **Step 4: Confirm the changed candidate has not reused or published a stable identity**

Run:

```powershell
$published = Find-PSResource -Name TenantPulse -Version 0.1.2 -Repository PSGallery -ErrorAction SilentlyContinue
if ($published) { throw 'TenantPulse 0.1.2 is already published; R0 expected an unpublished candidate.' }
if (-not (Test-Path ./output/TenantPulse.0.1.2.nupkg -PathType Leaf)) { throw 'Candidate package is missing.' }
if (Test-Path ./output/TenantPulse.0.1.1.nupkg -PathType Leaf) {
    throw 'Clean pack unexpectedly left the old 0.1.1 package beside changed bytes.'
}
```

Expected: no gallery `0.1.2`; exactly the local `0.1.2` candidate exists after `pack` cleaned output.

- [ ] **Step 5: Commit no generated artifacts and verify the source tree is clean**

Run:

```bash
git status --short
git diff --check
```

Expected: no uncommitted source changes and no tracked `output/` files. If documentation formatting changed during verification, commit only those tracked source files and rerun Step 1 before continuing.

- [ ] **Step 6: Fast-forward TenantPulse main only after GraphKit remains green**

First recheck the GraphKit exact-SHA CI result from Task 3 Step 9. Then from the TenantPulse R0 worktree:

```bash
git fetch origin
git merge-base --is-ancestor origin/main HEAD
git rev-parse HEAD
```

Expected: ancestry exits 0. Record the printed TenantPulse SHA in the execution report.

From `/Users/Adam.Gell/repo/TenantPulse`:

```bash
git merge --ff-only product/r0-source-truth
git push origin main
```

- [ ] **Step 7: Require the exact TenantPulse SHA to pass every CI job**

Run:

```powershell
$sha = (git rev-parse HEAD).Trim()
$runs = @(gh run list --workflow CI --commit $sha --limit 1 --json databaseId,headSha,status,conclusion,url | ConvertFrom-Json)
if ($runs.Count -ne 1 -or $runs[0].headSha -ne $sha) { throw 'No CI run found for the exact TenantPulse SHA.' }
gh run watch $runs[0].databaseId --exit-status
if ($LASTEXITCODE -ne 0) { throw 'TenantPulse CI failed.' }
$detail = gh run view $runs[0].databaseId --json headSha,conclusion,jobs,url | ConvertFrom-Json
if ($detail.headSha -ne $sha -or $detail.conclusion -ne 'success') { throw 'TenantPulse CI did not succeed for the exact SHA.' }
if (@($detail.jobs).Count -ne 7 -or @($detail.jobs | Where-Object conclusion -ne 'success').Count -ne 0) {
    throw 'TenantPulse did not pass all six OS/PowerShell matrix jobs plus the secret scan.'
}
$detail | Select-Object headSha, conclusion, url
```

Expected: six matrix jobs plus `Secret/PII scan (gitleaks)` all succeed for the exact SHA.

---

### Task 7: Close R0 without collapsing evidence states

**Files:**
- Verify only: both repositories and remote CI
- Report only: final response; no new documentation file

- [ ] **Step 1: Prove both local `main` branches equal remote `main`**

Run in each main checkout:

```bash
git fetch origin
git status --short
git rev-parse HEAD
git rev-parse origin/main
git diff --exit-code origin/main...HEAD
```

Expected:

- GraphKit status is clean; its existing `.env` is absent from status because it is ignored without being read.
- TenantPulse status is clean.
- In each repository, `HEAD` equals `origin/main` and the diff command exits 0.

- [ ] **Step 2: Re-run the cross-repository identity assertions**

Run:

```powershell
$graphKitManifest = Import-PowerShellDataFile /Users/Adam.Gell/repo/GraphKit/source/GraphKit.psd1
$tenantPulseManifest = Import-PowerShellDataFile /Users/Adam.Gell/repo/TenantPulse/source/TenantPulse.psd1
$graphRequirement = @($tenantPulseManifest.RequiredModules | Where-Object ModuleName -eq 'GraphKit')

if ([string] $graphKitManifest.ModuleVersion -ne '0.2.2') { throw 'GraphKit source identity drifted.' }
if ([string] $tenantPulseManifest.ModuleVersion -ne '0.1.2') { throw 'TenantPulse candidate identity drifted.' }
if ($graphRequirement.Count -ne 1 -or [string] $graphRequirement[0].RequiredVersion -ne '0.2.2') {
    throw 'TenantPulse no longer requires exact GraphKit 0.2.2.'
}
if ($graphRequirement[0].ContainsKey('ModuleVersion') -or $graphRequirement[0].ContainsKey('MaximumVersion')) {
    throw 'TenantPulse exact requirement is mixed with range semantics.'
}
```

Expected: command returns without throwing.

- [ ] **Step 3: Record the proof ladder in the execution report**

The final execution response must list, separately:

1. GraphKit final source SHA.
2. GraphKit local result: 753 tests, zero failures/errors/skips.
3. GraphKit CI run URL and six successful jobs for that exact SHA.
4. GraphKit gallery-payload parity result for `0.2.2`.
5. TenantPulse final source SHA.
6. TenantPulse local result: 2014 tests, zero failures/errors/skips/NotRun.
7. TenantPulse CI run URL and seven successful jobs for that exact SHA.
8. TenantPulse candidate package identity `0.1.2`, SHA-256, and successful dry-run digest verification.
9. Explicit publication state: GraphKit `0.2.2` reused unchanged; TenantPulse `0.1.2` not published.
10. Explicit gate: R1 remains blocked unless every item above passed.

Do not report local tests as CI, CI as live-tenant proof, package existence as publication, or publication as live verification.

- [ ] **Step 4: Mark R0 complete only if every gate passed**

R0 is complete only when both repositories are clean and remote-synchronized, exact package identities are proven, the GraphKit producer precedes the TenantPulse consumer, and exact-SHA CI is green. Any failed parity, dependency, package, or CI check leaves R0 blocked; do not begin R1.
