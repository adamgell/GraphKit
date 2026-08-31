<#
    .SYNOPSIS
        Captures and finalizes GraphKit's canonical tested-release proof.

    .DESCRIPTION
        Capture runs before Pester. It invalidates prior result/proof files and records the
        exact built-module file set plus package archive hash. Finalize runs only after
        Pester: it requires one matching NUnit/Pester-object pair, applies the complete
        release gate, rechecks the candidate and result bytes, and atomically writes
        tested-release-proof.json. A failed or interrupted test attempt therefore leaves
        no stale proof capable of authorizing publication.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Capture', 'Finalize')]
    [string] $Stage,

    [string] $RepositoryRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$minimumTests = 896
$allowedSkips = 0
$allowedNotRun = 0

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Split-Path $PSScriptRoot -Parent
}
$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).ProviderPath
$resultsDirectory = Join-Path $RepositoryRoot 'output/testResults'
$candidatePath = Join-Path $resultsDirectory 'candidate-release-input.json'
$proofPath = Join-Path $resultsDirectory 'tested-release-proof.json'

function Get-GraphKitReleaseCandidateState {
    param([Parameter(Mandatory)] [string] $Root)

    $versionScript = Join-Path $Root 'scripts/Get-GraphKitTrainVersion.ps1'
    if (-not (Test-Path -LiteralPath $versionScript -PathType Leaf)) {
        throw "Release proof requires '$versionScript'."
    }
    $fullVersion = (& $versionScript -RepositoryRoot $Root).Trim()
    if ($LASTEXITCODE -ne 0 -or $fullVersion -notmatch '^(?<base>\d+\.\d+\.\d+)-r8\.g(?<revision>[0-9a-f]{12})(?:\.d(?<diff>[0-9a-f]{12}))?$') {
        throw "Release proof received an invalid GraphKit train version '$fullVersion'."
    }
    $baseVersion = $Matches['base']
    $sourceRevision = (& git -C $Root rev-parse HEAD).Trim().ToLowerInvariant()
    if ($LASTEXITCODE -ne 0 -or $sourceRevision -notmatch '^[0-9a-f]{40}$') {
        throw "Release proof cannot resolve a 40-character source revision for '$Root'."
    }
    $sourceDiff = (& git -C $Root diff --binary HEAD)
    if ($LASTEXITCODE -ne 0) {
        throw "Release proof cannot determine the source state for '$Root'."
    }
    $sourceClean = [string]::IsNullOrEmpty($sourceDiff)
    $sourceDiffHash = if ($sourceClean) {
        $null
    }
    else {
        $bytes = [Text.Encoding]::UTF8.GetBytes($sourceDiff)
        [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    }

    $moduleRoot = Join-Path $Root 'output/module/GraphKit'
    $versionDirectories = @(
        Get-ChildItem -LiteralPath $moduleRoot -Directory -ErrorAction SilentlyContinue
    )
    if ($versionDirectories.Count -ne 1) {
        throw "Release proof requires exactly one built GraphKit version under '$moduleRoot'; found $($versionDirectories.Count). Run ./build.ps1 -Tasks pack."
    }
    $moduleDirectory = $versionDirectories[0].FullName
    $version = $versionDirectories[0].Name
    $manifestPath = Join-Path $moduleDirectory 'GraphKit.psd1'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Built GraphKit manifest is missing at '$manifestPath'."
    }
    $manifest = Import-PowerShellDataFile -LiteralPath $manifestPath
    if ($version -cne $baseVersion -or [string] $manifest.ModuleVersion -cne $baseVersion) {
        throw "Built manifest version '$($manifest.ModuleVersion)' does not match its version directory '$version'."
    }
    $expectedPrerelease = $fullVersion.Substring($baseVersion.Length + 1)
    if ([string] $manifest.PrivateData.PSData.Prerelease -cne $expectedPrerelease) {
        throw "Built manifest prerelease '$($manifest.PrivateData.PSData.Prerelease)' does not match release candidate '$fullVersion'."
    }

    [string[]] $relativePaths = @(
        Get-ChildItem -LiteralPath $moduleDirectory -Recurse -File -Force |
            ForEach-Object {
                $_.FullName.Substring($moduleDirectory.Length + 1) -replace '\\', '/'
            }
    )
    [System.Array]::Sort($relativePaths, [System.StringComparer]::Ordinal)
    if ($relativePaths.Count -eq 0) {
        throw "Built GraphKit module '$moduleDirectory' contains no files."
    }
    $files = @(
        $relativePaths | ForEach-Object {
            [pscustomobject] [ordered] @{
                path = $_
                sha256 = (Get-FileHash -LiteralPath (Join-Path $moduleDirectory $_) -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
    )

    $packagePath = Join-Path $Root "output/GraphKit.$fullVersion.nupkg"
    if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf)) {
        throw "Release candidate package '$packagePath' is missing. Run ./build.ps1 -Tasks pack before test."
    }

    [pscustomobject] [ordered] @{
        module = [pscustomobject] [ordered] @{
            name = 'GraphKit'
            version = $fullVersion
            baseVersion = $baseVersion
            files = $files
        }
        source = [pscustomobject] [ordered] @{
            revision = $sourceRevision
            clean = $sourceClean
            diffSha256 = $sourceDiffHash
        }
        package = [pscustomobject] [ordered] @{
            name = Split-Path -Leaf $packagePath
            sha256 = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
}

function Assert-GraphKitReleaseCandidateUnchanged {
    param(
        [Parameter(Mandatory)] [object] $Captured,
        [Parameter(Mandatory)] [object] $Current
    )

    $capturedFiles = @($Captured.module.files)
    $currentFiles = @($Current.module.files)
    $moduleChanged =
        [string] $Captured.module.name -cne [string] $Current.module.name -or
        [string] $Captured.module.version -cne [string] $Current.module.version -or
        [string] $Captured.module.baseVersion -cne [string] $Current.module.baseVersion -or
        $capturedFiles.Count -ne $currentFiles.Count
    if (-not $moduleChanged) {
        for ($index = 0; $index -lt $capturedFiles.Count; $index++) {
            if ([string] $capturedFiles[$index].path -cne [string] $currentFiles[$index].path -or
                [string] $capturedFiles[$index].sha256 -cne [string] $currentFiles[$index].sha256) {
                $moduleChanged = $true
                break
            }
        }
    }
    if ($moduleChanged) {
        throw 'The built module candidate changed after capture; no tested release proof was emitted.'
    }
    if ([string] $Captured.source.revision -cne [string] $Current.source.revision -or
        [bool] $Captured.source.clean -ne [bool] $Current.source.clean -or
        [string] $Captured.source.diffSha256 -cne [string] $Current.source.diffSha256) {
        throw 'The source candidate changed after capture; no tested release proof was emitted.'
    }
    if ([string] $Captured.package.name -cne [string] $Current.package.name -or
        [string] $Captured.package.sha256 -cne [string] $Current.package.sha256) {
        throw 'The package candidate changed after capture; no tested release proof was emitted.'
    }
}

function Get-GraphKitReleaseResultPair {
    param([Parameter(Mandatory)] [string] $Directory)

    $nunitFiles = @(Get-ChildItem -LiteralPath $Directory -Filter 'NUnitXml_*.xml' -File -ErrorAction SilentlyContinue)
    $pesterObjectFiles = @(Get-ChildItem -LiteralPath $Directory -Filter 'PesterObject_*.xml' -File -ErrorAction SilentlyContinue)
    if ($nunitFiles.Count -ne 1 -or $pesterObjectFiles.Count -ne 1) {
        throw "Release proof requires exactly one NUnit/Pester-object result pair; found $($nunitFiles.Count) NUnit and $($pesterObjectFiles.Count) Pester object file(s)."
    }
    $nunitSuffix = $nunitFiles[0].Name.Substring('NUnitXml_'.Length)
    $pesterObjectSuffix = $pesterObjectFiles[0].Name.Substring('PesterObject_'.Length)
    if ($nunitSuffix -cne $pesterObjectSuffix) {
        throw "NUnit and Pester-object result suffixes do not match: '$nunitSuffix' vs '$pesterObjectSuffix'."
    }
    [pscustomobject] [ordered] @{
        nunit = [pscustomobject] [ordered] @{
            name = $nunitFiles[0].Name
            path = $nunitFiles[0].FullName
            sha256 = (Get-FileHash -LiteralPath $nunitFiles[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        pesterObject = [pscustomobject] [ordered] @{
            name = $pesterObjectFiles[0].Name
            path = $pesterObjectFiles[0].FullName
            sha256 = (Get-FileHash -LiteralPath $pesterObjectFiles[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
}

function Get-GraphKitReleaseResultSummary {
    param([Parameter(Mandatory)] [object] $ResultPair)

    [xml] $resultDocument = Get-Content -LiteralPath $ResultPair.nunit.path -Raw
    $resultRoot = $resultDocument.SelectSingleNode('/test-results')
    $topSuite = if ($null -eq $resultRoot) { $null } else { $resultRoot.SelectSingleNode('test-suite') }
    if ($null -eq $resultRoot -or $null -eq $topSuite) {
        throw 'The NUnit result is structurally incomplete.'
    }
    function ConvertTo-ReleaseCount {
        param([Parameter(Mandatory)] [string] $Name)
        $raw = [string] $resultRoot.GetAttribute($Name)
        $parsed = 0
        if (-not [int]::TryParse($raw, [ref] $parsed) -or $parsed -lt 0) {
            throw "The NUnit '$Name' count is unreadable: '$raw'."
        }
        return $parsed
    }

    $pesterResult = Import-Clixml -LiteralPath $ResultPair.pesterObject.path
    foreach ($propertyName in @(
        'Result',
        'TotalCount',
        'PassedCount',
        'FailedCount',
        'SkippedCount',
        'NotRunCount',
        'InconclusiveCount',
        'FailedBlocksCount',
        'FailedContainersCount',
        'Executed'
    )) {
        if ($propertyName -notin @($pesterResult.PSObject.Properties.Name)) {
            throw "The Pester object has no '$propertyName' property."
        }
    }
    function ConvertTo-PesterReleaseCount {
        param([Parameter(Mandatory)] [string] $Name)
        $raw = $pesterResult.$Name
        $parsed = 0
        if ($null -eq $raw -or -not [int]::TryParse([string] $raw, [ref] $parsed) -or $parsed -lt 0) {
            throw "The Pester '$Name' count is unreadable: '$raw'."
        }
        return $parsed
    }
    function ConvertTo-PesterReleaseBoolean {
        param([Parameter(Mandatory)] [string] $Name)
        $raw = $pesterResult.$Name
        $parsed = $false
        if ($null -eq $raw -or -not [bool]::TryParse([string] $raw, [ref] $parsed)) {
            throw "The Pester '$Name' value is unreadable: '$raw'."
        }
        return $parsed
    }

    $pesterExecuted = ConvertTo-PesterReleaseBoolean -Name 'Executed'
    $pesterPassed = ConvertTo-PesterReleaseCount -Name 'PassedCount'

    $summary = [pscustomobject] [ordered] @{
        overallResult = [string] $topSuite.GetAttribute('result')
        pesterResult = [string] $pesterResult.Result
        executed = $pesterExecuted
        total = ConvertTo-ReleaseCount -Name 'total'
        passed = $pesterPassed
        failures = ConvertTo-ReleaseCount -Name 'failures'
        errors = ConvertTo-ReleaseCount -Name 'errors'
        skipped = ConvertTo-ReleaseCount -Name 'skipped'
        inconclusive = ConvertTo-ReleaseCount -Name 'inconclusive'
        notRun = ConvertTo-PesterReleaseCount -Name 'NotRunCount'
        failedBlocks = ConvertTo-PesterReleaseCount -Name 'FailedBlocksCount'
        failedContainers = ConvertTo-PesterReleaseCount -Name 'FailedContainersCount'
    }
    if ($summary.failedBlocks -gt 0) {
        throw "$($summary.failedBlocks) failed block(s) were recorded; no tested release proof was emitted."
    }
    if ($summary.failedContainers -gt 0) {
        throw "$($summary.failedContainers) failed container(s) / discovery error(s) were recorded; no tested release proof was emitted."
    }
    if (-not $summary.executed) {
        throw 'The Pester run was not executed; no tested release proof was emitted.'
    }
    $pesterInconclusive = ConvertTo-PesterReleaseCount -Name 'InconclusiveCount'
    if ($summary.inconclusive -gt 0 -or $pesterInconclusive -gt 0) {
        throw "$([Math]::Max($summary.inconclusive, $pesterInconclusive)) inconclusive test(s) were recorded; no tested release proof was emitted."
    }
    if ((ConvertTo-PesterReleaseCount -Name 'TotalCount') -ne $summary.total -or
        (ConvertTo-PesterReleaseCount -Name 'FailedCount') -ne $summary.failures -or
        (ConvertTo-PesterReleaseCount -Name 'SkippedCount') -ne $summary.skipped -or
        (ConvertTo-PesterReleaseCount -Name 'InconclusiveCount') -ne $summary.inconclusive) {
        throw 'The NUnit and Pester-object result summaries disagree.'
    }
    $pesterOutcomeTotal = [long] $summary.passed +
        [long] $summary.failures +
        [long] $summary.skipped +
        [long] $summary.inconclusive +
        [long] $summary.notRun
    if ($pesterOutcomeTotal -ne [long] $summary.total) {
        throw "Pester count arithmetic is inconsistent: passed + failed + skipped + inconclusive + NotRun is $pesterOutcomeTotal, not total $($summary.total)."
    }
    return $summary
}

if ($Stage -eq 'Capture') {
    if (-not (Test-Path -LiteralPath $resultsDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $resultsDirectory -Force | Out-Null
    }

    # Invalidate every previous authorization record before a new test attempt begins.
    Remove-Item -LiteralPath $candidatePath, $proofPath -Force -ErrorAction SilentlyContinue
    Get-ChildItem -LiteralPath $resultsDirectory -File -ErrorAction SilentlyContinue |
        Where-Object Name -Match '^(NUnitXml_|PesterObject_).*\.xml$' |
        Remove-Item -Force

    $candidate = Get-GraphKitReleaseCandidateState -Root $RepositoryRoot
    $capture = [pscustomobject] [ordered] @{
        schemaVersion = 2
        runId = [guid]::NewGuid().ToString('D')
        module = $candidate.module
        source = $candidate.source
        package = $candidate.package
    }
    $stagedCandidatePath = "$candidatePath.tmp-$PID-$([guid]::NewGuid().ToString('N'))"
    try {
        $capture | ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath $stagedCandidatePath -NoNewline -Encoding utf8NoBOM
        [System.IO.File]::Move($stagedCandidatePath, $candidatePath, $true)
    }
    finally {
        Remove-Item -LiteralPath $stagedCandidatePath -Force -ErrorAction SilentlyContinue
    }
    Write-Host "CAPTURED RELEASE CANDIDATE: GraphKit $($candidate.module.version); $(@($candidate.module.files).Count) shipped file(s); package $($candidate.package.sha256)."
    return
}

if (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
    throw "No pre-test candidate capture exists at '$candidatePath'. Run the test workflow from its Capture stage."
}
if (Test-Path -LiteralPath $proofPath -PathType Leaf) {
    throw "A tested release proof already exists at '$proofPath'; Capture must invalidate it before Finalize."
}
try {
    $captured = Get-Content -LiteralPath $candidatePath -Raw | ConvertFrom-Json -Depth 8
}
catch {
    throw "The pre-test candidate capture is unreadable: $($_.Exception.Message)"
}
$parsedRunId = [guid]::Empty
if ([int] $captured.schemaVersion -ne 2 -or
    -not [guid]::TryParse([string] $captured.runId, [ref] $parsedRunId) -or
    $parsedRunId -eq [guid]::Empty) {
    throw 'The pre-test candidate capture has an invalid schema version or run id.'
}

$currentCandidate = Get-GraphKitReleaseCandidateState -Root $RepositoryRoot
Assert-GraphKitReleaseCandidateUnchanged -Captured $captured -Current $currentCandidate
$resultPair = Get-GraphKitReleaseResultPair -Directory $resultsDirectory
$summary = Get-GraphKitReleaseResultSummary -ResultPair $resultPair

$gatePath = Join-Path $RepositoryRoot 'tests/QA/Assert-GateResult.ps1'
$gateOutput = & pwsh -NoLogo -NoProfile -File $gatePath `
    -ResultPath $resultPair.nunit.path `
    -MinimumTests $minimumTests `
    -AllowedSkips $allowedSkips 2>&1
if ($LASTEXITCODE -ne 0) {
    $flatGateOutput = (($gateOutput | Out-String) -replace '\r?\n\s*\|\s*', ' ' -replace '\s+', ' ').Trim()
    throw "The result pair did not pass the whole-result gate: $flatGateOutput"
}
if ($summary.pesterResult -cne 'Passed') {
    throw "The Pester result is '$($summary.pesterResult)', not Passed."
}
if ($summary.notRun -gt $allowedNotRun) {
    throw "$($summary.notRun) NotRun test block(s) exceed the tested release allowance of $allowedNotRun."
}

# The gate consumes the result files. Re-hash them and the candidate afterwards to close
# both replacement windows before any publication authority is written.
$postGateResultPair = Get-GraphKitReleaseResultPair -Directory $resultsDirectory
if ([string] $postGateResultPair.nunit.name -cne [string] $resultPair.nunit.name -or
    [string] $postGateResultPair.nunit.sha256 -cne [string] $resultPair.nunit.sha256 -or
    [string] $postGateResultPair.pesterObject.name -cne [string] $resultPair.pesterObject.name -or
    [string] $postGateResultPair.pesterObject.sha256 -cne [string] $resultPair.pesterObject.sha256) {
    throw 'The NUnit/Pester-object result pair changed while the whole-result gate was running.'
}
$postGateCandidate = Get-GraphKitReleaseCandidateState -Root $RepositoryRoot
Assert-GraphKitReleaseCandidateUnchanged -Captured $captured -Current $postGateCandidate

$releaseProof = [pscustomobject] [ordered] @{
    schemaVersion = 2
    runId = [string] $captured.runId
    source = $captured.source
    module = $captured.module
    package = $captured.package
    testRun = [pscustomobject] [ordered] @{
        nunit = [pscustomobject] [ordered] @{
            name = $resultPair.nunit.name
            sha256 = $resultPair.nunit.sha256
        }
        pesterObject = [pscustomobject] [ordered] @{
            name = $resultPair.pesterObject.name
            sha256 = $resultPair.pesterObject.sha256
        }
        policy = [pscustomobject] [ordered] @{
            minimumTests = $minimumTests
            allowedSkips = $allowedSkips
            allowedNotRun = $allowedNotRun
        }
        summary = $summary
    }
}

$stagedProofPath = "$proofPath.tmp-$PID-$([guid]::NewGuid().ToString('N'))"
try {
    $releaseProof | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $stagedProofPath -NoNewline -Encoding utf8NoBOM

    $verifierPath = Join-Path $RepositoryRoot 'scripts/Test-GraphKitReleaseProof.ps1'
    $packagePath = Join-Path $RepositoryRoot "output/$($captured.package.name)"
    $verificationOutput = & pwsh -NoLogo -NoProfile -File $verifierPath `
        -PackagePath $packagePath `
        -ProofPath $stagedProofPath `
        -RepositoryRoot $RepositoryRoot 2>&1
    if ($LASTEXITCODE -ne 0) {
        $flatVerificationOutput = (($verificationOutput | Out-String) -replace '\r?\n\s*\|\s*', ' ' -replace '\s+', ' ').Trim()
        throw "The staged tested release proof failed canonical verification: $flatVerificationOutput"
    }

    Remove-Item -LiteralPath $candidatePath -Force
    [System.IO.File]::Move($stagedProofPath, $proofPath, $true)
}
finally {
    Remove-Item -LiteralPath $stagedProofPath -Force -ErrorAction SilentlyContinue
}

Write-Host "RECORDED TESTED RELEASE PROOF: GraphKit $($captured.module.version); $(@($captured.module.files).Count) shipped file(s); $($summary.total) tests; proof '$proofPath'."
