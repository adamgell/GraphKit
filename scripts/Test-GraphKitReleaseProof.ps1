<#
    .SYNOPSIS
        Independently verifies a GraphKit tested-release proof and optionally snapshots it.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $PackagePath,
    [Parameter(Mandatory)] [string] $ProofPath,
    [Parameter(Mandatory)] [string] $RepositoryRoot,
    [string] $TestResultPath,
    [string] $PackageSnapshotPath,
    [string] $ProofSnapshotPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Get-LowerFileHash {
    param([Parameter(Mandatory)] [string] $Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Get-LowerStreamHash {
    param([Parameter(Mandatory)] [System.IO.Stream] $Stream)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return [Convert]::ToHexString($sha.ComputeHash($Stream)).ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function Assert-RegularFile {
    param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] [string] $Label)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -and ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) { return $item }
    throw "$Label '$Path' must be a regular file and must not be a symlink or reparse point."
}
function Assert-SafeRelativePath {
    param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] [string] $Kind)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains('\') -or $Path.StartsWith('/') -or
        $Path -match '^[A-Za-z]:' -or $Path -match '(^|/)\.\.?(/|$)') {
        throw "Unsafe $Kind path '$Path'."
    }
}
function Test-NuGetMetadataPath {
    param([Parameter(Mandatory)] [string] $Path)
    return $Path -in @('_rels/.rels', 'GraphKit.nuspec', '[Content_Types].xml') -or
        $Path -match '^package/services/metadata/core-properties/[^/]+\.psmdcp$'
}
function Assert-ExactMembers {
    param([Parameter(Mandatory)] $Object, [Parameter(Mandatory)] [string[]] $Expected, [Parameter(Mandatory)] [string] $Label)
    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    if (($actual -join "`n") -cne ($wanted -join "`n")) {
        throw "$Label members mismatch. Expected [$($wanted -join ', ')]; got [$($actual -join ', ')]."
    }
}
function Copy-VerifiedFile {
    param([string] $Source, [string] $Destination, [string] $ExpectedHash, [string] $Label)
    if ([string]::IsNullOrWhiteSpace($Destination)) { return $null }
    $full = [System.IO.Path]::GetFullPath($Destination, (Get-Location).ProviderPath)
    $directory = Split-Path -Parent $full
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { $null = New-Item -ItemType Directory -Path $directory -Force }
    Copy-Item -LiteralPath $Source -Destination $full -Force
    $item = Assert-RegularFile -Path $full -Label $Label
    if ((Get-LowerFileHash -Path $item.FullName) -cne $ExpectedHash) { throw "$Label snapshot digest mismatch after copy." }
    return $item.FullName
}

$repo = (Resolve-Path -LiteralPath $RepositoryRoot).ProviderPath
$package = Assert-RegularFile -Path (Resolve-Path -LiteralPath $PackagePath).ProviderPath -Label 'Package'
$proofFile = Assert-RegularFile -Path (Resolve-Path -LiteralPath $ProofPath).ProviderPath -Label 'Proof'
$proof = Get-Content -LiteralPath $proofFile.FullName -Raw | ConvertFrom-Json

Assert-ExactMembers -Object $proof -Expected @('schemaVersion', 'sourceRevision', 'module', 'package', 'testRun') -Label 'Proof'
Assert-ExactMembers -Object $proof.module -Expected @('name', 'version', 'files') -Label 'Module proof'
Assert-ExactMembers -Object $proof.package -Expected @('name', 'sizeBytes', 'sha256') -Label 'Package proof'
Assert-ExactMembers -Object $proof.testRun -Expected @('nunit') -Label 'Test-run proof'
Assert-ExactMembers -Object $proof.testRun.nunit -Expected @('name', 'sha256', 'total', 'failures', 'errors', 'skipped', 'inconclusive', 'notRun') -Label 'NUnit proof'
if ([int] $proof.schemaVersion -ne 1) { throw "Unsupported proof schema '$($proof.schemaVersion)'." }
if ([string] $proof.module.name -cne 'GraphKit' -or [string] $proof.module.version -cne '0.3.1') {
    throw "Proof is not for stable GraphKit 0.3.1."
}
if ([string] $proof.sourceRevision -notmatch '^[0-9a-f]{40}$') { throw 'Proof source revision is malformed.' }

if ($package.Name -cne [string] $proof.package.name) {
    throw "Package name mismatch: proof names '$($proof.package.name)', supplied '$($package.Name)'."
}

$trackedStatus = (& git -C $repo status --porcelain --untracked-files=no 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw "Could not inspect Git status for '$repo': $trackedStatus" }
if (-not [string]::IsNullOrEmpty($trackedStatus)) { throw 'Tracked source is dirty; release proof is stale.' }
$head = (& git -C $repo rev-parse HEAD 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $head -cne [string] $proof.sourceRevision) {
    throw "Source revision mismatch: proof '$($proof.sourceRevision)', repository '$head'."
}

$proofFiles = @($proof.module.files)
if ($proofFiles.Count -eq 0) { throw 'Proof module file list is empty.' }
$proofByPath = @{}
$proofPathKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($fileProof in $proofFiles) {
    Assert-ExactMembers -Object $fileProof -Expected @('path', 'sizeBytes', 'sha256') -Label 'Module file proof'
    $path = [string] $fileProof.path
    Assert-SafeRelativePath -Path $path -Kind 'proof module'
    if (-not $proofPathKeys.Add($path)) { throw "Duplicate proof module path '$path' (case-insensitive)." }
    if ([string] $fileProof.sha256 -notmatch '^[0-9a-f]{64}$' -or [int64] $fileProof.sizeBytes -lt 0) {
        throw "Malformed module file proof for '$path'."
    }
    $proofByPath[$path] = $fileProof
}

$moduleRoot = Join-Path $repo "output/module/GraphKit/$($proof.module.version)"
if (-not (Test-Path -LiteralPath $moduleRoot -PathType Container)) { throw "Built module '$moduleRoot' is absent." }
$builtPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
foreach ($file in Get-ChildItem -LiteralPath $moduleRoot -File -Recurse) {
    $null = Assert-RegularFile -Path $file.FullName -Label 'Built module file'
    $relative = [System.IO.Path]::GetRelativePath($moduleRoot, $file.FullName).Replace('\', '/')
    Assert-SafeRelativePath -Path $relative -Kind 'built module'
    if (-not $proofByPath.ContainsKey($relative)) { throw "Built file set mismatch; unlisted file '$relative'." }
    $expected = $proofByPath[$relative]
    if ((Get-LowerFileHash -Path $file.FullName) -cne [string] $expected.sha256 -or [int64] $file.Length -ne [int64] $expected.sizeBytes) {
        throw "Built file digest mismatch for '$relative'."
    }
    $null = $builtPaths.Add($relative)
}
$missingBuilt = @($proofByPath.Keys | Where-Object { -not $builtPaths.Contains($_) })
if ($missingBuilt.Count -gt 0) { throw "Built file set mismatch; missing: $($missingBuilt -join ', ')." }

$archivePaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$matchedModule = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
$archive = [System.IO.Compression.ZipFile]::OpenRead($package.FullName)
try {
    foreach ($entry in $archive.Entries) {
        if ([string]::IsNullOrEmpty($entry.Name)) { continue }
        $path = $entry.FullName
        Assert-SafeRelativePath -Path $path -Kind 'archive'
        if (-not $archivePaths.Add($path)) { throw "Duplicate archive path '$path' (case-insensitive)." }
        if (-not $proofByPath.ContainsKey($path)) {
            if (-not (Test-NuGetMetadataPath -Path $path)) { throw "Unlisted archive entry '$path'." }
            continue
        }
        $expected = $proofByPath[$path]
        $stream = $entry.Open()
        try { $actualHash = Get-LowerStreamHash -Stream $stream } finally { $stream.Dispose() }
        if ($actualHash -cne [string] $expected.sha256 -or [int64] $entry.Length -ne [int64] $expected.sizeBytes) {
            throw "Archive file digest mismatch for '$path'."
        }
        $null = $matchedModule.Add($path)
    }
}
finally { $archive.Dispose() }
$missingArchive = @($proofByPath.Keys | Where-Object { -not $matchedModule.Contains($_) })
if ($missingArchive.Count -gt 0) { throw "Archive file set mismatch; missing: $($missingArchive -join ', ')." }

$packageHash = Get-LowerFileHash -Path $package.FullName
if ([int64] $package.Length -ne [int64] $proof.package.sizeBytes) { throw 'Package size mismatch.' }
if ($packageHash -cne [string] $proof.package.sha256) { throw 'Package digest mismatch.' }

if ([string]::IsNullOrWhiteSpace($TestResultPath)) {
    $TestResultPath = Join-Path $repo "output/testResults/$($proof.testRun.nunit.name)"
}
$resultFile = Assert-RegularFile -Path (Resolve-Path -LiteralPath $TestResultPath).ProviderPath -Label 'Test result'
if ($resultFile.Name -cne [string] $proof.testRun.nunit.name) { throw 'Test result name mismatch.' }
if ((Get-LowerFileHash -Path $resultFile.FullName) -cne [string] $proof.testRun.nunit.sha256) { throw 'Test result digest mismatch.' }
[xml] $resultDocument = Get-Content -LiteralPath $resultFile.FullName -Raw
$resultRoot = $resultDocument.SelectSingleNode('/test-results')
if ($null -eq $resultRoot) { throw 'Test result has no /test-results root.' }
$topSuite = $resultRoot.SelectSingleNode('test-suite')
if ($null -eq $topSuite -or [string] $topSuite.GetAttribute('result') -notin @('Success', 'Passed')) {
    throw 'Test result overall status is not successful.'
}
$failedSuites = @($resultRoot.SelectNodes('//test-suite[@result="Failure" or @result="Error"]'))
if ($failedSuites.Count -gt 0) {
    $failedNames = @($failedSuites | ForEach-Object { [string] $_.GetAttribute('name') })
    throw "$($failedSuites.Count) failed container(s) or discovery error(s): $($failedNames -join ', ')."
}
$actualCounts = @{
    total = [int] $resultRoot.GetAttribute('total'); failures = [int] $resultRoot.GetAttribute('failures')
    errors = [int] $resultRoot.GetAttribute('errors'); skipped = [int] $resultRoot.GetAttribute('skipped')
    inconclusive = [int] $resultRoot.GetAttribute('inconclusive'); notRun = [int] $resultRoot.GetAttribute('not-run')
}
foreach ($field in $actualCounts.Keys) {
    if ($actualCounts[$field] -ne [int] $proof.testRun.nunit.$field) { throw "Test result count mismatch for '$field'." }
}
foreach ($zeroField in @('failures', 'errors', 'skipped', 'inconclusive', 'notRun')) {
    if ($actualCounts[$zeroField] -ne 0) { throw "Test result is not releasable: $zeroField=$($actualCounts[$zeroField])." }
}
if ($actualCounts.total -lt 791) { throw "Test result has $($actualCounts.total) tests; release-proof minimum is 791." }

$packageSnapshot = Copy-VerifiedFile -Source $package.FullName -Destination $PackageSnapshotPath -ExpectedHash $packageHash -Label 'Package'
$proofHash = Get-LowerFileHash -Path $proofFile.FullName
$proofSnapshot = Copy-VerifiedFile -Source $proofFile.FullName -Destination $ProofSnapshotPath -ExpectedHash $proofHash -Label 'Proof'

[pscustomobject]@{
    Version = [string] $proof.module.version
    PackageSha256 = $packageHash
    PackageSizeBytes = [int64] $package.Length
    TestCount = $actualCounts.total
    ShippedFileCount = $proofFiles.Count
    SourceRevision = $head
    PackageSnapshotPath = $packageSnapshot
    ProofSnapshotPath = $proofSnapshot
}
