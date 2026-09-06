<#
    .SYNOPSIS
        Seals a tested GraphKit package, built tree, NUnit result, and source revision.

    .DESCRIPTION
        This script never builds or publishes. Run pack first, test second, then create the
        proof. Every regular file in the built module must be present byte-for-byte in the
        package; the package container, complete file inventory, NUnit result, and clean tracked
        source revision are recorded together.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $PackagePath,
    [Parameter(Mandatory)] [string] $TestResultPath,
    [Parameter(Mandatory)] [string] $OutputPath,
    [string] $RepositoryRoot = (Split-Path $PSScriptRoot -Parent),
    [ValidateRange(1, [int]::MaxValue)] [int] $MinimumTests = 789
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

$repo = (Resolve-Path -LiteralPath $RepositoryRoot).ProviderPath
$package = Assert-RegularFile -Path (Resolve-Path -LiteralPath $PackagePath).ProviderPath -Label 'Package'
$testResult = Assert-RegularFile -Path (Resolve-Path -LiteralPath $TestResultPath).ProviderPath -Label 'Test result'

$trackedStatus = (& git -C $repo status --porcelain --untracked-files=no 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw "Could not inspect Git status for '$repo': $trackedStatus" }
if (-not [string]::IsNullOrEmpty($trackedStatus)) {
    throw 'Tracked source is dirty. Commit the exact tested source before creating a release proof.'
}
$sourceRevision = (& git -C $repo rev-parse HEAD 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceRevision -notmatch '^[0-9a-f]{40}$') {
    throw "Could not resolve a 40-character source revision for '$repo'."
}

if ($package.Name -notmatch '^GraphKit\.(?<version>\d+\.\d+\.\d+)\.nupkg$') {
    throw "Package '$($package.Name)' must be named GraphKit.<version>.nupkg."
}
$version = $Matches.version
if ($version -ne '0.3.1') { throw "This maintenance proof requires GraphKit 0.3.1; got '$version'." }

$moduleRoot = Join-Path $repo "output/module/GraphKit/$version"
if (-not (Test-Path -LiteralPath $moduleRoot -PathType Container)) {
    throw "Built module '$moduleRoot' does not exist. Run pack before test and proof creation."
}
$manifest = Import-PowerShellDataFile (Join-Path $moduleRoot 'GraphKit.psd1')
if ([string] $manifest.ModuleVersion -ne $version) {
    throw "Built manifest version '$($manifest.ModuleVersion)' does not match package version '$version'."
}

[xml] $resultDocument = Get-Content -LiteralPath $testResult.FullName -Raw
$resultRoot = $resultDocument.SelectSingleNode('/test-results')
if ($null -eq $resultRoot) { throw "Test result '$($testResult.FullName)' has no /test-results root." }
$counts = [ordered]@{
    total = [int] $resultRoot.GetAttribute('total')
    failures = [int] $resultRoot.GetAttribute('failures')
    errors = [int] $resultRoot.GetAttribute('errors')
    skipped = [int] $resultRoot.GetAttribute('skipped')
    inconclusive = [int] $resultRoot.GetAttribute('inconclusive')
    notRun = [int] $resultRoot.GetAttribute('not-run')
}
if ($counts.total -lt $MinimumTests) { throw "Test result has $($counts.total) tests; minimum is $MinimumTests." }
foreach ($zeroField in @('failures', 'errors', 'skipped', 'inconclusive', 'notRun')) {
    if ($counts[$zeroField] -ne 0) { throw "Test result is not releasable: $zeroField=$($counts[$zeroField])." }
}
$resultName = [string] $resultRoot.GetAttribute('name')
if ($testResult.Name -notmatch [regex]::Escape($version) -and $resultName -notmatch [regex]::Escape($version)) {
    throw "Test result '$($testResult.Name)' does not identify GraphKit $version."
}

$moduleFiles = [System.Collections.Generic.List[object]]::new()
$pathKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($file in Get-ChildItem -LiteralPath $moduleRoot -File -Recurse | Sort-Object FullName) {
    $null = Assert-RegularFile -Path $file.FullName -Label 'Built module file'
    $relative = [System.IO.Path]::GetRelativePath($moduleRoot, $file.FullName).Replace('\', '/')
    Assert-SafeRelativePath -Path $relative -Kind 'built module'
    if (-not $pathKeys.Add($relative)) { throw "Duplicate built module path '$relative' (case-insensitive)." }
    $moduleFiles.Add([ordered]@{
        path = $relative
        sizeBytes = [int64] $file.Length
        sha256 = Get-LowerFileHash -Path $file.FullName
    })
}
if ($moduleFiles.Count -eq 0) { throw 'Built module contains no files.' }

$archivePaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$matchedModule = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
$archive = [System.IO.Compression.ZipFile]::OpenRead($package.FullName)
try {
    foreach ($entry in $archive.Entries) {
        if ([string]::IsNullOrEmpty($entry.Name)) { continue }
        $path = $entry.FullName
        Assert-SafeRelativePath -Path $path -Kind 'archive'
        if (-not $archivePaths.Add($path)) { throw "Duplicate archive path '$path' (case-insensitive)." }

        $expected = $moduleFiles | Where-Object { $_.path -ceq $path } | Select-Object -First 1
        if ($null -eq $expected) {
            if (-not (Test-NuGetMetadataPath -Path $path)) { throw "Unlisted archive entry '$path'." }
            continue
        }

        $stream = $entry.Open()
        try { $actualHash = Get-LowerStreamHash -Stream $stream } finally { $stream.Dispose() }
        if ($actualHash -cne $expected.sha256 -or [int64] $entry.Length -ne $expected.sizeBytes) {
            throw "Archive file digest mismatch for '$path'."
        }
        $null = $matchedModule.Add($path)
    }
}
finally { $archive.Dispose() }

$missing = @($moduleFiles.path | Where-Object { -not $matchedModule.Contains($_) })
if ($missing.Count -gt 0) { throw "Archive file set mismatch; missing: $($missing -join ', ')." }

$proof = [ordered]@{
    schemaVersion = 1
    sourceRevision = $sourceRevision
    module = [ordered]@{
        name = 'GraphKit'
        version = $version
        files = @($moduleFiles)
    }
    package = [ordered]@{
        name = $package.Name
        sizeBytes = [int64] $package.Length
        sha256 = Get-LowerFileHash -Path $package.FullName
    }
    testRun = [ordered]@{
        nunit = [ordered]@{
            name = $testResult.Name
            sha256 = Get-LowerFileHash -Path $testResult.FullName
            total = $counts.total
            failures = $counts.failures
            errors = $counts.errors
            skipped = $counts.skipped
            inconclusive = $counts.inconclusive
            notRun = $counts.notRun
        }
    }
}

$outputFullPath = [System.IO.Path]::GetFullPath($OutputPath, (Get-Location).ProviderPath)
$outputDirectory = Split-Path -Parent $outputFullPath
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
    $null = New-Item -ItemType Directory -Path $outputDirectory -Force
}
$temporaryPath = Join-Path $outputDirectory ('.{0}.{1}.tmp' -f (Split-Path $outputFullPath -Leaf), [guid]::NewGuid().ToString('N'))
try {
    $stream = [System.IO.FileStream]::new($temporaryPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    $writer = [System.IO.StreamWriter]::new($stream, [System.Text.UTF8Encoding]::new($false))
    try { $writer.Write(($proof | ConvertTo-Json -Depth 12)) } finally { $writer.Dispose() }
    [System.IO.File]::Move($temporaryPath, $outputFullPath, $true)
}
finally {
    if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Force }
}

[pscustomobject] $proof
