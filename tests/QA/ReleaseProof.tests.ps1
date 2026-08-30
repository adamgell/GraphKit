BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:verifierPath = Join-Path $script:repoRoot 'scripts/Test-GraphKitReleaseProof.ps1'
    $script:generatorPath = Join-Path $script:repoRoot 'scripts/New-GraphKitTestedReleaseProof.ps1'

    function Add-GraphKitFixtureArchiveFile {
        param(
            [Parameter(Mandatory)] [System.IO.Compression.ZipArchive] $Archive,
            [Parameter(Mandatory)] [string] $EntryName,
            [Parameter(Mandatory)] [string] $SourcePath
        )

        $entry = $Archive.CreateEntry($EntryName)
        $entryStream = $entry.Open()
        $sourceStream = [System.IO.File]::OpenRead($SourcePath)
        try {
            $sourceStream.CopyTo($entryStream)
        }
        finally {
            $sourceStream.Dispose()
            $entryStream.Dispose()
        }
    }

    function Add-GraphKitFixtureArchiveText {
        param(
            [Parameter(Mandatory)] [System.IO.Compression.ZipArchive] $Archive,
            [Parameter(Mandatory)] [string] $EntryName,
            [Parameter(Mandatory)] [string] $Content
        )

        $entry = $Archive.CreateEntry($EntryName)
        $stream = $entry.Open()
        $writer = [System.IO.StreamWriter]::new($stream, [System.Text.UTF8Encoding]::new($false))
        try {
            $writer.Write($Content)
            $writer.Flush()
        }
        finally {
            $writer.Dispose()
        }
    }

    function Update-GraphKitFixtureProofPackageHash {
        param([Parameter(Mandatory)] [pscustomobject] $Fixture)

        $proof = Get-Content -LiteralPath $Fixture.ProofPath -Raw | ConvertFrom-Json
        $proof.package.sha256 = (Get-FileHash -LiteralPath $Fixture.PackagePath -Algorithm SHA256).Hash.ToLowerInvariant()
        $proof | ConvertTo-Json -Depth 10 |
            Set-Content -LiteralPath $Fixture.ProofPath -NoNewline -Encoding utf8NoBOM
    }

    function Set-GraphKitFixtureArchiveEntryText {
        param(
            [Parameter(Mandatory)] [pscustomobject] $Fixture,
            [Parameter(Mandatory)] [string] $EntryName,
            [Parameter(Mandatory)] [string] $Content
        )

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::Open($Fixture.PackagePath, [System.IO.Compression.ZipArchiveMode]::Update)
        try {
            $existing = @($archive.Entries | Where-Object FullName -CEQ $EntryName)
            foreach ($entry in $existing) { $entry.Delete() }
            Add-GraphKitFixtureArchiveText -Archive $archive -EntryName $EntryName -Content $Content
        }
        finally {
            $archive.Dispose()
        }
        Update-GraphKitFixtureProofPackageHash -Fixture $Fixture
    }

    function Get-GraphKitFixtureArchiveEntryText {
        param(
            [Parameter(Mandatory)] [pscustomobject] $Fixture,
            [Parameter(Mandatory)] [string] $EntryName
        )

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::OpenRead($Fixture.PackagePath)
        try {
            $entry = @($archive.Entries | Where-Object FullName -CEQ $EntryName)
            if ($entry.Count -ne 1) { throw "Fixture expected one '$EntryName' entry." }
            $reader = [System.IO.StreamReader]::new($entry[0].Open())
            try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
        }
        finally {
            $archive.Dispose()
        }
    }

    function New-GraphKitReleaseProofFixture {
        param(
            [int] $Failures = 0,
            [int] $Errors = 0,
            [int] $Skipped = 0,
            [int] $NotRun = 0,
            [int] $FailedContainers = 0,
            [int] $FailedBlocks = 0,
            [int] $Inconclusive = 0,
            [string] $PesterResult,
            [int] $Passed = -1,
            [bool] $Executed = $true,
            [int] $Total = 825
        )

        $fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('graphkit-release-proof-' + [guid]::NewGuid().ToString('N'))
        $version = '9.9.9'
        $moduleDir = Join-Path $fixtureRoot "output/module/GraphKit/$version"
        $resultsDir = Join-Path $fixtureRoot 'output/testResults'
        $gateDir = Join-Path $fixtureRoot 'tests/QA'
        $scriptsDir = Join-Path $fixtureRoot 'scripts'
        New-Item -ItemType Directory -Path $moduleDir, $resultsDir, $gateDir, $scriptsDir -Force | Out-Null

        Copy-Item -LiteralPath (Join-Path $script:repoRoot 'tests/QA/Assert-GateResult.ps1') `
            -Destination (Join-Path $gateDir 'Assert-GateResult.ps1')
        Copy-Item -LiteralPath $script:verifierPath `
            -Destination (Join-Path $scriptsDir 'Test-GraphKitReleaseProof.ps1')
        Copy-Item -LiteralPath (Join-Path $script:repoRoot 'scripts/Publish-GraphKitPackage.ps1') `
            -Destination (Join-Path $scriptsDir 'Publish-GraphKitPackage.ps1')
        Copy-Item -LiteralPath (Join-Path $script:repoRoot 'scripts/Publish-GraphKitToGallery.ps1') `
            -Destination (Join-Path $scriptsDir 'Publish-GraphKitToGallery.ps1')

        $payloads = [ordered] @{
            'Data/Operations/Probe.List.psd1' = "@{ SchemaVersion = 1; Type = 'Probe'; Operation = 'List' }`n"
            'Formats/GraphKit.Format.ps1xml' = "<Configuration><ViewDefinitions /></Configuration>`n"
            'GraphKit.psd1' = @"
@{
    RootModule = 'GraphKit.psm1'
    ModuleVersion = '$version'
    GUID = '12345678-1234-1234-9234-123456789abc'
    Author = 'Fixture Author'
    CompanyName = 'Fixture Company'
    Copyright = '(c) Fixture Author'
    Description = 'Fixture GraphKit release-proof module package.'
    FunctionsToExport = @('Get-GraphProbe')
    RequiredModules = @(@{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.38.1' })
    PrivateData = @{ PSData = @{
        Tags = @('Fixture', 'Graph')
        LicenseUri = 'https://opensource.org/licenses/MIT'
        ReleaseNotes = 'Fixture release notes.'
    } }
}
"@
            'GraphKit.psm1' = "function Get-GraphProbe { 'fixture' }`n"
            'en-US/about_GraphKit.help.txt' = "TOPIC`n    about_GraphKit`n"
        }

        foreach ($relativePath in $payloads.Keys) {
            $path = Join-Path $moduleDir $relativePath
            New-Item -ItemType Directory -Path (Split-Path $path -Parent) -Force | Out-Null
            Set-Content -LiteralPath $path -Value $payloads[$relativePath] -NoNewline -Encoding utf8NoBOM
        }
        Set-Content -LiteralPath (Join-Path $fixtureRoot 'LICENSE') -Value 'Fixture license.' -NoNewline -Encoding utf8NoBOM

        $packagePath = Join-Path $fixtureRoot "output/GraphKit.$version.nupkg"
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::Open($packagePath, [System.IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($relativePath in $payloads.Keys) {
                Add-GraphKitFixtureArchiveFile -Archive $archive -EntryName $relativePath -SourcePath (Join-Path $moduleDir $relativePath)
            }
            Add-GraphKitFixtureArchiveText -Archive $archive -EntryName 'GraphKit.nuspec' -Content @"
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata><id>GraphKit</id><version>$version</version><authors>Fixture Author</authors><owners>Fixture Author</owners><requireLicenseAcceptance>false</requireLicenseAcceptance><licenseUrl>https://opensource.org/licenses/MIT</licenseUrl><description>Fixture GraphKit release-proof module package.</description><releaseNotes>Fixture release notes.</releaseNotes><copyright>(c) Fixture Author</copyright><tags>Fixture Graph PSModule PSIncludes_Function PSFunction_Get-GraphProbe PSCommand_Get-GraphProbe</tags><dependencies><dependency id="Microsoft.Graph.Authentication" version="2.38.1" /></dependencies></metadata></package>
"@
            Add-GraphKitFixtureArchiveText -Archive $archive -EntryName '_rels/.rels' -Content '<Relationships />'
            Add-GraphKitFixtureArchiveText -Archive $archive -EntryName '[Content_Types].xml' -Content '<Types />'
            Add-GraphKitFixtureArchiveText -Archive $archive -EntryName 'package/services/metadata/core-properties/nuget.psmdcp' -Content '<coreProperties />'
        }
        finally {
            $archive.Dispose()
        }

        $suiteResult = if ($Errors -gt 0) {
            'Error'
        }
        elseif ($Failures -gt 0) {
            'Failure'
        }
        elseif ($Skipped -gt 0) {
            'Ignored'
        }
        else {
            'Success'
        }
        $pesterOutcome = if (-not [string]::IsNullOrWhiteSpace($PesterResult)) {
            $PesterResult
        }
        elseif ($suiteResult -eq 'Success') {
            'Passed'
        }
        else {
            $suiteResult
        }
        $resultSuffix = "GraphKit_v$version.Fixture.xml"
        $nunitPath = Join-Path $resultsDir "NUnitXml_$resultSuffix"
        $containerName = if ($FailedContainers -gt 0) { 'Discovery failure fixture' } else { 'GraphKit' }
        Set-Content -LiteralPath $nunitPath -Encoding utf8NoBOM -Value @"
<?xml version="1.0" encoding="utf-8"?>
<test-results name="GraphKit $version" total="$Total" errors="$Errors" failures="$Failures" not-run="0" inconclusive="0" ignored="0" skipped="$Skipped" invalid="0">
  <test-suite type="TestFixture" name="$containerName" result="$suiteResult" />
</test-results>
"@

        $pesterObjectPath = Join-Path $resultsDir "PesterObject_$resultSuffix"
        $resolvedPassed = if ($Passed -ge 0) {
            $Passed
        }
        else {
            $Total - $Failures - $Skipped - $NotRun - $Inconclusive
        }
        [pscustomobject] [ordered] @{
            Result = $pesterOutcome
            TotalCount = $Total
            PassedCount = $resolvedPassed
            FailedCount = $Failures
            SkippedCount = $Skipped
            NotRunCount = $NotRun
            FailedBlocksCount = $FailedBlocks
            FailedContainersCount = $FailedContainers
            InconclusiveCount = $Inconclusive
            Executed = $Executed
            Containers = @()
        } | Export-Clixml -LiteralPath $pesterObjectPath

        $moduleFiles = @(
            $payloads.Keys |
                Sort-Object |
                ForEach-Object {
                    [pscustomobject] [ordered] @{
                        path = $_
                        sha256 = (Get-FileHash -LiteralPath (Join-Path $moduleDir $_) -Algorithm SHA256).Hash.ToLowerInvariant()
                    }
                }
        )
        $proofPath = Join-Path $resultsDir 'tested-release-proof.json'
        [pscustomobject] [ordered] @{
            schemaVersion = 1
            runId = [guid]::NewGuid().ToString('D')
            module = [pscustomobject] [ordered] @{
                name = 'GraphKit'
                version = $version
                files = $moduleFiles
            }
            package = [pscustomobject] [ordered] @{
                name = Split-Path -Leaf $packagePath
                sha256 = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
            }
            testRun = [pscustomobject] [ordered] @{
                nunit = [pscustomobject] [ordered] @{
                    name = Split-Path -Leaf $nunitPath
                    sha256 = (Get-FileHash -LiteralPath $nunitPath -Algorithm SHA256).Hash.ToLowerInvariant()
                }
                pesterObject = [pscustomobject] [ordered] @{
                    name = Split-Path -Leaf $pesterObjectPath
                    sha256 = (Get-FileHash -LiteralPath $pesterObjectPath -Algorithm SHA256).Hash.ToLowerInvariant()
                }
                policy = [pscustomobject] [ordered] @{
                    minimumTests = 825
                    allowedSkips = 0
                    allowedNotRun = 0
                }
                summary = [pscustomobject] [ordered] @{
                    overallResult = $suiteResult
                    pesterResult = $pesterOutcome
                    executed = $Executed
                    total = $Total
                    passed = $resolvedPassed
                    failures = $Failures
                    errors = $Errors
                    skipped = $Skipped
                    notRun = $NotRun
                    inconclusive = $Inconclusive
                    failedBlocks = $FailedBlocks
                    failedContainers = $FailedContainers
                }
            }
        } | ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath $proofPath -NoNewline -Encoding utf8NoBOM

        [pscustomobject] @{
            Root = $fixtureRoot
            Version = $version
            ModuleDir = $moduleDir
            PackagePath = $packagePath
            ProofPath = $proofPath
            NUnitPath = $nunitPath
            PesterObjectPath = $pesterObjectPath
        }
    }

    function Invoke-GraphKitReleaseProofVerifier {
        param([Parameter(Mandatory)] [pscustomobject] $Fixture)

        $output = & pwsh -NoLogo -NoProfile -File $script:verifierPath `
            -PackagePath $Fixture.PackagePath `
            -ProofPath $Fixture.ProofPath `
            -RepositoryRoot $Fixture.Root 2>&1 | Out-String
        $output = $output -replace '\r?\n\s*\|\s*', ' '
        $output = ($output -replace '\s+', ' ').Trim()
        [pscustomobject] @{
            ExitCode = $LASTEXITCODE
            Output = $output
        }
    }

    function Invoke-GraphKitReleaseProofGenerator {
        param(
            [Parameter(Mandatory)] [pscustomobject] $Fixture,
            [Parameter(Mandatory)] [ValidateSet('Capture', 'Finalize')] [string] $Stage
        )

        $output = & pwsh -NoLogo -NoProfile -File $script:generatorPath `
            -Stage $Stage `
            -RepositoryRoot $Fixture.Root 2>&1 | Out-String
        $output = $output -replace '\r?\n\s*\|\s*', ' '
        $output = ($output -replace '\s+', ' ').Trim()
        [pscustomobject] @{
            ExitCode = $LASTEXITCODE
            Output = $output
        }
    }

    function Invoke-GraphKitFixturePublisher {
        param(
            [Parameter(Mandatory)] [pscustomobject] $Fixture,
            [Parameter(Mandatory)] [ValidateSet('PrivateChannel', 'PSGallery')] [string] $Publisher
        )

        $scriptPath = if ($Publisher -eq 'PrivateChannel') {
            Join-Path $Fixture.Root 'scripts/Publish-GraphKitPackage.ps1'
        }
        else {
            Join-Path $Fixture.Root 'scripts/Publish-GraphKitToGallery.ps1'
        }
        $arguments = if ($Publisher -eq 'PrivateChannel') {
            @(
                '-PackagePath', $Fixture.PackagePath,
                '-Channel', 'FileSystem',
                '-Destination', (Join-Path $Fixture.Root 'channel'),
                '-TestResultPath', $Fixture.NUnitPath,
                '-PinPath', (Join-Path $Fixture.Root 'graphkit.pin.json')
            )
        }
        else {
            @('-PackagePath', $Fixture.PackagePath, '-WhatIfOnly')
        }

        $output = & pwsh -NoLogo -NoProfile -File $scriptPath @arguments 2>&1 | Out-String
        $output = $output -replace '\r?\n\s*\|\s*', ' '
        $output = ($output -replace '\s+', ' ').Trim()
        [pscustomobject] @{
            ExitCode = $LASTEXITCODE
            Output = $output
        }
    }

    function Install-GraphKitFixtureMutatingVerifier {
        param([Parameter(Mandatory)] [pscustomobject] $Fixture)

        $coreVerifier = Join-Path $Fixture.Root 'scripts/Test-GraphKitReleaseProof.Core.ps1'
        Move-Item -LiteralPath (Join-Path $Fixture.Root 'scripts/Test-GraphKitReleaseProof.ps1') -Destination $coreVerifier
        Set-Content -LiteralPath (Join-Path $Fixture.Root 'scripts/Test-GraphKitReleaseProof.ps1') -Encoding utf8NoBOM -Value @'
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $PackagePath,
    [string] $ProofPath,
    [string] $TestResultPath,
    [string] $RepositoryRoot,
    [string] $VerifiedPackageCopyPath,
    [string] $VerifiedProofCopyPath
)
$parameters = @{
    PackagePath = $PackagePath
    ProofPath = $ProofPath
    TestResultPath = $TestResultPath
    RepositoryRoot = $RepositoryRoot
}
if (-not [string]::IsNullOrWhiteSpace($VerifiedPackageCopyPath)) {
    $parameters.VerifiedPackageCopyPath = $VerifiedPackageCopyPath
}
if (-not [string]::IsNullOrWhiteSpace($VerifiedProofCopyPath)) {
    $parameters.VerifiedProofCopyPath = $VerifiedProofCopyPath
}
$verified = & (Join-Path $PSScriptRoot 'Test-GraphKitReleaseProof.Core.ps1') @parameters
$effectiveProofPath = if ([string]::IsNullOrWhiteSpace($ProofPath)) {
    Join-Path $RepositoryRoot 'output/testResults/tested-release-proof.json'
}
else {
    $ProofPath
}
[System.IO.File]::WriteAllText($PackagePath, 'replacement package after verifier return')
[System.IO.File]::WriteAllText($effectiveProofPath, '{"replacementProof":true}')
$mutableManifestPath = Join-Path $RepositoryRoot "output/module/GraphKit/$($verified.Version)/GraphKit.psd1"
$mutableManifest = [System.IO.File]::ReadAllText($mutableManifestPath)
$mutableManifest = $mutableManifest.Replace(
    "GUID = '12345678-1234-1234-9234-123456789abc'",
    "GUID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'"
)
[System.IO.File]::WriteAllText($mutableManifestPath, $mutableManifest)
$verified
'@
    }

    function Invoke-GraphKitFixtureGalleryPreflight {
        param([Parameter(Mandatory)] [pscustomobject] $Fixture)

        $bootstrapPath = Join-Path $Fixture.Root 'Invoke-FixtureGalleryPreflight.ps1'
        Set-Content -LiteralPath $bootstrapPath -Encoding utf8NoBOM -Value @'
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $PublisherPath,
    [Parameter(Mandatory)] [string] $PackagePath,
    [Parameter(Mandatory)] [string] $ProofPath,
    [Parameter(Mandatory)] [string] $TestResultPath,
    [Parameter(Mandatory)] [string] $MutableManifestPath
)
function Find-PSResource {
    [CmdletBinding()]
    param([string] $Name, [string] $Repository)
    return $null
}
function Test-ModuleManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path)
    $resolved = (Resolve-Path -LiteralPath $Path).ProviderPath
    $mutable = (Resolve-Path -LiteralPath $MutableManifestPath).ProviderPath
    if ([string]::Equals($resolved, $mutable, [System.StringComparison]::Ordinal)) {
        throw 'Gallery reopened the mutable built manifest after proof verification.'
    }
    return Import-PowerShellDataFile -LiteralPath $resolved
}
& $PublisherPath `
    -PackagePath $PackagePath `
    -ProofPath $ProofPath `
    -TestResultPath $TestResultPath `
    -WhatIfOnly
'@

        $output = & pwsh -NoLogo -NoProfile -File $bootstrapPath `
            -PublisherPath (Join-Path $Fixture.Root 'scripts/Publish-GraphKitToGallery.ps1') `
            -PackagePath $Fixture.PackagePath `
            -ProofPath $Fixture.ProofPath `
            -TestResultPath $Fixture.NUnitPath `
            -MutableManifestPath (Join-Path $Fixture.ModuleDir 'GraphKit.psd1') 2>&1 | Out-String
        $output = $output -replace '\r?\n\s*\|\s*', ' '
        $output = ($output -replace '\s+', ' ').Trim()
        [pscustomobject] @{
            ExitCode = $LASTEXITCODE
            Output = $output
        }
    }
}

Describe 'Canonical tested release proof' {
    AfterEach {
        if ($script:fixture) {
            Remove-Item -LiteralPath $script:fixture.Root -Recurse -Force -ErrorAction SilentlyContinue
            $script:fixture = $null
        }
    }

    It 'accepts one proof binding the module, package, full result, and every shipped file' {
        $script:fixture = New-GraphKitReleaseProofFixture

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Output | Should -Match 'VERIFIED TESTED RELEASE'
        $result.Output | Should -Match '5 shipped file'
    }

    It 'rejects changed <Kind> bytes by their shipped relative path' -ForEach @(
        @{ Kind = 'descriptor'; RelativePath = 'Data/Operations/Probe.List.psd1' }
        @{ Kind = 'manifest'; RelativePath = 'GraphKit.psd1' }
        @{ Kind = 'format'; RelativePath = 'Formats/GraphKit.Format.ps1xml' }
        @{ Kind = 'help'; RelativePath = 'en-US/about_GraphKit.help.txt' }
    ) {
        $script:fixture = New-GraphKitReleaseProofFixture
        Add-Content -LiteralPath (Join-Path $script:fixture.ModuleDir $RelativePath) -Value 'changed after test'

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match ([regex]::Escape($RelativePath))
        $result.Output | Should -Match 'does not match the tested release proof'
    }

    It 'rejects a shipped file missing after the test run' {
        $script:fixture = New-GraphKitReleaseProofFixture
        Remove-Item -LiteralPath (Join-Path $script:fixture.ModuleDir 'GraphKit.psm1') -Force

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'GraphKit\.psm1'
        $result.Output | Should -Match 'file set differs'
    }

    It 'rejects an extra untested shipped file' {
        $script:fixture = New-GraphKitReleaseProofFixture
        Set-Content -LiteralPath (Join-Path $script:fixture.ModuleDir 'untested.txt') -Value 'extra' -NoNewline

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'untested\.txt'
        $result.Output | Should -Match 'file set differs'
    }

    It 'rejects <Kind> bytes changed only inside the package' -ForEach @(
        @{ Kind = 'descriptor'; RelativePath = 'Data/Operations/Probe.List.psd1' }
        @{ Kind = 'manifest'; RelativePath = 'GraphKit.psd1' }
        @{ Kind = 'format'; RelativePath = 'Formats/GraphKit.Format.ps1xml' }
        @{ Kind = 'help'; RelativePath = 'en-US/about_GraphKit.help.txt' }
    ) {
        $script:fixture = New-GraphKitReleaseProofFixture
        $changedContent = (Get-Content -LiteralPath (Join-Path $script:fixture.ModuleDir $RelativePath) -Raw) + "`nchanged only in package"
        Set-GraphKitFixtureArchiveEntryText -Fixture $script:fixture -EntryName $RelativePath -Content $changedContent

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match ([regex]::Escape($RelativePath))
        $result.Output | Should -Match 'does not match the tested release proof'
    }

    It 'rejects a shipped file missing only from the package' {
        $script:fixture = New-GraphKitReleaseProofFixture
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::Open($script:fixture.PackagePath, [System.IO.Compression.ZipArchiveMode]::Update)
        try {
            ($archive.GetEntry('GraphKit.psm1')).Delete()
        }
        finally {
            $archive.Dispose()
        }
        Update-GraphKitFixtureProofPackageHash -Fixture $script:fixture

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'missing:GraphKit\.psm1'
    }

    It 'rejects an extra file present only in the package' {
        $script:fixture = New-GraphKitReleaseProofFixture
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::Open($script:fixture.PackagePath, [System.IO.Compression.ZipArchiveMode]::Update)
        try {
            Add-GraphKitFixtureArchiveText -Archive $archive -EntryName 'extra.ps1' -Content 'untested package code'
        }
        finally {
            $archive.Dispose()
        }
        Update-GraphKitFixtureProofPackageHash -Fixture $script:fixture

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'extra:extra\.ps1'
    }

    It 'rejects a duplicate package entry path' {
        $script:fixture = New-GraphKitReleaseProofFixture
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::Open($script:fixture.PackagePath, [System.IO.Compression.ZipArchiveMode]::Update)
        try {
            Add-GraphKitFixtureArchiveText -Archive $archive -EntryName 'GraphKit.psm1' -Content 'duplicate payload'
        }
        finally {
            $archive.Dispose()
        }
        Update-GraphKitFixtureProofPackageHash -Fixture $script:fixture

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'duplicate entry path'
    }

    It 'rejects unsafe package path <EntryName>' -ForEach @(
        @{ EntryName = '../outside/' }
        @{ EntryName = '/absolute.ps1' }
        @{ EntryName = 'C:/absolute.ps1' }
        @{ EntryName = 'Data\\evil.ps1' }
        @{ EntryName = 'Data/../evil.ps1' }
        @{ EntryName = 'package/services/metadata/core-properties/../../../../evil.ps1' }
    ) {
        $script:fixture = New-GraphKitReleaseProofFixture
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::Open($script:fixture.PackagePath, [System.IO.Compression.ZipArchiveMode]::Update)
        try {
            Add-GraphKitFixtureArchiveText -Archive $archive -EntryName $EntryName -Content 'unsafe'
        }
        finally {
            $archive.Dispose()
        }
        Update-GraphKitFixtureProofPackageHash -Fixture $script:fixture

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'unsafe package entry path'
    }

    It 'rejects a case-colliding proof file path' {
        $script:fixture = New-GraphKitReleaseProofFixture
        $proof = Get-Content -LiteralPath $script:fixture.ProofPath -Raw | ConvertFrom-Json
        $proof.module.files += [pscustomobject] @{
            path = 'graphkit.psm1'
            sha256 = ($proof.module.files | Where-Object path -CEQ 'GraphKit.psm1').sha256
        }
        $proof | ConvertTo-Json -Depth 10 |
            Set-Content -LiteralPath $script:fixture.ProofPath -NoNewline -Encoding utf8NoBOM

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'case-colliding|duplicate module-file'
    }

    It 'rejects nuspec <Field> drift' -ForEach @(
        @{ Field = 'id'; Find = '<id>GraphKit</id>'; Replace = '<id>OtherModule</id>' }
        @{ Field = 'version'; Find = '<version>9.9.9</version>'; Replace = '<version>9.9.8</version>' }
        @{ Field = 'authors'; Find = '<authors>Fixture Author</authors>'; Replace = '<authors>Other Author</authors>' }
        @{ Field = 'description'; Find = '<description>Fixture GraphKit release-proof module package.</description>'; Replace = '<description>Different description.</description>' }
        @{ Field = 'license'; Find = '<licenseUrl>https://opensource.org/licenses/MIT</licenseUrl>'; Replace = '<licenseUrl>https://example.invalid/license</licenseUrl>' }
        @{ Field = 'tags'; Find = '<tags>Fixture Graph PSModule PSIncludes_Function PSFunction_Get-GraphProbe PSCommand_Get-GraphProbe</tags>'; Replace = '<tags>Different</tags>' }
        @{ Field = 'release notes'; Find = '<releaseNotes>Fixture release notes.</releaseNotes>'; Replace = '<releaseNotes>Different notes.</releaseNotes>' }
    ) {
        $script:fixture = New-GraphKitReleaseProofFixture
        $nuspec = Get-GraphKitFixtureArchiveEntryText -Fixture $script:fixture -EntryName 'GraphKit.nuspec'
        Set-GraphKitFixtureArchiveEntryText -Fixture $script:fixture -EntryName 'GraphKit.nuspec' -Content ($nuspec.Replace($Find, $Replace))

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'package metadata|nuspec'
    }

    It 'rejects an injected nuspec dependency' {
        $script:fixture = New-GraphKitReleaseProofFixture
        $nuspec = Get-GraphKitFixtureArchiveEntryText -Fixture $script:fixture -EntryName 'GraphKit.nuspec'
        $changed = $nuspec.Replace('</dependencies>', '<dependency id="Injected.Dependency" version="1.0.0" /></dependencies>')
        Set-GraphKitFixtureArchiveEntryText -Fixture $script:fixture -EntryName 'GraphKit.nuspec' -Content $changed

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'dependencies.*built manifest'
    }

    It 'rejects an injected nuspec metadata field' {
        $script:fixture = New-GraphKitReleaseProofFixture
        $nuspec = Get-GraphKitFixtureArchiveEntryText -Fixture $script:fixture -EntryName 'GraphKit.nuspec'
        $changed = $nuspec.Replace('<dependencies>', '<projectUrl>https://example.invalid/project</projectUrl><dependencies>')
        Set-GraphKitFixtureArchiveEntryText -Fixture $script:fixture -EntryName 'GraphKit.nuspec' -Content $changed

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'unsupported nuspec metadata'
    }

    It 'rejects a proof that binds a failing result' {
        $script:fixture = New-GraphKitReleaseProofFixture -Failures 1

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match '1 test\(s\) failed'
    }

    It 'rejects a proof that binds a skipped result' {
        $script:fixture = New-GraphKitReleaseProofFixture -Skipped 1

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match '1 test\(s\) skipped'
    }

    It 'rejects a proof that binds a NotRun block' {
        $script:fixture = New-GraphKitReleaseProofFixture -NotRun 1

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match '1 NotRun'
    }

    It 'rejects a proof that binds a discovery failure' {
        $script:fixture = New-GraphKitReleaseProofFixture -FailedContainers 1

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'failed container\(s\) / discovery error\(s\)'
    }

    It 'rejects Pester-only <Case> while NUnit remains successful' -ForEach @(
        @{ Case = 'non-passing result'; Parameters = @{ PesterResult = 'Failed' }; Expected = 'Pester result.*Passed' }
        @{ Case = 'failed block'; Parameters = @{ FailedBlocks = 1 }; Expected = '1 failed block' }
        @{ Case = 'inconclusive count'; Parameters = @{ Inconclusive = 1 }; Expected = '1 inconclusive' }
    ) {
        $script:fixture = New-GraphKitReleaseProofFixture @Parameters

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match $Expected
    }

    It 'rejects a Pester result whose passed count cannot account for its total' {
        $script:fixture = New-GraphKitReleaseProofFixture -Passed 0

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'Pester count arithmetic'
    }

    It 'rejects a Pester result that was not executed' {
        $script:fixture = New-GraphKitReleaseProofFixture -Executed:$false

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'not executed'
    }

    It 'rejects same-version package payload drift after the proof was recorded' {
        $script:fixture = New-GraphKitReleaseProofFixture
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::Open($script:fixture.PackagePath, [System.IO.Compression.ZipArchiveMode]::Update)
        try {
            Add-GraphKitFixtureArchiveText -Archive $archive -EntryName 'Data/Operations/Drift.List.psd1' -Content '@{ drift = $true }'
        }
        finally {
            $archive.Dispose()
        }

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'package archive changed after the passing test run'
    }
}

Describe 'Test workflow release-proof generation' {
    AfterEach {
        if ($script:fixture) {
            Remove-Item -LiteralPath $script:fixture.Root -Recurse -Force -ErrorAction SilentlyContinue
            $script:fixture = $null
        }
    }

    It 'capture invalidates old proof and result files before recording the candidate' {
        $script:fixture = New-GraphKitReleaseProofFixture

        $result = Invoke-GraphKitReleaseProofGenerator -Fixture $script:fixture -Stage Capture

        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match 'CAPTURED RELEASE CANDIDATE'
        Test-Path -LiteralPath $script:fixture.ProofPath | Should -BeFalse
        Test-Path -LiteralPath $script:fixture.NUnitPath | Should -BeFalse
        Test-Path -LiteralPath $script:fixture.PesterObjectPath | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $script:fixture.Root 'output/testResults/candidate-release-input.json') | Should -BeTrue
    }

    It 'finalize emits the one proof only after the captured candidate and result pair pass' {
        $script:fixture = New-GraphKitReleaseProofFixture
        $nunitBytes = [System.IO.File]::ReadAllBytes($script:fixture.NUnitPath)
        $pesterObjectBytes = [System.IO.File]::ReadAllBytes($script:fixture.PesterObjectPath)
        (Invoke-GraphKitReleaseProofGenerator -Fixture $script:fixture -Stage Capture).ExitCode | Should -Be 0
        [System.IO.File]::WriteAllBytes($script:fixture.NUnitPath, $nunitBytes)
        [System.IO.File]::WriteAllBytes($script:fixture.PesterObjectPath, $pesterObjectBytes)

        $result = Invoke-GraphKitReleaseProofGenerator -Fixture $script:fixture -Stage Finalize

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Output | Should -Match 'RECORDED TESTED RELEASE PROOF'
        $proof = Get-Content -LiteralPath $script:fixture.ProofPath -Raw | ConvertFrom-Json
        $proof.module.name | Should -Be 'GraphKit'
        $proof.module.version | Should -Be '9.9.9'
        @($proof.module.files).Count | Should -Be 5
        $proof.testRun.summary.total | Should -Be 825
        $proof.testRun.summary.notRun | Should -Be 0
        Test-Path -LiteralPath (Join-Path $script:fixture.Root 'output/testResults/candidate-release-input.json') | Should -BeFalse
    }

    It 'finalize refuses module drift after capture and leaves no tested proof' {
        $script:fixture = New-GraphKitReleaseProofFixture
        $nunitBytes = [System.IO.File]::ReadAllBytes($script:fixture.NUnitPath)
        $pesterObjectBytes = [System.IO.File]::ReadAllBytes($script:fixture.PesterObjectPath)
        (Invoke-GraphKitReleaseProofGenerator -Fixture $script:fixture -Stage Capture).ExitCode | Should -Be 0
        [System.IO.File]::WriteAllBytes($script:fixture.NUnitPath, $nunitBytes)
        [System.IO.File]::WriteAllBytes($script:fixture.PesterObjectPath, $pesterObjectBytes)
        Add-Content -LiteralPath (Join-Path $script:fixture.ModuleDir 'GraphKit.psm1') -Value '# drift'

        $result = Invoke-GraphKitReleaseProofGenerator -Fixture $script:fixture -Stage Finalize

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'module candidate changed after capture'
        Test-Path -LiteralPath $script:fixture.ProofPath | Should -BeFalse
    }

    It 'finalize refuses a NotRun result and leaves no tested proof' {
        $script:fixture = New-GraphKitReleaseProofFixture -NotRun 1
        $nunitBytes = [System.IO.File]::ReadAllBytes($script:fixture.NUnitPath)
        $pesterObjectBytes = [System.IO.File]::ReadAllBytes($script:fixture.PesterObjectPath)
        (Invoke-GraphKitReleaseProofGenerator -Fixture $script:fixture -Stage Capture).ExitCode | Should -Be 0
        [System.IO.File]::WriteAllBytes($script:fixture.NUnitPath, $nunitBytes)
        [System.IO.File]::WriteAllBytes($script:fixture.PesterObjectPath, $pesterObjectBytes)

        $result = Invoke-GraphKitReleaseProofGenerator -Fixture $script:fixture -Stage Finalize

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match '1 NotRun'
        Test-Path -LiteralPath $script:fixture.ProofPath | Should -BeFalse
    }

    It 'wires pack before test, Capture first, Record last, and canonical CI verification' {
        $buildYaml = Get-Content -LiteralPath (Join-Path $script:repoRoot 'build.yaml') -Raw
        $defaultWorkflow = [regex]::Match($buildYaml, '(?ms)^  ''\.'':.*?(?=^  build:)').Value
        $testWorkflow = [regex]::Match($buildYaml, '(?ms)^  test:.*?(?=^  [A-Za-z][A-Za-z0-9_-]*:)').Value

        $defaultWorkflow | Should -Match '(?s)-\s+pack.*-\s+test'
        @([regex]::Matches($testWorkflow, '(?m)^\s*-\s+Capture_Tested_Release_Proof_Candidate\s*$')).Count | Should -Be 1
        @([regex]::Matches($testWorkflow, '(?m)^\s*-\s+Pester_Tests_Stop_On_Fail\s*$')).Count | Should -Be 1
        @([regex]::Matches($testWorkflow, '(?m)^\s*-\s+Record_Tested_Release_Proof\s*$')).Count | Should -Be 1
        $testWorkflow.IndexOf('Capture_Tested_Release_Proof_Candidate') | Should -BeLessThan $testWorkflow.IndexOf('Pester_Tests_Stop_On_Fail')
        $testWorkflow.IndexOf('Pester_Tests_Stop_On_Fail') | Should -BeLessThan $testWorkflow.IndexOf('Record_Tested_Release_Proof')
        $testTaskLines = @(
            $testWorkflow -split '\r?\n' |
                Where-Object { $_ -match '^\s*-\s+[A-Za-z]' }
        )
        $testTaskLines[-1] | Should -Match 'Record_Tested_Release_Proof\s*$'

        $ci = Get-Content -LiteralPath (Join-Path $script:repoRoot '.github/workflows/ci.yml') -Raw
        $ci | Should -Match 'tested-release-proof\.json'
        $ci | Should -Match 'Test-GraphKitReleaseProof\.ps1'
    }
}

Describe 'Both publisher paths consume the canonical proof verifier' {
    AfterEach {
        if ($script:fixture) {
            Remove-Item -LiteralPath $script:fixture.Root -Recurse -Force -ErrorAction SilentlyContinue
            $script:fixture = $null
        }
    }

    It '<Publisher> refuses the canonical descriptor-drift verdict before publication' -ForEach @(
        @{ Publisher = 'PrivateChannel' }
        @{ Publisher = 'PSGallery' }
    ) {
        $script:fixture = New-GraphKitReleaseProofFixture
        Add-Content -LiteralPath (Join-Path $script:fixture.ModuleDir 'Data/Operations/Probe.List.psd1') -Value 'changed after test'

        $result = Invoke-GraphKitFixturePublisher -Fixture $script:fixture -Publisher $Publisher

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'Data/Operations/Probe\.List\.psd1'
        $result.Output | Should -Match 'does not match the tested release proof'
    }

    It 'private publication uses verifier-owned snapshots and preserves durable proof evidence' {
        $script:fixture = New-GraphKitReleaseProofFixture
        Install-GraphKitFixtureMutatingVerifier -Fixture $script:fixture

        $proofHashBefore = (Get-FileHash -LiteralPath $script:fixture.ProofPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $proofBefore = Get-Content -LiteralPath $script:fixture.ProofPath -Raw | ConvertFrom-Json
        $result = Invoke-GraphKitFixturePublisher -Fixture $script:fixture -Publisher PrivateChannel

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $publishedPackage = Join-Path $script:fixture.Root 'channel/GraphKit.9.9.9.nupkg'
        (Get-FileHash -LiteralPath $publishedPackage -Algorithm SHA256).Hash.ToLowerInvariant() |
            Should -Be $proofBefore.package.sha256

        $pin = Get-Content -LiteralPath (Join-Path $script:fixture.Root 'graphkit.pin.json') -Raw | ConvertFrom-Json
        $pin.sha256.ToLowerInvariant() | Should -Be $proofBefore.package.sha256
        $pin.testProofRunId | Should -Be $proofBefore.runId
        Test-Path -LiteralPath $pin.testProof -PathType Leaf | Should -BeTrue
        $pin.testProof | Should -Not -Be $script:fixture.ProofPath
        (Get-FileHash -LiteralPath $pin.testProof -Algorithm SHA256).Hash.ToLowerInvariant() |
            Should -Be $pin.testProofSha256.ToLowerInvariant()
        $pin.testProofSha256.ToLowerInvariant() | Should -Be $proofHashBefore
        (Get-Content -LiteralPath $pin.testProof -Raw | ConvertFrom-Json).runId | Should -Be $proofBefore.runId
        (Split-Path $pin.testProof -Leaf) | Should -Match ([regex]::Escape($pin.testProofSha256.ToLowerInvariant()))
    }

    It 'gallery preflight uses verifier-owned package and manifest snapshots after original bytes mutate' {
        $script:fixture = New-GraphKitReleaseProofFixture
        Install-GraphKitFixtureMutatingVerifier -Fixture $script:fixture

        $result = Invoke-GraphKitFixtureGalleryPreflight -Fixture $script:fixture

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Output | Should -Match 'PRE-FLIGHT PASSED'
        (Get-Content -LiteralPath $script:fixture.PackagePath -Raw) | Should -Be 'replacement package after verifier return'
        (Get-Content -LiteralPath $script:fixture.ProofPath -Raw) | Should -Be '{"replacementProof":true}'
    }

    It 'both publisher scripts switch to verifier-owned package snapshots' {
        foreach ($relativePath in @('scripts/Publish-GraphKitPackage.ps1', 'scripts/Publish-GraphKitToGallery.ps1')) {
            $publisher = Get-Content -LiteralPath (Join-Path $script:repoRoot $relativePath) -Raw
            $publisher | Should -Match 'VerifiedPackageCopyPath' -Because $relativePath
            $publisher | Should -Match 'VerifiedProofCopyPath' -Because $relativePath
            $publisher | Should -Match 'VerifiedPackagePath' -Because $relativePath
        }
        $privatePublisher = Get-Content -LiteralPath (Join-Path $script:repoRoot 'scripts/Publish-GraphKitPackage.ps1') -Raw
        $privatePublisher | Should -Not -Match '--clobber:'
        $privatePublisher | Should -Match '\$uploadArguments \+= ''--clobber'''
    }
}
