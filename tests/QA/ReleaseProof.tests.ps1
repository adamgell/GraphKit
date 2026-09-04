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

    function Add-GraphKitFixturePayloadBytes {
        param(
            [Parameter(Mandatory)] [pscustomobject] $Fixture,
            [Parameter(Mandatory)] [string] $EntryName,
            [Parameter(Mandatory)] [byte[]] $Bytes
        )

        $payloadPath = Join-Path $Fixture.ModuleDir $EntryName
        New-Item -ItemType Directory -Path (Split-Path $payloadPath -Parent) -Force | Out-Null
        [System.IO.File]::WriteAllBytes($payloadPath, $Bytes)

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::Open($Fixture.PackagePath, [System.IO.Compression.ZipArchiveMode]::Update)
        try {
            if (@($archive.Entries | Where-Object FullName -CEQ $EntryName).Count -ne 0) {
                throw "Fixture payload '$EntryName' already exists."
            }
            Add-GraphKitFixtureArchiveFile -Archive $archive -EntryName $EntryName -SourcePath $payloadPath
        }
        finally {
            $archive.Dispose()
        }

        $proof = Get-Content -LiteralPath $Fixture.ProofPath -Raw | ConvertFrom-Json
        $newRecord = [pscustomobject] [ordered] @{
            path = $EntryName
            sha256 = (Get-FileHash -LiteralPath $payloadPath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        $proof.module.files = @(@($proof.module.files) + $newRecord | Sort-Object path)
        $proof.package.sha256 = (Get-FileHash -LiteralPath $Fixture.PackagePath -Algorithm SHA256).Hash.ToLowerInvariant()
        $proof | ConvertTo-Json -Depth 10 |
            Set-Content -LiteralPath $Fixture.ProofPath -NoNewline -Encoding utf8NoBOM
    }

    function Add-GraphKitFixturePayloadText {
        param(
            [Parameter(Mandatory)] [pscustomobject] $Fixture,
            [Parameter(Mandatory)] [string] $EntryName,
            [Parameter(Mandatory)] [string] $Content
        )

        Add-GraphKitFixturePayloadBytes -Fixture $Fixture -EntryName $EntryName `
            -Bytes ([System.Text.UTF8Encoding]::new($false).GetBytes($Content))
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
            [switch] $ForGenerator,
            [switch] $IncludeGraphKitAuth,
            [string] $BaseVersion = '0.4.0',
            [switch] $DirtySource,
            [int] $Total = 1452
        )

        $fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('graphkit-release-proof-' + [guid]::NewGuid().ToString('N'))
        $baseVersion = $BaseVersion
        $revision = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        $version = "$baseVersion-r8.g$($revision.Substring(0, 12))"
        $sourceStateHash = if ($DirtySource) { ('b' * 64) -join '' } else { $null }
        if ($DirtySource) { $version += ".d$($sourceStateHash.Substring(0, 12))" }
        $moduleDir = Join-Path $fixtureRoot "output/module/GraphKit/$baseVersion"
        $resultsDir = Join-Path $fixtureRoot 'output/testResults'
        $gateDir = Join-Path $fixtureRoot 'tests/QA'
        $scriptsDir = Join-Path $fixtureRoot 'scripts'
        $privateScriptsDir = Join-Path $scriptsDir 'private'
        $buildDir = Join-Path $fixtureRoot '.build'
        New-Item -ItemType Directory -Path $moduleDir, $resultsDir, $gateDir, $scriptsDir, $privateScriptsDir, $buildDir -Force | Out-Null

        Copy-Item -LiteralPath (Join-Path $script:repoRoot 'tests/QA/Assert-GateResult.ps1') `
            -Destination (Join-Path $gateDir 'Assert-GateResult.ps1')
        Copy-Item -LiteralPath $script:verifierPath `
            -Destination (Join-Path $scriptsDir 'Test-GraphKitReleaseProof.ps1')
        Copy-Item -LiteralPath $script:generatorPath `
            -Destination (Join-Path $scriptsDir 'New-GraphKitTestedReleaseProof.ps1')
        Copy-Item -LiteralPath (Join-Path $script:repoRoot 'scripts/Publish-GraphKitPackage.ps1') `
            -Destination (Join-Path $scriptsDir 'Publish-GraphKitPackage.ps1')
        Copy-Item -LiteralPath (Join-Path $script:repoRoot 'scripts/Publish-GraphKitToGallery.ps1') `
            -Destination (Join-Path $scriptsDir 'Publish-GraphKitToGallery.ps1')
        Copy-Item -LiteralPath (Join-Path $script:repoRoot 'scripts/private/Test-GraphKitPackagePrivacy.ps1') `
            -Destination (Join-Path $privateScriptsDir 'Test-GraphKitPackagePrivacy.ps1')
        if ($IncludeGraphKitAuth) {
            Copy-Item -LiteralPath (Join-Path $script:repoRoot '.build/GraphKitAuth.tasks.ps1') `
                -Destination (Join-Path $buildDir 'GraphKitAuth.tasks.ps1')
            Copy-Item -LiteralPath (Join-Path $script:repoRoot 'scripts/private/GraphKit.AuthStageCapture.cs') `
                -Destination (Join-Path $privateScriptsDir 'GraphKit.AuthStageCapture.cs')
        }

        if ($ForGenerator) {
            Copy-Item -LiteralPath (Join-Path $script:repoRoot 'scripts/Get-GraphKitTrainVersion.ps1') `
                -Destination (Join-Path $scriptsDir 'Get-GraphKitTrainVersion.ps1')
            Copy-Item -LiteralPath (Join-Path $script:repoRoot 'scripts/private/GraphKit.SourceCapture.cs') `
                -Destination (Join-Path $privateScriptsDir 'GraphKit.SourceCapture.cs')
            Set-Content -LiteralPath (Join-Path $fixtureRoot '.gitignore') -Value "output/`nLICENSE`n" -NoNewline -Encoding utf8NoBOM
            & git -C $fixtureRoot init --quiet
            & git -C $fixtureRoot add .gitignore scripts tests
            & git -C $fixtureRoot -c user.name='GraphKit Fixture' -c user.email='fixture@example.invalid' commit --quiet -m 'fixture source'
            $revision = (& git -C $fixtureRoot rev-parse HEAD).Trim().ToLowerInvariant()
            $version = (& (Join-Path $scriptsDir 'Get-GraphKitTrainVersion.ps1') -RepositoryRoot $fixtureRoot).Trim()
        }
        $prerelease = $version.Substring($baseVersion.Length + 1)
        $requiredAssembliesLine = if ($IncludeGraphKitAuth) {
            "    RequiredAssemblies = @('Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll')`n"
        }
        else { '' }

        $payloads = [ordered] @{
            'Data/Operations/Probe.List.psd1' = "@{ SchemaVersion = 1; Type = 'Probe'; Operation = 'List' }`n"
            'Formats/GraphKit.Format.ps1xml' = "<Configuration><ViewDefinitions /></Configuration>`n"
            'GraphKit.psd1' = @"
@{
    RootModule = 'GraphKit.psm1'
    ModuleVersion = '$baseVersion'
    GUID = '12345678-1234-1234-9234-123456789abc'
    Author = 'Fixture Author'
    CompanyName = 'Fixture Company'
    Copyright = '(c) Fixture Author'
    Description = 'Fixture GraphKit release-proof module package.'
    FunctionsToExport = @('Get-GraphProbe')
$requiredAssembliesLine    RequiredModules = @(@{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.38.1' })
    PrivateData = @{ PSData = @{
        Tags = @('Fixture', 'Graph')
        LicenseUri = 'https://opensource.org/licenses/MIT'
        ReleaseNotes = 'Fixture release notes.'
        Prerelease = '$prerelease'
    } }
}
"@
            'GraphKit.psm1' = "function Get-GraphProbe { 'fixture' }`n"
            'en-US/about_GraphKit.help.txt' = "TOPIC`n    about_GraphKit`n"
        }
        if ($IncludeGraphKitAuth) {
            $payloads['Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll'] = 'fixture contracts bytes'
            $payloads['Assemblies/GraphKit.Auth/GraphKit.Auth.dll'] = 'fixture provider bytes'
            $payloads['Assemblies/GraphKit.Auth/GraphKit.Auth.deps.json'] = '{"runtimeTarget":{"name":"fixture"}}'
            $payloads['Assemblies/GraphKit.Auth/Microsoft.Identity.Client.dll'] = 'fixture msal bytes'
            $payloads['Assemblies/GraphKit.Auth/Microsoft.IdentityModel.Abstractions.dll'] = 'fixture abstractions bytes'
        }

        foreach ($relativePath in $payloads.Keys) {
            $path = Join-Path $moduleDir $relativePath
            New-Item -ItemType Directory -Path (Split-Path $path -Parent) -Force | Out-Null
            Set-Content -LiteralPath $path -Value $payloads[$relativePath] -NoNewline -Encoding utf8NoBOM
        }
        Set-Content -LiteralPath (Join-Path $fixtureRoot 'LICENSE') -Value 'Fixture license.' -NoNewline -Encoding utf8NoBOM
        if ($IncludeGraphKitAuth) {
            . (Join-Path $buildDir 'GraphKitAuth.tasks.ps1') -SkipTaskRegistration
            $null = New-GraphKitAuthSealedStage -OutputRoot (Join-Path $fixtureRoot 'output') `
                -FullVersion $version `
                -PayloadSourceRoot (Join-Path $moduleDir 'Assemblies/GraphKit.Auth')
        }

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
            schemaVersion = 3
            runId = [guid]::NewGuid().ToString('D')
            source = [pscustomobject] [ordered] @{
                revision = $revision
                clean = -not $DirtySource
                stateSha256 = if ($DirtySource) { $sourceStateHash } else { ('c' * 64) -join '' }
            }
            module = [pscustomobject] [ordered] @{
                name = 'GraphKit'
                version = $version
                baseVersion = $baseVersion
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
                    minimumTests = 1452
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
            BaseVersion = $baseVersion
            ModuleDir = $moduleDir
            PackagePath = $packagePath
            ProofPath = $proofPath
            NUnitPath = $nunitPath
            PesterObjectPath = $pesterObjectPath
        }
    }

    function Invoke-GraphKitReleaseProofVerifier {
        param(
            [Parameter(Mandatory)] [pscustomobject] $Fixture,
            [switch] $RequestSnapshots
        )

        $snapshotPackagePath = Join-Path $Fixture.Root 'verified/GraphKit.nupkg'
        $snapshotProofPath = Join-Path $Fixture.Root 'verified/tested-release-proof.json'
        $snapshotArguments = if ($RequestSnapshots) {
            @('-VerifiedPackageCopyPath', $snapshotPackagePath, '-VerifiedProofCopyPath', $snapshotProofPath)
        }
        else { @() }

        $output = & pwsh -NoLogo -NoProfile -File $script:verifierPath `
            -PackagePath $Fixture.PackagePath `
            -ProofPath $Fixture.ProofPath `
            -RepositoryRoot $Fixture.Root @snapshotArguments 2>&1 | Out-String
        $output = $output -replace '\r?\n\s*\|\s*', ' '
        $output = ($output -replace '\s+', ' ').Trim()
        [pscustomobject] @{
            ExitCode = $LASTEXITCODE
            Output = $output
            SnapshotPackagePath = $snapshotPackagePath
            SnapshotProofPath = $snapshotProofPath
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
$mutableManifestPath = Join-Path $RepositoryRoot "output/module/GraphKit/$($verified.BaseVersion)/GraphKit.psd1"
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
            $fixtureStageRoot = Join-Path $script:fixture.Root 'output/GraphKit.Auth/stage'
            if (Test-Path -LiteralPath $fixtureStageRoot -PathType Container) {
                . (Join-Path $script:fixture.Root '.build/GraphKitAuth.tasks.ps1') -SkipTaskRegistration
                Invoke-GraphKitAuthPrepareClean -OutputRoot (Join-Path $script:fixture.Root 'output') | Out-Null
            }
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

    It 'accepts GraphKit.Auth runtime bytes when the data-file Hashtable declares the exact contracts prerequisite' {
        $script:fixture = New-GraphKitReleaseProofFixture -IncludeGraphKitAuth

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Output | Should -Match 'VERIFIED TESTED RELEASE'
        $result.Output | Should -Match '10 shipped file'
    }

    It 'accepts a prerelease package from its base-version module directory and records source provenance' {
        $script:fixture = New-GraphKitReleaseProofFixture
        $proof = Get-Content -LiteralPath $script:fixture.ProofPath -Raw | ConvertFrom-Json

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $proof.source.revision | Should -Match '^[0-9a-f]{40}$'
        $proof.module.version | Should -Match '^0\.4\.0-r8\.g[0-9a-f]{12}$'
    }

    It 'rejects a proof whose base version is not the R8 0.4.0 successor base' {
        $script:fixture = New-GraphKitReleaseProofFixture -BaseVersion '0.4.1'

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match '0\.4\.0.*r8'
    }

    It 'rejects dirty provenance before it can emit authority or snapshots' {
        $script:fixture = New-GraphKitReleaseProofFixture -DirtySource

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture -RequestSnapshots

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'non-authoritative'
        $result.Output | Should -Not -Match '^VERIFIED TESTED RELEASE:'
        Test-Path -LiteralPath $result.SnapshotPackagePath | Should -BeFalse
        Test-Path -LiteralPath $result.SnapshotProofPath | Should -BeFalse
    }

    It 'accepts package-serializer trimming of terminal release-note line endings' {
        $script:fixture = New-GraphKitReleaseProofFixture
        $manifestPath = Join-Path $script:fixture.ModuleDir 'GraphKit.psd1'
        $manifestContent = Get-Content -LiteralPath $manifestPath -Raw
        $manifestContent = $manifestContent.Replace(
            "ReleaseNotes = 'Fixture release notes.'",
            'ReleaseNotes = "Fixture release notes.`n`n"'
        )
        Set-Content -LiteralPath $manifestPath -Value $manifestContent -NoNewline -Encoding utf8NoBOM
        Set-GraphKitFixtureArchiveEntryText `
            -Fixture $script:fixture `
            -EntryName 'GraphKit.psd1' `
            -Content $manifestContent

        $proof = Get-Content -LiteralPath $script:fixture.ProofPath -Raw | ConvertFrom-Json
        ($proof.module.files | Where-Object path -CEQ 'GraphKit.psd1').sha256 =
            (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $proof | ConvertTo-Json -Depth 10 |
            Set-Content -LiteralPath $script:fixture.ProofPath -NoNewline -Encoding utf8NoBOM

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Output | Should -Match 'VERIFIED TESTED RELEASE'
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

    It 'rejects NFC-equivalent package entry paths before file-set comparison' {
        $script:fixture = New-GraphKitReleaseProofFixture
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::Open(
            $script:fixture.PackagePath,
            [System.IO.Compression.ZipArchiveMode]::Update)
        try {
            Add-GraphKitFixtureArchiveText -Archive $archive -EntryName "Data/probé.ps1" -Content 'composed'
            Add-GraphKitFixtureArchiveText -Archive $archive -EntryName "Data/probe$([char]0x0301).ps1" -Content 'decomposed'
        }
        finally {
            $archive.Dispose()
        }
        Update-GraphKitFixtureProofPackageHash -Fixture $script:fixture

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'Unicode|normalization|NFC'
    }

    It 'rejects a ZIP entry encoded as <Kind>' -ForEach @(
        @{ Kind = 'a Unix symbolic link'; ExternalAttributes = ((0xA000 -bor 0x1A4) -shl 16) }
        @{ Kind = 'a Unix non-regular device'; ExternalAttributes = ((0x2000 -bor 0x180) -shl 16) }
        @{ Kind = 'a Windows reparse point'; ExternalAttributes = 0x0400 }
        @{ Kind = 'a Windows DOS directory'; ExternalAttributes = 0x0010 }
    ) {
        $script:fixture = New-GraphKitReleaseProofFixture
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::Open(
            $script:fixture.PackagePath,
            [System.IO.Compression.ZipArchiveMode]::Update)
        try {
            $entry = $archive.GetEntry('GraphKit.psm1')
            $entry.ExternalAttributes = $ExternalAttributes
        }
        finally {
            $archive.Dispose()
        }
        Update-GraphKitFixtureProofPackageHash -Fixture $script:fixture

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'non-regular|link|reparse'
    }

    It 'rejects unsafe package path <EntryName>' -ForEach @(
        @{ EntryName = '../outside/' }
        @{ EntryName = '/absolute.ps1' }
        @{ EntryName = 'C:/absolute.ps1' }
        @{ EntryName = 'Data\\evil.ps1' }
        @{ EntryName = 'Data//evil.ps1' }
        @{ EntryName = 'Data/./evil.ps1' }
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

    It 'rejects NFC-equivalent proof file paths' {
        $script:fixture = New-GraphKitReleaseProofFixture
        $proof = Get-Content -LiteralPath $script:fixture.ProofPath -Raw | ConvertFrom-Json
        $hash = ('d' * 64) -join ''
        $proof.module.files = @($proof.module.files) + @(
            [pscustomobject] @{ path = "Data/probé.ps1"; sha256 = $hash }
            [pscustomobject] @{ path = "Data/probe$([char]0x0301).ps1"; sha256 = $hash }
        )
        $proof | ConvertTo-Json -Depth 10 |
            Set-Content -LiteralPath $script:fixture.ProofPath -NoNewline -Encoding utf8NoBOM

        $result = Invoke-GraphKitReleaseProofVerifier -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'Unicode|normalization|NFC'
    }

    It 'rejects nuspec <Field> drift' -ForEach @(
        @{ Field = 'id'; Find = '<id>GraphKit</id>'; Replace = '<id>OtherModule</id>' }
        @{ Field = 'version'; Find = $null; Replace = '<version>9.9.8</version>' }
        @{ Field = 'authors'; Find = '<authors>Fixture Author</authors>'; Replace = '<authors>Other Author</authors>' }
        @{ Field = 'description'; Find = '<description>Fixture GraphKit release-proof module package.</description>'; Replace = '<description>Different description.</description>' }
        @{ Field = 'license'; Find = '<licenseUrl>https://opensource.org/licenses/MIT</licenseUrl>'; Replace = '<licenseUrl>https://example.invalid/license</licenseUrl>' }
        @{ Field = 'tags'; Find = '<tags>Fixture Graph PSModule PSIncludes_Function PSFunction_Get-GraphProbe PSCommand_Get-GraphProbe</tags>'; Replace = '<tags>Different</tags>' }
        @{ Field = 'release notes'; Find = '<releaseNotes>Fixture release notes.</releaseNotes>'; Replace = '<releaseNotes>Different notes.</releaseNotes>' }
    ) {
        $script:fixture = New-GraphKitReleaseProofFixture
        $nuspec = Get-GraphKitFixtureArchiveEntryText -Fixture $script:fixture -EntryName 'GraphKit.nuspec'
        if ($Field -eq 'version') {
            $Find = "<version>$($script:fixture.Version)</version>"
        }
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
        $script:fixture = New-GraphKitReleaseProofFixture -ForGenerator

        $result = Invoke-GraphKitReleaseProofGenerator -Fixture $script:fixture -Stage Capture

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Output | Should -Match 'CAPTURED RELEASE CANDIDATE'
        Test-Path -LiteralPath $script:fixture.ProofPath | Should -BeFalse
        Test-Path -LiteralPath $script:fixture.NUnitPath | Should -BeFalse
        Test-Path -LiteralPath $script:fixture.PesterObjectPath | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $script:fixture.Root 'output/testResults/candidate-release-input.json') | Should -BeTrue
    }

    It 'finalize emits the one proof only after the captured candidate and result pair pass' {
        $script:fixture = New-GraphKitReleaseProofFixture -ForGenerator
        $nunitBytes = [System.IO.File]::ReadAllBytes($script:fixture.NUnitPath)
        $pesterObjectBytes = [System.IO.File]::ReadAllBytes($script:fixture.PesterObjectPath)
        (Invoke-GraphKitReleaseProofGenerator -Fixture $script:fixture -Stage Capture).ExitCode | Should -Be 0
        [System.IO.File]::WriteAllBytes($script:fixture.NUnitPath, $nunitBytes)
        [System.IO.File]::WriteAllBytes($script:fixture.PesterObjectPath, $pesterObjectBytes)
        @(& git -C $script:fixture.Root status --porcelain=v1 --untracked-files=all) | Should -BeNullOrEmpty

        $result = Invoke-GraphKitReleaseProofGenerator -Fixture $script:fixture -Stage Finalize

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Output | Should -Match 'RECORDED TESTED RELEASE PROOF'
        $proof = Get-Content -LiteralPath $script:fixture.ProofPath -Raw | ConvertFrom-Json
        $proof.module.name | Should -Be 'GraphKit'
        $proof.module.version | Should -Be $script:fixture.Version
        $proof.module.baseVersion | Should -Be $script:fixture.BaseVersion
        $proof.source.revision | Should -Match '^[0-9a-f]{40}$'
        @($proof.module.files).Count | Should -Be 5
        $proof.testRun.summary.total | Should -Be 1452
        $proof.testRun.summary.notRun | Should -Be 0
        Test-Path -LiteralPath (Join-Path $script:fixture.Root 'output/testResults/candidate-release-input.json') | Should -BeFalse
    }

    It 'finalize refuses module drift after capture and leaves no tested proof' {
        $script:fixture = New-GraphKitReleaseProofFixture -ForGenerator
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
        $script:fixture = New-GraphKitReleaseProofFixture -ForGenerator -NotRun 1
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
        @([regex]::Matches($testWorkflow, '(?m)^\s*-\s+Pester_Tests_With_GraphKitAuth_ABI_Fixture\s*$')).Count | Should -Be 1
        @([regex]::Matches($testWorkflow, '(?m)^\s*-\s+Record_Tested_Release_Proof\s*$')).Count | Should -Be 1
        $testWorkflow.IndexOf('Capture_Tested_Release_Proof_Candidate') | Should -BeLessThan $testWorkflow.IndexOf('Pester_Tests_With_GraphKitAuth_ABI_Fixture')
        $testWorkflow.IndexOf('Pester_Tests_With_GraphKitAuth_ABI_Fixture') | Should -BeLessThan $testWorkflow.IndexOf('Record_Tested_Release_Proof')
        $testTaskLines = @(
            $testWorkflow -split '\r?\n' |
                Where-Object { $_ -match '^\s*-\s+[A-Za-z]' }
        )
        $testTaskLines[-1] | Should -Match 'Record_Tested_Release_Proof\s*$'

        $authTasks = Get-Content -LiteralPath (Join-Path $script:repoRoot '.build/GraphKitAuth.tasks.ps1') -Raw
        $guardedTask = [regex]::Match($authTasks,
            '(?ms)^\s*task Pester_Tests_With_GraphKitAuth_ABI_Fixture \{.*?^\s*\}\s*^\}').Value
        $guardedTask | Should -Match '(?s)try\s*\{.*Pester_Tests_Stop_On_Fail.*\}\s*finally\s*\{.*Remove-GraphKitAuthAbiTestFixture'

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

    It '<Publisher> rejects a dirty proof before publication authority is established' -ForEach @(
        @{ Publisher = 'PrivateChannel' }
        @{ Publisher = 'PSGallery' }
    ) {
        $script:fixture = New-GraphKitReleaseProofFixture -DirtySource

        $result = Invoke-GraphKitFixturePublisher -Fixture $script:fixture -Publisher $Publisher

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'non-authoritative'
    }

    It 'private publication uses verifier-owned snapshots and preserves durable proof evidence' {
        $script:fixture = New-GraphKitReleaseProofFixture
        Install-GraphKitFixtureMutatingVerifier -Fixture $script:fixture

        $proofHashBefore = (Get-FileHash -LiteralPath $script:fixture.ProofPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $proofBefore = Get-Content -LiteralPath $script:fixture.ProofPath -Raw | ConvertFrom-Json
        $result = Invoke-GraphKitFixturePublisher -Fixture $script:fixture -Publisher PrivateChannel

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $publishedPackage = Join-Path $script:fixture.Root "channel/GraphKit.$($script:fixture.Version).nupkg"
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

    It 'gallery preflight rejects a local path in strict UTF-8 deps JSON from the verifier-owned package without disclosing it' {
        $script:fixture = New-GraphKitReleaseProofFixture
        $sentinel = '/Users/GraphKitPrivacyJson/private-build'
        Add-GraphKitFixturePayloadText -Fixture $script:fixture `
            -EntryName 'Diagnostics/Fixture.deps.json' `
            -Content ('{"runtimeTarget":{"path":"' + $sentinel + '"}}')
        Install-GraphKitFixtureMutatingVerifier -Fixture $script:fixture

        $result = Invoke-GraphKitFixtureGalleryPreflight -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0 -Because $result.Output
        $result.Output | Should -Match 'package carries no identifiers that must stay private'
        $result.Output | Should -Match 'local user path'
        $result.Output | Should -Not -Match ([regex]::Escape($sentinel))
        (Get-Content -LiteralPath $script:fixture.PackagePath -Raw) | Should -Be 'replacement package after verifier return'
    }

    It 'gallery preflight fails closed when a deps JSON entry is not strict UTF-8' {
        $script:fixture = New-GraphKitReleaseProofFixture
        $invalidUtf8 = [byte[]] @(0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xc3, 0x28, 0x22, 0x7d)
        Add-GraphKitFixturePayloadBytes -Fixture $script:fixture `
            -EntryName 'Diagnostics/Invalid.deps.json' `
            -Bytes $invalidUtf8

        $result = Invoke-GraphKitFixtureGalleryPreflight -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0 -Because $result.Output
        $result.Output | Should -Match 'strict UTF-8'
        $result.Output | Should -Not -Match ([char] 0xfffd)
    }

    It 'gallery preflight applies every privacy category to authored CSharp without disclosing matched values' {
        $script:fixture = New-GraphKitReleaseProofFixture
        $privateGuid = '87f7ad68-c47e-48b4-a248-49602bc19e84'
        $thumbprint = '0123456789abcdef0123456789abcdef01234567'
        $localPath = 'C:\Users\GraphKitPrivacyCSharp\source.cs'
        $internalProject = 'IntuneHealthAutomation'
        Add-GraphKitFixturePayloadText -Fixture $script:fixture `
            -EntryName 'Diagnostics/Fixture.cs' `
            -Content @"
internal static class Fixture {
    private const string TenantId = "$privateGuid";
    private const string CertificateThumbprint = "$thumbprint";
    private const string SourcePath = @"$localPath";
    private const string Project = "$internalProject";
}
"@

        $result = Invoke-GraphKitFixtureGalleryPreflight -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0 -Because $result.Output
        $result.Output | Should -Match 'GUID that is not a well-known or package id'
        $result.Output | Should -Match 'certificate thumbprint'
        $result.Output | Should -Match 'local user path'
        $result.Output | Should -Match 'internal project name'
        foreach ($sentinel in @($privateGuid, $thumbprint, $localPath, $internalProject)) {
            $result.Output | Should -Not -Match ([regex]::Escape($sentinel))
        }
    }

    It 'gallery preflight scans first-party and dependency DLL strings in ASCII and UTF-16LE without disclosing matched values' {
        $script:fixture = New-GraphKitReleaseProofFixture
        $asciiSentinel = '/Users/GraphKitPrivacyBinary/private-build'
        $wideSentinel = 'IntuneHealthAutomation'
        Add-GraphKitFixturePayloadBytes -Fixture $script:fixture `
            -EntryName 'Binary/GraphKit.Auth.dll' `
            -Bytes ([System.Text.Encoding]::ASCII.GetBytes("prefix::$asciiSentinel::suffix"))
        Add-GraphKitFixturePayloadBytes -Fixture $script:fixture `
            -EntryName 'Binary/Microsoft.Identity.Client.DLL' `
            -Bytes ([System.Text.Encoding]::Unicode.GetBytes("prefix::$wideSentinel::suffix"))

        $result = Invoke-GraphKitFixtureGalleryPreflight -Fixture $script:fixture

        $result.ExitCode | Should -Not -Be 0 -Because $result.Output
        $result.Output | Should -Match 'binary-ascii: local user path'
        $result.Output | Should -Match 'binary-utf16le: internal project name'
        $result.Output | Should -Not -Match ([regex]::Escape($asciiSentinel))
        $result.Output | Should -Not -Match ([regex]::Escape($wideSentinel))
    }

    It 'gallery preflight accepts legitimate 40-hex source and vendor revisions' {
        $script:fixture = New-GraphKitReleaseProofFixture
        $sourceRevision = '6aee19bc50d2cdfbdba55d6694465855c5c6fb51'
        $vendorRevision = '013d71559a017f50aa4861487226c523959d1579'
        Add-GraphKitFixturePayloadText -Fixture $script:fixture `
            -EntryName 'Diagnostics/Revisions.deps.json' `
            -Content ('{"sourceRevision":"' + $sourceRevision + '"}')
        Add-GraphKitFixturePayloadBytes -Fixture $script:fixture `
            -EntryName 'Binary/Vendor.Dependency.dll' `
            -Bytes ([System.Text.Encoding]::ASCII.GetBytes("RepositoryCommit=$vendorRevision"))

        $result = Invoke-GraphKitFixtureGalleryPreflight -Fixture $script:fixture

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Output | Should -Match 'PRE-FLIGHT PASSED'
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
