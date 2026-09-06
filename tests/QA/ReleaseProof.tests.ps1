BeforeAll {
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:createProof = Join-Path $script:repoRoot 'scripts/New-GraphKitTestedReleaseProof.ps1'
    $script:verifyProof = Join-Path $script:repoRoot 'scripts/Test-GraphKitReleaseProof.ps1'

    function Set-ZipEntryText {
        param(
            [Parameter(Mandatory)] [string] $PackagePath,
            [Parameter(Mandatory)] [string] $EntryPath,
            [Parameter(Mandatory)] [string] $Text,
            [switch] $Add
        )

        $archive = [System.IO.Compression.ZipFile]::Open($PackagePath, 'Update')
        try {
            if (-not $Add) {
                $existing = $archive.GetEntry($EntryPath)
                if ($null -eq $existing) { throw "Fixture entry '$EntryPath' was not found." }
                $existing.Delete()
            }
            $entry = $archive.CreateEntry($EntryPath)
            $writer = [System.IO.StreamWriter]::new($entry.Open())
            try { $writer.Write($Text) } finally { $writer.Dispose() }
        }
        finally { $archive.Dispose() }
    }

    function Remove-ZipEntry {
        param([string] $PackagePath, [string] $EntryPath)
        $archive = [System.IO.Compression.ZipFile]::Open($PackagePath, 'Update')
        try {
            $entry = $archive.GetEntry($EntryPath)
            if ($null -eq $entry) { throw "Fixture entry '$EntryPath' was not found." }
            $entry.Delete()
        }
        finally { $archive.Dispose() }
    }

    function New-ReleaseProofFixture {
        param([Parameter(Mandatory)] [string] $Root)

        $moduleRoot = Join-Path $Root 'output/module/GraphKit/0.3.1'
        $operations = Join-Path $moduleRoot 'Data/Operations'
        $testRoot = Join-Path $Root 'output/testResults'
        $null = New-Item -ItemType Directory -Path $operations -Force
        $null = New-Item -ItemType Directory -Path $testRoot -Force

        @"
@{
    RootModule = 'GraphKit.psm1'
    ModuleVersion = '0.3.1'
    GUID = '212637ed-2571-4e88-8df2-888a0c163ccd'
    Author = 'Fixture'
    Description = 'Fixture'
}
"@ | Set-Content -LiteralPath (Join-Path $moduleRoot 'GraphKit.psd1') -Encoding utf8
        'function Get-Fixture { "ok" }' | Set-Content -LiteralPath (Join-Path $moduleRoot 'GraphKit.psm1') -Encoding utf8
        '@{ Name = "AppleEnrollmentProfile.ListByToken" }' |
            Set-Content -LiteralPath (Join-Path $operations 'AppleEnrollmentProfile.ListByToken.psd1') -Encoding utf8
        '@{ Name = "ManagedDevice.GetBeta" }' |
            Set-Content -LiteralPath (Join-Path $operations 'ManagedDevice.GetBeta.psd1') -Encoding utf8

        $resultPath = Join-Path $testRoot 'NUnitXml_GraphKit_v0.3.1.Fixture.xml'
        @'
<?xml version="1.0" encoding="utf-8"?>
<test-results name="GraphKit 0.3.1" total="789" errors="0" failures="0" not-run="0" inconclusive="0" ignored="0" skipped="0" invalid="0">
  <test-suite type="TestFixture" name="GraphKit" executed="True" result="Success" success="True" />
</test-results>
'@ | Set-Content -LiteralPath $resultPath -Encoding utf8

        $packagePath = Join-Path $Root 'output/GraphKit.0.3.1.nupkg'
        $archive = [System.IO.Compression.ZipFile]::Open($packagePath, 'Create')
        try {
            foreach ($file in Get-ChildItem -LiteralPath $moduleRoot -File -Recurse) {
                $relative = [System.IO.Path]::GetRelativePath($moduleRoot, $file.FullName).Replace('\', '/')
                [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $file.FullName, $relative) | Out-Null
            }
            foreach ($metadataPath in @('_rels/.rels', 'GraphKit.nuspec', '[Content_Types].xml', 'package/services/metadata/core-properties/fixture.psmdcp')) {
                $entry = $archive.CreateEntry($metadataPath)
                $writer = [System.IO.StreamWriter]::new($entry.Open())
                try { $writer.Write("fixture:$metadataPath") } finally { $writer.Dispose() }
            }
        }
        finally { $archive.Dispose() }

        "/output/*.nupkg`n/proof.json`n" | Set-Content -LiteralPath (Join-Path $Root '.gitignore') -Encoding utf8
        & git -C $Root init --quiet
        & git -C $Root config user.email fixture@example.invalid
        & git -C $Root config user.name Fixture
        & git -C $Root add .
        & git -C $Root commit --quiet -m fixture
        if ($LASTEXITCODE -ne 0) { throw 'Could not commit the release-proof fixture.' }

        $proofPath = Join-Path $Root 'proof.json'
        & $script:createProof -PackagePath $packagePath -TestResultPath $resultPath -OutputPath $proofPath -RepositoryRoot $Root -MinimumTests 789 | Out-Null

        return [pscustomobject]@{
            Root = $Root
            ModuleRoot = $moduleRoot
            PackagePath = $packagePath
            ResultPath = $resultPath
            ProofPath = $proofPath
        }
    }

    function Set-ProofSourceRevisionToHead {
        param([Parameter(Mandatory)] $Fixture)
        $proof = Get-Content -LiteralPath $Fixture.ProofPath -Raw | ConvertFrom-Json
        $proof.sourceRevision = (& git -C $Fixture.Root rev-parse HEAD).Trim()
        $proof | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Fixture.ProofPath -Encoding utf8
    }
}

Describe 'GraphKit tested-release proof' -Tag 'QA' {
    BeforeEach {
        $script:fixture = New-ReleaseProofFixture -Root (Join-Path $TestDrive ([guid]::NewGuid().ToString('N')))
    }

    It 'verifies the exact package, built tree, test result, and source revision' {
        $verified = & $script:verifyProof -PackagePath $fixture.PackagePath -ProofPath $fixture.ProofPath `
            -RepositoryRoot $fixture.Root -TestResultPath $fixture.ResultPath

        $verified.Version | Should -BeExactly '0.3.1'
        $verified.TestCount | Should -BeGreaterOrEqual 789
        $verified.ShippedFileCount | Should -BeGreaterThan 2
        $verified.PackageSha256 | Should -Match '^[0-9a-f]{64}$'
        $verified.SourceRevision | Should -Match '^[0-9a-f]{40}$'
    }

    It 'rejects changed Apple descriptor bytes inside the package' {
        Set-ZipEntryText -PackagePath $fixture.PackagePath -EntryPath 'Data/Operations/AppleEnrollmentProfile.ListByToken.psd1' -Text 'tampered'
        { & $script:verifyProof -PackagePath $fixture.PackagePath -ProofPath $fixture.ProofPath -RepositoryRoot $fixture.Root } |
            Should -Throw -ExpectedMessage '*archive file digest mismatch*AppleEnrollmentProfile*'
    }

    It 'rejects changed managed-device descriptor bytes in the built tree' {
        'tampered' | Set-Content -LiteralPath (Join-Path $fixture.ModuleRoot 'Data/Operations/ManagedDevice.GetBeta.psd1')
        & git -C $fixture.Root add output/module/GraphKit/0.3.1/Data/Operations/ManagedDevice.GetBeta.psd1
        & git -C $fixture.Root commit --quiet -m mutation
        Set-ProofSourceRevisionToHead -Fixture $fixture
        { & $script:verifyProof -PackagePath $fixture.PackagePath -ProofPath $fixture.ProofPath -RepositoryRoot $fixture.Root } |
            Should -Throw -ExpectedMessage '*built file digest mismatch*ManagedDevice.GetBeta*'
    }

    It 'rejects an unlisted package entry' {
        Set-ZipEntryText -PackagePath $fixture.PackagePath -EntryPath 'unexpected.txt' -Text 'extra' -Add
        { & $script:verifyProof -PackagePath $fixture.PackagePath -ProofPath $fixture.ProofPath -RepositoryRoot $fixture.Root } |
            Should -Throw -ExpectedMessage '*unlisted archive entry*unexpected.txt*'
    }

    It 'rejects a missing listed package entry' {
        Remove-ZipEntry -PackagePath $fixture.PackagePath -EntryPath 'GraphKit.psm1'
        { & $script:verifyProof -PackagePath $fixture.PackagePath -ProofPath $fixture.ProofPath -RepositoryRoot $fixture.Root } |
            Should -Throw -ExpectedMessage '*archive file set mismatch*GraphKit.psm1*'
    }

    It 'rejects unsafe archive traversal paths' {
        Set-ZipEntryText -PackagePath $fixture.PackagePath -EntryPath '../escape' -Text 'unsafe' -Add
        { & $script:verifyProof -PackagePath $fixture.PackagePath -ProofPath $fixture.ProofPath -RepositoryRoot $fixture.Root } |
            Should -Throw -ExpectedMessage '*unsafe archive path*'
    }

    It 'rejects changed NUnit bytes' {
        (Get-Content -LiteralPath $fixture.ResultPath -Raw).Replace('total="789"', 'total="790"') |
            Set-Content -LiteralPath $fixture.ResultPath -Encoding utf8
        & git -C $fixture.Root add output/testResults/NUnitXml_GraphKit_v0.3.1.Fixture.xml
        & git -C $fixture.Root commit --quiet -m result-mutation
        Set-ProofSourceRevisionToHead -Fixture $fixture
        { & $script:verifyProof -PackagePath $fixture.PackagePath -ProofPath $fixture.ProofPath -RepositoryRoot $fixture.Root -TestResultPath $fixture.ResultPath } |
            Should -Throw -ExpectedMessage '*test result digest mismatch*'
    }

    It 'rejects a stale source revision' {
        $proof = Get-Content -LiteralPath $fixture.ProofPath -Raw | ConvertFrom-Json
        $proof.sourceRevision = '0' * 40
        $proof | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $fixture.ProofPath -Encoding utf8
        { & $script:verifyProof -PackagePath $fixture.PackagePath -ProofPath $fixture.ProofPath -RepositoryRoot $fixture.Root } |
            Should -Throw -ExpectedMessage '*source revision mismatch*'
    }

    It 'rejects case-insensitive duplicate archive paths' {
        Set-ZipEntryText -PackagePath $fixture.PackagePath -EntryPath 'graphkit.psm1' -Text 'duplicate' -Add
        { & $script:verifyProof -PackagePath $fixture.PackagePath -ProofPath $fixture.ProofPath -RepositoryRoot $fixture.Root } |
            Should -Throw -ExpectedMessage '*duplicate archive path*'
    }

    It 'rejects a proof naming another package' {
        $proof = Get-Content -LiteralPath $fixture.ProofPath -Raw | ConvertFrom-Json
        $proof.package.name = 'GraphKit.0.3.1-other.nupkg'
        $proof | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $fixture.ProofPath -Encoding utf8
        { & $script:verifyProof -PackagePath $fixture.PackagePath -ProofPath $fixture.ProofPath -RepositoryRoot $fixture.Root } |
            Should -Throw -ExpectedMessage '*package name mismatch*'
    }

    It 'rejects a symlink supplied in place of the package' {
        $linkPath = Join-Path $fixture.Root 'linked-package.nupkg'
        $null = New-Item -ItemType SymbolicLink -Path $linkPath -Target $fixture.PackagePath
        { & $script:verifyProof -PackagePath $linkPath -ProofPath $fixture.ProofPath -RepositoryRoot $fixture.Root } |
            Should -Throw -ExpectedMessage '*must be a regular file*symlink*'
    }

    It 'rejects unknown top-level proof members' {
        $proof = Get-Content -LiteralPath $fixture.ProofPath -Raw | ConvertFrom-Json
        $proof | Add-Member -NotePropertyName surprise -NotePropertyValue $true
        $proof | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $fixture.ProofPath -Encoding utf8
        { & $script:verifyProof -PackagePath $fixture.PackagePath -ProofPath $fixture.ProofPath -RepositoryRoot $fixture.Root } |
            Should -Throw -ExpectedMessage '*Proof members mismatch*surprise*'
    }
}
