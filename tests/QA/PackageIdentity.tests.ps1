BeforeAll {
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:baseVersion = '0.4.0'
    $script:train = 'r8'
    $script:sourceManifestPath = Join-Path $script:repoRoot 'source/GraphKit.psd1'

    $script:versionScriptPath = Join-Path $script:repoRoot 'scripts/Get-GraphKitTrainVersion.ps1'
    $script:expectedVersion = (& $script:versionScriptPath -RepositoryRoot $script:repoRoot).Trim()
    if (-not $script:expectedVersion.StartsWith("$script:baseVersion-", [StringComparison]::Ordinal)) {
        throw "The derived package version '$script:expectedVersion' does not extend the expected base version '$script:baseVersion'."
    }
    $script:expectedPrerelease = $script:expectedVersion.Substring($script:baseVersion.Length + 1)
    if ([string]::IsNullOrWhiteSpace($script:expectedPrerelease)) {
        throw "The derived package version '$script:expectedVersion' has no prerelease identity."
    }
    if (-not $script:expectedPrerelease.StartsWith("$script:train.", [StringComparison]::Ordinal)) {
        throw "The derived package prerelease '$script:expectedPrerelease' is not bound to train '$script:train'."
    }
    $script:builtManifestPath = Join-Path $script:repoRoot "output/module/GraphKit/$script:baseVersion/GraphKit.psd1"
    $script:packagePath = Join-Path $script:repoRoot "output/GraphKit.$script:expectedVersion.nupkg"

    function Get-GraphKitPackageMetadata {
        param([Parameter(Mandatory)] [string] $PackagePath)

        $archive = [System.IO.Compression.ZipFile]::OpenRead($PackagePath)
        try {
            $entries = @($archive.Entries | Where-Object { $_.FullName -like '*.nuspec' })
            $entries.Count | Should -Be 1
            $reader = [System.IO.StreamReader]::new($entries[0].Open())
            try {
                [xml] $nuspec = $reader.ReadToEnd()
            }
            finally {
                $reader.Dispose()
            }
        }
        finally {
            $archive.Dispose()
        }

        return $nuspec.package.metadata
    }
}

Describe 'GraphKit release package identity' -Tag 'QA' {
    It 'declares the 0.4.0 r8 successor seed in source metadata' {
        $source = Import-PowerShellDataFile $script:sourceManifestPath

        [string] $source.ModuleVersion | Should -Be $script:baseVersion
        [string] $source.PrivateData.PSData.Prerelease | Should -Be $script:train
        [string] $source.PrivateData.PSData.ReleaseNotes | Should -Match '^0\.4\.0(?:\r?\n)'
    }

    It 'derives the complete package version from the exact repository source state' {
        Test-Path -LiteralPath $script:versionScriptPath -PathType Leaf | Should -BeTrue
        if (Test-Path -LiteralPath $script:versionScriptPath -PathType Leaf) {
            (& $script:versionScriptPath -RepositoryRoot $script:repoRoot) | Should -Be $script:expectedVersion
        }

        $buildPath = Join-Path $script:repoRoot 'build.ps1'
        $tokens = $null
        $parseErrors = $null
        $buildAst = [Management.Automation.Language.Parser]::ParseFile(
            $buildPath, [ref] $tokens, [ref] $parseErrors)
        @($parseErrors).Count | Should -Be 0
        $versionValidators = @($buildAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq 'Get-GraphKitValidatedTrainVersion'
        }, $true))
        $versionValidators.Count | Should -Be 1
        . ([scriptblock]::Create($versionValidators[0].Extent.Text))

        $stubRoot = Join-Path $TestDrive 'train-version-output-contract'
        $null = New-Item -ItemType Directory -Path $stubRoot -Force
        $validStub = Join-Path $stubRoot 'valid.ps1'
        $noneStub = Join-Path $stubRoot 'none.ps1'
        $multipleStub = Join-Path $stubRoot 'multiple.ps1'
        $objectStub = Join-Path $stubRoot 'object.ps1'
        $errorStub = Join-Path $stubRoot 'error.ps1'
        Set-Content -LiteralPath $validStub -Encoding utf8NoBOM -Value "[CmdletBinding()] param([string] `$RepositoryRoot)`n' 0.4.0-r8.fixture '"
        Set-Content -LiteralPath $noneStub -Encoding utf8NoBOM -Value "[CmdletBinding()] param([string] `$RepositoryRoot)"
        Set-Content -LiteralPath $multipleStub -Encoding utf8NoBOM -Value "[CmdletBinding()] param([string] `$RepositoryRoot)`n'one'`n 'two'"
        Set-Content -LiteralPath $objectStub -Encoding utf8NoBOM -Value "[CmdletBinding()] param([string] `$RepositoryRoot)`n[pscustomobject] @{ value = 'wrong type' }"
        Set-Content -LiteralPath $errorStub -Encoding utf8NoBOM -Value "[CmdletBinding()] param([string] `$RepositoryRoot)`nthrow 'train-version fixture failure'"

        Get-GraphKitValidatedTrainVersion -VersionScript $validStub -RepositoryRoot $stubRoot |
            Should -BeExactly '0.4.0-r8.fixture'
        foreach ($invalidStub in @($noneStub, $multipleStub, $objectStub)) {
            {
                Get-GraphKitValidatedTrainVersion -VersionScript $invalidStub -RepositoryRoot $stubRoot
            } | Should -Throw -ExpectedMessage '*exactly one non-empty string*'
        }
        {
            Get-GraphKitValidatedTrainVersion -VersionScript $errorStub -RepositoryRoot $stubRoot
        } | Should -Throw -ExpectedMessage '*train-version fixture failure*'
    }

    It 'builds the base module directory and packages the full r8 identity' {
        Test-Path $script:builtManifestPath -PathType Leaf | Should -BeTrue
        Test-Path $script:packagePath -PathType Leaf | Should -BeTrue
        Test-Path (Join-Path $script:repoRoot 'output/GraphKit.0.3.0.nupkg') -PathType Leaf | Should -BeFalse
    }

    It 'preserves base and full prerelease identities in the built manifest and package metadata' {
        Test-Path $script:builtManifestPath -PathType Leaf | Should -BeTrue
        Test-Path $script:packagePath -PathType Leaf | Should -BeTrue

        $builtManifest = Import-PowerShellDataFile $script:builtManifestPath
        $packageMetadata = Get-GraphKitPackageMetadata $script:packagePath
        [string] $builtManifest.ModuleVersion | Should -Be $script:baseVersion
        [string] $builtManifest.PrivateData.PSData.Prerelease | Should -Be $script:expectedPrerelease
        [string] $packageMetadata.version | Should -Be $script:expectedVersion
    }

    It 'preserves the base module manifest in the exact prerelease nupkg' {
        Test-Path $script:packagePath -PathType Leaf | Should -BeTrue

        $extractRoot = Join-Path $TestDrive 'release'
        [System.IO.Compression.ZipFile]::ExtractToDirectory($script:packagePath, $extractRoot)
        $packagedManifest = Import-PowerShellDataFile (Join-Path $extractRoot 'GraphKit.psd1')
        [string] $packagedManifest.ModuleVersion | Should -Be $script:baseVersion
        [string] $packagedManifest.PrivateData.PSData.Prerelease | Should -Be $script:expectedPrerelease
    }
}
