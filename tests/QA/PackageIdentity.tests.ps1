BeforeAll {
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:expectedVersion = '0.3.0'
    $script:sourceManifestPath = Join-Path $script:repoRoot 'source/GraphKit.psd1'
    $script:builtManifestPath = Join-Path $script:repoRoot "output/module/GraphKit/$script:expectedVersion/GraphKit.psd1"
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
    It 'declares released version 0.3.0 in source and release metadata' {
        $source = Import-PowerShellDataFile $script:sourceManifestPath

        [string] $source.ModuleVersion | Should -Be $script:expectedVersion
        [string] $source.PrivateData.PSData.ReleaseNotes | Should -Match '^0\.3\.0(?:\r?\n)'
    }

    It 'builds and packages the 0.3.0 identity' {
        Test-Path $script:builtManifestPath -PathType Leaf | Should -BeTrue
        Test-Path $script:packagePath -PathType Leaf | Should -BeTrue
    }

    It 'preserves 0.3.0 in the built manifest and exact package metadata' {
        Test-Path $script:builtManifestPath -PathType Leaf | Should -BeTrue
        Test-Path $script:packagePath -PathType Leaf | Should -BeTrue

        $builtManifest = Import-PowerShellDataFile $script:builtManifestPath
        $packageMetadata = Get-GraphKitPackageMetadata $script:packagePath
        [string] $builtManifest.ModuleVersion | Should -Be $script:expectedVersion
        [string] $packageMetadata.version | Should -Be $script:expectedVersion
    }

    It 'preserves 0.3.0 in the manifest extracted from the exact nupkg' {
        Test-Path $script:packagePath -PathType Leaf | Should -BeTrue

        $extractRoot = Join-Path $TestDrive 'release'
        [System.IO.Compression.ZipFile]::ExtractToDirectory($script:packagePath, $extractRoot)
        $packagedManifest = Import-PowerShellDataFile (Join-Path $extractRoot 'GraphKit.psd1')
        [string] $packagedManifest.ModuleVersion | Should -Be $script:expectedVersion
    }
}
