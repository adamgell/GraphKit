$requiredGraphKitAuthCases = @(
    @{ Path = 'Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll' }
    @{ Path = 'Assemblies/GraphKit.Auth/GraphKit.Auth.dll' }
    @{ Path = 'Assemblies/GraphKit.Auth/GraphKit.Auth.deps.json' }
    @{ Path = 'Assemblies/GraphKit.Auth/Microsoft.Identity.Client.dll' }
    @{ Path = 'Assemblies/GraphKit.Auth/Microsoft.IdentityModel.Abstractions.dll' }
)

BeforeAll {
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:sourceManifest = Import-PowerShellDataFile -Path (Join-Path $script:repoRoot 'source/GraphKit.psd1')
    $script:baseVersion = [string] $script:sourceManifest.ModuleVersion
    $script:builtModuleRoot = Join-Path $script:repoRoot "output/module/GraphKit/$script:baseVersion"
    $script:builtManifestPath = Join-Path $script:builtModuleRoot 'GraphKit.psd1'
    $script:packagePath = $null
    $script:packageEntries = @()

    if (Test-Path -LiteralPath $script:builtManifestPath -PathType Leaf) {
        $builtManifest = Import-PowerShellDataFile -Path $script:builtManifestPath
        $prerelease = [string] $builtManifest.PrivateData.PSData.Prerelease
        $fullVersion = if ([string]::IsNullOrWhiteSpace($prerelease)) {
            $script:baseVersion
        }
        else {
            "$script:baseVersion-$prerelease"
        }
        $script:packagePath = Join-Path $script:repoRoot "output/GraphKit.$fullVersion.nupkg"
    }

    if ($script:packagePath -and (Test-Path -LiteralPath $script:packagePath -PathType Leaf)) {
        $archive = [System.IO.Compression.ZipFile]::OpenRead($script:packagePath)
        try {
            $script:packageEntries = @($archive.Entries.FullName)
        }
        finally {
            $archive.Dispose()
        }
    }

}

Describe 'Packed GraphKit.Auth boundary' -Tag 'QA' {
    It 'contains the exact required path <Path>' -ForEach $requiredGraphKitAuthCases {
        $script:packagePath | Should -Not -BeNullOrEmpty -Because 'pack must produce a versioned GraphKit candidate'
        Test-Path -LiteralPath $script:packagePath -PathType Leaf | Should -BeTrue -Because 'the package boundary is tested against the packed candidate'

        @($script:packageEntries | Where-Object { $_ -ceq $Path }).Count | Should -Be 1 -Because "the archive must contain '$Path' exactly once"
        Test-Path -LiteralPath (Join-Path $script:builtModuleRoot $Path) -PathType Leaf |
            Should -BeTrue -Because "the packed path '$Path' must originate in the built module"
    }
}
