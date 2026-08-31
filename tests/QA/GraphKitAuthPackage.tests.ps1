$requiredGraphKitAuthCases = @(
    @{ Path = 'Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll' }
    @{ Path = 'Assemblies/GraphKit.Auth/GraphKit.Auth.dll' }
    @{ Path = 'Assemblies/GraphKit.Auth/GraphKit.Auth.deps.json' }
    @{ Path = 'Assemblies/GraphKit.Auth/Microsoft.Identity.Client.dll' }
    @{ Path = 'Assemblies/GraphKit.Auth/Microsoft.IdentityModel.Abstractions.dll' }
)

$graphKitAuthArchiveAliasCases = @(
    @{
        Kind = 'case alias'
        Entries = @(
            'Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll'
            'assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll'
        )
    }
    @{
        Kind = 'backslash alias'
        Entries = @(
            'Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll'
            'Assemblies\GraphKit.Auth\GraphKit.Auth.Contracts.dll'
        )
    }
    @{
        Kind = 'duplicate exact path'
        Entries = @(
            'Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll'
            'Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll'
        )
    }
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

    function Assert-GraphKitAuthArchiveEntry {
        param(
            [Parameter(Mandatory)] [string[]] $Entries,
            [Parameter(Mandatory)] [string] $RequiredPath
        )

        $exact = @($Entries | Where-Object { $_ -ceq $RequiredPath })
        $normalizedRequired = $RequiredPath.Replace('\', '/')
        $equivalent = @(
            $Entries | Where-Object {
                $normalized = $_.Replace('\', '/')
                [string]::Equals($normalized, $normalizedRequired, [StringComparison]::OrdinalIgnoreCase)
            }
        )
        if ($exact.Count -ne 1 -or $equivalent.Count -ne 1) {
            throw "The archive must contain '$RequiredPath' exactly once with no case, separator, or duplicate equivalent; found $($exact.Count) exact and $($equivalent.Count) equivalent entries."
        }
    }

    function New-GraphKitAuthArchiveFixture {
        param(
            [Parameter(Mandatory)] [string] $Path,
            [Parameter(Mandatory)] [string[]] $Entries
        )

        $archive = [System.IO.Compression.ZipFile]::Open($Path, [System.IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($entryName in $Entries) {
                $null = $archive.CreateEntry($entryName)
            }
        }
        finally {
            $archive.Dispose()
        }

        $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
        try {
            return @($archive.Entries.FullName)
        }
        finally {
            $archive.Dispose()
        }
    }
}

Describe 'Packed GraphKit.Auth boundary' -Tag 'QA' {
    It 'rejects an exact path plus a <Kind>' -ForEach $graphKitAuthArchiveAliasCases {
        $fixturePath = Join-Path $TestDrive ("graphkit-auth-$($Kind.Replace(' ', '-')).zip")
        $entries = @(New-GraphKitAuthArchiveFixture -Path $fixturePath -Entries $Entries)

        { Assert-GraphKitAuthArchiveEntry -Entries $entries -RequiredPath 'Assemblies/GraphKit.Auth/GraphKit.Auth.Contracts.dll' } |
            Should -Throw
    }

    It 'contains the exact required path <Path>' -ForEach $requiredGraphKitAuthCases {
        $script:packagePath | Should -Not -BeNullOrEmpty -Because 'pack must produce a versioned GraphKit candidate'
        Test-Path -LiteralPath $script:packagePath -PathType Leaf | Should -BeTrue -Because 'the package boundary is tested against the packed candidate'

        Assert-GraphKitAuthArchiveEntry -Entries $script:packageEntries -RequiredPath $Path
        Test-Path -LiteralPath (Join-Path $script:builtModuleRoot $Path) -PathType Leaf |
            Should -BeTrue -Because "the packed path '$Path' must originate in the built module"
    }
}
