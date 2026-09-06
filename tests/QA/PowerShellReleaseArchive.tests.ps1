$officialPowerShellArchiveCases = @(
    @{ Version = '7.4.19'; Asset = 'PowerShell-7.4.19-win-arm64.zip'; Hash = 'ac3a0249c0cd9f5b55f198f681485099ea73f45838dfd676457571a94d793463' }
    @{ Version = '7.4.19'; Asset = 'PowerShell-7.4.19-win-x64.zip'; Hash = 'cd62ad6d8174cc6fb85b335a0058444bc934fe27c39fa97fe342134286d28af9' }
    @{ Version = '7.4.19'; Asset = 'powershell-7.4.19-linux-arm64.tar.gz'; Hash = '2b11aafacf574222abaf691a0b3b2d463e617d17fe337343c2fb93ea871a4691' }
    @{ Version = '7.4.19'; Asset = 'powershell-7.4.19-linux-x64.tar.gz'; Hash = '1b023e097b0e0546ad9566f7a2126cbe0eb8455fa7b0c5de558e317b8ddc16c8' }
    @{ Version = '7.4.19'; Asset = 'powershell-7.4.19-osx-arm64.tar.gz'; Hash = 'fb9d6656d0c78c6d3f6e8d08ff15e5e0d867f886bf4ebecfde6484d2fa06c042' }
    @{ Version = '7.4.19'; Asset = 'powershell-7.4.19-osx-x64.tar.gz'; Hash = 'bb67378d9b9d469d0c3863aa8a5576a38ad8eaa0fd7aae2c4819e7caf06cb79c' }
    @{ Version = '7.6.5'; Asset = 'PowerShell-7.6.5-win-arm64.zip'; Hash = '20514a755d16428dc4355c85e0883c859531e71cc3e122670aa1fccdbf96ba7e' }
    @{ Version = '7.6.5'; Asset = 'PowerShell-7.6.5-win-x64.zip'; Hash = '32eb8f6cdce08f86e987d625a2733e54ac3e289ae7e1621b14c0b5bcec2434ea' }
    @{ Version = '7.6.5'; Asset = 'powershell-7.6.5-linux-arm64.tar.gz'; Hash = 'ed4084f215d8bce2edd23aa7cb1f1e7b0818e41363a635a22065d2701b6141df' }
    @{ Version = '7.6.5'; Asset = 'powershell-7.6.5-linux-x64.tar.gz'; Hash = 'b34ab3b19acac1d3d4d0d3cfdb02acf62f457b0b6a962ff008132033f7566844' }
    @{ Version = '7.6.5'; Asset = 'powershell-7.6.5-osx-arm64.tar.gz'; Hash = '8196d4b4e7c21b7f6df9d45687bb4e42dc8335f330b580d9eb15f3ef5042a8c3' }
    @{ Version = '7.6.5'; Asset = 'powershell-7.6.5-osx-x64.tar.gz'; Hash = '3db1d177ab39511c1b6b73b05a1630a5db4e8dce22857ca76f14c5d98f2733fd' }
)

BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $script:hashMapPath = Join-Path $script:repoRoot '.github/powershell-release-sha256.json'
    $script:installerPath = Join-Path $script:repoRoot '.github/scripts/Install-VerifiedPowerShellArchive.ps1'

    function New-TestPowerShellHashMap {
        param(
            [Parameter(Mandatory)][string] $Root,
            [Parameter(Mandatory)][string] $Version,
            [Parameter(Mandatory)][string] $Asset,
            [Parameter(Mandatory)][string] $Hash
        )

        $path = Join-Path $Root ('hash-map-' + [guid]::NewGuid().ToString('N') + '.json')
        [ordered]@{
            schemaVersion = 1
            provenance = [ordered]@{
                $Version = [ordered]@{
                    releaseUrl = "https://github.com/PowerShell/PowerShell/releases/tag/v$Version"
                    hashesUrl = "https://github.com/PowerShell/PowerShell/releases/download/v$Version/hashes.sha256"
                }
            }
            sha256 = [ordered]@{ "$Version/$Asset" = $Hash }
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path -Encoding utf8NoBOM
        return $path
    }
}

Describe 'Reviewed PowerShell release archive map' -Tag 'QA' {
    It 'binds <Version>/<Asset> to the official release checksum' -ForEach $officialPowerShellArchiveCases {
        Test-Path -LiteralPath $script:hashMapPath -PathType Leaf | Should -BeTrue
        if (-not (Test-Path -LiteralPath $script:hashMapPath -PathType Leaf)) { return }

        $map = Get-Content -LiteralPath $script:hashMapPath -Raw | ConvertFrom-Json -AsHashtable
        $key = "$Version/$Asset"
        $map.schemaVersion | Should -Be 1
        $map.sha256[$key] | Should -BeExactly $Hash
        $map.provenance[$Version].releaseUrl |
            Should -BeExactly "https://github.com/PowerShell/PowerShell/releases/tag/v$Version"
        $map.provenance[$Version].hashesUrl |
            Should -BeExactly "https://github.com/PowerShell/PowerShell/releases/download/v$Version/hashes.sha256"
    }

    It 'contains exactly the twelve archives dynamically selectable by CI' {
        Test-Path -LiteralPath $script:hashMapPath -PathType Leaf | Should -BeTrue
        if (-not (Test-Path -LiteralPath $script:hashMapPath -PathType Leaf)) { return }

        $map = Get-Content -LiteralPath $script:hashMapPath -Raw | ConvertFrom-Json -AsHashtable
        $ci = Get-Content -LiteralPath (Join-Path $script:repoRoot '.github/workflows/ci.yml') -Raw
        $matrixMatch = [regex]::Match($ci, '(?m)^\s*pwsh-version:\s*\[([^\]]+)\]')
        $matrixMatch.Success | Should -BeTrue
        $versions = @([regex]::Matches($matrixMatch.Groups[1].Value, '\d+\.\d+\.\d+') |
            ForEach-Object { $_.Value })
        $expectedKeys = @(
            foreach ($version in $versions) {
                "$version/PowerShell-$version-win-arm64.zip"
                "$version/PowerShell-$version-win-x64.zip"
                "$version/powershell-$version-linux-arm64.tar.gz"
                "$version/powershell-$version-linux-x64.tar.gz"
                "$version/powershell-$version-osx-arm64.tar.gz"
                "$version/powershell-$version-osx-x64.tar.gz"
            }
        )

        @($map.sha256.Keys).Count | Should -Be 12
        @(Compare-Object @($expectedKeys | Sort-Object) @($map.sha256.Keys | Sort-Object)).Count |
            Should -Be 0
        $ci | Should -Match '\$asset\s*=\s*"PowerShell-\$version-win-\$arch\.zip"'
        $ci | Should -Match '\$asset\s*=\s*"powershell-\$version-linux-\$arch\.tar\.gz"'
        $ci | Should -Match '\$asset\s*=\s*"powershell-\$version-osx-\$arch\.tar\.gz"'
    }
}

Describe 'Verified PowerShell release archive installation' -Tag 'QA' {
    It 'extracts an archive only when its bytes match the reviewed mapping' {
        $version = '9.9.9'
        $asset = 'PowerShell-9.9.9-win-x64.zip'
        $stage = Join-Path $TestDrive 'valid-stage'
        $archive = Join-Path $TestDrive $asset
        $install = Join-Path $TestDrive 'valid-install'
        $null = New-Item -ItemType Directory -Path $stage
        Set-Content -LiteralPath (Join-Path $stage 'pwsh-marker.txt') -Value 'verified archive' -NoNewline
        Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive
        $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        $map = New-TestPowerShellHashMap -Root $TestDrive -Version $version -Asset $asset -Hash $hash

        Test-Path -LiteralPath $script:installerPath -PathType Leaf | Should -BeTrue
        if (-not (Test-Path -LiteralPath $script:installerPath -PathType Leaf)) { return }
        & $script:installerPath -Version $version -AssetName $asset -ArchivePath $archive `
            -InstallDirectory $install -HashMapPath $map

        Get-Content -LiteralPath (Join-Path $install 'pwsh-marker.txt') -Raw |
            Should -BeExactly 'verified archive'
    }

    It 'rejects an archive with no exact version-and-asset mapping before extraction' {
        $version = '9.9.9'
        $asset = 'PowerShell-9.9.9-win-x64.zip'
        $caseRoot = Join-Path $TestDrive 'missing-case'
        $stage = Join-Path $caseRoot 'stage'
        $archive = Join-Path $caseRoot $asset
        $install = Join-Path $caseRoot 'install'
        $null = New-Item -ItemType Directory -Path $stage -Force
        Set-Content -LiteralPath (Join-Path $stage 'pwsh-marker.txt') -Value 'must not extract' -NoNewline
        Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive
        $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        $map = New-TestPowerShellHashMap -Root $caseRoot -Version $version `
            -Asset 'PowerShell-9.9.9-win-arm64.zip' -Hash $hash

        { & $script:installerPath -Version $version -AssetName $asset -ArchivePath $archive `
            -InstallDirectory $install -HashMapPath $map } |
            Should -Throw '*no reviewed SHA-256 mapping*'
        Test-Path -LiteralPath (Join-Path $install 'pwsh-marker.txt') | Should -BeFalse
    }

    It 'rejects a malformed reviewed digest before extraction' {
        $version = '9.9.9'
        $asset = 'PowerShell-9.9.9-win-x64.zip'
        $caseRoot = Join-Path $TestDrive 'malformed-case'
        $stage = Join-Path $caseRoot 'stage'
        $archive = Join-Path $caseRoot $asset
        $install = Join-Path $caseRoot 'install'
        $null = New-Item -ItemType Directory -Path $stage -Force
        Set-Content -LiteralPath (Join-Path $stage 'pwsh-marker.txt') -Value 'must not extract' -NoNewline
        Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive
        $map = New-TestPowerShellHashMap -Root $caseRoot -Version $version -Asset $asset -Hash 'not-a-digest'

        { & $script:installerPath -Version $version -AssetName $asset -ArchivePath $archive `
            -InstallDirectory $install -HashMapPath $map } |
            Should -Throw '*not a lowercase 64-character SHA-256*'
        Test-Path -LiteralPath (Join-Path $install 'pwsh-marker.txt') | Should -BeFalse
    }

    It 'rejects a digest mismatch before any archive entry is extracted' {
        $version = '9.9.9'
        $asset = 'PowerShell-9.9.9-win-x64.zip'
        $caseRoot = Join-Path $TestDrive 'mismatch-case'
        $stage = Join-Path $caseRoot 'stage'
        $archive = Join-Path $caseRoot $asset
        $install = Join-Path $caseRoot 'install'
        $null = New-Item -ItemType Directory -Path $stage -Force
        Set-Content -LiteralPath (Join-Path $stage 'pwsh-marker.txt') -Value 'must not extract' -NoNewline
        Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive
        $map = New-TestPowerShellHashMap -Root $caseRoot -Version $version -Asset $asset -Hash ('0' * 64)

        { & $script:installerPath -Version $version -AssetName $asset -ArchivePath $archive `
            -InstallDirectory $install -HashMapPath $map } |
            Should -Throw '*does not match its reviewed SHA-256*'
        Test-Path -LiteralPath (Join-Path $install 'pwsh-marker.txt') | Should -BeFalse
    }
}

Describe 'PowerShell CI archive verification wiring' -Tag 'QA' {
    It 'downloads, verifies and extracts as one gate before adding the runtime to PATH' {
        $ci = Get-Content -LiteralPath (Join-Path $script:repoRoot '.github/workflows/ci.yml') -Raw
        $downloadIndex = $ci.IndexOf('Invoke-WebRequest')
        $verifiedInstallIndex = $ci.IndexOf('Install-VerifiedPowerShellArchive.ps1')
        $pathIndex = $ci.IndexOf('$env:GITHUB_PATH')

        $downloadIndex | Should -BeGreaterOrEqual 0
        $verifiedInstallIndex | Should -BeGreaterThan $downloadIndex
        $pathIndex | Should -BeGreaterThan $verifiedInstallIndex
        $ci | Should -Match ([regex]::Escape('.github/powershell-release-sha256.json'))
        $ci | Should -Not -Match '(?m)^\s*(Expand-Archive|tar\s+-xzf)'
    }
}
