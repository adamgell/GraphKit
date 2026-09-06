BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $readme = Get-Content -LiteralPath (Join-Path $repoRoot 'README.md') -Raw
    $agents = Get-Content -LiteralPath (Join-Path $repoRoot 'AGENTS.md') -Raw
    $changelog = Get-Content -LiteralPath (Join-Path $repoRoot 'CHANGELOG.md') -Raw
    $integrationPlan = Get-Content -LiteralPath (Join-Path $repoRoot 'docs/superpowers/plans/2026-08-29-graphkit-0.3.0-integration.md') -Raw
    $manifestPath = Join-Path $repoRoot 'source/GraphKit.psd1'
    $maintenanceScopes = @($readme, $agents, $changelog)

    $readmeCurrentRelease = [regex]::Match(
        $readme,
        '(?ms)^GraphKit `0\.3\.0` is the current immutable release on PSGallery.*?(?=\r?\n\r?\n)'
    ).Value
    $agentsCurrentRelease = [regex]::Match(
        $agents,
        '(?ms)^\*\*Current release status:\*\* GraphKit `0\.3\.0` is the current immutable release on PSGallery.*?(?=\r?\n\r?\n)'
    ).Value
    $changelogCurrentRelease = [regex]::Match(
        $changelog,
        '(?ms)^## \[0\.3\.0\] - 2026-08-30\r?\n\r?\nGraphKit `0\.3\.0` was published.*?(?=\r?\n\r?\n### )'
    ).Value

    $releaseEvidencePatterns = @(
        '2026-08-30T04:38:20\.12Z',
        '207381-byte public\s+archive',
        '45319d7cf4f8333697343ccf9c1089c7e04da87a8df62553cbc140089337536d',
        'a0f0e92a054fe2976ca74a844f5de6161e1b8c67',
        'a1b0b8d54c17671761ef5aee017a453b072d1fe9',
        '33292245900',
        '33292580847',
        '772 tests',
        'six Windows/macOS/Ubuntu PowerShell 7\.4/7\.6 jobs'
    )

    function Assert-CurrentReleaseEvidence {
        param(
            [Parameter(Mandatory)] [string] $Text,
            [Parameter(Mandatory)] [string] $Location
        )

        $Text | Should -Not -BeNullOrEmpty -Because "$Location must expose a current 0.3.0 release scope."
        foreach ($pattern in $releaseEvidencePatterns) {
            $Text | Should -Match $pattern -Because "$Location must retain every verified current-release field."
        }
        $Text | Should -Not -Match '(?i)\b(?:candidate|unpublished)\b' -Because (
            "$Location must not describe the published current release as a candidate or unpublished."
        )
    }
}

Describe 'GraphKit current release truth' -Tag 'QA' {
    It 'records every verified field in the scoped README current-release text' {
        Assert-CurrentReleaseEvidence -Text $readmeCurrentRelease -Location 'README release status'
    }

    It 'records every verified field in the scoped operator current-release text' {
        Assert-CurrentReleaseEvidence -Text $agentsCurrentRelease -Location 'AGENTS current release status'
    }

    It 'records every verified field in the scoped changelog current-release text' {
        $changelogCurrentRelease | Should -Match '^## \[0\.3\.0\] - 2026-08-30'
        Assert-CurrentReleaseEvidence -Text $changelogCurrentRelease -Location 'CHANGELOG 0.3.0 release section'
    }

    It 'preserves the immutable 0.3.0 publication evidence while identifying 0.3.1 as unpublished maintenance work' {
        foreach ($scope in $maintenanceScopes) {
            $scope | Should -Match '(?is)0\.3\.1.*(?:maintenance|bridge).*(?:candidate|unpublished|not published)'
        }

        $manifest = Import-PowerShellDataFile $manifestPath
        [string] $manifest.ModuleVersion | Should -Be '0.3.1'
        [string] $manifest.PrivateData.PSData.ReleaseNotes | Should -Match '^0\.3\.1(?:\r?\n)'
        [string] $manifest.PrivateData.PSData.Prerelease | Should -BeNullOrEmpty
    }

    It 'marks the dated integration plan as executed and superseded by publication evidence' {
        $integrationPlan | Should -Match 'Status:\s*Completed and published'
        $integrationPlan | Should -Match '33292245900'
        $integrationPlan | Should -Match '33292580847'
    }
}
