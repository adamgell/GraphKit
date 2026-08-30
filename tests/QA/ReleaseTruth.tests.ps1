BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $readme = Get-Content -LiteralPath (Join-Path $repoRoot 'README.md') -Raw
    $agents = Get-Content -LiteralPath (Join-Path $repoRoot 'AGENTS.md') -Raw
    $changelog = Get-Content -LiteralPath (Join-Path $repoRoot 'CHANGELOG.md') -Raw
    $integrationPlan = Get-Content -LiteralPath (Join-Path $repoRoot 'docs/superpowers/plans/2026-08-29-graphkit-0.3.0-integration.md') -Raw
    $manifestPath = Join-Path $repoRoot 'source/GraphKit.psd1'
}

Describe 'GraphKit current release truth' -Tag 'QA' {
    It 'records the immutable public GraphKit 0.3.0 archive' {
        $readme | Should -Match 'GraphKit `0\.3\.0` is the current immutable release on PSGallery'
        $readme | Should -Match '45319d7cf4f8333697343ccf9c1089c7e04da87a8df62553cbc140089337536d'
    }

    It 'records exact merged-main and CI evidence in operator guidance' {
        $agents | Should -Match 'a1b0b8d54c17671761ef5aee017a453b072d1fe9'
        $agents | Should -Match '33292580847'
        $agents | Should -Match '772'
    }

    It 'does not claim the current 0.3.0 release is unpublished' {
        @($readme, $agents, $changelog) -join "`n" | Should -Not -Match '(?i)0\.3\.0.{0,80}unpublished|unpublished.{0,80}0\.3\.0'
    }

    It 'preserves the immutable released manifest identity' {
        $manifest = Import-PowerShellDataFile $manifestPath
        [string] $manifest.ModuleVersion | Should -Be '0.3.0'
        [string] $manifest.PrivateData.PSData.ReleaseNotes | Should -Match '^0\.3\.0(?:\r?\n)'
    }

    It 'marks the dated integration plan as executed and superseded by publication evidence' {
        $integrationPlan | Should -Match 'Status:\s*Completed and published'
        $integrationPlan | Should -Match '33292245900'
        $integrationPlan | Should -Match '33292580847'
    }
}
