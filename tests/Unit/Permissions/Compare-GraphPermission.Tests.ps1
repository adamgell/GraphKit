BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    # Import the BUILT module (never dot-source source files). Pester discovers
    # tests per file, so each file imports the module in its own BeforeAll.
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built GraphKit module found under output/module/GraphKit; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force
}

Describe 'Compare-GraphPermission' {

    It 'returns Missing for baseline entries absent from Actual' {
        $baseline = @(
            @{ Type = 'Application'; Value = 'A.Read.All' },
            @{ Type = 'Application'; Value = 'B.Read.All' }
        )
        $actual = @(
            @{ Type = 'Application'; Value = 'A.Read.All' }
        )

        $result = Compare-GraphPermission -Baseline $baseline -Actual $actual

        @($result.Missing).Count | Should -Be 1
        $result.Missing[0].Value | Should -Be 'B.Read.All'
        @($result.Extra).Count | Should -Be 0
        @($result.Matched).Count | Should -Be 1
    }

    It 'returns Extra for Actual entries absent from Baseline' {
        $baseline = @(
            @{ Type = 'Application'; Value = 'A.Read.All' }
        )
        $actual = @(
            @{ Type = 'Application'; Value = 'A.Read.All' },
            @{ Type = 'Application'; Value = 'Surplus.Role' }
        )

        $result = Compare-GraphPermission -Baseline $baseline -Actual $actual

        @($result.Extra).Count | Should -Be 1
        $result.Extra[0].Value | Should -Be 'Surplus.Role'
        @($result.Missing).Count | Should -Be 0
        @($result.Matched).Count | Should -Be 1
    }

    It 'matches Type and Value case-insensitively' {
        $baseline = @(
            @{ Type = 'application'; Value = 'a.read.all' }
        )
        $actual = @(
            @{ Type = 'Application'; Value = 'A.Read.All' }
        )

        $result = Compare-GraphPermission -Baseline $baseline -Actual $actual

        @($result.Matched).Count | Should -Be 1
        @($result.Missing).Count | Should -Be 0
        @($result.Extra).Count | Should -Be 0
    }

    It 'distinguishes entries by Type as well as Value' {
        $baseline = @(
            @{ Type = 'Application'; Value = 'Same.Name' }
        )
        $actual = @(
            @{ Type = 'Delegated'; Value = 'Same.Name' }
        )

        $result = Compare-GraphPermission -Baseline $baseline -Actual $actual

        @($result.Missing).Count | Should -Be 1
        @($result.Extra).Count | Should -Be 1
        @($result.Matched).Count | Should -Be 0
    }

    It 'returns empty lists when both sets are empty' {
        $result = Compare-GraphPermission -Baseline @() -Actual @()

        @($result.Missing).Count | Should -Be 0
        @($result.Extra).Count | Should -Be 0
        @($result.Matched).Count | Should -Be 0
    }
}
