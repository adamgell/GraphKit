BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built GraphKit module found under output/module/GraphKit; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force
}

Describe 'Test-GraphPathContainment' {
    It 'allows a legit nested path' {
        InModuleScope GraphKit -ArgumentList $TestDrive {
            param($Root)

            Test-GraphPathContainment -Root (Join-Path $Root 'evi') -Candidate (Join-Path $Root 'evi/sub/deep')
        } | Should -BeTrue
    }

    It 'allows a candidate equal to the root' {
        InModuleScope GraphKit -ArgumentList $TestDrive {
            param($Root)

            Test-GraphPathContainment -Root (Join-Path $Root 'evi') -Candidate (Join-Path $Root 'evi')
        } | Should -BeTrue
    }

    It 'normalizes trailing separators' {
        InModuleScope GraphKit -ArgumentList $TestDrive {
            param($Root)

            $candidate = (Join-Path $Root 'evi/sub') + [System.IO.Path]::DirectorySeparatorChar
            Test-GraphPathContainment -Root ((Join-Path $Root 'evi') + [System.IO.Path]::DirectorySeparatorChar) -Candidate $candidate
        } | Should -BeTrue
    }

    It 'blocks a ../ escape' {
        InModuleScope GraphKit -ArgumentList $TestDrive {
            param($Root)

            Test-GraphPathContainment -Root (Join-Path $Root 'evi') -Candidate (Join-Path $Root 'evi/sub/../../outside')
        } | Should -BeFalse
    }

    It 'blocks an absolute path outside the root' {
        InModuleScope GraphKit -ArgumentList $TestDrive {
            param($Root)

            Test-GraphPathContainment -Root (Join-Path $Root 'evi') -Candidate (Join-Path $Root 'other')
        } | Should -BeFalse
    }

    It 'does not treat a sibling prefix as contained' {
        InModuleScope GraphKit -ArgumentList $TestDrive {
            param($Root)

            Test-GraphPathContainment -Root (Join-Path $Root 'evi') -Candidate (Join-Path $Root 'evi-evil/x')
        } | Should -BeFalse
    }

    It 'rejects an empty root' {
        InModuleScope GraphKit {
            Test-GraphPathContainment -Root '' -Candidate '/tmp/x'
        } | Should -BeFalse
    }

    It 'rejects an empty candidate' {
        InModuleScope GraphKit {
            Test-GraphPathContainment -Root '/tmp' -Candidate ''
        } | Should -BeFalse
    }
 }
