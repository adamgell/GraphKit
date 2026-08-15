BeforeAll {
    $repoRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $built = Get-ChildItem -Path (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $built) {
        throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first, then re-run the tests.'
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force
}

Describe 'Test-GraphProfileId' {

    It 'accepts valid canonical identifiers' {
        InModuleScope GraphKit {
            Test-GraphProfileId -ProfileId 'ivy24' | Should -BeTrue
            Test-GraphProfileId -ProfileId 'a-b-c' | Should -BeTrue
            Test-GraphProfileId -ProfileId 'a' | Should -BeTrue
            Test-GraphProfileId -ProfileId ('a' + ('b' * 62)) | Should -BeTrue
            Test-GraphProfileId -ProfileId ('a' + ('b' * 63)) | Should -BeTrue
        }
    }

    It 'rejects invalid identifiers' {
        InModuleScope GraphKit {
            Test-GraphProfileId -ProfileId 'IVY24' | Should -BeFalse
            Test-GraphProfileId -ProfileId '-abc' | Should -BeFalse
            Test-GraphProfileId -ProfileId 'abc_' | Should -BeFalse
            Test-GraphProfileId -ProfileId 'abc def' | Should -BeFalse
            Test-GraphProfileId -ProfileId '' | Should -BeFalse
            Test-GraphProfileId -ProfileId ('a' + ('b' * 64)) | Should -BeFalse
        }
    }
}
