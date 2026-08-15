BeforeAll {
    $repoRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $built = Get-ChildItem -Path (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $built) {
        throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first, then re-run the tests.'
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force
}

Describe 'Save-GraphProfileStore' {

    It 'writes atomically and retains the previous generation as .bak' {
        InModuleScope GraphKit -Parameters @{ Path = (Join-Path $TestDrive 'profiles.json') } {
            Save-GraphProfileStore -Store @{ SchemaVersion = 1; Profiles = @(@{ ProfileId = 'a' }) } -StorePath $Path
            Test-Path -LiteralPath $Path | Should -BeTrue
            Test-Path -LiteralPath "$Path.bak" | Should -BeFalse

            Save-GraphProfileStore -Store @{ SchemaVersion = 1; Profiles = @(@{ ProfileId = 'a' }, @{ ProfileId = 'b' }) } -StorePath $Path
            Test-Path -LiteralPath "$Path.bak" | Should -BeTrue

            $bak = Get-Content -LiteralPath "$Path.bak" -Raw | ConvertFrom-Json -AsHashtable
            @($bak.Profiles).Count | Should -Be 1

            $current = Get-GraphProfileStore -StorePath $Path
            @($current.Profiles).Count | Should -Be 2
        }
    }

    It 'never leaves a half-written store or a stray temp file' {
        InModuleScope GraphKit -Parameters @{ Path = (Join-Path $TestDrive 'atomic.json') } {
            Save-GraphProfileStore -Store @{ SchemaVersion = 1; Profiles = @(@{ ProfileId = 'x' }) } -StorePath $Path
            Save-GraphProfileStore -Store @{ SchemaVersion = 1; Profiles = @(@{ ProfileId = 'x' }, @{ ProfileId = 'y' }) } -StorePath $Path

            $store = Get-GraphProfileStore -StorePath $Path
            @($store.Profiles).Count | Should -Be 2

            $tempFiles = @(Get-ChildItem -Path (Split-Path $Path -Parent) -Filter "$(Split-Path $Path -Leaf).tmp.*" -ErrorAction SilentlyContinue)
            $tempFiles.Count | Should -Be 0
        }
    }
}

Describe 'GraphProfileStoreLock' {

    It 'serializes access via the .lock sidecar and errors after the bounded retry' {
        InModuleScope GraphKit -Parameters @{ Path = (Join-Path $TestDrive 'locked.json') } {
            $first = Enter-GraphProfileStoreLock -StorePath $Path
            try {
                { Enter-GraphProfileStoreLock -StorePath $Path } | Should -Throw -ExpectedMessage '*Could not acquire the profile store lock*'
            }
            finally {
                Exit-GraphProfileStoreLock -Lock $first
            }

            # After release a fresh acquisition succeeds.
            $second = Enter-GraphProfileStoreLock -StorePath $Path
            Exit-GraphProfileStoreLock -Lock $second
        }
    }
}
