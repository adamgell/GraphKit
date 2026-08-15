BeforeAll {
    $repoRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $built = Get-ChildItem -Path (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $built) {
        throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first, then re-run the tests.'
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force
}

Describe 'Get-GraphProfileStore' {

    It 'returns an empty store for a missing file' {
        InModuleScope GraphKit -Parameters @{ StorePath = (Join-Path $TestDrive 'missing.json') } {
            $store = Get-GraphProfileStore -StorePath $StorePath
            $store.SchemaVersion | Should -Be 1
            @($store.Profiles).Count | Should -Be 0
        }
    }

    It 'round-trips a persisted store' {
        $path = Join-Path $TestDrive 'profiles.json'
        Set-Content -LiteralPath $path -Value '{"SchemaVersion":1,"Profiles":[{"ProfileId":"acme","Name":"Acme","Credential":{"VaultName":"v","SecretName":"s"}}]}'

        $store = InModuleScope GraphKit -Parameters @{ StorePath = $path } {
            Get-GraphProfileStore -StorePath $StorePath
        }
        $store.SchemaVersion | Should -Be 1
        @($store.Profiles).Count | Should -Be 1
        $store.Profiles[0].ProfileId | Should -Be 'acme'
    }

    It 'refuses a newer SchemaVersion with an actionable error naming both versions' {
        $path = Join-Path $TestDrive 'newer.json'
        Set-Content -LiteralPath $path -Value '{"SchemaVersion":42,"Profiles":[]}'

        { InModuleScope GraphKit -Parameters @{ StorePath = $path } { Get-GraphProfileStore -StorePath $StorePath } } |
            Should -Throw -ExpectedMessage '*SchemaVersion 42*newer*'
    }

    It 'reports the backup location when the primary store fails to parse' {
        $path = Join-Path $TestDrive 'corrupt.json'
        Set-Content -LiteralPath $path -Value '{ not valid json '
        Set-Content -LiteralPath "$path.bak" -Value '{}'

        { InModuleScope GraphKit -Parameters @{ StorePath = $path } { Get-GraphProfileStore -StorePath $StorePath } } |
            Should -Throw -ExpectedMessage '*could not be parsed*backup exists*'
    }

    It 'never silently recreates an empty store when parsing fails' {
        $path = Join-Path $TestDrive 'corrupt-no-backup.json'
        Set-Content -LiteralPath $path -Value '{ broken'

        { InModuleScope GraphKit -Parameters @{ StorePath = $path } { Get-GraphProfileStore -StorePath $StorePath } } |
            Should -Throw
        Test-Path -LiteralPath $path | Should -BeTrue
    }
}
