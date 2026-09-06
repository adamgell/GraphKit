BeforeAll {
    $repoRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $built = Get-ChildItem -Path (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $built) {
        throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first, then re-run the tests.'
    }
    $script:manifestPath = Join-Path $built.FullName 'GraphKit.psd1'
    Import-Module $script:manifestPath -Force
}

Describe 'Test-GraphMsalVersion' {

    It 'accepts the tested minimum exactly' {
        InModuleScope GraphKit {
            Test-GraphMsalVersion -Loaded '4.82.1' | Should -BeTrue
            Test-GraphMsalVersion -Loaded ([version] '4.82.1.0') | Should -BeTrue
        }
    }

    It 'accepts a version newer than the tested minimum' {
        InModuleScope GraphKit {
            Test-GraphMsalVersion -Loaded '5.0.0' | Should -BeTrue
        }
    }

    It 'rejects a version below the tested minimum' {
        InModuleScope GraphKit {
            Test-GraphMsalVersion -Loaded '4.0.0' | Should -BeFalse
            Test-GraphMsalVersion -Loaded '4.61.3' | Should -BeFalse
        }
    }

    It 'rejects an absent (null) version' {
        InModuleScope GraphKit {
            Test-GraphMsalVersion -Loaded $null | Should -BeFalse
        }
    }

    It 'rejects a non-version string rather than throwing' {
        InModuleScope GraphKit {
            Test-GraphMsalVersion -Loaded 'not-a-version' | Should -BeFalse
        }
    }
}

Describe 'Get-GraphLoadedMsalVersion' {

    It 'returns a parseable version at or above the tested minimum on this host' {
        InModuleScope GraphKit {
            $version = Get-GraphLoadedMsalVersion
            $version | Should -Not -BeNullOrEmpty
            ($version -is [version]) | Should -BeTrue
            Test-GraphMsalVersion -Loaded $version | Should -BeTrue -Because 'the host must carry a compliant MSAL copy'
        }
    }

    It 'resolves the SDK assembly path to an existing file on this host' {
        InModuleScope GraphKit {
            $path = Get-GraphMsalSdkAssemblyPath
            $path | Should -Not -BeNullOrEmpty
            (Test-Path -LiteralPath $path) | Should -BeTrue -Because 'the guard must locate the SDK-delivered MSAL assembly'
        }
    }

    It '<TypeName> exposes WithForceRefresh(Boolean)' -ForEach @(
        @{ TypeName = 'AcquireTokenForClientParameterBuilder' }
        @{ TypeName = 'AcquireTokenForManagedIdentityParameterBuilder' }
    ) {
        $assembly = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GetName().Name -eq 'Microsoft.Identity.Client' } |
            Select-Object -First 1
        $type = $assembly.GetTypes() | Where-Object Name -eq $TypeName
        $method = $type.GetMethod('WithForceRefresh', [type[]] @([bool]))

        $method | Should -Not -BeNullOrEmpty -Because 'GraphKit must propagate a 401 refresh through the exact loaded MSAL builder surface'
        $method.ReturnType | Should -Be $type
    }
}

Describe 'Import-time guard' {

    It 'imported the module without throwing (the guard already ran in this process)' {
        Get-Module GraphKit | Should -Not -BeNullOrEmpty
    }

    It 're-imports without throwing (the guard is idempotent)' {
        { Import-Module $script:manifestPath -Force -ErrorAction Stop } | Should -Not -Throw
        Get-Module GraphKit | Should -Not -BeNullOrEmpty
    }
}
