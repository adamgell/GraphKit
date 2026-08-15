BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built GraphKit module found under output/module/GraphKit; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force
}

Describe 'New-GraphEvidenceSummary' {
    It 'round-trips the declared fields into a typed DTO' {
        $summary = InModuleScope GraphKit -ArgumentList ([datetime]::UtcNow) {
            param($Now)

            New-GraphEvidenceSummary -Fields @{
                ProfileId    = 'ivy24'
                Name         = 'Ivy24 Lab'
                Kind         = 'lab'
                GeneratedUtc = $Now
                SourcePaths  = @('/tmp/a.json', '/tmp/b.json')
                Counts       = @{ rows = 3 }
                Notes        = @('rolled up from two runs')
            }
        }

        $summary.ProfileId | Should -Be 'ivy24'
        $summary.Kind | Should -Be 'lab'
        $summary.SourcePaths.Count | Should -Be 2
        $summary.Counts['rows'] | Should -Be 3
        $summary.Notes.Count | Should -Be 1
        $summary.PSObject.TypeNames | Should -Contain 'GraphKit.EvidenceSummary'
    }

    It 'rejects an unknown field that is not on the allowlist' {
        {
            InModuleScope GraphKit {
                New-GraphEvidenceSummary -Fields @{ ProfileId = 'ivy24'; SerialNumber = 'ABC123' }
            }
        } | Should -Throw -ExpectedMessage '*not on the declared allowlist*'
    }

    It 'rejects a client-secret field name via the credential assertion' {
        {
            InModuleScope GraphKit {
                New-GraphEvidenceSummary -Fields @{ ProfileId = 'ivy24'; ClientSecret = 'x' }
            }
        } | Should -Throw -ExpectedMessage '*credential pattern*'
    }

    It 'rejects a tenant-id field name via the credential assertion' {
        {
            InModuleScope GraphKit {
                New-GraphEvidenceSummary -Fields @{ ProfileId = 'ivy24'; TenantId = '00000000-0000-0000-0000-000000000000' }
            }
        } | Should -Throw -ExpectedMessage '*credential pattern*'
    }

    It 'rejects a bearer-token field name via the credential assertion' {
        {
            InModuleScope GraphKit {
                New-GraphEvidenceSummary -Fields @{ ProfileId = 'ivy24'; BearerToken = 'abc' }
            }
        } | Should -Throw -ExpectedMessage '*credential pattern*'
    }

    It 'rejects an empty ProfileId' {
        {
            InModuleScope GraphKit {
                New-GraphEvidenceSummary -Fields @{ ProfileId = '' }
            }
        } | Should -Throw -ExpectedMessage '*ProfileId*'
    }

    It 'defaults SourcePaths, Counts, and Notes to empty collections' {
        $summary = InModuleScope GraphKit {
            New-GraphEvidenceSummary -Fields @{ ProfileId = 'ivy24'; Name = 'x'; Kind = 'lab'; GeneratedUtc = ([datetime]::UtcNow) }
        }

        $summary.SourcePaths | Should -BeNullOrEmpty
        $summary.Notes | Should -BeNullOrEmpty
        $summary.Counts.Count | Should -Be 0
    }
}
