BeforeAll {
    $repoRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $built = Get-ChildItem -Path (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $built) {
        throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first, then re-run the tests.'
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force

    $script:tenantA = '3a4b5c6d-1111-2222-3333-444455556666'
    $script:tenantB = '9f8e7d6c-aaaa-bbbb-cccc-ddddeeeeffff'

    function New-LegacyFile {
        param([hashtable] $Content, [string] $Root)
        $path = Join-Path $Root ("legacy-{0}.json" -f [guid]::NewGuid())
        ($Content | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $path -Encoding utf8
        return $path
    }
}

Describe 'ConvertTo-GraphProfileIdSlug' {

    It 'collapses punctuation and case into a canonical id' {
        InModuleScope GraphKit {
            ConvertTo-GraphProfileIdSlug -Name 'Contoso Ltd. (Prod)' | Should -Be 'contoso-ltd-prod'
        }
    }

    It 'collapses runs of separators so spacing variants do not become different ids' {
        InModuleScope GraphKit {
            $a = ConvertTo-GraphProfileIdSlug -Name 'Contoso  Ltd   Prod'
            $b = ConvertTo-GraphProfileIdSlug -Name 'Contoso-Ltd-Prod'
            $a | Should -Be $b
        }
    }

    It 'never returns a leading or trailing hyphen' {
        InModuleScope GraphKit {
            $slug = ConvertTo-GraphProfileIdSlug -Name '  ***Acme***  '
            $slug | Should -Be 'acme'
        }
    }

    It 'truncates to the 64-character limit without leaving a trailing hyphen' {
        InModuleScope GraphKit {
            $slug = ConvertTo-GraphProfileIdSlug -Name (('a' * 63) + ' bcd')
            $slug.Length | Should -BeLessOrEqual 64
            $slug | Should -Not -Match '-$'
            Test-GraphProfileId -ProfileId $slug | Should -BeTrue
        }
    }

    It 'returns empty for a name with no usable characters, rather than inventing an id' {
        InModuleScope GraphKit {
            ConvertTo-GraphProfileIdSlug -Name '***' | Should -Be ''
        }
    }
}

Describe 'Import-GraphLegacyProfile' {

    Context 'parsing and refusal' {

        It 'rejects a file that is not JSON' {
            $path = Join-Path $TestDrive 'bad.json'
            'not json at all' | Set-Content -LiteralPath $path
            { Import-GraphLegacyProfile -Path $path } | Should -Throw -ExpectedMessage '*not valid JSON*'
        }

        It 'rejects a JSON document that is not an object' {
            $path = Join-Path $TestDrive 'array.json'
            '[1,2,3]' | Set-Content -LiteralPath $path
            { Import-GraphLegacyProfile -Path $path } | Should -Throw -ExpectedMessage '*JSON object at the top level*'
        }

        It 'refuses to import bearerTokens and says what to do instead' {
            # Secret material in plaintext. Relocating a secret is an operator decision;
            # the importer must not make it silently.
            $path = New-LegacyFile -Root $TestDrive -Content @{
                tenants      = @()
                bearerTokens = @(@{ name = 'x'; token = 'eyJabc' })
            }
            $report = Import-GraphLegacyProfile -Path $path -StorePath (Join-Path $TestDrive 's1.json')
            ($report.Blockers -join ' ') | Should -BeLike '*bearerTokens*'
            ($report.Blockers -join ' ') | Should -BeLike '*Set-Secret*'
            $report.ImportedIds | Should -BeNullOrEmpty
        }

        It 'reports unrecognised top-level keys instead of ignoring them' {
            # An unknown key is exactly where a credential could be hiding.
            $path = New-LegacyFile -Root $TestDrive -Content @{
                tenants      = @()
                mysteryField = 'something'
            }
            $report = Import-GraphLegacyProfile -Path $path -StorePath (Join-Path $TestDrive 's2.json')
            ($report.Blockers -join ' ') | Should -BeLike '*mysteryField*'
        }

        It 'throws when the file does not exist' {
            { Import-GraphLegacyProfile -Path (Join-Path $TestDrive 'nope.json') } |
                Should -Throw -ExpectedMessage '*was not found*'
        }
    }

    Context 'dry run' {

        It 'returns the full inventory and writes nothing under -WhatIf' {
            $store = Join-Path $TestDrive 'dryrun.json'
            $path = New-LegacyFile -Root $TestDrive -Content @{
                tenants = @(
                    @{ name = 'Acme Corp'; tenantId = $script:tenantA; clientId = [guid]::NewGuid().ToString(); authMethod = 'ClientSecret'; environment = 'Global' }
                )
            }

            $report = Import-GraphLegacyProfile -Path $path -StorePath $store -WhatIf

            $report.Planned.Count | Should -Be 1
            $report.Planned[0].ProfileId | Should -Be 'acme-corp'
            $report.Committed | Should -BeFalse
            Test-Path -LiteralPath $store | Should -BeFalse
        }
    }

    Context 'validation of individual entries' {

        It 'flags a non-GUID tenantId' {
            $path = New-LegacyFile -Root $TestDrive -Content @{
                tenants = @(@{ name = 'Bad'; tenantId = 'not-a-guid'; authMethod = 'Certificate'; certificateThumbprint = ('A' * 40) })
            }
            $report = Import-GraphLegacyProfile -Path $path -StorePath (Join-Path $TestDrive 's3.json')
            ($report.Planned[0].Reasons -join ' ') | Should -BeLike '*not a valid GUID*'
            $report.Planned[0].Importable | Should -BeFalse
        }

        It 'catches two legacy entries that collapse to the same ProfileId' {
            # Silently importing one and dropping the other would lose a tenant.
            $path = New-LegacyFile -Root $TestDrive -Content @{
                tenants = @(
                    @{ name = 'Acme Corp'; tenantId = $script:tenantA; authMethod = 'ClientSecret'; environment = 'Global' }
                    @{ name = 'ACME  CORP'; tenantId = $script:tenantB; authMethod = 'ClientSecret'; environment = 'Global' }
                )
            }
            $report = Import-GraphLegacyProfile -Path $path -StorePath (Join-Path $TestDrive 's4.json')
            ($report.Planned[1].Reasons -join ' ') | Should -BeLike '*both map to ProfileId*'
        }

        It 'refuses an entry whose ProfileId already exists in the store' {
            $store = Join-Path $TestDrive 'existing.json'
            Register-GraphTenant -ProfileId 'acme-corp' -Name 'Acme Corp' -Kind customer -TenantId $script:tenantB `
                -Environment Global -AuthMethod ClientSecret -ClientId '11111111-2222-3333-4444-555555555555' `
                -VaultName v -SecretName s -StorePath $store

            $path = New-LegacyFile -Root $TestDrive -Content @{
                tenants = @(@{ name = 'Acme Corp'; tenantId = $script:tenantA; authMethod = 'ClientSecret'; environment = 'Global' })
            }
            $report = Import-GraphLegacyProfile -Path $path -StorePath $store
            ($report.Planned[0].Reasons -join ' ') | Should -BeLike '*already exists*'
        }

        It 'marks ClientSecret and BearerToken entries as needing manual vault placement' {
            # The legacy file carries no secret for them, so an "imported" profile would
            # be one that cannot authenticate - worse than not importing it.
            $path = New-LegacyFile -Root $TestDrive -Content @{
                tenants = @(@{ name = 'Secret Tenant'; tenantId = $script:tenantA; authMethod = 'ClientSecret'; environment = 'Global' })
            }
            $report = Import-GraphLegacyProfile -Path $path -StorePath (Join-Path $TestDrive 's5.json')
            ($report.Planned[0].Reasons -join ' ') | Should -BeLike '*vault-backed credential material*'
        }

        It 'canonicalises authMethod and environment casing from the legacy file' {
            # The real IHA secrets.json writes 'certificate' lowercase. -in and ValidateSet
            # are both case-insensitive, so a raw pass-through would persist non-canonical
            # casing into the store and leave any ordinal comparison downstream to fail.
            $path = New-LegacyFile -Root $TestDrive -Content @{
                tenants = @(@{ name = 'Lower'; tenantId = $script:tenantA; authMethod = 'managedidentity'; environment = 'global' })
            }
            $report = Import-GraphLegacyProfile -Path $path -StorePath (Join-Path $TestDrive 's8.json') -WhatIf
            $report.Planned[0].AuthMethod | Should -BeExactly 'ManagedIdentity'
            $report.Planned[0].Environment | Should -BeExactly 'Global'
        }

        It 'assigns lab kind by name and the default kind to everything else' {
            # The heuristic keys on the word 'lab', not on any particular tenant name. It
            # previously special-cased a private lab tenant, which a public module has no
            # business knowing about.
            $path = New-LegacyFile -Root $TestDrive -Content @{
                tenants = @(
                    @{ name = 'Contoso Lab'; tenantId = $script:tenantA; authMethod = 'Certificate'; certificateThumbprint = ('A' * 40); environment = 'Global' }
                    @{ name = 'Northwind'; tenantId = $script:tenantB; authMethod = 'Certificate'; certificateThumbprint = ('B' * 40); environment = 'Global' }
                )
            }
            $report = Import-GraphLegacyProfile -Path $path -StorePath (Join-Path $TestDrive 's6.json') -WhatIf
            ($report.Planned | Where-Object LegacyName -eq 'Contoso Lab').Kind | Should -Be 'lab'
            ($report.Planned | Where-Object LegacyName -eq 'Northwind').Kind | Should -Be 'customer'
        }

        It 'does not treat a name merely containing the letters l-a-b as a lab' {
            # Word-boundary matching: 'Elaborate Corp' is not a lab tenant. Without \b this
            # silently misclassifies a customer, and the kind drives taxonomy checks.
            $path = New-LegacyFile -Root $TestDrive -Content @{
                tenants = @(@{ name = 'Elaborate Corp'; tenantId = $script:tenantA; authMethod = 'ManagedIdentity'; environment = 'Global' })
            }
            $report = Import-GraphLegacyProfile -Path $path -StorePath (Join-Path $TestDrive 's6b.json') -WhatIf
            $report.Planned[0].Kind | Should -Be 'customer'
        }
    }

    Context 'platform gate for certificate-store entries' {

        It 'handles certificate-store profiles according to platform support' {
            # Register-GraphTenant refuses store-based certificate material off Windows.
            # The importer surfaces that up front so the dry run stays useful on macOS,
            # rather than letting it throw halfway through a transaction.
            #
            # This asserts per-platform behaviour in one test rather than a pair of -Skip
            # tests, so CI on Windows genuinely exercises the Windows branch and the suite
            # reports zero skips - a skipped test turns the whole NUnit result to 'Ignored'.
            $store = Join-Path $TestDrive 'platform.json'
            $path = New-LegacyFile -Root $TestDrive -Content @{
                tenants = @(@{ name = 'Winonly'; tenantId = $script:tenantA; authMethod = 'Certificate'; certificateThumbprint = ('A' * 40); certificateStore = 'CurrentUser'; environment = 'Global' })
            }
            $report = Import-GraphLegacyProfile -Path $path -StorePath $store

            if ($IsWindows) {
                $report.Committed | Should -BeTrue
                $report.ImportedIds | Should -Contain 'winonly'
            }
            else {
                ($report.Planned[0].Reasons -join ' ') | Should -BeLike '*only be registered on Windows*'
                $report.Planned[0].Importable | Should -BeFalse
                $report.Committed | Should -BeFalse
            }
        }
    }

    Context 'transactional commit' {

        It 'imports every valid profile in one commit' {
            $store = Join-Path $TestDrive 'commit.json'
            $path = New-LegacyFile -Root $TestDrive -Content @{
                tenants = @(
                    @{ name = 'Alpha'; tenantId = $script:tenantA; authMethod = 'ManagedIdentity'; environment = 'Global' }
                    @{ name = 'Beta'; tenantId = $script:tenantB; authMethod = 'ManagedIdentity'; environment = 'Global' }
                )
            }
            $report = Import-GraphLegacyProfile -Path $path -StorePath $store

            $report.Committed | Should -BeTrue
            $report.ImportedIds | Should -Be @('alpha', 'beta')
            @((Get-GraphTenant -StorePath $store)).Count | Should -Be 2
        }

        It 'rolls the whole import back when a later profile fails, leaving no partial state' {
            # A partial import is the one outcome that must not happen: it produces a store
            # that looks migrated and is not.
            $store = Join-Path $TestDrive 'rollback.json'
            $path = New-LegacyFile -Root $TestDrive -Content @{
                tenants = @(
                    @{ name = 'Alpha'; tenantId = $script:tenantA; authMethod = 'ManagedIdentity'; environment = 'Global' }
                    @{ name = 'Beta'; tenantId = $script:tenantB; authMethod = 'ManagedIdentity'; environment = 'Global' }
                )
            }

            # The mock writes the store through the module's own private helpers rather
            # than delegating to Register-GraphTenant, which is itself mocked and would
            # recurse. The first profile must genuinely reach disk or the rollback under
            # test proves nothing.
            Mock -ModuleName GraphKit -CommandName Register-GraphTenant -MockWith {
                if ($ProfileId -eq 'beta') { throw 'simulated failure on the second profile' }
                $lock = Enter-GraphProfileStoreLock -StorePath $StorePath
                try {
                    $store = Get-GraphProfileStore -StorePath $StorePath
                    $store.Profiles = @($store.Profiles) + ([pscustomobject]@{ ProfileId = $ProfileId; Name = $Name })
                    Save-GraphProfileStore -Store $store -StorePath $StorePath
                }
                finally { Exit-GraphProfileStoreLock -Lock $lock }
            }

            $report = Import-GraphLegacyProfile -Path $path -StorePath $store

            $report.Outcome | Should -Be 'RolledBack'
            $report.Committed | Should -BeFalse
            ($report.Blockers -join ' ') | Should -BeLike '*Rollback complete*'
            # The store existed nowhere before the import, so rollback means it is gone.
            Test-Path -LiteralPath $store | Should -BeFalse
        }

        It 'restores previous contents when the store already had profiles' {
            $store = Join-Path $TestDrive 'rollback-existing.json'
            Register-GraphTenant -ProfileId 'preexisting' -Name 'Pre Existing' -Kind lab -TenantId $script:tenantB `
                -Environment Global -AuthMethod ManagedIdentity -StorePath $store
            $before = Get-Content -LiteralPath $store -Raw

            $path = New-LegacyFile -Root $TestDrive -Content @{
                tenants = @(
                    @{ name = 'Alpha'; tenantId = $script:tenantA; authMethod = 'ManagedIdentity'; environment = 'Global' }
                    @{ name = 'Beta'; tenantId = $script:tenantB; authMethod = 'ManagedIdentity'; environment = 'Global' }
                )
            }

            Mock -ModuleName GraphKit -CommandName Register-GraphTenant -MockWith {
                if ($ProfileId -eq 'beta') { throw 'simulated failure' }
                $lock = Enter-GraphProfileStoreLock -StorePath $StorePath
                try {
                    $store = Get-GraphProfileStore -StorePath $StorePath
                    $store.Profiles = @($store.Profiles) + ([pscustomobject]@{ ProfileId = $ProfileId; Name = $Name })
                    Save-GraphProfileStore -Store $store -StorePath $StorePath
                }
                finally { Exit-GraphProfileStoreLock -Lock $lock }
            }

            $report = Import-GraphLegacyProfile -Path $path -StorePath $store

            $report.Outcome | Should -Be 'RolledBack'
            (Get-Content -LiteralPath $store -Raw) | Should -Be $before
            @((Get-GraphTenant -StorePath $store)).Count | Should -Be 1
        }
    }
}
