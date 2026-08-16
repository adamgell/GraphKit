BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) { throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first.' }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force

    # An envelope shaped exactly as the pipeline produces one: the declaration rides on
    # Provenance, because Export-GraphResult never sees a descriptor.
    function New-DeclaredEnvelope {
        param([object[]] $Rows, [string[]] $Declared)
        $envelope = [PSCustomObject]@{
            Data       = $Rows
            Outcome    = 'Succeeded'
            Certainty  = 'Known'
            Telemetry  = @()
            Provenance = @{ ProfileId = 'probe'; SensitiveProperties = $Declared }
        }
        $envelope.PSObject.TypeNames.Insert(0, 'GraphKit.OperationResult')
        return $envelope
    }
}

Describe 'Export redaction is applied in every format' {

    BeforeEach {
        $script:dir = Join-Path $TestDrive ([guid]::NewGuid())
        $null = New-Item -ItemType Directory -Path $script:dir -Force
        $script:envelope = New-DeclaredEnvelope -Declared @('scriptContent') -Rows @(
            [PSCustomObject]@{ id = '1'; displayName = 'Onboard'; scriptContent = 'net user admin P@ssw0rd!' }
        )
    }

    It 'redacts a declared property in <Format>' -ForEach @(
        @{ Format = 'Csv'; Extension = 'csv' }
        @{ Format = 'Json'; Extension = 'json' }
        @{ Format = 'Markdown'; Extension = 'md' }
    ) {
        # The finding, stated as a test: before this change only Json redacted, and its pattern
        # did not match scriptContent anyway.
        Export-GraphResult -Result $script:envelope -As $Format -Path $script:dir -Name 'out'
        $content = Get-Content -LiteralPath (Join-Path $script:dir "out.$Extension") -Raw

        $content | Should -BeLike '*`[REDACTED`]*' -Because "$Format must redact a declared property"
        $content | Should -Not -BeLike '*P@ssw0rd!*' -Because "the secret must not survive into $Format"
        $content | Should -BeLike '*Onboard*' -Because 'undeclared properties must survive - this is redaction, not truncation'
    }

    It 'redacts inside the VaultEvidence raw rows.json' {
        $reportRoot = Join-Path $script:dir 'reports'
        $evidenceRoot = Join-Path $script:dir 'evidence'
        Export-GraphResult -Result $script:envelope -As VaultEvidence -ProfileId 'probe' -Kind lab `
            -ReportRoot $reportRoot -EvidenceRoot $evidenceRoot -VaultAdapter { param($Summary) } | Out-Null

        $rowsPath = Join-Path (Join-Path $reportRoot 'probe') 'rows.json'
        $rows = Get-Content -LiteralPath $rowsPath -Raw
        $rows | Should -BeLike '*`[REDACTED`]*'
        $rows | Should -Not -BeLike '*P@ssw0rd!*' -Because 'rows.json is written to disk in the clear and was the least obvious leak'
    }

    It 'writes the secret when -NoRedact is given' {
        # If the escape hatch does not actually produce raw output it is decorative, and someone
        # will build a workflow on an assumption that never held.
        Export-GraphResult -Result $script:envelope -As Csv -Path $script:dir -Name 'raw' -NoRedact
        $content = Get-Content -LiteralPath (Join-Path $script:dir 'raw.csv') -Raw
        $content | Should -BeLike '*P@ssw0rd!*'
        $content | Should -Not -BeLike '*`[REDACTED`]*'
    }

    It 'redacts only the declared branch of a dotted path' {
        # Declaring settingInstance wholesale would take settingDefinitionId with it and leave a
        # row that cannot say which setting it described.
        $envelope = New-DeclaredEnvelope -Declared @('settingInstance.groupSettingCollectionValue') -Rows @(
            [PSCustomObject]@{
                id              = 'p1'
                settingInstance = [PSCustomObject]@{
                    settingDefinitionId          = 'wifi_psk'
                    groupSettingCollectionValue  = 'SuperSecretPSK'
                }
            }
        )
        Export-GraphResult -Result $envelope -As Json -Path $script:dir -Name 'nested'
        $content = Get-Content -LiteralPath (Join-Path $script:dir 'nested.json') -Raw

        $content | Should -Not -BeLike '*SuperSecretPSK*'
        $content | Should -BeLike '*`[REDACTED`]*'
        $content | Should -BeLike '*wifi_psk*' -Because 'the sibling that identifies the setting must survive'
    }

    It 'does NOT redact properties merely because their name looks sensitive' {
        # The regression that the obvious fix would have shipped. DeviceCompliancePolicy returns
        # nine password* properties which are policy SETTINGS, not secrets; the envelope
        # sanitiser's pattern matches every one of them. Nothing is redacted here because
        # nothing was declared.
        $envelope = New-DeclaredEnvelope -Declared @('scriptContent') -Rows @(
            [PSCustomObject]@{
                id                    = 'c1'
                passwordRequired      = $true
                passwordMinimumLength = 8
                passwordRequiredType  = 'alphanumeric'
            }
        )
        Export-GraphResult -Result $envelope -As Csv -Path $script:dir -Name 'compliance'
        $content = Get-Content -LiteralPath (Join-Path $script:dir 'compliance.csv') -Raw

        $content | Should -Not -BeLike '*`[REDACTED`]*' -Because 'password policy settings are configuration, not credentials'
        $content | Should -BeLike '*alphanumeric*'
        $content | Should -BeLike '*8*'
    }

    It 'warns when raw rows are exported, because nothing can be declared' {
        # A silent no-op here is indistinguishable from a successful redaction - the same
        # false-sense-of-safety one level down.
        $warnings = @()
        Export-GraphResult -Result @([PSCustomObject]@{ id = '1'; scriptContent = 'secret' }) `
            -As Csv -Path $script:dir -Name 'rawrows' -WarningVariable warnings -WarningAction SilentlyContinue
        ($warnings -join ' ') | Should -BeLike '*no operation declaration is available*'
    }
}

Describe 'CSV formula injection' {

    BeforeEach {
        $script:dir = Join-Path $TestDrive ([guid]::NewGuid())
        $null = New-Item -ItemType Directory -Path $script:dir -Force
    }

    It 'prefixes a cell beginning <Char>' -ForEach @(
        @{ Char = '=' }, @{ Char = '+' }, @{ Char = '-' }, @{ Char = '@' }
    ) {
        # Device names are user-renamable in many Intune configurations, and these reports are
        # shared with customers.
        $row = [PSCustomObject]@{ deviceName = ($Char + 'HYPERLINK("http://evil","click")') }
        Export-GraphResult -Result @($row) -As Csv -Path $script:dir -Name 'inject' -WarningAction SilentlyContinue
        $content = Get-Content -LiteralPath (Join-Path $script:dir 'inject.csv') -Raw

        $content | Should -BeLike ("*'" + $Char + 'HYPERLINK*') -Because "a cell beginning $Char executes in Excel"
    }

    It 'does not prefix a negative NUMBER' {
        # Only strings are a formula risk. Prefixing numerics would corrupt every negative value
        # in a report - battery levels, offsets, deltas.
        $row = [PSCustomObject]@{ name = 'x'; offset = -5 }
        Export-GraphResult -Result @($row) -As Csv -Path $script:dir -Name 'numeric' -WarningAction SilentlyContinue
        $content = Get-Content -LiteralPath (Join-Path $script:dir 'numeric.csv') -Raw

        $content | Should -BeLike '*-5*'
        $content | Should -Not -BeLike "*'-5*"
    }

    It 'preserves every column when rows are hashtables' {
        # Regression. The transport parses JSON with -AsHashtable, so rows reach the exporter as
        # hashtables, and $row.PSObject.Properties on a hashtable enumerates Count/Keys/Values
        # rather than the entries. Reading the wrong member set silently produced a CSV with no
        # real columns at all - found by exporting live compliance policies and noticing
        # passwordRequired was missing where plain Export-Csv produces it.
        $row = @{ id = 'h1'; displayName = 'Hash Row'; passwordRequired = $true }
        Export-GraphResult -Result @($row) -As Csv -Path $script:dir -Name 'hashrow' -WarningAction SilentlyContinue
        $content = Get-Content -LiteralPath (Join-Path $script:dir 'hashrow.csv') -Raw

        $content | Should -BeLike '*displayName*'
        $content | Should -BeLike '*passwordRequired*'
        $content | Should -BeLike '*Hash Row*'
        $content | Should -Not -BeLike '*IsReadOnly*' -Because 'the hashtable''s own members must not become columns'
    }

    It 'does not prefix in Json, which does not execute formulas' {
        $row = [PSCustomObject]@{ deviceName = '=SUM(A1)' }
        Export-GraphResult -Result @($row) -As Json -Path $script:dir -Name 'nojson' -WarningAction SilentlyContinue
        $content = Get-Content -LiteralPath (Join-Path $script:dir 'nojson.json') -Raw

        $content | Should -BeLike '*=SUM(A1)*'
        $content | Should -Not -BeLike "*'=SUM*"
    }
}

Describe 'SensitiveProperties descriptor validation' {

    BeforeEach {
        $script:descriptorDir = Join-Path $TestDrive ([guid]::NewGuid())
        $null = New-Item -ItemType Directory -Path $script:descriptorDir -Force
        $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath
        $script:template = Get-Content (Join-Path $repoRoot 'source/Data/Operations/ManagedDevice.List.psd1') -Raw
    }

    It 'rejects a non-array' {
        # A typo'd declaration redacts nothing and looks correct, so it is rejected at load.
        $path = Join-Path $script:descriptorDir 'Bad.List.psd1'
        ($script:template -replace "ThrottleClass       = 'Read'", "ThrottleClass       = 'Read'`n    SensitiveProperties = 'scriptContent'") |
            Set-Content -LiteralPath $path -Encoding utf8
        InModuleScope GraphKit -Parameters @{ Path = $path } {
            { Import-GraphOperationDescriptor -Path $Path } | Should -Throw -ExpectedMessage '*must be an array*'
        }
    }

    It 'rejects an empty entry' {
        $path = Join-Path $script:descriptorDir 'Bad2.List.psd1'
        ($script:template -replace "ThrottleClass       = 'Read'", "ThrottleClass       = 'Read'`n    SensitiveProperties = @('scriptContent', '')") |
            Set-Content -LiteralPath $path -Encoding utf8
        InModuleScope GraphKit -Parameters @{ Path = $path } {
            { Import-GraphOperationDescriptor -Path $Path } | Should -Throw -ExpectedMessage '*non-empty property names*'
        }
    }

    It 'the shipped catalog declares the operations known to return secrets' {
        $declared = @{}
        foreach ($op in (Get-GraphOperation -List | Where-Object { $_.SensitiveProperties })) {
            $declared["$($op.Type)/$($op.Operation)"] = @($op.SensitiveProperties)
        }
        $declared['DeviceManagementScript/List'] | Should -Contain 'scriptContent'
        $declared['ServicePrincipal/List'] | Should -Contain 'passwordCredentials'
        $declared['ConfigurationPolicySetting/ListBeta'] | Should -Contain 'settingInstance.groupSettingCollectionValue'
    }
}
