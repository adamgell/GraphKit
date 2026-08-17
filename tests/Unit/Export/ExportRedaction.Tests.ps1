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
        # Value-scoped, not array-scoped: declaring the ARRAY replaced it wholesale and removed
        # endDateTime/startDateTime/keyId - exactly the metadata a credential-hygiene check reads.
        $declared['ServicePrincipal/List'] | Should -Contain 'passwordCredentials.secretText'
        $declared['ServicePrincipal/List'] | Should -Contain 'keyCredentials.key'
        $declared['ConfigurationPolicySetting/ListBeta'] | Should -Contain 'settingInstance.groupSettingCollectionValue'
    }
}

Describe 'Export defects found by the 0.2.0 review' {

    BeforeEach {
        $script:dir = Join-Path $TestDrive ([guid]::NewGuid())
        $null = New-Item -ItemType Directory -Path $script:dir -Force
    }

    It 'neutralises a formula hidden behind leading <Name>' -ForEach @(
        @{ Name = 'tab';   Prefix = "`t" }
        @{ Name = 'CR';    Prefix = "`r" }
        @{ Name = 'space'; Prefix = ' ' }
    ) {
        # Excel and LibreOffice strip leading whitespace before parsing, so these executed while
        # looking neutralised. The check tested $value[0] and all three walked past it.
        $row = [PSCustomObject]@{ deviceName = ($Prefix + '=HYPERLINK("http://evil","click")') }
        Export-GraphResult -Result @($row) -As Csv -Path $script:dir -Name inj -WarningAction SilentlyContinue
        (Get-Content -LiteralPath (Join-Path $script:dir 'inj.csv') -Raw) | Should -BeLike "*'*=HYPERLINK*"
    }

    It 'keeps real columns in Markdown when rows are hashtables' {
        # The Csv branch got an IDictionary guard after this exact bug; Markdown never did, so a
        # hashtable row produced columns named IsReadOnly/Keys/SyncRoot with every value crushed
        # into one cell. It bites hardest where NO declaration exists, because redaction otherwise
        # converts rows to PSCustomObjects first - i.e. the majority of operations.
        Export-GraphResult -Result @(@{ id = 'h1'; displayName = 'Hash Row'; enabled = $true }) `
            -As Markdown -Path $script:dir -Name md -WarningAction SilentlyContinue
        $md = Get-Content -LiteralPath (Join-Path $script:dir 'md.md') -Raw

        $md | Should -BeLike '*displayName*'
        $md | Should -BeLike '*Hash Row*'
        $md | Should -Not -BeLike '*SyncRoot*'
        $md | Should -Not -BeLike '*IsReadOnly*'
    }

    It 'unions Markdown columns across heterogeneous rows' {
        # Columns came from $rows[0] alone, so a field absent from the first row vanished from the
        # table for every row.
        Export-GraphResult -Result @(@{ id = '1' }, @{ id = '2'; extra = 'kept' }) `
            -As Markdown -Path $script:dir -Name het -WarningAction SilentlyContinue
        (Get-Content -LiteralPath (Join-Path $script:dir 'het.md') -Raw) | Should -BeLike '*extra*'
    }

    It 'redacts a declared property that sits inside an ARRAY' {
        # Arrays fell through to the PSObject branch, where $array.PSObject.Properties yields .NET
        # array metadata - and SyncRoot IS the array, so the whole unredacted subtree was copied
        # into the output, in a file that reads as redacted.
        $env = [PSCustomObject]@{
            Data = @(@{ id = 'p1'; settingInstance = @(
                        @{ settingDefinitionId = 'wifi'; groupSettingCollectionValue = 'SUPERSECRETPSK' }) })
            Outcome = 'Succeeded'; Certainty = 'Known'; Telemetry = @()
            Provenance = @{ ProfileId = 'probe'; SensitiveProperties = @('settingInstance.groupSettingCollectionValue') }
        }
        $env.PSObject.TypeNames.Insert(0, 'GraphKit.OperationResult')
        Export-GraphResult -Result $env -As Json -Path $script:dir -Name arr
        $json = Get-Content -LiteralPath (Join-Path $script:dir 'arr.json') -Raw

        $json | Should -Not -BeLike '*SUPERSECRETPSK*'
        $json | Should -Not -BeLike '*SyncRoot*' -Because 'array metadata must never replace the row'
        $json | Should -BeLike '*wifi*' -Because 'the sibling identifying the setting must survive'
    }

    It 'does not export the tenant id in provenance, but keeps row-level ids' {
        # AGENTS.md:127 forbids exporting tenant ids, and these files are shared with customers.
        # Row-level tenantId is different data the reader may legitimately need, so the scrub is
        # scoped to Provenance rather than done by name-matching across the whole envelope.
        $env = [PSCustomObject]@{
            Data = @(@{ id = 'd1'; tenantId = 'row-level-value' })
            Outcome = 'Succeeded'; Certainty = 'Known'; Telemetry = @()
            Provenance = @{ ProfileId = 'ivy24'; TenantId = '11111111-2222-3333-4444-555555555555' }
        }
        $env.PSObject.TypeNames.Insert(0, 'GraphKit.OperationResult')
        Export-GraphResult -Result $env -As Json -Path $script:dir -Name prov
        $json = Get-Content -LiteralPath (Join-Path $script:dir 'prov.json') -Raw

        $json | Should -Not -BeLike '*11111111-2222-3333-4444-555555555555*'
        $json | Should -BeLike '*row-level-value*'
        $json | Should -BeLike '*ivy24*' -Because 'ProfileId identifies the export without being a directory id'
    }

    It 'redacts credential vocabulary the denylist used to miss, without over-redacting' {
        # ApiKey / ClientAssertion / Thumbprint were written verbatim while the docstring claimed
        # secrets can never reach the file. A bare 'key' and 'cert*' were deliberately NOT added:
        # they would redact certificateExpirationDate and any settings row with a key field.
        $env = [PSCustomObject]@{
            Data = @(@{ clientAssertion = 'AAA.BBB.CCC'; certificateExpirationDate = '2027-01-01' })
            Outcome = 'Succeeded'; Certainty = 'Known'; Telemetry = @(); Provenance = @{ ProfileId = 'p' }
        }
        $env.PSObject.TypeNames.Insert(0, 'GraphKit.OperationResult')
        Export-GraphResult -Result $env -As Json -Path $script:dir -Name deny
        $json = Get-Content -LiteralPath (Join-Path $script:dir 'deny.json') -Raw

        # CHANGED in the 0.2.1 fix: the sanitiser no longer name-matches .Data, because doing so
        # overrode the descriptor and redacted whole containers. Row-level secrets are now the
        # DECLARATION's job, and an undeclared secret-looking property warns rather than being
        # silently replaced. Telemetry is still sanitised - that is where the pattern belongs.
        $json | Should -BeLike '*AAA.BBB.CCC*' -Because 'nothing was declared, so nothing in Data is redacted'
        $json | Should -BeLike '*2027-01-01*' -Because 'a certificate EXPIRY is not a secret'
    }
}

Describe 'The descriptor declaration is authoritative over row data' {
    # 0.2.1. On 0.2.0 the envelope sanitiser name-matched the WHOLE envelope including .Data, so
    # 'passwordCredentials' matched 'credential' and was replaced wholesale - taking endDateTime,
    # startDateTime and keyId with it. A credential-hygiene check reads exactly that metadata and
    # never the secret, so the export was useless for its one purpose. Neither a narrower dotted
    # declaration nor -NoRedact escaped it, because neither was what redacted.
    #
    # Two redaction layers disagreeing means the declared one is not authoritative, and a
    # declaration callers cannot rely on is worse than no declaration at all.

    BeforeEach {
        $script:dir = Join-Path $TestDrive ([guid]::NewGuid())
        $null = New-Item -ItemType Directory -Path $script:dir -Force
    }

    BeforeAll {
        # Inside BeforeAll, not at Describe scope: Pester 6 does not surface a function declared
        # directly in a Describe body to the It blocks within it.
        function New-CredEnvelope {
            param([string[]] $Declared)
            $e = [PSCustomObject]@{
                Data = @(@{ id = 'app1'
                            passwordCredentials = @(@{ keyId = 'k-1'; endDateTime = '2027-01-01'; secretText = 'SEKRIT' }) })
                Outcome = 'Succeeded'; Certainty = 'Known'
                Telemetry = @(@{ SanitizedUri = 'https://x/y'; AccessToken = 'TELEMETRY-TOKEN' })
                Provenance = @{ ProfileId = 'p'; SensitiveProperties = $Declared }
            }
            $e.PSObject.TypeNames.Insert(0, 'GraphKit.OperationResult')
            return $e
        }
    }

    It 'redacts a credential VALUE while preserving the metadata beside it' {
        # The behaviour TenantPulse's TP.ENT.0019 needs, and the shipped ServicePrincipal.List
        # declaration now matches this shape.
        Export-GraphResult -Result (New-CredEnvelope @('passwordCredentials.secretText')) `
            -As Json -Path $script:dir -Name v
        $json = Get-Content -LiteralPath (Join-Path $script:dir 'v.json') -Raw

        $json | Should -Not -BeLike '*SEKRIT*'
        $json | Should -BeLike '*2027-01-01*' -Because 'endDateTime is what a hygiene check reads'
        $json | Should -BeLike '*k-1*'        -Because 'keyId identifies which credential'
    }

    It 'still sanitises Telemetry, which is what the name pattern is actually for' {
        Export-GraphResult -Result (New-CredEnvelope @('passwordCredentials.secretText')) `
            -As Json -Path $script:dir -Name t
        (Get-Content -LiteralPath (Join-Path $script:dir 't.json') -Raw) |
            Should -Not -BeLike '*TELEMETRY-TOKEN*'
    }

    It 'honours an array-level declaration when that is genuinely what was declared' {
        Export-GraphResult -Result (New-CredEnvelope @('passwordCredentials')) `
            -As Json -Path $script:dir -Name a
        $json = Get-Content -LiteralPath (Join-Path $script:dir 'a.json') -Raw
        $json | Should -Not -BeLike '*SEKRIT*'
        $json | Should -Not -BeLike '*2027-01-01*' -Because 'declaring the array means the array'
    }

    It 'warns rather than silently exporting undeclared secret-looking rows' {
        # Dropping the name-based net entirely would trade one silent failure for another. It now
        # DETECTS and warns, naming the descriptor as the remedy - no false redaction.
        # An ENVELOPE with no declaration - not raw rows, which have their own separate warning.
        # This is the case that regressed: the operation WAS identified, its descriptor simply
        # declares nothing, and before this the sanitiser quietly covered for that.
        $e = [PSCustomObject]@{
            Data = @(@{ id = 'r1'; secretText = 'RAW' })
            Outcome = 'Succeeded'; Certainty = 'Known'; Telemetry = @()
            Provenance = @{ ProfileId = 'p' }
        }
        $e.PSObject.TypeNames.Insert(0, 'GraphKit.OperationResult')

        $warnings = @()
        Export-GraphResult -Result $e -As Json -Path $script:dir -Name w `
            -WarningVariable warnings -WarningAction SilentlyContinue

        ($warnings -join ' ') | Should -BeLike '*secretText*' -Because 'the warning must name what it saw'
        ($warnings -join ' ') | Should -BeLike '*descriptor*'  -Because 'and where the fix belongs'
        (Get-Content -LiteralPath (Join-Path $script:dir 'w.json') -Raw) | Should -BeLike '*RAW*' -Because 'it warns, it does not redact'
    }

    It 'stays quiet for an operation that returns no secrets' {
        # If this warned on ordinary exports it would become noise people suppress, and the one
        # time it mattered would be suppressed too.
        $warnings = @()
        $e = [PSCustomObject]@{
            Data = @(@{ id = 'd1'; deviceName = 'LAPTOP-1'; complianceState = 'compliant' })
            Outcome = 'Succeeded'; Certainty = 'Known'; Telemetry = @()
            Provenance = @{ ProfileId = 'p' }
        }
        $e.PSObject.TypeNames.Insert(0, 'GraphKit.OperationResult')
        Export-GraphResult -Result $e -As Json -Path $script:dir -Name q -WarningVariable warnings -WarningAction SilentlyContinue
        ($warnings -join ' ') | Should -Not -BeLike '*secret*'
    }
}

