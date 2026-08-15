BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built GraphKit module found under output/module/GraphKit; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force

    function New-TestEnvelope {
        param(
            [string] $Outcome = 'Succeeded',
            [string] $Certainty = 'Known',
            [object[]] $Data = @()
        )

        $envelope = [pscustomobject] @{
            Data       = $Data
            Outcome    = $Outcome
            Certainty  = $Certainty
            Telemetry  = @(
                [pscustomobject] @{
                    Attempt       = 1
                    SanitizedUri  = 'https://graph.microsoft.com/v1.0/me'
                    AccessToken   = 'secret-bearer-value'
                }
            )
            Provenance = @{
                ProfileId = 'ivy24'
                TenantId  = [guid] '00000000-0000-0000-0000-000000000001'
            }
        }
        $envelope.PSObject.TypeNames.Insert(0, 'GraphKit.OperationResult')
        return $envelope
    }

    $script:captured = [System.Collections.Generic.List[object]]::new()
}
Describe 'Export-GraphResult' {
    It 'refuses an Indeterminate result without -Force' {
        $envelope = New-TestEnvelope -Outcome Failed -Certainty Indeterminate

        {
            Export-GraphResult -Result $envelope -As Json -Path $TestDrive
        } | Should -Throw -ExpectedMessage '*Indeterminate*'
    }

    It 'allows an Indeterminate result with -Force' {
        $envelope = New-TestEnvelope -Outcome Failed -Certainty Indeterminate
        $dir = Join-Path $TestDrive 'force'

        { Export-GraphResult -Result $envelope -As Json -Path $dir -Force } | Should -Not -Throw
        (Test-Path -LiteralPath (Join-Path $dir 'graph-result.json')) | Should -BeTrue
    }

    It 'preserves the full envelope in Json (Outcome, Certainty, Telemetry, Provenance)' {
        $envelope = New-TestEnvelope -Data @([pscustomobject] @{ id = '1' })
        $dir = Join-Path $TestDrive 'json-fidelity'

        Export-GraphResult -Result $envelope -As Json -Path $dir -Name out

        $json = Get-Content -LiteralPath (Join-Path $dir 'out.json') -Raw | ConvertFrom-Json
        $json.Outcome | Should -Be 'Succeeded'
        $json.Certainty | Should -Be 'Known'
        $json.Telemetry | Should -Not -BeNullOrEmpty
        $json.Provenance | Should -Not -BeNullOrEmpty
    }

    It 'redacts credential values from Json telemetry' {
        $envelope = New-TestEnvelope
        $dir = Join-Path $TestDrive 'json-redact'

        Export-GraphResult -Result $envelope -As Json -Path $dir -Name out

        $raw = Get-Content -LiteralPath (Join-Path $dir 'out.json') -Raw
        $raw | Should -Not -Match 'secret-bearer-value'
        $raw | Should -Match '\[REDACTED\]'
    }

    It 'exports only Data rows for Csv' {
        $envelope = New-TestEnvelope -Data @([pscustomobject] @{ id = '1'; name = 'alpha' })
        $dir = Join-Path $TestDrive 'csv'

        Export-GraphResult -Result $envelope -As Csv -Path $dir -Name rows

        $rows = Import-Csv -LiteralPath (Join-Path $dir 'rows.csv')
        $rows.id | Should -Be '1'
        $rows.PSObject.Properties.Name | Should -Contain 'name'
        $rows.PSObject.Properties.Name | Should -Not -Contain 'Outcome'
        $rows.PSObject.Properties.Name | Should -Not -Contain 'Certainty'
    }

    It 'exports only Data rows for Markdown' {
        $envelope = New-TestEnvelope -Data @([pscustomobject] @{ id = '1'; name = 'alpha' })
        $dir = Join-Path $TestDrive 'md'

        Export-GraphResult -Result $envelope -As Markdown -Path $dir -Name rows

        $markdown = Get-Content -LiteralPath (Join-Path $dir 'rows.md') -Raw
        $markdown | Should -Match '\| id \|'
        $markdown | Should -Match '\| 1 \|'
        $markdown | Should -Not -Match 'Outcome'
    }

    It 'unwraps envelopes and exports Data rows for raw-row input to Csv' {
        $rows = @(
            [pscustomobject] @{ id = 'a' }
            [pscustomobject] @{ id = 'b' }
        )
        $dir = Join-Path $TestDrive 'raw-csv'

        Export-GraphResult -Result $rows -As Csv -Path $dir -Name rows

        (Import-Csv -LiteralPath (Join-Path $dir 'rows.csv')).Count | Should -Be 2
    }

    It 'writes raw rows under ReportRoot/<ProfileId>/ for VaultEvidence' {
        $envelope = New-TestEnvelope -Data @([pscustomobject] @{ id = '1' })
        $reportRoot = Join-Path $TestDrive 'reports'
        $evidenceRoot = Join-Path $TestDrive 'evidence'

        Export-GraphResult -Result $envelope -As VaultEvidence -ProfileId ivy24 -Kind lab -ReportRoot $reportRoot -EvidenceRoot $evidenceRoot

        (Test-Path -LiteralPath (Join-Path $reportRoot 'ivy24/rows.json')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $evidenceRoot 'ivy24/ivy24.md')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $evidenceRoot 'ivy24/log.md')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $evidenceRoot 'index.md')) | Should -BeTrue
    }

    It 'invokes the vault adapter with the summary DTO' {
        $script:captured.Clear()
        $stub = {
            param($Summary, $EvidenceRoot, $ReportRoot)
            $script:captured.Add($Summary)
        }
        $envelope = New-TestEnvelope -Data @([pscustomobject] @{ id = '1' })
        $reportRoot = Join-Path $TestDrive 'reports-adapter'
        $evidenceRoot = Join-Path $TestDrive 'evidence-adapter'

        Export-GraphResult -Result $envelope -As VaultEvidence -ProfileId ivy24 -Kind lab -ReportRoot $reportRoot -EvidenceRoot $evidenceRoot -VaultAdapter $stub

        $script:captured.Count | Should -Be 1
        $script:captured[0].ProfileId | Should -Be 'ivy24'
        $script:captured[0].Kind | Should -Be 'lab'
        $script:captured[0].SourcePaths.Count | Should -Be 1
        $script:captured[0].Counts['rows'] | Should -Be 1
    }

    It 'does not let a Name with slashes influence the output path' {
        $envelope = New-TestEnvelope -Data @([pscustomobject] @{ id = '1' })
        $reportRoot = Join-Path $TestDrive 'reports-name'
        $evidenceRoot = Join-Path $TestDrive 'evidence-name'

        Export-GraphResult -Result $envelope -As VaultEvidence -ProfileId ivy24 -Kind customer -Name '../../evil' -ReportRoot $reportRoot -EvidenceRoot $evidenceRoot

        (Test-Path -LiteralPath (Join-Path $reportRoot 'ivy24/rows.json')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $evidenceRoot 'ivy24/ivy24.md')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $TestDrive 'evil')) | Should -BeFalse
    }

    It 'rejects a non-canonical ProfileId for VaultEvidence' {
        $envelope = New-TestEnvelope
        $reportRoot = Join-Path $TestDrive 'reports-bad'
        $evidenceRoot = Join-Path $TestDrive 'evidence-bad'

        {
            Export-GraphResult -Result $envelope -As VaultEvidence -ProfileId '../../evil' -ReportRoot $reportRoot -EvidenceRoot $evidenceRoot
        } | Should -Throw -ExpectedMessage '*canonical identifier*'
    }

    It 'requires -Path for Csv, Json, and Markdown' {
        $envelope = New-TestEnvelope

        { Export-GraphResult -Result $envelope -As Csv } | Should -Throw -ExpectedMessage '*-Path*'
    }
}
