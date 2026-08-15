BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath

    $built = Get-ChildItem (Join-Path $repoRoot 'output/module/GraphKit') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $built) {
        throw 'No built GraphKit module found under output/module/GraphKit; run ./build.ps1 -Tasks build first.'
    }
    Import-Module (Join-Path $built.FullName 'GraphKit.psd1') -Force

    $script:reportRoot = Join-Path $TestDrive 'reports'
    $script:evidenceRoot = Join-Path $TestDrive 'evidence'
    $null = New-Item -ItemType Directory -Path (Join-Path $script:reportRoot 'ivy24') -Force
    $null = New-Item -ItemType Directory -Path $script:evidenceRoot -Force

    function New-TestSummary {
        param(
            [string] $ProfileId = 'ivy24',
            [string] $Name = 'Contoso',
            [string] $Kind = 'customer',
            [object[]] $SourcePaths = @()
        )

        $summary = [pscustomobject] @{
            ProfileId    = $ProfileId
            Name         = $Name
            Kind         = $Kind
            GeneratedUtc = [datetime]::UtcNow
            SourcePaths  = $SourcePaths
            Counts       = @{ rows = 5 }
            Notes        = @('rolled up from two runs')
        }
        $summary.PSObject.TypeNames.Insert(0, 'GraphKit.EvidenceSummary')
        return $summary
    }

    $script:defaultSource = @((Join-Path $script:reportRoot 'ivy24/rows.json'))
}

Describe 'Write-VaultEvidence' {
    It 'produces the summary page, log.md, and index.md' {
        InModuleScope GraphKit -ArgumentList (New-TestSummary -SourcePaths $script:defaultSource), $script:evidenceRoot, $script:reportRoot {
            param($Summary, $EvidenceRoot, $ReportRoot)

            Write-VaultEvidence -Summary $Summary -EvidenceRoot $EvidenceRoot -ReportRoot $ReportRoot
        }

        (Test-Path -LiteralPath (Join-Path $script:evidenceRoot 'ivy24/ivy24.md')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $script:evidenceRoot 'ivy24/log.md')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $script:evidenceRoot 'index.md')) | Should -BeTrue
    }

    It 'writes customers: [Name] frontmatter for Kind customer' {
        InModuleScope GraphKit -ArgumentList (New-TestSummary -SourcePaths $script:defaultSource), $script:evidenceRoot, $script:reportRoot {
            param($Summary, $EvidenceRoot, $ReportRoot)

            Write-VaultEvidence -Summary $Summary -EvidenceRoot $EvidenceRoot -ReportRoot $ReportRoot
        }

        $page = Get-Content -LiteralPath (Join-Path $script:evidenceRoot 'ivy24/ivy24.md') -Raw
        $page | Should -Match "customers: \['Contoso'\]"
    }

    It 'writes customers: [] frontmatter for a lab profile' {
        $labEvidence = Join-Path $TestDrive 'evidence-lab'

        InModuleScope GraphKit -ArgumentList (New-TestSummary -Kind lab -SourcePaths $script:defaultSource), $labEvidence, $script:reportRoot {
            param($Summary, $EvidenceRoot, $ReportRoot)

            Write-VaultEvidence -Summary $Summary -EvidenceRoot $EvidenceRoot -ReportRoot $ReportRoot
        }

        $page = Get-Content -LiteralPath (Join-Path $labEvidence 'ivy24/ivy24.md') -Raw
        $page | Should -Match 'customers: \[\]'
    }

    It 'includes at least two wikilinks and the source pointer' {
        InModuleScope GraphKit -ArgumentList (New-TestSummary -SourcePaths $script:defaultSource), $script:evidenceRoot, $script:reportRoot {
            param($Summary, $EvidenceRoot, $ReportRoot)

            Write-VaultEvidence -Summary $Summary -EvidenceRoot $EvidenceRoot -ReportRoot $ReportRoot
        }

        $page = Get-Content -LiteralPath (Join-Path $script:evidenceRoot 'ivy24/ivy24.md') -Raw
        $page | Should -Match '\[\[ivy24/log\]\]'
        $page | Should -Match '\[\[index\]\]'
        $page | Should -Match '\[\[Contoso\]\]'
        $page | Should -Match 'rows.json'
    }

    It 'refuses a source path outside the report root' {
        $bad = New-TestSummary -SourcePaths @('/etc/passwd')

        {
            InModuleScope GraphKit -ArgumentList $bad, $script:evidenceRoot, $script:reportRoot {
                param($Summary, $EvidenceRoot, $ReportRoot)

                Write-VaultEvidence -Summary $Summary -EvidenceRoot $EvidenceRoot -ReportRoot $ReportRoot
            }
        } | Should -Throw -ExpectedMessage '*outside the report root*'
    }

    It 'blocks a ProfileId that would escape the evidence root' {
        $bad = New-TestSummary -ProfileId '../evil' -Kind lab -SourcePaths $script:defaultSource

        {
            InModuleScope GraphKit -ArgumentList $bad, $script:evidenceRoot, $script:reportRoot {
                param($Summary, $EvidenceRoot, $ReportRoot)

                Write-VaultEvidence -Summary $Summary -EvidenceRoot $EvidenceRoot -ReportRoot $ReportRoot
            }
        } | Should -Throw -ExpectedMessage '*outside the evidence root*'
    }

    It 'appends log.md across two writes' {
        $appendEvidence = Join-Path $TestDrive 'evidence-append'

        InModuleScope GraphKit -ArgumentList (New-TestSummary -SourcePaths $script:defaultSource), $appendEvidence, $script:reportRoot {
            param($Summary, $EvidenceRoot, $ReportRoot)

            Write-VaultEvidence -Summary $Summary -EvidenceRoot $EvidenceRoot -ReportRoot $ReportRoot
            Write-VaultEvidence -Summary $Summary -EvidenceRoot $EvidenceRoot -ReportRoot $ReportRoot
        }

        $log = Get-Content -LiteralPath (Join-Path $appendEvidence 'ivy24/log.md')
        $log.Count | Should -Be 2
    }
}
