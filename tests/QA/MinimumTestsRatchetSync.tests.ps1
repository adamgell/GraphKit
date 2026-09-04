BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath

    function Get-SingleRatchetValue {
        param(
            [Parameter(Mandatory)] [string] $Text,
            [Parameter(Mandatory)] [string] $Pattern,
            [Parameter(Mandatory)] [string] $Location
        )

        $matches = @([regex]::Matches($Text, $Pattern))
        if ($matches.Count -eq 0) {
            throw "MinimumTests pattern matched nothing in $Location."
        }

        $values = @($matches | ForEach-Object { [int] $_.Groups[1].Value } | Select-Object -Unique)
        if ($values.Count -ne 1) {
            throw "MinimumTests pattern found distinct values in ${Location}: $($values -join ', ')."
        }

        return $values[0]
    }
}

Describe 'MinimumTests ratchet synchronization' -Tag 'QA' {
    It 'keeps every release authority equal to the independently discovered portable floor' {
        $ci = Get-Content -LiteralPath (Join-Path $script:repoRoot '.github/workflows/ci.yml') -Raw
        $generator = Get-Content -LiteralPath (Join-Path $script:repoRoot 'scripts/New-GraphKitTestedReleaseProof.ps1') -Raw
        $verifier = Get-Content -LiteralPath (Join-Path $script:repoRoot 'scripts/Test-GraphKitReleaseProof.ps1') -Raw
        $proofTests = Get-Content -LiteralPath (Join-Path $script:repoRoot 'tests/QA/ReleaseProof.tests.ps1') -Raw
        $publishTests = Get-Content -LiteralPath (Join-Path $script:repoRoot 'tests/QA/PublishChannel.tests.ps1') -Raw
        $agents = Get-Content -LiteralPath (Join-Path $script:repoRoot 'AGENTS.md') -Raw

        $values = [ordered] @{
            CI = Get-SingleRatchetValue -Text $ci -Pattern '-MinimumTests\s+(\d+)\s+-AllowedSkips' -Location '.github/workflows/ci.yml'
            Generator = Get-SingleRatchetValue -Text $generator -Pattern '\$minimumTests\s*=\s*(\d+)' -Location 'scripts/New-GraphKitTestedReleaseProof.ps1'
            Verifier = Get-SingleRatchetValue -Text $verifier -Pattern '\$minimumTests\s*=\s*(\d+)' -Location 'scripts/Test-GraphKitReleaseProof.ps1'
            ProofFixture = Get-SingleRatchetValue -Text $proofTests -Pattern '(?s)function New-GraphKitReleaseProofFixture.*?\[int\]\s+\$Total\s*=\s*(\d+)' -Location 'tests/QA/ReleaseProof.tests.ps1'
            ProofPolicy = Get-SingleRatchetValue -Text $proofTests -Pattern '(?s)function New-GraphKitReleaseProofFixture.*?minimumTests\s*=\s*(\d+)' -Location 'tests/QA/ReleaseProof.tests.ps1 policy'
            ProofAssertion = Get-SingleRatchetValue -Text $proofTests -Pattern '\$proof\.testRun\.summary\.total\s*\|\s*Should\s+-Be\s+(\d+)' -Location 'tests/QA/ReleaseProof.tests.ps1 assertion'
            PublisherFixture = Get-SingleRatchetValue -Text $publishTests -Pattern '(?s)function New-PassingResult.*?\[int\]\s+\$Total\s*=\s*(\d+)' -Location 'tests/QA/PublishChannel.tests.ps1'
            AgentGuidance = Get-SingleRatchetValue -Text $agents -Pattern 'post-release development tree requires\s+(\d+)\s+deterministic tests' -Location 'AGENTS.md'
        }

        @($values.Values | Select-Object -Unique).Count | Should -Be 1 -Because (
            'every release gate must use one floor; found ' +
            (($values.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ')
        )

        $discoveryScript = Join-Path $PSScriptRoot 'Get-GraphKitPesterDiscoveryCount.ps1'
        $discoveryOutput = @(& pwsh -NoLogo -NoProfile -File $discoveryScript `
            -RepositoryRoot $script:repoRoot 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "Independent Pester discovery failed: $($discoveryOutput -join ' ')"
        }
        $discovery = $discoveryOutput[-1] | ConvertFrom-Json
        $platformOnlySurplus = switch ([string]$discovery.platform) {
            'MacOS' { 0 }
            'Linux' { 2 }
            'Windows' { 6 }
            default { throw "Unsupported discovery platform '$($discovery.platform)'." }
        }
        $portableFloor = [int]$discovery.total - $platformOnlySurplus
        $values.CI | Should -Be $portableFloor -Because (
            "the shared floor must equal independent discovery minus the known $platformOnlySurplus " +
            "platform-only case(s); discovered $($discovery.total) across $($discovery.containers) containers"
        )
    }
}
