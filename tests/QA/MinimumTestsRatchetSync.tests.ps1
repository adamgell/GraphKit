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
    It 'keeps CI, proof production, proof verification, and the canonical fixture equal' {
        $ci = Get-Content -LiteralPath (Join-Path $script:repoRoot '.github/workflows/ci.yml') -Raw
        $generator = Get-Content -LiteralPath (Join-Path $script:repoRoot 'scripts/New-GraphKitTestedReleaseProof.ps1') -Raw
        $verifier = Get-Content -LiteralPath (Join-Path $script:repoRoot 'scripts/Test-GraphKitReleaseProof.ps1') -Raw
        $proofTests = Get-Content -LiteralPath (Join-Path $script:repoRoot 'tests/QA/ReleaseProof.tests.ps1') -Raw

        $values = [ordered] @{
            CI = Get-SingleRatchetValue -Text $ci -Pattern '-MinimumTests\s+(\d+)\s+-AllowedSkips' -Location '.github/workflows/ci.yml'
            Generator = Get-SingleRatchetValue -Text $generator -Pattern '\$minimumTests\s*=\s*(\d+)' -Location 'scripts/New-GraphKitTestedReleaseProof.ps1'
            Verifier = Get-SingleRatchetValue -Text $verifier -Pattern '\$minimumTests\s*=\s*(\d+)' -Location 'scripts/Test-GraphKitReleaseProof.ps1'
            ProofFixture = Get-SingleRatchetValue -Text $proofTests -Pattern '(?s)function New-GraphKitReleaseProofFixture.*?\[int\]\s+\$Total\s*=\s*(\d+)' -Location 'tests/QA/ReleaseProof.tests.ps1'
        }

        @($values.Values | Select-Object -Unique).Count | Should -Be 1 -Because (
            'every release gate must use one floor; found ' +
            (($values.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ')
        )
    }
}
