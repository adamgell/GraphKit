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
    It 'keeps CI, package verification, operator guidance, and the passing fixture equal' {
        $ci = Get-Content -LiteralPath (Join-Path $script:repoRoot '.github/workflows/ci.yml') -Raw
        $publisher = Get-Content -LiteralPath (Join-Path $script:repoRoot 'scripts/Publish-GraphKitPackage.ps1') -Raw
        $publishTests = Get-Content -LiteralPath (Join-Path $script:repoRoot 'tests/QA/PublishChannel.tests.ps1') -Raw

        $values = [ordered] @{
            CI = Get-SingleRatchetValue -Text $ci -Pattern '-MinimumTests\s+(\d+)\s+-AllowedSkips' -Location '.github/workflows/ci.yml'
            PublishCall = Get-SingleRatchetValue -Text $publisher -Pattern '-MinimumTests\s+(\d+)\s+-AllowedSkips' -Location 'scripts/Publish-GraphKitPackage.ps1 gate call'
            PublishHint = Get-SingleRatchetValue -Text $publisher -Pattern '-MinimumTests\s+(\d+)[\x27\x22]' -Location 'scripts/Publish-GraphKitPackage.ps1 error hint'
            PassingFixture = Get-SingleRatchetValue -Text $publishTests -Pattern '(?s)function New-PassingResult.*?\[int\]\s+\$Total\s*=\s*(\d+)' -Location 'tests/QA/PublishChannel.tests.ps1'
        }

        @($values.Values | Select-Object -Unique).Count | Should -Be 1 -Because (
            'every release gate must use one floor; found ' +
            (($values.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ')
        )
    }
}
