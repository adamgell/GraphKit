BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    . (Join-Path $script:repoRoot '.build/GraphKitAuth.tasks.ps1') -SkipTaskRegistration

    function New-GraphKitAuthTrxResult {
        param([Parameter(Mandatory)][int] $Total)

        $results = @(
            for ($index = 1; $index -le $Total; $index++) {
                '<UnitTestResult testId="{0}" outcome="Passed" />' -f $index
            }
        ) -join ''
        [xml] @"
<TestRun>
  <Results>$results</Results>
  <ResultSummary>
    <Counters total="$Total" executed="$Total" passed="$Total" failed="0" error="0"
      timeout="0" aborted="0" inconclusive="0" notExecuted="0" notRunnable="0"
      disconnected="0" warning="0" inProgress="0" pending="0" />
  </ResultSummary>
</TestRun>
"@
    }
}

Describe 'GraphKit.Auth machine-readable test result gate' -Tag 'QA' {
    It 'wires the authoritative validator into the build and accepts exactly 74 passing tests' {
        $taskSource = Get-Content -LiteralPath (
            Join-Path $script:repoRoot '.build/GraphKitAuth.tasks.ps1') -Raw
        @([regex]::Matches(
            $taskSource,
            '(?m)^\s*Assert-GraphKitAuthTestResult\s+-Result\s+\$trx\s*$'
        )).Count | Should -Be 1

        $result = New-GraphKitAuthTrxResult -Total 74

        { Assert-GraphKitAuthTestResult -Result $result } | Should -Not -Throw
    }

    It 'rejects an all-passing result with only 73 discovered tests' {
        $result = New-GraphKitAuthTrxResult -Total 73

        { Assert-GraphKitAuthTestResult -Result $result } |
            Should -Throw '*expected exactly 74*'
    }

    It 'rejects an all-passing result with 75 discovered tests' {
        $result = New-GraphKitAuthTrxResult -Total 75

        { Assert-GraphKitAuthTestResult -Result $result } |
            Should -Throw '*expected exactly 74*'
    }
}
