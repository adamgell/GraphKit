BeforeAll {
    # Assert-GateResult is the safety net the whole CI run hangs on: if it is wrong, every
    # other gate in this repository can pass while testing nothing. It was itself untested
    # until a legitimate platform skip made it report "the suite did not pass" for a suite
    # in which nothing failed. These tests mutation-test each condition by synthesising a
    # result file that violates exactly one of them.
    $script:gate = Join-Path $PSScriptRoot 'Assert-GateResult.ps1'

    function New-NUnitResult {
        param(
            [int] $Total = 600,
            [int] $Failures = 0,
            [int] $Errors = 0,
            [int] $Skipped = 0,
            [string] $SuiteResult = 'Success',
            [string] $Root
        )
        $path = Join-Path $Root ("nunit-{0}.xml" -f [guid]::NewGuid())
        $xml = @"
<?xml version="1.0" encoding="utf-8" standalone="no"?>
<test-results name="GraphKit" total="$Total" errors="$Errors" failures="$Failures" not-run="0" inconclusive="0" ignored="0" skipped="$Skipped" invalid="0" date="2026-08-15" time="12:00:00">
  <test-suite type="TestFixture" name="GraphKit" executed="True" result="$SuiteResult" success="$($SuiteResult -eq 'Success')" time="1.0" asserts="0" />
</test-results>
"@
        Set-Content -LiteralPath $path -Value $xml -Encoding utf8
        return $path
    }

    function Invoke-Gate {
        param([string] $ResultPath, [int] $MinimumTests = 500, [int] $AllowedSkips = 0)
        $out = & pwsh -NoProfile -File $script:gate -ResultPath $ResultPath -MinimumTests $MinimumTests -AllowedSkips $AllowedSkips 2>&1
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($out -join "`n") }
    }
}

Describe 'Assert-GateResult' {

    It 'passes a clean result' {
        $r = Invoke-Gate -ResultPath (New-NUnitResult -Root $TestDrive)
        $r.ExitCode | Should -Be 0
        $r.Output | Should -BeLike '*GATE PASSED*'
    }

    It 'fails when tests failed' {
        $r = Invoke-Gate -ResultPath (New-NUnitResult -Root $TestDrive -Failures 3 -SuiteResult 'Failure')
        $r.ExitCode | Should -Be 1
        $r.Output | Should -BeLike '*3 test(s) failed*'
    }

    It 'fails when the total is below the expected minimum' {
        $r = Invoke-Gate -ResultPath (New-NUnitResult -Root $TestDrive -Total 12) -MinimumTests 500
        $r.ExitCode | Should -Be 1
        $r.Output | Should -BeLike '*below the expected minimum*'
    }

    It 'fails when a test errored' {
        $r = Invoke-Gate -ResultPath (New-NUnitResult -Root $TestDrive -Errors 2 -SuiteResult 'Error')
        $r.ExitCode | Should -Be 1
        $r.Output | Should -BeLike '*errors attribute*'
    }

    It 'fails on a discovery error even when no assertion failed' {
        # The case the gate exists for: a container that never ran looks like zero failures.
        $r = Invoke-Gate -ResultPath (New-NUnitResult -Root $TestDrive -SuiteResult 'Error')
        $r.ExitCode | Should -Be 1
        $r.Output | Should -BeLike '*failed container(s) / discovery error(s)*'
    }

    Context 'skips' {

        It 'fails a skipped test against a zero allowance, naming the skip rather than blaming the suite' {
            # Regression: a single skip turns the NUnit result into 'Ignored', and the gate
            # used to report only "the suite did not pass" - a confident diagnosis of the
            # wrong problem, since nothing had failed.
            $r = Invoke-Gate -ResultPath (New-NUnitResult -Root $TestDrive -Skipped 1 -SuiteResult 'Ignored') -AllowedSkips 0
            $r.ExitCode | Should -Be 1
            $r.Output | Should -BeLike '*1 test(s) skipped*'
            $r.Output | Should -BeLike '*allowance is 0*'
        }

        It 'passes a skip that is within the declared allowance' {
            $r = Invoke-Gate -ResultPath (New-NUnitResult -Root $TestDrive -Skipped 1 -SuiteResult 'Ignored') -AllowedSkips 1
            $r.ExitCode | Should -Be 0
            $r.Output | Should -BeLike '*1 skipped (allowance 1)*'
        }

        It 'still fails an Ignored result that has no skips to explain it' {
            # An allowance must not become a blanket pass for any non-Passed result.
            $r = Invoke-Gate -ResultPath (New-NUnitResult -Root $TestDrive -Skipped 0 -SuiteResult 'Ignored') -AllowedSkips 5
            $r.ExitCode | Should -Be 1
            $r.Output | Should -BeLike "*Overall result is 'Ignored'*"
        }

        It 'still fails a failure even when skips are allowed' {
            $r = Invoke-Gate -ResultPath (New-NUnitResult -Root $TestDrive -Skipped 1 -Failures 1 -SuiteResult 'Ignored') -AllowedSkips 1
            $r.ExitCode | Should -Be 1
            $r.Output | Should -BeLike '*1 test(s) failed*'
        }
    }

    It 'fails when the result file is missing' {
        $r = Invoke-Gate -ResultPath (Join-Path $TestDrive 'absent.xml')
        $r.ExitCode | Should -Be 1
    }

    It 'fails when the result file is not valid XML' {
        $path = Join-Path $TestDrive 'garbage.xml'
        'this is not xml' | Set-Content -LiteralPath $path
        $r = Invoke-Gate -ResultPath $path
        $r.ExitCode | Should -Be 1
    }
}
