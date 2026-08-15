<#
    Gate on the WHOLE Pester result, not just the failed-assertion count.

    A discovery or container failure prevents tests from running without looking
    like a failed assertion - which is exactly how a CI suite can stay green while
    testing nothing. This helper parses the NUnit XML Sampler/Pester emits and fails
    the run unless every one of these holds:

        - the overall result is Passed
        - zero failed tests
        - zero failed containers / discovery errors
        - the errors attribute is empty (no test errors)
        - total test count is at or above an expected minimum
        - skipped tests stay within an explicit allowance (default zero)

    Every condition is checked independently and reported with an actionable message;
    any violation exits non-zero.

    This is a helper script, not a Pester test: its name does not end in .Tests.ps1,
    so Pester discovery never runs it as part of the suite.

    Run:  pwsh -File ./tests/QA/Assert-GateResult.ps1 -ResultPath output/testResults/NUnitXml_*.xml -MinimumTests 500 -AllowedSkips 0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ResultPath,

    [Parameter()]
    [int] $MinimumTests = 500,

    # Skips are permitted only up to an explicit budget. The default of zero means a new
    # skip must be argued for at the call site rather than absorbed silently.
    [int] $AllowedSkips = 0
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

if (-not (Test-Path -LiteralPath $ResultPath -PathType Leaf)) {
    Write-Error "Result file not found: $ResultPath"
    exit 1
}

try {
    [xml] $doc = Get-Content -LiteralPath $ResultPath -Raw
} catch {
    Write-Error "Result file is not valid XML: $ResultPath`n$($_.Exception.Message)"
    exit 1
}

$root = $doc.SelectSingleNode('/test-results')
if ($null -eq $root) {
    Write-Error "Result file has no <test-results> root element: $ResultPath"
    exit 1
}

function ConvertTo-Count {
    param([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return 0 }
    $parsed = 0
    if (-not [int]::TryParse($Value.Trim(), [ref] $parsed)) { return -1 }
    return $parsed
}

$violations = [System.Collections.Generic.List[string]]::new()

# 0. Skips, evaluated first because a single skipped test turns the whole NUnit result
# into 'Ignored'. Without this the gate reports "the suite did not pass" for a suite in
# which nothing failed, which is a confident diagnosis of the wrong problem - the same
# failure shape this repository keeps finding elsewhere. Skips are allowed only up to an
# explicit budget, so they stay a deliberate decision rather than a silent drift.
$skipped = ConvertTo-Count $root.GetAttribute('skipped')
$skipsWithinBudget = $false
if ($skipped -lt 0) {
    $violations.Add("skipped attribute is unreadable: '$($root.GetAttribute('skipped'))'.")
} elseif ($skipped -gt $AllowedSkips) {
    $violations.Add("$skipped test(s) skipped - the allowance is $AllowedSkips. If the skip is deliberate, raise -AllowedSkips and say why; if it is not, a test is being silently dropped.")
} else {
    $skipsWithinBudget = $true
}

# 1. Overall result is Passed (top-level suite result attribute).
$topSuite = $root.SelectSingleNode('test-suite')
if ($null -eq $topSuite) {
    $violations.Add('No top-level <test-suite> found - the result is structurally invalid.')
} else {
    $overallResult = [string] $topSuite.GetAttribute('result')
    $ignoredByAllowedSkips = ($overallResult -eq 'Ignored' -and $skipped -gt 0 -and $skipsWithinBudget)
    if ($overallResult -notin @('Success', 'Passed') -and -not $ignoredByAllowedSkips) {
        $violations.Add("Overall result is '$overallResult' - expected Passed. The suite did not pass.")
    }
}

# 2. Zero failed tests (failures attribute counts failed assertions).
$failures = ConvertTo-Count $root.GetAttribute('failures')
if ($failures -lt 0) {
    $violations.Add("failures attribute is unreadable: '$($root.GetAttribute('failures'))'.")
} elseif ($failures -ne 0) {
    $violations.Add("$failures test(s) failed - expected 0 failed tests.")
}

# 3. Zero failed containers / discovery errors (any suite-level Failure or Error node).
$failedSuites = $root.SelectNodes('//test-suite[@result="Failure" or @result="Error"]')
$failedSuiteCount = if ($null -eq $failedSuites) { 0 } else { $failedSuites.Count }
if ($failedSuiteCount -gt 0) {
    $names = @($failedSuites | ForEach-Object { [string] $_.GetAttribute('name') }) -join '; '
    $violations.Add("$failedSuiteCount failed container(s) / discovery error(s): $names")
}

# 4. errors attribute empty (no test errors).
$errorsRaw = ([string] $root.GetAttribute('errors')).Trim()
if ($errorsRaw -notin @('', '0')) {
    $violations.Add("errors attribute is '$errorsRaw' - expected empty (0 test errors).")
}

# 5. Total test count meets the expected minimum.
$total = ConvertTo-Count $root.GetAttribute('total')
if ($total -lt 0) {
    $violations.Add("total attribute is unreadable: '$($root.GetAttribute('total'))'.")
} elseif ($total -lt $MinimumTests) {
    $violations.Add("Total test count $total is below the expected minimum $MinimumTests - discovery may be silently dropping tests.")
}

if ($violations.Count -gt 0) {
    Write-Host ''
    Write-Host 'GATE FAILED: Pester result did not satisfy the whole-result conditions.' -ForegroundColor Red
    for ($i = 0; $i -lt $violations.Count; $i++) {
        Write-Host ("  [{0}] {1}" -f ($i + 1), $violations[$i]) -ForegroundColor Red
    }
    Write-Host ''
    exit 1
}

Write-Host "GATE PASSED: $total tests, $failures failed, $errorsRaw errors, $skipped skipped (allowance $AllowedSkips), total >= $MinimumTests." -ForegroundColor Green
exit 0
