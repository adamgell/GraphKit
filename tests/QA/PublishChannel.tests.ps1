BeforeAll {
    # PowerShell renders an exception in a box whose left gutter is a '|' on every wrapped
    # line, so "with DIFFERENT bytes" arrives as "with DIFFERENT" + newline + " | bytes".
    # Collapsing whitespace alone is not enough - it leaves "DIFFERENT | bytes" and the
    # assertion still fails. The wrap point depends on the runner's terminal width, so this
    # passed on a wide macOS terminal and failed on Linux and Windows.
    #
    # Strip the newline+gutter sequence FIRST (it needs the newlines), then collapse.
    function ConvertTo-FlatConsoleText {
        param([object] $Output)
        $text = ($Output | Out-String)
        $text = $text -replace '\r?\n\s*\|\s*', ' '
        return ($text -replace '\s+', ' ').Trim()
    }

    # Publish-GraphKitPackage is the one place where "what we tested" and "what we ship" can
    # silently diverge. Its refusals are the product; each is mutation-tested here by
    # constructing exactly the situation it must reject.
    $script:repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:publish = Join-Path $script:repoRoot 'scripts/Publish-GraphKitPackage.ps1'

    function New-FakeNupkg {
        param([string] $Root, [string] $Name = 'GraphKit.9.9.9.nupkg', [string] $Psm1Content = 'fake module body')
        $path = Join-Path $Root $Name
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $stage = Join-Path $Root ("stage-{0}" -f [guid]::NewGuid())
        $null = New-Item -ItemType Directory -Path $stage -Force
        Set-Content -LiteralPath (Join-Path $stage 'GraphKit.psm1') -Value $Psm1Content -NoNewline
        if (Test-Path $path) { Remove-Item $path -Force }
        [System.IO.Compression.ZipFile]::CreateFromDirectory($stage, $path)
        Remove-Item $stage -Recurse -Force
        return $path
    }

    function New-PassingResult {
        param([string] $Root, [string] $Version = '9.9.9', [int] $Total = 772)
        $path = Join-Path $Root "NUnitXml_GraphKit_v$Version.Test.xml"
        @"
<?xml version="1.0" encoding="utf-8" standalone="no"?>
<test-results name="GraphKit" total="$Total" errors="0" failures="0" not-run="0" inconclusive="0" ignored="0" skipped="0" invalid="0" date="2026-08-15" time="12:00:00">
  <test-suite type="TestFixture" name="GraphKit" executed="True" result="Success" success="True" time="1.0" asserts="0" />
</test-results>
"@ | Set-Content -LiteralPath $path -Encoding utf8
        return $path
    }

    function Invoke-Publish {
        param([hashtable] $Params)
        $args = @()
        foreach ($k in $Params.Keys) {
            if ($Params[$k] -is [switch] -or $Params[$k] -is [bool]) {
                if ($Params[$k]) { $args += "-$k" }
            }
            else { $args += "-$k"; $args += [string] $Params[$k] }
        }
        $out = & pwsh -NoProfile -File $script:publish @args 2>&1
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = (ConvertTo-FlatConsoleText -Output $out) }
    }
}

Describe 'Publish-GraphKitPackage refusals' {

    It 'refuses a package that does not exist, and says not to build here' {
        $r = Invoke-Publish @{ PackagePath = (Join-Path $TestDrive 'nope.nupkg'); Channel = 'FileSystem'; Destination = $TestDrive; SkipTestProof = $true }
        $r.ExitCode | Should -Not -Be 0
        # Match a phrase short enough to survive console line-wrapping in the error text.
        $r.Output | Should -BeLike '*does not exist*'
    }

    It 'refuses a file that is not a .nupkg' {
        $bogus = Join-Path $TestDrive 'GraphKit.9.9.9.zip'
        'x' | Set-Content -LiteralPath $bogus
        $r = Invoke-Publish @{ PackagePath = $bogus; Channel = 'FileSystem'; Destination = $TestDrive; SkipTestProof = $true }
        $r.ExitCode | Should -Not -Be 0
        $r.Output | Should -BeLike '*not a .nupkg*'
    }

    It 'refuses a package whose name carries no parseable version' {
        $bad = New-FakeNupkg -Root $TestDrive -Name 'GraphKit.nupkg'
        $r = Invoke-Publish @{ PackagePath = $bad; Channel = 'FileSystem'; Destination = $TestDrive; SkipTestProof = $true }
        $r.ExitCode | Should -Not -Be 0
        $r.Output | Should -BeLike '*Cannot parse a module name and version*'
    }

    It 'refuses to publish without test proof unless the escape hatch is explicit' {
        $pkg = New-FakeNupkg -Root $TestDrive
        $r = Invoke-Publish @{ PackagePath = $pkg; Channel = 'FileSystem'; Destination = (Join-Path $TestDrive 'ch1') }
        $r.ExitCode | Should -Not -Be 0
        $r.Output | Should -BeLike '*-TestResultPath is required*'
    }

    It 'refuses a test result belonging to a different version' {
        # A green result from another build proves nothing about these bytes.
        $pkg = New-FakeNupkg -Root $TestDrive
        $wrong = New-PassingResult -Root $TestDrive -Version '1.2.3'
        $r = Invoke-Publish @{ PackagePath = $pkg; Channel = 'FileSystem'; Destination = (Join-Path $TestDrive 'ch2'); TestResultPath = $wrong }
        $r.ExitCode | Should -Not -Be 0
        $r.Output | Should -Match 'does not reference version|not the one the tests ran against|built module at'
    }

    It 'refuses when the tested build is gone, so provenance cannot be established' {
        # output/module/GraphKit/9.9.9 does not exist, so nothing ties this package to a run.
        $pkg = New-FakeNupkg -Root $TestDrive
        $result = New-PassingResult -Root $TestDrive -Version '9.9.9'
        $r = Invoke-Publish @{ PackagePath = $pkg; Channel = 'FileSystem'; Destination = (Join-Path $TestDrive 'ch3'); TestResultPath = $result }
        $r.ExitCode | Should -Not -Be 0
        $r.Output | Should -BeLike '*cannot be tied back to the tested bits*'
    }

    It 'refuses a gate-failing test result' {
        $pkg = New-FakeNupkg -Root $TestDrive
        $failing = Join-Path $TestDrive 'NUnitXml_GraphKit_v9.9.9.Fail.xml'
        @'
<?xml version="1.0" encoding="utf-8" standalone="no"?>
<test-results name="GraphKit" total="772" errors="0" failures="4" not-run="0" inconclusive="0" ignored="0" skipped="0" invalid="0" date="2026-08-15" time="12:00:00">
  <test-suite type="TestFixture" name="GraphKit" executed="True" result="Failure" success="False" time="1.0" asserts="0" />
</test-results>
'@ | Set-Content -LiteralPath $failing -Encoding utf8
        $r = Invoke-Publish @{ PackagePath = $pkg; Channel = 'FileSystem'; Destination = (Join-Path $TestDrive 'ch4'); TestResultPath = $failing }
        $r.ExitCode | Should -Not -Be 0
        $r.Output | Should -BeLike '*did not pass the whole-result gate*'
    }

    Context 'channel immutability' {

        It 'refuses to replace an existing version with different bytes' {
            # Replacing a version under an existing pin makes every pin naming it a lie.
            $channel = Join-Path $TestDrive 'immutable'
            $null = New-Item -ItemType Directory -Path $channel -Force

            $first = New-FakeNupkg -Root $TestDrive -Psm1Content 'body one'
            $r1 = Invoke-Publish @{ PackagePath = $first; Channel = 'FileSystem'; Destination = $channel; SkipTestProof = $true; PinPath = (Join-Path $TestDrive 'p1.json') }
            $r1.ExitCode | Should -Be 0

            $second = New-FakeNupkg -Root (Join-Path $TestDrive 'v2') -Psm1Content 'body two DIFFERENT'
            $r2 = Invoke-Publish @{ PackagePath = $second; Channel = 'FileSystem'; Destination = $channel; SkipTestProof = $true; PinPath = (Join-Path $TestDrive 'p2.json') }
            $r2.ExitCode | Should -Not -Be 0
            $r2.Output | Should -BeLike '*DIFFERENT bytes*'
        }

        It 'accepts a republish of byte-identical content as a no-op' {
            $channel = Join-Path $TestDrive 'idempotent'
            $null = New-Item -ItemType Directory -Path $channel -Force
            $pkg = New-FakeNupkg -Root (Join-Path $TestDrive 'same') -Psm1Content 'identical body'

            $r1 = Invoke-Publish @{ PackagePath = $pkg; Channel = 'FileSystem'; Destination = $channel; SkipTestProof = $true; PinPath = (Join-Path $TestDrive 'q1.json') }
            $r2 = Invoke-Publish @{ PackagePath = $pkg; Channel = 'FileSystem'; Destination = $channel; SkipTestProof = $true; PinPath = (Join-Path $TestDrive 'q2.json') }
            $r1.ExitCode | Should -Be 0
            $r2.ExitCode | Should -Be 0
            $r2.Output | Should -BeLike '*Already published with identical bytes*'
        }
    }

    It 'writes a pin record naming the exact bytes' {
        $channel = Join-Path $TestDrive 'pinned'
        $pkg = New-FakeNupkg -Root (Join-Path $TestDrive 'pinsrc')
        $pinPath = Join-Path $TestDrive 'pin.json'
        $r = Invoke-Publish @{ PackagePath = $pkg; Channel = 'FileSystem'; Destination = $channel; SkipTestProof = $true; PinPath = $pinPath }
        $r.ExitCode | Should -Be 0

        $pin = Get-Content -LiteralPath $pinPath -Raw | ConvertFrom-Json
        $pin.version | Should -Be '9.9.9'
        $pin.sha256 | Should -Be (Get-FileHash -LiteralPath $pkg -Algorithm SHA256).Hash
        $pin.testProof | Should -BeLike '*without test proof*'
    }
}
