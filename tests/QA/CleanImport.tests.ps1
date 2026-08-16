BeforeAll {
    # Importing the built module must leave the session's error stream EMPTY.
    #
    # This exists because a defect escaped every other gate here. The module-load guard used
    # `Get-Command -Name X -ErrorAction SilentlyContinue` to test whether a function existed.
    # SilentlyContinue suppresses the *display* of an error, not the record: Get-Command still
    # wrote a CommandNotFoundException into $Error. The guard was false on every normal import,
    # so GraphKit dirtied $Error every single time it loaded. Nothing threw, nothing failed, and
    # 630 tests stayed green - it was found by an external reviewer importing a consumer module.
    #
    # Two things about how it is asserted matter:
    #
    #   - `Should -Not -Throw` would pass. A non-terminating error is not an exception. Asserting
    #     the absence of an exception says nothing about the error stream, and that gap is
    #     exactly how this survived.
    #   - `Import-Module -ErrorVariable ev` does NOT capture it either. -ErrorVariable collects
    #     errors from the Import-Module cmdlet itself, not errors recorded while the module body
    #     executes. Only $Error sees those.
    #
    # So the check runs in a CLEAN pwsh - this session has already imported GraphKit and has a
    # populated $Error - clears $Error, imports, and reports what is left.
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
    $built = Get-ChildItem -Path (Join-Path $script:repoRoot 'output/module/GraphKit') -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $built) {
        throw 'GraphKit is not built. Run ./build.ps1 -Tasks build first.'
    }
    $script:manifestPath = Join-Path $built.FullName 'GraphKit.psd1'

    function Invoke-CleanImportProbe {
        param([string] $ImportStatement)

        $probe = @"
`$ErrorActionPreference = 'Continue'
`$Error.Clear()
$ImportStatement
[pscustomobject]@{
    ErrorCount = `$Error.Count
    Errors     = @(`$Error | ForEach-Object {
        '{0}: {1} (at {2}:{3})' -f `$_.Exception.GetType().Name,
                                   (`$_.Exception.Message -replace '\s+', ' '),
                                   (Split-Path `$_.InvocationInfo.ScriptName -Leaf),
                                   `$_.InvocationInfo.ScriptLineNumber
    })
    Commands   = @(Get-Command -Module GraphKit).Count
} | ConvertTo-Json -Depth 4 -Compress
"@
        $raw = & pwsh -NoProfile -Command $probe 2>&1
        $json = @($raw | Where-Object { $_ -is [string] -and $_.TrimStart().StartsWith('{') }) | Select-Object -Last 1
        if (-not $json) { throw "Probe produced no result. Output was:`n$($raw -join "`n")" }
        return $json | ConvertFrom-Json
    }
}

Describe 'Built module imports cleanly' {

    It 'writes nothing to the error stream when imported by path' {
        $result = Invoke-CleanImportProbe "Import-Module '$script:manifestPath' -Force"

        # -Because carries the diagnosis: the failure text is otherwise just a number.
        $result.ErrorCount | Should -Be 0 -Because "importing GraphKit must leave `$Error empty; got: $($result.Errors -join ' | ')"
        $result.Commands | Should -BeGreaterThan 0
    }

    It 'writes nothing to the error stream when imported by name' {
        # The path a consumer actually takes: resolution through PSModulePath.
        $installed = Get-Module GraphKit -ListAvailable | Select-Object -First 1
        if ($null -eq $installed) {
            Set-ItResult -Skipped -Because 'GraphKit is not installed on PSModulePath; the by-path case above still covers module-body load errors'
            return
        }

        $result = Invoke-CleanImportProbe 'Import-Module GraphKit -Force'
        $result.ErrorCount | Should -Be 0 -Because "importing GraphKit by name must leave `$Error empty; got: $($result.Errors -join ' | ')"
    }

    It 'writes nothing to the error stream when imported twice' {
        # A re-import re-runs the module body, so any load-time error is emitted again.
        $result = Invoke-CleanImportProbe "Import-Module '$script:manifestPath' -Force; Import-Module '$script:manifestPath' -Force"
        $result.ErrorCount | Should -Be 0 -Because "re-importing must also leave `$Error empty; got: $($result.Errors -join ' | ')"
    }

    It 'registers its handler strategies despite the import-time guard being false' {
        # The guard this test was written for is false on a normal import, by design: the
        # registry is concatenated after this file. Registration therefore happens lazily on
        # first use, and that path must work - otherwise silencing the error would hide a
        # module that cannot resolve any strategy.
        $probe = @"
Import-Module '$script:manifestPath' -Force
& (Get-Module GraphKit) {
    Ensure-GraphV1StrategiesRegistered
    @(`$script:GraphHandlerStrategyRegistry.Keys).Count
}
"@
        $count = & pwsh -NoProfile -Command $probe 2>&1 | Select-Object -Last 1
        [int] $count | Should -Be 5 -Because 'all five v1 strategies must register: Collection, Singleton, Action, Reconciliation, LongRunningJob'
    }
}
