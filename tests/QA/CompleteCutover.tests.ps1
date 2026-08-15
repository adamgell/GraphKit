BeforeAll {
    # Complete-GraphKitCutover.ps1 deletes files on a production execution host, and it is the
    # one script here that cannot be exercised on this platform: it throws immediately off
    # Windows, by design, so its interesting paths never run in this suite. That is exactly
    # the situation where this repository has been bitten before - Assert-GateResult was the
    # safety net everything depended on and had no tests, and it had a real bug.
    #
    # These are AST tests, the pattern already used for New-ClientServicePrincipalCBA: they
    # assert structural safety properties that cannot be executed here. They were mutation
    # tested - each property was broken in the script and the corresponding test confirmed to
    # fail. That pass was worth running: the finally-block assertion originally only checked
    # that the block MENTIONED the variable, and a mutation deleting the unset branch survived
    # it. It is now strict about both directions.
    $script:scriptPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'scripts/Complete-GraphKitCutover.ps1'

    $tokens = $null
    $errors = $null
    $script:ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:scriptPath, [ref] $tokens, [ref] $errors)
    $script:parseErrors = $errors
    $script:text = Get-Content -LiteralPath $script:scriptPath -Raw
}

Describe 'Complete-GraphKitCutover safety properties' {

    It 'parses without error' {
        $script:parseErrors | Should -BeNullOrEmpty
    }

    It 'refuses to run off Windows before doing anything else' {
        # The platform guard must precede the module import and every tenant call. If it ran
        # later, a partially-completed run on the wrong host becomes possible.
        $guardIndex = $script:text.IndexOf('if (-not $IsWindows)')
        $guardIndex | Should -BeGreaterThan 0

        $importIndex = $script:text.IndexOf('Import-Module GraphKit')
        $importIndex | Should -BeGreaterThan $guardIndex -Because 'the platform guard must come before the module is loaded'
    }

    It 'throws rather than warns when verification fails' {
        # A warning would let execution continue to the retirement block. The distinction is
        # the whole safety property: the thing being deleted is the fallback.
        $script:text | Should -Match 'if \(-not \$verified\) \{[^}]*throw'
    }

    It 'gates retirement on verification performed in the same run' {
        # $verified is set only by the probe loop in this run; it is never read from a file,
        # a parameter, or an environment variable, so a previous green run cannot authorise
        # a deletion now.
        $assignments = $script:ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left.Extent.Text -eq '$verified'
            }, $true)

        @($assignments).Count | Should -BeGreaterThan 0
        foreach ($assignment in $assignments) {
            $assignment.Right.Extent.Text | Should -Not -Match 'env:|Get-Content|Import-Clixml|param'
        }
    }

    It 'reaches the failure throw before any retirement code' {
        $throwIndex = $script:text.IndexOf('The legacy layer must stay')
        $throwIndex | Should -BeGreaterThan 0

        # Locate the actual INVOCATION via the AST, not the phrase 'git rm' - that also
        # appears in the .DESCRIPTION near the top of the file, and matching documentation
        # instead of code is how a structural test passes while proving nothing.
        $gitRemovals = $script:ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -eq 'git' -and
                $node.Extent.Text -match '\brm\b'
            }, $true)

        @($gitRemovals).Count | Should -BeGreaterThan 0
        foreach ($removal in $gitRemovals) {
            $removal.Extent.StartOffset | Should -BeGreaterThan $throwIndex
        }
    }

    It 'restores both repoint variables in a finally block, in both directions' {
        # A failed verification must not leave the repoint switched on for the host.
        #
        # An earlier version of this test only asserted that the finally block MENTIONED
        # IHA_GRAPHKIT_REPOINT, and a mutation that deleted the unset branch survived it.
        # That mutation is the dangerous one: if the variable was not set before the run,
        # restoring only the assignment branch leaves the repoint switched ON for the host
        # afterwards. Both directions must be present for both variables.
        $tryStatements = $script:ast.FindAll({
                param($node) $node -is [System.Management.Automation.Language.TryStatementAst]
            }, $true)

        $finallyBlocks = @($tryStatements | Where-Object { $null -ne $_.Finally } |
                ForEach-Object { $_.Finally.Extent.Text } |
                Where-Object { $_ -match 'IHA_GRAPHKIT_REPOINT' })

        @($finallyBlocks).Count | Should -BeGreaterThan 0 -Because 'the flag must be restored even when verification throws'

        $restore = $finallyBlocks -join "`n"
        foreach ($variable in 'IHA_GRAPHKIT_REPOINT', 'IHA_GRAPHKIT_PROFILE') {
            $restore | Should -Match "Remove-Item Env:\\$variable" -Because "$variable must be UNSET again when it was unset before the run"
            $restore | Should -Match "\`$env:$variable\s*=" -Because "$variable must be restored to its prior value when it had one"
        }
    }

    It 'never bare-deletes the legacy files' {
        # Retirement goes through git rm on a branch so it is a reviewable diff and
        # recoverable from history. A Remove-Item on those paths would be unrecoverable.
        $removeItemCalls = $script:ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -in @('Remove-Item', 'del', 'rm')
            }, $true)

        foreach ($call in $removeItemCalls) {
            # The only permitted Remove-Item calls are the environment-variable cleanups.
            $call.Extent.Text | Should -Match 'Env:\\' -Because "unexpected deletion: $($call.Extent.Text)"
        }
    }

    It 'performs only read-only probes during verification' {
        # Verification must not mutate a customer tenant. Every probe is a GET through the
        # shim; no assign/POST/PATCH/DELETE appears in the verification section.
        $verifySection = $script:text.Substring(
            $script:text.IndexOf('[2/3]'),
            $script:text.IndexOf('[3/3]') - $script:text.IndexOf('[2/3]'))

        $verifySection | Should -Not -Match "-Method\s+'?(POST|PATCH|PUT|DELETE)"
        $verifySection | Should -Not -Match '/assign'
    }

    It 'declares ShouldProcess so -WhatIf works on a production host' {
        $script:text | Should -Match 'CmdletBinding\(SupportsShouldProcess\)'
        # And the retirement itself is inside a ShouldProcess check.
        # A character class excluding ')' breaks on the nested $($present.Count), so match
        # across the whole call instead.
        $script:text | Should -Match '(?s)\$PSCmdlet\.ShouldProcess\(.{0,120}?Retire'
    }
}
