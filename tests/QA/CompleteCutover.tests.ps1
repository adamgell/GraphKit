BeforeAll {
    # Complete-GraphKitCutover.ps1 deletes files on a production execution host, and it is the
    # one script here that cannot be exercised on this platform: it throws immediately off
    # Windows, by design, so its interesting paths never run in this suite. That is exactly
    # the situation where this repository has been bitten before - Assert-GateResult was the
    # safety net everything depended on and had no tests, and it had a real bug.
    #
    # These are AST tests, the pattern already used for New-ClientServicePrincipalCBA: they
    # assert structural safety properties that cannot be executed here. Each was mutation
    # checked by hand - break the property in the script and the test fails.
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
        $retireIndex = $script:text.IndexOf('$RetireLegacyLayer')
        $throwIndex | Should -BeGreaterThan 0
        # The -not $RetireLegacyLayer report block and the git rm both live after the throw.
        $script:text.IndexOf('git rm') | Should -BeGreaterThan $throwIndex
    }

    It 'restores the repoint flag in a finally block' {
        # A failed verification must not leave the repoint switched on for the host.
        $tryStatements = $script:ast.FindAll({
                param($node) $node -is [System.Management.Automation.Language.TryStatementAst]
            }, $true)

        $restoring = @($tryStatements | Where-Object {
                $null -ne $_.Finally -and $_.Finally.Extent.Text -match 'IHA_GRAPHKIT_REPOINT'
            })
        @($restoring).Count | Should -BeGreaterThan 0 -Because 'the flag must be restored even when verification throws'
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
        $script:text | Should -Match '\$PSCmdlet\.ShouldProcess\([^)]*Retire'
    }
}
