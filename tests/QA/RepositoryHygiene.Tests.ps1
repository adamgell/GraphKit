BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath

    if (-not (Get-Command -Name git -ErrorAction SilentlyContinue)) {
        throw 'Repository hygiene tests require git because .gitignore behavior, not file text, is the contract.'
    }

    function Get-GitIgnoreExitCode {
        param([Parameter(Mandatory)] [string] $Path)

        & git -C $script:repoRoot check-ignore --quiet --no-index -- $Path
        return $LASTEXITCODE
    }
}

Describe 'Repository hygiene' -Tag 'QA' {
    It 'ignores local .env without reading it' {
        Get-GitIgnoreExitCode -Path '.env' | Should -Be 0
        $trackedEnv = @(& git -C $script:repoRoot ls-files --cached -- '.env')
        $LASTEXITCODE | Should -Be 0
        $trackedEnv | Should -BeNullOrEmpty
    }

    It 'ignores isolated worktrees' {
        Get-GitIgnoreExitCode -Path '.worktrees/r0-marker' | Should -Be 0
    }

    It 'does not ignore tracked-source docs' {
        Get-GitIgnoreExitCode -Path 'docs/r0-marker.md' | Should -Be 1
    }

    It 'pins every declared dependency to an exact version' {
        $dependencies = Import-PowerShellDataFile -Path (Join-Path $script:repoRoot 'RequiredModules.psd1')
        $unversioned = @(
            $dependencies.GetEnumerator() |
                Where-Object { $_.Key -ne 'PSDependOptions' } |
                Where-Object { [string] $_.Value -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$' } |
                ForEach-Object Key
        )

        $unversioned | Should -BeNullOrEmpty
    }
}
