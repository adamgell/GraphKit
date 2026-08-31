BeforeAll {
    $script:versionScript = Join-Path (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath 'scripts/Get-GraphKitTrainVersion.ps1'

    function New-R8TrainVersionFixture {
        $root = Join-Path $TestDrive ('source-state-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path (Join-Path $root 'source/Private') -Force
        Set-Content -LiteralPath (Join-Path $root '.gitignore') -Value "output/`n.git-order`n" -NoNewline -Encoding utf8NoBOM
        Set-Content -LiteralPath (Join-Path $root 'source/Private/Tracked-One.ps1') -Value "'one'`n" -NoNewline -Encoding utf8NoBOM
        Set-Content -LiteralPath (Join-Path $root 'source/Private/Tracked-Two.ps1') -Value "'two'`n" -NoNewline -Encoding utf8NoBOM
        & git -C $root init --quiet
        & git -C $root add .gitignore source
        & git -C $root -c user.name='GraphKit QA' -c user.email='qa@example.invalid' commit --quiet -m 'fixture'
        return $root
    }

    function Get-R8TrainVersion {
        param([Parameter(Mandatory)] [string] $RepositoryRoot)

        $output = & pwsh -NoLogo -NoProfile -File $script:versionScript -RepositoryRoot $RepositoryRoot 2>&1 | Out-String
        [pscustomobject] @{
            ExitCode = $LASTEXITCODE
            Output = $output.Trim()
        }
    }
}

Describe 'GraphKit R8 train source-entry identity' -Tag 'QA' {
    It 'marks a non-ignored untracked package-producing regular file dirty' {
        $root = New-R8TrainVersionFixture
        Set-Content -LiteralPath (Join-Path $root 'source/Private/Untracked.ps1') -Value "'untracked bytes'`n" -NoNewline -Encoding utf8NoBOM

        $result = Get-R8TrainVersion -RepositoryRoot $root

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Output | Should -Match '^0\.4\.0-r8\.g[0-9a-f]{12}\.d[0-9a-f]{12}$'
    }

    It 'is independent of diff.orderFile for a multi-file tracked dirty state' {
        $root = New-R8TrainVersionFixture
        Set-Content -LiteralPath (Join-Path $root 'source/Private/Tracked-One.ps1') -Value "'one changed'`n" -NoNewline -Encoding utf8NoBOM
        Set-Content -LiteralPath (Join-Path $root 'source/Private/Tracked-Two.ps1') -Value "'two changed'`n" -NoNewline -Encoding utf8NoBOM
        $first = Get-R8TrainVersion -RepositoryRoot $root
        Set-Content -LiteralPath (Join-Path $root '.git-order') -Value "source/Private/Tracked-Two.ps1`nsource/Private/Tracked-One.ps1`n" -NoNewline -Encoding utf8NoBOM
        & git -C $root config diff.orderFile .git-order
        $second = Get-R8TrainVersion -RepositoryRoot $root

        $first.ExitCode | Should -Be 0 -Because $first.Output
        $second.ExitCode | Should -Be 0 -Because $second.Output
        $second.Output | Should -Be $first.Output
    }

    It 'changes identity when one byte in a dirty regular file changes' {
        $root = New-R8TrainVersionFixture
        $path = Join-Path $root 'source/Private/Untracked.ps1'
        [IO.File]::WriteAllBytes($path, [byte[]] @(1, 2, 3))
        $first = Get-R8TrainVersion -RepositoryRoot $root
        [IO.File]::WriteAllBytes($path, [byte[]] @(1, 2, 4))
        $second = Get-R8TrainVersion -RepositoryRoot $root

        $first.ExitCode | Should -Be 0 -Because $first.Output
        $second.ExitCode | Should -Be 0 -Because $second.Output
        $second.Output | Should -Not -Be $first.Output
    }

    It 'is independent of the creation order of equivalent untracked paths' {
        $root = New-R8TrainVersionFixture
        $firstPath = Join-Path $root 'source/Private/a.ps1'
        $secondPath = Join-Path $root 'source/Private/z.ps1'
        Set-Content -LiteralPath $secondPath -Value "'z'`n" -NoNewline -Encoding utf8NoBOM
        Set-Content -LiteralPath $firstPath -Value "'a'`n" -NoNewline -Encoding utf8NoBOM
        $forward = Get-R8TrainVersion -RepositoryRoot $root
        Remove-Item -LiteralPath $firstPath, $secondPath -Force
        Set-Content -LiteralPath $firstPath -Value "'a'`n" -NoNewline -Encoding utf8NoBOM
        Set-Content -LiteralPath $secondPath -Value "'z'`n" -NoNewline -Encoding utf8NoBOM
        $reverse = Get-R8TrainVersion -RepositoryRoot $root

        $forward.ExitCode | Should -Be 0 -Because $forward.Output
        $reverse.ExitCode | Should -Be 0 -Because $reverse.Output
        $reverse.Output | Should -Be $forward.Output
    }

    It 'fails closed for an untracked symbolic link rather than dereferencing it' {
        $root = New-R8TrainVersionFixture
        $target = Join-Path $root 'source/Private/target.ps1'
        Set-Content -LiteralPath $target -Value "'target'`n" -NoNewline -Encoding utf8NoBOM
        New-Item -ItemType SymbolicLink -Path (Join-Path $root 'source/Private/link.ps1') -Target $target | Out-Null

        $result = Get-R8TrainVersion -RepositoryRoot $root

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'symbolic link|unsupported'
    }

    It 'fails closed when Git reports an entry that disappears before capture' -Skip:$IsWindows {
        $root = New-R8TrainVersionFixture
        $shimDirectory = Join-Path $TestDrive ('git-missing-shim-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $shimDirectory -Force
        $shimPath = Join-Path $shimDirectory 'git'
        Set-Content -LiteralPath $shimPath -NoNewline -Encoding utf8NoBOM -Value @'
#!/bin/sh
if [ "$1" = "ls-files" ]; then
  printf 'source/Private/disappeared.ps1\0'
  exit 0
fi
exec /usr/bin/git "$@"
'@
        & /bin/chmod +x $shimPath
        $savedPath = $env:PATH
        try {
            $env:PATH = "$shimDirectory$([IO.Path]::PathSeparator)$savedPath"
            $result = Get-R8TrainVersion -RepositoryRoot $root
        }
        finally {
            $env:PATH = $savedPath
        }

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'disappeared|regular file'
    }

    It 'fails closed for a non-UTF-8 Unix path' -Skip:$IsWindows {
        $root = New-R8TrainVersionFixture
        $shimDirectory = Join-Path $TestDrive ('git-shim-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $shimDirectory -Force
        $shimPath = Join-Path $shimDirectory 'git'
        Set-Content -LiteralPath $shimPath -NoNewline -Encoding utf8NoBOM -Value @'
#!/bin/sh
if [ "$1" = "ls-files" ]; then
  printf '\377\0'
  exit 0
fi
exec /usr/bin/git "$@"
'@
        & /bin/chmod +x $shimPath
        $savedPath = $env:PATH
        try {
            $env:PATH = "$shimDirectory$([IO.Path]::PathSeparator)$savedPath"
            $result = Get-R8TrainVersion -RepositoryRoot $root
        }
        finally {
            $env:PATH = $savedPath
        }

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'UTF-8|path'
    }
}
