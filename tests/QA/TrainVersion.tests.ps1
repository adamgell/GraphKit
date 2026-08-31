BeforeAll {
    $script:versionScript = Join-Path (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath 'scripts/Get-GraphKitTrainVersion.ps1'

    function Invoke-R8GitBytes {
        param(
            [Parameter(Mandatory)] [string] $RepositoryRoot,
            [Parameter(Mandatory)] [string[]] $Arguments
        )

        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = 'git'
        $start.WorkingDirectory = $RepositoryRoot
        $start.UseShellExecute = $false
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        foreach ($argument in $Arguments) { $null = $start.ArgumentList.Add($argument) }
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $start
        $null = $process.Start()
        $stream = [IO.MemoryStream]::new()
        $process.StandardOutput.BaseStream.CopyTo($stream)
        $error = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) { throw "git $($Arguments -join ' ') failed: $error" }
        return ,$stream.ToArray()
    }

    function Get-R8TrainVersionOracle {
        param([Parameter(Mandatory)] [string] $RepositoryRoot)

        $revision = [Text.Encoding]::UTF8.GetString((Invoke-R8GitBytes -RepositoryRoot $RepositoryRoot -Arguments @('rev-parse', 'HEAD'))).Trim().ToLowerInvariant()
        $patch = Invoke-R8GitBytes -RepositoryRoot $RepositoryRoot -Arguments @(
            '-c', 'core.autocrlf=false', '-c', 'core.eol=lf', '-c', 'core.quotePath=true',
            'diff', '--no-ext-diff', '--no-textconv', '--no-renames', '--diff-algorithm=myers',
            '--binary', '--src-prefix=a/', '--dst-prefix=b/', 'HEAD'
        )
        $pathsRaw = Invoke-R8GitBytes -RepositoryRoot $RepositoryRoot -Arguments @('ls-files', '--others', '--exclude-standard', '-z')
        $paths = [Collections.Generic.List[byte[]]]::new()
        $offset = 0
        while ($offset -lt $pathsRaw.Length) {
            $end = [Array]::IndexOf($pathsRaw, [byte] 0, $offset)
            if ($end -lt 0) { throw 'Untracked-path stream is not NUL-terminated.' }
            $length = $end - $offset
            $path = [byte[]]::new($length)
            [Array]::Copy($pathsRaw, $offset, $path, 0, $length)
            $paths.Add($path)
            $offset = $end + 1
        }
        $orderedPaths = @($paths | Sort-Object { [Convert]::ToHexString($_) })
        $stream = [IO.MemoryStream]::new()
        $write = {
            param([byte[]] $Bytes)
            $stream.Write($Bytes, 0, $Bytes.Length)
        }
        $u64 = {
            param([int] $Length)
            & $write ([BitConverter]::GetBytes([uint64] $Length))
        }
        & $write ([Text.Encoding]::ASCII.GetBytes('GraphKit-R8-source-state-v1'))
        & $write ([byte[]] @(0))
        & $write ([Text.Encoding]::ASCII.GetBytes('patch'))
        & $u64 $patch.Length
        & $write $patch
        foreach ($path in $orderedPaths) {
            $relativePath = [Text.Encoding]::UTF8.GetString($path)
            $content = [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot $relativePath))
            & $write ([Text.Encoding]::ASCII.GetBytes('untracked'))
            & $u64 $path.Length
            & $write $path
            & $u64 $content.Length
            & $write $content
        }
        & $write ([Text.Encoding]::ASCII.GetBytes('end'))
        & $write ([byte[]] @(0))
        $stateHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream.ToArray())).ToLowerInvariant()
        $clean = $patch.Length -eq 0 -and $orderedPaths.Count -eq 0
        $suffix = if ($clean) { '' } else { ".d$($stateHash.Substring(0, 12))" }
        return "0.4.0-r8.g$($revision.Substring(0, 12))$suffix"
    }

    function New-R8TrainVersionFixture {
        $root = Join-Path $TestDrive ('source-state-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path (Join-Path $root 'source/Private') -Force
        Set-Content -LiteralPath (Join-Path $root '.gitignore') -Value "output/`n" -NoNewline -Encoding utf8NoBOM
        Set-Content -LiteralPath (Join-Path $root 'source/Private/Tracked.ps1') -Value "'tracked'`n" -NoNewline -Encoding utf8NoBOM
        & git -C $root init --quiet
        & git -C $root add .gitignore source
        & git -C $root -c user.name='GraphKit QA' -c user.email='qa@example.invalid' commit --quiet -m 'fixture'
        return $root
    }
}

Describe 'GraphKit R8 train source-state identity' -Tag 'QA' {
    It 'marks a non-ignored untracked package-producing file dirty and binds its bytes' {
        $root = New-R8TrainVersionFixture
        Set-Content -LiteralPath (Join-Path $root 'source/Private/Untracked.ps1') -Value "'untracked bytes'`n" -NoNewline -Encoding utf8NoBOM

        $actual = (& $script:versionScript -RepositoryRoot $root).Trim()
        $expected = Get-R8TrainVersionOracle -RepositoryRoot $root

        $actual | Should -Be $expected
        $actual | Should -Match '\.d[0-9a-f]{12}$'
    }

    It 'uses the same canonical source-state bytes despite Git diff and line-ending configuration' {
        $root = New-R8TrainVersionFixture
        Set-Content -LiteralPath (Join-Path $root 'source/Private/Tracked.ps1') -Value "'changed'`r`n" -NoNewline -Encoding utf8NoBOM
        $expected = Get-R8TrainVersionOracle -RepositoryRoot $root
        $first = (& $script:versionScript -RepositoryRoot $root).Trim()

        & git -C $root config diff.noprefix true
        & git -C $root config core.autocrlf true
        & git -C $root config core.eol crlf
        $second = (& $script:versionScript -RepositoryRoot $root).Trim()

        $first | Should -Be $expected
        $second | Should -Be $expected
    }
}
