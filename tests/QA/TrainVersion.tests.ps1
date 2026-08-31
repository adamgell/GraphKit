BeforeAll {
    $script:versionScript = Join-Path (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath 'scripts/Get-GraphKitTrainVersion.ps1'
    $script:sourceCaptureHelper = Join-Path (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath 'scripts/private/GraphKit.SourceCapture.cs'

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

    function Get-R8TrainVersionWithTimeout {
        param(
            [Parameter(Mandatory)] [string] $RepositoryRoot,
            [Parameter(Mandatory)] [int] $TimeoutMilliseconds
        )

        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = 'pwsh'
        $start.UseShellExecute = $false
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $null = $start.ArgumentList.Add('-NoLogo')
        $null = $start.ArgumentList.Add('-NoProfile')
        $null = $start.ArgumentList.Add('-File')
        $null = $start.ArgumentList.Add($script:versionScript)
        $null = $start.ArgumentList.Add('-RepositoryRoot')
        $null = $start.ArgumentList.Add($RepositoryRoot)
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $start
        $null = $process.Start()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            $process.Kill($true)
            $process.WaitForExit()
            return [pscustomobject] @{ Running = $true; ExitCode = $null; Output = '' }
        }
        [pscustomobject] @{
            Running = $false
            ExitCode = $process.ExitCode
            Output = ($process.StandardOutput.ReadToEnd() + $process.StandardError.ReadToEnd()).Trim()
        }
    }

    function New-R8GitShim {
        param(
            [Parameter(Mandatory)] [string] $Name,
            [Parameter(Mandatory)] [string] $Body
        )

        $shimDirectory = Join-Path $TestDrive ("git-shim-$Name-" + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $shimDirectory -Force
        $shimPath = Join-Path $shimDirectory 'git'
        Set-Content -LiteralPath $shimPath -NoNewline -Encoding utf8NoBOM -Value $Body
        & /bin/chmod +x $shimPath
        return $shimDirectory
    }

    function New-R8PortableGitShim {
        param(
            [Parameter(Mandatory)] [ValidateSet('duplicate-index', 'appearance', 'mutation', 'head-move', 'invalid-tree-oid')] [string] $Mode,
            [hashtable] $Configuration = @{}
        )

        $shimDirectory = Join-Path $TestDrive ("portable-git-shim-$Mode-" + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $shimDirectory -Force
        $payload = @{
            Mode = $Mode
            RealGit = @((Get-Command git -CommandType Application))[0].Source
            Configuration = $Configuration
        } | ConvertTo-Json -Compress -Depth 5
        $encodedPayload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
        $shimScript = Join-Path $shimDirectory 'git-shim.ps1'
        Set-Content -LiteralPath $shimScript -NoNewline -Encoding utf8NoBOM -Value (@'
$ErrorActionPreference = 'Stop'
$payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PAYLOAD__')) | ConvertFrom-Json
$gitArguments = @($args)

function Invoke-RealGit([string[]] $Arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $payload.RealGit
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $null = $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new(); $process.StartInfo = $start; $null = $process.Start()
    $output = [IO.MemoryStream]::new(); $process.StandardOutput.BaseStream.CopyTo($output)
    $errorText = $process.StandardError.ReadToEnd(); $process.WaitForExit()
    [pscustomobject] @{ ExitCode=$process.ExitCode; Output=$output.ToArray(); Error=$errorText }
}

function Write-Result($Result) {
    $stdout = [Console]::OpenStandardOutput(); $stdout.Write($Result.Output, 0, $Result.Output.Length)
    if ($Result.Error) { [Console]::Error.Write($Result.Error) }
    exit $Result.ExitCode
}

$isStage = $gitArguments.Count -ge 2 -and $gitArguments[0] -eq 'ls-files' -and $gitArguments[1] -eq '--stage'
$isOthers = $gitArguments.Count -ge 1 -and $gitArguments[0] -eq 'ls-files' -and $gitArguments -contains '--others'
$isTree = $gitArguments.Count -ge 1 -and $gitArguments[0] -eq 'ls-tree'
switch ($payload.Mode) {
    'duplicate-index' {
        $result = Invoke-RealGit $gitArguments
        if ($isStage -and $result.ExitCode -eq 0) {
            $joined = [byte[]]::new($result.Output.Length * 2)
            [Array]::Copy($result.Output, 0, $joined, 0, $result.Output.Length)
            [Array]::Copy($result.Output, 0, $joined, $result.Output.Length, $result.Output.Length)
            $result.Output = $joined
        }
        Write-Result $result
    }
    'appearance' {
        if ($isOthers) {
            if (-not [IO.File]::Exists($payload.Configuration.Counter)) {
                [IO.File]::WriteAllBytes($payload.Configuration.Counter, [byte[]] @())
                Write-Result ([pscustomobject] @{ ExitCode=0; Output=[byte[]] @(); Error='' })
            }
            [IO.File]::WriteAllText($payload.Configuration.Path, "'appeared'`n", [Text.UTF8Encoding]::new($false))
        }
        Write-Result (Invoke-RealGit $gitArguments)
    }
    'mutation' {
        if ($isOthers) {
            if ([IO.File]::Exists($payload.Configuration.Counter)) {
                [IO.File]::WriteAllText($payload.Configuration.Path, "'mutated after read'`n", [Text.UTF8Encoding]::new($false))
            } else {
                [IO.File]::WriteAllBytes($payload.Configuration.Counter, [byte[]] @())
            }
        }
        Write-Result (Invoke-RealGit $gitArguments)
    }
    'head-move' {
        if ($isOthers -and -not [IO.File]::Exists($payload.Configuration.Counter)) {
            [IO.File]::WriteAllBytes($payload.Configuration.Counter, [byte[]] @())
            $move = Invoke-RealGit @('-C', $payload.Configuration.Root, 'update-ref', 'HEAD', $payload.Configuration.Revision)
            if ($move.ExitCode -ne 0) { Write-Result $move }
        }
        Write-Result (Invoke-RealGit $gitArguments)
    }
    'invalid-tree-oid' {
        $result = Invoke-RealGit $gitArguments
        if ($isTree -and $result.ExitCode -eq 0) {
            $text = [Text.Encoding]::Latin1.GetString($result.Output)
            $text = [Text.RegularExpressions.Regex]::Replace($text, '(?<=blob )[0-9a-f]{40}', { param($match) $match.Value + '0' }, 1)
            $result.Output = [Text.Encoding]::Latin1.GetBytes($text)
        }
        Write-Result $result
    }
}
'@).Replace('__PAYLOAD__', $encodedPayload)

        if ($IsWindows) {
            Set-Content -LiteralPath (Join-Path $shimDirectory 'git.cmd') -NoNewline -Encoding ascii -Value '@pwsh.exe -NoLogo -NoProfile -File "%~dp0git-shim.ps1" %*'
        } else {
            $launcher = Join-Path $shimDirectory 'git'
            Set-Content -LiteralPath $launcher -NoNewline -Encoding utf8NoBOM -Value "#!/bin/sh`nexec pwsh -NoLogo -NoProfile -File '$shimScript' `"`$@`"`n"
            & /bin/chmod +x $launcher
        }
        return $shimDirectory
    }

    function Initialize-R8SourceCaptureHelper {
        $script:sourceCaptureHelper | Should -Exist -Because 'the build-time source capture must be independently testable'
        if (-not ('GraphKit.R8.SourceCapture' -as [type])) {
            Add-Type -Path $script:sourceCaptureHelper
        }
    }
}

Describe 'GraphKit R8 train source-entry identity' -Tag 'QA' {
    It 'fails closed when HEAD moves to a different commit with the same tree during capture' {
        $root = New-R8TrainVersionFixture
        $firstRevision = (& git -C $root rev-parse HEAD).Trim()
        & git -C $root -c user.name='GraphKit QA' -c user.email='qa@example.invalid' commit --quiet --allow-empty -m 'same tree, different commit'
        $secondRevision = (& git -C $root rev-parse HEAD).Trim()
        & git -C $root update-ref HEAD $firstRevision
        $counter = Join-Path $TestDrive ('git-head-move-' + [guid]::NewGuid().ToString('N'))
        $shimDirectory = New-R8PortableGitShim -Mode head-move -Configuration @{
            Counter = $counter
            Root = $root
            Revision = $secondRevision
        }
        $savedPath = $env:PATH
        try {
            $env:PATH = "$shimDirectory$([IO.Path]::PathSeparator)$savedPath"
            $result = Get-R8TrainVersion -RepositoryRoot $root
        }
        finally { $env:PATH = $savedPath }

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'HEAD|revision|commit.*changed'
    }

    It 'rejects a tree object identity whose length does not match the discovered format' {
        $root = New-R8TrainVersionFixture
        $shimDirectory = New-R8PortableGitShim -Mode invalid-tree-oid
        $savedPath = $env:PATH
        try {
            $env:PATH = "$shimDirectory$([IO.Path]::PathSeparator)$savedPath"
            $result = Get-R8TrainVersion -RepositoryRoot $root
        }
        finally { $env:PATH = $savedPath }

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'invalid object identity|unsupported entry header'
    }

    It 'fails closed with an actionable error for a SHA-256 object-format repository' {
        $root = Join-Path $TestDrive ('sha256-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $root -Force
        & git -C $root init --quiet --object-format=sha256
        if ($LASTEXITCODE -ne 0) { Set-ItResult -Skipped -Because 'the installed Git cannot create SHA-256 repositories'; return }
        Set-Content -LiteralPath (Join-Path $root 'tracked.ps1') -Value "'tracked'`n" -NoNewline -Encoding utf8NoBOM
        & git -C $root add tracked.ps1
        & git -C $root -c user.name='GraphKit QA' -c user.email='qa@example.invalid' commit --quiet -m 'sha256 fixture'

        $result = Get-R8TrainVersion -RepositoryRoot $root

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'SHA-256.*not supported|unsupported.*SHA-256'
    }

    It 'treats a Windows-style clean tracked 100755 entry as clean without losing index mode proof' {
        Initialize-R8SourceCaptureHelper
        [GraphKit.R8.SourceCapture]::ResolveEffectiveGitMode('', $false, '100755') | Should -Be '100755'

        if ($IsWindows) {
            $root = New-R8TrainVersionFixture
            & git -C $root update-index --chmod=+x source/Private/Tracked-One.ps1
            & git -C $root -c user.name='GraphKit QA' -c user.email='qa@example.invalid' commit --quiet -m 'tracked executable'
            $revision = (& git -C $root rev-parse HEAD).Trim().Substring(0, 12)

            $result = Get-R8TrainVersion -RepositoryRoot $root

            $result.ExitCode | Should -Be 0 -Because $result.Output
            $result.Output | Should -Be "0.4.0-r8.g$revision"
        }
    }

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
if [ "$1" = "ls-files" ] && printf '%s' "$*" | /usr/bin/grep -q -- '--others'; then
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
if [ "$1" = "ls-files" ] && printf '%s' "$*" | /usr/bin/grep -q -- '--others'; then
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

    It 'marks an executable-mode-only tracked change dirty even when core.filemode is false' -Skip:$IsWindows {
        $root = New-R8TrainVersionFixture
        $path = Join-Path $root 'source/Private/Tracked-One.ps1'
        & /bin/chmod +x $path
        & git -C $root config core.filemode false

        $result = Get-R8TrainVersion -RepositoryRoot $root

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Output | Should -Match '^0\.4\.0-r8\.g[0-9a-f]{12}\.d[0-9a-f]{12}$'
    }

    It 'marks a staged addition dirty' {
        $root = New-R8TrainVersionFixture
        Set-Content -LiteralPath (Join-Path $root 'source/Private/Staged-Added.ps1') -Value "'staged add'`n" -NoNewline -Encoding utf8NoBOM
        & git -C $root add source/Private/Staged-Added.ps1

        $result = Get-R8TrainVersion -RepositoryRoot $root

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Output | Should -Match '\.d[0-9a-f]{12}$'
    }

    It 'marks a staged deletion dirty' {
        $root = New-R8TrainVersionFixture
        & git -C $root rm --quiet source/Private/Tracked-One.ps1

        $result = Get-R8TrainVersion -RepositoryRoot $root

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Output | Should -Match '\.d[0-9a-f]{12}$'
    }

    It 'marks a staged rename dirty' {
        $root = New-R8TrainVersionFixture
        & git -C $root mv source/Private/Tracked-One.ps1 source/Private/Renamed-One.ps1

        $result = Get-R8TrainVersion -RepositoryRoot $root

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Output | Should -Match '\.d[0-9a-f]{12}$'
    }

    It 'marks an unstaged tracked deletion dirty' {
        $root = New-R8TrainVersionFixture
        Remove-Item -LiteralPath (Join-Path $root 'source/Private/Tracked-One.ps1') -Force

        $result = Get-R8TrainVersion -RepositoryRoot $root

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Output | Should -Match '\.d[0-9a-f]{12}$'
    }

    It 'rejects a gitlink index entry rather than representing it as a missing file' {
        $root = New-R8TrainVersionFixture
        $object = (& git -C $root rev-parse HEAD).Trim()
        & git -C $root update-index --add --cacheinfo "160000,$object,source/Private/Nested"

        $result = Get-R8TrainVersion -RepositoryRoot $root

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'gitlink|submodule|unsupported'
    }

    It 'accepts a valid untracked path containing tabs, newlines, and non-ASCII bytes' -Skip:$IsWindows {
        $root = New-R8TrainVersionFixture
        $path = Join-Path $root "source/Private/tab`tline`n雪.ps1"
        Set-Content -LiteralPath $path -Value "'valid path'`n" -NoNewline -Encoding utf8NoBOM

        $result = Get-R8TrainVersion -RepositoryRoot $root

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Output | Should -Match '\.d[0-9a-f]{12}$'
    }

    It 'fails closed when a duplicate index path is reported' {
        $root = New-R8TrainVersionFixture
        $shimDirectory = New-R8PortableGitShim -Mode duplicate-index
        $savedPath = $env:PATH
        try {
            $env:PATH = "$shimDirectory$([IO.Path]::PathSeparator)$savedPath"
            $result = Get-R8TrainVersion -RepositoryRoot $root
        }
        finally { $env:PATH = $savedPath }

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'duplicate'
    }

    It 'rejects an untracked FIFO promptly before opening it' -Skip:$IsWindows {
        $root = New-R8TrainVersionFixture
        $fifo = Join-Path $root 'source/Private/input.fifo'
        & /usr/bin/mkfifo $fifo

        $result = Get-R8TrainVersionWithTimeout -RepositoryRoot $root -TimeoutMilliseconds 3000

        $result.Running | Should -BeFalse -Because 'special files must be rejected rather than opened'
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'regular|special|unsupported'
    }

    It 'fails closed when a non-ignored entry appears after initial enumeration' {
        $root = New-R8TrainVersionFixture
        $appeared = Join-Path $root 'source/Private/appeared.ps1'
        $counter = Join-Path $TestDrive ('git-appearance-' + [guid]::NewGuid().ToString('N'))
        $shimDirectory = New-R8PortableGitShim -Mode appearance -Configuration @{
            Counter = $counter
            Path = $appeared
        }
        $savedPath = $env:PATH
        try {
            $env:PATH = "$shimDirectory$([IO.Path]::PathSeparator)$savedPath"
            $result = Get-R8TrainVersion -RepositoryRoot $root
        }
        finally { $env:PATH = $savedPath }

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'inventory|changed|race'
    }

    It 'fails closed when content mutates after the first metadata/read pass' {
        $root = New-R8TrainVersionFixture
        $path = Join-Path $root 'source/Private/Tracked-One.ps1'
        Set-Content -LiteralPath $path -Value "'dirty before race'`n" -NoNewline -Encoding utf8NoBOM
        $counter = Join-Path $TestDrive ('git-mutation-' + [guid]::NewGuid().ToString('N'))
        $shimDirectory = New-R8PortableGitShim -Mode mutation -Configuration @{
            Counter = $counter
            Path = $path
        }
        $savedPath = $env:PATH
        try {
            $env:PATH = "$shimDirectory$([IO.Path]::PathSeparator)$savedPath"
            $result = Get-R8TrainVersion -RepositoryRoot $root
        }
        finally { $env:PATH = $savedPath }

        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'changed|race|metadata|content'
    }

    It 'matches the fixed R8 source-state known vector' {
        $root = Join-Path $TestDrive ('known-vector-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path (Join-Path $root 'source/Private') -Force
        Set-Content -LiteralPath (Join-Path $root '.gitignore') -Value "output/`n" -NoNewline -Encoding utf8NoBOM
        Set-Content -LiteralPath (Join-Path $root 'source/Private/Tracked.ps1') -Value "'tracked'`n" -NoNewline -Encoding utf8NoBOM
        & git -C $root init --quiet
        & git -C $root add .
        $savedAuthorDate = $env:GIT_AUTHOR_DATE
        $savedCommitterDate = $env:GIT_COMMITTER_DATE
        try {
            $env:GIT_AUTHOR_DATE = '2001-02-03T04:05:06Z'
            $env:GIT_COMMITTER_DATE = '2001-02-03T04:05:06Z'
            & git -C $root -c user.name='GraphKit QA' -c user.email='qa@example.invalid' commit --quiet -m 'fixed vector'
        }
        finally {
            $env:GIT_AUTHOR_DATE = $savedAuthorDate
            $env:GIT_COMMITTER_DATE = $savedCommitterDate
        }
        Set-Content -LiteralPath (Join-Path $root 'source/Private/Untracked.ps1') -Value "'untracked'`n" -NoNewline -Encoding utf8NoBOM

        $state = & $script:versionScript -RepositoryRoot $root -AsObject

        $state.version | Should -Be '0.4.0-r8.g37b8420a67a0.d374f187ae54c'
        $state.sourceStateSha256 | Should -Be '374f187ae54cd351758b49728c5a6e4dc342510eb0606c68520f1c32e8331975'
    }
}

Describe 'GraphKit R8 root-anchored source capture' -Tag 'QA' {
    It 'rejects a Unix symbolic link in an intermediate path segment' -Skip:$IsWindows {
        Initialize-R8SourceCaptureHelper
        $root = Join-Path $TestDrive ('intermediate-link-' + [guid]::NewGuid().ToString('N'))
        $outside = Join-Path $TestDrive ('outside-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path (Join-Path $root 'source') -Force
        $null = New-Item -ItemType Directory -Path $outside -Force
        Set-Content -LiteralPath (Join-Path $outside 'Tracked.ps1') -Value "'same bytes'`n" -NoNewline -Encoding utf8NoBOM
        New-Item -ItemType SymbolicLink -Path (Join-Path $root 'source/Private') -Target $outside | Out-Null

        { [GraphKit.R8.SourceCapture]::Capture($root, 'source/Private/Tracked.ps1') } |
            Should -Throw -ExpectedMessage '*symbolic link*'
    }

    It 'closes Unix final descriptors when post-open type validation throws' -Skip:$IsWindows {
        Initialize-R8SourceCaptureHelper
        $root = Join-Path $TestDrive ('handle-ownership-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $root -Force
        $fifo = Join-Path $root 'unsupported.fifo'
        & /usr/bin/mkfifo $fifo
        { [GraphKit.R8.SourceCapture]::Capture($root, 'unsupported.fifo') } | Should -Throw
        $before = @([IO.Directory]::EnumerateFileSystemEntries('/dev/fd')).Count

        1..64 | ForEach-Object {
            { [GraphKit.R8.SourceCapture]::Capture($root, 'unsupported.fifo') } | Should -Throw
        }

        $after = @([IO.Directory]::EnumerateFileSystemEntries('/dev/fd')).Count
        ($after - $before) | Should -BeLessOrEqual 2 -Because 'every descriptor returned by openat must immediately gain a safe owner'
    }

    It 'rejects a Windows reparse point in an intermediate path segment without retaining handles' {
        Initialize-R8SourceCaptureHelper
        $root = Join-Path $TestDrive ('reparse-root-' + [guid]::NewGuid().ToString('N'))
        $outside = Join-Path $TestDrive ('reparse-outside-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path (Join-Path $root 'source') -Force
        $null = New-Item -ItemType Directory -Path $outside -Force
        Set-Content -LiteralPath (Join-Path $outside 'Tracked.ps1') -Value "'outside'`n" -NoNewline -Encoding utf8NoBOM
        $link = Join-Path $root 'source/Private'
        if ($IsWindows) {
            & cmd.exe /d /c "mklink /J `"$link`" `"$outside`"" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'The Windows test host could not create the required directory junction.' }
            $before = [Diagnostics.Process]::GetCurrentProcess().HandleCount
            1..16 | ForEach-Object {
                { [GraphKit.R8.SourceCapture]::Capture($root, 'source/Private/Tracked.ps1') } |
                    Should -Throw -ExpectedMessage '*reparse point*'
            }
            $after = [Diagnostics.Process]::GetCurrentProcess().HandleCount
        } else {
            New-Item -ItemType SymbolicLink -Path $link -Target $outside | Out-Null
            { [GraphKit.R8.SourceCapture]::Capture($root, 'source/Private/Tracked.ps1') } | Should -Throw
            $before = @([IO.Directory]::EnumerateFileSystemEntries('/dev/fd')).Count
            1..16 | ForEach-Object {
                { [GraphKit.R8.SourceCapture]::Capture($root, 'source/Private/Tracked.ps1') } | Should -Throw
            }
            $after = @([IO.Directory]::EnumerateFileSystemEntries('/dev/fd')).Count
        }
        ($after - $before) | Should -BeLessOrEqual 2
    }
}
