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
        param(
            [Parameter(Mandatory)] [string] $RepositoryRoot,
            [string] $VersionScript = $script:versionScript
        )

        $output = & pwsh -NoLogo -NoProfile -File $VersionScript -RepositoryRoot $RepositoryRoot 2>&1 | Out-String
        [pscustomobject] @{
            ExitCode = $LASTEXITCODE
            Output = $output.Trim()
        }
    }

    function Invoke-R8Bootstrap {
        param([Parameter(Mandatory)] [string] $Content)

        $bootstrap = Join-Path $TestDrive ('r8-bootstrap-' + [guid]::NewGuid().ToString('N') + '.ps1')
        Set-Content -LiteralPath $bootstrap -Value $Content -NoNewline -Encoding utf8NoBOM
        $output = & pwsh -NoLogo -NoProfile -File $bootstrap 2>&1 | Out-String
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

    function New-R8PortableGitShim {
        param(
            [Parameter(Mandatory)] [ValidateSet(
                'duplicate-index',
                'appearance',
                'mutation',
                'head-move',
                'invalid-tree-oid',
                'sha256-format',
                'missing',
                'invalid-path',
                'unmerged-stage',
                'helper-case-alias',
                'case-collision',
                'normalization-collision',
                'stderr-flood',
                'stdin-stdout-flood',
                'reverse-untracked'
            )] [string] $Mode,
            [hashtable] $Configuration = @{}
        )

        $shimDirectory = Join-Path $TestDrive ("portable-git-shim-$Mode-" + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $shimDirectory -Force
        $payload = @{
            Mode = $Mode
            RealGit = @((Get-Command git -CommandType Application))[0].Source
            InvocationLog = Join-Path $shimDirectory 'invocations.log'
            Configuration = $Configuration
        } | ConvertTo-Json -Compress -Depth 5
        $encodedPayload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
        $shimScript = Join-Path $shimDirectory 'git-shim.ps1'
        Set-Content -LiteralPath $shimScript -NoNewline -Encoding utf8NoBOM -Value (@'
$ErrorActionPreference = 'Stop'
$payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PAYLOAD__')) | ConvertFrom-Json
$gitArguments = @($args)
[IO.File]::AppendAllText(
    [string] $payload.InvocationLog,
    (($gitArguments | ConvertTo-Json -Compress) + [Environment]::NewLine),
    [Text.UTF8Encoding]::new($false)
)

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
$isObjectFormat = $gitArguments.Count -ge 2 -and $gitArguments[0] -eq 'rev-parse' -and $gitArguments[1] -eq '--show-object-format'
$isCheckIgnore = $gitArguments.Count -ge 1 -and $gitArguments[0] -eq 'check-ignore'
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
    'sha256-format' {
        if ($isObjectFormat) {
            Write-Result ([pscustomobject] @{ ExitCode=0; Output=[Text.Encoding]::ASCII.GetBytes("sha256`n"); Error='' })
        }
        Write-Result (Invoke-RealGit $gitArguments)
    }
    'missing' {
        if ($isOthers) {
            $bytes = [Text.Encoding]::UTF8.GetBytes('source/Private/disappeared.ps1')
            Write-Result ([pscustomobject] @{ ExitCode=0; Output=[byte[]] @($bytes + [byte] 0); Error='' })
        }
        Write-Result (Invoke-RealGit $gitArguments)
    }
    'invalid-path' {
        if ($isOthers) {
            Write-Result ([pscustomobject] @{ ExitCode=0; Output=[byte[]] @(255, 0); Error='' })
        }
        Write-Result (Invoke-RealGit $gitArguments)
    }
    'unmerged-stage' {
        $result = Invoke-RealGit $gitArguments
        if ($isStage -and $result.ExitCode -eq 0) {
            $text = [Text.Encoding]::Latin1.GetString($result.Output)
            $text = [Text.RegularExpressions.Regex]::Replace(
                $text,
                '(?<= [0-9a-f]{40} )0(?=\t)',
                [string] $payload.Configuration.Stage,
                1
            )
            $result.Output = [Text.Encoding]::Latin1.GetBytes($text)
        }
        Write-Result $result
    }
    'helper-case-alias' {
        if ($isCheckIgnore) {
            $inputBytes = [IO.MemoryStream]::new()
            [Console]::OpenStandardInput().CopyTo($inputBytes)
            Write-Result ([pscustomobject] @{ ExitCode=0; Output=$inputBytes.ToArray(); Error='' })
        }
        $result = Invoke-RealGit $gitArguments
        if (($isTree -or $isStage) -and $result.ExitCode -eq 0) {
            $text = [Text.Encoding]::Latin1.GetString($result.Output)
            $result.Output = [Text.Encoding]::Latin1.GetBytes(
                $text.Replace(
                    [string] $payload.Configuration.CanonicalPath,
                    [string] $payload.Configuration.AliasPath
                )
            )
        }
        Write-Result $result
    }
    'case-collision' {
        $result = Invoke-RealGit $gitArguments
        if ($isStage -and $result.ExitCode -eq 0) {
            $all = [Text.Encoding]::Latin1.GetString($result.Output)
            $pathOffset = $all.IndexOf('Tracked-One.ps1', [StringComparison]::Ordinal)
            if ($pathOffset -lt 0) { throw 'The case-collision shim could not find its tracked fixture path.' }
            $recordStart = $all.LastIndexOf([char] 0, $pathOffset) + 1
            $recordEnd = $all.IndexOf([char] 0, $pathOffset)
            $record = $all.Substring($recordStart, $recordEnd - $recordStart)
            $alias = [Text.Encoding]::Latin1.GetBytes($record.Replace('Tracked-One.ps1', 'tracked-one.ps1'))
            $joined = [byte[]]::new($result.Output.Length + $alias.Length + 1)
            [Array]::Copy($result.Output, 0, $joined, 0, $result.Output.Length)
            [Array]::Copy($alias, 0, $joined, $result.Output.Length, $alias.Length)
            $joined[$joined.Length - 1] = 0
            $result.Output = $joined
        }
        Write-Result $result
    }
    'normalization-collision' {
        $result = Invoke-RealGit $gitArguments
        if ($isStage -and $result.ExitCode -eq 0) {
            $tab = [Array]::IndexOf($result.Output, [byte] 9)
            $header = [Text.Encoding]::ASCII.GetString($result.Output, 0, $tab + 1)
            $first = [Text.Encoding]::UTF8.GetBytes($header + "source/Private/Caf$([char]0x00e9).ps1")
            $second = [Text.Encoding]::UTF8.GetBytes($header + "source/Private/Cafe$([char]0x0301).ps1")
            $joined = [byte[]]::new($result.Output.Length + $first.Length + $second.Length + 2)
            [Array]::Copy($result.Output, 0, $joined, 0, $result.Output.Length)
            $offset = $result.Output.Length
            [Array]::Copy($first, 0, $joined, $offset, $first.Length); $offset += $first.Length + 1
            [Array]::Copy($second, 0, $joined, $offset, $second.Length)
            $result.Output = $joined
        }
        Write-Result $result
    }
    'stderr-flood' {
        if ($isObjectFormat) {
            [Console]::Error.Write([string]::new([char] 'x', 1MB))
            Write-Result ([pscustomobject] @{
                ExitCode = 0
                Output = [Text.Encoding]::ASCII.GetBytes("sha1`n")
                Error = ''
            })
        }
        Write-Result (Invoke-RealGit $gitArguments)
    }
    'stdin-stdout-flood' {
        if ($isCheckIgnore) {
            $stdout = [Console]::OpenStandardOutput()
            $padding = [Text.Encoding]::ASCII.GetBytes(([string]::new([char] 'x', 8192)) + [char] 0)
            foreach ($index in 1..128) {
                $stdout.Write($padding, 0, $padding.Length)
            }
            $stdout.Flush()

            $inputBytes = [IO.MemoryStream]::new()
            [Console]::OpenStandardInput().CopyTo($inputBytes)
            $input = $inputBytes.ToArray()
            $stdout.Write($input, 0, $input.Length)
            $stdout.Flush()
            exit 0
        }
        Write-Result (Invoke-RealGit $gitArguments)
    }
    'reverse-untracked' {
        $result = Invoke-RealGit $gitArguments
        if ($isOthers -and $result.ExitCode -eq 0) {
            $records = [Collections.Generic.List[byte[]]]::new()
            $offset = 0
            while ($offset -lt $result.Output.Length) {
                $end = [Array]::IndexOf($result.Output, [byte] 0, $offset)
                $record = [byte[]]::new($end - $offset)
                [Array]::Copy($result.Output, $offset, $record, 0, $record.Length)
                $records.Add($record); $offset = $end + 1
            }
            $stream = [IO.MemoryStream]::new()
            for ($index = $records.Count - 1; $index -ge 0; $index--) {
                $stream.Write($records[$index], 0, $records[$index].Length); $stream.WriteByte(0)
            }
            $result.Output = $stream.ToArray()
        }
        Write-Result $result
    }
}
'@).Replace('__PAYLOAD__', $encodedPayload)

        if ($IsWindows) {
            $launcherTemplate = Join-Path $TestDrive 'r8-git-shim-launcher.exe'
            if (-not (Test-Path -LiteralPath $launcherTemplate -PathType Leaf)) {
                $compiler = @(
                    Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
                    Join-Path $env:WINDIR 'Microsoft.NET/Framework/v4.0.30319/csc.exe'
                ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
                if (-not $compiler) {
                    throw 'The Windows test host has no executable-compatible C# compiler for the Git shim launcher.'
                }
                $launcherSource = Join-Path $TestDrive 'r8-git-shim-launcher.cs'
                Set-Content -LiteralPath $launcherSource -NoNewline -Encoding utf8NoBOM -Value @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;

internal static class GitShimLauncher
{
    private static string Quote(string value)
    {
        var builder = new StringBuilder();
        builder.Append('"');
        int backslashes = 0;
        foreach (char character in value)
        {
            if (character == '\\')
            {
                backslashes++;
                continue;
            }
            if (character == '"')
            {
                builder.Append('\\', backslashes * 2 + 1);
                builder.Append('"');
                backslashes = 0;
                continue;
            }
            builder.Append('\\', backslashes);
            backslashes = 0;
            builder.Append(character);
        }
        builder.Append('\\', backslashes * 2);
        builder.Append('"');
        return builder.ToString();
    }

    public static int Main(string[] arguments)
    {
        try
        {
            string shim = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "git-shim.ps1");
            var forwarded = new List<string> { "-NoLogo", "-NoProfile", "-File", shim };
            forwarded.AddRange(arguments);
            var quoted = new List<string>();
            foreach (string argument in forwarded) quoted.Add(Quote(argument));
            var start = new ProcessStartInfo
            {
                FileName = "pwsh.exe",
                Arguments = string.Join(" ", quoted.ToArray()),
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using (Process process = Process.Start(start))
            {
                Task input = Task.Run(() =>
                {
                    Console.OpenStandardInput().CopyTo(process.StandardInput.BaseStream);
                    process.StandardInput.Close();
                });
                Task output = Task.Run(() => process.StandardOutput.BaseStream.CopyTo(Console.OpenStandardOutput()));
                Task error = Task.Run(() => process.StandardError.BaseStream.CopyTo(Console.OpenStandardError()));
                process.WaitForExit();
                Task.WaitAll(input, output, error);
                return process.ExitCode;
            }
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception);
            return 127;
        }
    }
}
'@
                $compilerOutput = & $compiler /nologo /target:exe "/out:$launcherTemplate" $launcherSource 2>&1
                if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $launcherTemplate -PathType Leaf)) {
                    throw "The Windows Git shim launcher did not compile: $($compilerOutput | Out-String)"
                }
            }
            Copy-Item -LiteralPath $launcherTemplate -Destination (Join-Path $shimDirectory 'git.exe')
        } else {
            $launcher = Join-Path $shimDirectory 'git'
            Set-Content -LiteralPath $launcher -NoNewline -Encoding utf8NoBOM -Value "#!/bin/sh`nexec pwsh -NoLogo -NoProfile -File '$shimScript' `"`$@`"`n"
            & /bin/chmod +x $launcher
        }
        return $shimDirectory
    }

    function Assert-R8PortableGitShimInvoked {
        param([Parameter(Mandatory)] [string] $ShimDirectory)

        $invocationLog = Join-Path $ShimDirectory 'invocations.log'
        $invocationLog | Should -Exist -Because 'every injected case must prove the executable shim handled the Git call'
        (Get-Content -LiteralPath $invocationLog -Raw) | Should -Not -BeNullOrEmpty
    }

    function Initialize-R8SourceCaptureHelper {
        $script:sourceCaptureHelper | Should -Exist -Because 'the build-time source capture must be independently testable'
        if (-not $script:sourceCaptureType) {
            $source = Get-Content -LiteralPath $script:sourceCaptureHelper -Raw
            $marker = '__GRAPHKIT_SOURCE_CAPTURE_NAMESPACE__'
            if ($source.Contains($marker)) {
                $namespace = 'GraphKit.R8.QA.N' + [guid]::NewGuid().ToString('N')
                $types = @(Add-Type -TypeDefinition $source.Replace($marker, $namespace) -PassThru)
                $sourceCaptureMatches = @($types | Where-Object FullName -CEQ "$namespace.SourceCapture")
                if ($sourceCaptureMatches.Count -ne 1) {
                    throw 'The GraphKit source-capture helper did not load exactly once.'
                }
                $script:sourceCaptureType = $sourceCaptureMatches[0]
            }
            else {
                if (-not ('GraphKit.R8.SourceCapture' -as [type])) {
                    Add-Type -Path $script:sourceCaptureHelper
                }
                $script:sourceCaptureType = 'GraphKit.R8.SourceCapture' -as [type]
            }
        }
        return $script:sourceCaptureType
    }

    function New-R8ControlledIdentityFixture {
        $root = New-R8TrainVersionFixture
        $scripts = Join-Path $root 'scripts'
        $private = Join-Path $scripts 'private'
        $null = New-Item -ItemType Directory -Path $private -Force
        $versionScript = Join-Path $scripts 'Get-GraphKitTrainVersion.ps1'
        $helper = Join-Path $private 'GraphKit.SourceCapture.cs'
        $versionSource = (Get-Content -LiteralPath $script:versionScript -Raw).Replace("`r`n", "`n")
        Set-Content -LiteralPath $versionScript -Value $versionSource -NoNewline -Encoding utf8NoBOM
        $source = (Get-Content -LiteralPath $script:sourceCaptureHelper -Raw).Replace("`r`n", "`n")
        $needle = 'return new CapturedSourceFile(before.Mode, before.HasExecutableMode, before.Identity, before.Length, content);'
        if (-not $source.Contains($needle)) { throw 'The controlled-identity fixture could not locate the capture return contract.' }
        $replacement = @'
string proofIdentity = Environment.GetEnvironmentVariable("GRAPHKIT_TEST_CAPTURE_IDENTITY") ?? before.Identity;
            return new CapturedSourceFile(before.Mode, before.HasExecutableMode, proofIdentity, before.Length, content);
'@
        Set-Content -LiteralPath $helper -Value $source.Replace($needle, $replacement) -NoNewline -Encoding utf8NoBOM
        & git -C $root add scripts
        & git -C $root -c user.name='GraphKit QA' -c user.email='qa@example.invalid' commit --quiet -m 'controlled helper'
        Set-Content -LiteralPath (Join-Path $root 'source/Private/Untracked.ps1') -Value "'untracked'`n" -NoNewline -Encoding utf8NoBOM
        [pscustomobject] @{ Root = $root; VersionScript = $versionScript }
    }

    function New-R8InternalHelperFixture {
        param([switch] $CaptureSentinel)

        $root = New-R8TrainVersionFixture
        $scripts = Join-Path $root 'scripts'
        $private = Join-Path $scripts 'private'
        $null = New-Item -ItemType Directory -Path $private -Force
        $versionScript = Join-Path $scripts 'Get-GraphKitTrainVersion.ps1'
        $helper = Join-Path $private 'GraphKit.SourceCapture.cs'
        Copy-Item -LiteralPath $script:versionScript -Destination $versionScript
        Copy-Item -LiteralPath $script:sourceCaptureHelper -Destination $helper
        if ($CaptureSentinel) {
            $source = (Get-Content -LiteralPath $helper -Raw).Replace("`r`n", "`n")
            $needle = @'
        public static CapturedSourceFile Capture(string repositoryRoot, string relativePath)
        {
'@
            $replacement = @'
        public static CapturedSourceFile Capture(string repositoryRoot, string relativePath)
        {
            string? captureSentinel = Environment.GetEnvironmentVariable("GRAPHKIT_TEST_CAPTURE_SENTINEL");
            if (!string.IsNullOrEmpty(captureSentinel))
            {
                File.AppendAllText(captureSentinel, relativePath + Environment.NewLine);
            }
'@
            if (-not $source.Contains($needle)) { throw 'The proof-bound sentinel fixture could not locate the generated Capture entry point.' }
            Set-Content -LiteralPath $helper -Value $source.Replace($needle, $replacement) -NoNewline -Encoding utf8NoBOM
        }
        & git -C $root add scripts
        & git -C $root -c user.name='GraphKit QA' -c user.email='qa@example.invalid' commit --quiet -m 'proof-bound helper'
        [pscustomobject] @{ Root = $root; VersionScript = $versionScript; Helper = $helper }
    }

    function New-R8ProofBoundCaptureSentinelFixture {
        New-R8InternalHelperFixture -CaptureSentinel
    }

    function New-R8RepositoryRootAlias {
        param(
            [Parameter(Mandatory)] [string] $Target,
            [Parameter(Mandatory)] [string] $Alias
        )

        if ($IsWindows) {
            $null = New-Item -ItemType Junction -Path $Alias -Target $Target
        }
        else {
            $null = New-Item -ItemType SymbolicLink -Path $Alias -Target $Target
        }

        return (Get-Item -LiteralPath $Alias -Force).FullName
    }

    $script:ambientCaptureSource = @'
using System;
using System.IO;

namespace GraphKit.R8
{
    public sealed class CapturedSourceFile
    {
        public string Mode => "100644";
        public bool HasExecutableMode => false;
        public string Identity => "ambient:malicious";
        public long Length => 0;
        public byte[] Content => Array.Empty<byte>();
    }

    public static class SourceCapture
    {
        public static string ResolveEffectiveGitMode(string capturedMode, bool hasExecutableMode, string indexMode) => indexMode ?? "100644";

        public static CapturedSourceFile Capture(string repositoryRoot, string relativePath)
        {
            string sentinel = Environment.GetEnvironmentVariable("GRAPHKIT_TEST_CAPTURE_SENTINEL");
            if (!string.IsNullOrEmpty(sentinel)) File.WriteAllText(sentinel, relativePath);
            throw new InvalidOperationException("ambient helper invoked");
        }
    }
}
'@
}

Describe 'GraphKit R8 train source-entry identity' -Tag 'QA' {
    It 'provides a directly executable Git shim and records interception instead of falling through to real Git' {
        $root = New-R8TrainVersionFixture
        $shimDirectory = New-R8PortableGitShim -Mode reverse-untracked
        $launcher = Join-Path $shimDirectory $(if ($IsWindows) { 'git.exe' } else { 'git' })
        $invocationLog = Join-Path $shimDirectory 'invocations.log'
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $launcher
        $start.WorkingDirectory = $root
        $start.UseShellExecute = $false
        $start.RedirectStandardInput = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $null = $start.ArgumentList.Add('rev-parse')
        $null = $start.ArgumentList.Add('--show-object-format')
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $start

        $null = $process.Start()
        $process.StandardInput.Close()
        $output = $process.StandardOutput.ReadToEnd()
        $errorText = $process.StandardError.ReadToEnd()
        $process.WaitForExit()

        $process.ExitCode | Should -Be 0 -Because $errorText
        $output.Trim() | Should -Be 'sha1'
        $invocationLog | Should -Exist -Because 'the injected process must prove the shim, not a PATH-resolved real Git, handled the call'
        (Get-Content -LiteralPath $invocationLog -Raw) | Should -Match 'rev-parse.*--show-object-format'

        $floodShim = New-R8PortableGitShim -Mode stderr-flood
        $savedPath = $env:PATH
        try {
            $env:PATH = "$floodShim$([IO.Path]::PathSeparator)$savedPath"
            $floodResult = Get-R8TrainVersionWithTimeout -RepositoryRoot $root -TimeoutMilliseconds 30000
        }
        finally {
            $env:PATH = $savedPath
        }
        Assert-R8PortableGitShimInvoked -ShimDirectory $floodShim
        $floodResult.Running | Should -BeFalse `
            -Because 'stdout and stderr must drain concurrently even when stderr exceeds the pipe buffer'
        $floodResult.ExitCode | Should -Be 0 -Because $floodResult.Output
        $floodResult.Output | Should -Match '^0\.4\.0-r8\.g[0-9a-f]{12}$'

        $bidirectionalRoot = New-R8TrainVersionFixture
        $ignoredRoot = Join-Path $bidirectionalRoot 'output'
        $null = New-Item -ItemType Directory -Path $ignoredRoot -Force
        foreach ($index in 1..1024) {
            $name = 'ignored-{0:D4}-{1}.tmp' -f $index, ([string]::new([char] 'y', 80))
            [IO.File]::WriteAllBytes((Join-Path $ignoredRoot $name), [byte[]] @(1))
        }
        $bidirectionalShim = New-R8PortableGitShim -Mode stdin-stdout-flood
        $savedPath = $env:PATH
        try {
            $env:PATH = "$bidirectionalShim$([IO.Path]::PathSeparator)$savedPath"
            $bidirectionalResult = Get-R8TrainVersionWithTimeout `
                -RepositoryRoot $bidirectionalRoot -TimeoutMilliseconds 30000
        }
        finally {
            $env:PATH = $savedPath
        }
        Assert-R8PortableGitShimInvoked -ShimDirectory $bidirectionalShim
        $bidirectionalResult.Running | Should -BeFalse `
            -Because 'Git stdin and stdout must drain concurrently when both exceed the pipe buffer'
        $bidirectionalResult.ExitCode | Should -Be 0 -Because $bidirectionalResult.Output
        $bidirectionalResult.Output | Should -Match '^0\.4\.0-r8\.g[0-9a-f]{12}(?:\.d[0-9a-f]{12})?$'
    }

    It 'ignores a malicious ambient legacy helper and remains deterministic across repeated calls in one process' {
        $root = New-R8TrainVersionFixture
        $revision = (& git -C $root rev-parse HEAD).Trim().Substring(0, 12)
        $versionLiteral = $script:versionScript.Replace("'", "''")
        $rootLiteral = $root.Replace("'", "''")
        $source = $script:ambientCaptureSource
        $bootstrap = @"
`$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
$source
'@
`$first = & '$versionLiteral' -RepositoryRoot '$rootLiteral'
`$second = & '$versionLiteral' -RepositoryRoot '$rootLiteral'
[pscustomobject] @{ first = [string] `$first; second = [string] `$second } | ConvertTo-Json -Compress
"@

        $result = Invoke-R8Bootstrap -Content $bootstrap

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $values = $result.Output | ConvertFrom-Json
        $values.first | Should -Be "0.4.0-r8.g$revision"
        $values.second | Should -Be $values.first
    }

    It 'rejects raw source paths that collide by ordinal case before capture' {
        $root = New-R8TrainVersionFixture
        $shimDirectory = New-R8PortableGitShim -Mode case-collision
        $savedPath = $env:PATH
        try {
            $env:PATH = "$shimDirectory$([IO.Path]::PathSeparator)$savedPath"
            $result = Get-R8TrainVersion -RepositoryRoot $root
        }
        finally { $env:PATH = $savedPath }

        Assert-R8PortableGitShimInvoked -ShimDirectory $shimDirectory
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'case|collid|ambiguous'
    }

    It 'rejects raw source paths that collide after Unicode normalization before capture' {
        $root = New-R8TrainVersionFixture
        $shimDirectory = New-R8PortableGitShim -Mode normalization-collision
        $savedPath = $env:PATH
        try {
            $env:PATH = "$shimDirectory$([IO.Path]::PathSeparator)$savedPath"
            $result = Get-R8TrainVersion -RepositoryRoot $root
        }
        finally { $env:PATH = $savedPath }

        Assert-R8PortableGitShimInvoked -ShimDirectory $shimDirectory
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'normalization|collid|ambiguous'
    }

    It 'rejects a case-aliased inventory record for the proof-bound helper inside the repository' {
        $fixture = New-R8InternalHelperFixture
        $shimDirectory = New-R8PortableGitShim -Mode helper-case-alias -Configuration @{
            CanonicalPath = 'scripts/private/GraphKit.SourceCapture.cs'
            AliasPath = 'Scripts/private/GraphKit.SourceCapture.cs'
        }
        $savedPath = $env:PATH
        try {
            $env:PATH = "$shimDirectory$([IO.Path]::PathSeparator)$savedPath"
            $result = Get-R8TrainVersion -RepositoryRoot $fixture.Root -VersionScript $fixture.VersionScript
        }
        finally { $env:PATH = $savedPath }

        Assert-R8PortableGitShimInvoked -ShimDirectory $shimDirectory
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'source-capture helper inside RepositoryRoot requires|Cannot root-anchored no-follow capture source entry|Git source paths collide by case or Unicode normalization'
        $result.Output | Should -Match 'exactly one exact raw inventory record|Source path segment[\s\S]*Scripts|Git source paths collide by case or Unicode normalization'
    }

    It 'binds a physically internal proof helper when RepositoryRoot is a Unix symlink or Windows junction alias' {
        $fixture = New-R8InternalHelperFixture
        $rootAlias = New-R8RepositoryRootAlias -Target $fixture.Root -Alias (Join-Path $TestDrive ('repository-alias-' + [guid]::NewGuid().ToString('N')))
        $shimDirectory = New-R8PortableGitShim -Mode helper-case-alias -Configuration @{
            CanonicalPath = 'scripts/private/GraphKit.SourceCapture.cs'
            AliasPath = 'Scripts/private/GraphKit.SourceCapture.cs'
        }
        $savedPath = $env:PATH
        try {
            $env:PATH = "$shimDirectory$([IO.Path]::PathSeparator)$savedPath"
            $result = Get-R8TrainVersion -RepositoryRoot $rootAlias -VersionScript $fixture.VersionScript
        }
        finally { $env:PATH = $savedPath }

        Assert-R8PortableGitShimInvoked -ShimDirectory $shimDirectory
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'source-capture helper inside RepositoryRoot requires|Cannot root-anchored no-follow capture source entry|Git source paths collide by case or Unicode normalization'
        $result.Output | Should -Match 'exactly one exact raw inventory record|Source path segment[\s\S]*Scripts|Git source paths collide by case or Unicode normalization'
    }

    It 'allows a genuinely external proof helper when RepositoryRoot is a filesystem alias' {
        $root = New-R8TrainVersionFixture
        $rootAlias = New-R8RepositoryRootAlias -Target $root -Alias (Join-Path $TestDrive ('external-helper-alias-' + [guid]::NewGuid().ToString('N')))

        $result = Get-R8TrainVersion -RepositoryRoot $rootAlias -VersionScript $script:versionScript

        $result.ExitCode | Should -Be 0 -Because $result.Output
        $result.Output.Trim() | Should -Match '^0\.4\.0-r8\.g[0-9a-f]{12}$'
    }

    It 'fails on unmerged index stage <Stage> before invoking worktree capture' -ForEach @(
        @{ Stage = 1 }
        @{ Stage = 2 }
        @{ Stage = 3 }
    ) {
        $fixture = New-R8ProofBoundCaptureSentinelFixture
        $sentinel = Join-Path $TestDrive ("capture-stage-$Stage-" + [guid]::NewGuid().ToString('N'))
        $shimDirectory = New-R8PortableGitShim -Mode unmerged-stage -Configuration @{ Stage = $Stage }
        $savedPath = $env:PATH
        $savedSentinel = $env:GRAPHKIT_TEST_CAPTURE_SENTINEL
        try {
            $env:GRAPHKIT_TEST_CAPTURE_SENTINEL = $sentinel
            $control = Get-R8TrainVersion -RepositoryRoot $fixture.Root -VersionScript $fixture.VersionScript
            $control.ExitCode | Should -Be 0 -Because $control.Output
            $sentinel | Should -Exist -Because 'the copied proof-bound generated helper must be demonstrably active in the control run'
            Remove-Item -LiteralPath $sentinel -Force

            $env:PATH = "$shimDirectory$([IO.Path]::PathSeparator)$savedPath"
            $result = Get-R8TrainVersion -RepositoryRoot $fixture.Root -VersionScript $fixture.VersionScript
        }
        finally {
            $env:PATH = $savedPath
            $env:GRAPHKIT_TEST_CAPTURE_SENTINEL = $savedSentinel
        }

        Assert-R8PortableGitShimInvoked -ShimDirectory $shimDirectory
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'unmerged'
        Test-Path -LiteralPath $sentinel | Should -BeFalse
    }

    It 'binds the helper-reported native handle identity into canonical source state' {
        $fixture = New-R8ControlledIdentityFixture
        $savedIdentity = $env:GRAPHKIT_TEST_CAPTURE_IDENTITY
        try {
            $env:GRAPHKIT_TEST_CAPTURE_IDENTITY = 'test-device:00000001:test-file:00000001'
            $first = Get-R8TrainVersion -RepositoryRoot $fixture.Root -VersionScript $fixture.VersionScript
            $env:GRAPHKIT_TEST_CAPTURE_IDENTITY = 'test-device:00000002:test-file:00000001'
            $second = Get-R8TrainVersion -RepositoryRoot $fixture.Root -VersionScript $fixture.VersionScript
        }
        finally { $env:GRAPHKIT_TEST_CAPTURE_IDENTITY = $savedIdentity }

        $first.ExitCode | Should -Be 0 -Because $first.Output
        $second.ExitCode | Should -Be 0 -Because $second.Output
        $second.Output | Should -Not -Be $first.Output
    }

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

        Assert-R8PortableGitShimInvoked -ShimDirectory $shimDirectory
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

        Assert-R8PortableGitShimInvoked -ShimDirectory $shimDirectory
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'invalid object identity|unsupported entry header'
    }

    It 'fails closed with an actionable error for a SHA-256 object-format repository' {
        $root = New-R8TrainVersionFixture
        $shimDirectory = New-R8PortableGitShim -Mode sha256-format
        $savedPath = $env:PATH
        try {
            $env:PATH = "$shimDirectory$([IO.Path]::PathSeparator)$savedPath"
            $result = Get-R8TrainVersion -RepositoryRoot $root
        }
        finally { $env:PATH = $savedPath }

        Assert-R8PortableGitShimInvoked -ShimDirectory $shimDirectory
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'SHA-256.*not supported|unsupported.*SHA-256'
    }

    It 'treats a Windows-style clean tracked 100755 entry as clean without losing index mode proof' {
        $captureType = Initialize-R8SourceCaptureHelper
        $captureType::ResolveEffectiveGitMode('', $false, '100755') | Should -Be '100755'

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
        $shimDirectory = New-R8PortableGitShim -Mode reverse-untracked
        $savedPath = $env:PATH
        try {
            $env:PATH = "$shimDirectory$([IO.Path]::PathSeparator)$savedPath"
            $reverse = Get-R8TrainVersion -RepositoryRoot $root
        }
        finally { $env:PATH = $savedPath }

        Assert-R8PortableGitShimInvoked -ShimDirectory $shimDirectory
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

    It 'fails closed when Git reports an entry that disappears before capture' {
        $root = New-R8TrainVersionFixture
        $shimDirectory = New-R8PortableGitShim -Mode missing
        $savedPath = $env:PATH
        try {
            $env:PATH = "$shimDirectory$([IO.Path]::PathSeparator)$savedPath"
            $result = Get-R8TrainVersion -RepositoryRoot $root
        }
        finally {
            $env:PATH = $savedPath
        }

        Assert-R8PortableGitShimInvoked -ShimDirectory $shimDirectory
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'disappeared|regular file'
    }

    It 'fails closed for a non-strict-UTF-8 raw Git path on every host' {
        $root = New-R8TrainVersionFixture
        $shimDirectory = New-R8PortableGitShim -Mode invalid-path
        $savedPath = $env:PATH
        try {
            $env:PATH = "$shimDirectory$([IO.Path]::PathSeparator)$savedPath"
            $result = Get-R8TrainVersion -RepositoryRoot $root
        }
        finally {
            $env:PATH = $savedPath
        }

        Assert-R8PortableGitShimInvoked -ShimDirectory $shimDirectory
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'UTF-8|path'
    }

    It 'marks a platform-representable executable-mode change dirty even when core.filemode is false' {
        $root = New-R8TrainVersionFixture
        $path = Join-Path $root 'source/Private/Tracked-One.ps1'
        if ($IsWindows) {
            & git -C $root update-index --chmod=+x source/Private/Tracked-One.ps1
        }
        else {
            & /bin/chmod +x $path
        }
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

    It 'accepts a platform-valid untracked path containing special and non-ASCII characters' {
        $root = New-R8TrainVersionFixture
        $relative = if ($IsWindows) { "source/Private/tab`t雪.ps1" } else { "source/Private/tab`tline`n雪.ps1" }
        $path = Join-Path $root $relative
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

        Assert-R8PortableGitShimInvoked -ShimDirectory $shimDirectory
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'duplicate'
    }

    It 'rejects an unsupported untracked filesystem entry promptly before reading it' {
        $root = New-R8TrainVersionFixture
        if ($IsWindows) {
            $outside = Join-Path $TestDrive ('unsupported-target-' + [guid]::NewGuid().ToString('N'))
            $null = New-Item -ItemType Directory -Path $outside -Force
            $junction = Join-Path $root 'source/Private/input.reparse'
            & cmd.exe /d /c "mklink /J `"$junction`" `"$outside`"" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'The Windows test host could not create the required directory junction.' }
        }
        else {
            $fifo = Join-Path $root 'source/Private/input.fifo'
            & /usr/bin/mkfifo $fifo
        }

        $result = Get-R8TrainVersionWithTimeout -RepositoryRoot $root -TimeoutMilliseconds 3000

        $result.Running | Should -BeFalse -Because 'special files must be rejected rather than opened'
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'regular|special|unsupported|reparse|cannot be opened'
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

        Assert-R8PortableGitShimInvoked -ShimDirectory $shimDirectory
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

        Assert-R8PortableGitShimInvoked -ShimDirectory $shimDirectory
        $result.ExitCode | Should -Not -Be 0
        $result.Output | Should -Match 'changed|race|metadata|content'
    }

    It 'matches the fixed R8 source-state known vector' {
        $fixture = New-R8ControlledIdentityFixture
        $savedIdentity = $env:GRAPHKIT_TEST_CAPTURE_IDENTITY
        try {
            $env:GRAPHKIT_TEST_CAPTURE_IDENTITY = 'known-device:00000001:known-file:00000002'
            $state = & $fixture.VersionScript -RepositoryRoot $fixture.Root -AsObject
        }
        finally { $env:GRAPHKIT_TEST_CAPTURE_IDENTITY = $savedIdentity }

        $state.sourceStateSha256 | Should -Be '88365586a59840cef20946c650bc5973567bf9be407728c3568af70d4d4cfcea'
        $state.version | Should -Match '^0\.4\.0-r8\.g[0-9a-f]{12}\.d88365586a598$'
    }
}

Describe 'GraphKit R8 root-anchored source capture' -Tag 'QA' {
    It 'maps Linux statx device fields in ABI order before formatting ordinary-file identity' {
        $captureType = Initialize-R8SourceCaptureHelper
        $script:sourceCaptureType -is [type] | Should -BeTrue `
            -Because 'the cached capture helper must remain one static-callable Type rather than Object[]'
        $statxType = $captureType.Assembly.GetType("$($captureType.Namespace).UnixNative+Statx", $true)
        $helperSource = Get-Content -LiteralPath $script:sourceCaptureHelper -Raw

        [Runtime.InteropServices.Marshal]::OffsetOf($statxType, 'RDeviceMajor').ToInt32() | Should -Be 128
        [Runtime.InteropServices.Marshal]::OffsetOf($statxType, 'RDeviceMinor').ToInt32() | Should -Be 132
        [Runtime.InteropServices.Marshal]::OffsetOf($statxType, 'DeviceMajor').ToInt32() | Should -Be 136
        [Runtime.InteropServices.Marshal]::OffsetOf($statxType, 'DeviceMinor').ToInt32() | Should -Be 140
        $helperSource | Should -Match 'EntryPoint = "fstat\$INODE64"'
        $helperSource | Should -Match 'Architecture\.Arm64 => DarwinFStat\('
        $helperSource | Should -Match 'Architecture\.X64 => DarwinFStatInode64\('
        $helperSource | Should -Match 'catch \(EntryPointNotFoundException exception\)'
        $helperSource | Should -Match 'FileTraverse\s*=\s*0x0020'
        $helperSource | Should -Match 'FileTraverse\s*\|\s*FileReadAttributes\s*\|\s*Synchronize'
        $helperSource | Should -Match 'directory\s*\?\s*FileListDirectory\s*\|\s*FileTraverse'
    }

    It 'rejects Windows reserved-device, ADS, and suspicious short-alias path forms without a platform skip' {
        $captureType = Initialize-R8SourceCaptureHelper
        $validator = $captureType.GetMethod('ValidateWindowsRelativePathForProof')
        $validator | Should -Not -BeNullOrEmpty -Because 'portable tests must execute the same lexical gate used by native Windows capture'

        foreach ($relativePath in @(
            'source/CON.ps1',
            'source/NUL',
            'source/file.ps1:payload',
            'source/LONGFI~1.PS1'
        )) {
            { $validator.Invoke($null, @($relativePath)) } | Should -Throw -Because $relativePath
        }
    }

    It 'rejects a wrong-case segment through a native check or the equivalent raw-inventory gate' {
        if ($IsWindows) {
            $captureType = Initialize-R8SourceCaptureHelper
            $root = Join-Path $TestDrive ('wrong-case-' + [guid]::NewGuid().ToString('N'))
            $null = New-Item -ItemType Directory -Path $root -Force
            Set-Content -LiteralPath (Join-Path $root 'ExactName.ps1') -Value "'exact'`n" -NoNewline -Encoding utf8NoBOM

            { $captureType::Capture($root, 'exactname.ps1') } | Should -Throw
        }
        else {
            $root = New-R8TrainVersionFixture
            $shimDirectory = New-R8PortableGitShim -Mode case-collision
            $savedPath = $env:PATH
            try {
                $env:PATH = "$shimDirectory$([IO.Path]::PathSeparator)$savedPath"
                $result = Get-R8TrainVersion -RepositoryRoot $root
            }
            finally { $env:PATH = $savedPath }

            Assert-R8PortableGitShimInvoked -ShimDirectory $shimDirectory
            $result.ExitCode | Should -Not -Be 0
            $result.Output | Should -Match 'case|collid|ambiguous'
        }
    }

    It 'accepts exactly 16 MiB but rejects the next byte before allocating capture buffers' {
        $captureType = Initialize-R8SourceCaptureHelper
        $root = Join-Path $TestDrive ('capture-ceiling-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $root -Force
        $boundary = Join-Path $root 'boundary.bin'
        $over = Join-Path $root 'over.bin'
        $boundaryStream = [IO.File]::Open($boundary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $boundaryStream.SetLength(16MB) } finally { $boundaryStream.Dispose() }
        $overStream = [IO.File]::Open($over, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $overStream.SetLength(16MB + 1) } finally { $overStream.Dispose() }

        $captured = $captureType::Capture($root, 'boundary.bin')
        $captured.Length | Should -Be 16MB
        $captured.Content.Length | Should -Be 16MB
        { $captureType::Capture($root, 'over.bin') } |
            Should -Throw -ExpectedMessage '*16 MiB*package-source*limit*'
    }

    It 'rejects an intermediate link or reparse point on every supported platform' {
        $captureType = Initialize-R8SourceCaptureHelper
        $root = Join-Path $TestDrive ('intermediate-link-' + [guid]::NewGuid().ToString('N'))
        $outside = Join-Path $TestDrive ('outside-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path (Join-Path $root 'source') -Force
        $null = New-Item -ItemType Directory -Path $outside -Force
        Set-Content -LiteralPath (Join-Path $outside 'Tracked.ps1') -Value "'same bytes'`n" -NoNewline -Encoding utf8NoBOM
        $link = Join-Path $root 'source/Private'
        if ($IsWindows) {
            & cmd.exe /d /c "mklink /J `"$link`" `"$outside`"" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'The Windows test host could not create the required directory junction.' }
        }
        else {
            New-Item -ItemType SymbolicLink -Path $link -Target $outside | Out-Null
        }

        { $captureType::Capture($root, 'source/Private/Tracked.ps1') } |
            Should -Throw -ExpectedMessage $(if ($IsWindows) { '*reparse point*' } else { '*symbolic link*' })
    }

    It 'closes final handles when an unsupported final entry is rejected' {
        $captureType = Initialize-R8SourceCaptureHelper
        $root = Join-Path $TestDrive ('handle-ownership-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $root -Force
        if ($IsWindows) {
            $null = New-Item -ItemType Directory -Path (Join-Path $root 'unsupported.entry')
            { $captureType::Capture($root, 'unsupported.entry') } | Should -Throw
            $before = [Diagnostics.Process]::GetCurrentProcess().HandleCount
        }
        else {
            $fifo = Join-Path $root 'unsupported.fifo'
            & /usr/bin/mkfifo $fifo
            { $captureType::Capture($root, 'unsupported.fifo') } | Should -Throw
            $before = @([IO.Directory]::EnumerateFileSystemEntries('/dev/fd')).Count
        }

        1..64 | ForEach-Object {
            { $captureType::Capture($root, $(if ($IsWindows) { 'unsupported.entry' } else { 'unsupported.fifo' })) } | Should -Throw
        }

        $after = if ($IsWindows) {
            [Diagnostics.Process]::GetCurrentProcess().HandleCount
        }
        else {
            @([IO.Directory]::EnumerateFileSystemEntries('/dev/fd')).Count
        }
        ($after - $before) | Should -BeLessOrEqual 2 -Because 'every native handle must immediately gain a safe owner'
    }

    It 'rejects a Windows reparse point in an intermediate path segment without retaining handles' {
        $captureType = Initialize-R8SourceCaptureHelper
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
                { $captureType::Capture($root, 'source/Private/Tracked.ps1') } |
                    Should -Throw -ExpectedMessage '*reparse point*'
            }
            $after = [Diagnostics.Process]::GetCurrentProcess().HandleCount
        } else {
            New-Item -ItemType SymbolicLink -Path $link -Target $outside | Out-Null
            { $captureType::Capture($root, 'source/Private/Tracked.ps1') } | Should -Throw
            $before = @([IO.Directory]::EnumerateFileSystemEntries('/dev/fd')).Count
            1..16 | ForEach-Object {
                { $captureType::Capture($root, 'source/Private/Tracked.ps1') } | Should -Throw
            }
            $after = @([IO.Directory]::EnumerateFileSystemEntries('/dev/fd')).Count
        }
        ($after - $before) | Should -BeLessOrEqual 2
    }
}
