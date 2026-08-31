[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $RepositoryRoot,

    [switch] $AsObject
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

function Invoke-GraphKitGitBytes {
    param(
        [Parameter(Mandatory)] [string] $Root,
        [Parameter(Mandatory)] [string[]] $Arguments
    )

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = 'git'
    $start.WorkingDirectory = $Root
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
    if ($process.ExitCode -ne 0) {
        throw "git $($Arguments -join ' ') failed: $error"
    }
    return ,$stream.ToArray()
}

function Get-GraphKitR8SourceState {
    param([Parameter(Mandatory)] [string] $Root)

    # The dirty hash is SHA-256 over this exact, length-framed byte stream:
    #   ASCII 'GraphKit-R8-source-state-v1' NUL
    #   ASCII 'patch' UInt64LE(length) normalized git-diff bytes
    #   zero or more ASCII 'untracked' UInt64LE(path length) raw-path bytes
    #       UInt64LE(content length) file-content bytes, ordered by raw path bytes
    #   ASCII 'end' NUL
    # The patch disables external/text conversions and fixes path prefixes and diff algorithm.
    # `git ls-files --others --exclude-standard -z` includes every non-ignored untracked file.
    $patch = Invoke-GraphKitGitBytes -Root $Root -Arguments @(
        '-c', 'core.autocrlf=false', '-c', 'core.eol=lf', '-c', 'core.safecrlf=false',
        '-c', 'core.quotePath=true', '-c', 'diff.noprefix=false', '-c', 'i18n.logOutputEncoding=UTF-8',
        'diff', '--no-ext-diff', '--no-textconv', '--no-renames', '--diff-algorithm=myers',
        '--binary', '--src-prefix=a/', '--dst-prefix=b/', 'HEAD'
    )
    $untrackedPathStream = Invoke-GraphKitGitBytes -Root $Root -Arguments @(
        'ls-files', '--others', '--exclude-standard', '-z'
    )

    $untrackedPaths = [Collections.Generic.List[byte[]]]::new()
    $offset = 0
    while ($offset -lt $untrackedPathStream.Length) {
        $end = [Array]::IndexOf($untrackedPathStream, [byte] 0, $offset)
        if ($end -lt 0) { throw 'Git returned an unterminated untracked-path stream.' }
        $length = $end - $offset
        $path = [byte[]]::new($length)
        [Array]::Copy($untrackedPathStream, $offset, $path, 0, $length)
        $untrackedPaths.Add($path)
        $offset = $end + 1
    }
    $orderedPaths = @($untrackedPaths | Sort-Object { [Convert]::ToHexString($_) })

    $stateBytes = [IO.MemoryStream]::new()
    $writeBytes = {
        param([Parameter(Mandatory)] [AllowEmptyCollection()] [byte[]] $Bytes)
        $stateBytes.Write($Bytes, 0, $Bytes.Length)
    }
    $writeLength = {
        param([Parameter(Mandatory)] [int] $Length)
        & $writeBytes ([BitConverter]::GetBytes([uint64] $Length))
    }

    & $writeBytes ([Text.Encoding]::ASCII.GetBytes('GraphKit-R8-source-state-v1'))
    & $writeBytes ([byte[]] @(0))
    & $writeBytes ([Text.Encoding]::ASCII.GetBytes('patch'))
    & $writeLength $patch.Length
    & $writeBytes $patch
    foreach ($path in $orderedPaths) {
        $relativePath = [Text.Encoding]::UTF8.GetString($path)
        $contentPath = Join-Path $Root $relativePath
        if (-not (Test-Path -LiteralPath $contentPath -PathType Leaf)) {
            throw "Non-ignored untracked path '$relativePath' is not a file."
        }
        $content = [IO.File]::ReadAllBytes($contentPath)
        & $writeBytes ([Text.Encoding]::ASCII.GetBytes('untracked'))
        & $writeLength $path.Length
        & $writeBytes $path
        & $writeLength $content.Length
        & $writeBytes $content
    }
    & $writeBytes ([Text.Encoding]::ASCII.GetBytes('end'))
    & $writeBytes ([byte[]] @(0))

    [pscustomobject] [ordered] @{
        clean = $patch.Length -eq 0 -and $orderedPaths.Count -eq 0
        sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stateBytes.ToArray())).ToLowerInvariant()
    }
}

$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).ProviderPath
$base = '0.4.0'
$train = 'r8'
$revisionBytes = Invoke-GraphKitGitBytes -Root $RepositoryRoot -Arguments @('rev-parse', 'HEAD')
$revision = [Text.Encoding]::UTF8.GetString($revisionBytes).Trim().ToLowerInvariant()
if ($revision -notmatch '^[0-9a-f]{40}$') {
    throw "Cannot resolve a 40-character source revision for '$RepositoryRoot'."
}
$sourceState = Get-GraphKitR8SourceState -Root $RepositoryRoot
$suffix = if ($sourceState.clean) { '' } else { ".d$($sourceState.sha256.Substring(0, 12))" }
$version = "$base-$train.g$($revision.Substring(0, 12))$suffix"

if ($AsObject) {
    [pscustomobject] [ordered] @{
        version = $version
        baseVersion = $base
        train = $train
        revision = $revision
        clean = [bool] $sourceState.clean
        sourceStateSha256 = $sourceState.sha256
    }
}
else {
    $version
}
