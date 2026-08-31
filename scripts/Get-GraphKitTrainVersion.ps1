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
    if ($process.ExitCode -ne 0) { throw "git $($Arguments -join ' ') failed: $error" }
    return ,$stream.ToArray()
}

function Get-GraphKitNulPaths {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [byte[]] $Bytes,
        [Parameter(Mandatory)] [string] $Source
    )

    $paths = [Collections.Generic.List[byte[]]]::new()
    $offset = 0
    while ($offset -lt $Bytes.Length) {
        $end = [Array]::IndexOf($Bytes, [byte] 0, $offset)
        if ($end -lt 0) { throw "$Source returned an unterminated path stream." }
        $length = $end - $offset
        $path = [byte[]]::new($length)
        [Array]::Copy($Bytes, $offset, $path, 0, $length)
        if ($path.Length -eq 0) { throw "$Source returned an empty path." }
        $paths.Add($path)
        $offset = $end + 1
    }
    return [pscustomobject] @{ paths = @($paths) }
}

function Get-GraphKitR8SourceState {
    param([Parameter(Mandatory)] [string] $Root)

    # SHA-256 is taken over GraphKit-R8-source-entry-state-v2, a domain-separated,
    # length-framed byte stream. Each entry is ordered by raw Git path bytes and contains
    # its type tag, exact raw path bytes, and exact file bytes. Changed tracked entries are
    # reported by `git diff --name-only -z --no-renames HEAD`; non-ignored untracked entries
    # come from `git ls-files --others --exclude-standard -z`. The HEAD revision separately
    # binds unchanged tracked content. No presentation-form `git diff` bytes participate.
    # Symlinks, non-regular entries, invalid UTF-8 paths, and entries that disappear before
    # capture fail closed rather than producing an ambiguous source identity.
    $trackedPaths = (Get-GraphKitNulPaths -Bytes (Invoke-GraphKitGitBytes -Root $Root -Arguments @(
        'diff', '--name-only', '-z', '--no-renames', 'HEAD'
    )) -Source 'git diff --name-only').paths
    $untrackedPaths = (Get-GraphKitNulPaths -Bytes (Invoke-GraphKitGitBytes -Root $Root -Arguments @(
        'ls-files', '--others', '--exclude-standard', '-z'
    )) -Source 'git ls-files --others').paths

    $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
    $entries = [Collections.Generic.List[object]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    function Add-GraphKitSourceEntry {
        param(
            [Parameter(Mandatory)] [byte[]] $RawPath,
            [Parameter(Mandatory)] [string] $Origin
        )

        $pathKey = [Convert]::ToHexString($RawPath)
        if (-not $seen.Add($pathKey)) { throw "Git reported duplicate source path bytes for '$Origin'." }
        try {
            $relativePath = $strictUtf8.GetString($RawPath)
        }
        catch {
            throw "Git reported a non-strict-UTF-8 source path for '$Origin'."
        }
        if ([string]::IsNullOrEmpty($relativePath) -or
            [IO.Path]::IsPathRooted($relativePath) -or
            @($relativePath -split '[\\/]' | Where-Object { $_ -in @('', '.', '..') }).Count -gt 0) {
            throw "Git reported an unsafe source path for '$Origin'."
        }
        $fullPath = Join-Path $Root $relativePath
        if ($Origin -eq 'tracked' -and -not (Test-Path -LiteralPath $fullPath)) {
            $entries.Add([pscustomobject] @{ path = $RawPath; type = 'tracked-deleted'; content = [byte[]] @() })
            return
        }
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            throw "Source entry '$relativePath' disappeared or is not a regular file."
        }
        try {
            $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Source entry '$relativePath' is an unsupported symbolic link."
            }
            if ($item -isnot [IO.FileInfo]) {
                throw "Source entry '$relativePath' is an unsupported non-regular file."
            }
            $content = [IO.File]::ReadAllBytes($fullPath)
        }
        catch {
            throw "Cannot bind source entry '$relativePath': $($_.Exception.Message)"
        }
        $entries.Add([pscustomobject] @{ path = $RawPath; type = "$Origin-regular"; content = $content })
    }

    foreach ($path in $trackedPaths) { Add-GraphKitSourceEntry -RawPath $path -Origin 'tracked' }
    foreach ($path in $untrackedPaths) { Add-GraphKitSourceEntry -RawPath $path -Origin 'untracked' }
    $orderedEntries = @($entries | Sort-Object { [Convert]::ToHexString($_.path) })

    $stream = [IO.MemoryStream]::new()
    $write = {
        param([Parameter(Mandatory)] [AllowEmptyCollection()] [byte[]] $Bytes)
        $stream.Write($Bytes, 0, $Bytes.Length)
    }
    $writeLength = {
        param([Parameter(Mandatory)] [int] $Length)
        & $write ([BitConverter]::GetBytes([uint64] $Length))
    }
    & $write ([Text.Encoding]::ASCII.GetBytes('GraphKit-R8-source-entry-state-v2'))
    & $write ([byte[]] @(0))
    foreach ($entry in $orderedEntries) {
        $typeBytes = [Text.Encoding]::ASCII.GetBytes([string] $entry.type)
        & $write ([Text.Encoding]::ASCII.GetBytes('entry'))
        & $writeLength $typeBytes.Length
        & $write $typeBytes
        & $writeLength $entry.path.Length
        & $write $entry.path
        & $writeLength $entry.content.Length
        & $write $entry.content
    }
    & $write ([Text.Encoding]::ASCII.GetBytes('end'))
    & $write ([byte[]] @(0))

    [pscustomobject] [ordered] @{
        clean = $orderedEntries.Count -eq 0
        sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream.ToArray())).ToLowerInvariant()
    }
}

$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).ProviderPath
$base = '0.4.0'
$train = 'r8'
$revision = [Text.Encoding]::UTF8.GetString((Invoke-GraphKitGitBytes -Root $RepositoryRoot -Arguments @('rev-parse', 'HEAD'))).Trim().ToLowerInvariant()
if ($revision -notmatch '^[0-9a-f]{40}$') { throw "Cannot resolve a 40-character source revision for '$RepositoryRoot'." }
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
else { $version }
