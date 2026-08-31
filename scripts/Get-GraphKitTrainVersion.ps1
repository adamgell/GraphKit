[CmdletBinding()]
param([Parameter(Mandatory)][string] $RepositoryRoot, [switch] $AsObject)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

function Invoke-GraphKitGitBytes {
    param([string] $Root, [string[]] $Arguments, [byte[]] $InputBytes = [byte[]] @(), [int[]] $AllowedExitCodes = @(0))
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = 'git'; $start.WorkingDirectory = $Root; $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true; $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $null = $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new(); $process.StartInfo = $start; $null = $process.Start()
    if ($InputBytes.Length) { $process.StandardInput.BaseStream.Write($InputBytes, 0, $InputBytes.Length) }
    $process.StandardInput.Close(); $output = [IO.MemoryStream]::new(); $process.StandardOutput.BaseStream.CopyTo($output)
    $error = $process.StandardError.ReadToEnd(); $process.WaitForExit()
    if ($process.ExitCode -notin $AllowedExitCodes) { throw "git $($Arguments -join ' ') failed: $error" }
    return ,$output.ToArray()
}

function Test-GraphKitBytesEqual { param([byte[]] $Left, [byte[]] $Right)
    if ($Left.Length -ne $Right.Length) { return $false }
    for ($i = 0; $i -lt $Left.Length; $i++) { if ($Left[$i] -ne $Right[$i]) { return $false } }
    return $true
}

function Get-GraphKitNulRecords { param([byte[]] $Bytes, [string] $Source)
    $records = [Collections.Generic.List[byte[]]]::new(); $offset = 0
    while ($offset -lt $Bytes.Length) {
        $end = [Array]::IndexOf($Bytes, [byte] 0, $offset)
        if ($end -lt 0) { throw "$Source returned an unterminated NUL record." }
        if ($end -eq $offset) { throw "$Source returned an empty record." }
        $record = [byte[]]::new($end - $offset); [Array]::Copy($Bytes, $offset, $record, 0, $record.Length)
        $records.Add($record); $offset = $end + 1
    }
    return [pscustomobject] @{ records = @($records) }
}

function Get-GraphKitRecordParts { param([byte[]] $Record, [string] $Source)
    $tab = [Array]::IndexOf($Record, [byte] 9)
    if ($tab -lt 1 -or $tab -eq $Record.Length - 1) { throw "$Source returned a malformed record." }
    $path = [byte[]]::new($Record.Length - $tab - 1); [Array]::Copy($Record, $tab + 1, $path, 0, $path.Length)
    [pscustomobject] @{ header = [Text.Encoding]::ASCII.GetString($Record, 0, $tab); path = $path }
}

function Add-GraphKitMapEntry { param($Map, [byte[]] $Path, $Entry, [string] $Source)
    $key = [Convert]::ToHexString($Path)
    if (-not $Map.TryAdd($key, $Entry)) { throw "$Source reported duplicate source path bytes." }
}

function ConvertFrom-GraphKitTree { param([byte[]] $Bytes)
    $map = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($record in (Get-GraphKitNulRecords $Bytes 'git ls-tree').records) {
        $part = Get-GraphKitRecordParts $record 'git ls-tree'
        if ($part.header -notmatch '^(?<mode>[0-7]{6}) (?<type>blob|commit) (?<object>[0-9a-f]{40,64})$') { throw 'git ls-tree returned an unsupported entry header.' }
        if ($Matches.type -eq 'commit') { throw 'Git HEAD contains an unsupported gitlink/submodule entry.' }
        if ($Matches.mode -notin @('100644', '100755')) { throw "Git HEAD contains unsupported mode '$($Matches.mode)'." }
        Add-GraphKitMapEntry $map $part.path ([pscustomobject] @{ path=$part.path; mode=$Matches.mode; type=$Matches.type; object=$Matches.object }) 'git ls-tree'
    }
    return $map
}

function ConvertFrom-GraphKitIndex { param([byte[]] $Bytes)
    $map = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($record in (Get-GraphKitNulRecords $Bytes 'git ls-files --stage').records) {
        $part = Get-GraphKitRecordParts $record 'git ls-files --stage'
        if ($part.header -notmatch '^(?<mode>[0-7]{6}) (?<object>[0-9a-f]{40,64}) (?<stage>[0-3])$') { throw 'git ls-files --stage returned an unsupported entry header.' }
        if ($Matches.stage -ne '0') { throw 'Git index contains an unmerged source entry.' }
        if ($Matches.mode -eq '160000') { throw 'Git index contains an unsupported gitlink/submodule entry.' }
        if ($Matches.mode -notin @('100644', '100755')) { throw "Git index contains unsupported mode '$($Matches.mode)'." }
        Add-GraphKitMapEntry $map $part.path ([pscustomobject] @{ path=$part.path; mode=$Matches.mode; type='blob'; object=$Matches.object }) 'git ls-files --stage'
    }
    return $map
}

function Get-GraphKitRelativePath { param([byte[]] $RawPath, [Text.UTF8Encoding] $Utf8)
    try { $path = $Utf8.GetString($RawPath) } catch { throw 'Git reported a non-strict-UTF-8 source path.' }
    if ([string]::IsNullOrEmpty($path) -or [IO.Path]::IsPathRooted($path) -or @($path -split '[\\/]' | Where-Object { $_ -in @('', '.', '..') }).Count) { throw 'Git reported an unsafe source path.' }
    return $path
}

function Initialize-GraphKitNoFollowSupport {
    if (-not $IsWindows -and -not ('GraphKit.R8.NoFollow' -as [type])) { Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace GraphKit.R8 {
 public sealed class Metadata { public int Mode; public string Identity; }
 public static class NoFollow {
  [DllImport("libc", SetLastError=true)] static extern int lstat(string path, IntPtr buffer);
  [DllImport("libc", SetLastError=true)] static extern int fstat(int fd, IntPtr buffer);
  [DllImport("libc", SetLastError=true)] static extern int open(string path, int flags);
  static bool Mac { get { return RuntimeInformation.IsOSPlatform(OSPlatform.OSX); } }
  static Metadata Decode(byte[] b) {
   if (Mac) return new Metadata { Mode=BitConverter.ToUInt16(b,4), Identity=BitConverter.ToUInt32(b,0).ToString("x8")+":"+BitConverter.ToUInt64(b,8).ToString("x16") };
   if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) return new Metadata { Mode=BitConverter.ToInt32(b,24), Identity=BitConverter.ToUInt64(b,0).ToString("x16")+":"+BitConverter.ToUInt64(b,8).ToString("x16") };
   throw new PlatformNotSupportedException("No-follow source capture is unavailable on this platform.");
  }
  static Metadata Stat(Func<IntPtr,int> f) { var b=new byte[512]; var h=GCHandle.Alloc(b,GCHandleType.Pinned); try { if(f(h.AddrOfPinnedObject())!=0) throw new Win32Exception(Marshal.GetLastWin32Error()); return Decode(b); } finally { h.Free(); } }
  public static Metadata LStat(string path) { return Stat(p => lstat(path,p)); }
  public static SafeFileHandle Open(string path, out Metadata metadata) { int flags=Mac ? 0x104 : 0x20800; int fd=open(path,flags); if(fd<0) throw new Win32Exception(Marshal.GetLastWin32Error()); try { metadata=Stat(p => fstat(fd,p)); return new SafeFileHandle((IntPtr)fd,true); } catch { throw; } }
 }
}
'@ }
}

function Get-GraphKitFileType { param([int] $Mode) return ($Mode -band 0xF000) }
function Get-GraphKitMode { param([int] $Mode) return [Convert]::ToString($Mode, 8).PadLeft(6, '0') }

function Get-GraphKitWorktreeEntry { param([string] $Root, [byte[]] $RawPath, [Text.UTF8Encoding] $Utf8)
    $relative = Get-GraphKitRelativePath $RawPath $Utf8; $fullPath = Join-Path $Root $relative
    if ($IsWindows) {
        if (-not [IO.File]::Exists($fullPath)) { return [pscustomobject] @{ type='missing'; mode=''; identity=''; content=[byte[]] @() } }
        $before = Get-Item -LiteralPath $fullPath -Force
        if (($before.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $before -isnot [IO.FileInfo]) { throw "Source entry '$relative' is an unsupported symbolic link or special file." }
        $content = [IO.File]::ReadAllBytes($fullPath); $after = Get-Item -LiteralPath $fullPath -Force
        if (($after.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $after -isnot [IO.FileInfo] -or $before.Length -ne $after.Length -or $before.LastWriteTimeUtc -ne $after.LastWriteTimeUtc -or $content.Length -ne $after.Length) { throw "Source entry '$relative' changed during capture." }
        return [pscustomobject] @{ type='regular'; mode='100644'; identity=$before.FullName; content=$content }
    }
    try { $before = [GraphKit.R8.NoFollow]::LStat($fullPath) } catch [ComponentModel.Win32Exception] { return [pscustomobject] @{ type='missing'; mode=''; identity=''; content=[byte[]] @() } }
    $beforeType = Get-GraphKitFileType $before.Mode
    if ($beforeType -eq 0xA000) { throw "Source entry '$relative' is an unsupported symbolic link." }
    if ($beforeType -ne 0x8000) { throw "Source entry '$relative' is an unsupported special/non-regular file." }
    $opened = $null
    try { $handle = [GraphKit.R8.NoFollow]::Open($fullPath, [ref] $opened) } catch { throw "Cannot no-follow open source entry '$relative': $($_.Exception.Message)" }
    try {
        if ((Get-GraphKitFileType $opened.Mode) -ne 0x8000 -or $opened.Mode -ne $before.Mode -or $opened.Identity -ne $before.Identity) { throw "Source entry '$relative' changed during no-follow open." }
        $file = [IO.FileStream]::new($handle, [IO.FileAccess]::Read); try { $buffer = [IO.MemoryStream]::new(); $file.CopyTo($buffer); $content = $buffer.ToArray() } finally { $file.Dispose() }
    }
    finally { if ($handle) { $handle.Dispose() } }
    try { $after = [GraphKit.R8.NoFollow]::LStat($fullPath) } catch { throw "Source entry '$relative' disappeared during capture." }
    if ((Get-GraphKitFileType $after.Mode) -ne 0x8000 -or $after.Mode -ne $before.Mode -or $after.Identity -ne $before.Identity) { throw "Source entry '$relative' changed during no-follow metadata capture." }
    return [pscustomobject] @{ type='regular'; mode=(Get-GraphKitMode $before.Mode); identity=$before.Identity; content=$content }
}

function Get-GraphKitBlobId { param([string] $Format, [byte[]] $Content)
    $header = [Text.Encoding]::ASCII.GetBytes("blob $($Content.Length)`0"); $bytes = [byte[]]::new($header.Length + $Content.Length)
    [Array]::Copy($header, 0, $bytes, 0, $header.Length); [Array]::Copy($Content, 0, $bytes, $header.Length, $Content.Length)
    $hash = if ($Format -eq 'sha1') { [Security.Cryptography.SHA1]::HashData($bytes) } elseif ($Format -eq 'sha256') { [Security.Cryptography.SHA256]::HashData($bytes) } else { throw "Unsupported Git object format '$Format'." }
    return [Convert]::ToHexString($hash).ToLowerInvariant()
}

function Get-GraphKitFilesystemExtras { param([string] $Root, $Known, [Text.UTF8Encoding] $Utf8)
    if ($IsWindows) { return [byte[]] @() }
    $found = [Collections.Generic.List[byte[]]]::new(); $directories = [Collections.Generic.Stack[string]]::new(); $directories.Push($Root)
    while ($directories.Count) { foreach ($fullPath in [IO.Directory]::EnumerateFileSystemEntries($directories.Pop())) {
        $relative = $fullPath.Substring($Root.Length).TrimStart([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
        if ($relative -eq '.git' -or $relative.StartsWith(".git$([IO.Path]::DirectorySeparatorChar)", [StringComparison]::Ordinal)) { continue }
        $raw = $Utf8.GetBytes(($relative -replace '\\', '/')); $meta = [GraphKit.R8.NoFollow]::LStat($fullPath)
        if ((Get-GraphKitFileType $meta.Mode) -eq 0x4000) { $directories.Push($fullPath) } elseif (-not $Known.Contains([Convert]::ToHexString($raw))) { $found.Add($raw) }
    } }
    $stream = [IO.MemoryStream]::new(); foreach ($raw in @($found | Sort-Object { [Convert]::ToHexString($_) })) { $stream.Write($raw,0,$raw.Length); $stream.WriteByte(0) }; return ,$stream.ToArray()
}

function Get-GraphKitInventory { param([string] $Root, [Text.UTF8Encoding] $Utf8)
    $headBytes = Invoke-GraphKitGitBytes $Root @('ls-tree','-r','-z','HEAD')
    $indexBytes = Invoke-GraphKitGitBytes $Root @('ls-files','--stage','-z')
    $untrackedBytes = Invoke-GraphKitGitBytes $Root @('ls-files','--others','--exclude-standard','-z')
    $head = ConvertFrom-GraphKitTree $headBytes; $index = ConvertFrom-GraphKitIndex $indexBytes
    $known = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal); foreach ($key in $head.Keys) { $null=$known.Add($key) }; foreach ($key in $index.Keys) { $null=$known.Add($key) }; foreach ($path in (Get-GraphKitNulRecords $untrackedBytes 'git ls-files --others').records) { $null=$known.Add([Convert]::ToHexString($path)) }
    $extras = (Get-GraphKitNulRecords (Get-GraphKitFilesystemExtras $Root $known $Utf8) 'filesystem inventory').records
    if ($extras.Count) {
        $input=[IO.MemoryStream]::new(); foreach($path in $extras){$input.Write($path,0,$path.Length);$input.WriteByte(0)}
        $ignored = (Get-GraphKitNulRecords (Invoke-GraphKitGitBytes $Root @('check-ignore','-z','--stdin') $input.ToArray() @(0,1)) 'git check-ignore').records
        $ignoredKeys=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal); foreach($path in $ignored){$null=$ignoredKeys.Add([Convert]::ToHexString($path))}
        $joined=[IO.MemoryStream]::new();$joined.Write($untrackedBytes,0,$untrackedBytes.Length);foreach($path in $extras){if(-not $ignoredKeys.Contains([Convert]::ToHexString($path))){$joined.Write($path,0,$path.Length);$joined.WriteByte(0)}};$untrackedBytes=$joined.ToArray()
    }
    [pscustomobject] @{ headBytes=$headBytes; indexBytes=$indexBytes; untrackedBytes=$untrackedBytes; head=$head; index=$index }
}

function Get-GraphKitR8SourceState { param([string] $Root)
    # v3: domain-separated, length-framed HEAD/index/worktree inventory.  Git plumbing supplies
    # raw paths; each entry binds HEAD/index mode/type/object and no-follow worktree mode/type/bytes.
    # Snapshots before/after reads and a second no-follow content read make source races fatal.
    $utf8=[Text.UTF8Encoding]::new($false,$true); Initialize-GraphKitNoFollowSupport
    $format=[Text.Encoding]::ASCII.GetString((Invoke-GraphKitGitBytes $Root @('rev-parse','--show-object-format'))).Trim().ToLowerInvariant(); if($format -notin @('sha1','sha256')){throw "Unsupported Git object format '$format'."}
    $before=Get-GraphKitInventory $Root $utf8; $untracked=Get-GraphKitNulRecords $before.untrackedBytes 'git untracked inventory'; $records=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach($entry in $before.head.Values){$records.Add([Convert]::ToHexString($entry.path),[pscustomobject]@{path=$entry.path;head=$entry;index=$null})};foreach($entry in $before.index.Values){$key=[Convert]::ToHexString($entry.path);if($records.ContainsKey($key)){$records[$key].index=$entry}else{$records.Add($key,[pscustomobject]@{path=$entry.path;head=$null;index=$entry})}};foreach($path in $untracked.records){$key=[Convert]::ToHexString($path);if($records.ContainsKey($key)){throw 'Git reported a duplicate path across tracked and untracked inventories.'};$records.Add($key,[pscustomobject]@{path=$path;head=$null;index=$null})}
    $captured=[Collections.Generic.List[object]]::new();foreach($record in @($records.Values|Sort-Object{[Convert]::ToHexString($_.path)})){$worktree=Get-GraphKitWorktreeEntry $Root $record.path $utf8;if($worktree.type -eq 'missing' -and -not $record.head -and -not $record.index){throw 'A non-ignored untracked source entry disappeared during capture.'};$blob=if($record.index -and $worktree.type -eq 'regular' -and $worktree.mode -eq $record.index.mode){Get-GraphKitBlobId $format $worktree.content}else{''};$captured.Add([pscustomobject]@{path=$record.path;head=$record.head;index=$record.index;worktree=$worktree;blob=$blob})}
    $after=Get-GraphKitInventory $Root $utf8;if(-not(Test-GraphKitBytesEqual $before.headBytes $after.headBytes) -or -not(Test-GraphKitBytesEqual $before.indexBytes $after.indexBytes) -or -not(Test-GraphKitBytesEqual $before.untrackedBytes $after.untrackedBytes)){throw 'Git source inventory changed during capture; refusing to emit a train version.'}
    foreach($entry in $captured){$again=Get-GraphKitWorktreeEntry $Root $entry.path $utf8;if($again.type -ne $entry.worktree.type -or $again.mode -ne $entry.worktree.mode -or $again.identity -ne $entry.worktree.identity -or -not(Test-GraphKitBytesEqual $again.content $entry.worktree.content)){throw 'Source entry changed during capture; refusing to emit a train version.'}}
    $clean=$untracked.records.Count -eq 0 -and $before.head.Count -eq $before.index.Count;foreach($entry in $captured){if(-not $entry.head -or -not $entry.index -or $entry.head.mode -ne $entry.index.mode -or $entry.head.type -ne $entry.index.type -or $entry.head.object -ne $entry.index.object -or $entry.worktree.type -ne 'regular' -or $entry.worktree.mode -ne $entry.index.mode -or $entry.blob -ne $entry.index.object){$clean=$false}}
    $stream=[IO.MemoryStream]::new();$write={param([byte[]]$b)$stream.Write($b,0,$b.Length)};$field={param([string]$n,[byte[]]$b)&$write([Text.Encoding]::ASCII.GetBytes($n));&$write([BitConverter]::GetBytes([uint64]$b.Length));&$write $b};&$write([Text.Encoding]::ASCII.GetBytes('GraphKit-R8-source-entry-state-v3'));&$write([byte[]]@(0));foreach($entry in $captured){&$write([Text.Encoding]::ASCII.GetBytes('entry'));&$field 'path' $entry.path;foreach($side in @('head','index')){$value=$entry.$side;if($null -eq $value){$mode='';$type='';$object=''}else{$mode=[string]$value.mode;$type=[string]$value.type;$object=[string]$value.object};&$field "$side-mode" ([Text.Encoding]::ASCII.GetBytes($mode));&$field "$side-type" ([Text.Encoding]::ASCII.GetBytes($type));&$field "$side-object" ([Text.Encoding]::ASCII.GetBytes($object))};&$field 'worktree-type' ([Text.Encoding]::ASCII.GetBytes([string]$entry.worktree.type));&$field 'worktree-mode' ([Text.Encoding]::ASCII.GetBytes([string]$entry.worktree.mode));&$field 'worktree-content' $entry.worktree.content};&$write([Text.Encoding]::ASCII.GetBytes('end'));&$write([byte[]]@(0))
    [pscustomobject]@{clean=[bool]$clean;sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream.ToArray())).ToLowerInvariant()}
}

$RepositoryRoot=(Resolve-Path -LiteralPath $RepositoryRoot).ProviderPath;$base='0.4.0';$train='r8';$revision=[Text.Encoding]::UTF8.GetString((Invoke-GraphKitGitBytes $RepositoryRoot @('rev-parse','HEAD'))).Trim().ToLowerInvariant();if($revision -notmatch '^[0-9a-f]{40}$'){throw "Cannot resolve a 40-character source revision for '$RepositoryRoot'."};$state=Get-GraphKitR8SourceState $RepositoryRoot;$version="$base-$train.g$($revision.Substring(0,12))$(if($state.clean){''}else{".d$($state.sha256.Substring(0,12))"})";if($AsObject){[pscustomobject][ordered]@{version=$version;baseVersion=$base;train=$train;revision=$revision;clean=[bool]$state.clean;sourceStateSha256=$state.sha256}}else{$version}
