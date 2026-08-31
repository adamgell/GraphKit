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

function ConvertFrom-GraphKitTree { param([byte[]] $Bytes, [int] $ObjectIdLength)
    $map = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($record in (Get-GraphKitNulRecords $Bytes 'git ls-tree').records) {
        $part = Get-GraphKitRecordParts $record 'git ls-tree'
        if ($part.header -cnotmatch "^(?<mode>[0-7]{6}) (?<type>blob|commit) (?<object>[0-9a-f]{$ObjectIdLength})$") { throw 'git ls-tree returned an unsupported entry header or invalid object identity.' }
        if ($Matches.type -eq 'commit') { throw 'Git HEAD contains an unsupported gitlink/submodule entry.' }
        if ($Matches.mode -notin @('100644', '100755')) { throw "Git HEAD contains unsupported mode '$($Matches.mode)'." }
        Add-GraphKitMapEntry $map $part.path ([pscustomobject] @{ path=$part.path; mode=$Matches.mode; type=$Matches.type; object=$Matches.object }) 'git ls-tree'
    }
    return $map
}

function ConvertFrom-GraphKitIndex { param([byte[]] $Bytes, [int] $ObjectIdLength)
    $map = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($record in (Get-GraphKitNulRecords $Bytes 'git ls-files --stage').records) {
        $part = Get-GraphKitRecordParts $record 'git ls-files --stage'
        if ($part.header -cnotmatch "^(?<mode>[0-7]{6}) (?<object>[0-9a-f]{$ObjectIdLength}) (?<stage>[0-3])$") { throw 'git ls-files --stage returned an unsupported entry header or invalid object identity.' }
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

function Resolve-GraphKitPhysicalPath { param([string] $Path)
    $pathComparer = if ($IsWindows) { [StringComparer]::OrdinalIgnoreCase } else { [StringComparer]::Ordinal }
    $visitedLinks = [Collections.Generic.HashSet[string]]::new($pathComparer)

    function Resolve-GraphKitExistingPathComponents { param([string] $FullPath, $VisitedLinks)
        $fullPath = [IO.Path]::GetFullPath($FullPath)
        $root = [IO.Path]::GetPathRoot($fullPath)
        if ([string]::IsNullOrEmpty($root)) { throw "Cannot resolve physical path '$FullPath' without a filesystem root." }
        $separators = [char[]] @([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
        $segments = $fullPath.Substring($root.Length).Split($separators, [StringSplitOptions]::RemoveEmptyEntries)
        $current = $root
        foreach ($segment in $segments) {
            $candidate = [IO.Path]::Combine($current, $segment)
            $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
            $target = $item.ResolveLinkTarget($true)
            if ($null -ne $target) {
                $linkPath = [IO.Path]::GetFullPath($item.FullName)
                if (-not $VisitedLinks.Add($linkPath)) { throw "Filesystem link cycle detected while resolving '$Path'." }
                $current = Resolve-GraphKitExistingPathComponents ([IO.Path]::GetFullPath($target.FullName)) $VisitedLinks
            }
            else {
                $current = [IO.Path]::GetFullPath($item.FullName)
            }
        }
        return $current
    }

    return Resolve-GraphKitExistingPathComponents ([IO.Path]::GetFullPath($Path)) $visitedLinks
}

function Get-GraphKitProofBoundHelperInventoryPath { param([string] $Root, [string] $Helper, [Text.UTF8Encoding] $Utf8)
    $rootPath = Resolve-GraphKitPhysicalPath $Root
    $helperPath = Resolve-GraphKitPhysicalPath $Helper
    $relative = [IO.Path]::GetRelativePath($rootPath, $helperPath)
    if ([IO.Path]::IsPathRooted($relative) -or
        $relative -eq '..' -or
        $relative.StartsWith("..$([IO.Path]::DirectorySeparatorChar)", [StringComparison]::Ordinal) -or
        $relative.StartsWith("..$([IO.Path]::AltDirectorySeparatorChar)", [StringComparison]::Ordinal)) {
        return $null
    }
    $gitPath = $relative.Replace([IO.Path]::DirectorySeparatorChar, '/').Replace([IO.Path]::AltDirectorySeparatorChar, '/')
    return ,$Utf8.GetBytes($gitPath)
}

function Initialize-GraphKitSourceCapture {
    $helper = Join-Path $PSScriptRoot 'private/GraphKit.SourceCapture.cs'
    if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) { throw "The GraphKit source-capture helper is missing at '$helper'." }
    $helperBytes = [IO.File]::ReadAllBytes($helper)
    $helperHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($helperBytes)).ToLowerInvariant()
    $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
    try { $template = $strictUtf8.GetString($helperBytes) }
    catch { throw "The GraphKit source-capture helper '$helper' is not strict UTF-8." }
    $marker = '__GRAPHKIT_SOURCE_CAPTURE_NAMESPACE__'
    if (($template.Split([string[]] @($marker), [StringSplitOptions]::None).Length - 1) -ne 1) {
        throw "The GraphKit source-capture helper '$helper' must contain exactly one namespace identity marker."
    }
    $nonce = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(16)).ToLowerInvariant()
    $namespace = "GraphKit.R8.Generated.H$helperHash.N$nonce"
    $expectedTypeName = "$namespace.SourceCapture"
    $collision = @([AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object { $_.GetType($expectedTypeName, $false, $false) } | Where-Object { $null -ne $_ })
    if ($collision.Count) { throw "The generated GraphKit source-capture type identity '$expectedTypeName' already exists; refusing an ambient helper collision." }
    $compiledTypes = @(Add-Type -TypeDefinition $template.Replace($marker, $namespace) -PassThru)
    $captureTypes = @($compiledTypes | Where-Object FullName -CEQ $expectedTypeName)
    if ($captureTypes.Count -ne 1) { throw "The proof-bound GraphKit source-capture helper did not return exactly one '$expectedTypeName' type." }
    $loadedTypes = @([AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object { $_.GetType($expectedTypeName, $false, $false) } | Where-Object { $null -ne $_ })
    if ($loadedTypes.Count -ne 1 -or -not [object]::ReferenceEquals($loadedTypes[0], $captureTypes[0])) {
        throw "The generated GraphKit source-capture type identity '$expectedTypeName' collided during compilation; refusing ambient code."
    }
    [pscustomobject] @{ type = $captureTypes[0]; sourceBytes = $helperBytes; sourceSha256 = $helperHash; sourcePath = [IO.Path]::GetFullPath($helper) }
}

function Get-GraphKitWorktreeEntry { param([string] $Root, [byte[]] $RawPath, [Text.UTF8Encoding] $Utf8, [AllowNull()][string] $IndexMode, [type] $CaptureType)
    $relative = Get-GraphKitRelativePath $RawPath $Utf8
    try { $capture = $CaptureType::Capture($Root, $relative) }
    catch {
        $failure = if ($_.Exception.InnerException) { $_.Exception.InnerException } else { $_.Exception }
        if ($failure -is [IO.FileNotFoundException] -or $failure.InnerException -is [IO.FileNotFoundException]) {
            return [pscustomobject] @{ type='missing'; mode=''; identity=''; length=0; content=[byte[]] @() }
        }
        throw "Cannot root-anchored no-follow capture source entry '$relative': $($failure.Message)"
    }
    $mode = $CaptureType::ResolveEffectiveGitMode($capture.Mode, $capture.HasExecutableMode, $IndexMode)
    return [pscustomobject] @{ type='regular'; mode=$mode; identity=$capture.Identity; length=$capture.Length; content=$capture.Content }
}

function Assert-GraphKitRawPathSetUnambiguous { param($Records, [Text.UTF8Encoding] $Utf8)
    $portable = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($record in $Records) {
        $relative = Get-GraphKitRelativePath $record.path $Utf8
        $normalized = $relative.Normalize([Text.NormalizationForm]::FormC)
        $rawKey = [Convert]::ToHexString($record.path)
        $existing = ''
        if ($portable.TryGetValue($normalized, [ref] $existing) -and $existing -cne $rawKey) {
            throw "Git source paths collide by case or Unicode normalization at '$relative'; refusing an ambiguous package-source inventory."
        }
        $portable[$normalized] = $rawKey
    }
}

function Get-GraphKitBlobId { param([string] $Format, [byte[]] $Content)
    $header = [Text.Encoding]::ASCII.GetBytes("blob $($Content.Length)`0"); $bytes = [byte[]]::new($header.Length + $Content.Length)
    [Array]::Copy($header, 0, $bytes, 0, $header.Length); [Array]::Copy($Content, 0, $bytes, $header.Length, $Content.Length)
    $hash = if ($Format -eq 'sha1') { [Security.Cryptography.SHA1]::HashData($bytes) } elseif ($Format -eq 'sha256') { [Security.Cryptography.SHA256]::HashData($bytes) } else { throw "Unsupported Git object format '$Format'." }
    return [Convert]::ToHexString($hash).ToLowerInvariant()
}

function Get-GraphKitFilesystemExtras { param([string] $Root, $Known, [Text.UTF8Encoding] $Utf8)
    $found = [Collections.Generic.List[byte[]]]::new(); $directories = [Collections.Generic.Stack[string]]::new(); $directories.Push($Root)
    while ($directories.Count) { foreach ($fullPath in [IO.Directory]::EnumerateFileSystemEntries($directories.Pop())) {
        $relative = $fullPath.Substring($Root.Length).TrimStart([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
        if ($relative -eq '.git' -or $relative.StartsWith(".git$([IO.Path]::DirectorySeparatorChar)", [StringComparison]::Ordinal)) { continue }
        $raw = $Utf8.GetBytes(($relative -replace '\\', '/')); $item = Get-Item -LiteralPath $fullPath -Force
        if ($item -is [IO.DirectoryInfo] -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { $directories.Push($fullPath) } elseif (-not $Known.Contains([Convert]::ToHexString($raw))) { $found.Add($raw) }
    } }
    $stream = [IO.MemoryStream]::new(); foreach ($raw in @($found | Sort-Object { [Convert]::ToHexString($_) })) { $stream.Write($raw,0,$raw.Length); $stream.WriteByte(0) }; return ,$stream.ToArray()
}

function Get-GraphKitObjectFormat { param([byte[]] $Bytes)
    $format = [Text.Encoding]::ASCII.GetString($Bytes).Trim().ToLowerInvariant()
    if ($format -eq 'sha256') { throw 'Git SHA-256 object-format repositories are not supported by the GraphKit R8 release-identity proof. Use a SHA-1 clone for package production.' }
    if ($format -ne 'sha1') { throw "Unsupported Git object format '$format'." }
    return [pscustomobject] @{ name='sha1'; objectIdLength=40 }
}

function Get-GraphKitCommitOid { param([byte[]] $Bytes, [int] $ObjectIdLength)
    $oid = [Text.Encoding]::ASCII.GetString($Bytes).Trim()
    if ($oid -cnotmatch "^[0-9a-f]{$ObjectIdLength}$") { throw "Git returned an invalid $ObjectIdLength-character HEAD commit object identity." }
    return $oid
}

function Get-GraphKitInventory { param([string] $Root, [Text.UTF8Encoding] $Utf8)
    $formatBytes = Invoke-GraphKitGitBytes $Root @('rev-parse','--show-object-format')
    $format = Get-GraphKitObjectFormat $formatBytes
    $headOidBytes = Invoke-GraphKitGitBytes $Root @('rev-parse','--verify','HEAD^{commit}')
    $headOid = Get-GraphKitCommitOid $headOidBytes $format.objectIdLength
    $headBytes = Invoke-GraphKitGitBytes $Root @('ls-tree','-r','-z',$headOid)
    $indexBytes = Invoke-GraphKitGitBytes $Root @('ls-files','--stage','-z')
    $untrackedBytes = Invoke-GraphKitGitBytes $Root @('ls-files','--others','--exclude-standard','-z')
    $head = ConvertFrom-GraphKitTree $headBytes $format.objectIdLength; $index = ConvertFrom-GraphKitIndex $indexBytes $format.objectIdLength
    $known = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal); foreach ($key in $head.Keys) { $null=$known.Add($key) }; foreach ($key in $index.Keys) { $null=$known.Add($key) }; foreach ($path in (Get-GraphKitNulRecords $untrackedBytes 'git ls-files --others').records) { $null=$known.Add([Convert]::ToHexString($path)) }
    $extras = (Get-GraphKitNulRecords (Get-GraphKitFilesystemExtras $Root $known $Utf8) 'filesystem inventory').records
    if ($extras.Count) {
        $input=[IO.MemoryStream]::new(); foreach($path in $extras){$input.Write($path,0,$path.Length);$input.WriteByte(0)}
        $ignored = (Get-GraphKitNulRecords (Invoke-GraphKitGitBytes $Root @('check-ignore','-z','--stdin') $input.ToArray() @(0,1)) 'git check-ignore').records
        $ignoredKeys=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal); foreach($path in $ignored){$null=$ignoredKeys.Add([Convert]::ToHexString($path))}
        $joined=[IO.MemoryStream]::new();$joined.Write($untrackedBytes,0,$untrackedBytes.Length);foreach($path in $extras){if(-not $ignoredKeys.Contains([Convert]::ToHexString($path))){$joined.Write($path,0,$path.Length);$joined.WriteByte(0)}};$untrackedBytes=$joined.ToArray()
    }
    [pscustomobject] @{ formatBytes=$formatBytes; format=$format.name; objectIdLength=$format.objectIdLength; headOidBytes=$headOidBytes; headOid=$headOid; headBytes=$headBytes; indexBytes=$indexBytes; untrackedBytes=$untrackedBytes; head=$head; index=$index }
}

function Get-GraphKitR8SourceState { param([string] $Root)
    # v4: domain-separated, length-framed HEAD/index/worktree inventory.  Git plumbing supplies
    # raw paths; each entry binds HEAD/index mode/type/object and no-follow worktree
    # mode/type/handle identity/bytes.  The helper template bytes are proof-bound separately from
    # its per-invocation unpredictable compiled type identity.
    # Snapshots before/after reads and a second no-follow content read make source races fatal.
    $utf8=[Text.UTF8Encoding]::new($false,$true); $captureHelper=Initialize-GraphKitSourceCapture; $captureType=$captureHelper.type;$helperPath=Get-GraphKitProofBoundHelperInventoryPath $Root $captureHelper.sourcePath $utf8
    $before=Get-GraphKitInventory $Root $utf8; $untracked=Get-GraphKitNulRecords $before.untrackedBytes 'git untracked inventory'; $records=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach($entry in $before.head.Values){$records.Add([Convert]::ToHexString($entry.path),[pscustomobject]@{path=$entry.path;head=$entry;index=$null})};foreach($entry in $before.index.Values){$key=[Convert]::ToHexString($entry.path);if($records.ContainsKey($key)){$records[$key].index=$entry}else{$records.Add($key,[pscustomobject]@{path=$entry.path;head=$null;index=$entry})}};foreach($path in $untracked.records){$key=[Convert]::ToHexString($path);if($records.ContainsKey($key)){throw 'Git reported a duplicate path across tracked and untracked inventories.'};$records.Add($key,[pscustomobject]@{path=$path;head=$null;index=$null})}
    Assert-GraphKitRawPathSetUnambiguous @($records.Values) $utf8
    $captured=[Collections.Generic.List[object]]::new();foreach($record in @($records.Values|Sort-Object{[Convert]::ToHexString($_.path)})){$indexMode=if($record.index){[string]$record.index.mode}else{$null};$worktree=Get-GraphKitWorktreeEntry $Root $record.path $utf8 $indexMode $captureType;if($worktree.type -eq 'missing' -and -not $record.head -and -not $record.index){throw 'A non-ignored untracked source entry disappeared during capture.'};$blob=if($record.index -and $worktree.type -eq 'regular' -and $worktree.mode -eq $record.index.mode){Get-GraphKitBlobId $before.format $worktree.content}else{''};$captured.Add([pscustomobject]@{path=$record.path;head=$record.head;index=$record.index;worktree=$worktree;blob=$blob})}
    $after=Get-GraphKitInventory $Root $utf8;if(-not(Test-GraphKitBytesEqual $before.formatBytes $after.formatBytes) -or -not(Test-GraphKitBytesEqual $before.headOidBytes $after.headOidBytes) -or -not(Test-GraphKitBytesEqual $before.headBytes $after.headBytes) -or -not(Test-GraphKitBytesEqual $before.indexBytes $after.indexBytes) -or -not(Test-GraphKitBytesEqual $before.untrackedBytes $after.untrackedBytes)){throw 'Git HEAD commit or source inventory changed during capture; refusing to emit a train version.'}
    foreach($entry in $captured){$indexMode=if($entry.index){[string]$entry.index.mode}else{$null};$again=Get-GraphKitWorktreeEntry $Root $entry.path $utf8 $indexMode $captureType;if($again.type -ne $entry.worktree.type -or $again.mode -ne $entry.worktree.mode -or $again.identity -ne $entry.worktree.identity -or $again.length -ne $entry.worktree.length -or -not(Test-GraphKitBytesEqual $again.content $entry.worktree.content)){throw 'Source entry changed during capture; refusing to emit a train version.'}}
    if($null -ne $helperPath){$helperRecord=@($captured|Where-Object{Test-GraphKitBytesEqual $_.path $helperPath});if($helperRecord.Count -ne 1){throw "The proof-bound source-capture helper inside RepositoryRoot requires exactly one exact raw inventory record; found $($helperRecord.Count)."};if(-not(Test-GraphKitBytesEqual $helperRecord[0].worktree.content $captureHelper.sourceBytes)){throw 'The compiled source-capture helper bytes do not match the proof-bound package-source inventory.'}}
    $clean=$untracked.records.Count -eq 0 -and $before.head.Count -eq $before.index.Count;foreach($entry in $captured){if(-not $entry.head -or -not $entry.index -or $entry.head.mode -ne $entry.index.mode -or $entry.head.type -ne $entry.index.type -or $entry.head.object -ne $entry.index.object -or $entry.worktree.type -ne 'regular' -or $entry.worktree.mode -ne $entry.index.mode -or $entry.blob -ne $entry.index.object){$clean=$false}}
    $stream=[IO.MemoryStream]::new();$write={param([byte[]]$b)$stream.Write($b,0,$b.Length)};$field={param([string]$n,[byte[]]$b)&$write([Text.Encoding]::ASCII.GetBytes($n));&$write([BitConverter]::GetBytes([uint64]$b.Length));&$write $b};&$write([Text.Encoding]::ASCII.GetBytes('GraphKit-R8-source-entry-state-v4'));&$write([byte[]]@(0));&$field 'capture-helper-sha256' ([Text.Encoding]::ASCII.GetBytes([string]$captureHelper.sourceSha256));foreach($entry in $captured){&$write([Text.Encoding]::ASCII.GetBytes('entry'));&$field 'path' $entry.path;foreach($side in @('head','index')){$value=$entry.$side;if($null -eq $value){$mode='';$type='';$object=''}else{$mode=[string]$value.mode;$type=[string]$value.type;$object=[string]$value.object};&$field "$side-mode" ([Text.Encoding]::ASCII.GetBytes($mode));&$field "$side-type" ([Text.Encoding]::ASCII.GetBytes($type));&$field "$side-object" ([Text.Encoding]::ASCII.GetBytes($object))};&$field 'worktree-type' ([Text.Encoding]::ASCII.GetBytes([string]$entry.worktree.type));&$field 'worktree-mode' ([Text.Encoding]::ASCII.GetBytes([string]$entry.worktree.mode));&$field 'worktree-identity' ([Text.Encoding]::UTF8.GetBytes([string]$entry.worktree.identity));&$field 'worktree-content' $entry.worktree.content};&$write([Text.Encoding]::ASCII.GetBytes('end'));&$write([byte[]]@(0))
    [pscustomobject]@{revision=$before.headOid;clean=[bool]$clean;sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream.ToArray())).ToLowerInvariant()}
}

$RepositoryRoot=Resolve-GraphKitPhysicalPath (Resolve-Path -LiteralPath $RepositoryRoot).ProviderPath;$base='0.4.0';$train='r8';$state=Get-GraphKitR8SourceState $RepositoryRoot;$revision=$state.revision;$version="$base-$train.g$($revision.Substring(0,12))$(if($state.clean){''}else{".d$($state.sha256.Substring(0,12))"})";if($AsObject){[pscustomobject][ordered]@{version=$version;baseVersion=$base;train=$train;revision=$revision;clean=[bool]$state.clean;sourceStateSha256=$state.sha256}}else{$version}
