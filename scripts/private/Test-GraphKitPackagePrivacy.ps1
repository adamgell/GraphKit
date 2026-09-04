function Get-GraphKitPackagePrivacyDigest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    return [System.Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
}

function Test-GraphKitPackagePrivacyPlaceholderGuid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Value
    )

    # Sequential all-zero namespace values are conventional deterministic test ids, including
    # ...0002 and ...0099. They cannot be RFC 4122 identifiers because the version field is zero.
    if ($Value -match '^00000000-0000-0000-0000-[0-9]{12}$') {
        return $true
    }

    foreach ($segment in @($Value -split '-')) {
        if (@($segment.ToCharArray() | Select-Object -Unique).Count -gt 1) {
            return $false
        }
    }
    return $true
}

function Add-GraphKitPackagePrivacyFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]] $Findings,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]] $FindingKeys,

        [Parameter(Mandatory)]
        [string] $EntryName,

        [Parameter(Mandatory)]
        [string] $Encoding,

        [Parameter(Mandatory)]
        [string] $Category,

        [Parameter(Mandatory)]
        [string] $Evidence
    )

    $entryDigest = Get-GraphKitPackagePrivacyDigest -Value $EntryName
    $evidenceDigest = Get-GraphKitPackagePrivacyDigest -Value $Evidence
    $key = "$entryDigest|$Category|$evidenceDigest"
    if (-not $FindingKeys.Add($key)) {
        return
    }

    # No matched value is retained. Callers can safely render the fixed category and digests
    # in a public CI log without echoing the identifier the gate exists to contain.
    $Findings.Add([pscustomobject] [ordered] @{
        Category = $Category
        Encoding = $Encoding
        EntrySha256 = $entryDigest
        EvidenceSha256 = $evidenceDigest
    })
}

function Test-GraphKitPackagePrivacyText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter(Mandatory)]
        [string] $EntryName,

        [Parameter(Mandatory)]
        [string] $Encoding,

        [Parameter(Mandatory)]
        [System.Collections.Generic.HashSet[string]] $AllowedGuids,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]] $Findings,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]] $FindingKeys
    )

    $fixedPatterns = [ordered] @{
        'local user path' = '(?i)(?:/Users/[A-Za-z0-9._-]+|[A-Za-z]:\\Users\\[A-Za-z0-9._-]+)'
        'internal project name' = '(?i)\bivy24\b|\bIntuneHealthAutomation\b'
    }
    foreach ($category in $fixedPatterns.Keys) {
        foreach ($match in [regex]::Matches($Text, $fixedPatterns[$category])) {
            Add-GraphKitPackagePrivacyFinding -Findings $Findings -FindingKeys $FindingKeys `
                -EntryName $EntryName -Encoding $Encoding -Category $category -Evidence $match.Value
        }
    }

    $guidPattern = '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
    foreach ($match in [regex]::Matches($Text, $guidPattern)) {
        if ($AllowedGuids.Contains($match.Value) -or
            (Test-GraphKitPackagePrivacyPlaceholderGuid -Value $match.Value)) {
            continue
        }
        Add-GraphKitPackagePrivacyFinding -Findings $Findings -FindingKeys $FindingKeys `
            -EntryName $EntryName -Encoding $Encoding `
            -Category 'GUID that is not a well-known or package id' -Evidence $match.Value
    }

    # Forty hexadecimal characters are also the normal shape of Git source and dependency
    # revisions. Treating every such value as a certificate thumbprint makes the real compiled
    # package fail on its deterministic RepositoryCommit metadata. Require certificate context
    # close to the value instead; the match is still redacted before it leaves this function.
    $thumbprintPattern = '(?is)\b(?:certificate(?:[-_ ]?thumbprint)?|thumbprint|certificate[-_ ]?fingerprint)\b[^\r\n]{0,64}?\b(?<value>[0-9a-f]{40})\b'
    foreach ($match in [regex]::Matches($Text, $thumbprintPattern)) {
        Add-GraphKitPackagePrivacyFinding -Findings $Findings -FindingKeys $FindingKeys `
            -EntryName $EntryName -Encoding $Encoding -Category 'certificate thumbprint' `
            -Evidence $match.Groups['value'].Value
    }

    # Customer tokens stay represented only by one-way digests in public source. Never add a
    # plaintext customer name here and never retain the matching token in a result object.
    $secretTokenHashes = @{
        '5cad5cdbf022740cbfc976f9836ac89d' = 'customer name (A)'
        'e03427b1afcd1e84a97ed1f2241466cb' = 'internal workspace tenant'
        '9a08498936078c81ec926fedbce5e7c9' = 'customer name (A, short form)'
        '6ca05670c4afd49e806f7cddbab83b00' = 'lab tenant id'
    }
    foreach ($token in [regex]::Matches($Text, '[A-Za-z0-9][A-Za-z0-9-]{3,}')) {
        $tokenDigest = (Get-GraphKitPackagePrivacyDigest -Value $token.Value.ToLowerInvariant()).Substring(0, 32)
        if ($secretTokenHashes.ContainsKey($tokenDigest)) {
            Add-GraphKitPackagePrivacyFinding -Findings $Findings -FindingKeys $FindingKeys `
                -EntryName $EntryName -Encoding $Encoding `
                -Category ("internal identifier - {0}" -f $secretTokenHashes[$tokenDigest]) `
                -Evidence $token.Value
        }
    }
}

function ConvertFrom-GraphKitPackagePrintableAscii {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes
    )

    $text = [System.Text.StringBuilder]::new()
    $run = [System.Text.StringBuilder]::new()
    foreach ($value in $Bytes) {
        if ($value -ge 0x20 -and $value -le 0x7e) {
            $null = $run.Append([char] $value)
            continue
        }
        if ($run.Length -ge 4) {
            $null = $text.AppendLine($run.ToString())
        }
        $null = $run.Clear()
    }
    if ($run.Length -ge 4) {
        $null = $text.AppendLine($run.ToString())
    }
    return $text.ToString()
}

function Get-GraphKitPackagePrivacyAllowedGuidSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [guid] $ModuleGuid
    )

    $allowedGuids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($allowedGuid in @(
        '00000000-0000-0000-0000-000000000000',
        '00000000-0000-0000-0000-000000000001',
        '00000003-0000-0000-c000-000000000000',
        # Public solution metadata: the C# project-type id and the three stable
        # GraphKit.Auth project ids. Keep this explicit so an unrelated GUID in
        # project metadata still fails the privacy gate.
        'FAE04EC0-301F-11D3-BF4B-00C04F79EFBC',
        'A1A5DC18-8823-4AA1-BB0D-6F96E19E13C0',
        'B2B6ED29-9934-4BB2-CC1E-70A7F20F24D1',
        'C3C7FE3A-AA45-4CC3-DD2F-81B8A31035E2',
        $ModuleGuid.ToString('D')
    )) {
        $null = $allowedGuids.Add($allowedGuid)
    }
    return ,$allowedGuids
}

function Test-GraphKitAuthSourcePrivacy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $SourceRoot,

        [Parameter(Mandatory)]
        [guid] $ModuleGuid
    )

    if (-not (Test-Path -LiteralPath $SourceRoot -PathType Container)) {
        throw 'GraphKit.Auth privacy scan requires the authored source directory.'
    }

    try {
        $resolvedSourceRoot = (Resolve-Path -LiteralPath $SourceRoot -ErrorAction Stop).ProviderPath
        $sourceCandidates = @(Get-ChildItem -LiteralPath $resolvedSourceRoot -Recurse -File -Force -ErrorAction Stop)
    }
    catch {
        throw 'GraphKit.Auth privacy scan could not enumerate the authored source directory.'
    }

    $findings = [System.Collections.Generic.List[object]]::new()
    $findingKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $allowedGuids = Get-GraphKitPackagePrivacyAllowedGuidSet -ModuleGuid $ModuleGuid
    $sourcePathKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $normalizedSourcePathKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $maximumSourceFileBytes = 32MB
    $maximumSourceBytes = 128MB
    [long] $scannedBytes = 0
    [int] $sourceFilesScanned = 0
    $authoredTextExtensions = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($extension in @('.cs', '.csproj', '.props', '.sln', '.json')) {
        $null = $authoredTextExtensions.Add($extension)
    }

    foreach ($sourceFile in $sourceCandidates) {
        $relativePath = [System.IO.Path]::GetRelativePath($resolvedSourceRoot, $sourceFile.FullName).Replace('\', '/')
        $segments = @($relativePath -split '/')
        if (@($segments | Where-Object { $_ -ieq 'bin' -or $_ -ieq 'obj' }).Count -gt 0 -or
            -not $authoredTextExtensions.Contains([System.IO.Path]::GetExtension($sourceFile.Name))) {
            continue
        }

        $sourcePathDigest = Get-GraphKitPackagePrivacyDigest -Value $relativePath
        $normalizedPath = $relativePath.Normalize([System.Text.NormalizationForm]::FormC)
        if ($relativePath -cne $normalizedPath -or
            -not $sourcePathKeys.Add($relativePath) -or
            -not $normalizedSourcePathKeys.Add($normalizedPath)) {
            throw "GraphKit.Auth privacy scan rejected an ambiguous source path (source sha256: $sourcePathDigest)."
        }

        [long] $declaredLength = $sourceFile.Length
        if ($declaredLength -lt 0 -or $declaredLength -gt $maximumSourceFileBytes) {
            throw "GraphKit.Auth privacy scan rejected an oversized source file (source sha256: $sourcePathDigest)."
        }
        $scannedBytes += $declaredLength
        if ($scannedBytes -gt $maximumSourceBytes) {
            throw 'GraphKit.Auth privacy scan rejected a source tree whose bytes exceed the fixed bound.'
        }

        try {
            $bytes = [System.IO.File]::ReadAllBytes($sourceFile.FullName)
        }
        catch {
            throw "GraphKit.Auth privacy scan failed closed while reading source (source sha256: $sourcePathDigest)."
        }
        if ($bytes.LongLength -ne $declaredLength) {
            throw "GraphKit.Auth privacy scan rejected source whose byte count changed while reading (source sha256: $sourcePathDigest)."
        }

        try {
            $text = $strictUtf8.GetString($bytes)
        }
        catch {
            throw "GraphKit.Auth privacy scan rejected an authored project file that is not strict UTF-8 (source sha256: $sourcePathDigest)."
        }
        if ($text.Length -gt 0 -and $text[0] -eq [char] 0xfeff) {
            $text = $text.Substring(1)
        }

        Test-GraphKitPackagePrivacyText -Text $relativePath -EntryName $relativePath -Encoding 'source-path' `
            -AllowedGuids $allowedGuids -Findings $findings -FindingKeys $findingKeys
        Test-GraphKitPackagePrivacyText -Text $text -EntryName $relativePath -Encoding 'source-strict-utf8' `
            -AllowedGuids $allowedGuids -Findings $findings -FindingKeys $findingKeys
        $sourceFilesScanned++
    }

    if ($sourceFilesScanned -eq 0) {
        throw 'GraphKit.Auth privacy scan found no authored project files and failed closed.'
    }

    return [pscustomobject] [ordered] @{
        Passed = $findings.Count -eq 0
        Findings = @($findings)
        SourceFilesScanned = $sourceFilesScanned
        BytesScanned = $scannedBytes
    }
}

function Read-GraphKitPackagePrivacyEntryBytesBounded {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [System.IO.Stream] $EntryStream,

        [Parameter(Mandatory)]
        [long] $DeclaredLength
    )

    $maximumEntryBytes = 32MB
    if ($DeclaredLength -lt 0 -or $DeclaredLength -gt $maximumEntryBytes) {
        throw 'Package privacy scan rejected an entry whose declared byte count is outside the fixed bound.'
    }

    $memory = [System.IO.MemoryStream]::new()
    try {
        $buffer = [byte[]]::new(81920)
        [long] $remainingWithSentinel = $DeclaredLength + 1
        while ($remainingWithSentinel -gt 0) {
            $requested = [int] [Math]::Min([long] $buffer.Length, $remainingWithSentinel)
            $read = $EntryStream.Read($buffer, 0, $requested)
            if ($read -le 0) {
                break
            }
            $memory.Write($buffer, 0, $read)
            $remainingWithSentinel -= $read
        }

        if ($memory.Length -ne $DeclaredLength) {
            throw 'Package privacy scan rejected an entry whose actual byte count differs from its declared byte count.'
        }
        return ,$memory.ToArray()
    }
    finally {
        $memory.Dispose()
    }
}

function Test-GraphKitPackagePrivacy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $PackagePath,

        [Parameter(Mandatory)]
        [guid] $ModuleGuid
    )

    if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) {
        throw 'Package privacy scan requires one existing verifier-owned package file.'
    }

    $findings = [System.Collections.Generic.List[object]]::new()
    $findingKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $allowedGuids = Get-GraphKitPackagePrivacyAllowedGuidSet -ModuleGuid $ModuleGuid

    $textExtensions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($textExtension in @(
        '.psm1', '.psd1', '.ps1', '.ps1xml', '.txt', '.nuspec', '.xml', '.md', '.json', '.cs', '.psmdcp', '.rels'
    )) {
        $null = $textExtensions.Add($textExtension)
    }
    $strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $lenientUtf8 = [System.Text.UTF8Encoding]::new($false, $false)
    $maximumEntryBytes = 32MB
    $maximumScannedBytes = 128MB
    [long] $scannedBytes = 0
    [int] $textEntriesScanned = 0
    [int] $binaryEntriesScanned = 0

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    try {
        $archive = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $PackagePath).ProviderPath)
    }
    catch {
        throw 'Package privacy scan could not open the verifier-owned package as a ZIP archive.'
    }

    try {
        $entryNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $archive.Entries) {
            $entryName = [string] $entry.FullName
            $entryDigest = Get-GraphKitPackagePrivacyDigest -Value $entryName
            if ([string]::IsNullOrWhiteSpace($entryName) -or
                [string]::IsNullOrEmpty($entry.Name) -or
                -not $entryNames.Add($entryName)) {
                throw "Package privacy scan rejected an ambiguous entry (entry sha256: $entryDigest)."
            }
            if ($entry.Length -lt 0 -or $entry.Length -gt $maximumEntryBytes) {
                throw "Package privacy scan rejected an oversized entry (entry sha256: $entryDigest)."
            }
            $scannedBytes += [long] $entry.Length
            if ($scannedBytes -gt $maximumScannedBytes) {
                throw 'Package privacy scan rejected a package whose scannable bytes exceed the fixed bound.'
            }

            Test-GraphKitPackagePrivacyText -Text $entryName -EntryName $entryName -Encoding 'entry-name' `
                -AllowedGuids $allowedGuids -Findings $findings -FindingKeys $findingKeys

            $extension = [System.IO.Path]::GetExtension($entry.Name)
            if (-not $textExtensions.Contains($extension) -and $extension -ine '.dll') {
                continue
            }

            $entryStream = $entry.Open()
            try {
                $bytes = Read-GraphKitPackagePrivacyEntryBytesBounded `
                    -EntryStream $entryStream -DeclaredLength ([long] $entry.Length)
            }
            catch {
                throw "Package privacy scan failed closed while reading an entry (entry sha256: $entryDigest)."
            }
            finally {
                $entryStream.Dispose()
            }

            if ($extension -ine '.dll') {
                try {
                    $text = $strictUtf8.GetString($bytes)
                }
                catch {
                    throw "Package privacy scan rejected a text entry that is not strict UTF-8 (entry sha256: $entryDigest)."
                }
                if ($text.Length -gt 0 -and $text[0] -eq [char] 0xfeff) {
                    $text = $text.Substring(1)
                }
                Test-GraphKitPackagePrivacyText -Text $text -EntryName $entryName -Encoding 'strict-utf8' `
                    -AllowedGuids $allowedGuids -Findings $findings -FindingKeys $findingKeys
                $textEntriesScanned++
                continue
            }

            $asciiText = ConvertFrom-GraphKitPackagePrintableAscii -Bytes $bytes
            Test-GraphKitPackagePrivacyText -Text $asciiText -EntryName $entryName -Encoding 'binary-ascii' `
                -AllowedGuids $allowedGuids -Findings $findings -FindingKeys $findingKeys

            $utf8Text = $lenientUtf8.GetString($bytes)
            Test-GraphKitPackagePrivacyText -Text $utf8Text -EntryName $entryName -Encoding 'binary-utf8' `
                -AllowedGuids $allowedGuids -Findings $findings -FindingKeys $findingKeys

            foreach ($offset in @(0, 1)) {
                $byteCount = $bytes.Length - $offset
                if ($byteCount -lt 2) { continue }
                if (($byteCount % 2) -ne 0) { $byteCount-- }
                $utf16Text = [System.Text.Encoding]::Unicode.GetString($bytes, $offset, $byteCount)
                Test-GraphKitPackagePrivacyText -Text $utf16Text -EntryName $entryName -Encoding 'binary-utf16le' `
                    -AllowedGuids $allowedGuids -Findings $findings -FindingKeys $findingKeys
            }
            $binaryEntriesScanned++
        }
    }
    finally {
        $archive.Dispose()
    }

    return [pscustomobject] [ordered] @{
        Passed = $findings.Count -eq 0
        Findings = @($findings)
        TextEntriesScanned = $textEntriesScanned
        BinaryEntriesScanned = $binaryEntriesScanned
        BytesScanned = $scannedBytes
    }
}
