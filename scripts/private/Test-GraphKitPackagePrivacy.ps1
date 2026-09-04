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
    $allowedGuids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($allowedGuid in @(
        '00000000-0000-0000-0000-000000000000',
        '00000000-0000-0000-0000-000000000001',
        '00000003-0000-0000-c000-000000000000',
        $ModuleGuid.ToString('D')
    )) {
        $null = $allowedGuids.Add($allowedGuid)
    }

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
            $memory = [System.IO.MemoryStream]::new()
            try {
                $entryStream.CopyTo($memory)
                $bytes = $memory.ToArray()
            }
            catch {
                throw "Package privacy scan failed closed while reading an entry (entry sha256: $entryDigest)."
            }
            finally {
                $memory.Dispose()
                $entryStream.Dispose()
            }
            if ($bytes.LongLength -ne $entry.Length) {
                throw "Package privacy scan rejected an entry whose byte count changed while reading (entry sha256: $entryDigest)."
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
