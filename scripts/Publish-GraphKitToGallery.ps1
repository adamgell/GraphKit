<#
    .SYNOPSIS
        Pre-flight checks, then publishes GraphKit to the PowerShell Gallery.

    .DESCRIPTION
        Publishing to the public gallery is effectively permanent: a version can be unlisted
        but never deleted, and the module name is claimed for good. Everything this script
        does before the push exists because of that.

        The API key is never taken as a plain parameter and never appears on a command line.
        It is prompted for as a SecureString, so it does not enter shell history, does not sit
        in a variable another process can read, and is converted to plain text only at the
        moment it is handed to Publish-PSResource.

        Pre-flight refuses to publish when:

          - the package does not exist, or was not built from the current manifest version
          - the manifest fails Test-ModuleManifest
          - required gallery metadata is missing (Author, Description, Tags, LicenseUri)
          - the package contains identifiers that must not become public - tenant ids, client
            ids, certificate thumbprints, local paths, or internal project names
          - that exact version already exists on the gallery
          - the test suite result for this version is absent or failing

        The scan is the important one. Everything else can be fixed in the next version; a
        tenant id in a published package cannot be taken back.

    .PARAMETER PackagePath
        The .nupkg to publish. Defaults to the current version in output/.

    .PARAMETER WhatIfOnly
        Run every pre-flight check and stop, without prompting for a key or publishing.

    .EXAMPLE
        ./scripts/Publish-GraphKitToGallery.ps1 -WhatIfOnly

        Runs the full pre-flight and publishes nothing.

    .EXAMPLE
        ./scripts/Publish-GraphKitToGallery.ps1

        Runs pre-flight, prompts for the API key, publishes.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $PackagePath,

    [switch] $WhatIfOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$repoRoot = Split-Path $PSScriptRoot -Parent
$manifestPath = Join-Path $repoRoot 'source/GraphKit.psd1'
$manifest = Import-PowerShellDataFile $manifestPath
$version = $manifest.ModuleVersion

if ([string]::IsNullOrWhiteSpace($PackagePath)) {
    $PackagePath = Join-Path $repoRoot "output/GraphKit.$version.nupkg"
}

$failures = [System.Collections.Generic.List[string]]::new()
function Test-Gate {
    param([string] $Name, [bool] $Passed, [string] $Detail = '')
    $mark = if ($Passed) { '[+]' } else { '[-]' }
    $colour = if ($Passed) { 'Green' } else { 'Red' }
    Write-Host ("  {0} {1,-46} {2}" -f $mark, $Name, $Detail) -ForegroundColor $colour
    if (-not $Passed) { $failures.Add($Name) }
}

Write-Host ''
Write-Host "  Pre-flight for GraphKit $version -> PowerShell Gallery" -ForegroundColor Cyan
Write-Host ''

# --- package exists and matches the manifest version ------------------------------------
$packageExists = Test-Path -LiteralPath $PackagePath -PathType Leaf
Test-Gate 'package exists' $packageExists $(if ($packageExists) { Split-Path $PackagePath -Leaf } else { $PackagePath })

if ($packageExists) {
    Test-Gate 'package version matches the manifest' ((Split-Path $PackagePath -Leaf) -eq "GraphKit.$version.nupkg") "manifest says $version"
}

# --- manifest validity and gallery metadata ----------------------------------------------
$builtManifest = Join-Path $repoRoot "output/module/GraphKit/$version/GraphKit.psd1"
if (Test-Path -LiteralPath $builtManifest) {
    try {
        $null = Test-ModuleManifest -Path $builtManifest -ErrorAction Stop
        Test-Gate 'Test-ModuleManifest passes' $true
    }
    catch {
        Test-Gate 'Test-ModuleManifest passes' $false $_.Exception.Message
    }
}
else {
    Test-Gate 'built module present' $false $builtManifest
}

$psData = $manifest.PrivateData.PSData
Test-Gate 'Author set' (-not [string]::IsNullOrWhiteSpace($manifest.Author)) $manifest.Author
Test-Gate 'Description set' (-not [string]::IsNullOrWhiteSpace($manifest.Description))
Test-Gate 'Tags set' ($psData.ContainsKey('Tags') -and @($psData.Tags).Count -gt 0) "$(@($psData.Tags).Count) tags"
Test-Gate 'LicenseUri set' ($psData.ContainsKey('LicenseUri') -and -not [string]::IsNullOrWhiteSpace($psData.LicenseUri))
Test-Gate 'LICENSE file present' (Test-Path -LiteralPath (Join-Path $repoRoot 'LICENSE'))
Test-Gate 'ReleaseNotes set' ($psData.ContainsKey('ReleaseNotes') -and -not [string]::IsNullOrWhiteSpace($psData.ReleaseNotes))

# --- the scan that cannot be undone after the fact ---------------------------------------
if ($packageExists) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($PackagePath)
    try {
        $findings = [System.Collections.Generic.List[string]]::new()
        $patterns = @{
            'GUID that is not a well-known Microsoft id' = '\b(?!00000000-0000-0000-0000-00000000000[01]\b)(?!00000003-0000-0000-c000-000000000000\b)(?!' + [regex]::Escape($manifest.GUID) + '\b)[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
            'certificate thumbprint'                     = '\b[0-9A-Fa-f]{40}\b'
            'local user path'                            = '/Users/[A-Za-z0-9._-]+|C:\\Users\\[A-Za-z0-9._-]+'
            'internal project name'                      = '(?i)\bivy24\b|\bIntuneHealthAutomation\b'
        }

        # Customer names are matched by HASH rather than by literal, because this script lives in
        # a public repository: a regex spelling out a customer name would publish the name it
        # exists to keep out. SHA-256 of the lowercased token, first 32 hex chars. To add one,
        # hash it the same way and give it a non-identifying label - never the name itself.
        $secretTokenHashes = @{
            '5cad5cdbf022740cbfc976f9836ac89d' = 'customer name (A)'
            'e03427b1afcd1e84a97ed1f2241466cb' = 'internal workspace tenant'
            '9a08498936078c81ec926fedbce5e7c9' = 'customer name (A, short form)'
            '6ca05670c4afd49e806f7cddbab83b00' = 'lab tenant id'
        }
        function Get-TokenDigest {
            param([string] $Token)
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($Token.ToLowerInvariant())
            return [System.BitConverter]::ToString(
                [System.Security.Cryptography.SHA256]::HashData($bytes)
            ).Replace('-', '').ToLowerInvariant().Substring(0, 32)
        }

        foreach ($entry in $archive.Entries) {
            if ($entry.FullName -notmatch '\.(psm1|psd1|ps1|ps1xml|txt|nuspec|xml|md)$') { continue }
            $reader = [System.IO.StreamReader]::new($entry.Open())
            try { $content = $reader.ReadToEnd() } finally { $reader.Dispose() }

            foreach ($token in [regex]::Matches($content, '[A-Za-z0-9][A-Za-z0-9-]{3,}')) {
                $digest = Get-TokenDigest -Token $token.Value
                if ($secretTokenHashes.ContainsKey($digest)) {
                    # Report the label, never the matched value - this output is shown on screen
                    # and would otherwise reintroduce the name it just caught.
                    $findings.Add(('{0}: internal identifier - {1}' -f $entry.FullName, $secretTokenHashes[$digest]))
                }
            }

            foreach ($label in $patterns.Keys) {
                foreach ($match in [regex]::Matches($content, $patterns[$label])) {
                    # Documentation placeholders like 11111111-2222-3333-4444-555555555555 are
                    # conventional in .EXAMPLE blocks and carry no information. A real
                    # identifier never has every segment built from one repeated character.
                    if ($label -like 'GUID*') {
                        # @() is required: Select-Object -Unique returns a scalar for a
                        # segment of identical characters, and a scalar has no .Count under
                        # Set-StrictMode.
                        $segments = @($match.Value -split '-')
                        $varied = @($segments | Where-Object { @($_.ToCharArray() | Select-Object -Unique).Count -gt 1 })
                        if ($varied.Count -eq 0) { continue }
                    }
                    $findings.Add("$label in $($entry.FullName): $($match.Value)")
                }
            }
        }
    }
    finally { $archive.Dispose() }

    Test-Gate 'package carries no identifiers that must stay private' ($findings.Count -eq 0) "$($findings.Count) finding(s)"
    foreach ($finding in ($findings | Select-Object -First 12)) {
        Write-Host "        $finding" -ForegroundColor Yellow
    }
}

# --- the version is not already on the gallery -------------------------------------------
try {
    $existing = Find-PSResource -Name GraphKit -Repository PSGallery -ErrorAction SilentlyContinue
    if ($null -eq $existing) {
        Test-Gate 'name is unclaimed on PSGallery' $true 'no existing GraphKit'
    }
    else {
        $versions = @($existing | ForEach-Object { $_.Version.ToString() })
        Test-Gate 'this version is not already published' ($version -notin $versions) "gallery has: $($versions -join ', ')"
    }
}
catch {
    Test-Gate 'gallery reachable' $false $_.Exception.Message
}

# --- a passing test result for this exact version ----------------------------------------
$resultFile = Get-ChildItem -Path (Join-Path $repoRoot 'output/testResults') -Filter "NUnit*$version*.xml" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($null -eq $resultFile) {
    Test-Gate "test result for $version present" $false 'run ./build.ps1 -Tasks pack then -Tasks test'
}
else {
    [xml] $doc = Get-Content -LiteralPath $resultFile.FullName -Raw
    $root = $doc.SelectSingleNode('/test-results')
    $failed = [int] $root.GetAttribute('failures')
    $total = [int] $root.GetAttribute('total')
    Test-Gate "tests green for $version" ($failed -eq 0) "$total tests, $failed failed"
}

Write-Host ''
if ($failures.Count -gt 0) {
    Write-Host "  PRE-FLIGHT FAILED - $($failures.Count) gate(s):" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
    Write-Host ''
    exit 1
}
Write-Host '  PRE-FLIGHT PASSED' -ForegroundColor Green
Write-Host ''

if ($WhatIfOnly) {
    Write-Host '  -WhatIfOnly: stopping before the key prompt. Nothing was published.' -ForegroundColor DarkGray
    Write-Host ''
    exit 0
}

# --- publish ------------------------------------------------------------------------------
Write-Host '  This publishes to the PUBLIC PowerShell Gallery.' -ForegroundColor Yellow
Write-Host '  A published version can be unlisted but NEVER deleted, and the name is claimed permanently.' -ForegroundColor Yellow
Write-Host ''

if (-not $PSCmdlet.ShouldProcess("GraphKit $version", 'Publish to the public PowerShell Gallery')) {
    Write-Host '  Cancelled.' -ForegroundColor DarkGray
    exit 0
}

$confirmation = Read-Host "  Type the version ($version) to confirm"
if ($confirmation -ne $version) {
    Write-Host '  Version did not match. Nothing was published.' -ForegroundColor Red
    exit 1
}

# Prompted, never a parameter: this keeps the key out of shell history and out of any
# transcript of this session.
$secureKey = Read-Host '  PSGallery API key' -AsSecureString
if ($secureKey.Length -eq 0) {
    Write-Host '  No key entered. Nothing was published.' -ForegroundColor Red
    exit 1
}

$plainKey = [System.Net.NetworkCredential]::new('', $secureKey).Password
try {
    Publish-PSResource -NupkgPath $PackagePath -Repository PSGallery -ApiKey $plainKey -ErrorAction Stop
    Write-Host ''
    Write-Host "  PUBLISHED: GraphKit $version" -ForegroundColor Green
    Write-Host '  https://www.powershellgallery.com/packages/GraphKit' -ForegroundColor Green
    Write-Host '  Indexing usually takes a few minutes before Install-PSResource can find it.' -ForegroundColor DarkGray
    Write-Host ''
}
finally {
    # Do not leave the key recoverable from this process.
    $plainKey = $null
    [System.GC]::Collect()
}
