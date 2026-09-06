<#
    .SYNOPSIS
        Verifies a sealed GraphKit package and optionally publishes it to PSGallery.

    .DESCRIPTION
        Report-only by default. Publication requires the named -Publish switch, normal
        ShouldProcess authorization, and a securely entered API key. The published input is a
        verifier-owned snapshot, never the caller-owned path.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $PackagePath,
    [Parameter(Mandatory)] [string] $ProofPath,
    [switch] $Publish
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0
$repoRoot = Split-Path $PSScriptRoot -Parent
$manifest = Import-PowerShellDataFile (Join-Path $repoRoot 'source/GraphKit.psd1')
$version = [string] $manifest.ModuleVersion
if ([string]::IsNullOrWhiteSpace($PackagePath)) { $PackagePath = Join-Path $repoRoot "output/GraphKit.$version.nupkg" }

$snapshotRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("graphkit-gallery-{0}" -f [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $snapshotRoot
try {
    $verifier = Join-Path $PSScriptRoot 'Test-GraphKitReleaseProof.ps1'
    $verified = & $verifier -PackagePath $PackagePath -ProofPath $ProofPath -RepositoryRoot $repoRoot `
        -PackageSnapshotPath (Join-Path $snapshotRoot (Split-Path $PackagePath -Leaf)) `
        -ProofSnapshotPath (Join-Path $snapshotRoot 'tested-release-proof.json')

    if ($verified.Version -cne $version) { throw "Verified package version '$($verified.Version)' does not match source manifest '$version'." }
    $builtManifestPath = Join-Path $repoRoot "output/module/GraphKit/$version/GraphKit.psd1"
    $null = Test-ModuleManifest -Path $builtManifestPath -ErrorAction Stop
    $psData = $manifest.PrivateData.PSData
    foreach ($required in @('Author', 'Description')) {
        if ([string]::IsNullOrWhiteSpace([string] $manifest[$required])) { throw "Manifest $required is required for PSGallery." }
    }
    if (@($psData.Tags).Count -eq 0 -or [string]::IsNullOrWhiteSpace([string] $psData.LicenseUri) -or
        [string]::IsNullOrWhiteSpace([string] $psData.ReleaseNotes)) {
        throw 'Manifest Tags, LicenseUri, and ReleaseNotes are required for PSGallery.'
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $findings = [System.Collections.Generic.List[string]]::new()
    $patterns = @{
        'GUID that is not a well-known Microsoft id' = '\b(?!00000000-0000-0000-0000-00000000000[01]\b)(?!00000003-0000-0000-c000-000000000000\b)(?!' + [regex]::Escape($manifest.GUID) + '\b)[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
        'certificate thumbprint' = '\b[0-9A-Fa-f]{40}\b'
        'local user path' = '/Users/[A-Za-z0-9._-]+|C:\\Users\\[A-Za-z0-9._-]+'
        'internal project name' = '(?i)\bivy24\b|\bIntuneHealthAutomation\b'
    }
    $secretTokenHashes = @{
        '5cad5cdbf022740cbfc976f9836ac89d' = 'customer name (A)'
        'e03427b1afcd1e84a97ed1f2241466cb' = 'internal workspace tenant'
        '9a08498936078c81ec926fedbce5e7c9' = 'customer name (A, short form)'
        '6ca05670c4afd49e806f7cddbab83b00' = 'lab tenant id'
    }
    function Get-TokenDigest {
        param([string] $Token)
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Token.ToLowerInvariant())
        return [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant().Substring(0, 32)
    }

    $archive = [System.IO.Compression.ZipFile]::OpenRead($verified.PackageSnapshotPath)
    try {
        foreach ($entry in $archive.Entries) {
            if ($entry.FullName -notmatch '\.(psm1|psd1|ps1|ps1xml|txt|nuspec|xml|md)$') { continue }
            $reader = [System.IO.StreamReader]::new($entry.Open())
            try { $content = $reader.ReadToEnd() } finally { $reader.Dispose() }
            foreach ($token in [regex]::Matches($content, '[A-Za-z0-9][A-Za-z0-9-]{3,}')) {
                $digest = Get-TokenDigest -Token $token.Value
                if ($secretTokenHashes.ContainsKey($digest)) { $findings.Add("$($entry.FullName): $($secretTokenHashes[$digest])") }
            }
            foreach ($label in $patterns.Keys) {
                foreach ($match in [regex]::Matches($content, $patterns[$label])) {
                    if ($label -like 'GUID*') {
                        $segments = @($match.Value -split '-')
                        if (@($segments | Where-Object { @($_.ToCharArray() | Select-Object -Unique).Count -gt 1 }).Count -eq 0) { continue }
                    }
                    $findings.Add("$label in $($entry.FullName)")
                }
            }
        }
    }
    finally { $archive.Dispose() }
    if ($findings.Count -gt 0) { throw "Package privacy scan failed with $($findings.Count) finding(s): $($findings -join '; ')." }

    Write-Host ''
    Write-Host "  VERIFIED: GraphKit $version" -ForegroundColor Green
    Write-Host "  package : $([System.IO.Path]::GetFileName($verified.PackageSnapshotPath)) ($($verified.PackageSizeBytes) bytes)" -ForegroundColor Cyan
    Write-Host "  sha256  : $($verified.PackageSha256)" -ForegroundColor Cyan
    Write-Host "  tests   : $($verified.TestCount)" -ForegroundColor Cyan
    Write-Host "  files   : $($verified.ShippedFileCount)" -ForegroundColor Cyan
    Write-Host "  source  : $($verified.SourceRevision)" -ForegroundColor Cyan
    Write-Host ''

    if (-not $Publish) {
        Write-Host '  Report-only verification complete. Nothing was published.' -ForegroundColor DarkGray
        return $verified
    }

    $existing = Find-PSResource -Name GraphKit -Repository PSGallery -ErrorAction SilentlyContinue
    $versions = @($existing | ForEach-Object { $_.Version.ToString() })
    if ($version -in $versions) { throw "GraphKit $version is already published to PSGallery." }

    if (-not $PSCmdlet.ShouldProcess("GraphKit $version", 'Publish verified package to the public PowerShell Gallery')) {
        Write-Host '  Nothing was published because ShouldProcess did not authorize the operation.' -ForegroundColor DarkGray
        return $verified
    }

    $secureKey = Read-Host 'PSGallery API key' -AsSecureString
    if ($secureKey.Length -eq 0) { throw 'No PSGallery API key was entered. Nothing was published.' }
    $plainKey = [System.Net.NetworkCredential]::new('', $secureKey).Password
    try {
        Publish-PSResource -NupkgPath $verified.PackageSnapshotPath -Repository PSGallery -ApiKey $plainKey -ErrorAction Stop
    }
    finally {
        $plainKey = $null
        [System.GC]::Collect()
    }
    Write-Host "  PUBLISHED: GraphKit $version" -ForegroundColor Green
    $verified
}
finally {
    if (Test-Path -LiteralPath $snapshotRoot) { Remove-Item -LiteralPath $snapshotRoot -Recurse -Force }
}
