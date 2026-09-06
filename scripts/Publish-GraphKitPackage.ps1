<#
    .SYNOPSIS
        Verifies a sealed GraphKit package and optionally publishes it to a versioned channel.

    .DESCRIPTION
        Report-only by default. The script never builds and has no proof bypass. It publishes only
        when -Publish is named and ShouldProcess authorizes the exact destination, and it operates
        only on a verifier-owned snapshot of the package.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string] $PackagePath,
    [Parameter(Mandatory)] [string] $ProofPath,
    [Parameter(Mandatory)] [ValidateSet('FileSystem', 'GitHubRelease')] [string] $Channel,
    [Parameter(Mandatory)] [string] $Destination,
    [switch] $Publish,
    [string] $PinPath,
    [switch] $Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$repoRoot = Split-Path $PSScriptRoot -Parent
$verifier = Join-Path $PSScriptRoot 'Test-GraphKitReleaseProof.ps1'
$snapshotRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("graphkit-publish-{0}" -f [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $snapshotRoot

try {
    $packageSnapshot = Join-Path $snapshotRoot (Split-Path $PackagePath -Leaf)
    $proofSnapshot = Join-Path $snapshotRoot 'tested-release-proof.json'
    $verified = & $verifier -PackagePath $PackagePath -ProofPath $ProofPath -RepositoryRoot $repoRoot `
        -PackageSnapshotPath $packageSnapshot -ProofSnapshotPath $proofSnapshot

    Write-Host ''
    Write-Host "  VERIFIED: GraphKit $($verified.Version)" -ForegroundColor Green
    Write-Host "  package : $([System.IO.Path]::GetFileName($verified.PackageSnapshotPath)) ($($verified.PackageSizeBytes) bytes)" -ForegroundColor Cyan
    Write-Host "  sha256  : $($verified.PackageSha256)" -ForegroundColor Cyan
    Write-Host "  tests   : $($verified.TestCount)" -ForegroundColor Cyan
    Write-Host "  files   : $($verified.ShippedFileCount)" -ForegroundColor Cyan
    Write-Host "  source  : $($verified.SourceRevision)" -ForegroundColor Cyan
    Write-Host "  channel : $Channel -> $Destination" -ForegroundColor Cyan
    Write-Host ''

    if (-not $Publish) {
        Write-Host '  Report-only verification complete. Nothing was published.' -ForegroundColor DarkGray
        return [pscustomobject]@{
            Version = $verified.Version; PackageSha256 = $verified.PackageSha256
            PackageSizeBytes = $verified.PackageSizeBytes; TestCount = $verified.TestCount
            ShippedFileCount = $verified.ShippedFileCount; SourceRevision = $verified.SourceRevision
            Published = $false; Channel = $Channel; Destination = $Destination; PinPath = $null
        }
    }

    $snapshot = Get-Item -LiteralPath $verified.PackageSnapshotPath
    $publishedSource = $null
    $published = $false

    switch ($Channel) {
        'FileSystem' {
            $target = Join-Path $Destination $snapshot.Name
            if (Test-Path -LiteralPath $target -PathType Leaf) {
                $existingHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
                if ($existingHash -ceq $verified.PackageSha256) {
                    Write-Host '  Already published with identical bytes; nothing to replace.' -ForegroundColor Green
                    $published = $true
                }
                elseif (-not $Force) {
                    throw "Version $($verified.Version) already exists in '$Destination' with DIFFERENT bytes. Publish a new version, or use -Force only for an explicitly authorized recovery."
                }
            }

            if (-not $published -and $PSCmdlet.ShouldProcess($target, 'Publish verified package to file-system channel')) {
                if (-not (Test-Path -LiteralPath $Destination -PathType Container)) {
                    $null = New-Item -ItemType Directory -Path $Destination -Force
                }
                Copy-Item -LiteralPath $verified.PackageSnapshotPath -Destination $target -Force
                $published = $true
            }
            $publishedSource = if (Test-Path -LiteralPath $Destination -PathType Container) {
                (Resolve-Path -LiteralPath $Destination).ProviderPath
            }
        }

        'GitHubRelease' {
            if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw 'The gh CLI is required for GitHubRelease.' }
            if ($Destination -notmatch '^[^/]+/[^/]+$') { throw "GitHubRelease destination must be owner/repo; got '$Destination'." }
            $tag = "v$($verified.Version)"
            if ($PSCmdlet.ShouldProcess("$Destination release $tag", 'Upload verified package to GitHub release')) {
                & gh release view $tag --repo $Destination --json tagName *> $null
                if ($LASTEXITCODE -ne 0) {
                    & gh release create $tag --repo $Destination --title "GraphKit $($verified.Version)" `
                        --notes "GraphKit $($verified.Version). sha256 $($verified.PackageSha256)" --prerelease=false
                    if ($LASTEXITCODE -ne 0) { throw "gh release create failed for $Destination $tag." }
                }
                elseif (-not $Force) { throw "Release $tag already exists in $Destination." }

                & gh release upload $tag $verified.PackageSnapshotPath --repo $Destination --clobber:$Force
                if ($LASTEXITCODE -ne 0) { throw "gh release upload failed for $Destination $tag." }
                $published = $true
            }
            $publishedSource = "https://github.com/$Destination/releases/tag/$tag"
        }
    }

    if (-not $published) {
        Write-Host '  Nothing was published because ShouldProcess did not authorize the operation.' -ForegroundColor DarkGray
        return [pscustomobject]@{
            Version = $verified.Version; PackageSha256 = $verified.PackageSha256
            PackageSizeBytes = $verified.PackageSizeBytes; TestCount = $verified.TestCount
            ShippedFileCount = $verified.ShippedFileCount; SourceRevision = $verified.SourceRevision
            Published = $false; Channel = $Channel; Destination = $Destination; PinPath = $null
        }
    }

    if ([string]::IsNullOrWhiteSpace($PinPath)) {
        $PinPath = if ($Channel -eq 'FileSystem') { Join-Path $Destination 'graphkit.pin.json' } else { Join-Path $repoRoot 'graphkit.pin.json' }
    }
    $pin = [ordered]@{
        schema = 'graphkit-pin/2'; moduleName = 'GraphKit'; version = $verified.Version
        sha256 = $verified.PackageSha256; sizeBytes = $verified.PackageSizeBytes
        channel = $Channel; source = $publishedSource; packageName = $snapshot.Name
        sourceRevision = $verified.SourceRevision; testCount = $verified.TestCount
        releaseProofSha256 = (Get-FileHash -LiteralPath $verified.ProofSnapshotPath -Algorithm SHA256).Hash.ToLowerInvariant()
        publishedUtc = [datetime]::UtcNow.ToString('o')
    }
    if ($PSCmdlet.ShouldProcess($PinPath, 'Write verified package pin record')) {
        $pinDirectory = Split-Path -Parent $PinPath
        if (-not [string]::IsNullOrWhiteSpace($pinDirectory) -and -not (Test-Path -LiteralPath $pinDirectory -PathType Container)) {
            $null = New-Item -ItemType Directory -Path $pinDirectory -Force
        }
        $pin | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $PinPath -Encoding utf8
    }

    [pscustomobject]@{
        Version = $verified.Version; PackageSha256 = $verified.PackageSha256
        PackageSizeBytes = $verified.PackageSizeBytes; TestCount = $verified.TestCount
        ShippedFileCount = $verified.ShippedFileCount; SourceRevision = $verified.SourceRevision
        Published = $true; Channel = $Channel; Destination = $Destination; PinPath = $PinPath
    }
}
finally {
    if (Test-Path -LiteralPath $snapshotRoot) { Remove-Item -LiteralPath $snapshotRoot -Recurse -Force }
}
