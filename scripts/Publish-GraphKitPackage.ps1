<#
    .SYNOPSIS
        Publishes an already-built, already-tested GraphKit package to a private versioned
        channel and writes the pin record that consumers install against.

    .DESCRIPTION
        Phase 5 step 3 of the cutover. Three rules from the design are enforced here rather
        than left to operator discipline:

        **Publish only the already-tested artifact.** This script never builds. It takes a
        .nupkg that already exists and refuses to run unless a passing test result is
        presented for the same version. Rebuilding in the publish step would ship bits that
        nothing tested, and the difference is invisible afterwards.

        **The channel must exist before anything depends on it.** Publishing writes a pin
        record - name, version, sha256, channel, source - which is the artifact consumers
        install against. An install that cannot name the exact bytes it expects is not a pin.

        **Versioned and immutable.** Re-publishing a version that already exists in the
        channel is refused unless -Force is given, because silently replacing a version
        under a pin makes the pin a lie.

        Two channels are implemented:

        - FileSystem: a directory acting as a PSResourceGet repository. Works today with no
          external account, and is what the machinery is proven against.
        - GitHubRelease: uploads the .nupkg as an asset on a release of a private GitHub
          repository. Requires the gh CLI, authenticated, with the repository already
          created. This performs an outward publication and is therefore never run without
          an explicit -Confirm decision.

    .PARAMETER PackagePath
        Path to the already-built .nupkg.

    .PARAMETER Channel
        FileSystem or GitHubRelease.

    .PARAMETER Destination
        For FileSystem, the repository directory. For GitHubRelease, owner/repo.

    .PARAMETER TestResultPath
        NUnit result file bound by the canonical tested-release proof. Required unless
        -SkipTestProof is given together with -WhatIf for a read-only channel dry run.

    .PARAMETER ProofPath
        Canonical tested-release proof. Defaults to
        output/testResults/tested-release-proof.json.

    .PARAMETER PinPath
        Where to write the pin record. Defaults to ./output/graphkit.pin.json.

    .EXAMPLE
        ./scripts/Publish-GraphKitPackage.ps1 -PackagePath output/GraphKit.0.0.1.nupkg `
            -Channel FileSystem -Destination ~/graphkit-channel `
            -TestResultPath output/testResults/NUnitXml_GraphKit_v0.0.1.MacOS.PSv.7.6.5.xml
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string] $PackagePath,

    [Parameter(Mandatory)]
    [ValidateSet('FileSystem', 'GitHubRelease')]
    [string] $Channel,

    [Parameter(Mandatory)]
    [string] $Destination,

    [string] $TestResultPath,

    [string] $ProofPath,

    [switch] $SkipTestProof,

    [string] $PinPath,

    [switch] $Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$repoRoot = Split-Path $PSScriptRoot -Parent

if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) {
    throw "Package '$PackagePath' does not exist. Build it first with ./build.ps1 -Tasks pack; this script deliberately does not build, so that what ships is what was tested."
}

$package = Get-Item -LiteralPath $PackagePath
if ($package.Extension -ne '.nupkg') {
    throw "Package '$PackagePath' is not a .nupkg."
}

# Version comes from the file name, which is what the channel will key on.
if ($package.BaseName -notmatch '^(?<name>.+?)\.(?<version>\d+\.\d+\.\d+(?:-[A-Za-z0-9.\-]+)?)$') {
    throw "Cannot parse a module name and version from '$($package.Name)'. Expected <Name>.<Version>.nupkg."
}
$moduleName = $Matches['name']
$moduleVersion = $Matches['version']

if ($moduleName -ne 'GraphKit') {
    throw "Package '$($package.Name)' is '$moduleName', not GraphKit."
}

# --- Proof that these exact bits passed their tests -------------------------------------
$verifiedSnapshotDirectory = $null
try {
if ($SkipTestProof) {
    if (-not $WhatIfPreference) {
        throw '-SkipTestProof is only allowed with -WhatIf. A real private-channel publication always requires the canonical tested-release proof.'
    }
    Write-Warning 'DRY RUN WITHOUT TEST PROOF. -SkipTestProof is accepted only because -WhatIf prevents package, proof, and pin writes.'
    $verifiedRelease = $null
    $verifiedProofSnapshot = $null
}
else {
    if ([string]::IsNullOrWhiteSpace($TestResultPath)) {
        throw 'A -TestResultPath is required: the contract is to publish only the already-tested artifact. Pass the NUnit result for this build, or pass -SkipTestProof and accept that the package is unverified.'
    }
    if (-not (Test-Path -LiteralPath $TestResultPath -PathType Leaf)) {
        throw "Test result '$TestResultPath' does not exist."
    }

    # One verifier owns the release definition for both private-channel and PSGallery
    # publication. It binds the exact package archive and result pair to every shipped
    # module file; this publisher deliberately carries no second, weaker proof path.
    $releaseProofPath = if ([string]::IsNullOrWhiteSpace($ProofPath)) {
        Join-Path $repoRoot 'output/testResults/tested-release-proof.json'
    }
    else {
        $ProofPath
    }
    $verifier = Join-Path $repoRoot 'scripts/Test-GraphKitReleaseProof.ps1'
    $verifiedSnapshotDirectory = [System.IO.Directory]::CreateTempSubdirectory('graphkit-verified-release-').FullName
    $verifiedPackageCopyPath = Join-Path $verifiedSnapshotDirectory $package.Name
    $verifiedProofCopyPath = Join-Path $verifiedSnapshotDirectory 'tested-release-proof.json'
    try {
        $verifiedRelease = & $verifier `
            -PackagePath $package.FullName `
            -ProofPath $releaseProofPath `
            -TestResultPath $TestResultPath `
            -RepositoryRoot $repoRoot `
            -VerifiedPackageCopyPath $verifiedPackageCopyPath `
            -VerifiedProofCopyPath $verifiedProofCopyPath
    }
    catch {
        Remove-Item -LiteralPath $verifiedSnapshotDirectory -Recurse -Force -ErrorAction SilentlyContinue
        $verifiedSnapshotDirectory = $null
        throw
    }
    $package = Get-Item -LiteralPath $verifiedRelease.VerifiedPackagePath
    $verifiedProofSnapshot = Get-Item -LiteralPath $verifiedRelease.VerifiedProofPath
    Write-Verbose "Canonical tested-release proof accepted $($verifiedRelease.ShippedFileCount) shipped file(s)."
}

$hash = (Get-FileHash -LiteralPath $package.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
if (-not $SkipTestProof -and $hash -cne $verifiedRelease.PackageSha256) {
    throw 'The verifier-owned package snapshot changed before publication.'
}
$proofAssetName = if ($SkipTestProof) {
    $null
}
else {
    "GraphKit.$moduleVersion.tested-release.$($verifiedRelease.ProofSha256).json"
}
if (-not $SkipTestProof) {
    $contentAddressedProofPath = Join-Path $verifiedSnapshotDirectory $proofAssetName
    Move-Item -LiteralPath $verifiedProofSnapshot.FullName -Destination $contentAddressedProofPath
    $verifiedProofSnapshot = Get-Item -LiteralPath $contentAddressedProofPath
}

Write-Host ''
Write-Host "  package : $($package.Name) ($($package.Length) bytes)" -ForegroundColor Cyan
Write-Host "  version : $moduleVersion" -ForegroundColor Cyan
Write-Host "  sha256  : $hash" -ForegroundColor Cyan
Write-Host "  channel : $Channel -> $Destination" -ForegroundColor Cyan
Write-Host ''

# --- Publish ----------------------------------------------------------------------------
$publishedSource = $null
$publishedProofSource = if ($SkipTestProof) { 'NONE - WhatIf-only unverified dry run' } else { $null }

switch ($Channel) {
    'FileSystem' {
        $target = Join-Path $Destination $package.Name
        $proofTarget = if ($SkipTestProof) { $null } else { Join-Path $Destination $proofAssetName }
        $packageAlreadyPublished = $false

        if (Test-Path -LiteralPath $target -PathType Leaf) {
            $existingHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($existingHash -ceq $hash) {
                $packageAlreadyPublished = $true
            }
            elseif (-not $Force) {
                throw "Version $moduleVersion already exists in '$Destination' with DIFFERENT bytes (channel $existingHash vs local $hash). Replacing it would make every existing pin a lie. Publish a new version, or pass -Force if you are certain."
            }
        }

        if (-not $SkipTestProof) {
            if (Test-Path -LiteralPath $proofTarget -PathType Leaf) {
                $existingProofHash = (Get-FileHash -LiteralPath $proofTarget -Algorithm SHA256).Hash.ToLowerInvariant()
                if ($existingProofHash -cne $verifiedRelease.ProofSha256) {
                    throw "Content-addressed proof '$proofTarget' exists with different bytes; refusing to replace it."
                }
                Write-Host '  Tested-release proof already exists with identical bytes; nothing to do.' -ForegroundColor Green
            }
            elseif ($PSCmdlet.ShouldProcess($proofTarget, 'Publish immutable tested-release proof')) {
                if (-not (Test-Path -LiteralPath $Destination -PathType Container)) {
                    $null = New-Item -ItemType Directory -Path $Destination -Force
                }
                Copy-Item -LiteralPath $verifiedProofSnapshot.FullName -Destination $proofTarget
                $publishedProofHash = (Get-FileHash -LiteralPath $proofTarget -Algorithm SHA256).Hash.ToLowerInvariant()
                if ($publishedProofHash -cne $verifiedRelease.ProofSha256) {
                    Remove-Item -LiteralPath $proofTarget -Force -ErrorAction SilentlyContinue
                    throw "Published tested-release proof '$proofTarget' failed its content hash check."
                }
                Write-Host "  Published tested-release proof to $proofTarget" -ForegroundColor Green
            }
            $publishedProofSource = [System.IO.Path]::GetFullPath($proofTarget)

            if (-not $WhatIfPreference -and -not (Test-Path -LiteralPath $proofTarget -PathType Leaf)) {
                throw 'The tested-release proof was not published; refusing to make the package discoverable.'
            }
        }

        if ($packageAlreadyPublished) {
            Write-Host '  Already published with identical bytes; nothing to do.' -ForegroundColor Green
        }
        elseif ($PSCmdlet.ShouldProcess($target, 'Publish package to file-system channel')) {
            if (-not (Test-Path -LiteralPath $Destination -PathType Container)) {
                $null = New-Item -ItemType Directory -Path $Destination -Force
            }
            Copy-Item -LiteralPath $package.FullName -Destination $target -Force
            $publishedPackageHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($publishedPackageHash -cne $hash) {
                Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue
                throw "Published package '$target' failed its content hash check."
            }
            Write-Host "  Published to $target" -ForegroundColor Green
        }

        $publishedSource = [System.IO.Path]::GetFullPath($Destination)
    }

    'GitHubRelease' {
        if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
            throw 'The gh CLI is required for the GitHubRelease channel and was not found on PATH.'
        }
        if ($Destination -notmatch '^[^/]+/[^/]+$') {
            throw "For -Channel GitHubRelease, -Destination must be owner/repo; got '$Destination'."
        }

        $tag = "v$moduleVersion"

        # This is an outward publication: it sends the package to GitHub. It only happens
        # under an explicit ShouldProcess decision, never as a side effect.
        if ($PSCmdlet.ShouldProcess("$Destination release $tag", 'Upload proof and package assets to GitHub release')) {
            $exists = (& gh release view $tag --repo $Destination --json tagName 2>$null)
            if ($LASTEXITCODE -ne 0) {
                & gh release create $tag --repo $Destination --title "GraphKit $moduleVersion" --notes "GraphKit $moduleVersion. sha256 $hash" --prerelease=false
                if ($LASTEXITCODE -ne 0) { throw "gh release create failed for $Destination $tag." }
            }
            elseif (-not $Force) {
                throw "Release $tag already exists in $Destination. Publish a new version rather than replacing one under an existing pin, or pass -Force."
            }

            $proofUploadArguments = @(
                'release', 'upload', $tag,
                $verifiedProofSnapshot.FullName,
                '--repo', $Destination
            )
            if ($Force) { $proofUploadArguments += '--clobber' }
            & gh @proofUploadArguments
            if ($LASTEXITCODE -ne 0) { throw "gh tested-release proof upload failed for $Destination $tag." }

            $packageUploadArguments = @(
                'release', 'upload', $tag,
                $package.FullName,
                '--repo', $Destination
            )
            if ($Force) { $packageUploadArguments += '--clobber' }
            & gh @packageUploadArguments
            if ($LASTEXITCODE -ne 0) { throw "gh package upload failed for $Destination $tag." }
            Write-Host "  Uploaded $($package.Name) and $proofAssetName to $Destination release $tag" -ForegroundColor Green
        }

        $publishedSource = "https://github.com/$Destination/releases/tag/$tag"
        $publishedProofSource = "https://github.com/$Destination/releases/download/$tag/$proofAssetName"
    }
}

# --- Pin record -------------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($PinPath)) {
    # NOT output/: the 'pack' task begins with Clean, so a pin written there is deleted by
    # the next build - and the pin is the contract a consumer installs against, so losing it
    # silently breaks every downstream host. For a file-system channel the pin belongs beside
    # the package it describes, which also means it travels with the channel automatically.
    $PinPath = if ($Channel -eq 'FileSystem') {
        Join-Path $Destination 'graphkit.pin.json'
    }
    else {
        Join-Path $repoRoot 'graphkit.pin.json'
    }
}

$pin = [ordered]@{
    schema        = 'graphkit-pin/1'
    moduleName    = $moduleName
    version       = $moduleVersion
    sha256        = $hash
    sizeBytes     = $package.Length
    channel       = $Channel
    source        = $publishedSource
    packageName   = $package.Name
    testProof     = $publishedProofSource
    testProofSha256 = if ($SkipTestProof) { $null } else { $verifiedRelease.ProofSha256 }
    testProofRunId = if ($SkipTestProof) { $null } else { $verifiedRelease.RunId }
    publishedUtc  = [datetime]::UtcNow.ToString('o')
}

if ($PSCmdlet.ShouldProcess($PinPath, 'Write pin record')) {
    $pinDir = Split-Path -Parent $PinPath
    if (-not [string]::IsNullOrEmpty($pinDir) -and -not (Test-Path -LiteralPath $pinDir -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $pinDir -Force
    }
    ($pin | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $PinPath -Encoding utf8
    Write-Host "  Pin record written to $PinPath" -ForegroundColor Green
}

Write-Host ''
[pscustomobject] $pin
}
finally {
    if (-not [string]::IsNullOrWhiteSpace($verifiedSnapshotDirectory)) {
        Remove-Item -LiteralPath $verifiedSnapshotDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}
