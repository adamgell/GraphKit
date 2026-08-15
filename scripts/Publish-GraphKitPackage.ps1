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
        NUnit result file proving this build passed. Required unless -SkipTestProof is given,
        which exists only for a channel dry run and says so loudly.

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
if ($SkipTestProof) {
    Write-Warning 'PUBLISHING WITHOUT TEST PROOF. -SkipTestProof was given, so this package is NOT known to have passed its suite. Do not use this for a channel that anything installs from.'
}
else {
    if ([string]::IsNullOrWhiteSpace($TestResultPath)) {
        throw 'A -TestResultPath is required: the contract is to publish only the already-tested artifact. Pass the NUnit result for this build, or pass -SkipTestProof and accept that the package is unverified.'
    }
    if (-not (Test-Path -LiteralPath $TestResultPath -PathType Leaf)) {
        throw "Test result '$TestResultPath' does not exist."
    }

    $gate = Join-Path $repoRoot 'tests/QA/Assert-GateResult.ps1'
    & pwsh -NoProfile -File $gate -ResultPath $TestResultPath -MinimumTests 600 -AllowedSkips 0 | Write-Verbose
    if ($LASTEXITCODE -ne 0) {
        throw "The supplied test result did not pass the whole-result gate, so this package must not be published. Run: pwsh -File tests/QA/Assert-GateResult.ps1 -ResultPath '$TestResultPath' -MinimumTests 600"
    }

    # The result must belong to this version, or it proves nothing about these bits.
    [xml] $resultDoc = Get-Content -LiteralPath $TestResultPath -Raw
    $resultName = [string] $resultDoc.SelectSingleNode('/test-results').GetAttribute('name')
    if ($TestResultPath -notmatch [regex]::Escape($moduleVersion) -and $resultName -notmatch [regex]::Escape($moduleVersion)) {
        throw "Test result '$TestResultPath' does not reference version $moduleVersion. Publishing a package against another build's result would make the proof meaningless."
    }

    # Matching version numbers are not proof that these bytes are the tested bytes: the
    # 'pack' task begins with Clean, so a build/test/pack ordering silently rebuilds the
    # module after the suite ran and ships something no test ever saw. Compare the psm1
    # inside the package against the built module the tests actually imported. This turns
    # "publish only the already-tested artifact" from a procedural rule into a checked one.
    $builtPsm1 = Join-Path $repoRoot "output/module/GraphKit/$moduleVersion/GraphKit.psm1"
    if (-not (Test-Path -LiteralPath $builtPsm1 -PathType Leaf)) {
        throw "The built module at '$builtPsm1' is gone, so this package cannot be tied back to the tested bits. Run ./build.ps1 -Tasks pack FIRST and ./build.ps1 -Tasks test SECOND - test does not clean, pack does."
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($package.FullName)
    try {
        $entry = $archive.Entries | Where-Object { $_.FullName -eq 'GraphKit.psm1' } | Select-Object -First 1
        if ($null -eq $entry) { throw "Package '$($package.Name)' contains no GraphKit.psm1." }

        $stream = $entry.Open()
        try {
            $sha = [System.Security.Cryptography.SHA256]::Create()
            $packagedHash = [System.BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '')
        }
        finally { $stream.Dispose() }
    }
    finally { $archive.Dispose() }

    $testedHash = (Get-FileHash -LiteralPath $builtPsm1 -Algorithm SHA256).Hash
    if (-not [string]::Equals($packagedHash, $testedHash, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "The GraphKit.psm1 inside '$($package.Name)' ($packagedHash) is NOT the one the tests ran against ($testedHash). The module was rebuilt between testing and packaging, so this package is unverified. Run ./build.ps1 -Tasks pack, then ./build.ps1 -Tasks test, then publish."
    }
    Write-Verbose "Packaged GraphKit.psm1 matches the tested build ($testedHash)."
}

$hash = (Get-FileHash -LiteralPath $package.FullName -Algorithm SHA256).Hash

Write-Host ''
Write-Host "  package : $($package.Name) ($($package.Length) bytes)" -ForegroundColor Cyan
Write-Host "  version : $moduleVersion" -ForegroundColor Cyan
Write-Host "  sha256  : $hash" -ForegroundColor Cyan
Write-Host "  channel : $Channel -> $Destination" -ForegroundColor Cyan
Write-Host ''

# --- Publish ----------------------------------------------------------------------------
$publishedSource = $null

switch ($Channel) {
    'FileSystem' {
        $target = Join-Path $Destination $package.Name

        if ((Test-Path -LiteralPath $target -PathType Leaf) -and -not $Force) {
            $existingHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
            if ($existingHash -eq $hash) {
                Write-Host '  Already published with identical bytes; nothing to do.' -ForegroundColor Green
            }
            else {
                throw "Version $moduleVersion already exists in '$Destination' with DIFFERENT bytes (channel $existingHash vs local $hash). Replacing it would make every existing pin a lie. Publish a new version, or pass -Force if you are certain."
            }
        }
        elseif ($PSCmdlet.ShouldProcess($target, 'Publish package to file-system channel')) {
            if (-not (Test-Path -LiteralPath $Destination -PathType Container)) {
                $null = New-Item -ItemType Directory -Path $Destination -Force
            }
            Copy-Item -LiteralPath $package.FullName -Destination $target -Force
            Write-Host "  Published to $target" -ForegroundColor Green
        }

        $publishedSource = (Resolve-Path -LiteralPath $Destination).Path
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
        if ($PSCmdlet.ShouldProcess("$Destination release $tag", 'Upload package asset to GitHub release')) {
            $exists = (& gh release view $tag --repo $Destination --json tagName 2>$null)
            if ($LASTEXITCODE -ne 0) {
                & gh release create $tag --repo $Destination --title "GraphKit $moduleVersion" --notes "GraphKit $moduleVersion. sha256 $hash" --prerelease=false
                if ($LASTEXITCODE -ne 0) { throw "gh release create failed for $Destination $tag." }
            }
            elseif (-not $Force) {
                throw "Release $tag already exists in $Destination. Publish a new version rather than replacing one under an existing pin, or pass -Force."
            }

            & gh release upload $tag $package.FullName --repo $Destination --clobber:$Force
            if ($LASTEXITCODE -ne 0) { throw "gh release upload failed for $Destination $tag." }
            Write-Host "  Uploaded $($package.Name) to $Destination release $tag" -ForegroundColor Green
        }

        $publishedSource = "https://github.com/$Destination/releases/tag/$tag"
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
    testProof     = if ($SkipTestProof) { 'NONE - published without test proof' } else { (Resolve-Path -LiteralPath $TestResultPath).Path }
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
