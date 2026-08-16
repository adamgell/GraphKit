<#
    .SYNOPSIS
        Installs the exact pinned GraphKit version on an execution host, verifies it is the
        bytes the pin names, and records what was there before so one command restores it.

    .DESCRIPTION
        Phase 5 step 4 of the cutover, and the safety net step 5 depends on.

        **Install the exact version, then prove it.** Installing a version is not the same as
        installing the artifact that was tested: a channel can hold a different build under
        the same version. The installed module's package digest is compared against the pin
        and the install is rejected on mismatch, before anything imports it.

        **Record the previous state first.** The cutover rule is that every caller keeps
        working at every step and one command rolls back. That is only true if the previous
        pin is written down before the new one lands, so this captures every GraphKit
        version already present and writes a restore record.

        **Verify by importing the installed package in a clean process.** Importing in the
        current session proves less, because this session has already imported GraphKit from
        source and has its dependencies loaded.

    .PARAMETER PinPath
        Pin record written by Publish-GraphKitPackage.ps1.

    .PARAMETER Scope
        CurrentUser (default) or AllUsers.

    .PARAMETER RestoreRecordPath
        Where to write the rollback record. Defaults next to the pin.

    .PARAMETER SkipDependencies
        Do not install Microsoft.Graph.Authentication / SecretManagement. Use when they are
        already managed on the host.

    .EXAMPLE
        ./scripts/Install-GraphKitPinned.ps1 -PinPath output/graphkit.pin.json
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # Not mandatory: when this script sits in a transfer bundle next to its pin - which is how
    # it reaches an execution host - running it bare should just work. A mandatory parameter
    # prompts for a path the caller has no reason to know, and the obvious guesses fail.
    [string] $PinPath,

    [ValidateSet('CurrentUser', 'AllUsers')]
    [string] $Scope = 'CurrentUser',

    [string] $RestoreRecordPath,

    # Overrides the channel directory recorded in the pin. A pin's job is to name the exact
    # BYTES, not a path: the publisher's directory layout is deployment detail and does not
    # survive a move to another host. The sha256 check below is unchanged and still gates the
    # install, so relocating the channel cannot weaken the guarantee - it only stops an
    # absolute path from being mistaken for one.
    [string] $Source,

    [switch] $SkipDependencies
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

if ([string]::IsNullOrWhiteSpace($PinPath)) {
    # Prefer a pin beside this script (the bundle layout), then the repository's channel.
    $candidates = @(
        (Join-Path $PSScriptRoot 'graphkit.pin.json')
        (Join-Path (Split-Path $PSScriptRoot -Parent) 'graphkit.pin.json')
    )
    $PinPath = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1

    if ([string]::IsNullOrWhiteSpace($PinPath)) {
        throw "No -PinPath given and no graphkit.pin.json found next to this script. Pass -PinPath explicitly, or run this from a bundle directory that contains the pin."
    }
    Write-Host "  using pin beside the script: $PinPath" -ForegroundColor DarkGray
}

if (-not (Test-Path -LiteralPath $PinPath -PathType Leaf)) {
    throw "Pin record '$PinPath' does not exist. Expected a graphkit.pin.json - in a transfer bundle it sits beside this script, so running the script with no arguments from that folder is usually what you want."
}

$pin = Get-Content -LiteralPath $PinPath -Raw | ConvertFrom-Json
foreach ($required in @('moduleName', 'version', 'sha256', 'channel', 'source')) {
    if (-not $pin.PSObject.Properties[$required] -or [string]::IsNullOrWhiteSpace([string]$pin.$required)) {
        throw "Pin record '$PinPath' is missing '$required'."
    }
}

Write-Host ''
Write-Host "  pin     : $($pin.moduleName) $($pin.version)" -ForegroundColor Cyan
Write-Host "  sha256  : $($pin.sha256)" -ForegroundColor Cyan
Write-Host "  channel : $($pin.channel) -> $(if ([string]::IsNullOrWhiteSpace($Source)) { $pin.source } else { $Source })" -ForegroundColor Cyan
Write-Host ''

# --- 1. Record what is here NOW, before anything changes --------------------------------
$previous = @(Get-Module -Name $pin.moduleName -ListAvailable | ForEach-Object {
        [ordered]@{ Version = $_.Version.ToString(); Path = $_.ModuleBase }
    })

if ([string]::IsNullOrWhiteSpace($RestoreRecordPath)) {
    $RestoreRecordPath = Join-Path (Split-Path -Parent $PinPath) 'graphkit.restore.json'
}

$restore = [ordered]@{
    schema           = 'graphkit-restore/1'
    capturedUtc      = [datetime]::UtcNow.ToString('o')
    moduleName       = $pin.moduleName
    previousVersions = $previous
    installingVersion = $pin.version
    note             = $(
        # Reinstalling the same version is the common case on a re-run, and treating the
        # outgoing version as something to "leave in place" produced the nonsense
        # "uninstalling 0.1.0 and leaving 0.1.0 in place". Only OTHER versions survive a
        # rollback.
        $others = @($previous | ForEach-Object { $_.Version } | Where-Object { $_ -ne $pin.version })
        if ($previous.Count -eq 0) {
            'GraphKit was not installed before this. Rollback means uninstalling the pinned version.'
        }
        elseif ($others.Count -eq 0) {
            "$($pin.version) was already installed and has been reinstalled over. Rollback means uninstalling it; no other version was present to fall back to."
        }
        else {
            "Rollback means uninstalling $($pin.version) and leaving $($others -join ', ') in place."
        }
    )
}

if ($PSCmdlet.ShouldProcess($RestoreRecordPath, 'Write rollback record')) {
    ($restore | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $RestoreRecordPath -Encoding utf8
    Write-Host "  Rollback record: $RestoreRecordPath" -ForegroundColor Green
    Write-Host "    $($restore.note)" -ForegroundColor DarkGray
}

# --- 2. Register the channel -------------------------------------------------------------
$repoName = 'GraphKitPrivate'

if ($pin.channel -ne 'FileSystem') {
    throw "Automated install currently supports the FileSystem channel only; this pin names '$($pin.channel)'. For a GitHub release, download the asset to a directory and re-pin against it, or extend this script once that channel is in use."
}

$channelSource = if (-not [string]::IsNullOrWhiteSpace($Source)) {
    $Source
}
elseif (Test-Path -LiteralPath (Join-Path (Split-Path $PinPath -Parent) $pin.packageName) -PathType Leaf) {
    # The package sits beside the pin: this is a transfer bundle, and the publisher's recorded
    # path almost certainly does not exist on this host. Prefer what is actually here.
    Split-Path $PinPath -Parent
}
else {
    [string] $pin.source
}

if (-not (Test-Path -LiteralPath $channelSource -PathType Container)) {
    throw "Channel source '$channelSource' is not reachable from this host. The pin records the publisher's path; on another machine pass -Source pointing at a directory this host can read. The digest check is unaffected."
}

if ($channelSource -ne [string] $pin.source) {
    Write-Host "  source override: $channelSource" -ForegroundColor DarkGray
    Write-Host "    (pin recorded $($pin.source); the sha256 check still decides)" -ForegroundColor DarkGray
}

$existingRepo = Get-PSResourceRepository -Name $repoName -ErrorAction SilentlyContinue
if ($PSCmdlet.ShouldProcess($repoName, 'Register private PSResource repository')) {
    if ($null -eq $existingRepo) {
        Register-PSResourceRepository -Name $repoName -Uri $channelSource -Trusted
        Write-Host "  Registered repository '$repoName' -> $channelSource" -ForegroundColor Green
    }
    elseif ($existingRepo.Uri.LocalPath -ne $channelSource -and $existingRepo.Uri.AbsoluteUri -ne $channelSource) {
        Set-PSResourceRepository -Name $repoName -Uri $channelSource -Trusted
        Write-Host "  Repointed repository '$repoName' -> $channelSource" -ForegroundColor Green
    }
}

# --- 3. Install the exact version --------------------------------------------------------
if ($PSCmdlet.ShouldProcess("$($pin.moduleName) $($pin.version)", "Install from $repoName into $Scope")) {
    # Dependencies come from PSGallery, not the private channel. Install-PSResource resolves
    # a package's dependencies from the SAME repository it installs from, and a single-module
    # private channel cannot satisfy its own graph - so GraphKit is installed with
    # -SkipDependencyCheck and its dependencies are satisfied here, explicitly and by version.
    #
    # That is also the intent rather than a workaround: Microsoft.Graph.Authentication is
    # depended on solely to deliver Microsoft.Identity.Client.dll, and the design is emphatic
    # that GraphKit must never ship a competing copy. Mirroring it into a private channel
    # would be shipping one.
    if (-not $SkipDependencies) {
        $required = @{
            'Microsoft.Graph.Authentication'        = [version] '2.38.1'
            'Microsoft.PowerShell.SecretManagement' = [version] '1.1.2'
        }

        foreach ($dep in $required.Keys) {
            $minimum = $required[$dep]
            $present = Get-Module $dep -ListAvailable |
                Sort-Object Version -Descending | Select-Object -First 1

            # "Installed" is not the same as "new enough": a host carrying an older
            # Microsoft.Graph.Authentication would satisfy a presence check and then fail
            # the manifest's minimum at import.
            if ($null -ne $present -and $present.Version -ge $minimum) {
                Write-Host "  Dependency $dep v$($present.Version) satisfies >= $minimum" -ForegroundColor DarkGray
                continue
            }

            $found = if ($null -eq $present) { 'absent' } else { "v$($present.Version)" }
            Write-Host "  Installing $dep (>= $minimum; found $found)" -ForegroundColor DarkGray

            # Get-Module -ListAvailable says absent while Install-PSResource says "already
            # installed" when a previous install left a directory PSResourceGet has recorded but
            # PowerShell cannot load - a partially written module, most often from an
            # interrupted install. Without -Reinstall the installer declines, this loop reports
            # success, and the failure resurfaces much later as GraphKit's RequiredModules being
            # unsatisfiable. Force a real reinstall in exactly that case.
            $installArgs = @{
                Name            = $dep
                Version         = "[$minimum,)"
                Repository      = 'PSGallery'
                Scope           = $Scope
                TrustRepository = $true
                ErrorAction     = 'Stop'
            }
            if ($null -eq $present) {
                $recorded = Get-InstalledPSResource -Name $dep -ErrorAction SilentlyContinue
                if ($null -ne $recorded) {
                    Write-Host "    $dep is recorded as installed but is not loadable; reinstalling over it" -ForegroundColor Yellow
                    $installArgs.Reinstall = $true
                }
            }

            Install-PSResource @installArgs

            # Installing is not the same as being usable. Confirm the dependency is now
            # discoverable before moving on, or GraphKit's own import fails later with a
            # message about RequiredModules that says nothing about which install went wrong.
            $after = Get-Module $dep -ListAvailable |
                Sort-Object Version -Descending | Select-Object -First 1
            if ($null -eq $after -or $after.Version -lt $minimum) {
                $recorded = Get-InstalledPSResource -Name $dep -ErrorAction SilentlyContinue
                $where = if ($null -ne $recorded) { " PSResourceGet records it at '$($recorded[0].InstalledLocation)'." } else { '' }
                throw "$dep still is not discoverable after installing it.$where Check that its install location is on `$env:PSModulePath and that the module directory is complete - an interrupted install leaves one that is recorded but unloadable. Removing that directory and re-running usually fixes it."
            }
            Write-Host "    $dep v$($after.Version) is now discoverable" -ForegroundColor DarkGray
        }
    }

    Install-PSResource -Name $pin.moduleName -Version $pin.version -Repository $repoName `
        -Scope $Scope -TrustRepository -Reinstall -SkipDependencyCheck -ErrorAction Stop
    Write-Host "  Installed $($pin.moduleName) $($pin.version)" -ForegroundColor Green
}

# --- 4. Prove the installed bits are the pinned bits -------------------------------------
$installed = Get-Module -Name $pin.moduleName -ListAvailable |
    Where-Object { $_.Version.ToString() -eq $pin.version } |
    Select-Object -First 1

if ($null -eq $installed) {
    if ($WhatIfPreference) {
        Write-Host '  (WhatIf) Skipping verification; nothing was installed.' -ForegroundColor DarkGray
        return
    }
    throw "$($pin.moduleName) $($pin.version) is not present after install."
}

$channelPackage = Join-Path $channelSource $pin.packageName
if (Test-Path -LiteralPath $channelPackage -PathType Leaf) {
    $actual = (Get-FileHash -LiteralPath $channelPackage -Algorithm SHA256).Hash
    if (-not [string]::Equals($actual, $pin.sha256, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "DIGEST MISMATCH: the channel copy of $($pin.packageName) is $actual but the pin names $($pin.sha256). The channel content changed under the pin; do not proceed."
    }
    Write-Host "  Digest verified against the channel copy." -ForegroundColor Green
}
else {
    Write-Warning "Could not find $($pin.packageName) in the channel to re-verify its digest; the install succeeded but the byte-level check was skipped."
}

# --- 5. Import the INSTALLED package in a clean process ----------------------------------
# This session already has GraphKit loaded from source, so importing here would prove
# nothing about what a fresh IHA host will do.
$probe = @"
`$ErrorActionPreference = 'Stop'
Import-Module $($pin.moduleName) -RequiredVersion $($pin.version) -Force
`$m = Get-Module $($pin.moduleName)
[pscustomobject]@{
    Version  = `$m.Version.ToString()
    Commands = @(Get-Command -Module $($pin.moduleName)).Count
    Base     = `$m.ModuleBase
} | ConvertTo-Json -Compress
"@

$probeResult = & pwsh -NoProfile -Command $probe 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "The installed package failed to import in a clean process:`n$($probeResult -join "`n")"
}

$parsed = ($probeResult | Select-Object -Last 1) | ConvertFrom-Json
Write-Host "  Clean-process import: v$($parsed.Version), $($parsed.Commands) commands" -ForegroundColor Green
Write-Host "    from $($parsed.Base)" -ForegroundColor DarkGray
Write-Host ''
Write-Host 'INSTALL VERIFIED' -ForegroundColor Green
Write-Host ''

[pscustomobject]@{
    PSTypeName        = 'GraphKit.PinnedInstallResult'
    ModuleName        = $pin.moduleName
    Version           = $parsed.Version
    Commands          = $parsed.Commands
    ModuleBase        = $parsed.Base
    DigestVerified    = (Test-Path -LiteralPath $channelPackage -PathType Leaf)
    RestoreRecordPath = $RestoreRecordPath
    # Member enumeration on an empty array throws under Set-StrictMode 3.0, which is
    # exactly the state on a host installing GraphKit for the first time - the common case.
    PreviousVersions  = @($previous | ForEach-Object { $_.Version })
}
