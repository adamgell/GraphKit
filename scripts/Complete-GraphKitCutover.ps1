<#
    .SYNOPSIS
        Finishes phase 5 on an IntuneHealthAutomation execution host: imports the legacy
        profiles, verifies the repoint read-only against a real tenant, and only then allows
        the legacy authentication layer to be retired.

    .DESCRIPTION
        This is the last step of the cutover and the only one that cannot be run from a
        development Mac. The two customer profiles are certificate-STORE profiles, so their
        private keys live in the Windows certificate store; `Register-GraphTenant` refuses
        store-based certificate material off Windows, and the keys are not present there
        anyway. Verification therefore has to happen where the certificates are.

        The ordering is the point, and it is enforced rather than documented:

          1. Import the legacy profiles (transactional, refuses on any conflict).
          2. Verify READ-ONLY through the repointed data plane, with the flag enabled for the
             duration of this run only. Nothing is written to the tenant.
          3. Retirement is refused unless that verification passed in THIS run. A previous
             green run does not count, because the thing being deleted is the fallback.

        Retirement removes IntuneHealthAutomation's legacy authentication layer. It is done
        with `git rm` on a branch, never a bare delete, so it is recoverable from history and
        reviewable as a diff. The script prints the exact command to undo it.

    .PARAMETER IhaPath
        Root of the IntuneHealthAutomation checkout.

    .PARAMETER ProfileId
        GraphKit ProfileId to verify against, e.g. 'contoso'.

    .PARAMETER LegacySecretsPath
        Legacy secrets.json to import. Defaults to <IhaPath>/secrets.json.

    .PARAMETER RetireLegacyLayer
        Retire the legacy authentication layer. Refused unless verification passed in this run.

    .EXAMPLE
        ./scripts/Complete-GraphKitCutover.ps1 -IhaPath C:\repo\IntuneHealthAutomation -ProfileId contoso

        Import and verify only. Writes nothing to the tenant and deletes nothing.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string] $IhaPath,

    [Parameter(Mandatory)]
    [string] $ProfileId,

    [string] $LegacySecretsPath,

    [switch] $RetireLegacyLayer
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

if (-not (Test-Path -LiteralPath $IhaPath -PathType Container)) {
    throw "IntuneHealthAutomation path '$IhaPath' does not exist."
}
if ([string]::IsNullOrWhiteSpace($LegacySecretsPath)) {
    $LegacySecretsPath = Join-Path $IhaPath 'secrets.json'
}

Write-Host ''
Write-Host '  Phase 5 completion' -ForegroundColor Cyan
Write-Host "    host     : $($PSVersionTable.Platform) / PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor DarkGray
Write-Host "    tenant   : $ProfileId" -ForegroundColor DarkGray
Write-Host ''

if (-not $IsWindows) {
    throw "This must run on the IHA execution host. Certificate-store profiles are Windows-only and the customer private keys live in the Windows certificate store; this platform is $($PSVersionTable.Platform)."
}

Import-Module GraphKit -ErrorAction Stop
Write-Host "  GraphKit $((Get-Module GraphKit).Version) loaded from $((Get-Module GraphKit).ModuleBase)" -ForegroundColor Green

# --- 1. Import legacy profiles ------------------------------------------------------------
Write-Host ''
Write-Host '  [1/3] Importing legacy profiles' -ForegroundColor Cyan

if (Test-Path -LiteralPath $LegacySecretsPath -PathType Leaf) {
    $inventory = Import-GraphLegacyProfile -Path $LegacySecretsPath -WhatIf
    foreach ($p in $inventory.Planned) {
        $state = if ($p.Importable) { 'importable' } else { ($p.Reasons -join '; ') }
        Write-Host ("    {0,-20} -> {1,-20} {2}" -f $p.LegacyName, $p.ProfileId, $state) -ForegroundColor DarkGray
    }

    if (@($inventory.Planned | Where-Object Importable).Count -gt 0) {
        if ($PSCmdlet.ShouldProcess($LegacySecretsPath, 'Import legacy tenant profiles')) {
            $imported = Import-GraphLegacyProfile -Path $LegacySecretsPath
            Write-Host "    imported: $(@($imported.ImportedIds) -join ', ')" -ForegroundColor Green
        }
    }
    else {
        Write-Host '    nothing new to import (already present, or nothing importable)' -ForegroundColor DarkGray
    }
}
else {
    Write-Host "    no legacy file at '$LegacySecretsPath'; skipping import" -ForegroundColor DarkGray
}

# --- 2. Read-only verification through the repointed plane --------------------------------
Write-Host ''
Write-Host '  [2/3] Verifying the repoint READ-ONLY' -ForegroundColor Cyan

$verified = $false
$previousFlag = $env:IHA_GRAPHKIT_REPOINT
$previousProfile = $env:IHA_GRAPHKIT_PROFILE

try {
    # Enabled for this process only. The host's own configuration is restored in the finally
    # block, so a failed verification never leaves the repoint switched on.
    $env:IHA_GRAPHKIT_REPOINT = '1'
    $env:IHA_GRAPHKIT_PROFILE = $ProfileId

    $shim = Join-Path $IhaPath 'src/private/Utilities/Invoke-GraphKitGraphRequest.ps1'
    if (-not (Test-Path -LiteralPath $shim -PathType Leaf)) {
        throw "The GraphKit data plane is not present at '$shim'. Check out the branch that adds it before completing the cutover."
    }
    if (-not (Get-Command Write-LogEntry -ErrorAction SilentlyContinue)) {
        function Write-LogEntry { param($Value, $Severity) Write-Verbose $Value }
    }
    . $shim

    # Read-only probes only. Nothing here mutates the tenant.
    $probes = @(
        @{ Name = 'managed devices'; Uri = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices' }
        @{ Name = 'mobile apps';     Uri = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps' }
        @{ Name = 'compliance';      Uri = 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies' }
        @{ Name = 'groups';          Uri = 'https://graph.microsoft.com/beta/groups' }
    )

    $failures = 0
    foreach ($probe in $probes) {
        try {
            $response = Invoke-GraphKitGraphRequest -Uri $probe.Uri
            if ($null -eq $response) { throw 'no descriptor covered the URI' }
            Write-Host ("    {0,-18} {1,6} records" -f $probe.Name, @($response.value).Count) -ForegroundColor Green
        }
        catch {
            $failures++
            Write-Host ("    {0,-18} FAILED: {1}" -f $probe.Name, $_.Exception.Message.Split([char]10)[0]) -ForegroundColor Red
        }
    }

    $verified = ($failures -eq 0)
}
finally {
    if ($null -eq $previousFlag) { Remove-Item Env:\IHA_GRAPHKIT_REPOINT -ErrorAction SilentlyContinue }
    else { $env:IHA_GRAPHKIT_REPOINT = $previousFlag }
    if ($null -eq $previousProfile) { Remove-Item Env:\IHA_GRAPHKIT_PROFILE -ErrorAction SilentlyContinue }
    else { $env:IHA_GRAPHKIT_PROFILE = $previousProfile }
}

if (-not $verified) {
    throw "Verification failed for '$ProfileId'. The legacy layer must stay: it is the fallback that makes the repoint reversible."
}
Write-Host "    verification PASSED for $ProfileId" -ForegroundColor Green

# --- 3. Retirement, gated on the verification above ---------------------------------------
Write-Host ''
Write-Host '  [3/3] Legacy layer' -ForegroundColor Cyan

$legacyLayer = @(
    'src/private/Authentication/Get-CBAToken.ps1'
    'src/private/Authentication/Update-AccessToken.ps1'
    'src/private/Authentication/Set-GraphEnvironment.ps1'
    'src/private/Authentication/Get-SecretsConfiguration.ps1'
)

$present = @($legacyLayer | Where-Object { Test-Path -LiteralPath (Join-Path $IhaPath $_) -PathType Leaf })

if (-not $RetireLegacyLayer) {
    Write-Host '    Retirement not requested. Files that -RetireLegacyLayer would remove:' -ForegroundColor DarkGray
    $present | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
    Write-Host ''
    Write-Host '    Enable the repoint on this host, run it in production for the rollback window,' -ForegroundColor Yellow
    Write-Host '    and only then re-run with -RetireLegacyLayer.' -ForegroundColor Yellow
    return
}

if ($present.Count -eq 0) {
    Write-Host '    already retired' -ForegroundColor Green
    return
}

if ($PSCmdlet.ShouldProcess("$($present.Count) legacy authentication file(s)", 'Retire via git rm on a branch')) {
    Push-Location $IhaPath
    try {
        $branch = 'cutover/retire-legacy-auth'
        & git checkout -b $branch 2>&1 | Out-Null
        foreach ($file in $present) { & git rm -q -- $file }
        & git commit -q -m "Retire the legacy authentication layer after GraphKit cutover verification

Removed only after a read-only verification of the repointed data plane passed
against '$ProfileId' on this host, in the same run that performed the removal."
        Write-Host "    retired on branch '$branch'" -ForegroundColor Green
        Write-Host "    undo with: git checkout main; git branch -D $branch" -ForegroundColor DarkGray
    }
    finally { Pop-Location }
}
