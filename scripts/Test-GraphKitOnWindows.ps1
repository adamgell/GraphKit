<#
    .SYNOPSIS
        Verifies GraphKit itself on Windows. No tenant, no credentials, no IHA.

    .DESCRIPTION
        GraphKit's cross-platform suite runs in the supported CI matrix. This script supplements
        that suite with platform-specific paths that only Windows can prove:

          - the certificate-store credential resolver, which throws on non-Windows by design
          - certificate-store profile registration, likewise
          - file locking and path handling under a different filesystem

        This exercises those paths using a throwaway self-signed certificate created in
        CurrentUser\My and deleted afterwards, so it needs no tenant, no vault, and no secret
        material. It writes nothing outside a temporary directory and the one test
        certificate.

        A live token is deliberately NOT attempted. That needs a real credential on this host,
        which is a separate decision; this answers "does GraphKit run correctly here".

    .PARAMETER KeepCertificate
        Leave the throwaway certificate in place (for debugging). It is removed by default.

    .EXAMPLE
        ./Test-GraphKitOnWindows.ps1
#>
[CmdletBinding()]
param(
    [switch] $KeepCertificate
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

if (-not $IsWindows) {
    throw "This verifies the Windows-only paths and must run on Windows; this platform is $($PSVersionTable.Platform)."
}

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result {
    param([string] $Name, [bool] $Passed, [string] $Detail = '')
    $results.Add([pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
    $mark = if ($Passed) { '[+]' } else { '[-]' }
    $colour = if ($Passed) { 'Green' } else { 'Red' }
    Write-Host ("  {0} {1,-52} {2}" -f $mark, $Name, $Detail) -ForegroundColor $colour
}

Write-Host ''
Write-Host "  GraphKit on Windows - PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor Cyan
Write-Host ''

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("graphkit-win-{0}" -f [guid]::NewGuid())
$null = New-Item -ItemType Directory -Path $workDir -Force
$testCert = $null

try {
    # --- 1. Import ------------------------------------------------------------------------
    Import-Module GraphKit -ErrorAction Stop
    $module = Get-Module GraphKit
    Add-Result 'module imports' $true "v$($module.Version)"
    Add-Result 'commands exported' (@(Get-Command -Module GraphKit).Count -ge 16) "$(@(Get-Command -Module GraphKit).Count) commands"

    # --- 2. Catalog -----------------------------------------------------------------------
    $catalog = @(Get-GraphOperation -List)
    Add-Result 'operation catalog loads' ($catalog.Count -gt 0) "$($catalog.Count) descriptors"

    $beta = @($catalog | Where-Object { $_.ApiVersion -eq 'beta' })
    Add-Result 'beta descriptors present' ($beta.Count -gt 0) "$($beta.Count) beta"

    # --- 3. Profile store on a path that does not exist yet -------------------------------
    # This is the first-run case that failed on a clean machine: the lock sidecar cannot be
    # created if its directory is absent, and the retry loop used to report that as
    # "another process may be writing".
    $freshStore = Join-Path $workDir 'nested\deeper\profiles.json'
    Register-GraphTenant -ProfileId 'wintest' -Name 'Windows Test' -Kind lab `
        -TenantId '11111111-2222-3333-4444-555555555555' -Environment Global `
        -AuthMethod ManagedIdentity -StorePath $freshStore | Out-Null
    Add-Result 'first-run profile store on a missing directory' (Test-Path -LiteralPath $freshStore) 'created'

    $listed = @(Get-GraphTenant -StorePath $freshStore)
    Add-Result 'profile round-trips' ($listed.Count -eq 1 -and $listed[0].ProfileId -eq 'wintest')

    # A second profile exercises the read-modify-write lock path.
    Register-GraphTenant -ProfileId 'wintest2' -Name 'Windows Test 2' -Kind lab `
        -TenantId '66666666-7777-8888-9999-000000000000' -Environment Global `
        -AuthMethod ManagedIdentity -StorePath $freshStore | Out-Null
    Add-Result 'store lock allows sequential writes' (@(Get-GraphTenant -StorePath $freshStore).Count -eq 2)

    Remove-GraphTenant -ProfileId 'wintest2' -StorePath $freshStore -Confirm:$false
    Add-Result 'profile removal' (@(Get-GraphTenant -StorePath $freshStore).Count -eq 1)

    # --- 4. The Windows-only certificate-store paths --------------------------------------
    # These cannot run on macOS at all: Register-GraphTenant and the credential resolver both
    # throw on non-Windows by design, so this is the first time they execute anywhere.
    $testCert = New-SelfSignedCertificate -Subject 'CN=GraphKit Windows Verification' `
        -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable `
        -KeySpec Signature -NotAfter (Get-Date).AddDays(1) -ErrorAction Stop
    Add-Result 'throwaway certificate created' $true $testCert.Thumbprint.Substring(0, 12)

    Register-GraphTenant -ProfileId 'wincert' -Name 'Windows Cert Test' -Kind lab `
        -TenantId '11111111-2222-3333-4444-555555555555' `
        -ClientId '99999999-8888-7777-6666-555555555555' -Environment Global `
        -AuthMethod Certificate -StoreLocation CurrentUser -StoreName My `
        -Thumbprint $testCert.Thumbprint -StorePath $freshStore | Out-Null
    Add-Result 'certificate-store profile registers (Windows-only path)' $true

    # Resolve the credential: this is Get-GraphVaultCredential's store lookup, which has never
    # executed on any platform before now.
    $resolved = & (Get-Module GraphKit) {
        param($StorePath)
        $store = Get-GraphProfileStore -StorePath $StorePath
        $profileRecord = $store.Profiles | Where-Object { $_.ProfileId -eq 'wincert' }
        Get-GraphVaultCredential -Credential $profileRecord.Credential -AuthMethod 'Certificate'
    } $freshStore

    $cert = if ($resolved.PSObject.Properties['Material']) { $resolved.Material } else { $resolved }
    Add-Result 'certificate resolves from the store' ($null -ne $cert)
    Add-Result 'resolved certificate has its private key' ([bool]$cert.HasPrivateKey) 'required to sign a client assertion'
    Add-Result 'resolved thumbprint matches' ($cert.Thumbprint -eq $testCert.Thumbprint)

    # A thumbprint that is not present must fail with a message naming the store, not with a
    # later, more confusing MSAL error.
    $missingHandled = $false
    try {
        & (Get-Module GraphKit) {
            Get-GraphVaultCredential -Credential @{ StoreLocation = 'CurrentUser'; StoreName = 'My'; Thumbprint = ('F' * 40) } -AuthMethod 'Certificate'
        }
    }
    catch { $missingHandled = $_.Exception.Message -match 'No certificate matching' }
    Add-Result 'missing certificate reports the store, not an MSAL error' $missingHandled

    # --- 5. Context resolution without any network call -----------------------------------
    $context = Get-GraphContext -ProfileId 'wincert' -StorePath $freshStore
    Add-Result 'context resolves offline' ($context.TokenSource.AuthMode -eq 'Certificate') "AuthMode=$($context.TokenSource.AuthMode)"
}
finally {
    if ($null -ne $testCert -and -not $KeepCertificate) {
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($testCert.Thumbprint)" -Force -ErrorAction SilentlyContinue
        Write-Host "  (throwaway certificate removed)" -ForegroundColor DarkGray
    }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -eq 0) {
    Write-Host "  GRAPHKIT VERIFIED ON WINDOWS - $($results.Count) checks passed" -ForegroundColor Green
    exit 0
}
Write-Host "  $($failed.Count) of $($results.Count) checks FAILED:" -ForegroundColor Red
$failed | ForEach-Object { Write-Host "    $($_.Name)" -ForegroundColor Red }
exit 1
