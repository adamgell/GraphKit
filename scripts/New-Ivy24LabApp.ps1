<#
    Recreate the Ivy24 lab app registration end to end and prove it works.

    Deletes any existing registration, creates a new one with read+write Graph application
    permissions, verifies every role was actually granted, then authenticates app-only with
    the generated certificate and reads a real Intune endpoint.

    Runs unattended: the PFX password is generated and written next to the certificate.
    Requires an existing delegated Graph session for the target tenant (a cached MSAL token
    is sufficient - Connect-MgGraph is called silently).

    -TenantId is required rather than baked in. It used to hardcode a real lab tenant id,
    which put a tenant identifier in version control - the thing AGENTS.md tells everyone else
    never to commit. A placeholder would have been worse than either: the script would run,
    fail its own tenant guard, and look broken rather than unconfigured.

    Run:  pwsh -NoProfile -File ./scripts/New-Ivy24LabApp.ps1 -TenantId <guid>
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string] $TenantId,

    [string] $DisplayName = 'GraphKit-Lab',

    [string] $OutPath = "$HOME/.graphkit/certs/lab"
)

$ErrorActionPreference = 'Stop'
$CreateScript = Join-Path $PSScriptRoot 'New-ClientServicePrincipalCBA.ps1'

function Step { param($t) Write-Host "`n=== $t ===" -ForegroundColor Cyan }

Step '1. Connect (silent, reusing cached delegated token)'
Connect-MgGraph -TenantId $TenantId -Scopes Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All, Directory.ReadWrite.All -NoWelcome
$ctx = Get-MgContext
if ($ctx.TenantId -ne $TenantId) { throw "Wrong tenant: $($ctx.TenantId)" }
$org = Get-MgOrganization | Select-Object -First 1
"  tenant  : $($ctx.TenantId)"
"  org     : $($org.DisplayName)"
"  domains : $(($org.VerifiedDomains | ForEach-Object { $_.Name }) -join ', ')"
"  account : $($ctx.Account)"
$needed = @('Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'Directory.ReadWrite.All')
$missing = @($needed | Where-Object { $_ -notin $ctx.Scopes })
if ($missing) { throw "Missing scopes: $($missing -join ', ')" }
"  scopes  : all required present"

Step "2. Delete existing '$DisplayName'"
$existing = @(Get-MgApplication -Filter "displayName eq '$DisplayName'")
if ($existing.Count -eq 0) { '  nothing to delete' }
else {
    foreach ($a in $existing) { Remove-MgApplication -ApplicationId $a.Id; "  deleted $($a.Id)" }
    $deadline = (Get-Date).AddSeconds(90)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 5
        if (@(Get-MgApplication -Filter "displayName eq '$DisplayName'").Count -eq 0) { break }
        '  waiting for deletion to propagate...'
    }
    if (@(Get-MgApplication -Filter "displayName eq '$DisplayName'").Count -gt 0) { throw 'Deletion did not propagate in 90s' }
    '  deletion confirmed'
}

if (Test-Path $OutPath) { Get-ChildItem $OutPath -File | Remove-Item -Force; "  cleared old certificate files" }

Step '3. Generate password and create registration (unattended)'
$bytes = [byte[]]::new(24)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$plainPw = [Convert]::ToBase64String($bytes) -replace '[+/=]', 'x'
$securePw = ConvertTo-SecureString $plainPw -AsPlainText -Force
"  generated a $($plainPw.Length)-character password"

$result = & $CreateScript -displayName $DisplayName -Read -Write `
    -CertificateSubject "/CN=$DisplayName" -outPath $OutPath -CertificatePassword $securePw -Verbose

if (-not $result) { throw 'Creation returned nothing' }
"  appId      : $($result.ApplicationId)"
"  objectId   : $($result.ObjectId)"
"  spId       : $($result.ServicePrincipalId)"
"  thumbprint : $($result.CertificateThumbprint)"
"  expires    : $($result.CertificateEndDate)"

# Persist the password so it is recoverable. 600 perms; should move to SecretManagement.
$pwFile = Join-Path $OutPath 'pfx-password.txt'
Set-Content -Path $pwFile -Value $plainPw -NoNewline
& chmod 600 $pwFile
"  password saved: $pwFile (mode 600)"

Step '4. Verify granted Graph application roles'
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$granted = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $result.ServicePrincipalId |
        Where-Object { $_.ResourceId -eq $graphSp.Id } |
        ForEach-Object { $id = $_.AppRoleId; ($graphSp.AppRoles | Where-Object { $_.Id -eq $id }).Value })
"  granted: $($granted.Count) roles"
$expectedWrite = @('DeviceManagementConfiguration.ReadWrite.All', 'DeviceManagementApps.ReadWrite.All',
    'DeviceManagementManagedDevices.ReadWrite.All', 'DeviceManagementServiceConfig.ReadWrite.All',
    'DeviceManagementRBAC.ReadWrite.All', 'Group.ReadWrite.All')
$missingWrite = @($expectedWrite | Where-Object { $_ -notin $granted })
if ($missingWrite) { throw "Missing write permissions: $($missingWrite -join ', ')" }
'  all 6 write permissions present'
$granted | Sort-Object | ForEach-Object { "    $_" }

Step '5. Prove app-only certificate authentication'
$pfx = Join-Path $OutPath "$($DisplayName -replace '[^\w\-]', '').pfx"
$cert = [System.Security.Cryptography.X509Certificates.X509CertificateLoader]::LoadPkcs12FromFile($pfx, $plainPw)
"  PFX opened with generated password, private key: $($cert.HasPrivateKey)"

Disconnect-MgGraph | Out-Null
$connected = $false
foreach ($i in 1..8) {
    try { Connect-MgGraph -ClientId $result.ApplicationId -TenantId $TenantId -Certificate $cert -NoWelcome; $connected = $true; break }
    catch { "  attempt $i/8 waiting for propagation"; Start-Sleep -Seconds 10 }
}
if (-not $connected) { throw 'App-only auth failed after 8 attempts' }
$appCtx = Get-MgContext
if ($appCtx.AuthType -ne 'AppOnly') { throw "AuthType is $($appCtx.AuthType), expected AppOnly" }
"  AuthType   : $($appCtx.AuthType)"
"  AppName    : $($appCtx.AppName)"

$pol = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies').value
"  read $(@($pol).Count) compliance policies - Intune read works"
$devs = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=1').value
"  read managedDevices endpoint - $(@($devs).Count) returned"

Write-Host "`nSUCCESS" -ForegroundColor Green
"  TenantId  : $TenantId"
"  ClientId  : $($result.ApplicationId)"
"  Thumbprint: $($result.CertificateThumbprint)"
"  PFX       : $pfx"
