# File-scope parameters, so the script can be invoked directly as documented in README.md,
# CLAUDE.md and docs/. Without these, PowerShell routes unmatched arguments into $args and
# discards them: the script defines the function, ignores everything passed to it and exits
# silently having done nothing. Keep this block in sync with the function's own parameters.
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $false, HelpMessage = 'The display name of the App Registration')]
    [string]
    $displayName = 'CDW-M365ConfigurationScan',

    [Parameter(Mandatory = $false, HelpMessage = 'The subject name for the new self-signed certificate')]
    [string]
    $CertificateSubject = '/CN=CDW-M365ConfigurationScan',

    [Parameter(Mandatory = $false)]
    [int]
    $CertValidityInYears = 1,

    [Parameter(Mandatory = $false, HelpMessage = 'Path to output the certificates and connection information')]
    [string]
    $outPath = 'C:\temp\M365ConfigurationExport\',

    [Parameter(Mandatory = $false, HelpMessage = 'Grant the read-only Graph application permissions. This is the default when neither -Read nor -Write is supplied.')]
    [switch]
    $Read,

    [Parameter(Mandatory = $false, HelpMessage = 'Additionally grant read-write Graph application permissions. Intended for lab tenants that need to exercise write paths.')]
    [switch]
    $Write,

    [Parameter(Mandatory = $false, HelpMessage = 'Password for the exported PFX. Supply this to run unattended; omit it to be prompted.')]
    [securestring]
    $CertificatePassword
)

function New-ClientServicePrincipalCBA() {
    <#
    .SYNOPSIS
        Creates a service principal with certificate-based authentication for tenant scanning
    .DESCRIPTION
        Creates an Azure AD application registration and service principal for Microsoft Graph
        to perform configuration scans and assessments.

        The permission set is selected with -Read and -Write, which are additive. Supplying
        neither grants the read-only set, matching this script's original behaviour.

        -Write is intended for lab tenants that need to exercise write paths. It deliberately
        excludes Directory.ReadWrite.All, AppRoleAssignment.ReadWrite.All and
        DeviceManagementManagedDevices.PrivilegedOperations.All; see the comment above
        $GraphPermissionsWrite for the reasoning.
    .NOTES
        Author: CDW Consultant
        Date: 04/13/2025
        Last Modified: 08/14/2026
        Version: 1.4
        Change Log:
            - 1.0: Initial version
            - 1.1: Added password prompt for certificate export and removed password from output
            - 1.2: Added prerequisite checks for modules and Graph authentication
            - 1.3: Improved error handling for app role assignments
            - 1.4: Added -Read and -Write permission set selection; unresolved permissions
                   now fail loudly instead of being dropped silently
    .EXAMPLE
        New-ClientServicePrincipalCBA -Verbose
        Creates a service principal with the default name 'CDW-M365ConfigurationScan' and the
        read-only permission set.

    .EXAMPLE
        New-ClientServicePrincipalCBA -displayName "MyCustomScanApp" -Verbose
        Creates a service principal with a custom display name and the read-only permission set.

    .EXAMPLE
        New-ClientServicePrincipalCBA -displayName "GraphKit-Ivy24" -Read -Write -outPath ~/.graphkit/certs/ivy24 -Verbose
        Creates a lab service principal with both read and write permission sets.

    .EXAMPLE
        New-ClientServicePrincipalCBA -displayName "GraphKit-Ivy24-Write" -Write -outPath ~/.graphkit/certs/ivy24w -Verbose
        Creates a service principal with only the write permission set, keeping read and write
        blast radii in separate registrations.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    Param(
        [Parameter(Mandatory = $false, HelpMessage = 'The display name of the App Registration')]
        [string]
        $displayName = 'CDW-M365ConfigurationScan',

        [Parameter(Mandatory = $false, HelpMessage = 'The subject name for the new self-signed certificate')]
        [string]
        $CertificateSubject = '/CN=CDW-M365ConfigurationScan',

        [Parameter(Mandatory = $false)]
        [int]
        $CertValidityInYears = 1,

        [Parameter(Mandatory = $false, HelpMessage = 'Path to output the certificates and connection information')]
        [string]
        $outPath = 'C:\temp\M365ConfigurationExport\',

        [Parameter(Mandatory = $false, HelpMessage = 'Grant the read-only Graph application permissions. This is the default when neither -Read nor -Write is supplied.')]
        [switch]
        $Read,

        [Parameter(Mandatory = $false, HelpMessage = 'Additionally grant read-write Graph application permissions. Intended for lab tenants that need to exercise write paths.')]
        [switch]
        $Write,

        [Parameter(Mandatory = $false, HelpMessage = 'Password for the exported PFX. Supply this to run unattended; omit it to be prompted.')]
        [securestring]
        $CertificatePassword
    )

    # Read and write are additive. Neither supplied means read-only, preserving
    # the original behaviour of this script for existing callers.
    $grantRead = $Read.IsPresent -or -not $Write.IsPresent
    $grantWrite = $Write.IsPresent

    # $outPath is consumed two incompatible ways: by PowerShell cmdlets such as New-Item and
    # Test-Path, which resolve '~' and relative paths, and by openssl, which is a native binary
    # with no shell to expand anything. Join-Path preserves '~' literally, so a path like
    # '~/certs' created the directory correctly and then handed openssl a literal '~/certs/x.key'
    # it could not open. Normalise once here so every downstream consumer sees a full path.
    # GetUnresolvedProviderPathFromPSPath is used rather than Resolve-Path because the directory
    # does not exist yet at this point.
    $outPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($outPath)
    Write-Verbose "Resolved output path: $outPath"

    # Check for required modules
    $requiredModules = @('Microsoft.Graph.Applications', 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Identity.DirectoryManagement')
    $missingModules = @()

    foreach ($module in $requiredModules) {
        if (-not (Get-Module -Name $module -ListAvailable)) {
            $missingModules += $module
        }
    }

    if ($missingModules.Count -gt 0) {
        Write-Warning "The following required modules are missing: $($missingModules -join ', ')"
        $installModules = Read-Host -Prompt 'Would you like to install these modules now? (Y/N)'
        
        if ($installModules -eq 'Y' -or $installModules -eq 'y') {
            foreach ($module in $missingModules) {
                try {
                    Write-Verbose "Installing module: $module"
                    Install-Module -Name $module -Scope CurrentUser -Force -ErrorAction Stop
                }
                catch {
                    Write-Error "Failed to install module $module. Error: $_"
                    return
                }
            }
        }
        else {
            Write-Host "`n❌ Certificate setup cancelled by user." -ForegroundColor Red
            Write-Host "   Required modules are missing: $($missingModules -join ', ')" -ForegroundColor Yellow
            Write-Host "   To set up certificate authentication later, install the modules and run:" -ForegroundColor Gray
            Write-Host "     ./New-ClientServicePrincipalCBA.ps1" -ForegroundColor DarkGray
            throw "ModulesDeclined:User declined to install required modules for certificate setup"
        }
    }

    # Check for Microsoft Graph authentication
    try {
        $graphContext = Get-MgContext -ErrorAction Stop
        if (-not $graphContext) {
            throw 'Not connected to Microsoft Graph'
        }
        
        # Check for necessary scopes/permissions
        $requiredScopes = @('Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'Directory.ReadWrite.All')
        $missingScopes = @()
        
        foreach ($scope in $requiredScopes) {
            if ($graphContext.Scopes -notcontains $scope) {
                $missingScopes += $scope
            }
        }
        
        if ($missingScopes.Count -gt 0) {
            Write-Warning "Microsoft Graph connection is missing required scopes: $($missingScopes -join ', ')"
            $reconnect = Read-Host -Prompt 'Would you like to reconnect with the required scopes? (Y/N)'
            
            if ($reconnect -eq 'Y' -or $reconnect -eq 'y') {
                try {
                    Disconnect-MgGraph | Out-Null
                    Connect-MgGraph -Scopes $requiredScopes -ErrorAction Stop
                }
                catch {
                    Write-Error "Failed to authenticate to Microsoft Graph with required scopes. Error: $_"
                    return
                }
            }
            else {
                Write-Error "Microsoft Graph connection is missing required scopes. Please reconnect with the following scopes and try again: $($missingScopes -join ', ')"
                return
            }
        }
    }
    catch {
        Write-Warning "Not connected to Microsoft Graph: $_"
        $connect = Read-Host -Prompt 'Would you like to connect to Microsoft Graph now? (Y/N)'
        
        if ($connect -eq 'Y' -or $connect -eq 'y') {
            try {
                Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'Directory.ReadWrite.All' -ErrorAction Stop
            }
            catch {
                Write-Error "Failed to authenticate to Microsoft Graph. Error: $_"
                return
            }
        }
        else {
            Write-Error 'Microsoft Graph authentication is required to continue.'
            return
        }
    }
    
    # Microsoft Graph permissions required for Intune Health Check
    $GraphPermissionsRead = @(
        'DeviceManagementConfiguration.Read.All',
        'DeviceManagementApps.Read.All',
        'DeviceManagementManagedDevices.Read.All',
        'DeviceManagementServiceConfig.Read.All',
        'Directory.Read.All',
        'Reports.Read.All',
        'User.Read.All',
        'Group.Read.All',
        'Device.Read.All',
        'Policy.Read.ConditionalAccess',
        'RoleManagement.Read.Directory',
        'Application.Read.All',
        'AuditLog.Read.All'
    )

    # Write permissions are scoped to Intune workloads plus group membership, which is
    # what assignment targeting needs. Three permissions are deliberately excluded:
    #
    #   Directory.ReadWrite.All                              - mutates users, groups and roles tenant-wide
    #   AppRoleAssignment.ReadWrite.All                      - lets the app grant itself further roles
    #   DeviceManagementManagedDevices.PrivilegedOperations.All - remote wipe and retire
    #
    # The first two are privilege-escalation paths and the third is destructive. Add them
    # to this array explicitly if a scenario genuinely requires them; they should not
    # arrive as a side effect of asking for -Write.
    $GraphPermissionsWrite = @(
        'DeviceManagementConfiguration.ReadWrite.All',
        'DeviceManagementApps.ReadWrite.All',
        'DeviceManagementManagedDevices.ReadWrite.All',
        'DeviceManagementServiceConfig.ReadWrite.All',
        'DeviceManagementRBAC.ReadWrite.All',
        'Group.ReadWrite.All'
    )

    $GraphPermissionsRequired = @()
    if ($grantRead) { $GraphPermissionsRequired += $GraphPermissionsRead }
    if ($grantWrite) { $GraphPermissionsRequired += $GraphPermissionsWrite }
    $GraphPermissionsRequired = $GraphPermissionsRequired | Sort-Object -Unique

    $accessSummary = if ($grantRead -and $grantWrite) { 'read and write' } elseif ($grantWrite) { 'write only' } else { 'read only' }
    Write-Verbose "Permission set: $accessSummary ($($GraphPermissionsRequired.Count) permissions)"

    # Get Graph resource and resolve permissions
    Write-Verbose 'Resolving Microsoft Graph permissions'
    try {
        $GraphPermissionsRequiredResolved = Find-MgGraphPermission |
            Where-Object { $_.Name -in $GraphPermissionsRequired -and $_.PermissionType -eq 'Application' } |
            Select-Object Name, PermissionType, Id |
            Sort-Object -Property Name
    }
    catch {
        Write-Error "Failed to resolve Microsoft Graph permissions. Error: $_"
        return
    }

    # A permission that cannot be resolved would otherwise be dropped silently, producing an
    # app registration with fewer rights than requested and a confusing failure much later.
    $unresolved = $GraphPermissionsRequired | Where-Object { $_ -notin $GraphPermissionsRequiredResolved.Name }
    if ($unresolved) {
        Write-Error "The following Graph application permissions could not be resolved: $($unresolved -join ', '). Verify the names and that Microsoft.Graph.Applications is current."
        return
    }

    if ($grantWrite) {
        Write-Host "`n  Write permissions requested for '$displayName':" -ForegroundColor Yellow
        $GraphPermissionsWrite | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
        Write-Host "  Intended for lab tenants. Do not grant these in a customer tenant.`n" -ForegroundColor Yellow
    }
    # Generate self-signed certificate (cross-platform)
    Write-Verbose 'Generating self-signed certificate'
    try {
        # Check if running on Windows
        if ($PSVersionTable.Platform -eq 'Win32NT' -or [System.Environment]::OSVersion.Platform -eq 'Win32NT') {
            # Windows - use New-SelfSignedCertificate
            $cert = New-SelfSignedCertificate -Subject $CertificateSubject -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears($CertValidityInYears)
        }
        else {
            # macOS/Linux - use OpenSSL
            Write-Verbose "Cross-platform certificate generation using OpenSSL"
            
            # Ensure output directory exists
            if (-not (Test-Path $outPath)) {
                New-Item -ItemType Directory -Path $outPath -Force | Out-Null
            }
            
            $certName = $displayName -replace '[^\w\-]', ''
            $keyFile = Join-Path $outPath "$certName.key"
            $crtFile = Join-Path $outPath "$certName.crt"
            $pfxFile = Join-Path $outPath "$certName.pfx"
            
            # Call openssl through the call operator with an argument array rather than building
            # a string for Invoke-Expression. Arguments are passed to the process verbatim, so a
            # path containing a space or a quote cannot break the command, and there is no
            # expression-injection surface.
            $opensslArgs = @(
                'req', '-x509', '-newkey', 'rsa:2048',
                '-keyout', $keyFile,
                '-out', $crtFile,
                '-days', ($CertValidityInYears * 365),
                '-nodes',
                '-subj', $CertificateSubject
            )
            Write-Verbose "Running: openssl $($opensslArgs -join ' ')"
            $opensslOutput = & openssl @opensslArgs 2>&1

            # Surface openssl's own diagnostics. Reporting only 'Failed to generate certificate'
            # discards the one piece of information needed to fix the problem. openssl writes
            # key-generation progress to stderr as runs of '.' and '+', which would otherwise
            # bury the real message, so drop lines that carry no text.
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path $crtFile)) {
                $reason = @($opensslOutput | ForEach-Object { "$_" } | Where-Object { $_ -notmatch '^[.+*\s]*$' }) -join ' '
                if ([string]::IsNullOrWhiteSpace($reason)) { $reason = 'no diagnostic output' }
                throw "OpenSSL failed to generate the certificate (exit code $LASTEXITCODE): $reason"
            }
            
            # Get certificate thumbprint
            $thumbprintCmd = "openssl x509 -in '$crtFile' -fingerprint -sha1 -noout | cut -d'=' -f2 | sed 's/://g'"
            $thumbprint = (Invoke-Expression $thumbprintCmd).Trim()
            
            # Get certificate not after date
            $notAfterCmd = "openssl x509 -in '$crtFile' -noout -enddate | cut -d'=' -f2"
            $notAfterStr = (Invoke-Expression $notAfterCmd).Trim()
            $notAfter = [DateTime]::ParseExact($notAfterStr, "MMM dd HH:mm:ss yyyy GMT", $null)
            
            # Read certificate data for Azure AD
            $certBytes = [System.IO.File]::ReadAllBytes($crtFile)
            
            # Create a certificate object-like structure
            $cert = [PSCustomObject]@{
                Thumbprint = $thumbprint
                NotAfter = $notAfter
                RawData = $certBytes
                Subject = $CertificateSubject
                FilePath = $crtFile
                KeyPath = $keyFile
                PfxPath = $pfxFile
            }
            
            Write-Verbose "Generated certificate with thumbprint: $thumbprint"
        }
    }
    catch {
        Write-Error "Failed to generate self-signed certificate. Error: $_"
        return
    }

    # Prompt for certificate password.
    #
    # SecureStringToBSTR produces a UTF-16 BSTR (two bytes per character). PtrToStringAuto
    # resolves to the ANSI variant on Unix, so it reads the first byte, hits the null byte of
    # the second, and returns ONLY THE FIRST CHARACTER. The PFX was therefore exported with a
    # one-character password while the operator believed they had set a strong one - both a
    # security defect and the cause of 'the certificate data cannot be read with the provided
    # password' when loading the PFX later with the password actually typed.
    #
    # NetworkCredential does the conversion correctly on every platform and needs no manual
    # BSTR lifetime management (the previous code also leaked the BSTR - no ZeroFreeBSTR).
    # -CertificatePassword allows unattended runs (CI, automated recreation of lab tenants).
    # Omitting it preserves the interactive prompt.
    if ($PSBoundParameters.ContainsKey('CertificatePassword') -and $CertificatePassword) {
        $certPasswordSecure = $CertificatePassword
        Write-Verbose 'Using the supplied certificate password (unattended mode)'
    }
    else {
        $certPasswordSecure = Read-Host -AsSecureString -Prompt 'Enter password to protect the certificate'
    }
    $certPassword = [System.Net.NetworkCredential]::new('', $certPasswordSecure).Password

    if ([string]::IsNullOrEmpty($certPassword)) {
        Write-Error 'The certificate password is empty. Aborting rather than exporting an unprotected PFX.'
        return
    }
            
    # Export certificate to PFX file with the provided password
    try {
        Write-Verbose "Exporting certificate to $outPath"
        
        if ($PSVersionTable.Platform -eq 'Win32NT' -or [System.Environment]::OSVersion.Platform -eq 'Win32NT') {
            # Windows - use Export-PfxCertificate
            Export-PfxCertificate -Cert $cert -FilePath "$outPath\$displayName.pfx" -Password $certPasswordSecure | Out-Null
            $keyCredentialCert = Export-Certificate -Cert $cert -FilePath "$outPath\$displayName.cer"
            $certObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($keyCredentialCert)
        }
        else {
            # macOS/Linux - use OpenSSL to create PFX.
            #
            # Two changes from the previous Invoke-Expression approach:
            #  - the call operator passes arguments to the process verbatim, so a password
            #    containing a quote, '$' or ';' cannot break the command or be re-evaluated
            #    as PowerShell code
            #  - the password is handed over via an environment variable rather than
            #    'pass:<secret>', which would expose it in the process command line to any
            #    user able to run ps
            $env:GRAPHKIT_PFX_PASSWORD = $certPassword
            try {
                $pfxArgs = @(
                    'pkcs12', '-export',
                    '-out', $cert.PfxPath,
                    '-inkey', $cert.KeyPath,
                    '-in', $cert.FilePath,
                    '-passout', 'env:GRAPHKIT_PFX_PASSWORD'
                )
                $pfxOutput = & openssl @pfxArgs 2>&1
            }
            finally {
                Remove-Item Env:\GRAPHKIT_PFX_PASSWORD -ErrorAction SilentlyContinue
            }

            if ($LASTEXITCODE -ne 0 -or -not (Test-Path $cert.PfxPath)) {
                $reason = @($pfxOutput | ForEach-Object { "$_" } | Where-Object { $_ -notmatch '^[.+*\s]*$' }) -join ' '
                if ([string]::IsNullOrWhiteSpace($reason)) { $reason = 'no diagnostic output' }
                throw "OpenSSL failed to export the PFX (exit code $LASTEXITCODE): $reason"
            }

            # Prove the PFX opens with the password the operator actually typed. Without this
            # the mismatch only surfaces much later, at Connect-MgGraph, as a misleading
            # 'the password may be incorrect'.
            try {
                $verifyCert = [System.Security.Cryptography.X509Certificates.X509CertificateLoader]::LoadPkcs12FromFile($cert.PfxPath, $certPassword)
                if (-not $verifyCert.HasPrivateKey) {
                    throw 'the exported PFX contains no private key, so it cannot be used for app-only authentication'
                }
                Write-Verbose "Verified PFX opens with the supplied password (thumbprint $($verifyCert.Thumbprint))"
            }
            catch {
                throw "The exported PFX at $($cert.PfxPath) could not be reopened with the supplied password: $($_.Exception.Message)"
            }
            
            # For Azure AD, we need the raw certificate data
            $certObject = [PSCustomObject]@{
                RawData = $cert.RawData
                Thumbprint = $cert.Thumbprint
            }
        }
    }
    catch {
        Write-Error "Failed to export certificate to $outPath. Error: $_"
        return
    }

    Write-Verbose "Certificate exported successfully"

    # Check if application already exists
    $existingApp = Get-MgApplication -Filter "displayName eq '$displayName'"

    if ($null -eq $existingApp) {
        if ($PSCmdlet.ShouldProcess($displayName, 'Create new application registration')) {

            # Create Graph permission array
            $GraphResourceAccessArray = @()
            foreach ($permission in $GraphPermissionsRequiredResolved) {
                $GraphResourceAccessArray += @{
                    Id   = $permission.Id
                    Type = 'Role'
                }
                Write-Verbose "Adding Graph permission: $($permission.Name)"
            }

            # Microsoft Graph App ID
            $GraphResourceId = '00000003-0000-0000-c000-000000000000'

            Write-Verbose "Creating new application registration: $displayName"
            try {
                $app = New-MgApplication -DisplayName $displayName -SignInAudience 'AzureADMyOrg' -Web @{ RedirectUris = 'urn:ietf:wg:oauth:2.0:oob' } -RequiredResourceAccess @{ ResourceAppId = $GraphResourceId; ResourceAccess = $GraphResourceAccessArray } -AdditionalProperties @{} -KeyCredentials @(@{ Type = 'AsymmetricX509Cert'; Usage = 'Verify'; Key = $certObject.RawData })
            }
            catch {
                Write-Error "Failed to create application registration. Error: $_"
                return
            }

            Write-Verbose "Application created successfully with Microsoft Graph permissions"


            # Create service principal
            try {
                Write-Verbose "Creating service principal for $displayName"
                $sp = New-MgServicePrincipal -AppId $app.AppId -AdditionalProperties @{}
                Write-Verbose 'Successfully created service principal'
            }
            catch {
                Write-Error "Failed to create service principal. Error: $_"
                return
            }
            # NOTE: this entire section - the service principal lookup, the Microsoft Graph
            # permission grants, and the Exchange/SharePoint grants - was previously enclosed
            # in a <# ... #> block comment running from here to just before the connection
            # information is built. The application and service principal were created, and
            # the function then returned a success object having granted NOTHING. That is why
            # registrations produced by this script had their permissions configured in
            # requiredResourceAccess but zero appRoleAssignments.
            #
            # The Microsoft Graph portion is restored below. Exchange Online and SharePoint
            # Online remain commented out further down: this tool only needs Graph, and
            # requiring those service principals to exist would fail tenants that do not have
            # them provisioned.

            # Get the Microsoft Graph service principal.
            # This filtered on $GraphAppId, a variable that is never assigned anywhere in the
            # script. Without Set-StrictMode that expands to an empty string, producing the
            # filter "appId eq ''" and a 400 Request_UnsupportedQuery. The Graph application
            # id is already held in $GraphResourceId, assigned above where the application is
            # created; reuse it rather than introducing a second constant.
            try {
                Write-Verbose 'Getting the Microsoft Graph service principal'
                $graphSp = Get-MgServicePrincipal -Filter "appId eq '$GraphResourceId'"

                if (-not $graphSp) {
                    throw "Microsoft Graph service principal (appId $GraphResourceId) not found in this tenant"
                }

                $graphSpId = $graphSp.Id
            }
            catch {
                Write-Error "Failed to get the Microsoft Graph service principal. Error: $_"
                return
            }

            # Wait for service principal creation to propagate
            Write-Verbose 'Waiting 5 seconds for service principal creation to propagate...'
            Start-Sleep -Seconds 5

            # Add Certificate Credential for ServicePrincipal

            # Grant application permissions.
            # Failures are collected rather than warned-and-forgotten. Previously each failed
            # assignment produced only a Write-Warning and the loop continued, so the script
            # returned a success object describing an application that did not actually hold
            # the permissions it claimed - the exact 'configured but not granted' gap this
            # tooling exists to avoid.
            Write-Verbose 'Granting Microsoft Graph permissions'
            $grantFailures = [System.Collections.Generic.List[string]]::new()
            $grantedRoles = [System.Collections.Generic.List[string]]::new()

            foreach ($permission in $GraphPermissionsRequiredResolved) {
                try {
                    Write-Verbose "  - Assigning role: $($permission.Name)"

                    # Check if role exists in the target application
                    $appRole = $graphSp.AppRoles | Where-Object { $_.Id -eq $permission.Id }
                    if (-not $appRole) {
                        $grantFailures.Add("$($permission.Name): role ID $($permission.Id) not present in the Microsoft Graph service principal")
                        continue
                    }

                    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id -AppRoleId $permission.Id -ResourceId $graphSpId | Out-Null
                    $grantedRoles.Add($permission.Name)
                }
                catch {
                    $grantFailures.Add("$($permission.Name): $($_.Exception.Message)")
                }
            }

            # Verify against the service principal rather than trusting the loop. An assignment
            # can be accepted and still not be present, so read the granted state back.
            $actuallyGranted = @(
                Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue |
                    Where-Object { $_.ResourceId -eq $graphSpId } |
                    ForEach-Object { $roleId = $_.AppRoleId; ($graphSp.AppRoles | Where-Object { $_.Id -eq $roleId }).Value }
            )
            $notGranted = @($GraphPermissionsRequiredResolved.Name | Where-Object { $_ -notin $actuallyGranted })

            if ($grantFailures.Count -gt 0 -or $notGranted.Count -gt 0) {
                $detail = @()
                if ($grantFailures.Count -gt 0) { $detail += "Assignment errors: $($grantFailures -join '; ')" }
                if ($notGranted.Count -gt 0) { $detail += "Requested but not granted: $($notGranted -join ', ')" }
                throw ("Application '$displayName' (appId $($app.AppId)) was created but its permissions are incomplete. " +
                    "$($detail -join '. '). Granted $($actuallyGranted.Count) of $($GraphPermissionsRequiredResolved.Count). " +
                    'Assigning Graph application roles requires Privileged Role Administrator or Global Administrator. ' +
                    "Delete the incomplete registration with: Remove-MgApplication -ApplicationId $($app.Id)")
            }

            Write-Verbose "Verified $($actuallyGranted.Count) Microsoft Graph application roles granted"

            # Exchange Online and SharePoint Online grants remain disabled. This tool only
            # requires Microsoft Graph, and demanding those service principals be present
            # would fail in tenants that have not provisioned them.
            <#
            Write-Verbose 'Granting Exchange Online permissions'
            try {
                # Check if role exists in the target application
                $exoAppRole = $exoSp.AppRoles | Where-Object { $_.Id -eq $ExoPermissionId }
                if (-not $exoAppRole) {
                    Write-Warning "Exchange Online role ID $ExoPermissionId not found. Skipping assignment."
                }
                else {
                    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id -AppRoleId $ExoPermissionId -ResourceId $exoSpId
                }
            }
            catch {
                Write-Warning "Failed to assign Exchange Online role. Error: $_"
            }

            Write-Verbose 'Granting SharePoint Online permissions'
            try {
                # Check if role exists in the target application
                $spoAppRole = $spoSp.AppRoles | Where-Object { $_.Id -eq $SpoPermissionId }
                if (-not $spoAppRole) {
                    Write-Warning "SharePoint Online role ID $SpoPermissionId not found. Skipping assignment."
                }
                else {
                    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id -AppRoleId $SpoPermissionId -ResourceId $spoSpId
                }
            }
            catch {
                Write-Warning "Failed to assign SharePoint Online role. Error: $_"
            }
            #>
            # Create URLs and Connection Information.
            # Resolve the tenant once and reuse it. These strings previously read $context.TenantId,
            # but no variable named $context exists in this script - the connection check earlier
            # uses $graphContext - so $null.TenantId silently produced an empty string. That
            # yielded an admin consent URL with a doubled slash and a connection command with
            # -TenantId "", while the returned object showed the correct value. Reading it once
            # keeps all three consistent by construction.
            $resolvedTenantId = (Get-MgContext).TenantId
            if ([string]::IsNullOrWhiteSpace($resolvedTenantId)) {
                Write-Warning 'Unable to determine the tenant ID from the current Graph context. The admin consent URL and connection command below will be incomplete.'
            }

            $adminConsentUrl = 'https://login.microsoftonline.com/' + $resolvedTenantId + '/adminconsent?client_id=' + $app.AppId

            # -CertificateThumbprint resolves against the Windows certificate store, which does
            # not exist on macOS or Linux. Emitting it there causes Connect-MgGraph to fall back
            # to interactive authentication, which then fails with AADSTS50011 because this
            # registration has no localhost redirect URI - it is an app-only registration and
            # should not have one. Emit a command that matches the running platform.
            if ($IsWindows) {
                $connectionCommand = 'Connect-MgGraph -ClientId "' + $app.AppId + '" -TenantId "' + $resolvedTenantId + '" -CertificateThumbprint "' + $cert.Thumbprint + '"'
            }
            else {
                # LoadPkcs12FromFile has no SecureString overload - only (String, String) and
                # (String, ReadOnlySpan<char>). Passing a SecureString directly is silently
                # coerced and fails with a misleading 'the password may be incorrect'. Convert
                # at the call site instead. Verified against PowerShell 7.6 / .NET 10 with a
                # PFX produced by this script's own openssl export.
                $pfxPath = Join-Path $outPath "$($displayName -replace '[^\w\-]', '').pfx"
                $connectionCommand = @"
`$pfxPassword = Read-Host -AsSecureString -Prompt 'PFX password'
`$cert = [System.Security.Cryptography.X509Certificates.X509CertificateLoader]::LoadPkcs12FromFile(
    '$pfxPath', [System.Net.NetworkCredential]::new('', `$pfxPassword).Password)
Connect-MgGraph -ClientId "$($app.AppId)" -TenantId "$resolvedTenantId" -Certificate `$cert
"@
            }
            # Output important information
            $output = [PSCustomObject]@{
                ApplicationName       = $displayName
                ApplicationId         = $app.AppId
                ObjectId              = $app.Id
                ServicePrincipalId    = $sp.Id
                TenantId              = $resolvedTenantId
                CertificateThumbprint = $cert.Thumbprint
                CertificatePath       = $outPath
                CertificateSubject    = $CertificateSubject
                CertificateEndDate    = $cert.NotAfter
                AdminConsentURL       = $adminConsentUrl
                ConnectionCommand     = $connectionCommand
            }

            return $output
            $output | Out-File -FilePath "'$outPath'\appDetails.txt"
        }
    }
    else {
        Write-Warning "Application with name '$displayName' already exists. Please use a different name or remove the existing application."
        return $null
    }
}

# Invoke only when the script is run directly, never when it is dot-sourced.
# Dot-sourcing sets InvocationName to '.', and callers who dot-source expect the function
# to be defined and nothing else to happen. Direct invocation reports the script path
# (./New-ClientServicePrincipalCBA.ps1) or '&' when called through the call operator.
if ($MyInvocation.InvocationName -ne '.') {
    New-ClientServicePrincipalCBA @PSBoundParameters
}