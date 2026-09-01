function Register-GraphTenant {
    <#
    .SYNOPSIS
        Registers a tenant profile in the GraphKit profile store.

    .DESCRIPTION
        Persists a tenant profile (non-secret metadata plus SecretManagement
        references) into the profile store under a canonical ProfileId. The
        credential shape is discriminated by -AuthMethod: a client secret or
        bearer token reference, a certificate (PFX with a vault-backed password,
        vault certificate material, or a Windows certificate-store lookup), or a
        managed identity. The write is performed under an interprocess lock with
        atomic replacement, and injected (non-persistable) credential objects are
        rejected. Kind=customer may validate Name against an injected taxonomy
        adapter.

    .PARAMETER ProfileId
        The canonical path-safe profile identifier (^[a-z0-9][a-z0-9-]{0,63}$).
        It is the only value ever used to select a profile or build a path.

    .PARAMETER Name
        The display name for this tenant. When Kind is customer this is the
        vault customer tag; it is never used as a selector or a path segment.

    .PARAMETER Kind
        The tenant kind: customer, lab or internal. Only customer validates Name
        against the CDW customer tag list via the taxonomy adapter.

    .PARAMETER TenantId
        The canonical target tenant GUID. Must be a valid GUID.

    .PARAMETER ClientId
        The application (client) GUID. Required for Certificate and ClientSecret.
        It must not be supplied for ManagedIdentity or BearerToken.

    .PARAMETER Environment
        The Graph cloud: Global, China, Germany, USGov or USGovDoD.

    .PARAMETER AuthMethod
        The authentication method: Certificate, ClientSecret, BearerToken or
        ManagedIdentity. It selects which credential parameters are required.

    .PARAMETER VaultName
        The SecretManagement vault name holding a client secret, a bearer token,
        or vault certificate material, depending on AuthMethod.

    .PARAMETER SecretName
        The secret name within the vault holding the client secret or the bearer
        token value, depending on AuthMethod.

    .PARAMETER SecretVersion
        Optional version metadata for the client secret or bearer token. The
        pinned SecretManagement 1.1.2 Get-Secret API has no Version parameter,
        so such a profile fails before vault access today. Use a distinct secret
        name for each immutable generation with the supported provider.

    .PARAMETER PfxPath
        The path to a PFX certificate file (Certificate AuthMethod, PFX shape).

    .PARAMETER PfxVaultName
        The SecretManagement vault holding the PFX password (PFX shape).

    .PARAMETER PfxSecretName
        The secret name holding the PFX password within that vault (PFX shape).

    .PARAMETER PfxSecretVersion
        Optional version metadata for the PFX password secret. The pinned
        SecretManagement 1.1.2 Get-Secret API cannot resolve it; use a distinct
        password secret name for each immutable generation today.

    .PARAMETER CertificateName
        The vault certificate name (Certificate AuthMethod, vault-material
        shape).

    .PARAMETER CertificateVersion
        Optional version metadata for vault certificate material. The pinned
        SecretManagement 1.1.2 Get-Secret API cannot resolve it; use a distinct
        certificate secret name for each immutable generation today.

    .PARAMETER CertificatePasswordVaultName
        Optional SecretManagement vault holding the password for encrypted
        vault certificate material. Supply it together with
        CertificatePasswordSecretName.

    .PARAMETER CertificatePasswordSecretName
        Optional secret name holding the password for encrypted vault
        certificate material. Supply it together with
        CertificatePasswordVaultName.

    .PARAMETER CertificatePasswordVersion
        Optional version metadata for the vault-certificate password. The
        pinned SecretManagement 1.1.2 Get-Secret API cannot resolve it; use a
        distinct password secret name for each immutable generation today.

    .PARAMETER StoreLocation
        The certificate store location (Windows only) for a store-lookup
        certificate; never the sole supported shape.

    .PARAMETER StoreName
        The certificate store name (Windows only) for a store-lookup
        certificate.

    .PARAMETER Thumbprint
        The certificate thumbprint to look up in the Windows certificate store.

    .PARAMETER Subject
        The certificate subject to look up in the Windows certificate store.

    .PARAMETER ManagedIdentityClientId
        Registration input persisted only as Credential.ClientId for a
        user-assigned managed identity client GUID. For system-assigned identity, omit it.
        It must not be supplied for any other
        authentication mode.

    .PARAMETER StorePath
        Optional override for the profile store path. Defaults to
        ~/.graphkit/profiles.json when omitted.

    .PARAMETER TaxonomyAdapter
        An optional scriptblock invoked with -Name for Kind=customer to validate
        the customer tag; it is a no-op when omitted.

    .PARAMETER Certificate
        An injected X509Certificate2 object. Injected certificates are
        context-only and cannot be persisted; passing one is an error.

    .PARAMETER TokenProvider
        An injected token-provider scriptblock. Providers are context-only and
        cannot be persisted; passing one is an error.

    .EXAMPLE
        Register-GraphTenant -ProfileId acme -Name Acme -Kind customer `
            -TenantId 3a4b5c6d-... -Environment Global -AuthMethod ClientSecret `
            -ClientId 7d6e5f44-... `
            -VaultName GraphKit -SecretName acme-client-secret

    .EXAMPLE
        Register-GraphTenant -ProfileId lab01 -Name Lab -Kind lab `
            -TenantId 3a4b5c6d-... -Environment Global -AuthMethod ManagedIdentity

    .EXAMPLE
        Register-GraphTenant -ProfileId contoso -Name 'Contoso' -Kind customer `
            -TenantId 3a4b5c6d-... -AuthMethod Certificate `
            -ClientId 7d6e5f44-... -PfxPath ./contoso.pfx `
            -PfxVaultName GraphKit -PfxSecretName contoso-pfx-password
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'CertificatePasswordVaultName', Justification = 'This value is a SecretManagement vault selector, not credential material.')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'CertificatePasswordSecretName', Justification = 'This value is a SecretManagement secret-name selector, not credential material.')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'CertificatePasswordVersion', Justification = 'This value is immutable generation metadata, not credential material.')]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $ProfileId,

        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [ValidateSet('customer', 'lab', 'internal')]
        [string] $Kind,

        [Parameter(Mandatory)]
        [string] $TenantId,

        [string] $ClientId,

        [Parameter(Mandatory)]
        [ValidateSet('Global', 'China', 'Germany', 'USGov', 'USGovDoD')]
        [string] $Environment,

        [Parameter(Mandatory)]
        [ValidateSet('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')]
        [string] $AuthMethod,

        [string] $VaultName,

        [string] $SecretName,

        [string] $SecretVersion,

        [string] $PfxPath,

        [string] $PfxVaultName,

        [string] $PfxSecretName,

        [string] $PfxSecretVersion,

        [string] $CertificateName,

        [string] $CertificateVersion,

        [string] $CertificatePasswordVaultName,

        [string] $CertificatePasswordSecretName,

        [string] $CertificatePasswordVersion,

        [string] $StoreLocation,

        [string] $StoreName,

        [string] $Thumbprint,

        [string] $Subject,

        [string] $ManagedIdentityClientId,

        [string] $StorePath,

        [scriptblock] $TaxonomyAdapter,

        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,

        [scriptblock] $TokenProvider
    )

    # Injected material is context-only and cannot be persisted.
    if ($null -ne $Certificate) {
        throw 'An injected X509Certificate2 cannot be persisted to the profile store. Use Get-GraphContext -Certificate to use it for a single context only.'
    }
    if ($null -ne $TokenProvider) {
        throw 'An injected token provider cannot be persisted to the profile store. Use Get-GraphContext -TokenProvider to use it for a single context only.'
    }

    if (-not (Test-GraphProfileId -ProfileId $ProfileId)) {
        throw "ProfileId '$ProfileId' is not a valid canonical profile identifier (expected ^[a-z0-9][a-z0-9-]{0,63}$)."
    }

    $tenantGuid = [guid]::Empty
    if (-not [guid]::TryParse([string]$TenantId, [ref]$tenantGuid)) {
        throw "TenantId '$TenantId' is not a valid GUID."
    }
    $tenantIdString = $tenantGuid.ToString()

    # Preserve the successor store's nullable top-level field for modes that do
    # not use an application client id. An explicitly supplied blank string is
    # still non-null metadata and the shared schema validator rejects it.
    $clientIdString = if ($PSBoundParameters.ContainsKey('ClientId')) {
        $ClientId
    }
    else {
        $null
    }

    switch ($AuthMethod) {
        'ClientSecret' {
            if ([string]::IsNullOrEmpty($VaultName)) { throw "AuthMethod 'ClientSecret' requires -VaultName." }
            if ([string]::IsNullOrEmpty($SecretName)) { throw "AuthMethod 'ClientSecret' requires -SecretName." }
            $credential = @{ VaultName = $VaultName; SecretName = $SecretName; Version = $SecretVersion }
        }
        'Certificate' {
            $hasPfx = -not [string]::IsNullOrEmpty($PfxPath)
            $hasVaultCert = -not [string]::IsNullOrEmpty($CertificateName)
            $hasStore = -not [string]::IsNullOrEmpty($StoreLocation) -or -not [string]::IsNullOrEmpty($StoreName)

            if ($hasPfx) {
                if ([string]::IsNullOrEmpty($PfxVaultName)) { throw "Certificate PFX requires -PfxVaultName." }
                if ([string]::IsNullOrEmpty($PfxSecretName)) { throw "Certificate PFX requires -PfxSecretName." }
                $credential = @{
                    PfxPath  = $PfxPath
                    Password = @{
                        VaultName  = $PfxVaultName
                        SecretName = $PfxSecretName
                        Version    = $PfxSecretVersion
                    }
                }
            }
            elseif ($hasVaultCert) {
                if ([string]::IsNullOrEmpty($VaultName)) { throw "Vault certificate material requires -VaultName." }
                $credential = @{ VaultName = $VaultName; CertificateName = $CertificateName; Version = $CertificateVersion }

                $hasPasswordVault = -not [string]::IsNullOrEmpty($CertificatePasswordVaultName)
                $hasPasswordName = -not [string]::IsNullOrEmpty($CertificatePasswordSecretName)
                if ($hasPasswordVault -ne $hasPasswordName) {
                    throw 'Vault certificate password parameters must include both -CertificatePasswordVaultName and -CertificatePasswordSecretName.'
                }
                if ($hasPasswordVault) {
                    $credential.Password = @{
                        VaultName  = $CertificatePasswordVaultName
                        SecretName = $CertificatePasswordSecretName
                        Version    = $CertificatePasswordVersion
                    }
                }
            }
            elseif ($hasStore) {
                # Windows-only, declared as such; never the sole supported shape.
                if (-not $IsWindows) {
                    throw "Certificate store lookup is Windows-only; this platform is $($PSVersionTable.Platform). Use -PfxPath or vault certificate material instead."
                }
                $credential = @{ StoreLocation = $StoreLocation; StoreName = $StoreName; Thumbprint = $Thumbprint; Subject = $Subject }
            }
            else {
                throw "AuthMethod 'Certificate' requires -PfxPath (+ vault-backed password), -CertificateName (+ -VaultName), or a store lookup (-StoreLocation/-StoreName)."
            }
        }
        'BearerToken' {
            if ([string]::IsNullOrEmpty($VaultName)) { throw "AuthMethod 'BearerToken' requires -VaultName." }
            if ([string]::IsNullOrEmpty($SecretName)) { throw "AuthMethod 'BearerToken' requires -SecretName." }
            $credential = @{ VaultName = $VaultName; SecretName = $SecretName; Version = $SecretVersion }
        }
        'ManagedIdentity' {
            $credential = @{}
            if ($PSBoundParameters.ContainsKey('ManagedIdentityClientId')) {
                $credential.ClientId = $ManagedIdentityClientId
            }
        }
    }

    if ($AuthMethod -ne 'ManagedIdentity' -and
        $PSBoundParameters.ContainsKey('ManagedIdentityClientId')) {
        # Registration accepts the public spelling only as input. Represent a
        # contradictory use as alternate nested metadata so the one persisted-
        # schema validator rejects it with the same matrix used everywhere else.
        $credential.ManagedIdentityClientId = $ManagedIdentityClientId
    }

    $schema = Assert-GraphTenantProfileAuthSchema -Profile @{
        AuthMethod = $AuthMethod
        ClientId   = $clientIdString
        Credential = $credential
    }
    $clientIdString = $schema.ApplicationClientId
    if ($AuthMethod -eq 'ManagedIdentity') {
        if ([string]::IsNullOrEmpty([string] $schema.ManagedIdentityClientId)) {
            $null = $credential.Remove('ClientId')
        }
        else {
            $credential.ClientId = $schema.ManagedIdentityClientId
        }
    }

    if ($Kind -eq 'customer' -and $null -ne $TaxonomyAdapter) {
        # The CDW adapter validates Name against the customer tag list; a
        # mismatch throws. Without an adapter this is a deliberate no-op.
        & $TaxonomyAdapter -Name $Name
    }

    if ([string]::IsNullOrEmpty($StorePath)) {
        $StorePath = Join-Path $HOME '.graphkit/profiles.json'
    }

    $newProfile = @{
        ProfileId   = $ProfileId
        Name        = $Name
        Kind        = $Kind
        TenantId    = $tenantIdString
        ClientId    = $clientIdString
        AuthMethod  = $AuthMethod
        Environment = $Environment
        Credential  = $credential
    }

    $lock = Enter-GraphProfileStoreLock -StorePath $StorePath
    try {
        $store = Get-GraphProfileStore -StorePath $StorePath

        if ($store.Profiles | Where-Object { $_.ProfileId -eq $ProfileId }) {
            throw "A profile with ProfileId '$ProfileId' already exists in '$StorePath'. Remove it first or choose another ProfileId."
        }

        $store.Profiles = @($store.Profiles) + $newProfile
        Save-GraphProfileStore -Store $store -StorePath $StorePath
    }
    finally {
        Exit-GraphProfileStoreLock -Lock $lock
    }

    return $newProfile
}
