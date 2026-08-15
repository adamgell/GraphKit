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
        The application (client) GUID. May be omitted for a fixed bearer or a
        system-assigned managed identity.

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
        Optional SecretManagement version of the client secret or bearer token.

    .PARAMETER PfxPath
        The path to a PFX certificate file (Certificate AuthMethod, PFX shape).

    .PARAMETER PfxVaultName
        The SecretManagement vault holding the PFX password (PFX shape).

    .PARAMETER PfxSecretName
        The secret name holding the PFX password within that vault (PFX shape).

    .PARAMETER CertificateName
        The vault certificate name (Certificate AuthMethod, vault-material
        shape).

    .PARAMETER CertificateVersion
        Optional SecretManagement version of the vault certificate material.

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
        The user-assigned managed identity client GUID; omit for a
        system-assigned managed identity.

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
            -VaultName GraphKit -SecretName acme-client-secret

    .EXAMPLE
        Register-GraphTenant -ProfileId lab01 -Name Lab -Kind lab `
            -TenantId 3a4b5c6d-... -Environment Global -AuthMethod ManagedIdentity

    .EXAMPLE
        Register-GraphTenant -ProfileId ivy24 -Name Ivy24 -Kind lab `
            -TenantId 3a4b5c6d-... -AuthMethod Certificate -PfxPath ./ivy24.pfx `
            -PfxVaultName GraphKit -PfxSecretName ivy24-pfx-password
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
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

        [string] $CertificateName,

        [string] $CertificateVersion,

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

    $clientIdString = $null
    if (-not [string]::IsNullOrEmpty($ClientId)) {
        $clientGuid = [guid]::Empty
        if (-not [guid]::TryParse([string]$ClientId, [ref]$clientGuid)) {
            throw "ClientId '$ClientId' is not a valid GUID."
        }
        $clientIdString = $clientGuid.ToString()
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
                    Password = @{ VaultName = $PfxVaultName; SecretName = $PfxSecretName }
                }
            }
            elseif ($hasVaultCert) {
                if ([string]::IsNullOrEmpty($VaultName)) { throw "Vault certificate material requires -VaultName." }
                $credential = @{ VaultName = $VaultName; CertificateName = $CertificateName; Version = $CertificateVersion }
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
            $credential = @{ ClientId = $ManagedIdentityClientId }
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
