<#
    Private: resolve a persisted credential reference into acquisition material.

    Resolves the discriminated credential shapes persisted by Register-GraphTenant
    into the concrete material a token source consumes, without acquiring a token
    or touching the network. Vault-backed shapes are resolved lazily and on demand:
    a missing SecretManagement vault extension must never break module import, so
    managed identity, injected credentials, Get-Help and catalog inspection (none
    of which touch a persisted credential) stay usable. Vault validation runs here,
    only when a shape actually reads a vault, and fails with an actionable message
    naming SecretManagement and how to register a vault.

    All SecretManagement commands (Get-Secret, Get-SecretVault) are invoked as
    plain commands so tests can mock them scoped to the GraphKit module.

    Shapes discriminated by -AuthMethod plus the keys present in -Credential:
      ClientSecret            vault secret              -> SecureString
      Certificate (PFX)       PFX path + vault password  -> X509Certificate2
      Certificate (vault)     vault certificate bytes    -> X509Certificate2
      Certificate (store)     Windows cert: store lookup -> X509Certificate2
      BearerToken             vault secret              -> plain-text string
      ManagedIdentity         ClientId or $null          -> no vault call

    X509Certificate2 instances returned here are created by GraphKit, so the caller
    owns and disposes them. Caller-injected certificates and token providers never
    pass through this function (they are context-only and never persisted).
#>

function Get-GraphVaultCredential {
    [CmdletBinding()]
    # Material is X509Certificate2 (caller-owned, caller-disposed), SecureString,
    # string, or $null (managed identity).
    [OutputType([System.Management.Automation.PSCustomObject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [hashtable] $Credential,

        [string] $VaultName,

        [Parameter(Mandatory)]
        [ValidateSet('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')]
        [string] $AuthMethod
    )

    switch ($AuthMethod) {
        'ClientSecret' {
            $vault = Resolve-GraphVaultName -Credential $Credential -DefaultVault $VaultName
            $secretName = [string] $Credential.SecretName
            if ([string]::IsNullOrEmpty($secretName)) {
                throw "AuthMethod 'ClientSecret' is missing a SecretName in the persisted credential; cannot resolve the client secret from the vault."
            }

            Assert-GraphVaultRegistered -VaultName $vault
            $secret = Get-GraphSecret -Vault $vault -Name $secretName -Version ([string] $Credential.Version)
            $secret = ConvertTo-GraphSecureString -Value $secret

            return New-GraphCredentialMaterial -AuthMethod 'ClientSecret' -Material $secret
        }

        'BearerToken' {
            $vault = Resolve-GraphVaultName -Credential $Credential -DefaultVault $VaultName
            $secretName = [string] $Credential.SecretName
            if ([string]::IsNullOrEmpty($secretName)) {
                throw "AuthMethod 'BearerToken' is missing a SecretName in the persisted credential; cannot resolve the bearer token from the vault."
            }

            Assert-GraphVaultRegistered -VaultName $vault
            $secret = Get-GraphSecret -Vault $vault -Name $secretName -Version ([string] $Credential.Version)
            $plain = if ($secret -is [System.Security.SecureString]) {
                [System.Net.NetworkCredential]::new('', $secret).Password
            }
            else {
                [string] $secret
            }

            if ([string]::IsNullOrEmpty($plain)) {
                throw "Secret '$secretName' in vault '$vault' resolved to an empty bearer token."
            }

            return New-GraphCredentialMaterial -AuthMethod 'BearerToken' -Material $plain
        }

        'Certificate' {
            if ($Credential.ContainsKey('PfxPath') -and -not [string]::IsNullOrEmpty([string] $Credential.PfxPath)) {
                $password = Resolve-GraphVaultPassword -Password $Credential.Password -DefaultVault $VaultName
                if ($null -eq $password) {
                    throw "Certificate (PFX) requires a vault-backed password reference (Password = @{ VaultName; SecretName }) alongside PfxPath."
                }

                try {
                    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([string] $Credential.PfxPath, $password)
                }
                catch {
                    throw "Could not load the PFX certificate from '$($Credential.PfxPath)': $($_.Exception.Message)"
                }

                return New-GraphCredentialMaterial -AuthMethod 'Certificate' -Material $cert
            }

            if ($Credential.ContainsKey('CertificateName') -and -not [string]::IsNullOrEmpty([string] $Credential.CertificateName)) {
                $vault = Resolve-GraphVaultName -Credential $Credential -DefaultVault $VaultName
                Assert-GraphVaultRegistered -VaultName $vault

                $raw = Get-GraphSecret -Vault $vault -Name ([string] $Credential.CertificateName) -Version ([string] $Credential.Version)
                $password = Resolve-GraphVaultPassword -Password $Credential.Password -DefaultVault $VaultName
                $cert = ConvertTo-GraphCertificate -Raw $raw -VaultName $vault -SecretName ([string] $Credential.CertificateName) -Password $password

                return New-GraphCredentialMaterial -AuthMethod 'Certificate' -Material $cert
            }

            if ($Credential.ContainsKey('StoreLocation') -or $Credential.ContainsKey('StoreName') -or $Credential.ContainsKey('Thumbprint') -or $Credential.ContainsKey('Subject')) {
                $cert = Get-GraphStoreCertificate -Credential $Credential
                return New-GraphCredentialMaterial -AuthMethod 'Certificate' -Material $cert
            }

            throw "AuthMethod 'Certificate' requires a persisted credential with a PfxPath (+ vault-backed Password), a CertificateName (+ VaultName), or a store lookup (StoreLocation/StoreName with Thumbprint or Subject)."
        }

        'ManagedIdentity' {
            $clientId = $Credential.ClientId
            if ($null -ne $clientId) {
                $clientId = [string] $clientId
            }
            return New-GraphCredentialMaterial -AuthMethod 'ManagedIdentity' -Material $null -ManagedIdentityClientId $clientId
        }
    }
}

function Resolve-GraphVaultName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Credential,

        [string] $DefaultVault
    )

    $vault = [string] $Credential.VaultName
    if ([string]::IsNullOrEmpty($vault)) {
        $vault = [string] $DefaultVault
    }
    return $vault
}

function Assert-GraphVaultRegistered {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $VaultName
    )

    if ([string]::IsNullOrEmpty($VaultName)) {
        throw "No SecretManagement vault name was supplied. Register a vault with 'Register-SecretVault -Name <vault> -ModuleName <module>' (for example, install an extension with 'Install-Module Microsoft.PowerShell.SecretStore') and reference it in the credential, or pass -VaultName."
    }

    $vault = Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue
    if ($null -eq $vault) {
        throw "The SecretManagement vault '$VaultName' is not registered. Install a vault extension (for example, 'Install-Module Microsoft.PowerShell.SecretStore') and register it with 'Register-SecretVault -Name $VaultName -ModuleName <ModuleName>', or register the vault you intend to use. GraphKit resolves vault-backed credentials on demand and does not require a registered vault at import time."
    }
}

function Get-GraphSecret {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [string] $Vault,

        [Parameter(Mandatory)]
        [string] $Name,

        [string] $Version
    )

    $params = @{ Vault = $Vault; Name = $Name; ErrorAction = 'SilentlyContinue' }
    if (-not [string]::IsNullOrEmpty($Version)) {
        $getSecret = Get-Command Get-Secret -ErrorAction SilentlyContinue
        if ($null -eq $getSecret -or -not $getSecret.Parameters.ContainsKey('Version')) {
            throw "A secret version ('$Version') was requested for '$Name' but the loaded Microsoft.PowerShell.SecretManagement does not support per-secret versions. Store each version under a distinct secret name, or upgrade SecretManagement."
        }
        $params['Version'] = $Version
    }

    $secret = Get-Secret @params
    if ($null -eq $secret) {
        throw "Secret '$Name' was not found in vault '$Vault'."
    }
    return $secret
}

function Resolve-GraphVaultPassword {
    [CmdletBinding()]
    [OutputType([System.Security.SecureString])]
    param(
        [object] $Password,

        [string] $DefaultVault
    )

    if ($null -eq $Password) {
        return $null
    }
    if ($Password -is [System.Security.SecureString]) {
        return $Password
    }
    if ($Password -is [hashtable]) {
        $vault = [string] $Password.VaultName
        if ([string]::IsNullOrEmpty($vault)) {
            $vault = [string] $DefaultVault
        }
        $secretName = [string] $Password.SecretName
        if ([string]::IsNullOrEmpty($secretName)) {
            throw "A vault-backed password reference is missing a SecretName."
        }

        Assert-GraphVaultRegistered -VaultName $vault
        $secret = Get-GraphSecret -Vault $vault -Name $secretName -Version ([string] $Password.Version)
        return ConvertTo-GraphSecureString -Value $secret
    }

    $secure = ConvertTo-GraphSecureString -Value $Password
    return $secure
}

function ConvertTo-GraphSecureString {
    [CmdletBinding()]
    [OutputType([System.Security.SecureString])]
    param(
        [Parameter(Mandatory)]
        [object] $Value
    )

    if ($Value -is [System.Security.SecureString]) {
        return $Value
    }
    if ($Value -is [string]) {
        $secure = [System.Security.SecureString]::new()
        foreach ($ch in ([string] $Value).ToCharArray()) {
            $secure.AppendChar($ch)
        }
        return $secure
    }

    throw "Cannot convert material of type '$($Value.GetType().FullName)' to a SecureString; provide a SecureString or a plain-text string."
}

function ConvertTo-GraphCertificate {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        [Parameter(Mandatory)]
        [object] $Raw,

        [Parameter(Mandatory)]
        [string] $VaultName,

        [Parameter(Mandatory)]
        [string] $SecretName,

        [System.Security.SecureString] $Password
    )

    # A byte[] flattened by PowerShell pipeline enumeration into an object[]
    # (for example, a mock returning a byte[] through the pipeline) is reassembled.
    if ($Raw -is [System.Array] -and $Raw -isnot [byte[]]) {
        $Raw = [byte[]] @($Raw)
    }

    $bytes = $null
    if ($Raw -is [byte[]]) {
        $bytes = $Raw
    }
    elseif ($Raw -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
        return $Raw
    }
    elseif ($Raw -is [System.Security.SecureString]) {
        $plain = [System.Net.NetworkCredential]::new('', $Raw).Password
        $bytes = ConvertTo-GraphCertificateBytes -Text $plain -VaultName $VaultName -SecretName $SecretName
    }
    elseif ($Raw -is [string]) {
        $bytes = ConvertTo-GraphCertificateBytes -Text $Raw -VaultName $VaultName -SecretName $SecretName
    }
    else {
        throw "The certificate secret '$SecretName' in vault '$VaultName' has unsupported material type '$($Raw.GetType().FullName)'. Supported shapes: a PFX byte array (byte[]), a base64-encoded PFX string, or a path to a PFX file."
    }

    # ConvertTo-GraphCertificateBytes output is flattened by pipeline
    # enumeration, so the bytes arrive as object[]; reassemble them so the
    # X509Certificate2 constructor binds the byte[] overload instead of
    # coercing the enumerated bytes into a space-joined file-path string.
    $bytes = [byte[]] $bytes

    try {
        if ($null -ne $Password) {
            return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes, $Password)
        }
        return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
    }
    catch {
        throw "The certificate secret '$SecretName' in vault '$VaultName' could not be interpreted as a PFX: $($_.Exception.Message)"
    }
}

function ConvertTo-GraphCertificateBytes {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [string] $Text,

        [Parameter(Mandatory)]
        [string] $VaultName,

        [Parameter(Mandatory)]
        [string] $SecretName
    )

    # A base64-encoded PFX is the most common string form.
    try {
        return [System.Convert]::FromBase64String($Text)
    }
    catch {
        # Not base64; fall through to a PFX file path.
    }

    if (Test-Path -LiteralPath $Text -PathType Leaf) {
        return [System.IO.File]::ReadAllBytes($Text)
    }

    throw "The certificate secret '$SecretName' in vault '$VaultName' is neither a PFX byte array, a base64-encoded PFX, nor a path to a PFX file. Supported shapes: a PFX byte array (byte[]), a base64-encoded PFX string, or a path to a PFX file."
}

function Get-GraphStoreCertificate {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Credential
    )

    if (-not $IsWindows) {
        throw "Certificate store lookup is Windows-only; this platform is $($PSVersionTable.Platform). Use a PFX path with a vault-backed password, or vault certificate material, instead."
    }

    $location = [string] $Credential.StoreLocation
    if ([string]::IsNullOrEmpty($location)) {
        $location = 'CurrentUser'
    }
    $storeName = [string] $Credential.StoreName
    if ([string]::IsNullOrEmpty($storeName)) {
        $storeName = 'My'
    }

    $thumbprint = [string] $Credential.Thumbprint
    $subject = [string] $Credential.Subject
    if ([string]::IsNullOrEmpty($thumbprint) -and [string]::IsNullOrEmpty($subject)) {
        throw "Certificate store lookup requires a Thumbprint or Subject to select a certificate."
    }

    $certs = Get-ChildItem -Path "Cert:\$location\$storeName" -ErrorAction Stop

    $match = $null
    if (-not [string]::IsNullOrEmpty($thumbprint)) {
        $match = $certs | Where-Object { $_.Thumbprint -eq $thumbprint.Replace(' ', '') } | Select-Object -First 1
    }
    else {
        $match = $certs | Where-Object { $_.Subject -like "*$subject*" } | Select-Object -First 1
    }

    if ($null -eq $match) {
        $selector = if ($thumbprint) { "thumbprint '$thumbprint'" } else { "subject '$subject'" }
        throw "No certificate matching $selector was found in the Cert:\$location\$storeName store."
    }

    return $match
}

function New-GraphCredentialMaterial {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string] $AuthMethod,

        [object] $Material,

        [object] $ManagedIdentityClientId
    )

    return [PSCustomObject]@{
        PSTypeName              = 'GraphKit.CredentialMaterial'
        AuthMethod              = $AuthMethod
        Material                = $Material
        ManagedIdentityClientId = $ManagedIdentityClientId
    }
}
