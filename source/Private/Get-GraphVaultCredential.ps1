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

    First vault use requires and imports Microsoft.PowerShell.SecretManagement 1.1.2 or
    newer. Its Get-Secret and Get-SecretVault commands are always invoked module-qualified;
    an unrelated function with the same name can never satisfy the dependency boundary.

    Shapes discriminated by -AuthMethod plus the keys present in -Credential:
      ClientSecret            vault secret              -> SecureString
      Certificate (PFX)       PFX path + vault password  -> X509Certificate2
      Certificate (vault)     vault certificate bytes    -> X509Certificate2
      Certificate (store)     Windows cert: store lookup -> X509Certificate2
      BearerToken             vault secret              -> plain-text string
      ManagedIdentity         ClientId or $null          -> no vault call

    Credential material carries explicit OwnsMaterial metadata. Certificates
    constructed from persisted PFX bytes/files and copies of provider-returned
    certificates are GraphKit-owned; caller-injected certificates never pass
    through this function and remain caller-owned.
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

            Assert-GraphSecretVersionSupported -Name $secretName -Version ([string] $Credential.Version)
            Assert-GraphVaultRegistered -VaultName $vault
            $secret = Get-GraphSecret -Vault $vault -Name $secretName -Version ([string] $Credential.Version)
            $secret = ConvertTo-GraphSecureString -Value $secret

            $generation = Get-GraphCredentialGeneration -TenantProfile @{
                AuthMethod = 'ClientSecret'
                Credential = $Credential
            }

            return New-GraphCredentialMaterial -AuthMethod 'ClientSecret' -Material $secret `
                -OwnsMaterial:$true -CredentialGeneration $generation
        }

        'BearerToken' {
            $vault = Resolve-GraphVaultName -Credential $Credential -DefaultVault $VaultName
            $secretName = [string] $Credential.SecretName
            if ([string]::IsNullOrEmpty($secretName)) {
                throw "AuthMethod 'BearerToken' is missing a SecretName in the persisted credential; cannot resolve the bearer token from the vault."
            }

            Assert-GraphSecretVersionSupported -Name $secretName -Version ([string] $Credential.Version)
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

            $generation = Get-GraphCredentialGeneration -TenantProfile @{
                AuthMethod = 'BearerToken'
                Credential = $Credential
            }
            return New-GraphCredentialMaterial -AuthMethod 'BearerToken' -Material $plain `
                -CredentialGeneration $generation
        }

        'Certificate' {
            if ($Credential.ContainsKey('PfxPath') -and -not [string]::IsNullOrEmpty([string] $Credential.PfxPath)) {
                $password = $null
                $snapshot = $null
                try {
                    $password = Resolve-GraphVaultPassword -Password $Credential.Password -DefaultVault $VaultName
                    if ($null -eq $password) {
                        throw "Certificate (PFX) requires a vault-backed password reference (Password = @{ VaultName; SecretName }) alongside PfxPath."
                    }

                    $snapshot = Get-GraphPfxSnapshot -Path ([string] $Credential.PfxPath)
                    try {
                        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                            [byte[]] $snapshot.Bytes,
                            $password
                        )
                    }
                    catch {
                        throw "Could not load the PFX certificate from '$($Credential.PfxPath)': $($_.Exception.Message)"
                    }

                    $generation = Get-GraphCredentialGeneration `
                        -TenantProfile @{ AuthMethod = 'Certificate'; Credential = $Credential } `
                        -PfxContentSha256 ([string] $snapshot.Sha256) `
                        -PfxCanonicalPath ([string] $snapshot.Path)

                    return New-GraphCredentialMaterial -AuthMethod 'Certificate' -Material $cert `
                        -OwnsMaterial:$true -CredentialGeneration $generation
                }
                finally {
                    if ($null -ne $password) {
                        $password.Dispose()
                    }
                    if ($null -ne $snapshot -and $snapshot.Bytes -is [byte[]]) {
                        [System.Security.Cryptography.CryptographicOperations]::ZeroMemory(
                            [byte[]] $snapshot.Bytes
                        )
                    }
                }
            }

            if ($Credential.ContainsKey('CertificateName') -and -not [string]::IsNullOrEmpty([string] $Credential.CertificateName)) {
                Assert-GraphSecretVersionSupported `
                    -Name ([string] $Credential.CertificateName) `
                    -Version ([string] $Credential.Version)
                Assert-GraphVaultPasswordReference -Password $Credential.Password
                $vault = Resolve-GraphVaultName -Credential $Credential -DefaultVault $VaultName
                Assert-GraphVaultRegistered -VaultName $vault

                $password = $null
                try {
                    $raw = Get-GraphSecret -Vault $vault -Name ([string] $Credential.CertificateName) -Version ([string] $Credential.Version)
                    $password = Resolve-GraphVaultPassword -Password $Credential.Password -DefaultVault $VaultName
                    $cert = ConvertTo-GraphCertificate -Raw $raw -VaultName $vault -SecretName ([string] $Credential.CertificateName) -Password $password

                    $generation = Get-GraphCredentialGeneration -TenantProfile @{
                        AuthMethod = 'Certificate'
                        Credential = $Credential
                    }
                    return New-GraphCredentialMaterial -AuthMethod 'Certificate' -Material $cert `
                        -OwnsMaterial:$true -CredentialGeneration $generation
                }
                finally {
                    if ($null -ne $password) {
                        $password.Dispose()
                    }
                }
            }

            if ($Credential.ContainsKey('StoreLocation') -or $Credential.ContainsKey('StoreName') -or $Credential.ContainsKey('Thumbprint') -or $Credential.ContainsKey('Subject')) {
                $cert = Get-GraphStoreCertificate -Credential $Credential
                $generation = Get-GraphCredentialGeneration -TenantProfile @{
                    AuthMethod = 'Certificate'
                    Credential = $Credential
                }
                return New-GraphCredentialMaterial -AuthMethod 'Certificate' -Material $cert `
                    -OwnsMaterial:$true -CredentialGeneration $generation
            }

            throw "AuthMethod 'Certificate' requires a persisted credential with a PfxPath (+ vault-backed Password), a CertificateName (+ VaultName), or a store lookup (StoreLocation/StoreName with Thumbprint or Subject)."
        }

        'ManagedIdentity' {
            $clientId = $Credential.ClientId
            if ($null -ne $clientId) {
                $clientId = [string] $clientId
            }
            $generation = Get-GraphCredentialGeneration -TenantProfile @{
                AuthMethod = 'ManagedIdentity'
                Credential = $Credential
            }
            return New-GraphCredentialMaterial -AuthMethod 'ManagedIdentity' -Material $null `
                -ManagedIdentityClientId $clientId -CredentialGeneration $generation
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

$script:GraphSecretManagementMinimumVersion = [version] '1.1.2'

function Import-GraphSecretManagement {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSModuleInfo])]
    param()

    $moduleName = 'Microsoft.PowerShell.SecretManagement'
    $minimum = $script:GraphSecretManagementMinimumVersion

    # A too-old loaded copy is an ambiguous command boundary even when a newer copy is also
    # installed: module-qualified invocation names the module, not its version. Fail loudly
    # instead of depending on PowerShell's loaded-module resolution order.
    $loaded = @(Get-Module -Name $moduleName)
    $oldLoaded = @($loaded | Where-Object { $_.Version -lt $minimum } | Sort-Object Version -Descending)
    if ($oldLoaded.Count -gt 0) {
        throw "$moduleName $minimum or newer is required for vault-backed credentials, but v$($oldLoaded[0].Version) is already loaded. Remove the old module from this process and install/import at least v$minimum before retrying."
    }

    $selected = @($loaded | Where-Object { $_.Version -ge $minimum } | Sort-Object Version -Descending | Select-Object -First 1)
    if ($selected.Count -eq 0) {
        $available = @(Get-Module -Name $moduleName -ListAvailable -Refresh | Sort-Object Version -Descending)
        $candidate = @($available | Where-Object { $_.Version -ge $minimum } | Select-Object -First 1)
        if ($candidate.Count -eq 0) {
            if ($available.Count -gt 0) {
                throw "$moduleName $minimum or newer is required for vault-backed credentials; the newest discoverable version is v$($available[0].Version). Upgrade it with 'Install-Module $moduleName -MinimumVersion $minimum -Force', then retry."
            }
            throw "GraphKit vault-backed credentials require $moduleName. Install the tested minimum with 'Install-Module $moduleName -MinimumVersion $minimum', then install and register a vault extension with Register-SecretVault. Non-vault GraphKit flows do not require this module."
        }

        try {
            $selected = @(Import-Module -Name $candidate[0].Path -PassThru -ErrorAction Stop |
                    Where-Object { $_.Name -eq $moduleName -and $_.Version -ge $minimum } |
                    Sort-Object Version -Descending | Select-Object -First 1)
        }
        catch {
            throw "Could not import $moduleName v$($candidate[0].Version) for vault-backed credentials: $($_.Exception.Message)"
        }
    }

    if ($selected.Count -eq 0) {
        throw "$moduleName was discovered but no loaded module met the required minimum version $minimum after import."
    }

    $vaultCommand = Get-Command -Name Get-SecretVault -Module $moduleName -CommandType Function, Cmdlet -ErrorAction Ignore
    $secretCommand = Get-Command -Name Get-Secret -Module $moduleName -CommandType Function, Cmdlet -ErrorAction Ignore
    if ($null -eq $vaultCommand -or $null -eq $secretCommand) {
        throw "$moduleName v$($selected[0].Version) does not export both Get-SecretVault and Get-Secret; reinstall a complete module package before retrying."
    }

    return $selected[0]
}

function Invoke-GraphSecretManagementGetVault {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [System.Management.Automation.ActionPreference] $SecretErrorAction = 'SilentlyContinue'
    )

    Microsoft.PowerShell.SecretManagement\Get-SecretVault -Name $Name -ErrorAction $SecretErrorAction
}

function Invoke-GraphSecretManagementGetSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Vault,
        [Parameter(Mandatory)] [string] $Name,
        [string] $Version,
        [System.Management.Automation.ActionPreference] $SecretErrorAction = 'SilentlyContinue'
    )

    $params = @{ Vault = $Vault; Name = $Name; ErrorAction = $SecretErrorAction }
    if (-not [string]::IsNullOrEmpty($Version)) { $params['Version'] = $Version }
    Microsoft.PowerShell.SecretManagement\Get-Secret @params
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

    $null = Import-GraphSecretManagement
    $vault = Invoke-GraphSecretManagementGetVault -Name $VaultName -SecretErrorAction SilentlyContinue
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

    $params = @{ Vault = $Vault; Name = $Name; SecretErrorAction = 'SilentlyContinue' }
    Assert-GraphSecretVersionSupported -Name $Name -Version $Version
    if (-not [string]::IsNullOrEmpty($Version)) {
        $params['Version'] = $Version
    }

    $secret = Invoke-GraphSecretManagementGetSecret @params
    if ($null -eq $secret) {
        throw "Secret '$Name' was not found in vault '$Vault'."
    }
    return $secret
}

function Assert-GraphSecretVersionSupported {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [string] $Version
    )

    if ([string]::IsNullOrEmpty($Version)) {
        return
    }

    $null = Import-GraphSecretManagement
    $getSecret = Get-Command -Name Get-Secret -Module Microsoft.PowerShell.SecretManagement -ErrorAction SilentlyContinue
    if ($null -eq $getSecret -or -not $getSecret.Parameters.ContainsKey('Version')) {
        throw "A secret version ('$Version') was requested for '$Name' but the loaded Microsoft.PowerShell.SecretManagement does not support per-secret versions. Store each immutable generation under a distinct secret name; Version metadata cannot be resolved through this Get-Secret API."
    }
}

function Assert-GraphVaultPasswordReference {
    [CmdletBinding()]
    param([object] $Password)

    if ($Password -isnot [hashtable]) {
        return
    }

    $secretName = [string] $Password.SecretName
    if ([string]::IsNullOrEmpty($secretName)) {
        throw 'A vault-backed password reference is missing a SecretName.'
    }
    Assert-GraphSecretVersionSupported -Name $secretName -Version ([string] $Password.Version)
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
        # A directly supplied SecureString is caller-owned. The certificate
        # resolver disposes only this private copy after import.
        return $Password.Copy()
    }
    if ($Password -is [hashtable]) {
        Assert-GraphVaultPasswordReference -Password $Password
        $vault = [string] $Password.VaultName
        if ([string]::IsNullOrEmpty($vault)) {
            $vault = [string] $DefaultVault
        }
        $secretName = [string] $Password.SecretName

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
        # Vault/provider-returned SecureString instances remain provider-owned.
        # Callers of this helper explicitly own and dispose the returned copy.
        return $Value.Copy()
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

    $bytes = $null
    # A byte[] flattened by PowerShell pipeline enumeration into an object[]
    # (for example, a provider returning a byte[] through the pipeline) is
    # reassembled directly into the one GraphKit-owned import buffer. Avoid a
    # second clone whose first copy would otherwise survive until GC.
    if ($Raw -is [System.Array] -and $Raw -isnot [byte[]]) {
        $bytes = [byte[]] @($Raw)
    }
    elseif ($Raw -is [byte[]]) {
        # Never zero provider-owned material. Import from a private copy and
        # deterministically clear that copy below on success or failure.
        $bytes = [byte[]] $Raw.Clone()
    }
    elseif ($Raw -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
        # Never retain or later dispose a provider-owned certificate object.
        # X509Certificate2's copy constructor duplicates its native context and
        # preserves the private-key association without exporting key material.
        try {
            return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Raw)
        }
        catch {
            throw "The certificate secret '$SecretName' in vault '$VaultName' could not be copied into GraphKit-owned material: $($_.Exception.Message)"
        }
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
    finally {
        if ($bytes -is [byte[]]) {
            [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)
        }
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

    # A certificate without an accessible private key cannot sign a client assertion. Without
    # this check the store lookup succeeds and the failure surfaces later inside MSAL, where
    # the message is about assertion signing rather than about the certificate the operator
    # actually chose. This is the common Windows case: the public certificate is installed,
    # the key is not, or the process lacks rights to it in LocalMachine.
    if (-not $match.HasPrivateKey) {
        throw "Certificate '$($match.Thumbprint)' in Cert:\$location\$storeName has no accessible private key, so it cannot sign a client assertion. Import the PFX with its key, and for LocalMachine make sure this process has permission to read it."
    }

    try {
        # The certificate-provider wrapper remains provider-owned. Return a
        # GraphKit-owned duplicate so module cleanup never disposes that wrapper.
        return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($match)
    }
    catch {
        throw "Certificate '$($match.Thumbprint)' in Cert:\$location\$storeName could not be copied into GraphKit-owned material: $($_.Exception.Message)"
    }
}

function New-GraphCredentialMaterial {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string] $AuthMethod,

        [object] $Material,

        [object] $ManagedIdentityClientId,

        [bool] $OwnsMaterial = $false,

        [string] $CredentialGeneration
    )

    return [PSCustomObject]@{
        PSTypeName              = 'GraphKit.CredentialMaterial'
        AuthMethod              = $AuthMethod
        Material                = $Material
        ManagedIdentityClientId = $ManagedIdentityClientId
        OwnsMaterial            = $OwnsMaterial
        CredentialGeneration    = $CredentialGeneration
    }
}
