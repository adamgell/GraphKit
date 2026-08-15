<#
    Private: the real MSAL confidential-client factory.

    This is the piece that connects resolved credential material to an actual MSAL
    application. Without it every auth method threw "MSAL confidential-client resolution
    is not wired ... pass -MsalFactory", which meant GraphKit could not acquire a token by
    any means unless a caller injected a factory. Every test injected one, so the whole
    suite passed against a module that had never authenticated to anything.

    The factory is built LAZILY: New-GraphTokenSource returns a source whose Acquire has
    not yet run, and constructing a source must never acquire a token or touch the vault.
    The credential is therefore resolved inside the returned scriptblock, on first use.

    MSAL performs the certificate assertion signing (RS256, x5t, jti, validity window),
    which is the reason GraphKit depends on it rather than hand-rolling client
    credentials: GraphKit writes no OAuth cryptography.
#>
function New-GraphMsalApplicationFactory {
    [CmdletBinding()]
    [OutputType([scriptblock])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Profile,

        [Parameter(Mandatory)]
        [hashtable] $Cloud,

        # Injected for tests: resolves the profile's credential to material. Defaults to
        # the real vault-backed resolver.
        [scriptblock] $CredentialResolver
    )

    $authority = '{0}/{1}' -f ([string] $Cloud.Authority).TrimEnd('/'), [string] $Profile.TenantId
    $clientId = [string] $Profile.ClientId
    $authMethod = [string] $Profile.AuthMethod
    $profileCopy = $Profile

    # The command reference is captured HERE, while module scope is still in view. The
    # returned scriptblock is invoked from inside a PowerShell class method, where
    # module-private functions are NOT resolvable by name - calling them by name there
    # fails with "term not recognized". Closing over the resolved command is what makes
    # the lazy factory work from a class.
    #
    # No MSAL version assert is needed here: the guard in Assert-GraphMsalEnvironment.ps1
    # runs at module import, so a version below the tested minimum has already failed the
    # import before any factory can be built.
    $vaultResolve = Get-Command -Name Get-GraphVaultCredential -CommandType Function

    $resolver = $CredentialResolver
    if ($null -eq $resolver) {
        $resolver = { param($P) & $vaultResolve -Credential $P.Credential -AuthMethod $P.AuthMethod }.GetNewClosure()
    }

    return {
        $material = & $resolver $profileCopy
        if ($null -eq $material) {
            throw "GraphKit could not resolve credential material for tenant '$($profileCopy.TenantId)'."
        }

        $builder = [Microsoft.Identity.Client.ConfidentialClientApplicationBuilder]::Create($clientId)

        switch ($authMethod) {
            'Certificate' {
                $certificate = $material.Material
                if ($certificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
                    throw "Certificate profile for tenant '$($profileCopy.TenantId)' resolved to '$($certificate.GetType().Name)' rather than an X509Certificate2."
                }
                if (-not $certificate.HasPrivateKey) {
                    throw "The certificate for tenant '$($profileCopy.TenantId)' carries no private key, so it cannot sign a client assertion."
                }
                $builder = $builder.WithCertificate($certificate)
            }

            'ClientSecret' {
                $secret = $material.Material
                if ($secret -is [System.Security.SecureString]) {
                    $secret = [System.Net.NetworkCredential]::new('', $secret).Password
                }
                if ([string]::IsNullOrEmpty([string] $secret)) {
                    throw "Client-secret profile for tenant '$($profileCopy.TenantId)' resolved to an empty secret."
                }
                $builder = $builder.WithClientSecret([string] $secret)
            }

            default {
                throw "New-GraphMsalApplicationFactory does not build confidential clients for AuthMethod '$authMethod'."
            }
        }

        return $builder.WithAuthority($authority).Build()
    }.GetNewClosure()
}

<#
    Private: the real MSAL managed-identity factory. Managed identity uses a different
    builder entirely - ManagedIdentityApplicationBuilder with
    AcquireTokenForManagedIdentity - which is exactly why contexts own an
    IGraphTokenSource rather than a confidential client directly.
#>
function New-GraphManagedIdentityFactory {
    [CmdletBinding()]
    [OutputType([scriptblock])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Profile
    )

    $credential = $Profile.Credential
    $userAssignedClientId = $null
    if ($null -ne $credential -and $null -ne $credential.ClientId -and '' -ne [string] $credential.ClientId) {
        $userAssignedClientId = [string] $credential.ClientId
    }

    return {
        $identity = if ($null -ne $userAssignedClientId) {
            [Microsoft.Identity.Client.AppConfig.ManagedIdentityId]::WithUserAssignedClientId($userAssignedClientId)
        }
        else {
            [Microsoft.Identity.Client.AppConfig.ManagedIdentityId]::SystemAssigned
        }

        return [Microsoft.Identity.Client.ManagedIdentityApplicationBuilder]::Create($identity).Build()
    }.GetNewClosure()
}
