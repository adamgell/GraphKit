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
        [scriptblock] $CredentialResolver,

        # The generation captured when the immutable context/source was built.
        # Persisted PFX resolution returns the generation of the exact byte
        # snapshot it imported; a mismatch means the path changed underneath the
        # context and must never share token/proof identity with the old bytes.
        [string] $ExpectedCredentialGeneration,

        # Private test seams. Production uses the loaded MSAL builder and the
        # centralized module-lifecycle resource registrar.
        [scriptblock] $ApplicationBuilderFactory,

        [scriptblock] $OwnedResourceRegistrar
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
    $ownedResourceRegister = Get-Command -Name Register-GraphModuleOwnedResource -CommandType Function

    $resolver = $CredentialResolver
    if ($null -eq $resolver) {
        $resolver = { param($P) & $vaultResolve -Credential $P.Credential -AuthMethod $P.AuthMethod }.GetNewClosure()
    }

    $builderCreate = $ApplicationBuilderFactory
    if ($null -eq $builderCreate) {
        $builderCreate = {
            param($ApplicationClientId)
            [Microsoft.Identity.Client.ConfidentialClientApplicationBuilder]::Create($ApplicationClientId)
        }
    }

    $resourceRegistrar = $OwnedResourceRegistrar
    if ($null -eq $resourceRegistrar) {
        $resourceRegistrar = {
            param($Resource, [bool] $OwnedByGraphKit)
            & $ownedResourceRegister -Resource $Resource -OwnedByGraphKit:$OwnedByGraphKit
        }.GetNewClosure()
    }

    return {
        $material = & $resolver $profileCopy
        if ($null -eq $material) {
            throw "GraphKit could not resolve credential material for tenant '$($profileCopy.TenantId)'."
        }

        $ownedResource = $null
        $resourceTransferred = $false
        $ownedEphemeralMaterial = $null

        try {
            if ([bool] $material.OwnsMaterial -and $material.Material -is [System.IDisposable]) {
                if ($authMethod -eq 'Certificate') {
                    $ownedResource = [System.IDisposable] $material.Material
                }
                else {
                    # Client-secret material is copied into MSAL during builder
                    # configuration and must never enter the module lifetime.
                    $ownedEphemeralMaterial = [System.IDisposable] $material.Material
                }
            }

            $actualGeneration = [string] $material.CredentialGeneration
            $expectedMatchesActual = [string]::Equals(
                $ExpectedCredentialGeneration,
                $actualGeneration,
                [System.StringComparison]::Ordinal
            )
            $expectedIsIsolatedActual = $false
            if (-not [string]::IsNullOrEmpty($ExpectedCredentialGeneration) -and
                -not [string]::IsNullOrEmpty($actualGeneration)) {
                $expectedIsIsolatedActual = $ExpectedCredentialGeneration.StartsWith(
                    "$actualGeneration|context:",
                    [System.StringComparison]::Ordinal
                ) -and
                    $ExpectedCredentialGeneration.Substring(
                        ("$actualGeneration|context:").Length
                    ) -match '^[0-9a-f]{32}$'
            }

            if (-not [string]::IsNullOrEmpty($ExpectedCredentialGeneration) -and
                ([string]::IsNullOrEmpty($actualGeneration) -or
                    (-not $expectedMatchesActual -and -not $expectedIsIsolatedActual))) {
                if ([string]::IsNullOrEmpty($actualGeneration)) {
                    throw (
                        "Credential material for tenant '$($profileCopy.TenantId)' did not report the generation " +
                        'captured when this context was created. Refusing acquisition because material identity cannot be verified.'
                    )
                }
                throw (
                    "Credential material changed after this context was created for tenant '$($profileCopy.TenantId)'. " +
                    'Create a new GraphKit context so acquisition and tenant-proof identity use the new credential generation.'
                )
            }

            $builder = & $builderCreate $clientId
            if ($null -eq $builder) {
                throw 'The confidential-client application builder factory returned no builder.'
            }

            switch ($authMethod) {
                'Certificate' {
                    $certificate = $material.Material
                    if ($certificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
                        $resolvedType = if ($null -eq $certificate) { '<null>' } else { $certificate.GetType().Name }
                        throw "Certificate profile for tenant '$($profileCopy.TenantId)' resolved to '$resolvedType' rather than an X509Certificate2."
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

            $application = $builder.WithAuthority($authority).Build()
            if ($null -eq $application) {
                throw 'The confidential-client application builder returned no application.'
            }

            if ($null -ne $ownedResource) {
                # Registration is an ownership transfer, not factory output.
                # The default registrar returns the resource for convenience;
                # suppress it so this factory always emits exactly one object:
                # the confidential-client application.
                $null = & $resourceRegistrar $ownedResource $true
                $resourceTransferred = $true
            }

            return $application
        }
        catch {
            if ($null -ne $ownedResource -and -not $resourceTransferred) {
                try { $ownedResource.Dispose() } catch { }
            }
            throw
        }
        finally {
            if ($null -ne $ownedEphemeralMaterial) {
                try { $ownedEphemeralMaterial.Dispose() } catch { }
            }
        }
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
