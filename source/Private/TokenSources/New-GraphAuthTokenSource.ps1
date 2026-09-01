<#
    Private: validate the successor profile identity discriminator shared by
    registration, metadata validation, and context construction.
#>
function Assert-GraphTenantProfileAuthSchema {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Profile
    )

    $authMethod = [string] $Profile.AuthMethod
    $credential = if ($Profile.Credential -is [hashtable]) {
        [hashtable] $Profile.Credential
    }
    else {
        @{}
    }

    $topLevelClientId = [string] $Profile.ClientId
    $nestedClientId = [string] $credential.ClientId
    $hasTopLevelClientId = -not [string]::IsNullOrWhiteSpace($topLevelClientId)
    $hasNonNullTopLevelClientId = $Profile.ContainsKey('ClientId') -and
        $null -ne $Profile.ClientId
    $hasNestedClientId = $credential.ContainsKey('ClientId')
    $applicationClientId = $null
    $managedIdentityClientId = $null

    $unsupportedSelectors = [System.Collections.Generic.List[string]]::new()
    foreach ($name in @(
        'ManagedIdentityClientId',
        'ApplicationClientId',
        'UserAssignedClientId',
        'IdentitySelector',
        'ObjectId',
        'ResourceId',
        'ManagedIdentityObjectId',
        'ManagedIdentityResourceId'
    )) {
        if ($Profile.ContainsKey($name)) {
            $unsupportedSelectors.Add($name)
        }
        if ($credential.ContainsKey($name)) {
            $unsupportedSelectors.Add("Credential.$name")
        }
    }
    if ($unsupportedSelectors.Count -ne 0) {
        throw "AuthMethod '$authMethod' contains unsupported identity selector metadata ($($unsupportedSelectors -join ', ')). Re-register the profile using only top-level ClientId for Certificate/ClientSecret or Credential.ClientId for user-assigned ManagedIdentity."
    }

    switch ($authMethod) {
        { $_ -in @('Certificate', 'ClientSecret') } {
            if (-not $hasTopLevelClientId) {
                throw "AuthMethod '$authMethod' requires a non-empty, non-zero top-level ClientId. Re-register the profile with -ClientId."
            }
            if ($hasNestedClientId) {
                throw "AuthMethod '$authMethod' must not declare ManagedIdentityClientId or Credential.ClientId. Re-register the profile with only the top-level application ClientId."
            }

            $parsed = [guid]::Empty
            if (-not [guid]::TryParse($topLevelClientId, [ref] $parsed)) {
                throw "AuthMethod '$authMethod' ClientId '$topLevelClientId' is not a valid GUID. Re-register the profile with a non-zero application ClientId."
            }
            if ($parsed -eq [guid]::Empty) {
                throw "AuthMethod '$authMethod' requires a non-zero ClientId. Re-register the profile with the application ClientId."
            }
            $applicationClientId = $parsed.ToString('D')
            break
        }
        'ManagedIdentity' {
            if ($hasNonNullTopLevelClientId) {
                throw "AuthMethod 'ManagedIdentity' must not declare top-level ClientId. Re-register the profile and use -ManagedIdentityClientId only for a user-assigned identity."
            }
            $selector = if ($hasNestedClientId) {
                $nestedClientId
            }
            else {
                $null
            }
            if ($null -ne $selector) {
                if ([string]::IsNullOrWhiteSpace($selector)) {
                    throw 'ManagedIdentity Credential.ClientId must be a non-empty, non-zero GUID when the key is present. Re-register the profile or omit Credential.ClientId entirely for system-assigned identity.'
                }
                $parsed = [guid]::Empty
                if (-not [guid]::TryParse($selector, [ref] $parsed)) {
                    throw "ManagedIdentityClientId / Credential.ClientId '$selector' is not a valid GUID. Re-register the profile with a non-zero user-assigned managed-identity client GUID."
                }
                if ($parsed -eq [guid]::Empty) {
                    throw 'ManagedIdentity requires a non-zero ManagedIdentityClientId / Credential.ClientId for user-assigned identity. Re-register the profile or omit the selector for system-assigned identity.'
                }
                $managedIdentityClientId = $parsed.ToString('D')
            }
            break
        }
        'BearerToken' {
            if ($hasNonNullTopLevelClientId -or $hasNestedClientId) {
                throw "AuthMethod 'BearerToken' must not declare ClientId, ManagedIdentityClientId, or Credential.ClientId. Re-register the profile without a client identity selector."
            }
            break
        }
        default {
            throw "Unknown AuthMethod '$authMethod'. Re-register the profile with Certificate, ClientSecret, ManagedIdentity, or BearerToken."
        }
    }

    return [pscustomobject] @{
        ApplicationClientId     = $applicationClientId
        ManagedIdentityClientId = $managedIdentityClientId
    }
}

<#
    Private: the sole PowerShell-to-GraphKit.Auth descriptor bridge. Credential
    material stays PowerShell-owned until the exact typed CreateSource call.
#>
function New-GraphAuthTokenSource {
    [CmdletBinding()]
    [OutputType([GraphKit.Auth.IGraphTokenSource])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Profile,

        [Parameter(Mandatory)]
        [hashtable] $Cloud,

        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    )

    if ($null -eq $script:GraphKitAuthHost) {
        throw [System.InvalidOperationException]::new('The module-scoped GraphKit.Auth host is unavailable.')
    }

    $schema = Assert-GraphTenantProfileAuthSchema -Profile $Profile
    $authMethod = [string] $Profile.AuthMethod
    $material = $null
    $ownsMaterial = $false
    $generation = $null
    $credential = $null
    $request = $null
    $ownershipCeded = $false

    try {
        if ($null -ne $Certificate) {
            if ($authMethod -ne 'Certificate') {
                throw [System.ArgumentException]::new('An injected certificate may only be used with Certificate authentication.', 'Certificate')
            }
            $material = $Certificate
            $generation = Get-GraphCredentialGeneration -TenantProfile @{
                AuthMethod = 'Certificate'
                Credential = @{ Thumbprint = $Certificate.Thumbprint }
            }
        }
        elseif ($authMethod -eq 'BearerToken' -and
            -not [string]::IsNullOrWhiteSpace([string] $Profile.Credential.Token)) {
            $material = [string] $Profile.Credential.Token
            $generation = Get-GraphCredentialGeneration -TenantProfile $Profile
        }
        else {
            $resolved = Get-GraphVaultCredential -Credential $Profile.Credential -AuthMethod $authMethod
            $material = $resolved.Material
            $ownsMaterial = [bool] $resolved.OwnsMaterial
            $generation = [string] $resolved.CredentialGeneration
            if ([string]::IsNullOrWhiteSpace($generation)) {
                $generation = Get-GraphCredentialGeneration -TenantProfile $Profile
            }
        }

        if (-not (Test-GraphCredentialReferencePinned -TenantProfile $Profile) -and
            $null -eq $Certificate) {
            $generation = "$generation|context:$([guid]::NewGuid().ToString('N'))"
        }
        if ([string]::IsNullOrWhiteSpace($generation)) {
            throw [System.InvalidOperationException]::new('Credential generation resolution returned an empty value.')
        }

        switch ($authMethod) {
            'Certificate' {
                $credential = [GraphKit.Auth.CertificateCredential]::new(
                    [System.Security.Cryptography.X509Certificates.X509Certificate2] $material,
                    $ownsMaterial)
                $clientId = [Nullable[guid]] ([guid] $schema.ApplicationClientId)
                $mode = [GraphKit.Auth.GraphAuthMode]::Certificate
            }
            'ClientSecret' {
                $credential = [GraphKit.Auth.ClientSecretCredential]::new(
                    [Security.SecureString] $material,
                    $ownsMaterial)
                $clientId = [Nullable[guid]] ([guid] $schema.ApplicationClientId)
                $mode = [GraphKit.Auth.GraphAuthMode]::ClientSecret
            }
            'ManagedIdentity' {
                $managedIdentitySelector = if ([string]::IsNullOrEmpty([string] $schema.ManagedIdentityClientId)) {
                    $null
                }
                else {
                    [string] $schema.ManagedIdentityClientId
                }
                # PowerShell's direct constructor binder coerces a null string
                # argument to String.Empty. Invoke the exact ABI constructor
                # through reflection so system-assigned identity remains a
                # genuine null discriminator.
                $managedIdentityArguments = [object[]]::new(1)
                $managedIdentityArguments[0] = $managedIdentitySelector
                $credential = [GraphKit.Auth.ManagedIdentityCredential].GetConstructor(
                    [type[]] @([string])).Invoke($managedIdentityArguments)
                $clientId = [Nullable[guid]] $null
                $mode = [GraphKit.Auth.GraphAuthMode]::ManagedIdentity
            }
            'BearerToken' {
                $credential = [GraphKit.Auth.FixedBearerCredential]::new([string] $material)
                $clientId = [Nullable[guid]] $null
                $mode = [GraphKit.Auth.GraphAuthMode]::BearerToken
            }
        }

        $request = [GraphKit.Auth.GraphTokenRequest]::new(
            [string] $Profile.Environment,
            [guid] ([string] $Profile.TenantId),
            [uri] $Cloud.Authority,
            [uri] $Cloud.Resource,
            $clientId,
            $mode,
            $credential,
            $generation)

        if ($ownsMaterial) {
            # The default-context host accepts ownership on method entry. From
            # this exact point forward it alone decides whether host or provider
            # cleanup applies, including when CreateSource throws.
            $ownershipCeded = $true
        }
        $source = $script:GraphKitAuthHost.CreateSource(
            [GraphKit.Auth.GraphTokenRequest] $request)
    }
    catch {
        if ($ownsMaterial -and -not $ownershipCeded -and $material -is [IDisposable]) {
            try {
                $material.Dispose()
            }
            catch {
                throw [GraphKit.Auth.GraphAuthException]::new(
                    'credential_material_cleanup_failed',
                    'CredentialOwnership',
                    'GraphKit.Auth could not clean up credential material after request construction failed before host entry.',
                    $null,
                    $null)
            }
        }
        throw
    }

    try {
        return Register-GraphModuleOwnedResource -Resource $source -OwnedByGraphKit:$true
    }
    catch {
        try {
            $source.Dispose()
        }
        catch {
            throw [System.InvalidOperationException]::new(
                'GraphKit.Auth source registration failed and the returned source could not be disposed safely.')
        }
        throw
    }
}
