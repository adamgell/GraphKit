<#
    Private: the GraphKit token source contract and its implementations.

    A context owns an IGraphTokenSource, not a confidential MSAL client directly.
    PowerShell classes cannot declare new interfaces, so v1 realizes that
    contract as an abstract base class (PowerShell has no `abstract` keyword on
    methods; the base Acquire throws NotImplementedException, which is the idiom
    for an abstract method) with four concrete subclasses. All of this lives in
    ONE file because PowerShell resolves class types in definition order and the
    subclasses must reference the base class and result class.

    Single-flight acquisition is process-wide (a static ConcurrentDictionary)
    so that many runspaces acquiring the same canonical tuple share one in-flight
    acquisition; a failure surfaces to every waiter.
#>

class GraphTokenResult {
    [string] $AccessToken
    [System.DateTimeOffset] $ExpiresOnUtc
    [string] $TokenType
    [string[]] $Scopes
    [string] $VerifiedTenantId
    [string] $TokenFingerprint
    [string] $CredentialGeneration
}

class GraphTokenSourceBase {
    [bool] $CanRefresh
    [string] $AuthMode
    [string] $Audience
    [string] $ClientId
    [System.DateTimeOffset] $ExpiresOn
    [string] $VerifiedTenantId
    [string] $CredentialGeneration

    hidden [GraphTokenResult] $CachedResult

    [GraphTokenResult] Acquire([bool]$forceRefresh, [System.Threading.CancellationToken]$cancellation) {
        throw [System.NotImplementedException]::new('GraphTokenSourceBase.Acquire must be overridden by a concrete token source.')
    }

    hidden [bool] HasValidCachedToken() {
        return $null -ne $this.CachedResult -and $this.CachedResult.ExpiresOnUtc -gt [System.DateTimeOffset]::UtcNow
    }

    hidden [void] CacheResult([GraphTokenResult]$result) {
        $this.CachedResult = $result
        $this.ExpiresOn = $result.ExpiresOnUtc
        $this.VerifiedTenantId = $result.VerifiedTenantId
    }
}

class ConfidentialClientTokenSource : GraphTokenSourceBase {
    hidden [scriptblock] $BuilderFactory
    hidden [object] $Application

    ConfidentialClientTokenSource([scriptblock]$builderFactory, [string]$authMode, [string]$audience, [string]$clientId, [string]$generation) {
        $this.BuilderFactory = $builderFactory
        $this.AuthMode = $authMode
        $this.Audience = $audience
        $this.ClientId = $clientId
        $this.CredentialGeneration = $generation
        $this.CanRefresh = $true
    }

    hidden [object] GetApplication() {
        if ($null -eq $this.Application) {
            $this.Application = & $this.BuilderFactory
        }
        return $this.Application
    }

    [GraphTokenResult] Acquire([bool]$forceRefresh, [System.Threading.CancellationToken]$cancellation) {
        if (-not $forceRefresh -and $this.HasValidCachedToken()) {
            return $this.CachedResult
        }

        $app = $this.GetApplication()
        $scopes = [string[]]@("$($this.Audience)/.default")
        $authResult = $app.AcquireTokenForClient($scopes).ExecuteAsync($cancellation).GetAwaiter().GetResult()

        $result = [GraphTokenResult]::new()
        $result.AccessToken = $authResult.AccessToken
        $result.ExpiresOnUtc = [System.DateTimeOffset] $authResult.ExpiresOn
        $result.TokenType = 'Bearer'
        $result.Scopes = $scopes
        $result.VerifiedTenantId = $null
        $result.TokenFingerprint = Get-GraphFingerprint -Value $authResult.AccessToken
        $result.CredentialGeneration = $this.CredentialGeneration

        $this.CacheResult($result)
        return $result
    }
}

class ManagedIdentityTokenSource : GraphTokenSourceBase {
    hidden [scriptblock] $BuilderFactory
    hidden [object] $Application

    ManagedIdentityTokenSource([scriptblock]$builderFactory, [string]$audience, [string]$clientId, [string]$generation) {
        $this.BuilderFactory = $builderFactory
        $this.AuthMode = 'ManagedIdentity'
        $this.Audience = $audience
        $this.ClientId = $clientId
        $this.CredentialGeneration = $generation
        $this.CanRefresh = $true
    }

    hidden [object] GetApplication() {
        if ($null -eq $this.Application) {
            $this.Application = & $this.BuilderFactory
        }
        return $this.Application
    }

    [GraphTokenResult] Acquire([bool]$forceRefresh, [System.Threading.CancellationToken]$cancellation) {
        if (-not $forceRefresh -and $this.HasValidCachedToken()) {
            return $this.CachedResult
        }

        $app = $this.GetApplication()
        $scope = "$($this.Audience)/.default"
        $authResult = $app.AcquireTokenForManagedIdentity($scope).ExecuteAsync($cancellation).GetAwaiter().GetResult()

        $result = [GraphTokenResult]::new()
        $result.AccessToken = $authResult.AccessToken
        $result.ExpiresOnUtc = [System.DateTimeOffset] $authResult.ExpiresOn
        $result.TokenType = 'Bearer'
        $result.Scopes = [string[]]@($scope)
        $result.VerifiedTenantId = $null
        $result.TokenFingerprint = Get-GraphFingerprint -Value $authResult.AccessToken
        $result.CredentialGeneration = $this.CredentialGeneration

        $this.CacheResult($result)
        return $result
    }
}

class ProviderTokenSource : GraphTokenSourceBase {
    hidden [scriptblock] $Provider

    ProviderTokenSource([scriptblock]$provider, [string]$audience, [string]$clientId, [string]$generation) {
        $this.Provider = $provider
        $this.AuthMode = 'Provider'
        $this.Audience = $audience
        $this.ClientId = $clientId
        $this.CredentialGeneration = $generation
        $this.CanRefresh = $true
    }

    [GraphTokenResult] Acquire([bool]$forceRefresh, [System.Threading.CancellationToken]$cancellation) {
        if (-not $forceRefresh -and $this.HasValidCachedToken()) {
            return $this.CachedResult
        }

        $provided = & $this.Provider
        if ($null -eq $provided) {
            throw 'The token provider returned no token.'
        }

        $token = $null
        if ($provided -is [string]) {
            $token = $provided
        }
        else {
            $token = $provided.Token
            if ([string]::IsNullOrEmpty([string]$token)) {
                $token = $provided.AccessToken
            }
        }

        if ([string]::IsNullOrEmpty([string]$token)) {
            throw 'The token provider returned an empty token.'
        }

        $expires = [System.DateTimeOffset]::MinValue
        if ($provided -isnot [string]) {
            $rawExpiry = $provided.ExpiresOnUtc
            if ($null -eq $rawExpiry) {
                $rawExpiry = $provided.ExpiresOn
            }
            if ($null -ne $rawExpiry) {
                $expires = [System.DateTimeOffset] $rawExpiry
            }
        }

        $result = [GraphTokenResult]::new()
        $result.AccessToken = [string]$token
        $result.ExpiresOnUtc = $expires
        $result.TokenType = 'Bearer'
        $result.Scopes = [string[]]@("$($this.Audience)/.default")
        $result.VerifiedTenantId = $null
        $result.TokenFingerprint = Get-GraphFingerprint -Value ([string]$token)
        $result.CredentialGeneration = $this.CredentialGeneration

        # Only cache a provider token that carries an explicit future expiry; a
        # token with no expiry is never reused and forces a fresh provider call.
        if ($expires -gt [System.DateTimeOffset]::UtcNow) {
            $this.CacheResult($result)
        }
        return $result
    }
}

class FixedBearerTokenSource : GraphTokenSourceBase {
    hidden [string] $Bearer

    FixedBearerTokenSource([string]$bearer, [string]$audience, [string]$generation) {
        $this.Bearer = $bearer
        $this.AuthMode = 'BearerToken'
        $this.Audience = $audience
        $this.CredentialGeneration = $generation
        $this.CanRefresh = $false
    }

    [GraphTokenResult] Acquire([bool]$forceRefresh, [System.Threading.CancellationToken]$cancellation) {
        if ($forceRefresh) {
            throw [System.InvalidOperationException]::new('A fixed bearer token cannot be refreshed. Supply a new token (a new context) instead of forcing a refresh on an unrefreshable source.')
        }

        if ($null -eq $this.CachedResult) {
            $result = [GraphTokenResult]::new()
            $result.AccessToken = $this.Bearer
            $result.ExpiresOnUtc = [System.DateTimeOffset]::MinValue
            $result.TokenType = 'Bearer'
            $result.Scopes = [string[]]@("$($this.Audience)/.default")
            $result.VerifiedTenantId = $null
            $result.TokenFingerprint = Get-GraphFingerprint -Value $this.Bearer
            $result.CredentialGeneration = $this.CredentialGeneration
            $this.CachedResult = $result
        }
        return $this.CachedResult
    }
}

class GraphTokenFlight {
    [System.Threading.ManualResetEventSlim] $Done
    [object] $Result
    [System.Exception] $Error

    GraphTokenFlight() {
        $this.Done = [System.Threading.ManualResetEventSlim]::new($false)
    }
}

class GraphTokenFlightRegistry {
    static [System.Collections.Concurrent.ConcurrentDictionary[string, GraphTokenFlight]] $Flights =
        [System.Collections.Concurrent.ConcurrentDictionary[string, GraphTokenFlight]]::new()
}

<#
    Private: SHA-256 hex digest of a value. Used for token fingerprints (over the
    bearer, which must never be logged or exported) and for the non-secret
    credential fingerprint (over credential-generation material).
#>
function Get-GraphFingerprint {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value
    )

    if ([string]::IsNullOrEmpty($Value)) {
        return $null
    }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))
        return ([System.BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

<#
    Private: derive a non-secret credential-generation string from a profile.
    The generation changes whenever the underlying vault version, certificate or
    provider generation changes, but never embeds a secret value.
#>
function Get-GraphCredentialGeneration {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $TenantProfile
    )

    $authMethod = [string]$TenantProfile.AuthMethod
    $credential = $TenantProfile.Credential

    switch ($authMethod) {
        'ClientSecret' {
            return "ClientSecret|$($credential.VaultName)|$($credential.SecretName)|$($credential.Version)"
        }
        'Certificate' {
            if ($null -ne $credential.PfxPath) {
                $passwordRef = $credential.Password
                return "Certificate|PFX|$($credential.PfxPath)|$($passwordRef.VaultName)|$($passwordRef.SecretName)"
            }
            if ($null -ne $credential.CertificateName) {
                return "Certificate|Vault|$($credential.VaultName)|$($credential.CertificateName)|$($credential.Version)"
            }
            if ($null -ne $credential.StoreLocation) {
                return "Certificate|Store|$($credential.StoreLocation)|$($credential.StoreName)|$($credential.Thumbprint)|$($credential.Subject)"
            }
            return "Certificate|Injected|$($credential.Thumbprint)"
        }
        'BearerToken' {
            return "BearerToken|$($credential.VaultName)|$($credential.SecretName)|$($credential.Version)"
        }
        'ManagedIdentity' {
            if ($null -ne $credential.ClientId -and $credential.ClientId -ne '') {
                return "ManagedIdentity|$($credential.ClientId)"
            }
            return 'ManagedIdentity|system'
        }
        'Provider' {
            return "Provider|$($credential.Identity)"
        }
        default {
            throw "Unknown AuthMethod '$authMethod'."
        }
    }
}

<#
    Private: build the canonical acquisition tuple key. GUIDs and hosts are
    lower-cased and scopes are sorted and de-duplicated so that equivalent
    inputs always yield the same key, while any component change yields a new
    key.
#>
function Get-GraphTokenAcquisitionKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Environment,
        [Parameter(Mandatory)]
        [string] $TenantId,
        [Parameter(Mandatory)]
        [string] $Authority,
        [Parameter(Mandatory)]
        [string] $Resource,
        [string] $ClientId,
        [Parameter(Mandatory)]
        [string] $AuthMode,
        [string] $IdentitySelector,
        [Parameter(Mandatory)]
        [string] $Generation,
        [string[]] $Scopes
    )

    $normalizedScopes = @(
        $Scopes |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { $_.Trim().ToLowerInvariant() } |
            Sort-Object -Unique
    )
    if ($normalizedScopes.Count -eq 0) {
        $normalizedScopes = @("$($Resource.TrimEnd('/').ToLowerInvariant())/.default")
    }

    $clientIdPart = if ($null -eq $ClientId) { '' } else { $ClientId.Trim().ToLowerInvariant() }
    $identityPart = if ($null -eq $IdentitySelector) { '' } else { $IdentitySelector.Trim().ToLowerInvariant() }

    $parts = @(
        $Environment.Trim().ToLowerInvariant(),
        $TenantId.Trim().ToLowerInvariant(),
        $Authority.Trim().ToLowerInvariant(),
        ($normalizedScopes -join ' '),
        $clientIdPart,
        $AuthMode.Trim().ToLowerInvariant(),
        $identityPart,
        $Generation
    )

    return ($parts -join '|')
}

<#
    Private: single-flight acquisition per canonical tuple key. The first caller
    runs the acquisition script and everyone else awaits the same result; a
    failure surfaces to every waiter and is not cached.
#>
function Invoke-GraphTokenSingleFlight {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [string] $Key,
        [Parameter(Mandatory)]
        [scriptblock] $AcquireScript
    )

    $flight = [GraphTokenFlight]::new()

    if ([GraphTokenFlightRegistry]::Flights.TryAdd($Key, $flight)) {
        try {
            $flight.Result = & $AcquireScript
        }
        catch {
            $flight.Error = $_.Exception
        }
        finally {
            $flight.Done.Set()
            $removed = [GraphTokenFlight] $null
            $null = [GraphTokenFlightRegistry]::Flights.TryRemove($Key, [ref] $removed)
        }
    }
    else {
        $existing = [GraphTokenFlightRegistry]::Flights[$Key]
        if ($null -eq $existing) {
            # Narrow race: the leader removed the entry between our failed
            # TryAdd and the lookup. Fall back to acquiring directly.
            return & $AcquireScript
        }
        $existing.Done.Wait()
        if ($null -ne $existing.Error) {
            throw $existing.Error
        }
        return $existing.Result
    }

    if ($null -ne $flight.Error) {
        throw $flight.Error
    }
    return $flight.Result
}

<#
    Private: build a token source from a profile and its cloud metadata. The
    MSAL builder factory is injected for testability and supplied by the
    auth-resolution phase; constructing a source never acquires a token.
#>
function New-GraphTokenSource {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Profile,
        [Parameter(Mandatory)]
        [hashtable] $Cloud,
        [scriptblock] $MsalFactory
    )

    $authMethod = [string]$Profile.AuthMethod
    $audience = [string]$Cloud.Resource
    $clientId = $Profile.ClientId
    $generation = Get-GraphCredentialGeneration -TenantProfile $Profile

    switch ($authMethod) {
        'Certificate' {
            $factory = $MsalFactory
            if ($null -eq $factory) {
                $factory = {
                    throw 'MSAL confidential-client resolution is not wired for this certificate profile yet; pass -MsalFactory (the auth-resolution phase supplies the real builder).'
                }
            }
            return [ConfidentialClientTokenSource]::new($factory, 'Certificate', $audience, $clientId, $generation)
        }
        'ClientSecret' {
            $factory = $MsalFactory
            if ($null -eq $factory) {
                $factory = {
                    throw 'MSAL confidential-client resolution is not wired for this secret profile yet; pass -MsalFactory (the auth-resolution phase supplies the real builder).'
                }
            }
            return [ConfidentialClientTokenSource]::new($factory, 'ClientSecret', $audience, $clientId, $generation)
        }
        'ManagedIdentity' {
            $factory = {
                throw 'MSAL managed-identity resolution is not wired for this profile yet; the auth-resolution phase supplies the real ManagedIdentityApplicationBuilder.'
            }
            return [ManagedIdentityTokenSource]::new($factory, $audience, $clientId, $generation)
        }
        'BearerToken' {
            $token = $Profile.Credential.Token
            if ([string]::IsNullOrEmpty([string]$token)) {
                throw 'Bearer-token resolution from the vault is not available in this phase; the auth-resolution phase supplies the resolved token.'
            }
            return [FixedBearerTokenSource]::new([string]$token, $audience, $generation)
        }
        default {
            throw "Unknown AuthMethod '$authMethod'."
        }
    }
}

<#
    Private: validate a caller-injected token source against the duck contract.
    The source must expose an Acquire member and the CanRefresh, AuthMode,
    Audience and ClientId properties; the error names every missing member.
#>
function Assert-GraphTokenSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Source
    )

    if ($null -eq $Source) {
        throw 'The token source is null; pass a valid GraphKit token source.'
    }

    $missing = [System.Collections.Generic.List[string]]::new()

    if ($null -eq $Source.PSObject.Members['Acquire']) {
        $missing.Add('Acquire member')
    }

    foreach ($member in @('CanRefresh', 'AuthMode', 'Audience', 'ClientId')) {
        if ($null -eq $Source.PSObject.Members[$member]) {
            $missing.Add("$member property")
        }
    }

    if ($missing.Count -gt 0) {
        $typeName = $Source.GetType().FullName
        throw "The supplied token source (type '$typeName') does not satisfy the GraphKit token source contract. Missing: $($missing -join ', ')."
    }
}
