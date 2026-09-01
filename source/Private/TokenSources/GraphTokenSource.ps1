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
    # When the token was received. Refresh skew is a percentage of LIFETIME, so the
    # issue time must be recorded; deriving it from the JWT is not permitted (Graph
    # access tokens are resource-owned and clients must not parse them).
    [System.DateTimeOffset] $ReceivedOnUtc
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
    hidden [guid] $CreationRunspaceId

    hidden [GraphTokenResult] $CachedResult
    hidden [bool] $CachedResultWasForceRefresh
    hidden [object] $CacheLock

    GraphTokenSourceBase() {
        $this.CacheLock = [object]::new()
        $runspace = [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace
        $this.CreationRunspaceId = if ($null -eq $runspace) {
            [guid]::Empty
        }
        else {
            $runspace.InstanceId
        }
    }

    [GraphTokenResult] Acquire([bool]$forceRefresh, [System.Threading.CancellationToken]$cancellation) {
        throw [System.NotImplementedException]::new('GraphTokenSourceBase.Acquire must be overridden by a concrete token source.')
    }

    # Adaptive refresh skew, per spec: min(5 min, max(60 s, 10% of lifetime)).
    #
    # Without this a token expiring in milliseconds is served as valid, the request
    # goes out, Graph answers 401, and the single permitted force-refresh is spent on
    # an entirely predictable failure - mid-pagination, that costs the page.
    #
    # The spread is derived from the token fingerprint rather than a random number.
    # It is therefore deterministic per token (tests stay reproducible) while still
    # differing across tokens, so fifteen contexts connected in bulk do not all
    # reacquire at the same instant. Spread is 0-10% of the skew, and only ever
    # refreshes EARLIER, never later.
    hidden [double] RefreshSkewSeconds([GraphTokenResult]$result) {
        $lifetime = 0.0
        if ($result.ReceivedOnUtc -gt [System.DateTimeOffset]::MinValue) {
            $lifetime = ($result.ExpiresOnUtc - $result.ReceivedOnUtc).TotalSeconds
        }

        $skew = [Math]::Min(300.0, [Math]::Max(60.0, $lifetime * 0.1))

        $spread = 0.0
        $fingerprint = [string] $result.TokenFingerprint
        if (-not [string]::IsNullOrEmpty($fingerprint)) {
            # First byte of the hex digest -> 0..255 -> 0..10% of the skew.
            $bucket = [Convert]::ToInt32($fingerprint.Substring(0, 2), 16)
            $spread = $skew * 0.1 * ($bucket / 255.0)
        }

        return $skew + $spread
    }

    hidden [GraphTokenResult] GetValidCachedToken() {
        [System.Threading.Monitor]::Enter($this.CacheLock)
        try {
            $current = $this.CachedResult
            if ($null -eq $current) {
                return $null
            }

            $expires = $current.ExpiresOnUtc
            if ($expires -le [System.DateTimeOffset]::MinValue) {
                # No expiry is known (a fixed bearer): never treat it as skew-valid.
                return $null
            }

            $refreshAt = $expires.AddSeconds(-1.0 * $this.RefreshSkewSeconds($current))
            if ($refreshAt -gt [System.DateTimeOffset]::UtcNow) {
                return $current
            }
            return $null
        }
        finally {
            [System.Threading.Monitor]::Exit($this.CacheLock)
        }
    }

    hidden [GraphTokenResult] GetCachedToken() {
        [System.Threading.Monitor]::Enter($this.CacheLock)
        try {
            return $this.CachedResult
        }
        finally {
            [System.Threading.Monitor]::Exit($this.CacheLock)
        }
    }

    hidden [void] CacheResult([GraphTokenResult]$result, [bool]$forceRefresh) {
        [System.Threading.Monitor]::Enter($this.CacheLock)
        try {
            $current = $this.CachedResult
            $replace = $null -eq $current

            if (-not $replace) {
                $replace = $result.ReceivedOnUtc -gt $current.ReceivedOnUtc

                # ReceivedOnUtc is recorded at acquisition time and normally
                # provides a strict order. When two results share a clock tick,
                # preserve a forced-refresh result over an ordinary result, then
                # prefer the later expiry within the same acquisition mode.
                # Otherwise retain the incumbent instead of making cache order
                # depend on whichever sender resumes last.
                if (-not $replace -and $result.ReceivedOnUtc -eq $current.ReceivedOnUtc) {
                    $replace = ($forceRefresh -and -not $this.CachedResultWasForceRefresh) -or
                        ($forceRefresh -eq $this.CachedResultWasForceRefresh -and
                            $result.ExpiresOnUtc -gt $current.ExpiresOnUtc)
                }
            }

            if ($replace) {
                $this.CachedResult = $result
                $this.CachedResultWasForceRefresh = $forceRefresh
                $this.ExpiresOn = $result.ExpiresOnUtc
                $this.VerifiedTenantId = $result.VerifiedTenantId
            }
        }
        finally {
            [System.Threading.Monitor]::Exit($this.CacheLock)
        }
    }

    [void] AdoptSharedResult([GraphTokenResult]$result, [bool]$forceRefresh) {
        $currentRunspace = [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace
        $currentRunspaceId = if ($null -eq $currentRunspace) { [guid]::Empty } else { $currentRunspace.InstanceId }
        if ($currentRunspaceId -ne $this.CreationRunspaceId) {
            throw [System.InvalidOperationException]::new(
                'This legacy PowerShell token source is bound to the runspace where its context was created. ' +
                'Cross-runspace context use is disabled because PowerShell-class token acquisition can hang; ' +
                'the compiled GraphKit.Auth token source is required for that contract.'
            )
        }

        if ($null -eq $result) {
            throw [System.ArgumentNullException]::new('result')
        }

        if (-not [string]::Equals(
                [string] $result.CredentialGeneration,
                [string] $this.CredentialGeneration,
                [System.StringComparison]::Ordinal)) {
            throw [System.InvalidOperationException]::new(
                'Refusing to adopt a shared token result from a different credential generation.'
            )
        }

        $this.CacheResult($result, $forceRefresh)
    }
}

class ConfidentialClientTokenSource : GraphTokenSourceBase {
    hidden [scriptblock] $BuilderFactory
    hidden [object] $Application
    hidden [object] $ApplicationLock

    ConfidentialClientTokenSource([scriptblock]$builderFactory, [string]$authMode, [string]$audience, [string]$clientId, [string]$generation) {
        $this.BuilderFactory = $builderFactory
        $this.ApplicationLock = [object]::new()
        $this.AuthMode = $authMode
        $this.Audience = $audience
        $this.ClientId = $clientId
        $this.CredentialGeneration = $generation
        $this.CanRefresh = $true
    }

    hidden [object] GetApplication() {
        [System.Threading.Monitor]::Enter($this.ApplicationLock)
        try {
            if ($null -eq $this.Application) {
                $candidate = & $this.BuilderFactory
                if ($null -eq $candidate) {
                    throw [System.InvalidOperationException]::new(
                        'The confidential-client application factory returned no application.'
                    )
                }
                $this.Application = $candidate
            }
            return $this.Application
        }
        finally {
            [System.Threading.Monitor]::Exit($this.ApplicationLock)
        }
    }

    [GraphTokenResult] Acquire([bool]$forceRefresh, [System.Threading.CancellationToken]$cancellation) {
        $currentRunspace = [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace
        $currentRunspaceId = if ($null -eq $currentRunspace) { [guid]::Empty } else { $currentRunspace.InstanceId }
        if ($currentRunspaceId -ne $this.CreationRunspaceId) {
            throw [System.InvalidOperationException]::new(
                'This legacy PowerShell token source is bound to the runspace where its context was created. ' +
                'Cross-runspace context use is disabled because PowerShell-class token acquisition can hang; ' +
                'the compiled GraphKit.Auth token source is required for that contract.'
            )
        }

        if (-not $forceRefresh) {
            $cached = $this.GetValidCachedToken()
            if ($null -ne $cached) {
                return $cached
            }
        }

        $app = $this.GetApplication()
        $scopes = [string[]]@("$($this.Audience)/.default")
        $builder = $app.AcquireTokenForClient($scopes).WithForceRefresh($forceRefresh)
        $authResult = $builder.ExecuteAsync($cancellation).GetAwaiter().GetResult()

        $result = [GraphTokenResult]::new()
        $result.AccessToken = $authResult.AccessToken
        $result.ExpiresOnUtc = [System.DateTimeOffset] $authResult.ExpiresOn
        $result.ReceivedOnUtc = [System.DateTimeOffset]::UtcNow
        $result.TokenType = 'Bearer'
        $result.Scopes = $scopes
        $result.VerifiedTenantId = $null
        $result.TokenFingerprint = Get-GraphFingerprint -Value $authResult.AccessToken
        $result.CredentialGeneration = $this.CredentialGeneration

        $this.CacheResult($result, $forceRefresh)
        return $result
    }
}

class ManagedIdentityTokenSource : GraphTokenSourceBase {
    hidden [scriptblock] $BuilderFactory
    hidden [object] $Application
    hidden [object] $ApplicationLock

    ManagedIdentityTokenSource([scriptblock]$builderFactory, [string]$audience, [string]$clientId, [string]$generation) {
        $this.BuilderFactory = $builderFactory
        $this.ApplicationLock = [object]::new()
        $this.AuthMode = 'ManagedIdentity'
        $this.Audience = $audience
        $this.ClientId = $clientId
        $this.CredentialGeneration = $generation
        $this.CanRefresh = $true
    }

    hidden [object] GetApplication() {
        [System.Threading.Monitor]::Enter($this.ApplicationLock)
        try {
            if ($null -eq $this.Application) {
                $candidate = & $this.BuilderFactory
                if ($null -eq $candidate) {
                    throw [System.InvalidOperationException]::new(
                        'The managed-identity application factory returned no application.'
                    )
                }
                $this.Application = $candidate
            }
            return $this.Application
        }
        finally {
            [System.Threading.Monitor]::Exit($this.ApplicationLock)
        }
    }

    [GraphTokenResult] Acquire([bool]$forceRefresh, [System.Threading.CancellationToken]$cancellation) {
        $currentRunspace = [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace
        $currentRunspaceId = if ($null -eq $currentRunspace) { [guid]::Empty } else { $currentRunspace.InstanceId }
        if ($currentRunspaceId -ne $this.CreationRunspaceId) {
            throw [System.InvalidOperationException]::new(
                'This legacy PowerShell token source is bound to the runspace where its context was created. ' +
                'Cross-runspace context use is disabled because PowerShell-class token acquisition can hang; ' +
                'the compiled GraphKit.Auth token source is required for that contract.'
            )
        }

        if (-not $forceRefresh) {
            $cached = $this.GetValidCachedToken()
            if ($null -ne $cached) {
                return $cached
            }
        }

        $app = $this.GetApplication()
        $scope = "$($this.Audience)/.default"
        $builder = $app.AcquireTokenForManagedIdentity($scope).WithForceRefresh($forceRefresh)
        $authResult = $builder.ExecuteAsync($cancellation).GetAwaiter().GetResult()

        $result = [GraphTokenResult]::new()
        $result.AccessToken = $authResult.AccessToken
        $result.ExpiresOnUtc = [System.DateTimeOffset] $authResult.ExpiresOn
        $result.ReceivedOnUtc = [System.DateTimeOffset]::UtcNow
        $result.TokenType = 'Bearer'
        $result.Scopes = [string[]]@($scope)
        $result.VerifiedTenantId = $null
        $result.TokenFingerprint = Get-GraphFingerprint -Value $authResult.AccessToken
        $result.CredentialGeneration = $this.CredentialGeneration

        $this.CacheResult($result, $forceRefresh)
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
        $currentRunspace = [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace
        $currentRunspaceId = if ($null -eq $currentRunspace) { [guid]::Empty } else { $currentRunspace.InstanceId }
        if ($currentRunspaceId -ne $this.CreationRunspaceId) {
            throw [System.InvalidOperationException]::new(
                'This legacy PowerShell token source is bound to the runspace where its context was created. ' +
                'Cross-runspace context use is disabled because PowerShell-class token acquisition can hang; ' +
                'the compiled GraphKit.Auth token source is required for that contract.'
            )
        }

        if (-not $forceRefresh) {
            $cached = $this.GetValidCachedToken()
            if ($null -ne $cached) {
                return $cached
            }
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
        $result.ReceivedOnUtc = [System.DateTimeOffset]::UtcNow
        $result.TokenType = 'Bearer'
        $result.Scopes = [string[]]@("$($this.Audience)/.default")
        $result.VerifiedTenantId = $null
        $result.TokenFingerprint = Get-GraphFingerprint -Value ([string]$token)
        $result.CredentialGeneration = $this.CredentialGeneration

        # Only cache a provider token that carries an explicit future expiry; a
        # token with no expiry is never reused and forces a fresh provider call.
        if ($expires -gt [System.DateTimeOffset]::UtcNow) {
            $this.CacheResult($result, $forceRefresh)
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
        $currentRunspace = [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace
        $currentRunspaceId = if ($null -eq $currentRunspace) { [guid]::Empty } else { $currentRunspace.InstanceId }
        if ($currentRunspaceId -ne $this.CreationRunspaceId) {
            throw [System.InvalidOperationException]::new(
                'This legacy PowerShell token source is bound to the runspace where its context was created. ' +
                'Cross-runspace context use is disabled because PowerShell-class token acquisition can hang; ' +
                'the compiled GraphKit.Auth token source is required for that contract.'
            )
        }

        if ($forceRefresh) {
            throw [System.InvalidOperationException]::new('A fixed bearer token cannot be refreshed. Supply a new token (a new context) instead of forcing a refresh on an unrefreshable source.')
        }

        $cached = $this.GetCachedToken()
        if ($null -eq $cached) {
            $result = [GraphTokenResult]::new()
            $result.AccessToken = $this.Bearer
            $result.ExpiresOnUtc = [System.DateTimeOffset]::MinValue
            $result.ReceivedOnUtc = [System.DateTimeOffset]::UtcNow
        $result.TokenType = 'Bearer'
            $result.Scopes = [string[]]@("$($this.Audience)/.default")
            $result.VerifiedTenantId = $null
            $result.TokenFingerprint = Get-GraphFingerprint -Value $this.Bearer
            $result.CredentialGeneration = $this.CredentialGeneration
            $this.CacheResult($result, $false)
            $cached = $this.GetCachedToken()
        }
        return $cached
    }
}

class GraphTokenFlight {
    [System.Threading.Tasks.TaskCompletionSource[object]] $Completion
    [bool] $LeaderCancellationRequested

    GraphTokenFlight() {
        $this.Completion = [System.Threading.Tasks.TaskCompletionSource[object]]::new(
            [System.Threading.Tasks.TaskCreationOptions]::RunContinuationsAsynchronously
        )
        $this.LeaderCancellationRequested = $false
    }
}

class GraphTokenFlightRegistry {
    static [System.Collections.Concurrent.ConcurrentDictionary[string, GraphTokenFlight]] $Flights =
        [System.Collections.Concurrent.ConcurrentDictionary[string, GraphTokenFlight]]::new()
    static [object] $RemovalLock = [object]::new()
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

function Get-GraphPfxSnapshot {
    <#
        Read a persisted PFX once and bind its canonical path, exact bytes and
        SHA-256 identity together. Callers that construct a certificate use the
        returned Bytes property rather than reopening the path, so the material
        cannot change between generation verification and import.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'A persisted PFX path is empty; GraphKit cannot derive its credential generation.'
    }

    try {
        # .NET's GetFullPath resolves against Environment.CurrentDirectory,
        # which PowerShell does not update for Set-Location. Resolve through
        # the PowerShell path API so a relative PFX means relative to the
        # caller's actual FileSystem location at context construction.
        $provider = $null
        $drive = $null
        $canonicalPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
            $Path,
            [ref] $provider,
            [ref] $drive
        )
        if ($null -eq $provider -or $provider.Name -ne 'FileSystem') {
            $providerName = if ($null -eq $provider) { '<unknown>' } else { $provider.Name }
            throw "PFX paths must use the FileSystem provider; '$Path' resolved through '$providerName'."
        }
        $bytes = [System.IO.File]::ReadAllBytes($canonicalPath)
    }
    catch {
        throw "The PFX at '$Path' could not be read to derive its credential generation: $($_.Exception.Message)"
    }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }

    return [pscustomobject] @{
        Path   = $canonicalPath
        Bytes  = $bytes
        Sha256 = $digest
    }
}

<#
    Private: derive a non-secret credential-generation string from a profile.
    The generation changes whenever the underlying vault version, certificate or
    provider generation changes, but never embeds a secret value.
#>
function New-GraphCredentialGenerationValue {
    <#
        Build an unambiguous, non-secret credential identity. Raw delimiter
        concatenation is unsafe because distinct persisted references can contain
        `|` and collapse to the same string. Each field is therefore length-
        prefixed; the internal kind is fixed by GraphKit and versioned as `g1`.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Kind,

        [AllowNull()]
        [object[]] $Components
    )

    $builder = [System.Text.StringBuilder]::new("g1|$Kind")
    foreach ($component in @($Components)) {
        $value = if ($null -eq $component) { '' } else { [string] $component }
        $null = $builder.Append('|').Append($value.Length).Append(':').Append($value)
    }
    return $builder.ToString()
}

function Get-GraphCredentialGeneration {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $TenantProfile,

        # Internal snapshot seam: the PFX resolver has already read the exact
        # bytes it will import, so it supplies their digest/path to avoid a
        # second path read and a generation-to-load TOCTOU window.
        [string] $PfxContentSha256,

        [string] $PfxCanonicalPath
    )

    $authMethod = [string]$TenantProfile.AuthMethod
    $credential = $TenantProfile.Credential

    switch ($authMethod) {
        'ClientSecret' {
            return New-GraphCredentialGenerationValue -Kind 'ClientSecret' -Components @(
                $credential.VaultName,
                $credential.SecretName,
                $credential.Version
            )
        }
        'Certificate' {
            if ($null -ne $credential.PfxPath) {
                $passwordRef = $credential.Password
                $contentHash = $PfxContentSha256
                $path = $PfxCanonicalPath
                if ([string]::IsNullOrEmpty($contentHash) -or [string]::IsNullOrEmpty($path)) {
                    $snapshot = Get-GraphPfxSnapshot -Path ([string] $credential.PfxPath)
                    try {
                        $contentHash = [string] $snapshot.Sha256
                        $path = [string] $snapshot.Path
                    }
                    finally {
                        if ($snapshot.Bytes -is [byte[]]) {
                            [System.Security.Cryptography.CryptographicOperations]::ZeroMemory(
                                [byte[]] $snapshot.Bytes
                            )
                        }
                    }
                }
                return New-GraphCredentialGenerationValue -Kind 'Certificate.PFX' -Components @(
                    $path,
                    "sha256:$contentHash",
                    $passwordRef.VaultName,
                    $passwordRef.SecretName,
                    $passwordRef.Version
                )
            }
            if ($null -ne $credential.CertificateName) {
                $passwordRef = $credential.Password
                return New-GraphCredentialGenerationValue -Kind 'Certificate.Vault' -Components @(
                    $credential.VaultName,
                    $credential.CertificateName,
                    $credential.Version,
                    $passwordRef.VaultName,
                    $passwordRef.SecretName,
                    $passwordRef.Version
                )
            }
            if ($null -ne $credential.StoreLocation) {
                return New-GraphCredentialGenerationValue -Kind 'Certificate.Store' -Components @(
                    $credential.StoreLocation,
                    $credential.StoreName,
                    $credential.Thumbprint,
                    $credential.Subject
                )
            }
            return New-GraphCredentialGenerationValue -Kind 'Certificate.Injected' -Components @(
                $credential.Thumbprint
            )
        }
        'BearerToken' {
            return New-GraphCredentialGenerationValue -Kind 'BearerToken' -Components @(
                $credential.VaultName,
                $credential.SecretName,
                $credential.Version
            )
        }
        'ManagedIdentity' {
            if ($null -ne $credential.ClientId -and $credential.ClientId -ne '') {
                return New-GraphCredentialGenerationValue -Kind 'ManagedIdentity' -Components @(
                    $credential.ClientId
                )
            }
            return New-GraphCredentialGenerationValue -Kind 'ManagedIdentity' -Components @('system')
        }
        'Provider' {
            return New-GraphCredentialGenerationValue -Kind 'Provider' -Components @(
                $credential.Identity
            )
        }
        default {
            throw "Unknown AuthMethod '$authMethod'."
        }
    }
}

function Test-GraphCredentialReferencePinned {
    <#
        A versioned vault slot or certificate thumbprint is immutable enough to
        participate in cross-context token sharing. Mutable selectors (an
        unversioned secret name or certificate subject) are context-scoped so a
        rotation can never make a new context adopt an old context's flight.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $TenantProfile
    )

    $credential = $TenantProfile.Credential
    switch ([string] $TenantProfile.AuthMethod) {
        'ClientSecret' {
            return -not [string]::IsNullOrEmpty([string] $credential.Version)
        }
        'BearerToken' {
            return [string]::IsNullOrEmpty([string] $credential.Token) -and
                -not [string]::IsNullOrEmpty([string] $credential.Version)
        }
        'Certificate' {
            if (-not [string]::IsNullOrEmpty([string] $credential.PfxPath)) {
                return -not [string]::IsNullOrEmpty([string] $credential.Password.Version)
            }
            if (-not [string]::IsNullOrEmpty([string] $credential.CertificateName)) {
                $materialPinned = -not [string]::IsNullOrEmpty([string] $credential.Version)
                $hasPassword = $null -ne $credential.Password -and
                    (-not [string]::IsNullOrEmpty([string] $credential.Password.SecretName) -or
                        -not [string]::IsNullOrEmpty([string] $credential.Password.VaultName))
                $passwordPinned = -not $hasPassword -or
                    -not [string]::IsNullOrEmpty([string] $credential.Password.Version)
                return $materialPinned -and $passwordPinned
            }
            if (-not [string]::IsNullOrEmpty([string] $credential.Thumbprint)) {
                return $true
            }
            if (-not [string]::IsNullOrEmpty([string] $credential.Subject)) {
                return $false
            }
            # Caller-injected certificates are identified by thumbprint in the
            # synthetic profile and provider identities already carry a nonce.
            return $true
        }
        default {
            return $true
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
    Private: remove a completed flight only when the key still names that exact
    instance. TryRemove(key, out) alone can remove a newer replacement flight if
    a cancelled leader completes while a live waiter starts the replacement.
#>
function Remove-GraphTokenFlightIfCurrent {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Key,
        [Parameter(Mandatory)]
        [GraphTokenFlight] $Flight
    )

    [System.Threading.Monitor]::Enter([GraphTokenFlightRegistry]::RemovalLock)
    try {
        $current = [GraphTokenFlight] $null
        if (-not [GraphTokenFlightRegistry]::Flights.TryGetValue($Key, [ref] $current) -or
            -not [object]::ReferenceEquals($current, $Flight)) {
            return $false
        }

        $removed = [GraphTokenFlight] $null
        return [GraphTokenFlightRegistry]::Flights.TryRemove($Key, [ref] $removed)
    }
    finally {
        [System.Threading.Monitor]::Exit([GraphTokenFlightRegistry]::RemovalLock)
    }
}

<#
    Private: single-flight acquisition per canonical tuple key. The first caller
    runs the acquisition script and everyone else awaits the same result. A
    non-cancellation failure surfaces to every waiter and is not cached; if the
    leader is cancelled, a still-live waiter starts or joins a replacement flight.
#>
function Invoke-GraphTokenSingleFlight {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [string] $Key,
        [Parameter(Mandatory)]
        [scriptblock] $AcquireScript,
        [System.Threading.CancellationToken] $CancellationToken = [System.Threading.CancellationToken]::None
    )

    while ($true) {
        $flight = [GraphTokenFlight]::new()

        if ([GraphTokenFlightRegistry]::Flights.TryAdd($Key, $flight)) {
            try {
                $result = & $AcquireScript
                $null = $flight.Completion.TrySetResult($result)
                return $result
            }
            catch {
                $failure = $_.Exception
                $candidate = $failure
                $isCancellationFailure = $false
                while ($null -ne $candidate) {
                    if ($candidate -is [System.OperationCanceledException]) {
                        $isCancellationFailure = $true
                        break
                    }
                    $candidate = $candidate.InnerException
                }

                # Record the leader's caller-specific cancellation disposition
                # before publishing completion. A provider may throw its own OCE
                # while the leader token remains live; followers must fan that out
                # as one shared failure rather than multiplying provider calls.
                $flight.LeaderCancellationRequested =
                    $CancellationToken.IsCancellationRequested -and $isCancellationFailure
                $null = $flight.Completion.TrySetException($failure)
                # The leader observes its own failed task even when no waiter was
                # present, preventing an unobserved-task exception later.
                $null = $flight.Completion.Task.Exception
                throw
            }
            finally {
                $null = Remove-GraphTokenFlightIfCurrent -Key $Key -Flight $flight
            }
        }

        $existing = [GraphTokenFlight] $null
        if (-not [GraphTokenFlightRegistry]::Flights.TryGetValue($Key, [ref] $existing)) {
            # The leader completed and removed the entry between TryAdd and
            # TryGetValue. Retry the registry operation; never bypass the flight
            # with a direct duplicate acquisition.
            continue
        }

        try {
            return $existing.Completion.Task.WaitAsync($CancellationToken).GetAwaiter().GetResult()
        }
        catch {
            $candidate = $_.Exception
            $sharedAcquisitionWasCancelled = $false
            while ($null -ne $candidate) {
                if ($candidate -is [System.OperationCanceledException]) {
                    $sharedAcquisitionWasCancelled = $true
                    break
                }
                $candidate = $candidate.InnerException
            }

            $leaderCallerWasCancelled =
                $sharedAcquisitionWasCancelled -and $existing.LeaderCancellationRequested

            if (-not $leaderCallerWasCancelled -or $CancellationToken.IsCancellationRequested) {
                throw
            }

            # A leader's caller-specific cancellation must not poison live
            # waiters. Remove only the exact completed flight (never a newer
            # replacement added for the same key), then let this caller compete
            # to lead or join the replacement acquisition.
            $null = Remove-GraphTokenFlightIfCurrent -Key $Key -Flight $existing
            continue
        }
    }
}

<#
    Private: separate ordinary and forced refresh work for one canonical tuple.
    A forced waiter must never join an ordinary acquisition that can legally
    return the token Graph has just rejected with 401.
#>
function Get-GraphTokenFlightKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $AcquisitionKey,
        [bool] $ForceRefresh = $false
    )

    $mode = if ($ForceRefresh) { 'refresh' } else { 'ordinary' }
    return "$AcquisitionKey|flight:$mode"
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
    if ($null -eq $MsalFactory) {
        return New-GraphAuthTokenSource -Profile $Profile -Cloud $Cloud
    }

    $factoryProfile = $Profile
    if ($authMethod -eq 'Certificate' -and
        -not [string]::IsNullOrEmpty([string] $Profile.Credential.PfxPath)) {
        # Capture the canonical path at context/source construction. Lazy vault
        # resolution may occur after Set-Location; it must reopen the same path
        # whose bytes were bound into this immutable source's generation.
        $snapshot = Get-GraphPfxSnapshot -Path ([string] $Profile.Credential.PfxPath)
        try {
            $generation = Get-GraphCredentialGeneration -TenantProfile $Profile `
                -PfxContentSha256 ([string] $snapshot.Sha256) `
                -PfxCanonicalPath ([string] $snapshot.Path)
            $factoryProfile = $Profile.Clone()
            $factoryCredential = $Profile.Credential.Clone()
            $factoryCredential.PfxPath = [string] $snapshot.Path
            $factoryProfile.Credential = $factoryCredential
        }
        finally {
            if ($snapshot.Bytes -is [byte[]]) {
                [System.Security.Cryptography.CryptographicOperations]::ZeroMemory(
                    [byte[]] $snapshot.Bytes
                )
            }
        }
    }
    else {
        $generation = Get-GraphCredentialGeneration -TenantProfile $Profile
    }
    if (-not (Test-GraphCredentialReferencePinned -TenantProfile $Profile)) {
        # Never hash secret/password material to discover an unversioned
        # rotation. Instead, isolate mutable selectors to this immutable
        # context. Versioned references still coalesce across contexts.
        $generation = "$generation|context:$([guid]::NewGuid().ToString('N'))"
    }

    switch ($authMethod) {
        'Certificate' {
            # -MsalFactory remains injectable for tests; when absent the REAL factory is
            # used. It previously defaulted to a scriptblock that threw, which meant the
            # module could not authenticate by any means outside a test.
            $factory = $MsalFactory
            if ($null -eq $factory) {
                $factory = New-GraphMsalApplicationFactory -Profile $factoryProfile -Cloud $Cloud `
                    -ExpectedCredentialGeneration $generation
            }
            return [ConfidentialClientTokenSource]::new($factory, 'Certificate', $audience, $clientId, $generation)
        }
        'ClientSecret' {
            $factory = $MsalFactory
            if ($null -eq $factory) {
                $factory = New-GraphMsalApplicationFactory -Profile $Profile -Cloud $Cloud `
                    -ExpectedCredentialGeneration $generation
            }
            return [ConfidentialClientTokenSource]::new($factory, 'ClientSecret', $audience, $clientId, $generation)
        }
        'ManagedIdentity' {
            return [ManagedIdentityTokenSource]::new(
                $MsalFactory,
                $audience,
                ([string] $Profile.Credential.ClientId),
                $generation)
        }
        'BearerToken' {
            # An inline token (context-only, never persisted) wins; otherwise resolve the
            # vault reference. Resolution previously threw outright.
            $token = $Profile.Credential.Token
            if ([string]::IsNullOrEmpty([string]$token)) {
                $material = Get-GraphVaultCredential -Credential $Profile.Credential -AuthMethod 'BearerToken'
                $token = $material.Material
            }
            if ([string]::IsNullOrEmpty([string]$token)) {
                throw "Bearer-token profile for tenant '$($Profile.TenantId)' resolved to an empty token."
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
