<#
    Private: tenant-proof binding for a bearer token.

    Commercial Graph serves every tenant from the same host, so authority
    validation proves nothing about WHICH tenant a token addresses. A Tenant B
    token attached to a Tenant A profile would succeed against B while every
    result, telemetry record, and evidence page was stamped Tenant A. This
    function performs the actual proof: a GET /v1.0/organization issued with the
    token itself through the normal GraphKit pipeline (Invoke-GraphRetry), using
    a synthetic AllowUnverifiedRead descriptor. That explicit identity requirement
    exempts the proof request from recursively requiring another proof while every
    ordinary descriptor that requires Verified identity remains fail-closed.

    The proof is bound to the CURRENT token result via its TokenFingerprint and
    CredentialGeneration. A successful proof is cached; a cache hit skips the
    network call entirely. A provider's claim that a token is valid is never
    treated as proof - only a recorded binding skips the call. A mismatch is a
    hard error naming both the returned tenant and the target tenant; the
    cross-tenant contamination guard must never be silent.
#>

# Script-scoped binding cache. Key: "{fingerprint}|{generation}|{tenant}" -> $true
# only after a successful proof. Shared with the sender so an already-proven
# token skips a second proof call.
$script:GraphTenantBindingCache = @{}

function Get-GraphTenantBindingKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Fingerprint,

        [AllowNull()]
        [AllowEmptyString()]
        [string] $Generation,

        [Parameter(Mandatory = $true)]
        [guid] $TenantId
    )

    if ([string]::IsNullOrWhiteSpace($Fingerprint)) {
        throw [System.InvalidOperationException]::new(
            'Tenant binding requires a non-empty TokenFingerprint.'
        )
    }
    if ([string]::IsNullOrWhiteSpace($Generation)) {
        throw [System.InvalidOperationException]::new(
            'Tenant binding requires a non-empty CredentialGeneration.'
        )
    }

    return '{0}|{1}|{2}' -f ([string] $Fingerprint), ([string] $Generation), $TenantId.ToString()
}

function Test-GraphTenantBinding {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Fingerprint,

        [AllowNull()]
        [AllowEmptyString()]
        [string] $Generation,

        [Parameter(Mandatory = $true)]
        [guid] $TenantId
    )

    # An incomplete tuple is never a cache identity. Return false here so a
    # provider-supplied tenant claim cannot turn missing metadata into the
    # shared key "||tenant"; Confirm-GraphTenantBinding owns the diagnostic.
    if ([string]::IsNullOrWhiteSpace($Fingerprint) -or
        [string]::IsNullOrWhiteSpace($Generation)) {
        return $false
    }

    $key = Get-GraphTenantBindingKey -Fingerprint $Fingerprint -Generation $Generation -TenantId $TenantId
    return ($script:GraphTenantBindingCache.ContainsKey($key) -and $script:GraphTenantBindingCache[$key] -eq $true)
}

function New-GraphTenantBindingDeadlineException {
    [CmdletBinding()]
    [OutputType([System.TimeoutException])]
    param()

    $exception = [System.TimeoutException]::new(
        'Tenant proof deadline expired before the token could be verified.'
    )
    $exception.Data['GraphKit.TenantBindingDeadlineExpired'] = $true
    return $exception
}

<#
    Private: expose one already-acquired result through the token-source duck
    contract for the /organization proof. The source is deliberately
    non-refreshable: proving a refreshed or independently reacquired bearer and
    then caching that proof against the caller's earlier fingerprint would break
    the exact-token binding invariant.
#>
function New-GraphPinnedTokenSource {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $true)]
        [object] $TokenResult
    )

    $source = [pscustomobject] @{
        CanRefresh           = $false
        AuthMode             = 'PinnedTokenResult'
        Audience             = $null
        ClientId             = $null
        CredentialGeneration = [string] $TokenResult.CredentialGeneration
        Result               = $TokenResult
    }

    $source | Add-Member -MemberType ScriptMethod -Name Acquire -Value {
        param([bool] $forceRefresh, $cancellationToken)
        if ($forceRefresh) {
            throw [System.InvalidOperationException]::new('A pinned token result cannot be refreshed during tenant proof.')
        }
        return $this.Result
    }

    return $source
}

function Confirm-GraphTenantBinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object] $Context,

        [Parameter(Mandatory = $true)]
        [object] $TokenResult,

        [System.Threading.CancellationToken] $CancellationToken = [System.Threading.CancellationToken]::None,

        [TimeSpan] $RemainingDeadline = [TimeSpan]::FromSeconds(300),

        [scriptblock] $ProofTransport,

        [hashtable] $ProofCache
    )

    $targetTenant = $Context.TenantId
    $fingerprintProperty = $TokenResult.PSObject.Properties['TokenFingerprint']
    $generationProperty = $TokenResult.PSObject.Properties['CredentialGeneration']
    $fingerprint = if ($null -eq $fingerprintProperty) { $null } else { [string] $fingerprintProperty.Value }
    $generation = if ($null -eq $generationProperty) { $null } else { [string] $generationProperty.Value }

    # Validate the complete cache identity before even selecting or consulting
    # a cache. Empty metadata would otherwise collapse distinct bearer tokens
    # onto the same "||tenant" entry and let the second token inherit proof.
    if ([string]::IsNullOrWhiteSpace($fingerprint)) {
        throw [System.InvalidOperationException]::new(
            'Tenant binding cannot proceed without a non-empty TokenFingerprint.'
        )
    }
    if ([string]::IsNullOrWhiteSpace($generation)) {
        throw [System.InvalidOperationException]::new(
            'Tenant binding cannot proceed without a non-empty CredentialGeneration.'
        )
    }

    # The binding decision is made from the cache (fingerprint + generation +
    # tenant), never from a VerifiedTenantId the result already carries: a
    # provider's claim is not proof.
    $cache = $ProofCache
    if ($null -eq $cache) {
        $cache = $script:GraphTenantBindingCache
    }

    $cacheKey = Get-GraphTenantBindingKey `
        -Fingerprint $fingerprint `
        -Generation $generation `
        -TenantId $targetTenant

    if ($cache.ContainsKey($cacheKey) -and $cache[$cacheKey] -eq $true) {
        # Already proven for this exact token/generation/tenant: reuse it.
        $TokenResult.VerifiedTenantId = $targetTenant.ToString()
        return
    }

    # Caller/module cancellation wins when it coincides with budget exhaustion.
    # A pure proof-budget cancellation is converted back to DeadlineExpired by
    # the sender, but a caller-signalled token must retain Cancelled semantics.
    $CancellationToken.ThrowIfCancellationRequested()
    if ($RemainingDeadline -le [TimeSpan]::Zero) {
        throw (New-GraphTenantBindingDeadlineException)
    }

    # ---- Proof read: GET /v1.0/organization with the token itself ----
    $proofUri = [uri] ('{0}/v1.0/organization' -f $Context.GraphBaseUri.AbsoluteUri.TrimEnd('/'))

    $proofDescriptor = @{
        CredentialPolicy    = 'GraphBearer'
        ReplayPolicy        = 'Safe'
        ThrottleClass       = 'Read'
        ResourceFamily      = 'Graph.Directory'
        IdentityRequirement = 'AllowUnverifiedRead'
        ApiVersion          = 'v1.0'
        Condition           = $null
        Reconciliation      = $null
    }

    $transport = $ProofTransport
    if ($null -eq $transport) {
        $transport = {
            param($Context, $Descriptor, $Uri, $CancellationToken, $RemainingDeadline)
            $deadlineSecondsValue = [Math]::Min(
                86400.0,
                [Math]::Ceiling(([TimeSpan] $RemainingDeadline).TotalSeconds))
            $deadlineSeconds = [int] $deadlineSecondsValue
            if ($deadlineSeconds -lt 1) {
                throw (New-GraphTenantBindingDeadlineException)
            }
            Invoke-GraphRetry -Context $Context -Descriptor $Descriptor -Uri $Uri -Method GET `
                -Headers @{} -Body $null -CancellationToken $CancellationToken `
                -DeadlineSeconds $deadlineSeconds
        }
    }

    # Invoke the normal retry/sender pipeline with a source pinned to this exact
    # result. The original provider may rotate on every call; it must never be
    # consulted while proving the bearer that the outer sender is about to use.
    $contextCloud = if ($null -ne $Context.PSObject.Properties['Cloud']) {
        [string] $Context.Cloud
    }
    else {
        ''
    }
    $proofCloud = if ([string]::IsNullOrWhiteSpace($contextCloud)) { 'TenantProof' } else { $contextCloud }
    $proofClientId = if ($null -ne $Context.PSObject.Properties['ClientId']) {
        $Context.ClientId
    }
    else {
        $null
    }
    $proofContext = [pscustomobject] @{
        ProfileId             = 'tenant-proof'
        TenantId              = $targetTenant
        Cloud                 = $proofCloud
        GraphBaseUri          = $Context.GraphBaseUri
        ClientId              = $proofClientId
        TokenSource           = New-GraphPinnedTokenSource -TokenResult $TokenResult
        CredentialFingerprint = $fingerprint
        AcquisitionCacheKey   = "tenant-proof|$cacheKey"
        IdentityState         = 'NotAcquired'
    }

    $envelope = & $transport -Context $proofContext -Descriptor $proofDescriptor -Uri $proofUri `
        -CancellationToken $CancellationToken -RemainingDeadline $RemainingDeadline

    if ($null -eq $envelope -or $envelope.Outcome -ne 'Succeeded') {
        # Invoke-GraphRetry represents cancellation as an envelope. Convert a
        # caller-signalled proof cancellation back to OperationCanceledException
        # so the outer retry loop preserves its established Cancelled outcome and
        # releases its admission instead of treating cancellation as an identity
        # failure with a misleading diagnostic.
        if ($CancellationToken.IsCancellationRequested) {
            $CancellationToken.ThrowIfCancellationRequested()
        }
        if ($null -ne $envelope -and [string] $envelope.Outcome -ceq 'DeadlineExpired') {
            throw (New-GraphTenantBindingDeadlineException)
        }

        throw (
            'Tenant proof failed: the /organization read did not succeed, so the token cannot be verified for tenant {0}.' -f $targetTenant
        )
    }

    $actualTenant = $null
    $rows = $envelope.Data
    if ($null -ne $rows -and $null -ne $rows.value -and $rows.value.Count -ge 1) {
        $actualTenant = $rows.value[0].id
    }

    if ([string]::IsNullOrEmpty([string] $actualTenant)) {
        throw (
            'Tenant proof failed: the /organization read returned no tenant identifier, so the token cannot be verified for tenant {0}.' -f $targetTenant
        )
    }

    $actualGuid = [guid]::Empty
    $targetGuid = [guid]::Empty
    $actualParsed = [guid]::TryParse([string] $actualTenant, [ref] $actualGuid)
    $targetParsed = [guid]::TryParse([string] $targetTenant, [ref] $targetGuid)

    if (-not ($actualParsed -and $targetParsed -and $actualGuid -eq $targetGuid)) {
        throw (
            ('Tenant binding failed: the token is bound to tenant {0}, not the target tenant {1}. ' +
             'Refusing to send; this is a cross-tenant contamination guard.') -f ([string] $actualTenant), ([string] $targetTenant)
        )
    }

    $TokenResult.VerifiedTenantId = $targetTenant.ToString()
    $cache[$cacheKey] = $true
}
