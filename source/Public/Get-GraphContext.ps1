function Get-GraphContext {
    <#
    .SYNOPSIS
        Resolves a tenant profile into an immutable GraphKit runtime context.

    .DESCRIPTION
        Resolves a persisted tenant profile (by its canonical ProfileId) into an
        immutable GraphKit.Context object that owns a per-context token source.
        Resolution performs zero network calls and never acquires a token; the
        context carries a 'NotAcquired' identity state until the first
        acquisition. A caller may inject an X509Certificate2 or a token-provider
        scriptblock for context-only use; injected material is never persisted.

    .PARAMETER ProfileId
        The canonical path-safe profile identifier (^[a-z0-9][a-z0-9-]{0,63}$).
        Only the canonical identifier selects a profile; display names never do.

    .PARAMETER StorePath
        Optional override for the profile store path. Defaults to
        ~/.graphkit/profiles.json when omitted.

    .PARAMETER Certificate
        An optional X509Certificate2 to use for this context only. It is never
        persisted to the profile store and is not disposed by GraphKit.

    .PARAMETER TokenProvider
        An optional scriptblock that returns a token (and, when available, an
        ExpiresOnUtc) for this context only. It is never persisted and is called
        only when a token is acquired.

    .PARAMETER MsalFactory
        An optional scriptblock that returns a configured MSAL confidential
        client application builder. Supplied for testability and by the
        auth-resolution phase; it is invoked only when a token is acquired.

    .EXAMPLE
        $context = Get-GraphContext -ProfileId ivy24
        $context.GraphBaseUri   # https://graph.microsoft.com (Global cloud)

    .EXAMPLE
        $context = Get-GraphContext -ProfileId lab01 -Certificate $certificate
        # Injects a caller-owned certificate for this context only; it is not
        # written to profiles.json and GraphKit will not dispose of it.
    #>
    [CmdletBinding()]
    [OutputType('GraphKit.Context')]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $ProfileId,

        [string] $StorePath,

        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,

        [scriptblock] $TokenProvider,

        [scriptblock] $MsalFactory
    )

    if (-not (Test-GraphProfileId -ProfileId $ProfileId)) {
        throw "ProfileId '$ProfileId' is not a valid canonical profile identifier (expected ^[a-z0-9][a-z0-9-]{0,63}$)."
    }

    if ([string]::IsNullOrEmpty($StorePath)) {
        $StorePath = Join-Path $HOME '.graphkit/profiles.json'
    }

    $store = Get-GraphProfileStore -StorePath $StorePath
    $tenantProfile = $store.Profiles | Where-Object { $_.ProfileId -eq $ProfileId } | Select-Object -First 1
    if ($null -eq $tenantProfile) {
        throw "No profile with ProfileId '$ProfileId' exists in the profile store at '$StorePath'."
    }

    $cloud = Get-GraphCloudMetadata -Name ([string]$tenantProfile.Environment)

    $identitySelector = ''
    $authMode = $null

    if ($null -ne $TokenProvider) {
        $providerIdentity = [guid]::NewGuid().ToString('N')
        $generation = Get-GraphCredentialGeneration -TenantProfile @{
            AuthMethod = 'Provider'
            Credential = @{ Identity = $providerIdentity }
        }
        $source = [ProviderTokenSource]::new($TokenProvider, [string]$cloud.Resource, $tenantProfile.ClientId, $generation)
        $identitySelector = $providerIdentity
        $authMode = 'Provider'
    }
    elseif ($null -ne $Certificate) {
        $generation = Get-GraphCredentialGeneration -TenantProfile @{
            AuthMethod = 'Certificate'
            Credential = @{ Thumbprint = $Certificate.Thumbprint }
        }
        $factory = $MsalFactory
        if ($null -eq $factory) {
            $factory = {
                throw 'MSAL confidential-client resolution is not wired for an injected certificate yet; pass -MsalFactory (the auth-resolution phase supplies the real builder).'
            }
        }
        $source = [ConfidentialClientTokenSource]::new($factory, 'Certificate', [string]$cloud.Resource, $tenantProfile.ClientId, $generation)
        $authMode = 'Certificate'
    }
    else {
        $source = New-GraphTokenSource -Profile $tenantProfile -Cloud $cloud -MsalFactory $MsalFactory
        $authMode = $source.AuthMode
        if ($authMode -eq 'ManagedIdentity') {
            $cred = $tenantProfile.Credential
            if ($null -ne $cred.ClientId -and $cred.ClientId -ne '') {
                $identitySelector = [string]$cred.ClientId
            }
            else {
                $identitySelector = 'system'
            }
        }
    }

    $credentialFingerprint = Get-GraphFingerprint -Value $source.CredentialGeneration
    $acquisitionKey = Get-GraphTokenAcquisitionKey `
        -Environment ([string]$tenantProfile.Environment) `
        -TenantId ([string]$tenantProfile.TenantId) `
        -Authority ([string]$cloud.Authority) `
        -Resource ([string]$cloud.Resource) `
        -ClientId $tenantProfile.ClientId `
        -AuthMode $authMode `
        -IdentitySelector $identitySelector `
        -Generation $source.CredentialGeneration `
        -Scopes @("$($cloud.Resource)/.default")

    $tenantGuid = [guid] ([string]$tenantProfile.TenantId)
    $clientGuid = $null
    if ($null -ne $tenantProfile.ClientId -and [string]$tenantProfile.ClientId -ne '') {
        $clientGuid = [guid] ([string]$tenantProfile.ClientId)
    }

    return [PSCustomObject]@{
        PSTypeName            = 'GraphKit.Context'
        ProfileId             = $tenantProfile.ProfileId
        TenantId              = $tenantGuid
        Cloud                 = $tenantProfile.Environment
        GraphBaseUri          = $cloud.GraphBaseUri
        ClientId              = $clientGuid
        TokenSource           = $source
        CredentialFingerprint = $credentialFingerprint
        AcquisitionCacheKey   = $acquisitionKey
        IdentityState         = 'NotAcquired'
    }
}
