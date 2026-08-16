function Test-GraphTenant {
    <#
    .SYNOPSIS
        Validates tenant profile metadata without any network call.

    .DESCRIPTION
        Performs metadata-level validation of a tenant profile: required fields
        are present, the ProfileId matches its canonical regex, TenantId and
        ClientId are GUIDs (or null), and Kind, AuthMethod and Environment are
        known values. It never touches the network or resolves any credential.
        Accepts either a stored profile by -ProfileId or an in-memory
        -TenantProfile.

    .PARAMETER ProfileId
        Optional canonical identifier of a stored profile to look up and
        validate. Used with the profile store; it selects by canonical id only.

    .PARAMETER TenantProfile
        An in-memory profile hashtable to validate directly, bypassing the
        store. Used when the profile is already loaded.

    .PARAMETER StorePath
        Optional override for the profile store path. Defaults to
        ~/.graphkit/profiles.json when omitted.

    .EXAMPLE
        if (Test-GraphTenant -ProfileId contoso) { 'valid' }
        # Validates the stored contoso profile metadata.

    .EXAMPLE
        Test-GraphTenant -TenantProfile @{ ProfileId = 'x'; TenantId = '...' }
        # Validates an in-memory profile shape without touching the store.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ProfileId')]
        [string] $ProfileId,

        [Parameter(Mandatory, ParameterSetName = 'TenantProfile', Position = 0)]
        [hashtable] $TenantProfile,

        [string] $StorePath
    )

    if ($PSCmdlet.ParameterSetName -eq 'ProfileId') {
        if (-not (Test-GraphProfileId -ProfileId $ProfileId)) {
            return $false
        }
        if ([string]::IsNullOrEmpty($StorePath)) {
            $StorePath = Join-Path $HOME '.graphkit/profiles.json'
        }
        $store = Get-GraphProfileStore -StorePath $StorePath
        $TenantProfile = $store.Profiles | Where-Object { $_.ProfileId -eq $ProfileId } | Select-Object -First 1
        if ($null -eq $TenantProfile) {
            return $false
        }
    }

    foreach ($required in @('ProfileId', 'Name', 'Kind', 'TenantId', 'AuthMethod', 'Environment')) {
        if ($null -eq $TenantProfile[$required] -or [string]::IsNullOrEmpty([string]$TenantProfile[$required])) {
            return $false
        }
    }

    if (-not (Test-GraphProfileId -ProfileId ([string]$TenantProfile.ProfileId))) {
        return $false
    }

    $tenantGuid = [guid]::Empty
    if (-not [guid]::TryParse([string]$TenantProfile.TenantId, [ref]$tenantGuid)) {
        return $false
    }

    if ($null -ne $TenantProfile.ClientId -and [string]$TenantProfile.ClientId -ne '') {
        $clientGuid = [guid]::Empty
        if (-not [guid]::TryParse([string]$TenantProfile.ClientId, [ref]$clientGuid)) {
            return $false
        }
    }

    if ($TenantProfile.Kind -notin @('customer', 'lab', 'internal')) {
        return $false
    }
    if ($TenantProfile.AuthMethod -notin @('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')) {
        return $false
    }
    if ($TenantProfile.Environment -notin @('Global', 'China', 'Germany', 'USGov', 'USGovDoD')) {
        return $false
    }

    return $true
}
