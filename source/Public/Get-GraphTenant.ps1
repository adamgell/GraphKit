function Get-GraphTenant {
    <#
    .SYNOPSIS
        Lists registered tenant profiles from the profile store.

    .DESCRIPTION
        Reads the profile store and returns every registered tenant profile, or a
        single profile when -ProfileId is supplied. Only the canonical ProfileId
        selects a profile; the display Name is never a selector.

    .PARAMETER ProfileId
        Optional canonical profile identifier. When supplied, only that profile
        is returned and an error is raised if it does not exist.

    .PARAMETER StorePath
        Optional override for the profile store path. Defaults to
        ~/.graphkit/profiles.json when omitted.

    .EXAMPLE
        Get-GraphTenant
        # Lists every registered tenant profile from the profile store.

    .EXAMPLE
        $tenant = Get-GraphTenant -ProfileId ivy24
        $tenant.Environment   # Global
    #>
    [CmdletBinding()]
    [OutputType([hashtable], [object[]])]
    param(
        [string] $ProfileId,

        [string] $StorePath
    )

    if ([string]::IsNullOrEmpty($StorePath)) {
        $StorePath = Join-Path $HOME '.graphkit/profiles.json'
    }

    if (-not [string]::IsNullOrEmpty($ProfileId) -and -not (Test-GraphProfileId -ProfileId $ProfileId)) {
        throw "ProfileId '$ProfileId' is not a valid canonical profile identifier (expected ^[a-z0-9][a-z0-9-]{0,63}$)."
    }

    $store = Get-GraphProfileStore -StorePath $StorePath

    if (-not [string]::IsNullOrEmpty($ProfileId)) {
        $tenantProfile = $store.Profiles | Where-Object { $_.ProfileId -eq $ProfileId } | Select-Object -First 1
        if ($null -eq $tenantProfile) {
            throw "No profile with ProfileId '$ProfileId' exists in the profile store at '$StorePath'."
        }
        return $tenantProfile
    }

    return @($store.Profiles)
}
