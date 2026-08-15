function Remove-GraphTenant {
    <#
    .SYNOPSIS
        Removes a registered tenant profile from the profile store.

    .DESCRIPTION
        Deletes a tenant profile from the profile store under an interprocess
        lock, using an atomic write so a concurrent registration is never lost
        and a half-written store is never observed. The -ProfileId is mandatory;
        the display Name is never a selector.

    .PARAMETER ProfileId
        The canonical profile identifier (^[a-z0-9][a-z0-9-]{0,63}$) of the
        tenant profile to remove.

    .PARAMETER StorePath
        Optional override for the profile store path. Defaults to
        ~/.graphkit/profiles.json when omitted.

    .EXAMPLE
        Remove-GraphTenant -ProfileId lab01
        # Removes the lab01 tenant profile from the profile store.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([void])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $ProfileId,

        [string] $StorePath
    )

    if (-not (Test-GraphProfileId -ProfileId $ProfileId)) {
        throw "ProfileId '$ProfileId' is not a valid canonical profile identifier (expected ^[a-z0-9][a-z0-9-]{0,63}$)."
    }

    if ([string]::IsNullOrEmpty($StorePath)) {
        $StorePath = Join-Path $HOME '.graphkit/profiles.json'
    }

    $lock = Enter-GraphProfileStoreLock -StorePath $StorePath
    try {
        $store = Get-GraphProfileStore -StorePath $StorePath

        $matchingProfiles = @($store.Profiles | Where-Object { $_.ProfileId -eq $ProfileId })
        if ($matchingProfiles.Count -eq 0) {
            throw "No profile with ProfileId '$ProfileId' exists in the profile store at '$StorePath'."
        }

        if ($PSCmdlet.ShouldProcess("tenant profile '$ProfileId' in '$StorePath'", 'Remove')) {
            $store.Profiles = @($store.Profiles | Where-Object { $_.ProfileId -ne $ProfileId })
            Save-GraphProfileStore -Store $store -StorePath $StorePath
        }
    }
    finally {
        Exit-GraphProfileStoreLock -Lock $lock
    }
}
