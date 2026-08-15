<#
    Private: read the persisted profile store.

    The store is an index of every tenant GraphKit can reach. SchemaVersion sits
    at the root; a newer schema is refused rather than silently ignoring fields
    it does not understand. A parse failure is reported together with the backup
    location, never silently recreating an empty store that would look like all
    profiles had vanished.
#>

function Get-GraphProfileStore {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string] $StorePath
    )

    $supportedSchemaVersion = 1

    if ([string]::IsNullOrEmpty($StorePath)) {
        $StorePath = Join-Path $HOME '.graphkit/profiles.json'
    }

    if (-not (Test-Path -LiteralPath $StorePath -PathType Leaf)) {
        return @{ SchemaVersion = $supportedSchemaVersion; Profiles = @() }
    }

    try {
        $raw = Get-Content -LiteralPath $StorePath -Raw -ErrorAction Stop
        $store = $raw | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    }
    catch {
        $backupPath = "$StorePath.bak"
        if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
            $backupNote = "A backup exists at '$backupPath'."
        }
        else {
            $backupNote = "No backup file was found at '$backupPath'."
        }
        throw "The profile store at '$StorePath' could not be parsed: $($_.Exception.Message) $backupNote Refusing to recreate an empty store."
    }

    $version = 0
    if ($null -eq $store.SchemaVersion) {
        throw "The profile store at '$StorePath' has no SchemaVersion at the root and cannot be read safely. Restore it from '$StorePath.bak' if a backup exists."
    }
    if (-not [int]::TryParse([string]$store.SchemaVersion, [ref]$version)) {
        throw "The profile store at '$StorePath' has an invalid SchemaVersion '$($store.SchemaVersion)'. Expected an integer."
    }

    if ($version -gt $supportedSchemaVersion) {
        throw "The profile store at '$StorePath' uses SchemaVersion $version, which is newer than this version of GraphKit supports (SchemaVersion $supportedSchemaVersion). Upgrade GraphKit to read this store; refusing to silently ignore unrecognized fields."
    }
    if ($version -lt $supportedSchemaVersion) {
        throw "The profile store at '$StorePath' uses SchemaVersion $version, which is older than the supported SchemaVersion $supportedSchemaVersion and has no migration path. Restore or recreate the store manually."
    }

    $profiles = $store.Profiles
    if ($null -eq $profiles) {
        $profiles = @()
    }
    else {
        $profiles = @($profiles)
    }

    return @{
        SchemaVersion = $version
        Profiles      = $profiles
    }
}
