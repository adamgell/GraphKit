function Import-GraphLegacyProfile {
    <#
        .SYNOPSIS
            Imports a legacy secrets.json tenant configuration into the
            GraphKit profile store.

        .DESCRIPTION
            Phase 5 step 2 of the cutover. Three properties matter more than convenience
            here, because this runs once against real tenant configuration:

            **Data-only parsing.** The legacy file is read with ConvertFrom-Json and nothing
            else. It is never dot-sourced, never passed to Invoke-Expression, and no field is
            treated as executable. Unknown top-level keys are reported rather than ignored,
            because a key this importer does not understand may be one carrying credentials.

            **Dry run first.** -WhatIf produces the full inventory - every profile that would
            be created, every one that would be skipped, and why - while writing nothing. The
            inventory is the point of the dry run, so it is emitted in both modes rather than
            suppressed under -WhatIf the way a normal ShouldProcess message would be.

            **Transactional commit.** Register-GraphTenant takes the profile-store lock per
            call, so an outer lock would deadlock against it. Instead the store file is
            snapshotted before the first write and restored if any profile fails, leaving the
            store exactly as it was. A partial import is the one outcome that must not happen:
            it produces a store that looks migrated and is not.

            Secrets are never copied. Legacy certificate entries carry a thumbprint and a store
            name, which are references rather than key material, and those are what get
            written. If the legacy file carries bearerTokens - real secret material in
            plaintext - they are reported and refused rather than silently relocated, because
            moving a secret is an operator decision that deserves an explicit command.

        .PARAMETER Path
            Path to the legacy secrets.json.

        .PARAMETER DefaultKind
            Profile kind applied to imported tenants. Entries whose name matches a known lab
            tenant are marked 'lab' regardless.

        .PARAMETER ProfileIdMap
            Optional explicit map of legacy tenant name to canonical ProfileId, for names that
            do not slugify into something you want to live with.

        .PARAMETER StorePath
            Profile store path. Defaults to the standard location.

        .EXAMPLE
            Import-GraphLegacyProfile -Path ./secrets.json -WhatIf

            Inventory only. Writes nothing.

        .EXAMPLE
            Import-GraphLegacyProfile -Path ./secrets.json

            Imports every valid entry, or none.
    #>
    # SupportsShouldProcess is what provides -WhatIf, which is the spec's required dry-run
    # inventory. ConfirmImpact stays at the default: the operator ran a migration command
    # explicitly, the import refuses rather than overwrites when a ProfileId already exists,
    # and it rolls back on failure - so an interactive prompt buys nothing and makes the
    # command unusable from a script.
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $Path,

        [ValidateSet('customer', 'lab', 'internal')]
        [string] $DefaultKind = 'customer',

        [hashtable] $ProfileIdMap,

        [string] $StorePath
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Legacy profile file '$Path' was not found."
    }

    if ([string]::IsNullOrEmpty($StorePath)) {
        $StorePath = Join-Path $HOME '.graphkit/profiles.json'
    }

    # Data-only parse. -Depth is bounded so a pathological file cannot blow the stack, and
    # the raw text is never evaluated.
    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    try {
        $legacy = $raw | ConvertFrom-Json -Depth 12 -ErrorAction Stop
    }
    catch {
        throw "Legacy profile file '$Path' is not valid JSON: $($_.Exception.Message)"
    }

    if ($null -eq $legacy -or $legacy -isnot [pscustomobject]) {
        throw "Legacy profile file '$Path' must contain a JSON object at the top level."
    }

    $known = @('tenants', 'settings', 'bearerTokens')
    $unknownKeys = @($legacy.PSObject.Properties.Name | Where-Object { $_ -notin $known })

    $plan = [System.Collections.Generic.List[pscustomobject]]::new()
    $blockers = [System.Collections.Generic.List[string]]::new()

    if ($unknownKeys.Count -gt 0) {
        # Not fatal, but it must be said: an unrecognised key may be where credentials live.
        $blockers.Add("Unrecognised top-level keys were present and not imported: $($unknownKeys -join ', '). Confirm none of them carries credentials.")
    }

    $bearer = $legacy.PSObject.Properties['bearerTokens']
    if ($null -ne $bearer -and $null -ne $bearer.Value -and @($bearer.Value).Count -gt 0) {
        $blockers.Add("The legacy file contains $(@($bearer.Value).Count) bearerTokens entry/entries. These are secret material in plaintext and are deliberately NOT imported: place each one in a vault with Set-Secret, then register it with Register-GraphTenant -AuthMethod BearerToken -VaultName <vault> -SecretName <name>.")
    }

    $tenants = @()
    if ($null -ne $legacy.PSObject.Properties['tenants']) {
        $tenants = @($legacy.tenants)
    }

    if ($tenants.Count -eq 0) {
        $blockers.Add("No 'tenants' array was found in '$Path'.")
    }

    $existing = @()
    if (Test-Path -LiteralPath $StorePath -PathType Leaf) {
        $existing = @((Get-GraphProfileStore -StorePath $StorePath).Profiles)
    }
    $existingIds = @($existing | ForEach-Object { $_.ProfileId })

    $seenIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

    foreach ($entry in $tenants) {
        $name = [string]$entry.name
        $reasons = [System.Collections.Generic.List[string]]::new()

        $profileId = $null
        if ($null -ne $ProfileIdMap -and $ProfileIdMap.ContainsKey($name)) {
            $profileId = [string]$ProfileIdMap[$name]
        }
        else {
            $profileId = ConvertTo-GraphProfileIdSlug -Name $name
        }

        if ([string]::IsNullOrEmpty($profileId) -or -not (Test-GraphProfileId -ProfileId $profileId)) {
            $reasons.Add("Legacy name '$name' does not yield a valid ProfileId; supply one via -ProfileIdMap.")
        }
        elseif ($profileId -in $existingIds) {
            $reasons.Add("A profile '$profileId' already exists in the store; remove it first or map this entry to another id.")
        }
        elseif (-not $seenIds.Add($profileId)) {
            $reasons.Add("Two legacy entries both map to ProfileId '$profileId'; disambiguate with -ProfileIdMap.")
        }

        # The legacy file writes these in whatever casing it happens to use ('certificate'),
        # and PowerShell's -in and ValidateSet are both case-insensitive, so a raw pass-through
        # would silently persist non-canonical casing into the profile store and leave any
        # ordinal comparison downstream to fail on it. Canonicalise to the declared spelling.
        $authMethodCanonical = @('Certificate', 'ClientSecret', 'BearerToken', 'ManagedIdentity')
        $authMethod = [string]$entry.authMethod
        if ([string]::IsNullOrEmpty($authMethod)) { $authMethod = 'Certificate' }
        $matched = @($authMethodCanonical | Where-Object { $_ -eq $authMethod })
        if ($matched.Count -eq 1) {
            $authMethod = $matched[0]
        }
        else {
            $reasons.Add("Unsupported authMethod '$authMethod'.")
        }

        $tenantGuid = [guid]::Empty
        if (-not [guid]::TryParse([string]$entry.tenantId, [ref]$tenantGuid)) {
            $reasons.Add('tenantId is not a valid GUID.')
        }

        $environmentCanonical = @('Global', 'China', 'Germany', 'USGov', 'USGovDoD')
        $environment = [string]$entry.environment
        if ([string]::IsNullOrEmpty($environment)) { $environment = 'Global' }
        $matchedEnv = @($environmentCanonical | Where-Object { $_ -eq $environment })
        if ($matchedEnv.Count -eq 1) {
            $environment = $matchedEnv[0]
        }
        else {
            $reasons.Add("Unsupported environment '$environment'.")
        }

        $thumbprint = [string]$entry.certificateThumbprint
        $store = [string]$entry.certificateStore

        if ($authMethod -eq 'Certificate') {
            if ([string]::IsNullOrEmpty($thumbprint)) {
                $reasons.Add('Certificate entry has no certificateThumbprint.')
            }
            if ([string]::IsNullOrEmpty($store)) {
                $store = 'CurrentUser'
            }
            if (-not $IsWindows) {
                # Register-GraphTenant refuses store-based certificate material off Windows,
                # by design. Surface it here as a platform blocker rather than letting it
                # throw mid-transaction, so the dry run is still fully useful on macOS.
                $reasons.Add("Certificate-store profiles can only be registered on Windows; this is $($PSVersionTable.Platform). Run the import on the Windows execution host, or convert the entry to PFX/vault certificate material.")
            }
        }
        elseif ($authMethod -in @('ClientSecret', 'BearerToken')) {
            $reasons.Add("authMethod '$authMethod' requires vault-backed credential material that the legacy file does not carry; register this tenant manually after placing its secret in a vault.")
        }

        $plan.Add([pscustomobject]@{
                PSTypeName  = 'GraphKit.LegacyImportPlanItem'
                LegacyName  = $name
                ProfileId   = $profileId
                TenantId    = if ($tenantGuid -ne [guid]::Empty) { $tenantGuid.ToString() } else { $null }
                ClientId    = [string]$entry.clientId
                AuthMethod  = $authMethod
                Environment = $environment
                # A name containing 'lab' as a whole word is treated as a lab tenant. This is a
                # convenience heuristic only; -DefaultKind decides everything else.
                Kind        = if ($name -match '(?i)\blab\b') { 'lab' } else { $DefaultKind }
                Thumbprint  = $thumbprint
                StoreName   = $store
                IsDefault   = [bool]$entry.isDefault
                Importable  = ($reasons.Count -eq 0)
                Reasons     = @($reasons)
            })
    }

    $importable = @($plan | Where-Object { $_.Importable })
    $skipped = @($plan | Where-Object { -not $_.Importable })

    $report = [pscustomobject]@{
        PSTypeName   = 'GraphKit.LegacyImportReport'
        Source       = (Resolve-Path -LiteralPath $Path).Path
        StorePath    = $StorePath
        Planned      = @($plan)
        ImportedIds  = @()
        SkippedCount = $skipped.Count
        Blockers     = @($blockers)
        Committed    = $false
        Outcome      = 'Planned'
        Certainty    = 'Known'
    }

    if ($importable.Count -eq 0) {
        $report.Outcome = if ($plan.Count -eq 0) { 'NothingToImport' } else { 'NothingImportable' }
        return $report
    }

    $target = "$($importable.Count) profile(s) [$(($importable.ProfileId) -join ', ')] into '$StorePath'"
    if (-not $PSCmdlet.ShouldProcess($target, 'Import legacy tenant profiles')) {
        # The inventory IS the deliverable of a dry run, so it is returned, not suppressed.
        return $report
    }

    # Snapshot for rollback. An absent store is itself a valid snapshot state.
    $hadStore = Test-Path -LiteralPath $StorePath -PathType Leaf
    $snapshot = if ($hadStore) { [System.IO.File]::ReadAllBytes($StorePath) } else { $null }

    $imported = [System.Collections.Generic.List[string]]::new()
    try {
        foreach ($item in $importable) {
            $splat = @{
                ProfileId   = $item.ProfileId
                Name        = $item.LegacyName
                Kind        = $item.Kind
                TenantId    = $item.TenantId
                Environment = $item.Environment
                AuthMethod  = $item.AuthMethod
                StorePath   = $StorePath
            }
            if (-not [string]::IsNullOrEmpty($item.ClientId)) { $splat.ClientId = $item.ClientId }
            if ($item.AuthMethod -eq 'Certificate') {
                $splat.StoreLocation = $item.StoreName
                $splat.StoreName = 'My'
                $splat.Thumbprint = $item.Thumbprint
            }

            $null = Register-GraphTenant @splat
            $imported.Add($item.ProfileId)
        }
    }
    catch {
        $restoreNote = Restore-GraphProfileStoreSnapshot -StorePath $StorePath -Snapshot $snapshot -HadStore $hadStore
        $report.Outcome = 'RolledBack'
        $report.Certainty = 'Known'
        $report.Blockers = @($blockers) + @("Import failed on profile '$($imported.Count + 1)' of $($importable.Count): $($_.Exception.Message)") + @($restoreNote)
        return $report
    }

    $report.ImportedIds = @($imported)
    $report.Committed = $true
    $report.Outcome = 'Imported'
    return $report
}
