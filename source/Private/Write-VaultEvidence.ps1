<#
    Private: filesystem evidence writer for the vault.

    Write-VaultEvidence consumes a summary DTO only - raw Graph rows never reach
    this function. It writes the summary page beneath {EvidenceRoot}/{ProfileId}/,
    appends log.md in the same directory, and updates {EvidenceRoot}/index.md.
    Every write is preceded by a path-containment check: both roots and each final
    path are canonicalized and asserted to remain beneath their root, so a hostile
    or accidental path segment can never escape the configured base. Only the
    canonical ProfileId builds a path segment; Name is free text and is never used
    as a path component.
#>
function Write-VaultEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [PSCustomObject] $Summary,

        [Parameter(Mandatory)]
        [string] $EvidenceRoot,

        [Parameter(Mandatory)]
        [string] $ReportRoot
    )

    $profileId = [string] $Summary.ProfileId

    if ([string]::IsNullOrWhiteSpace($profileId)) {
        throw 'Write-VaultEvidence requires a non-empty Summary.ProfileId; it is the only value used to build evidence paths.'
    }

    $evidenceRootFull = [System.IO.Path]::GetFullPath($EvidenceRoot)
    $reportRootFull = [System.IO.Path]::GetFullPath($ReportRoot)

    # Only ProfileId builds paths; Name never does. All final paths are assembled
    # from the canonicalized roots plus the path-safe ProfileId.
    $profileDir = Join-Path $evidenceRootFull $profileId
    $summaryPath = Join-Path $profileDir "$profileId.md"
    $logPath = Join-Path $profileDir 'log.md'
    $indexPath = Join-Path $evidenceRootFull 'index.md'

    # Path containment is verified before any write, never assumed.
    foreach ($path in @($summaryPath, $logPath, $indexPath)) {
        if (-not (Test-GraphPathContainment -Root $evidenceRootFull -Candidate $path)) {
            throw "Refusing to write evidence outside the evidence root: '$path' is not beneath '$evidenceRootFull'."
        }
    }

    foreach ($source in @($Summary.SourcePaths)) {
        if (-not (Test-GraphPathContainment -Root $reportRootFull -Candidate ([string] $source))) {
            throw "Refusing to reference a source outside the report root: '$source' is not beneath '$reportRootFull'."
        }
    }

    # --- Frontmatter -------------------------------------------------------
    $customers = if ($Summary.Kind -eq 'customer' -and -not [string]::IsNullOrWhiteSpace([string] $Summary.Name)) {
        @($Summary.Name)
    } else {
        @()
    }

    $customersYaml = if ($customers.Count -eq 0) {
        '[]'
    } else {
        '[' + (($customers | ForEach-Object { "'{0}'" -f ($_ -replace "'", "''") }) -join ', ') + ']'
    }

    $sourceLines = foreach ($source in @($Summary.SourcePaths)) {
        "  - '{0}'" -f ([string] $source -replace "'", "''")
    }

    $sourcesBlock = if ($sourceLines.Count -eq 0) {
        'sources: []'
    } else {
        "sources:`n" + ($sourceLines -join "`n")
    }

    $generatedIso = if ($null -ne $Summary.GeneratedUtc) { ([datetime] $Summary.GeneratedUtc).ToString('o') } else { '' }
    $kind = if ([string]::IsNullOrWhiteSpace([string] $Summary.Kind)) { '' } else { [string] $Summary.Kind }
    $displayName = if ([string]::IsNullOrWhiteSpace([string] $Summary.Name)) { $profileId } else { [string] $Summary.Name }

    # --- Body --------------------------------------------------------------
    $countEntries = if ($null -eq $Summary.Counts) { @() } else { @($Summary.Counts.GetEnumerator()) }
    $countLines = foreach ($entry in $countEntries) {
        "- {0}: {1}" -f $entry.Key, $entry.Value
    }
    $countsText = if ($countLines.Count -eq 0) { '- (no counts)' } else { ($countLines -join "`n") }
    $noteEntries = if ($null -eq $Summary.Notes) { @() } else { @($Summary.Notes) }
    $noteLines = foreach ($note in $noteEntries) {
        "- {0}" -f $note
    }
    $notesText = if ($noteLines.Count -eq 0) { '- (no notes)' } else { ($noteLines -join "`n") }

    $wikiLinks = @("[[$profileId/log]]", '[[index]]')
    if ($customers.Count -gt 0) {
        $wikiLinks += "[[$displayName]]"
    }

    $page = @"
---
customers: $customersYaml
$sourcesBlock
generated: $generatedIso
profileId: $profileId
kind: $kind
---

# Evidence: $displayName ($profileId)

Rollups and counts only. Raw rows are filed outside the vault; see `sources:` above.

## Counts

$countsText

## Notes

$notesText

## Related

$(($wikiLinks | ForEach-Object { $_ }) -join ' | ')
"@

    # --- Write (containment already verified) ------------------------------
    $null = New-Item -ItemType Directory -Path $profileDir -Force

    Set-Content -LiteralPath $summaryPath -Value $page -Encoding utf8

    $rowsCount = if ($null -ne $Summary.Counts) { $Summary.Counts['rows'] } else { $null }
    $logLine = "- {0} | kind={1} | rows={2} | [[$profileId|$profileId]]" -f $generatedIso, $kind, $rowsCount
    Add-Content -LiteralPath $logPath -Value $logLine -Encoding utf8
    # index.md: ensure the heading and one line per profile (idempotent).
    $indexEntry = "- [[$profileId|$displayName]]"
    $indexLines = @()
    if (Test-Path -LiteralPath $indexPath -PathType Leaf) {
        $indexLines = @(Get-Content -LiteralPath $indexPath)
    }

    if ($indexLines -notcontains $indexEntry) {
        $builder = [System.Collections.Generic.List[string]]::new()
        if ($indexLines.Count -eq 0 -or $indexLines[0] -ne '# Evidence index') {
            $builder.Add('# Evidence index')
        }
        foreach ($line in $indexLines) {
            if ($line -ne '# Evidence index') {
                $builder.Add($line)
            }
        }
        $builder.Add($indexEntry)
        Set-Content -LiteralPath $indexPath -Value $builder.ToArray() -Encoding utf8
    }
}
